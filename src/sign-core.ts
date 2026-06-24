// @version 1.0.0-S (mn-vault-S) — stamped 2026-06-24
// ─────────────────────────────────────────────────────────────────────────────
// sign-core.ts — the SHARED, security-critical signing pipeline.
//
// BOTH delivery paths call this identical code, so the cryptographic logic never
// forks between them:
//   • Path A (sign-once.ts): human-run, one-shot. unlock → signCore → print → exit.
//   • Path B (vault.ts):     daemon. unlock once → signCore per socket request.
//
// CORE PROMISE (the property the whole vault rests on):
//   The vault signs ONLY what it has decoded and approved. If it cannot fully
//   decode every object it is about to sign, it REFUSES (fail-closed). It never
//   signs an object it could not read, and it never returns key material.
//
// CONCURRENCY/LIFECYCLE PROMISE:
//   While a signing operation is in flight, the keys are NOT cleared out from
//   under it. clearKeys() refuses while `busy`; callers (idle timer, shutdown)
//   must wait for the in-flight op to finish. signCore re-checks isCleared()
//   before each key use so a permitted clear between ops fails closed cleanly.
//
// Verified against @midnight-ntwrk/ledger-v8 8.0.3 + wallet-sdk-* on disk.
// INFERRED (confirm with `tsc` on the build machine): exact keystore accessor
// names, the UnboundTransaction (de)serialize entry points, the decode path into
// UnshieldedOffer inputs/outputs, the per-input vs per-segment signing granularity,
// and whether finalizeRecipe proves internally. The STRUCTURE and SAFETY posture
// are correct; a few SDK symbol names may need adjustment after tsc.
// ─────────────────────────────────────────────────────────────────────────────

import { createDecipheriv } from 'crypto';
import { readFileSync, existsSync } from 'fs';
import type { SealedFile, SignContext, DecodedSummary } from './types.js';
import { normalizeNetworkId, sealAAD, ARGON2_MIN } from './net-ids.js';

import * as ledger from '@midnight-ntwrk/ledger-v8';
import { HDWallet, Roles } from '@midnight-ntwrk/wallet-sdk-hd';
import { createKeystore } from '@midnight-ntwrk/wallet-sdk-unshielded-wallet';
import { WalletFacade } from '@midnight-ntwrk/wallet-sdk-facade';

// Largest unbound-tx hex we will accept (defence against memory exhaustion from a
// same-uid caller / buggy pipeline). 2 MiB of hex = 1 MiB of bytes — far above any
// real transaction, far below anything that hurts.
const MAX_TX_HEX_LEN = 2 * 1024 * 1024;

// ── Typed errors so callers branch on TYPE, never on message text. ────────────
// GuardError       = the vault refused (policy, undecodable, net mismatch, cap, size).
//                    Maps to GUARD_DENIED, and is the SAFE outcome.
// VaultLockedError = keys are not available (locked/cleared/busy-conflict).
// Anything else    = an unexpected internal fault.
export class GuardError extends Error {
  constructor(message: string) { super(message); this.name = 'GuardError'; }
}
export class VaultLockedError extends Error {
  constructor(message = 'vault is locked') { super(message); this.name = 'VaultLockedError'; }
}

// ── Network config (preprod default; override via env). Both paths share it. ──
export interface NetConfig {
  networkId: string;
  indexer: string;
  indexerWS: string;
  node: string;
  proof: string;
}
export function netFromEnv(): NetConfig {
  // networkId is normalized HERE so a single canonical value flows everywhere:
  // the SDK (createKeystore/WalletFacade), the guard's network check, the stored
  // bundle, and the AAD. No raw/case-variant networkId reaches the SDK or guard.
  return {
    networkId: normalizeNetworkId(process.env.MN_NETWORK ?? 'preprod'),
    indexer:   process.env.MN_INDEXER    ?? 'https://indexer.preprod.midnight.network/api/v4/graphql',
    indexerWS: process.env.MN_INDEXER_WS ?? 'wss://indexer.preprod.midnight.network/api/v4/graphql/ws',
    node:      process.env.MN_NODE       ?? 'https://rpc.preprod.midnight.network',
    // NOTE: 6300 is the official image; on Apple-silicon the Bricktowers ARM64
    // image on 6301 is what works (6300 fails under Rosetta). Override via MN_PROOF.
    proof:     process.env.MN_PROOF      ?? 'http://127.0.0.1:6300',
  };
}

// ── Optional, OFF-by-default value ceiling (atoms). Enable via MN_MAX_OUTPUT_ATOMS.
// Decimal-only (AAH consistency): a value like '0x10' must not be silently read as
// 16. On a malformed value we refuse to apply a cap silently — we warn and treat
// the ceiling as unset, so the operator notices rather than getting a cap that
// means something other than what they typed.
function maxOutputAtoms(): bigint | null {
  const v = process.env.MN_MAX_OUTPUT_ATOMS;
  if (!v) return null;
  const n = parseAtoms(v);                         // canonical decimal-only parse
  if (n === null) {
    console.error(`⚠ MN_MAX_OUTPUT_ATOMS='${v}' is not a plain decimal integer — ignoring the ceiling.`);
    return null;
  }
  return n > 0n ? n : null;
}

// ── The opaque secret holder. Only this object holds key material. ────────────
// It also carries the NetConfig it was unlocked with (single source of truth for
// "which network this wallet is on") and a `busy` guard so keys can't be cleared
// mid-operation.
export interface KeyBundle {
  readonly wallet: any;             // synced WalletFacade
  readonly shieldedSecretKeys: any; // ledger.ZswapSecretKeys
  readonly dustSecretKey: any;      // ledger.DustSecretKey
  readonly keystore: any;           // unshielded keystore; .signData(payload)
  readonly verifyingKeyHex: string; // PUBLIC
  readonly addressBech32?: string;  // PUBLIC
  readonly net: NetConfig;          // the network this wallet is bound to (truth)
  readonly isCleared: () => boolean;// true once keys are zeroed
  readonly isBusy: () => boolean;   // true while a signing op holds the keys
  // Run `fn` with the keys marked busy so clearKeys() refuses mid-flight. This is
  // a FIRST-CLASS method (not an external `?.` hook) so the busy bracket can never
  // silently no-op and fail open. Always releases busy, even if `fn` throws.
  readonly withKeysBusy: <T>(fn: () => Promise<T>) => Promise<T>;
  // Zero/stop everything. Returns false WITHOUT clearing if an op is in flight
  // (so the caller must retry after the op finishes); true once cleared. Idempotent.
  readonly clearKeys: () => boolean;
}

// ── Read a hidden line (master password) from a TRUSTED terminal. ─────────────
export function promptHidden(q: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      return reject(new Error('master password must be entered at an interactive terminal (stdin is not a TTY)'));
    }
    process.stderr.write(q);
    const chars: number[] = [];
    process.stdin.setRawMode(true); process.stdin.resume();
    const onData = (buf: Buffer) => {
      for (const byte of buf) {
        if (byte === 0x0a || byte === 0x0d || byte === 0x04) {
          process.stdin.setRawMode(false); process.stdin.pause();
          process.stdin.off('data', onData); process.stderr.write('\n');
          return resolve(Buffer.from(chars));
        } else if (byte === 0x03) {                 // Ctrl-C: zero partial pw, then exit
          chars.fill(0);
          process.stdin.setRawMode(false);
          process.exit(130);
        }
        else if (byte === 0x7f) { chars.pop(); }
        else { chars.push(byte); }
      }
    };
    process.stdin.on('data', onData);
  });
}

// ── UNLOCK: decrypt seed → derive keys → start synced wallet → ZERO seed. ─────
export async function unlock(sealedPath: string, net: NetConfig): Promise<KeyBundle> {
  if (!existsSync(sealedPath)) throw new Error(`No sealed file at ${sealedPath}. Run: vault-seal`);
  const sealed: SealedFile = JSON.parse(readFileSync(sealedPath, 'utf8'));
  if (sealed.kdf !== 'argon2id') throw new Error(`Refusing: sealed kdf '${sealed.kdf}' != argon2id`);

  // AAJ: version is the PRIMARY format discriminator. v2 = network-bound AAD.
  // A v1 (or unversioned) file predates network-bound sealing — reject it with a
  // clear re-seal message rather than a confusing "wrong password" at decrypt.
  if ((sealed.v as number) !== 2) {
    throw new Error(`sealed file is format v${(sealed as any).v ?? '?'}, this build requires v2 (network-bound AAD). Re-seal with \`vault-seal <network>\` after backing up — see handoff. (Pre-release; no migration by design.)`);
  }

  // KK: normalize + validate BOTH the configured network and the sealed-file
  // network against the known set. A typo ('mainet') or case drift ('MAINNET')
  // is rejected here rather than silently mis-binding around real funds.
  const wantNet = normalizeNetworkId(net.networkId);
  const sealedNet = normalizeNetworkId(sealed.networkId ?? wantNet);
  if (sealedNet !== wantNet) {
    throw new Error(`sealed file is for network '${sealedNet}' but vault is configured for '${wantNet}'. Refusing to unlock on a mismatched network.`);
  }

  // NN: refuse a sealed file whose KDF params are weaker than our sane minimums
  // (a tampered weak-KDF file would make the password trivially brute-forceable).
  const kp = sealed.kdfParams;
  if (!kp || kp.m < ARGON2_MIN.m || kp.t < ARGON2_MIN.t || kp.p < ARGON2_MIN.p || kp.keyLen < ARGON2_MIN.keyLen) {
    throw new Error(`sealed kdfParams below minimum (need m>=${ARGON2_MIN.m}, t>=${ARGON2_MIN.t}, p>=${ARGON2_MIN.p}, keyLen>=${ARGON2_MIN.keyLen}) — refusing (possible tampering or unsafe seal)`);
  }

  const pw = await promptHidden('Master password (hidden): ');
  let argon2: typeof import('argon2');
  try { argon2 = await import('argon2'); } catch { pw.fill(0); throw new Error('argon2 required: npm install argon2'); }
  let dek: Buffer;
  try {
    dek = await argon2.hash(pw, {
      type: argon2.argon2id, salt: Buffer.from(sealed.saltHex, 'hex'),
      memoryCost: kp.m, timeCost: kp.t, parallelism: kp.p, hashLength: kp.keyLen, raw: true,
    }) as Buffer;
  } finally {
    pw.fill(0);
  }

  let seed: Buffer;
  try {
    const d = createDecipheriv('aes-256-gcm', dek, Buffer.from(sealed.ivHex, 'hex'));
    // MM: recompute the AAD from the VALIDATED network rather than trusting the
    // file's stored aadHex. The AAD binds version+networkId, so if anyone edited
    // networkId in the sealed file (without re-sealing), the GCM tag no longer
    // matches and decryption FAILS — the network label is now authenticated.
    // (Legacy v1 files are already rejected by the v===2 check above, so here we
    // can trust the format and just bind the network.)
    d.setAAD(sealAAD(sealedNet));
    d.setAuthTag(Buffer.from(sealed.authTagHex, 'hex'));
    seed = Buffer.concat([d.update(Buffer.from(sealed.ciphertextHex, 'hex')), d.final()]);
  } catch {
    dek.fill(0);
    throw new Error('Wrong password, tampered sealed file, or network-label mismatch.');
  }
  dek.fill(0);

  let shieldedSecretKeys: any, dustSecretKey: any, keystore: any;
  try {
    const hd: any = HDWallet.fromSeed(seed);
    if (hd.type !== 'seedOk') throw new Error('Invalid seed.');
    const res = hd.hdWallet.selectAccount(0)
      .selectRoles([Roles.Zswap, Roles.NightExternal, Roles.Dust])
      .deriveKeysAt(0);
    if (res.type !== 'keysDerived') throw new Error('Key derivation failed.');

    shieldedSecretKeys = (ledger as any).ZswapSecretKeys.fromSeed(res.keys[Roles.Zswap]);
    dustSecretKey      = (ledger as any).DustSecretKey.fromSeed(res.keys[Roles.Dust]);
    keystore           = createKeystore(res.keys[Roles.NightExternal], net.networkId);
    hd.hdWallet?.clear?.();
  } finally {
    seed.fill(0);   // zeroed even if derivation throws
  }

  // Resolve the PUBLIC verifying key. If neither accessor yields a non-empty
  // value, FAIL LOUDLY at unlock rather than serve an empty key later.
  const verifyingKeyHex: string =
    keystore.getVerifyingKeyHex?.() ?? keystore.getPublicKey?.()?.toString?.() ?? '';
  if (!verifyingKeyHex || !/^[0-9a-fA-F]+$/.test(verifyingKeyHex)) {
    try { keystore?.clear?.(); } catch {}
    try { shieldedSecretKeys?.clear?.(); } catch {}
    try { dustSecretKey?.clear?.(); } catch {}
    throw new Error('could not read the public verifying key from the keystore (SDK accessor mismatch) — refusing to start with an empty key');
  }

  const wallet: any = await (WalletFacade as any).init({
    networkId: net.networkId,
    indexerClientConnection: { indexerHttpUrl: net.indexer, indexerWsUrl: net.indexerWS },
    provingServerUrl: new URL(net.proof),
    relayURL: new URL(net.node.replace(/^http/, 'ws')),
  });
  await wallet.start(shieldedSecretKeys, dustSecretKey);

  let cleared = false;
  let busyDepth = 0;                          // RR: counter, not boolean — robust to overlap
  const bundle: KeyBundle = {
    wallet, shieldedSecretKeys, dustSecretKey, keystore, verifyingKeyHex,
    addressBech32: keystore.getBech32Address?.(),
    net,
    isCleared: () => cleared,
    isBusy: () => busyDepth > 0,
    async withKeysBusy<T>(fn: () => Promise<T>): Promise<T> {
      if (cleared) throw new VaultLockedError('keys already cleared — unlock again');
      busyDepth++;
      try { return await fn(); }
      finally { busyDepth--; }
    },
    clearKeys() {
      if (cleared) return true;
      if (busyDepth > 0) return false;         // never zero keys out from under an in-flight op
      cleared = true;
      try { shieldedSecretKeys?.clear?.(); } catch {}
      try { dustSecretKey?.clear?.(); } catch {}
      try { keystore?.clear?.(); } catch {}
      try { wallet?.stop?.(); } catch {}
      return true;
    },
  };
  return bundle;
}

// ── Decode ONE transaction's unshielded offers into a readable summary. ───────
interface DecodeResult {
  outputs: DecodedSummary['outputs'];
  inputCount: number;
  offersSeen: number;
  intentCount: number;
  outputsSeen: number;     // total output objects encountered (readable or not)
  unreadable: number;      // output objects whose fields did not decode honestly
}

// Is a decoded recipient string actually meaningful? Reject empty, the "?"
// placeholder, and JS's "[object Object]" (the tell-tale of String(someObject)).
function recipientLooksReadable(s: string): boolean {
  if (!s) return false;
  if (s === '?' ) return false;
  if (s.includes('[object')) return false;     // "[object Object]" etc.
  return s.trim().length > 0;
}
// THE single canonical value parser. Everything that turns a value into atoms goes
// through here, so the decimal-only rule lives in exactly ONE place (no sibling
// copies to drift). Returns a non-negative bigint, or null if the value isn't a
// clean non-negative integer. DECIMAL-ONLY: BigInt() alone would silently accept
// '0x10'(=16), '0o17', '0b101', and '  5  ' — none of which the SDK emits for a
// value; accepting them would mean approving a number the human reads differently
// than we parsed. An absent value (undefined/null) is a legitimate 0.
function parseAtoms(v: any): bigint | null {
  if (typeof v === 'bigint') return v >= 0n ? v : null;
  if (typeof v === 'number') return Number.isInteger(v) && v >= 0 ? BigInt(v) : null;
  if (typeof v === 'string') {
    if (!/^[0-9]+$/.test(v.trim())) return null;   // decimal digits only — no 0x/0o/1e/sign
    try { const n = BigInt(v.trim()); return n >= 0n ? n : null; } catch { return null; }
  }
  if (v === undefined || v === null) return 0n;    // absent value = 0 (legitimately)
  return null;
}
// Display form: the same parse, rendered as a string (or null). Single source of
// truth — delegates to parseAtoms so the validation rule cannot diverge.
function valueAsNonNegIntString(v: any): string | null {
  const n = parseAtoms(v);
  return n === null ? null : n.toString();
}

// R5: sane upper bounds so a malicious unbound tx cannot drive an unbounded decode
// loop (CPU/memory DoS) and so a human is never shown an absurd transaction. These
// are far above any legitimate tx; exceeding them is treated as undecodable.
const MAX_INTENTS = 1000;
const MAX_OUTPUTS = 10000;
class TxTooLargeError extends Error {}

function decodeTx(tx: any): DecodeResult {
  const outputs: DecodedSummary['outputs'] = [];
  let inputCount = 0, offersSeen = 0, intentCount = 0, outputsSeen = 0, unreadable = 0;
  const intents = tx?.intents ?? new Map();
  const keys = typeof intents.keys === 'function' ? Array.from(intents.keys()) : [];
  if (keys.length > MAX_INTENTS) throw new TxTooLargeError(`transaction has ${keys.length} intents (max ${MAX_INTENTS})`);
  for (const seg of keys) {
    const intent = intents.get(seg);
    if (!intent) continue;
    intentCount++;
    for (const offer of [intent.guaranteedUnshieldedOffer, intent.fallibleUnshieldedOffer]) {
      if (!offer) continue;
      offersSeen++;
      inputCount += offer.inputs?.length ?? 0;
      for (const o of offer.outputs ?? []) {
        outputsSeen++;
        if (outputsSeen > MAX_OUTPUTS) throw new TxTooLargeError(`transaction has more than ${MAX_OUTPUTS} outputs`);
        // EE: decode HONESTLY. If a field isn't a sane primitive, mark unreadable
        // rather than coercing an object into "[object Object]" and pretending.
        const rawRecipient = (o.owner ?? o.address);
        const recipient = (typeof rawRecipient === 'string' || typeof rawRecipient === 'number')
          ? String(rawRecipient) : '';
        const valueStr = valueAsNonNegIntString(o.value);
        const tokenRaw = (o.type ?? o.tokenType);
        // A token field may be legitimately absent (→ native) but if PRESENT and
        // not a readable string, treat the output as unreadable rather than
        // silently labeling a custom token 'native'.
        const tokenPresent = tokenRaw !== undefined && tokenRaw !== null;
        const tokenReadable = !tokenPresent || typeof tokenRaw === 'string';
        const token = tokenPresent ? (typeof tokenRaw === 'string' ? tokenRaw : '<unreadable>') : 'native';
        const readable = recipientLooksReadable(recipient) && valueStr !== null && tokenReadable;
        if (!readable) unreadable++;
        outputs.push({
          recipient: readable ? recipient : '<unreadable>',
          valueAtoms: valueStr ?? '<unreadable>',
          token,
        });
      }
    }
  }
  return { outputs, inputCount, offersSeen, intentCount, outputsSeen, unreadable };
}

// ── The blind-signing guard: DECODE the tx and FAIL CLOSED if we cannot. ──────
export function decodeAndGuard(tx: any, ctx: SignContext, net: NetConfig, label: string): DecodedSummary {
  // (1) Network cross-check FIRST. Normalize the caller's value so 'Preprod'
  //     and 'preprod' aren't a false mismatch (net.networkId is already canonical).
  if (ctx.network) {
    let askedNet: string;
    try { askedNet = normalizeNetworkId(ctx.network); }
    catch { throw new GuardError(`request names unknown network '${ctx.network}'`); }
    if (askedNet !== net.networkId) {
      throw new GuardError(`network mismatch: request says '${askedNet}', vault is on '${net.networkId}'`);
    }
  }
  // (2) Policy: purpose allowlist.
  const allowed = new Set(['deploy', 'register-dust', 'interact', 'other']);
  if (!allowed.has(ctx.purpose)) throw new GuardError(`purpose '${ctx.purpose}' not allowed`);
  // (3) Decode; any throw = cannot read ⇒ fail closed.
  let d: DecodeResult;
  try { d = decodeTx(tx); }
  catch (e: any) { throw new GuardError(`undecodable transaction [${label}] (fail-closed): ${e?.message ?? e}`); }
  // (4) FAIL-CLOSED on "structure present but unreadable" and on "nothing to sign".
  if (d.intentCount > 0 && d.offersSeen === 0) {
    throw new GuardError(`transaction [${label}] has ${d.intentCount} intent(s) but no readable unshielded offers — cannot verify, refusing (fail-closed)`);
  }
  if (d.intentCount === 0) {
    throw new GuardError(`transaction [${label}] has no intents to authorize — refusing (nothing to sign)`);
  }
  // (4b) EE: if ANY output failed to decode honestly, we cannot vouch for what we
  //      would sign — refuse rather than show the human "<unreadable>" and proceed.
  if (d.unreadable > 0) {
    throw new GuardError(`transaction [${label}] has ${d.unreadable}/${d.outputsSeen} output(s) whose fields did not decode to readable values — cannot verify, refusing (fail-closed)`);
  }
  // (4c) DD: refuse a zero-effect sign (offers present but no inputs and no
  //      outputs anywhere) UNLESS the purpose is one where an empty unshielded
  //      shape is legitimate (e.g. dust registration carries its effect elsewhere).
  const zeroEffect = d.inputCount === 0 && d.outputsSeen === 0;
  if (zeroEffect && ctx.purpose !== 'register-dust') {
    throw new GuardError(`transaction [${label}] has no inputs and no outputs (zero-effect) for purpose '${ctx.purpose}' — refusing`);
  }
  // (5) Optional value ceiling. The per-output cap stops any single output from
  //     exceeding the limit; R6 adds a TOTAL cap so many individually-small outputs
  //     cannot sum past the ceiling unnoticed. Both use the same env value: the
  //     per-output limit is the value, the total limit is value × output count is
  //     NOT assumed — we treat the env as the cap on EACH output AND, separately,
  //     refuse if the SUM exceeds the cap, whichever is the tighter guarantee the
  //     operator asked for. (Operators who only want a per-output cap can set it
  //     high; the total check then rarely binds.)
  const cap = maxOutputAtoms();
  if (cap !== null) {
    let total = 0n;
    for (const o of d.outputs) {
      const v = parseAtoms(o.valueAtoms);          // canonical parse — self-validating, not reliant on decode order
      if (v === null) throw new GuardError(`output value '${o.valueAtoms}' not a clean integer [${label}]`);
      if (v > cap) throw new GuardError(`output ${v} exceeds per-output cap MN_MAX_OUTPUT_ATOMS=${cap} [${label}]`);
      total += v;
    }
    if (total > cap) {
      throw new GuardError(`total unshielded output ${total} across ${d.outputs.length} output(s) exceeds MN_MAX_OUTPUT_ATOMS=${cap} [${label}] — refusing (fail-closed)`);
    }
  }
  return { outputs: d.outputs, inputCount: d.inputCount, network: net.networkId };
}

// ── Sign each intent's unshielded offers via the callback. No silent reuse. ───
// GG: every signature the keystore returns is asserted non-empty before use, so
// we never assemble a "finalized" tx containing hollow/empty signatures that would
// only fail at submit time (after we'd reported success).
function isNonEmptySig(s: any): boolean {
  if (s == null) return false;
  if (typeof s === 'string') return s.length > 0;
  if (s instanceof Uint8Array || Buffer.isBuffer(s)) return s.length > 0;
  if (typeof s.length === 'number') return s.length > 0;     // array-like
  return true;   // opaque SDK signature object — accept (can't introspect)
}

function signIntents(tx: any, signFn: (p: Uint8Array) => any, proofMarker: 'proof' | 'pre-proof'): void {
  if (!tx?.intents || tx.intents.size === 0) return;
  for (const seg of tx.intents.keys()) {
    const intent = tx.intents.get(seg);
    if (!intent) continue;
    const cloned: any = (ledger as any).Intent.deserialize('signature', proofMarker, 'pre-binding', intent.serialize());
    const segSig = signFn(cloned.signatureData(seg));
    if (!isNonEmptySig(segSig)) {
      throw new Error(`keystore returned an empty signature for segment ${String(seg)} — refusing to emit an unsigned transaction`);
    }
    for (const key of ['fallibleUnshieldedOffer', 'guaranteedUnshieldedOffer']) {
      const offer = cloned[key];
      if (!offer) continue;
      const nInputs: number = offer.inputs?.length ?? 0;
      const existing: any[] = (offer.signatures && typeof offer.signatures.at === 'function')
        ? Array.from({ length: nInputs }, (_, i) => offer.signatures.at(i))
        : [];
      const sigs = Array.from({ length: nInputs }, (_, i) => {
        const s = existing[i];
        if (s !== undefined && s !== null) return s;
        if (nInputs === 1) return segSig;
        throw new GuardError(`signature slot ${i}/${nInputs} missing for ${key}; refusing to reuse one signature across inputs`);
      });
      // Every slot we are about to attach must be a real signature.
      sigs.forEach((s, i) => {
        if (!isNonEmptySig(s)) throw new Error(`empty signature at slot ${i} for ${key} — refusing to emit an unsigned transaction`);
      });
      cloned[key] = offer.addSignatures(sigs);
    }
    tx.intents.set(seg, cloned);
  }
}

// ── THE ONE SIGNING PIPELINE. Identical for both paths. ───────────────────────
// Uses keys.net as the single source of truth for the network (ignores any
// divergent ambient env). Marks the bundle busy across the whole op so the keys
// cannot be cleared mid-flight.
export interface SignResult { finalizedTxHex: string; decoded: DecodedSummary; }

// Optional gate invoked AFTER guarding (we know exactly what will be signed) and
// BEFORE signing. Return 'approve' to proceed, anything else to refuse. Path A
// passes none (the human already chose to run the one-shot signer). The daemon
// passes a hook that blocks on out-of-band human approval.
export type ApprovalHook = (decoded: DecodedSummary) => Promise<'approve' | 'deny'>;

export async function signCore(
  keys: KeyBundle, unboundTxHex: string, ctx: SignContext, approval?: ApprovalHook,
): Promise<SignResult> {
  if (keys.isCleared()) throw new VaultLockedError('keys already cleared — unlock again');
  if (typeof unboundTxHex !== 'string' || unboundTxHex.length === 0) {
    throw new GuardError('unboundTxHex must be non-empty hex');
  }
  if (unboundTxHex.length > MAX_TX_HEX_LEN) {
    throw new GuardError(`unboundTxHex too large (${unboundTxHex.length} chars > ${MAX_TX_HEX_LEN})`);
  }
  if (!/^[0-9a-fA-F]+$/.test(unboundTxHex)) {
    throw new GuardError('unboundTxHex must be hex');
  }
  const net = keys.net;   // SINGLE SOURCE OF TRUTH — the wallet's own network

  // CC: run the whole operation inside the bundle's first-class busy bracket, so
  // clearKeys() refuses while we hold the keys. This cannot silently no-op.
  return keys.withKeysBusy(async () => {
    // 1. Deserialize (fail-closed on bad bytes).
    let tx: any;
    try {
      tx = (ledger as any).UnboundTransaction
        ? (ledger as any).UnboundTransaction.deserialize(Buffer.from(unboundTxHex, 'hex'))
        : (ledger as any).Transaction.deserialize(Buffer.from(unboundTxHex, 'hex'));
    } catch (e: any) {
      throw new GuardError(`could not deserialize unbound transaction (fail-closed): ${e?.message ?? e}`);
    }

    // 2. PRE-BALANCE GUARD on the requested tx.
    decodeAndGuard(tx, ctx, net, 'requested');

    // 3. BALANCE internally (keys used here; never leave this process).
    const recipe = await keys.wallet.balanceUnboundTransaction(
      tx, { shieldedSecretKeys: keys.shieldedSecretKeys, dustSecretKey: keys.dustSecretKey },
      { ttl: new Date(Date.now() + 30 * 60 * 1000) },
    );

    // 4. AUTHORITATIVE GUARD on the base tx (the thing primarily signed).
    const decoded = decodeAndGuard(recipe.baseTransaction, ctx, net, 'base');
    for (const o of decoded.outputs) (o as any).origin = 'base';

    // 5. GUARD THE BALANCING TX TOO if present — never sign an undecoded object.
    if (recipe.balancingTransaction) {
      const bal = decodeAndGuard(recipe.balancingTransaction, ctx, net, 'balancing');
      for (const o of bal.outputs) (o as any).origin = 'balancing';
      decoded.outputs.push(...bal.outputs);
      decoded.inputCount += bal.inputCount;
    }

    // 6. HUMAN APPROVAL GATE (if a hook was supplied). We now know exactly what
    //    will be signed (the guarded `decoded`). The daemon blocks here on an
    //    out-of-band human verdict; fail closed on anything but an explicit approve.
    if (approval) {
      const verdict = await approval(decoded);
      if (verdict !== 'approve') {
        throw new GuardError('signing was not approved by a human (denied or timed out)');
      }
      if (keys.isCleared()) throw new VaultLockedError('keys cleared while awaiting approval');
    }

    // 7. SIGN via the keystore callback (key stays in the keystore).
    if (keys.isCleared()) throw new VaultLockedError('keys cleared mid-operation');
    const signFn = (payload: Uint8Array) => keys.keystore.signData(payload);
    signIntents(recipe.baseTransaction, signFn, 'proof');
    if (recipe.balancingTransaction) signIntents(recipe.balancingTransaction, signFn, 'pre-proof');

    // 8. FINALIZE → finalized tx the pipeline can prove + submit. No key inside.
    const finalized = await keys.wallet.finalizeRecipe(recipe);
    const finalizedTxHex = Buffer.from(finalized.serialize()).toString('hex');

    return { finalizedTxHex, decoded };
  });
}
