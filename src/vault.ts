#!/usr/bin/env node
// @version 1.0.0-S (mn-vault-S) — stamped 2026-06-24
// ─────────────────────────────────────────────────────────────────────────────
// vault.ts — Gate 1: the ONE-GATE signing vault.
//
// THE BOUNDARY (audit src/types.ts as the attack surface): the socket exposes
// exactly three operations — ping, verifying-key (PUBLIC only), and
// prepare-and-sign. There is NO low-level sign(bytes). There is NO method that
// returns a secret key. The insecure paths are not guarded-away; they are
// not-built. That is what "closed by construction" means.
//
// THE FLOW:
//   unlock once → decrypt seed → derive ALL keys → start synced wallet → ZERO seed
//   prepare-and-sign(unboundTx, ctx):
//       deserialize → DECODE (guard reasons over the real tx) → FAIL CLOSED if
//       undecodable → policy check → balance internally → sign via keystore
//       callback → finalize → return finalizedTx + decoded summary. No key leaves.
//
// Secret keys live ONLY as locals/closures in `unlock()` and the handler; they
// are never assigned to a field a response serializes. (Gate-1 rule 3.)
//
// Verified against @midnight-ntwrk/ledger-v8 8.0.3 + wallet-sdk-* on disk.
// INFERRED (confirm with `tsc` on the Mac): exact accessor names
// (getVerifyingKeyHex / getBech32Address), the UnboundTransaction (de)serialize
// entry points, and the decode path into UnshieldedOffer inputs/outputs. The
// STRUCTURE is correct; a few SDK symbol names may need adjustment after tsc.
// ─────────────────────────────────────────────────────────────────────────────

import { createServer, type Socket } from 'net';
import { randomUUID } from 'crypto';
import { existsSync, appendFileSync, chmodSync, mkdirSync, unlinkSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

import type {
  VaultRequest, VaultResponse, PrepareAndSignRequest, DecodedSummary,
} from './types.js';

// SHARED signing core — IDENTICAL pipeline used by Path A (sign-once.ts) and this
// daemon (Path B). The cryptographic logic lives in ONE place so it cannot drift.
import { unlock as coreUnlock, signCore, netFromEnv, GuardError, VaultLockedError, type KeyBundle, type NetConfig } from './sign-core.js';
import { claimEdition } from './edition.js';
import {
  generatePairingCode, sessionIdFromCode, resetQueue, postPending, awaitVerdict,
  type PendingRequest,
} from './approval.js';
import { createHash as _createHash } from 'crypto';

// How long the daemon waits for a human verdict before refusing (fail-closed).
// IMPORTANT (AD1/AD2): the approval wait happens INSIDE the serialized critical
// section, so the daemon signs exactly ONE thing at a time and a pending approval
// holds the queue until it is answered or times out. This is intentional for a
// human-approved signer (you approve one at a time), and it bounds blast radius:
// • other signing requests queue behind a pending approval (deny it to free them);
// • keys stay warm during the wait, so worst-case warm time ≈ idle interval +
//   this timeout. Keep this modest. A stuck/un-approved request is auto-denied at
//   the timeout, which releases the queue and lets idle-clear proceed.
const APPROVAL_TIMEOUT_MS = posIntEnvSafe('MN_VAULT_APPROVAL_MS', 2 * 60 * 1000);
function posIntEnvSafe(name: string, def: number): number {
  const raw = process.env[name]; if (!raw) return def;
  const n = Number(raw); return Number.isFinite(n) && n > 0 ? Math.floor(n) : def;
}

// The pairing code: generated in memory at startup, printed for the human to type
// into vault-approve. NEVER written to disk. This is the out-of-band secret.
// BG5: set as soon as a shutdown signal arrives. A pending approval wait observes
// this and abandons promptly (treated as deny) so Ctrl-C doesn't appear to hang
// for up to the approval timeout while a human who has walked away never answers.
let shuttingDown = false;

const PAIRING_CODE = generatePairingCode();
const SESSION_ID   = sessionIdFromCode(PAIRING_CODE);

const VAULT_DIR   = join(homedir(), '.mn-vault');
const SEALED_PATH = join(VAULT_DIR, 'sealed.enc');
const SOCKET_PATH = join(VAULT_DIR, 'vault.sock');
const AUDIT_PATH  = join(VAULT_DIR, 'audit.log');   // append-only; ship off-box in prod

// JJ: parse a positive-integer env var; on missing/NaN/<=0 fall back to the
// default and warn. A bad value must NEVER silently disable a protection
// (a NaN rate limit or NaN idle-timeout would otherwise turn the guard off).
function posIntEnv(name: string, def: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    console.error(`⚠ ${name}='${raw}' is not a positive number — using default ${def}`);
    return def;
  }
  return Math.floor(n);
}

const startedAt = Date.now();
const RATE_MAX  = posIntEnv('MN_VAULT_RATE', 20);
const recent: number[] = [];
const NET: NetConfig = netFromEnv();

// ── In-memory secret state = the KeyBundle from sign-core. Never serialized. ──
let S: KeyBundle | null = null;

// ── Daemon-local state: idle-lock bookkeeping. Keys themselves live in S (a
//    KeyBundle from sign-core); secrets are never serialized into a response. ──
let lastActivity = Date.now();
let idleTimer: NodeJS.Timeout | null = null;
const IDLE_MS = posIntEnv('MN_VAULT_IDLE_MS', 15*60*1000); // 15 min default

// Unlock via the SHARED core (prompts master password, derives keys, starts wallet,
// zeroes seed). The daemon then HOLDS the returned KeyBundle for its lifetime.
async function unlock(): Promise<void> {
  if (!existsSync(SEALED_PATH)) { console.error(`No sealed file at ${SEALED_PATH}. Run: vault-seal`); process.exit(1); }
  console.error('Starting synced wallet (holds keys internally)…');
  try {
    S = await coreUnlock(SEALED_PATH, NET);
  } catch (e: any) {
    console.error(`❌ ${e.message}`); process.exit(3);
  }
  console.error('🔓 Unlocked. All secret keys held in-process; seed zeroed.');
}

// GATE 2 hardening: zero the resident keys via the KeyBundle's clearKeys (which
// calls the SDK's clear()). Called on idle timeout and shutdown. clearKeys()
// REFUSES (returns false) while a signing op is in flight, so we never zero keys
// out from under an active sign; callers retry. After a successful clear the vault
// is LOCKED until restart. Honest limit: clear() does not wipe proof-preimage copies.
function clearKeys(reason: string): boolean {
  if (!S) return true;
  if (S.isBusy()) return false;          // an op holds the keys — do not clear now
  const ok = S.clearKeys();
  if (!ok) return false;
  S = null;
  audit({ event: 'keys-cleared', reason });
  console.error(`🔒 Keys cleared (${reason}). Vault is LOCKED — restart to unlock.`);
  return true;
}

function armIdleLock(): void {
  if (idleTimer) clearInterval(idleTimer);
  idleTimer = setInterval(() => {
    // Only clear when genuinely idle AND not mid-operation. If a sign is in flight
    // (isBusy), skip this tick; lastActivity is refreshed around the op, so we
    // re-evaluate next tick once it completes.
    if (S && !S.isBusy() && Date.now() - lastActivity > IDLE_MS) clearKeys('idle-timeout');
  }, 30_000);
  (idleTimer as any).unref?.();
}


function audit(row: object): string {
  const id = randomUUID();
  try {
    mkdirSync(VAULT_DIR, { recursive: true });
    appendFileSync(AUDIT_PATH, JSON.stringify({ id, t: new Date().toISOString(), ...row }) + '\n');
    chmodSync(AUDIT_PATH, 0o600);
  } catch {/* never crash signing on audit failure; ship off-box in prod */}
  return id;
}

function rateOk(): boolean {
  const now = Date.now();
  while (recent.length && now - recent[0] > 60_000) recent.shift();
  if (recent.length >= RATE_MAX) return false;
  recent.push(now); return true;
}

function send(sock: Socket, m: VaultResponse) { sock.write(JSON.stringify(m) + '\n'); }

// ── SIGNING SERIALIZATION (mutex) ─────────────────────────────────────────────
// prepare-and-sign balances against the wallet's UTXO set, then signs+finalizes.
// Two concurrent calls would balance against the SAME unspent outputs before
// either submits — selecting the same input (on-chain double-spend; one tx fails)
// or corrupting wallet state mid-balance. The wallet is a single shared resource,
// so signing must be serialized: one prepare-and-sign runs to completion before
// the next begins. This is a correctness control, not a security-boundary control.
// (ping and verifying-key are read-only and are NOT serialized.)
let signChain: Promise<void> = Promise.resolve();
function runExclusive<T>(fn: () => Promise<T>): Promise<T> {
  const result = signChain.then(fn, fn);          // queue after the current op, regardless of its outcome
  signChain = result.then(() => {}, () => {});    // keep the chain alive even if this op throws
  return result;
}

// ── The ONLY request handler. Three cases. Nothing else is reachable. ─────────
async function handle(req: VaultRequest, sock: Socket): Promise<void> {
  if (req.type === 'ping') return send(sock, { type:'pong', ready: !!S, uptimeMs: Date.now()-startedAt });
  if (!S) return send(sock, { type:'error', code:'LOCKED', message:'vault is locked' });

  if (req.type === 'verifying-key')
    return send(sock, { type:'verifying-key-result', verifyingKeyHex: S.verifyingKeyHex, addressBech32: S.addressBech32 });

  if (req.type === 'prepare-and-sign') {
    const r = req as PrepareAndSignRequest;
    if (!r.unboundTxHex || !/^[0-9a-fA-F]+$/.test(r.unboundTxHex) || !r.context)
      return send(sock, { type:'error', code:'BAD_REQUEST', message:'missing unboundTxHex or context' });
    if (!rateOk()) { audit({ event:'rate-limited', ctx:r.context }); return send(sock, { type:'error', code:'RATE_LIMITED', message:'rate limit exceeded' }); }

    // SERIALIZED: the entire wallet-touching critical section runs exclusively, so
    // concurrent calls cannot balance against the same UTXO set or race the wallet.
    // AE1: track whether the requesting client is still connected. If it disconnects
    // while we await human approval, we abort rather than ask a human to approve —
    // and sign — a transaction for a caller that has gone away.
    let clientGone = false;
    const markGone = () => { clientGone = true; };
    sock.on('close', markGone);
    sock.on('error', markGone);
    return runExclusive(async () => {
      const st = S;                                  // re-check inside the lock: idle/shutdown may have cleared keys
      if (!st) { sock.off('close', markGone); sock.off('error', markGone); return send(sock, { type:'error', code:'LOCKED', message:'vault locked before signing' }); }
      try {
        if (clientGone) { audit({ event:'abort-client-gone', phase:'before-start', ctx:r.context }); return; }
        // The SHARED signing pipeline (identical to Path A): deserialize → pre-guard
        // → balance → authoritative guard on the balanced tx → sign via keystore
        // callback → finalize. Fails closed on anything it cannot decode. No key
        // leaves this process. (GATE 2: balancing needs raw keys for nullifier
        // derivation/note decryption; contained here, window shrunk via clearKeys.)
        lastActivity = Date.now();
        let approvalId = '';            // AF1: surface the approval id+digest to the audit row
        let approvalDigest = '';
        const approvalHook = async (decoded: import('./sign-core.js').SignResult['decoded']) => {
          // AE1: if the requesting client has already disconnected, do NOT prompt a
          // human or sign — abort now (the result would have nowhere to go).
          if (clientGone || !sock.writable) return 'deny' as const;
          const id = randomUUID().replace(/-/g, '') + randomUUID().replace(/-/g, '');  // 256-bit
          const now = Date.now();
          const digest = _createHash('sha256')
            .update(JSON.stringify(decoded.outputs.map((o: any) => [o.recipient, o.valueAtoms, o.token])) + `|${decoded.network}|${decoded.inputCount}`)
            .digest('hex');
          approvalId = id; approvalDigest = digest;
          const pending: PendingRequest = {
            id, sessionId: SESSION_ID, createdAt: new Date(now).toISOString(), createdMs: now, digest,
            decoded: { purpose: r.context.purpose, network: decoded.network, inputCount: decoded.inputCount, outputs: decoded.outputs },
          };
          postPending(pending);
          audit({ event: 'approval-requested', id, purpose: r.context.purpose, outputs: decoded.outputs.length, digest });
          const verdict = await awaitVerdict(PAIRING_CODE, pending, APPROVAL_TIMEOUT_MS, () => shuttingDown || clientGone);
          // AE1: re-check liveness AFTER approval — if the client vanished while the
          // human was deciding, refuse so we don't sign for a gone caller.
          if (clientGone || !sock.writable) { audit({ event:'abort-client-gone', phase:'post-approval', id }); return 'deny' as const; }
          audit({ event: verdict === 'approve' ? 'approval-granted' : 'approval-denied', id, digest });
          return verdict;
        };

        const { finalizedTxHex, decoded } = await signCore(st, r.unboundTxHex, r.context, approvalHook);
        lastActivity = Date.now();

        // AAE+AF1: the audit row records the SAME approval digest the human's verdict
        // was bound to, so the chain human-saw → approved → signed → logged is
        // provable with one matching fingerprint (not two different hashes).
        const auditId = audit({ event:'prepare-and-sign', purpose:r.context.purpose, outputs:decoded.outputs.length, inputs:decoded.inputCount, network:decoded.network, approvalId, approvalDigest });
        // AE2: if the client disconnected after we signed, the finalized tx cannot be
        // delivered. Record that explicitly (the summaryDigest above proves WHAT was
        // signed) rather than silently dropping it.
        if (!sock.writable) { audit({ event:'signed-but-undelivered', auditId, approvalDigest }); return; }
        return send(sock, { type:'prepare-and-sign-result', finalizedTxHex, auditId, decoded });
      } catch (e: any) {
        // Branch on ERROR TYPE, never on message text (which can drift).
        if (e instanceof GuardError) {
          audit({ event:'guard-denied', reason:e.message, ctx:r.context });
          return send(sock, { type:'error', code:'GUARD_DENIED', message:e.message });
        }
        if (e instanceof VaultLockedError) {
          return send(sock, { type:'error', code:'LOCKED', message:e.message });
        }
        return send(sock, { type:'error', code:'INTERNAL', message:`prepare-and-sign failed: ${String(e?.message ?? e)}` });
      } finally {
        sock.off('close', markGone); sock.off('error', markGone);
      }
    });
  }

  return send(sock, { type:'error', code:'BAD_REQUEST', message:'unknown request' });
}


// Max bytes we buffer on a single socket connection before seeing a newline.
// Protects the daemon from a same-uid caller that streams without delimiting.
const MAX_LINE_BYTES = 2 * 1024 * 1024;

async function main() {
  // Mutual exclusion FIRST: refuse if the one-shot 'sign' edition owns this machine.
  try { claimEdition('daemon'); }
  catch (e: any) { console.error(`❌ ${e.message}`); process.exit(1); }

  await unlock();
  try { unlinkSync(SOCKET_PATH); } catch {}
  const server = createServer((sock) => {
    let buf = '';
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      if (buf.length > MAX_LINE_BYTES) {           // oversized, undelimited input → drop + reject
        buf = '';
        send(sock, { type:'error', code:'BAD_REQUEST', message:'request too large' });
        try { sock.destroy(); } catch {}
        return;
      }
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i+1);
        if (!line.trim()) continue;
        let req: VaultRequest;
        try { req = JSON.parse(line); } catch { send(sock, { type:'error', code:'BAD_REQUEST', message:'invalid json' }); continue; }
        handle(req, sock).catch((e) => send(sock, { type:'error', code:'INTERNAL', message:e.message }));
      }
    });
    sock.on('error', () => {});
  });
  server.listen(SOCKET_PATH, () => {
    chmodSync(SOCKET_PATH, 0o600);
    resetQueue();                              // AC5: clear any stale pending/verdict files
    console.error(`🛡️  mn-vault — warm-key daemon (Path B) listening on ${SOCKET_PATH} (0600)`);
    console.error('   one gate: prepare-and-sign · guard: decode+fail-closed · no key ever leaves');
    console.error('');
    console.error('   ┌─────────────────────────────────────────────────────────┐');
    console.error(`   │  PAIRING CODE:   ${PAIRING_CODE}                              `);
    console.error('   └─────────────────────────────────────────────────────────┘');
    console.error('   HUMAN APPROVAL REQUIRED. In a SEPARATE terminal, run:  vault-approve');
    console.error('   and type the pairing code above when it asks. Until an approver is');
    console.error('   paired and approves, NOTHING can be signed (no approver / deny / timeout');
    console.error('   = refused). The pairing code is shown only here and lives only in memory.');
    console.error('   Ctrl-C to stop (waits for any in-flight signing, then locks).');
    armIdleLock();
    console.error(`   keys auto-clear after ${Math.round(IDLE_MS/60000)} min idle (MN_VAULT_IDLE_MS).`);
  });

  // Graceful shutdown: do NOT kill an in-flight signing op's CRYPTO, but a pending
  // human-approval wait is abandoned immediately (treated as deny via the shared
  // `shuttingDown` flag) so Ctrl-C is prompt even if the approver walked away.
  const shutdown = async (sig: string) => {
    if (shuttingDown) return; shuttingDown = true;
    console.error(`\n${sig} received — abandoning any pending approval, finishing in-flight signing, then locking…`);
    try { server.close(); } catch {}
    const deadline = Date.now() + 60_000;            // hard cap so we never hang forever
    while (!clearKeys('shutdown') && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 200));
    }
    if (S) { try { S.clearKeys(); } catch {} S = null; } // last-resort if still busy at deadline
    try { unlinkSync(SOCKET_PATH); } catch {}
    try { resetQueue(); } catch {}                   // don't leave stale pending files behind
    process.exit(0);
  };
  process.on('SIGINT',  () => { void shutdown('SIGINT'); });
  process.on('SIGTERM', () => { void shutdown('SIGTERM'); });
}
main().catch((e) => { console.error('Vault failed:', e.message); process.exit(1); });
