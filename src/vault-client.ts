// @version 1.0.0-S (mn-vault-S) — stamped 2026-06-24
// ─────────────────────────────────────────────────────────────────────────────
// vault-client.ts — the pipeline's interface to the one-gate vault.
//
// Holds NO secret. Safe to read, log, and run in an AI-reachable process.
// It can do exactly what the vault allows: ping, get the PUBLIC verifying key,
// and prepare-and-sign an unbound transaction. There is no method here to fetch
// a key, because there is no such method on the vault.
//
// Pipeline shape (all seed-free / key-free):
//   1. build the unbound transaction (no secrets needed)
//   2. const { finalizedTxHex, decoded } = await client.prepareAndSign(txHex, ctx)
//   3. verify `decoded` matches what you intended (defence in depth)
//   4. proveTransaction(finalized) → submitTransaction(...)   ← still seed-free
// ─────────────────────────────────────────────────────────────────────────────

import { createConnection, type Socket } from 'net';
import { join } from 'path';
import { homedir } from 'os';
import { existsSync } from 'fs';
import type { VaultRequest, VaultResponse, SignContext, DecodedSummary } from './types.js';

const SOCKET_PATH = join(homedir(), '.mn-vault', 'vault.sock');
const TIMEOUT_MS = 120_000;   // balancing + proving prep can take time

export class VaultClient {
  constructor(private socketPath: string = SOCKET_PATH) {}

  private rpc(req: VaultRequest): Promise<VaultResponse> {
    return new Promise((resolve, reject) => {
      if (!existsSync(this.socketPath))
        return reject(new Error(`Vault not running. Start it: vault  (socket ${this.socketPath})`));
      const sock: Socket = createConnection(this.socketPath);
      let buf = ''; let done = false;
      const timer = setTimeout(() => { if(!done){done=true; sock.destroy(); reject(new Error('vault timeout'));} }, TIMEOUT_MS);
      sock.on('connect', () => sock.write(JSON.stringify(req) + '\n'));
      sock.on('data', (d) => {
        buf += d.toString('utf8');
        const nl = buf.indexOf('\n');
        if (nl >= 0 && !done) { done = true; clearTimeout(timer); sock.end();
          try { resolve(JSON.parse(buf.slice(0, nl))); } catch { reject(new Error('bad vault response')); } }
      });
      sock.on('error', (e) => { if(!done){done=true; clearTimeout(timer); reject(e);} });
    });
  }

  async ping(): Promise<boolean> {
    try { const r = await this.rpc({ type:'ping' }); return r.type==='pong' && r.ready; } catch { return false; }
  }

  /** PUBLIC verifying key + address. Safe — cannot reveal any secret key. */
  async verifyingKey(): Promise<{ verifyingKeyHex: string; addressBech32?: string }> {
    const r = await this.rpc({ type:'verifying-key' });
    if (r.type !== 'verifying-key-result') throw new Error(r.type==='error' ? r.message : 'unexpected');
    return { verifyingKeyHex: r.verifyingKeyHex, addressBech32: r.addressBech32 };
  }

  /**
   * THE ONE GATE. Send an unbound tx (built seed-free); the vault balances,
   * guards, signs, and returns a finalized tx + a decoded summary of what it
   * authorized. The seed and all secret keys stay inside the vault.
   */
  async prepareAndSign(unboundTxHex: string, context: SignContext):
    Promise<{ finalizedTxHex: string; decoded: DecodedSummary; auditId: string }> {
    const r = await this.rpc({ type:'prepare-and-sign', unboundTxHex, context });
    if (r.type !== 'prepare-and-sign-result')
      throw new Error(r.type==='error' ? `vault denied: ${r.message}` : 'unexpected');
    return { finalizedTxHex: r.finalizedTxHex, decoded: r.decoded, auditId: r.auditId };
  }
}

/**
 * PP — defence-in-depth helper. The vault already guards what it signs, but a
 * caller with its OWN notion of intent (expected recipients/total) can verify the
 * vault's decoded summary matches that intent before proving+submitting. Throws if
 * the decoded outputs don't satisfy the expectation. Optional, but recommended for
 * unattended pipelines: it makes the human/caller's intent an enforced check, not a
 * comment. Example:
 *   verifyDecoded(decoded, { expectRecipients: ['addr1...'], maxTotalAtoms: 5_000_000n });
 */
export function verifyDecoded(
  decoded: DecodedSummary,
  expect: { expectRecipients?: string[]; maxTotalAtoms?: bigint; expectNetwork?: string },
): void {
  if (expect.expectNetwork && decoded.network !== expect.expectNetwork) {
    throw new Error(`decoded network '${decoded.network}' != expected '${expect.expectNetwork}'`);
  }
  if (decoded.outputs.some(o => o.recipient === '<unreadable>' || o.valueAtoms === '<unreadable>')) {
    throw new Error('decoded summary contains unreadable outputs — do not proceed');
  }
  if (expect.expectRecipients) {
    const allow = new Set(expect.expectRecipients);
    const bad = decoded.outputs.find(o => !allow.has(o.recipient));
    if (bad) throw new Error(`unexpected recipient in decoded summary: ${bad.recipient}`);
  }
  if (expect.maxTotalAtoms !== undefined) {
    let total = 0n;
    for (const o of decoded.outputs) { try { total += BigInt(o.valueAtoms); } catch { throw new Error(`non-integer value in decoded summary: ${o.valueAtoms}`); } }
    if (total > expect.maxTotalAtoms) throw new Error(`decoded total ${total} exceeds expected max ${expect.maxTotalAtoms}`);
  }
}
