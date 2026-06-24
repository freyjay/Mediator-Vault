// @version 1.0.0-S (mn-vault-S) — stamped 2026-06-24
// ─────────────────────────────────────────────────────────────────────────────
// edition.ts — mutual-exclusion between the two editions.
//
// A machine must have EXACTLY ONE signing surface installed/active:
//   • "sign"   edition (Path A): the one-shot human signer, NO daemon.
//   • "daemon" edition (Path B): the long-lived socket signer.
//
// This module is the RUN-TIME enforcement (the load-bearing layer). Each signing
// entry point calls claimEdition() before doing anything. If the vault directory
// is already owned by the OTHER edition, the tool refuses to run and tells the
// user to remove the other edition first ("if you want apple, remove orange").
//
// HONEST SCOPE: this is a SAFETY/integrity control — it prevents the two surfaces
// from coexisting by accident or by a careless install. It is NOT a cryptographic
// control and does not defend against a root user or someone hand-editing the
// lock file (same-uid/root is out of scope for the whole project). It guarantees
// that the NORMAL operation of either tool cannot silently leave both signing
// surfaces live on one machine.
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, existsSync, mkdirSync, chmodSync, openSync, writeSync, closeSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

export type Edition = 'sign' | 'daemon';

const VAULT_DIR = join(homedir(), '.mn-vault');
const LOCK_PATH = join(VAULT_DIR, 'edition.lock');

const HUMAN: Record<Edition, string> = {
  sign:   'mn-vault-sign (Path A — one-shot signer, no daemon)',
  daemon: 'mn-vault-daemon (Path B — signing daemon)',
};
const OTHER: Record<Edition, Edition> = { sign: 'daemon', daemon: 'sign' };

interface LockFile { edition: Edition; claimedAt: string; }

function readLock(): LockFile | null {
  if (!existsSync(LOCK_PATH)) return null;
  try {
    const l = JSON.parse(readFileSync(LOCK_PATH, 'utf8'));
    if (l && (l.edition === 'sign' || l.edition === 'daemon')) return l as LockFile;
    return null;
  } catch { return null; }
}

// R1/R2: atomically create the lock as `me`, failing if it already exists. 'wx'
// maps to O_CREAT|O_EXCL — the kernel guarantees only ONE caller wins the create
// even if two start simultaneously (closes the TOCTOU race), and O_EXCL refuses to
// follow a pre-planted symlink at LOCK_PATH (closes the symlink-redirect risk).
// Returns true if WE created it, false if it already existed (caller then reads it).
function tryCreateLock(me: Edition): boolean {
  let fd: number | undefined;
  try {
    fd = openSync(LOCK_PATH, 'wx', 0o600);            // O_CREAT|O_EXCL, no symlink follow
    writeSync(fd, JSON.stringify({ edition: me, claimedAt: new Date().toISOString() } satisfies LockFile, null, 2));
    return true;
  } catch (e: any) {
    if (e?.code === 'EEXIST') return false;            // someone else holds (or pre-made) the lock
    throw new Error(`could not claim edition lock at ${LOCK_PATH}: ${e?.message ?? e}`);
  } finally {
    if (fd !== undefined) { try { chmodSync(LOCK_PATH, 0o600); } catch {} try { closeSync(fd); } catch {} }
  }
}

/**
 * Assert that THIS edition may operate in this vault directory, and claim it.
 *
 * - If no edition has claimed the dir yet → atomically claim it for `me`, proceed.
 * - If the dir is already claimed by `me` → proceed.
 * - If the dir is claimed by the OTHER edition → REFUSE (throw). The two signing
 *   surfaces must never coexist; the user removes one to use the other.
 *
 * Call this at the very top of every signing entry point (sign-once, vault),
 * BEFORE reading the seed or opening any socket.
 */
export function claimEdition(me: Edition): void {
  try { mkdirSync(VAULT_DIR, { recursive: true }); } catch {}
  try { chmodSync(VAULT_DIR, 0o700); } catch {}

  // Atomic claim attempt FIRST (no read-then-write window). If we win the create,
  // the edition is ours and we're done.
  if (tryCreateLock(me)) return;

  // The lock already existed — read it and decide. If it's a torn/garbage file
  // (readLock → null) we fail closed rather than overwrite it, since blindly
  // reclaiming could mask a second live process.
  const existing = readLock();
  if (!existing) {
    throw new Error(
      `An edition lock exists at ${LOCK_PATH} but could not be read.\n` +
      `Refusing to proceed (fail-closed). If you are certain no vault is running,\n` +
      `remove it and retry:  rm ${LOCK_PATH}`,
    );
  }
  if (existing.edition !== me) {
    throw new Error(
      `This machine already has ${HUMAN[existing.edition]} installed and active.\n` +
      `You are trying to run ${HUMAN[me]}.\n` +
      `Only ONE signing edition may exist at a time. To switch:\n` +
      `  1. uninstall the ${OTHER[me]} edition  (npm rm -g mn-vault-${OTHER[me]})\n` +
      `  2. remove its lock:  rm ${LOCK_PATH}\n` +
      `  3. then install/run the ${me} edition.\n` +
      `(If you want apple, remove orange; if you want orange, remove apple.)`,
    );
  }
  // existing.edition === me → already ours, proceed.
}

/** For install-time checks: what edition (if any) currently owns this machine. */
export function currentEdition(): Edition | null {
  return readLock()?.edition ?? null;
}

export { LOCK_PATH };
