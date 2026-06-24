// @version 1.0.0-S (mn-vault-S) — stamped 2026-06-24
// ─────────────────────────────────────────────────────────────────────────────
// types.ts — Vault protocol (THE security boundary)
//
// AUDIT THIS FILE AS THE ATTACK SURFACE. The set of request types below is the
// COMPLETE set of things any socket peer can ask the vault to do. There is no
// method that returns a secret key. There is no low-level "sign arbitrary bytes"
// method. Gate 1 is closed BY CONSTRUCTION: the insecure paths are not absent-
// because-guarded, they are absent-because-not-built.
//
// SCOPE (in):  the seed and ALL derived secret keys never leave the vault.
// SCOPE (out): a malicious process under the SAME user account (see handoff doc,
//              Appendix "upgrade kit"). 0600 socket is the only same-uid control.
//
// Verified against @midnight-ntwrk/ledger-v8 8.0.3.
// ─────────────────────────────────────────────────────────────────────────────

export type Hex = string;

// ── REQUESTS (pipeline → vault) — this is the entire attack surface ──────────
//
// Exactly three. ping (liveness), verifying-key (PUBLIC only), prepare-and-sign
// (the ONE signing-capable method; balances + signs internally; returns a
// finalized tx, never a key). Nothing else exists.

export interface PingRequest { type: 'ping'; }

export interface VerifyingKeyRequest { type: 'verifying-key'; }

/**
 * The ONE gate. The pipeline sends an unbound transaction (built seed-free) plus
 * context. The vault balances it (using secret keys it holds internally), signs
 * it, and returns a FINALIZED transaction the pipeline can prove + submit.
 *
 * The vault DECODES the transaction to enforce policy (the blind-signing guard)
 * and FAILS CLOSED on anything it cannot decode. The caller-supplied `context`
 * is for human display / audit only and is NOT trusted for the security check —
 * the guard reasons over the DECODED transaction, not over `context`.
 */
export interface PrepareAndSignRequest {
  type: 'prepare-and-sign';
  unboundTxHex: Hex;          // serialized UnboundTransaction, hex
  context: SignContext;       // for human display + audit; NOT a security input
}

export interface SignContext {
  purpose: 'deploy' | 'register-dust' | 'interact' | 'other';
  description: string;
  network?: string;
}

// The COMPLETE request union. If a request type is not here, the vault cannot do
// it. Adding a type here = adding to the attack surface = requires a guard review.
export type VaultRequest =
  | PingRequest
  | VerifyingKeyRequest
  | PrepareAndSignRequest;

// ── RESPONSES (vault → pipeline) — audit: none carry secret key material ─────

export interface PongResponse { type: 'pong'; ready: boolean; uptimeMs: number; }

export interface VerifyingKeyResponse {
  type: 'verifying-key-result';
  verifyingKeyHex: Hex;       // PUBLIC. Derives the address; cannot reveal the key.
  addressBech32?: string;     // PUBLIC.
}

export interface PrepareAndSignResponse {
  type: 'prepare-and-sign-result';
  finalizedTxHex: Hex;        // balanced + signed, ready to prove+submit. No key.
  auditId: string;            // ties to an append-only audit row
  decoded: DecodedSummary;    // what the vault actually authorized (for the caller)
}

/** What the guard decoded and approved — returned so the caller can verify intent. */
export interface DecodedSummary {
  outputs: { recipient: string; valueAtoms: string; token: string; origin?: 'base' | 'balancing' }[];
  inputCount: number;
  network: string;
}

export interface VaultError {
  type: 'error';
  code:
    | 'LOCKED'
    | 'GUARD_DENIED'       // policy rejected, OR tx could not be decoded (fail-closed)
    | 'RATE_LIMITED'
    | 'BAD_REQUEST'
    | 'INTERNAL';
  message: string;
}

export type VaultResponse =
  | PongResponse
  | VerifyingKeyResponse
  | PrepareAndSignResponse
  | VaultError;

// ── Sealed-file format (seal.ts writes; sign-core.ts reads via unlock()) ─────
// v2 = network-bound AAD (the AAD authenticates version+networkId). v1 files
// (constant AAD) are detected at unlock and rejected with a "re-seal required"
// message; there is intentionally no silent migration.

export interface SealedFile {
  v: 2;
  kdf: 'argon2id';            // ACTUAL kdf, recorded so the file cannot mislabel itself
  kdfParams: { m: number; t: number; p: number; keyLen: number };
  aead: 'aes-256-gcm';
  saltHex: Hex;
  ivHex: Hex;
  authTagHex: Hex;
  ciphertextHex: Hex;
  aadHex: Hex;                // documentary only: = sealAAD(networkId). unlock RECOMPUTES the AAD from the validated network and does not trust this field.
  networkId: string;
  createdAt: string;
}
