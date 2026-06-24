// @version 1.0.0-S (mn-vault-S) — stamped 2026-06-24
// ─────────────────────────────────────────────────────────────────────────────
// net-ids.ts — canonical network identifiers + the AEAD AAD construction.
//
// Both seal.ts (writer) and sign-core.ts (reader) MUST build the AAD identically,
// byte-for-byte, or AES-GCM decryption fails. Keeping it in one place guarantees
// that. The AAD binds the version AND the networkId, so the GCM tag authenticates
// the network label — tampering with networkId in the sealed file then fails
// decryption instead of being silently accepted.
// ─────────────────────────────────────────────────────────────────────────────

// The set of networks the vault recognizes. Reject anything else at seal AND
// unlock, so a typo ('mainet') can never be sealed or silently accepted.
export const KNOWN_NETWORKS = ['preprod', 'mainnet', 'devnet', 'undeployed'] as const;
export type KnownNetwork = typeof KNOWN_NETWORKS[number];

// Normalize + validate a free-text network id. Throws on unknown.
export function normalizeNetworkId(raw: string): KnownNetwork {
  const n = String(raw ?? '').trim().toLowerCase();
  if ((KNOWN_NETWORKS as readonly string[]).includes(n)) return n as KnownNetwork;
  throw new Error(`unknown network '${raw}'. Known networks: ${KNOWN_NETWORKS.join(', ')}`);
}

// The sealed-file format version that the AAD is bound to.
export const SEAL_VERSION = 1 as const;

// Build the AAD that BOTH seal and unlock use. Binds version + networkId so the
// GCM tag authenticates them. If either differs at unlock time, decryption fails.
export function sealAAD(networkId: string): Buffer {
  return Buffer.from(`mn-vault-seal-v${SEAL_VERSION}|net=${networkId}`, 'utf8');
}

// Sane Argon2id minimums (OWASP-aligned-ish). Reject a sealed file whose KDF
// params are weaker than this at unlock — a tampered weak-KDF file is refused.
export const ARGON2_MIN = { m: 19456, t: 2, p: 1, keyLen: 32 } as const;

// ── Terminal display safety (shared by sign-once and the approver) ───────────
// AF6: any decoded field shown to a human is a SECURITY SURFACE — a crafted
// recipient/token must not be able to embed ANSI/control codes that spoof the
// display (hide an amount, fake an "approved" line, rewrite the prompt). Strip
// ESC + C0/C1 control chars to a visible placeholder and cap length.
export function sanitizeForTerminal(s: string, maxLen = 120): string {
  const str = String(s ?? '');
  let out = '';
  for (const ch of str) {
    const code = ch.codePointAt(0)!;
    if (code === 0x1b || code < 0x20 || (code >= 0x7f && code <= 0x9f)) out += '\uFFFD';
    else out += ch;
  }
  if (out.length > maxLen) out = out.slice(0, maxLen) + `…(+${out.length - maxLen} chars)`;
  return out;
}

// AF7: group integer digits (5000000 → 5,000,000) so magnitudes aren't misread.
export function groupDigits(decimal: string): string {
  if (!/^[0-9]+$/.test(decimal)) return sanitizeForTerminal(decimal, 40);
  return decimal.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}
