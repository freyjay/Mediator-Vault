#!/usr/bin/env node
// @version 1.0.0-S (mn-vault-S) — stamped 2026-06-24
// ─────────────────────────────────────────────────────────────────────────────
// seal.ts — ONE-TIME setup. Encrypts the seed at rest.
//
// Run on a TRUSTED terminal, NOT through an AI-driven session, because the
// plaintext seed and the master password are typed here. After sealing, the
// plaintext seed is never needed again — the vault unlocks from sealed.enc.
//
// Hardening choices (each fixes a finding from the code review):
//   • Argon2id is REQUIRED — no scrypt fallback. If argon2 is missing we abort,
//     instead of silently downgrading and mislabeling the file. (Fixes W3.)
//   • The ACTUAL kdf is recorded in the file, so it can never lie about itself.
//   • Seed handled as a Buffer and zeroed; we do not build seed strings.
//   • sealed.enc written 0600.
// ─────────────────────────────────────────────────────────────────────────────

import { randomBytes, createCipheriv } from 'crypto';
import { writeFileSync, mkdirSync, existsSync, chmodSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import type { SealedFile } from './types.js';
import { normalizeNetworkId, sealAAD } from './net-ids.js';

const VAULT_DIR = join(homedir(), '.mn-vault');
const SEALED_PATH = join(VAULT_DIR, 'sealed.enc');

// Argon2id parameters. m=64MiB, t=3, p=1 → ~0.5–2s/attempt on a laptop.
const ARGON2 = { m: 65536, t: 3, p: 1, keyLen: 32 };

function promptHidden(question: string): Promise<Buffer> {
  return new Promise((resolve) => {
    process.stderr.write(question);
    const chars: number[] = [];
    process.stdin.setRawMode(true);
    process.stdin.resume();
    const onData = (buf: Buffer) => {
      for (const byte of buf) {
        if (byte === 0x0a || byte === 0x0d || byte === 0x04) {     // enter / EOT
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.off('data', onData);
          process.stderr.write('\n');
          resolve(Buffer.from(chars));
          return;
        } else if (byte === 0x03) {                                 // Ctrl-C
          process.stderr.write('\n');
          process.exit(130);
        } else if (byte === 0x7f) {                                 // backspace
          chars.pop();
        } else {
          chars.push(byte);
        }
      }
    };
    process.stdin.on('data', onData);
  });
}

async function deriveKey(password: Buffer, salt: Buffer): Promise<Buffer> {
  let argon2: typeof import('argon2');
  try {
    argon2 = await import('argon2');
  } catch {
    console.error('\n❌ argon2 is not installed and is REQUIRED.');
    console.error('   Install it and re-run:  npm install argon2');
    console.error('   (No scrypt fallback — a seed-guarding vault must not');
    console.error('    silently downgrade its KDF.)\n');
    process.exit(2);
  }
  const key = await argon2.hash(password, {
    type: argon2.argon2id,
    salt,
    memoryCost: ARGON2.m,
    timeCost: ARGON2.t,
    parallelism: ARGON2.p,
    hashLength: ARGON2.keyLen,
    raw: true,
  });
  return key as Buffer;
}

async function main() {
  let networkId: string;
  try {
    networkId = normalizeNetworkId(process.argv[2] ?? 'preprod');
  } catch (e: any) {
    console.error(`❌ ${e.message}`);
    console.error('   Usage: vault-seal <network>   (e.g. vault-seal preprod)');
    process.exit(1);
  }
  console.error('══════════════════════════════════════════════════');
  console.error('  Midnight Vault — Seal (one-time)');
  console.error(`  Network: ${networkId}`);
  console.error('  Run this on a trusted terminal, NOT via an AI session.');
  console.error('══════════════════════════════════════════════════\n');

  if (existsSync(SEALED_PATH)) {
    console.error(`⚠️  ${SEALED_PATH} exists. Remove it first to re-seal.`);
    process.exit(1);
  }

  // Seed (64 hex chars) — read hidden, validate, keep as bytes.
  const seedHexBuf = await promptHidden('Seed (64 hex chars, hidden): ');
  const seedHex = seedHexBuf.toString('utf8').trim();
  seedHexBuf.fill(0);
  if (!/^[0-9a-fA-F]{64}$/.test(seedHex)) {
    console.error('❌ Seed must be exactly 64 hex characters.');
    process.exit(1);
  }
  const seed = Buffer.from(seedHex, 'hex');

  const pw1 = await promptHidden('Master password (min 16 chars): ');
  const pw2 = await promptHidden('Confirm master password: ');
  if (!pw1.equals(pw2)) { seed.fill(0); pw1.fill(0); pw2.fill(0); console.error('❌ Passwords do not match.'); process.exit(1); }
  if (pw1.length < 16) { seed.fill(0); pw1.fill(0); pw2.fill(0); console.error('❌ Password too short (min 16).'); process.exit(1); }
  pw2.fill(0);

  console.error('\nDeriving key (Argon2id, ~1–2s)…');
  const salt = randomBytes(32);
  const key = await deriveKey(pw1, salt);
  pw1.fill(0);

  const iv = randomBytes(12);
  const aad = sealAAD(networkId);                 // binds version + networkId
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(seed), cipher.final()]);
  const authTag = cipher.getAuthTag();
  seed.fill(0);
  key.fill(0);

  const sealed: SealedFile = {
    v: 2,
    kdf: 'argon2id',
    kdfParams: ARGON2,
    aead: 'aes-256-gcm',
    saltHex: salt.toString('hex'),
    ivHex: iv.toString('hex'),
    authTagHex: authTag.toString('hex'),
    ciphertextHex: ciphertext.toString('hex'),
    aadHex: aad.toString('hex'),
    networkId,
    createdAt: new Date().toISOString(),
  };

  mkdirSync(VAULT_DIR, { recursive: true });
  writeFileSync(SEALED_PATH, JSON.stringify(sealed, null, 2), { mode: 0o600 });
  try { chmodSync(SEALED_PATH, 0o600); } catch {/* file already created 0600 via mode */}

  console.error('\n✅ Sealed.');
  console.error(`   ${SEALED_PATH}  (0600)`);
  console.error('   The plaintext seed is no longer needed. Back up sealed.enc safely.');
  console.error('   It cannot be decrypted without the master password.\n');
}

main().catch((e) => { console.error('Seal failed:', e.message); process.exit(1); });
