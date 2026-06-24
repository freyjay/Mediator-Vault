#!/usr/bin/env node
// @version 1.0.0-S (mn-vault-S) — stamped 2026-06-24
// ─────────────────────────────────────────────────────────────────────────────
// sign-once.ts — PATH A (default): the minimal, human-in-the-loop signer.
//
// NO daemon. NO socket. NO long-lived process. Nothing the AI can connect to.
//
// This is the recommended path when on-chain signing is INFREQUENT (e.g. a deploy
// every few days). The AI does everything seed-free (compile, audit, dry-run,
// build the unbound tx); when an actual deploy must be signed, a HUMAN runs this
// once, in a trusted terminal:
//
//   1. AI writes the unbound transaction hex to a file (seed-free), e.g. tx.hex
//   2. Human runs:  vault-sign tx.hex --purpose deploy --desc "hello-world preprod"
//   3. This prompts the master password (hidden), unlocks, signs, prints the
//      finalized tx hex, and EXITS. Keys are zeroed; nothing keeps running.
//   4. The AI (or human) takes the finalized hex and proves + submits (seed-free).
//
// Because there is no standing process and no socket, the "same-uid caller" /
// USE surface that the daemon has DOES NOT EXIST here. The seed is in memory only
// for the brief moment of one signing, then gone.
//
// Usage:
//   vault-sign <unbound-tx-file> [--purpose deploy|register-dust|interact|other]
//                                [--desc "human description"]
//                                [--out finalized.hex]
//   echo <hex> | vault-sign -    (read tx hex from stdin)
// ─────────────────────────────────────────────────────────────────────────────

import { readFileSync, writeFileSync, existsSync, accessSync, constants as fsConstants } from 'fs';
import { join, dirname, resolve } from 'path';
import { homedir } from 'os';
import { unlock, signCore, netFromEnv } from './sign-core.js';
import { claimEdition } from './edition.js';
import { sanitizeForTerminal, groupDigits } from './net-ids.js';
import type { SignContext } from './types.js';

const SEALED_PATH = join(homedir(), '.mn-vault', 'sealed.enc');

function parseArgs(argv: string[]) {
  const a = { file: '', purpose: 'deploy', desc: '', out: '' };
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t === '--purpose') a.purpose = argv[++i] ?? 'deploy';
    else if (t === '--desc') a.desc = argv[++i] ?? '';
    else if (t === '--out') a.out = argv[++i] ?? '';
    else rest.push(t);
  }
  a.file = rest[0] ?? '';
  return a;
}

function readTxHex(file: string): string {
  if (file === '-' || file === '') {
    // read from stdin
    const data = readFileSync(0, 'utf8');
    return data.trim();
  }
  return readFileSync(file, 'utf8').trim();
}

async function main() {
  // Mutual exclusion FIRST: refuse if the daemon edition owns this machine.
  try { claimEdition('sign'); }
  catch (e: any) { console.error(`❌ ${e.message}`); process.exit(1); }

  const args = parseArgs(process.argv.slice(2));
  if (!args.file) {
    console.error('Usage: vault-sign <unbound-tx-file> [--purpose ...] [--desc "..."] [--out file]');
    console.error('       (or pipe hex:  echo <hex> | vault-sign -)');
    process.exit(1);
  }

  const validPurposes = new Set(['deploy', 'register-dust', 'interact', 'other']);
  if (!validPurposes.has(args.purpose)) {
    console.error(`❌ --purpose must be one of: ${[...validPurposes].join(', ')}`);
    process.exit(1);
  }

  const unboundTxHex = readTxHex(args.file);
  if (!/^[0-9a-fA-F]+$/.test(unboundTxHex)) {
    console.error('❌ input is not valid hex (expected a serialized unbound transaction).');
    process.exit(1);
  }

  const net = netFromEnv();

  // AE8: verify we can actually write the output BEFORE unlocking/signing, so we
  // never perform a signing ceremony (using the seed) only to discard the result
  // because the output path was unwritable.
  if (args.out) {
    const outDir = dirname(resolve(args.out));
    if (!existsSync(outDir)) {
      console.error(`❌ output directory does not exist: ${outDir}`);
      console.error('   create it (or choose a different --out) before signing.');
      process.exit(1);
    }
    try { accessSync(outDir, fsConstants.W_OK); }
    catch { console.error(`❌ output directory is not writable: ${outDir}`); process.exit(1); }
  }

  console.error('══════════════════════════════════════════════════');
  console.error('  mn-vault — sign-once (Path A: human-in-the-loop)');
  console.error(`  Network: ${net.networkId}`);
  console.error('  Run on a trusted terminal, NOT via an AI session.');
  console.error('  Nothing stays running after this; keys are zeroed on exit.');
  console.error('══════════════════════════════════════════════════\n');

  // Unlock (prompts master password), sign once, then ALWAYS clear keys.
  const keys = await unlock(SEALED_PATH, net);
  try {
    const ctx: SignContext = { purpose: args.purpose as SignContext['purpose'], description: args.desc, network: net.networkId };
    const { finalizedTxHex, decoded } = await signCore(keys, unboundTxHex, ctx);

    // Show the human what was actually authorized (defence in depth).
    // AF6: sanitize every displayed field — a crafted recipient/token must not be
    // able to inject ANSI/control codes that spoof this receipt. AF7: group digits.
    console.error('\n✅ Signed. The vault authorized this transaction (unshielded view):');
    console.error(`   network:  ${sanitizeForTerminal(decoded.network, 16)}`);
    console.error(`   inputs:   ${decoded.inputCount}`);
    console.error(`   outputs:  ${decoded.outputs.length}`);
    for (const o of decoded.outputs.slice(0, 8)) {
      const origin = (o as any).origin === 'balancing' ? '  [balancing/change]' : '';
      console.error(`     → ${sanitizeForTerminal(o.recipient, 80)}   ${groupDigits(o.valueAtoms)} ${sanitizeForTerminal(o.token, 24)}${origin}`);
    }
    if (decoded.outputs.length > 8) console.error(`     … (+${decoded.outputs.length - 8} more)`);

    // Emit the finalized tx hex (to stdout, or to a file). This carries NO key.
    if (args.out) {
      // Write the APPROVAL SUMMARY FIRST (best-effort), then the signed tx LAST.
      // Ordering matters: the signed artifact's persistence must NOT depend on the
      // summary. If the summary write fails, we still persist the tx and warn —
      // we never let a summary failure make a SUCCESSFUL sign look failed (which
      // would tempt a re-run = double sign).
      const summaryPath = args.out.replace(/\.[^./]*$/, '') + '.summary.json';
      try {
        writeFileSync(summaryPath, JSON.stringify({
          signedAt: new Date().toISOString(),
          purpose: ctx.purpose,
          description: ctx.description,
          network: decoded.network,
          inputCount: decoded.inputCount,
          outputs: decoded.outputs,
        }, null, 2), { mode: 0o600 });
      } catch (e: any) {
        console.error(`   ⚠ could not write approval summary (${e?.message ?? e}) — continuing; the signed tx is what matters`);
      }
      writeFileSync(args.out, finalizedTxHex, { mode: 0o600 });   // the signed artifact, written LAST
      console.error(`\n   finalized tx written to ${args.out}`);
      console.error(`   approval summary: ${summaryPath}`);
      console.error('   Next (seed-free): proveTransaction → submitTransaction.\n');
    } else {
      console.error('\n   finalized tx hex (prove + submit this — it carries no key):\n');
      process.stdout.write(finalizedTxHex + '\n');
    }
  } finally {
    keys.clearKeys();   // zero keys + stop the wallet — nothing left in memory
    console.error('\n🔒 Keys zeroed. Done.');
  }
}

main().catch((e) => { console.error('sign-once failed:', e.message); process.exit(1); });
