#!/usr/bin/env node
// @version 1.0.0-S (mn-vault-S) — stamped 2026-06-24
// ─────────────────────────────────────────────────────────────────────────────
// approve.ts — vault-approve: the human's OUT-OF-BAND approval terminal (Path B).
//
// Run this in a SEPARATE window from the AI's. On start it asks you to TYPE the
// pairing code shown by the daemon — that code is the shared secret, carried by
// you (never written to disk), and is what authenticates your approvals. This is
// the only thing that can release a signature from the warm-key daemon.
//
// Per-signature approval is the default: each request shows what would be signed
// and waits for your y/N. You may open a bounded batch with `budget N`/`budget 10m`.
//
// Single input model (no stdin races): each line you type is interpreted as either
// a command (budget…/quit) or the answer to the pending request currently shown.
// ─────────────────────────────────────────────────────────────────────────────

import { createInterface } from 'readline';
import {
  sessionIdFromCode, normalizeCode, sanitizeForTerminal, groupDigits,
  listPending, writeVerdict, type PendingRequest,
} from './approval.js';

let CODE = '';
let SESSION_ID = '';
let budgetCount = 0;
let budgetUntil = 0;
const handled = new Set<string>();
let current: PendingRequest | null = null;   // the request currently awaiting y/N

const rl = createInterface({ input: process.stdin, output: process.stderr });
const out = (s: string) => process.stderr.write(s + '\n');

function showRequest(req: PendingRequest): void {
  out('\n────────────────────────────────────────────────────────');
  out(`🖊  SIGNATURE REQUESTED — id ${sanitizeForTerminal(req.id.slice(0, 12), 12)}…`);
  const ageSec = Math.max(0, Math.round((Date.now() - req.createdMs) / 1000));
  out(`   requested ${ageSec}s ago   purpose: ${sanitizeForTerminal(req.decoded.purpose, 24)}   network: ${sanitizeForTerminal(req.decoded.network, 16)}`);
  out(`   inputs: ${req.decoded.inputCount}   outputs: ${req.decoded.outputs.length}   (unshielded view)`);
  for (const o of req.decoded.outputs.slice(0, 10)) {
    const tag = o.origin === 'balancing' ? '  [balancing/change]' : '';
    // AF6: every field sanitized before printing; AF7: amounts digit-grouped.
    out(`     → ${sanitizeForTerminal(o.recipient, 80)}   ${groupDigits(o.valueAtoms)} ${sanitizeForTerminal(o.token, 24)}${tag}`);
  }
  if (req.decoded.outputs.length > 10) out(`     … (+${req.decoded.outputs.length - 10} more)`);
  out('   (shows the unshielded outputs the vault decoded; amounts are in atoms.)');
  out('────────────────────────────────────────────────────────');
  out('   Approve this signature? type  y  or  n   (or: budget N | budget 10m | budget off)');
}

function decide(req: PendingRequest, decision: 'approve' | 'deny'): void {
  writeVerdict(CODE, req.id, decision, req.digest);
  out(decision === 'approve' ? '   ✅ approved.' : '   ⛔ denied.');
}

// Handle one typed line under the single input model.
function onLine(line: string): void {
  const t = line.trim();
  const lower = t.toLowerCase();

  // Commands work whether or not a request is pending.
  if (lower.startsWith('budget')) {
    const arg = lower.split(/\s+/)[1] ?? '';
    if (arg === 'off' || arg === '0') { budgetCount = 0; budgetUntil = 0; out('   batch budget OFF — back to per-signature approval.'); }
    else if (/^\d+m$/.test(arg)) { const m = parseInt(arg); budgetUntil = Date.now() + m * 60000; budgetCount = 0; out(`   batch budget: auto-approve for ${m} minute(s). Watch this window.`); }
    else if (/^\d+$/.test(arg)) { budgetCount = parseInt(arg); budgetUntil = 0; out(`   batch budget: auto-approve the next ${budgetCount} signature(s).`); }
    else out('   usage: budget N | budget 10m | budget off');
    return;
  }
  if (lower === 'quit' || lower === 'exit') { out('   stopping approver. The daemon can no longer get signatures.'); process.exit(0); }

  // Otherwise it's an answer to the current pending request (if any).
  if (current) {
    const decision = (lower === 'y' || lower === 'yes') ? 'approve' : 'deny';
    decide(current, decision);
    current = null;
    return;
  }
  if (t.length) out('   (nothing awaiting approval right now)');
}

// Requests older than this are assumed already timed-out by the daemon, so the
// approver won't prompt for them (avoids a y/N that writes a verdict no one reads).
// Slightly longer than the daemon's default 2-min timeout to allow clock skew.
const STALE_MS = 3 * 60 * 1000;

async function poll(): Promise<void> {
  for (;;) {
    if (!current) {
      const pending = listPending(SESSION_ID).filter((r) => !handled.has(r.id));
      const next = pending[0];
      if (next) {
        handled.add(next.id);
        if (Date.now() - next.createdMs > STALE_MS) {
          out(`   (skipping request ${next.id.slice(0, 12)}… — too old, the daemon has already given up on it)`);
        } else {
          const batchActive = budgetCount > 0 || budgetUntil > Date.now();
          if (batchActive) {
            if (budgetCount > 0) budgetCount--;
            showRequest(next);
            out(`   ✅ auto-approved under batch budget${budgetCount > 0 ? ` (${budgetCount} left)` : ''}.`);
            decide(next, 'approve');
          } else {
            current = next;
            showRequest(next);
          }
        }
      }
    }
    await new Promise((r) => setTimeout(r, 250));
  }
}

async function main() {
  out('══════════════════════════════════════════════════════════');
  out('  mn-vault — approver (Path B, out-of-band human approval)');
  out('══════════════════════════════════════════════════════════');
  const code = await new Promise<string>((res) =>
    rl.question('  Type the PAIRING CODE shown by the daemon, then Enter: ', res));
  CODE = normalizeCode(code);
  if (CODE.length < 6) { out('  That does not look like a pairing code. Start the daemon, copy its code, and rerun.'); process.exit(1); }
  SESSION_ID = sessionIdFromCode(CODE);
  out('');
  out('  Paired. This window now approves signatures for that daemon session.');
  out('  Default: every signature needs your  y/n  here (per-signature).');
  out('  Optional batch:  budget 5   |   budget 10m   |   budget off');
  out('  Type  quit  to stop approving (the daemon then cannot sign).');
  out('  Keep this window in view.');
  out('══════════════════════════════════════════════════════════');

  rl.on('line', onLine);
  await poll();
}

main().catch((e) => { out(`approver failed: ${e.message}`); process.exit(1); });
