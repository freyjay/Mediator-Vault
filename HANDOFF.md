# mn-vault — Engineering Handoff

**Status:** pre-release (v1.0.0-S). Logic + lifecycle verified and tested in-sandbox; SDK symbol layer still inferred (needs `tsc` + a testnet dry-run on the build machine). Not yet reviewed by a second cryptographer — required before guarding a mainnet seed.

**What this is:** a local signing vault that houses a Midnight wallet seed so an AI assistant can **never read it**. The seed is sealed at rest (Argon2id + AES-256-GCM); signing happens behind a boundary that returns only a finalized transaction, never key material.

---

## 1. The two paths (the core product decision)

Both paths share **one** signing core (`sign-core.ts`), so the cryptographic logic cannot drift between them. Users choose by workload; the daemon's risk is disclosed.

| | **Path A — `vault-sign` (DEFAULT)** | **Path B — `vault` daemon (opt-in)** |
|---|---|---|
| Shape | Human-run, one-shot CLI | Long-lived process + `0600` Unix socket |
| Trigger | A human runs it in a trusted terminal | Any same-uid process can call the socket |
| Lifetime | Unlock → sign once → zero keys → exit | Unlocked for its run; idle-clears keys |
| USE surface | **None** — nothing is listening | A standing, same-uid-reachable signer |
| Fits | Infrequent signing (deploys every few days) | Frequent unattended on-chain writes |
| Evidence it fits | The deploy breadcrumbs show the seed is touched at exactly one rare, discrete moment; compiles/audits/dry-runs are already seed-free | Only if `call_circuit`-style writes become frequent + seed-requiring |

**Why Path A is the default:** the deploy-breadcrumbs evidence showed the seed-usage boundary and the frequent-compile path do not intersect. A permanent daemon solves a frequency problem the current workload doesn't have, and its USE gap (any same-uid caller, including the AI-as-user, can ask it to sign) **cannot exist** when nothing is listening. Path B remains available and is honest about that gap.

**READ vs USE (the distinction that must not get lost):** the vault fully solves "the AI can't **read** the seed" — architectural, not behavioral; the seed is never in any AI-reachable surface. It does **not**, on its own, solve "the AI can't **use** the seed" in Path B, because a `0600` socket admits any same-uid process. That's a limit of the socket mechanism, not a door the vault opened. Path A closes it by construction.

---

## 2. The core promises (what the code guarantees)

1. **The seed is never returned.** No socket verb, no return value, no field on any response carries the seed or any derived secret key. The protocol (`types.ts`) is the entire attack surface: `ping`, `verifying-key` (PUBLIC only), `prepare-and-sign` (returns a finalized tx + a decoded summary).
2. **We sign only what we decoded and approved.** Every transaction object that gets signed — the base **and** the balancing tx — is decoded and guarded first. If anything can't be fully, honestly decoded, the vault **refuses** (fail-closed). Proven by reference identity (we guard and sign the same object) + tests.
3. **Keys are never cleared mid-signing.** A `busy` depth-counter makes `clearKeys()` refuse while an operation is in flight; the idle timer and shutdown wait. Proven by the lifecycle tests.
4. **Bad input fails closed, not open.** Undecodable bytes, unreadable fields, empty/zero-effect transactions, oversized input, wrong network, hollow signatures — all refuse.

---

## 3. The six review passes — every finding and its disposition

Severity at time of finding. All HIGH/CRITICAL are **fixed** unless marked otherwise. Letters are the working labels from the review.

### Passes 1–2 (first round, already applied earlier)
| ID | Sev | Finding | Fix |
|---|---|---|---|
| A | CRIT | Guard checked base tx but balancing tx was signed un-guarded | Guard **every** signed object (base + balancing); fold balancing outputs into the audited summary |
| B | CRIT | Fail-**open**: a tx with intents but zero readable offers returned success | Refuse when structure present but unreadable; refuse zero-intent |
| C | HIGH | `signIntents` silently reused one segment sig across N inputs | Never reuse; single-input uses segment sig, multi-input missing slot **throws** |
| D | HIGH | `ctx.network` vs vault network never cross-checked | Guard throws on network mismatch |
| I | HIGH | Daemon classified errors by regex on message text | Typed errors (`GuardError`/`VaultLockedError`); branch on `instanceof` |
| J | CRIT | Idle timer (on `setInterval`, outside the mutex) could clear keys mid-sign | `busy` guard; `clearKeys()` refuses while busy; idle skips; shutdown waits (60s cap) |
| X | CRIT | Path A: a summary-write failure after signing could mask success → double-sign | Write summary best-effort **first**, signed tx **last**; summary failure only warns |
| L,N,M,R,S,K,U,Z | HIGH–LOW | net source-of-truth, empty-pubkey, pw-zero on Ctrl-C, tx size cap, socket buffer cap, output origin tags, rate semantics, proof-port note | All applied |

### Pass 3 (deep assumptions)
| ID | Sev | Finding | Fix |
|---|---|---|---|
| CC | HIGH | `busy` was an external `(keys as any).__setBusy?.()` hook — the `?.` made the safety guard **fail open** if missing | Replaced with a **first-class** `withKeysBusy(fn)` method on `KeyBundle`; cannot silently no-op |
| DD | HIGH | An empty offer (0 in/0 out) counted as "decoded" and could be approved | Refuse **zero-effect** signs unless purpose is `register-dust` |
| EE | HIGH | `String(o.owner)` yielded `"[object Object]"` for nested fields → human "verifies" garbage (false-confidence decode) | **Honest decode**: validate recipient is a readable string, value is a non-negative integer; any unreadable field ⇒ refuse |
| GG | HIGH | Keystore could return an empty signature → a "finalized" tx with hollow sigs that fails only at submit | Assert every signature is non-empty before `addSignatures`; throw otherwise |
| JJ | MED | `Number(env)` → `NaN` silently **disabled** the rate limit / idle-clear | `posIntEnv()` validates; NaN/≤0 falls back to default with a warning |
| BB | — | Suspected busy/throw stuck-state | Verified correct (busy set after the pre-checks, released in `finally`) — no fix, covered by test |

### Pass 4 (seal path, types, cross-file)
| ID | Sev | Finding | Fix |
|---|---|---|---|
| **MM** | **HIGH** | **The AEAD's AAD did not bind `networkId`** — an attacker could relabel the sealed file's network undetectably | AAD now binds version + networkId (`mn-vault-seal-v1\|net=<net>`); recomputed at unlock from the validated network. Relabeling now **fails GCM authentication** — proven by test |
| KK | HIGH | `networkId` was free-text; a typo (`mainet`) or case drift could mis-bind | `normalizeNetworkId()` validates against a known set at **both** seal and unlock |
| NN | MED | Tampered weak `kdfParams` (m=1) would make the password trivially brute-forceable | Validate `kdfParams` against `ARGON2_MIN` (m≥19456, t≥2) at unlock |
| LL | MED | `chmodSync` after write could throw on an already-0600 file and abort a good seal | Best-effort `try/catch` (file is created `0600` via the mode option anyway) |
| PP | MED | Client documented "verify decoded matches intent" but provided no helper | Added optional `verifyDecoded()` so callers can **enforce** intent, not just be told to |

### Passes 5–6 (cracks the fixes themselves introduced)
| ID | Sev | Finding | Fix |
|---|---|---|---|
| VV | HIGH | The guard's `ctx.network` check compared raw strings, inconsistent with the new unlock normalization → could falsely reject `Preprod` vs `preprod` | Normalize the caller's `ctx.network` before comparing |
| WW | HIGH | `netFromEnv()` returned a raw `networkId` that reached the SDK and the stored bundle | Normalize `networkId` **inside** `netFromEnv()` so one canonical value flows to SDK, guard, bundle, and AAD |
| RR | HIGH | `busy` boolean was not overlap-safe (a nested/overlapping bracket's exit could clear `busy` while another op ran) | `busy` is now a **depth counter**; clears only when all brackets exit — proven by overlap test |
| ZZ | HIGH | A long sign draining a queue could let the idle timer fire between ops | `lastActivity` refreshed at each op's mutex-fn entry; worst case is a clean `LOCKED`, never a mid-sign clear |
| TT | MED | A non-string token field was silently labeled `native`, misleading the human | Non-string token ⇒ `<unreadable>` ⇒ refuse (consistent with recipient/value honesty) |
| AAE | MED | Audit logged counts but not **what** was authorized | Audit now records a SHA-256 `summaryDigest` of the decoded outputs — proves what was signed without dumping recipients |
| UU | MED | The MM/AAD change breaks **old** sealed files (different AAD) → confusing "wrong password" | Detect legacy AAD and emit a clear **"re-seal required after upgrade"** message. (Pre-release; no migration by design — see §6.) |
### Passes 7–8 (runtime execution + protocol re-read)
Pass 7 was a **runtime** harness: 17 hostile payloads executed against the real guard (null/garbage tx, fake `intents.keys()`, throwing iterators, type-confused `purpose`/`network`, oversized values). **All refused; none crashed; zero fail-open.** Committed as `tests/runtime.test.mjs`.
| ID | Sev | Finding | Fix |
|---|---|---|---|
| AAH | MED | `BigInt('0x10')` = 16 — hex/octal/sci-notation/whitespace value strings were silently accepted as a number the human reads differently (decode-honesty gap) | `valueAsNonNegIntString` now requires **decimal digits only** (`/^[0-9]+$/`); `0x10`, `1e9`, `+5`, `' 5 '` all ⇒ unreadable ⇒ refuse |
| AAI | LOW-MED | `DecodedSummary.outputs` didn't declare the `origin` field that `signCore` actually sends over the wire (type lied about shape) | Added `origin?: 'base' \| 'balancing'` to the type |
| AAJ | MED | `SealedFile.v` was `1` but the AAD format had changed; `v` wasn't used as the format discriminator | Bumped to **v2**; `unlock` checks `v===2` first and gives a clear "re-seal required" for older files; stale "vault.ts reads" comment corrected |
| AAK,AAL,AAM,AAN | — | transport-layer purpose check (cosmetic); JSON.parse crash-safety; `description` injection vectors; `--out` path traversal | Verified sound / acceptable — no change |

**Convergence note:** passes 7–8 found one real fix (AAH) and two consistency fixes (AAI, AAJ); the rest of pass 8 *confirmed soundness* rather than finding flaws. Eight passes in, static review is at its floor — the remaining risk lives in the SDK symbol layer (needs `tsc` + dry-run) and in a second cryptographer's eyes, not in another read-through.

---

## 4. Files

```
vault/
  src/
    types.ts         protocol = the security boundary (audit this first)
    net-ids.ts       canonical networks, normalizeNetworkId, sealAAD (binds net), ARGON2_MIN
    seal.ts          one-time seal ceremony (Argon2id + AES-256-GCM, network-bound AAD)
    sign-core.ts     SHARED pipeline: unlock + decodeAndGuard + signIntents + signCore
    sign-once.ts     PATH A — human-run one-shot signer (no daemon, no socket)
    vault.ts         PATH B — one-gate signing daemon (socket, mutex, audit, idle-lock)
    vault-client.ts  seed-free pipeline interface + verifyDecoded() helper
  tests/
    guard.test.mjs       fail-closed guard, network check, policy, value cap (9)
    signing.test.mjs     no-silent-sig-reuse, size cap (9)
    lifecycle.test.mjs   busy guard: keys not cleared mid-sign; idle/shutdown discipline (11)
    decode.test.mjs      honest decode, zero-effect, net normalization, AAD-binds-net, token honesty, busy counter (18)
    runtime.test.mjs     RUNTIME hostile-input harness: null/garbage tx, fake maps, throwing iterators, type confusion (17)
  package.json       scripts: seal / sign / start / start:daemon / test ; bins: vault, vault-seal, vault-sign
  tsconfig.json
```

**Test status:** `npm test` → **103 assertions, all green** (in-sandbox, pure-logic models of the SDK-independent paths).

---

## 5. How to run

```bash
cd vault
npm install
npm run typecheck          # tsc --noEmit — THE step that confirms the inferred SDK symbols
npm test                   # 47 assertions

# One-time seal (trusted terminal, NOT an AI session):
npm run seal -- preprod    # or: vault-seal preprod   (network is validated)

# Path A (default): human signs one tx
vault-sign tx.hex --purpose deploy --desc "hello-world preprod" --out finalized.hex
#   writes finalized.hex (the signed tx) + finalized.summary.json (what was authorized)

# Path B (opt-in daemon): for frequent unattended writes
npm run start              # listens on ~/.mn-vault/vault.sock (0600); Ctrl-C waits for in-flight op
```

Env knobs (all optional): `MN_NETWORK` (validated), `MN_INDEXER`, `MN_INDEXER_WS`, `MN_NODE`, `MN_PROOF` (note: 6300 official; **6301** for the Bricktowers ARM64 image on Apple silicon), `MN_VAULT_RATE`, `MN_VAULT_IDLE_MS`, `MN_MAX_OUTPUT_ATOMS` (optional value ceiling, off by default).

---

## 6. What is still PENDING (do not skip before mainnet)

1. **`npx tsc --noEmit` on the build machine.** The SDK symbol layer is **inferred**, not confirmed. Specifically verify:
   - keystore accessors: `signData`, `getVerifyingKeyHex`, `getBech32Address` (unlock fails loudly if the pubkey accessor is wrong — good — but confirm the real names);
   - `UnboundTransaction.deserialize` / `.serialize` entry points;
   - `Intent.deserialize('signature', proofMarker, 'pre-binding', …)` argument shape;
   - `balanceUnboundTransaction` argument + `recipe.{baseTransaction,balancingTransaction}` shape, and the **`ttl` type** (we pass a `Date`; confirm vs ms/height);
   - whether `finalizeRecipe` proves internally or a separate prove step is needed;
   - **the per-input vs per-segment signing granularity** (finding C) — the one place where being wrong is unrecoverable. Our code makes the unsafe case **throw**, which is the right default, but the real semantics must be confirmed.
   Paste any `tsc` errors back and they get fixed against the real types.

2. **Testnet dry-run** end-to-end (seal → build unbound tx seed-free → `vault-sign` → prove → submit on preprod) to confirm the finalized tx is accepted.

3. **Second cryptographer review** of the `signIntents` signing path specifically, before guarding a live mainnet seed. One reviewer is insufficient for unrecoverable stakes.

4. **Re-seal note (UU):** because the AAD now binds the network, any sealed file created before this change will not decrypt and will produce the "re-seal required" message. Pre-release, so this is acceptable — but anyone who already sealed must back up and re-seal. There is intentionally no silent migration (a migration path would mean accepting the old, unbound-AAD format).

---

## 7. Scope — explicitly OUT (resist scope creep)

- **Same-uid attacker reading vault RAM** (`/proc/pid/mem`, debugger, swap, core dump). Out of scope by design; the threat model is "the AI tooling I invited in," not "other processes running as me." Hygiene mitigations (mlock, disable core dumps) are a documented optional upgrade, not built.
- **Compromised OS / root.** Unwinnable in user space; out of scope.
- **The PHANTOM GATE witness/shadow architecture, economic tiers, ZK preconditions.** Different layer, different threat. Its Chapter 5 (Rust sidecar / key-custody boundary) independently corroborates this design and is noted as a future **roadmap** (Rust signing core for zeroize-grade memory), not a merge.
- **A general arbitrary-secret manager.** Would force a key-vending path, reopening the exact leak the vault closes.

---

## 8. One-line summary

The vault ensures the AI never **holds** the seed (solved, architectural). Path A (default) has no standing surface for the AI to even **use** it; Path B (opt-in daemon) trades that for unattended automation and discloses the same-uid USE gap honestly. Six review passes hardened the signing core to fail closed on every uncertain case, with 103 passing assertions — and the SDK symbol layer plus a second cryptographer remain the gate before mainnet.

---

## 9. Post-review simplification (after asking "did the passes over-build?")

A self-audit of passes 7–8 asked the right question: *did each change earn its place, or did thoroughness add cruft?* Result:

- **AAH (decimal-only values): kept.** Genuine decode-honesty fix, cheap, cannot reject a legitimate (decimal) value.
- **AAI (`origin` field typed): kept.** Small but real human-verification aid (distinguishes the deploy output from change); now correctly typed rather than `as any`.
- **AAJ (version check) — corrected.** The `v===2` check was found to be **redundant** with the pass-5/6 legacy-AAD string-sniff (two mechanisms detecting one condition — drift risk). Resolved by **removing the weaker mechanism**: the AAD-string sniff and its re-throw guard are gone; the explicit `v===2` check is the single, clean format discriminator. `aadHex` is now documented as **documentary-only** (unlock recomputes the AAD from the validated network and never trusts the stored field), and the comment says so rather than implying it's load-bearing.

Net effect: fewer lines, one legacy-detection mechanism instead of two, and an honest comment on `aadHex`. This is the discipline working in the other direction — not just adding guards, but removing a guard that duplicated another. 64 assertions still green.

---

## 10. Two editions, mutually exclusive (apple XOR orange)

The two paths are now packaged as **two separately-installable editions built from
one source tree** — the user installs the one matching their workflow, and a machine
may have **only one**:

- **🍎 `mn-vault-sign` (apple, Path A):** ships `seal` + `sign-once` + the shared core.
  **`vault.js` (the daemon) is not in the package** — an apple install has no daemon
  on disk to start, accidentally or otherwise.
- **🍊 `mn-vault-daemon` (orange, Path B):** ships `seal` + `vault` + the shared core.
  `sign-once.js` is not in the package.

**Why editions instead of two repos:** the signing core (`sign-core.ts`, `types.ts`,
`seal.ts`, `net-ids.ts`) is a **single source of truth**, compiled once; both editions
are *assembled* from the same `dist/`, so the cryptography **cannot drift** between
them. Two repos would have risked two diverging copies of the signing path — a worse,
silent failure mode. This gives "orange or apple" at the install boundary with "one
orchard" at the source boundary.

**Mutual exclusion is enforced in three layers** (honest about each):
1. **Runtime (load-bearing):** `edition.ts` `claimEdition()` runs first in every entry
   point. It writes `~/.mn-vault/edition.lock` on first run and **refuses** if the dir
   is already owned by the other edition. Even a script-bypassed install can't make a
   tool sign in a mixed-edition vault. (Proven: `tests/edition.test.mjs`, 11 assertions.)
2. **Install-time:** `scripts/preinstall.mjs` refuses `npm install` of one edition when
   the other's lock exists. Catches the normal install; bypassable with
   `--ignore-scripts` (which is why Layer 1 isn't the load-bearing one).
3. **Artifact:** each package's `files` allowlist physically excludes the other
   edition's binary. (Proven by the build's forbidden-file assertion.)

**Honest scope:** this is a **safety/integrity** control (prevent accidental
coexistence of two signing surfaces), not a cryptographic one. It does not defend
against root or someone hand-editing `edition.lock` — consistent with the project's
same-uid/root out-of-scope stance.

**Switching editions:** remove the current edition + its lock
(`npm rm -g mn-vault-<edition> && rm ~/.mn-vault/edition.lock`), then install the
other. The sealed seed is **edition-agnostic** (just the encrypted seed); only the
signing surface is exclusive — re-sealing is not required to switch.

**Build:** `npm run build:editions` → compiles once, assembles `build/mn-vault-sign`
and `build/mn-vault-daemon`, asserting each excludes the forbidden file. Publish one
per machine.

---

## 11. Path B redesigned: warm-key + mandatory human approval (no "unattended")

The word **unattended** has been removed from the design. Path B is no longer "a daemon that
signs on request"; it is now **"a warm-key signer that cannot sign without an out-of-band
human approval."** Both editions now require a human action to produce any signature.

**Why:** unattended signing — and especially autonomous-agent signing — is contrary to the
project's whole purpose. "Frequent" was worth keeping (warm keys, no re-unlock per signature);
"unattended" was not. The fix removes the only property that enabled it: signing on request
with no per-signature human gate.

**Mechanism (`approval.ts` + `approve.ts`):**
- The daemon balances + guards a tx (so it knows exactly what would be signed), then posts a
  **pending request** (decoded summary + a digest; **no keys**) to a file queue under
  `~/.mn-vault/pending/` and **blocks** on `signCore`'s new optional `ApprovalHook`.
- The human runs **`vault-approve`** in a SEPARATE terminal (the AI's session can't drive it).
  It shows each request's recipients/amounts/network and waits for **y/N**. Default is
  **per-signature**; an explicit bounded **batch budget** (`budget N` / `budget 10m`) is optional.
- Only an explicit, authenticated **approve** releases the signature. No approver attached,
  a denial, a wrong-digest verdict, a forged MAC, or a timeout ⇒ **refuse** (fail-closed).

**Authenticity (closes the same-UID USE gap — corrected design):** the daemon generates a
~40-bit **pairing code in memory only** (never written to disk) and prints it; the human reads
it off the daemon terminal and **types it into `vault-approve`**. Both processes hold the code
in RAM; each verdict carries an **HMAC keyed by the code**, bound to the session id, request id,
and a digest of the exact decoded transaction. A background same-UID process can read the queue
files (decoded summaries + HMACs) but **not the code** — so it cannot forge a valid "approve."
To sign without the human it would have to guess the code (one online attempt per request, each
request single-shot — infeasible at ~40 bits) or read another process's memory. **Honest
boundary: the only ways to sign without approval are an out-of-scope same-UID memory read or
root.** There is no on-disk secret (an earlier draft stored a session secret in a 0600 file —
that was a real flaw, AC1, since 0600 doesn't stop same-UID reads; it has been removed).
Additional hardening: verdicts must match the session (AC2), use 256-bit request ids and must
post-date the request so a pre-planted verdict is rejected (AC3), are written atomically via
temp+rename (AC4), and the queue is wiped on daemon startup (AC5). The approver uses a single
input model so the budget command and y/N prompt can't race (AC6).

**Serialized one-at-a-time (AD1/AD2 — intentional + bounded):** the approval wait happens
inside the daemon's serialized critical section, so the daemon signs exactly one thing at a
time and a pending approval holds the queue. This is correct for a human-approved signer, and
its blast radius is bounded: a stuck/un-approved request is auto-denied at the timeout (default
**2 min**, `MN_VAULT_APPROVAL_MS`), which frees the queue; denying in the approver frees it
immediately. Worst-case warm-key time ≈ idle interval + approval timeout, documented in
`WORKFLOW.md`. The approver also skips requests older than ~3 min so it never prompts for a
request the daemon already abandoned (AD3).

**Cross-platform:** the approver↔daemon channel is a **file queue**, not a socket, so it works
identically on macOS, Linux, and Windows (open a second PowerShell window and run
`vault-approve`).

**Editions:** orange ships `vault` + `vault-approve` + `approval.js`. Apple is unchanged
(one-shot, no daemon, no approver needed — the human already chose to run each signature).

**Tests:** `tests/approval.test.mjs` (7 assertions) proves approve releases; deny / forged-code / wrong-session / pre-dated
/ wrong-digest / timeout all fail closed (incl. AC1: reading the queue can't forge an approve). Full suite now **82 assertions**.

**`signCore` change:** added an optional `approval?: ApprovalHook` parameter invoked AFTER the
authoritative guard and BEFORE signing. Path A passes none; the daemon passes the hook. The
shared signing pipeline is otherwise unchanged, so the crypto still cannot drift between editions.

---

## 12. Passes 9–10: lifecycle & data-flow integrity (two new angles)

Two further review passes from angles not previously taken: the failure/cleanup/resource
lifecycle, and data-flow integrity across process boundaries.

### Pass 9 — failure / cleanup / resource lifecycle
| ID | Sev | Finding | Disposition |
|---|---|---|---|
| AE1 | HIGH | Client could disconnect while the daemon awaited human approval — daemon would still prompt, sign, and then fail to deliver, for a caller that's gone | **Fixed**: track `sock` close/error; abort before prompting and re-check after approval; never sign for a disconnected client |
| AE2 | HIGH | Sign could succeed but delivery fail silently (socket closed) | **Fixed**: if not writable after signing, record `signed-but-undelivered` in the audit (with the approval digest) instead of dropping silently |
| AE8 | MED | `vault-sign` wrote output after signing — an unwritable `--out` wasted a signing ceremony | **Fixed**: pre-check the output directory exists and is writable BEFORE unlocking/signing |
| AE3 | — | Does the mutex release on throw? | **Verified OK** — `signChain` continues on both resolve and reject |
| AE5 | — | Audit unbounded growth / write failure | **Verified OK** for safety (audit is best-effort, never throws into signing); rotation/shipping remains an ops note |
| AE7 | — | Seal file perms window | **Verified OK** — written with `mode:0o600` |
| AE4, AE6, AE9 | LOW | Orphaned verdict files cleared on restart; idle timer; pre-existing dir perms | Noted; acceptable |

### Pass 10 — data-flow integrity across boundaries
| ID | Sev | Finding | Disposition |
|---|---|---|---|
| AF6 | HIGH | **Terminal injection**: the approver display is the security surface, but recipient/token strings were printed unsanitized — a crafted field with ANSI/control codes could spoof what the human sees (hide an amount, fake an "approved" line) | **Fixed**: `sanitizeForTerminal()` strips ESC/C0/C1 control chars to `\uFFFD` and caps length; applied to every displayed field. Proven by `tests/display.test.mjs` |
| AF1 | HIGH | The approval digest and the audit digest were different hashes — the chain "human-approved → signed → logged" couldn't be lined up | **Fixed**: the audit row records the same `approvalId` + `approvalDigest` the human's verdict was bound to — one provable fingerprint end-to-end |
| AF2 | MED-HIGH | The human approved a summary that only shows the **unshielded** view | **Fixed (honesty)**: the approver labels it "(unshielded view)" and states amounts are in atoms, so the human knows the scope of what they're approving |
| AF7 | MED | Raw atom amounts (`5000000`) are easy to misread | **Fixed (UX-safety)**: `groupDigits()` shows `5,000,000` |
| AF4 | — | Client doesn't re-decode the finalized tx to confirm it matches `decoded` | **Noted as trust-model boundary** — the daemon is the TCB; the human-approval digest is the integrity anchor, not a client re-decode |
| AF3, AF5, AF8 | — | Balancing outputs shown+hashed; description not shown (no free-text injection); no mutation gap between display and signing | **Verified OK** |

**Tests:** added `tests/display.test.mjs` (11 assertions: sanitizer neutralizes a screen-spoof
attack; digit grouping). Full suite now **93 assertions**, all green.

**Net:** the approver terminal is now treated as a security surface (sanitized), the
authorization chain is provable with a single digest, and the daemon no longer signs for a
vanished client. No new SDK assumptions were introduced; the `tsc` + dry-run + second-reviewer
gates from §6 still stand.

---

## 13. Passes 11–12: backward-looking + concurrency/shared-state

### Pass 11 — BACKWARD-LOOKING (re-verify prior fixes; hunt the "fixed here, not its twin" pattern)
This pass re-audited earlier fixes in the *current* code and looked for the same risk
left unfixed in a sibling location. It found the most serious bug of this round:
| ID | Sev | Finding | Disposition |
|---|---|---|---|
| AF6-in-A | **HIGH/critical** | The terminal-injection sanitizer (AF6) was applied to the **approver only** — `vault-sign` (Path A, the **default** edition) displayed the decoded tx with the **same unsanitized** recipient/token fields. A crafted tx could spoof what the Path-A user sees. | **Fixed**: sign-once now sanitizes + digit-groups its display too |
| (cascade) | HIGH | The first attempt fixed it by importing the sanitizer from `approval.ts` — which the **apple edition doesn't ship**, so it would have **broken apple at runtime**. | **Caught + fixed**: moved `sanitizeForTerminal`/`groupDigits` to the shared, daemon-free `net-ids.ts`; both editions ship it; `approval.ts` re-exports for compatibility |
| AAH-twin | MED | `maxOutputAtoms()` (the optional value ceiling) still used raw `BigInt`, so `MN_MAX_OUTPUT_ATOMS=0x10` would be silently read as 16 — the same class as AAH, in a sibling parser. | **Fixed**: decimal-only + warns and ignores a malformed ceiling rather than applying a surprising one |
| BW1, BW3 | — | Network normalization (seal/env/guard) and Path A's local `.summary.json` | **Verified OK** (Path A's full-detail local summary is appropriate for a human-run tool; the daemon uses a digest because it's a long-lived shared process) |

**Lesson recorded:** fixes should land in the **shared** path, not be hand-applied per caller.
The AF6 miss and the import cascade both came from per-caller fixes; consolidating display
safety into `net-ids.ts` removes the chance of a future third caller missing it.

### Pass 12 — CONCURRENCY / SHARED-STATE across the file queue
The `pending/` dir is filesystem-mediated IPC between daemon and approver; this pass traced
the classic races.
| ID | Sev | Finding | Disposition |
|---|---|---|---|
| BG2 | HIGH | The atomic write (temp+rename) was applied to the **verdict** (AC4) but **not** its twin, the **request** write — the approver could read a torn request. | **Fixed**: `postPending` now writes atomically too |
| BG5 | HIGH | On Ctrl-C, shutdown could appear to **hang up to ~60s** while a pending approval held `busy` and a walked-away human never answered. | **Fixed**: a shared `shuttingDown` flag is observed by the approval wait (`shouldAbort`), so a pending approval is abandoned (deny) immediately and shutdown is prompt. Tested. |
| BG7 | — | Could a same-UID process tamper the on-disk request to get a different signature? | **Verified safe**: the daemon validates the verdict against its **in-memory** digest, so editing the queue file's digest/summary ⇒ mismatch ⇒ **deny** (fail-closed) |
| BG3 | LOW-MED | Two approvers with the same code could double-prompt (last verdict wins) | **Documented**: run a single approver (no unsafe outcome — still requires the code + correct digest + post-dating) |
| BG1, BG4, BG6 | — | Burst can't occur (mutex serializes); orphaned verdicts cleared on restart; dir perms tightened each call | **Verified OK** |

**Also fixed:** a fragile test (BG5 assertions had been appended after a `process.exit`, the
dead-code-after-exit pattern) was restructured into the main flow so the count is honest.
Shutdown now also `resetQueue()`s so no stale pending files survive a restart.

**Tests:** full suite now **95 assertions**, all green (`approval.test.mjs` → 9).

**Standing caveat unchanged:** still no SDK verification — `tsc` + preprod dry-run + a second
cryptographer on the signing path remain the gates before mainnet (§6).

---

## 14. Red-team pass + evolution diff (R1/R2/R5/R6 + regression verification)

A map-driven red-team pass attacked the least-examined surfaces (edition lock, protocol
boundary, decoder, seal ceremony), and an evolution diff compared the current tree against the
`gate1` snapshot to catch any fix that silently broke an earlier one.

### Evolution diff (gate1 → current) — did we break anything while fixing?
- The four leaf modules `seal.ts`, `edition.ts`*, `types.ts`, `vault-client.ts` are **byte-identical** to gate1 except `edition.ts` (intentionally changed for R1/R2). Every other change since gate1 is **additive** (approval gate, lifecycle fixes, R5 caps).
- All security invariants present in gate1 are present now: key-zeroing (18 sites), fail-closed `GuardError` (now 22, up from 20 — the new caps), network-bound AAD, socket 0600 + edition claim. **No invariant was lost.** The recurring "fixed-here-not-its-twin" bug was always a *missing second location*, never a *corrupted first* — the diff confirms it.

### Red-team findings
| ID | Sev | Finding | Disposition |
|---|---|---|---|
| R8 | (would be HIGH) | Seed seal-vs-unlock mismatch from whitespace/case? | **Verified SAFE** — seal stores decoded *bytes* (`Buffer.from(hex)`), not the string, so normalization can't diverge |
| R5 | MED | `decodeTx` had no caps → a malicious unbound tx with huge intents/outputs = unbounded-loop DoS holding the mutex | **Fixed**: `MAX_INTENTS=1000`, `MAX_OUTPUTS=10000`; exceeding → `TxTooLargeError` → caught as `GuardError` (fail-closed). Tested |
| R1/R2 | LOW-MED | Edition lock used read-then-write (TOCTOU race: two simultaneous starts both pass) and non-atomic write (symlink-redirect risk) | **Fixed**: atomic `openSync(LOCK,'wx',0o600)` (`O_CREAT\|O_EXCL`, no symlink follow). A torn lock now fails closed rather than reclaiming. Tested (scenarios 4–5) |
| R6 | MED | Per-output value cap didn't bound the TOTAL — many sub-cap outputs could sum past the ceiling unnoticed | **Fixed**: guard now also refuses if the SUM of unshielded outputs exceeds `MN_MAX_OUTPUT_ATOMS`. Tested |
| R3 | (verify) | Does `handle()` touch `req.<field>` before checking `req.type`? | **Verified SAFE** — type checked first on every branch; null→caught→INTERNAL, array/number→BAD_REQUEST |
| R4 | — | Empty/huge `context` object | **Verified OK** — `{}` → purpose undefined → allowlist refuses; size capped by `MAX_LINE_BYTES` |
| R7 | (unfixable here) | The guard cannot verify signing-AUTHORITY semantics (per-input signature meaning) without the SDK | **Noted** — this is precisely the second-cryptographer + `tsc` gap, not closable by static review |

**Tests:** full suite now **103 assertions**, all green (edition 14, guard 11, decode 21).

**The honest finish line is unchanged:** R7 is the frontier, and it requires running against the
real Midnight libraries. `tsc --noEmit` (turns `sign-core` from inferred→verified), a preprod
dry-run, and a second human cryptographer remain the gates before mainnet.

---

## 15. Version S — eagle-eye whole-system pass

A final pass from the system level (not per-module): does everything connect seamlessly?
Verified mechanically:

- **Import integrity:** every cross-module import resolves to a real export (no dangling symbols).
- **Edition isolation:** apple's transitive import closure is `edition, net-ids, sign-core, types` — it does NOT pull in `approval` or `vault` (no daemon code reaches the one-shot signer). Orange pulls in `approval, approve, edition, net-ids, sign-core, types, vault`. The approver pulls in only `approval, net-ids`.
- **Edition packaging:** each edition ships exactly its closure — no MISSING file (which would crash at runtime) and no dead files except `vault-client.ts`, which is shipped deliberately as the consumer-facing API (imported by the AI-side pipeline, not by the vault binaries).
- **Protocol seam:** the daemon emits exactly the two result shapes (`prepare-and-sign-result`, `verifying-key-result`) the client/types expect.
- **Approval→sign→audit chain:** the digest the human approves (computed from `decoded.outputs`) is the digest the verdict HMAC binds, is the digest the audit records (`approvalId`+`approvalDigest`). In `sign-core`, `approval(decoded)` runs immediately before `signIntents(recipe…)` with no re-balance between — so what the human saw IS what is signed IS what is logged.
- **Lifecycle convergence:** `clientGone` (socket close/error) and `shuttingDown` (SIGINT/SIGTERM) are observed at the same points (before start, inside the hook, after approval, via the `awaitVerdict` abort callback), and listeners are removed on every exit path.
- **Single-source logic:** display sanitizer defined once (`net-ids`), value parsing unified to one `parseAtoms()` (4 callers, 1 definition). The duplication that caused the earlier "fixed-here-not-its-twin" bugs is consolidated.
- **Balance:** all 10 source modules brace/paren-balanced.

**Tests:** 103 assertions, all green. **Version stamped `1.0.0-S`.**

**Unchanged finish line:** this is whole-system *structural* soundness. `sign-core` still rests on
39 inferred SDK symbols. `npx tsc --noEmit`, a preprod dry-run, and a second cryptographer on the
signing path remain the gates before mainnet.
