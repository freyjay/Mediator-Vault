# mn-vault

> **At a glance** — a local vault that holds a Midnight wallet seed so an **AI assistant can
> never read it**. The seed is sealed on disk (Argon2id + AES‑256‑GCM) and only ever unlocked
> briefly inside one signing process; nothing returns the seed or any derived key — only a
> finalized transaction.
>
> | | |
> |---|---|
> | **What it is** | A signing vault with two editions (install one): 🍎 **apple** = one‑shot signer (no daemon); 🍊 **orange** = warm‑key daemon that signs only with out‑of‑band human approval. |
> | **Guarantee (in scope)** | The AI can never *read* the seed — architectural, not a policy. Verified logic + 103 tests. |
> | **Out of scope** | A same‑UID attacker reading process memory, or root. |
> | **Needs** | Node ≥ 20 · npm · git. |
> | **Install** | `git clone <REPO_URL> && cd mn-vault && npm install && npx tsc --noEmit && npm test` |
> | **Status** | `1.0.0-S` — pre‑release. SDK symbols **inferred**: run `npx tsc --noEmit`, then a preprod dry‑run + 2nd cryptographer review **before any mainnet seed**. |
> | **Top 3 don'ts** | ① never paste your seed / `.env` into an AI ② never commit `~/.mn-vault/*`, `PROOF-OF-EXPOSURE.md`, or `.env` ③ if `npx tsc` offers `tsc@2.0.4`, say **no**. |
>
> Full detail below: [Prerequisites](#prerequisites) · [Install & verify](#install-verify) · [What NOT to do](#-what-not-to-do) · [Editions](#two-editions-pick-the-one-that-fits-your-workflow)

---

**In plain terms:** a safe for your Midnight wallet seed, so an **AI assistant can never
read it**. The seed is locked up, and only gets briefly unlocked inside the one small
program that signs a transaction — never handed to the AI, never printed, never logged.

**Technical:** the seed is encrypted at rest with **Argon2id** (key-derivation) + **AES-256-GCM**
(authenticated encryption) and exists in plaintext only transiently, inside the single
signing process. No tool, log, or API response ever returns the seed or any derived secret
key (shielded/ dust/ unshielded signing keys).

---

## Prerequisites

**Plain:** you need Node.js (a JavaScript runtime), its bundled `npm`, and `git`. Nothing else
is installed globally — the TypeScript compiler comes with the project.

**Technical:**
- **Node.js ≥ 20** (developed/run on **v22.x**; `@types/node` pinned to the 20.x type surface).
- **npm** (ships with Node) · **git** to clone.
- **Do not** install a global `typescript`/`tsc` — the pinned compiler (`typescript@5.9.3`)
  resolves locally from `node_modules` after `npm install`.
- Platform: macOS / Linux / Windows. The daemon edition uses a `0600` Unix-domain socket on
  macOS/Linux; the human-approval transport is a portable file queue (works on Windows too).

---

## Install & verify

**Plain:** clone it, install dependencies, then run two checks — one that confirms the code
matches the real Midnight libraries, one that runs the test suite. Do this in a throwaway
folder first to confirm it works before you trust it with anything.

**Technical:**
```bash
git clone <REPO_URL> mn-vault && cd mn-vault
npm install                 # resolves the pinned Midnight SDK + dev tooling
npx tsc --noEmit            # type-checks the signing core against the real SDK (the gate)
npm test                    # 103 assertions across 8 suites
```
A clean `tsc` run (no output) means the ~39 SDK symbols in `src/sign-core.ts` are **verified**,
not just inferred. Full procedure, expected output, and failure handling:
**`VERIFYING-A-CLEAN-INSTALL.md`**.

> This repo is the shared **source**. To produce the two installable editions, run
> `npm run build:editions` (see the contributors section below).

---

## ⚠️ What NOT to do

**Plain — the short list that keeps you safe:**
- **Never paste your seed (or `.env`) into an AI chat, or run the seal step "through" an AI.**
  Seal it yourself in a normal terminal. The whole point of this tool is that the AI never sees
  the seed — don't hand it over by accident.
- **Never commit runtime files to git** — the sealed seed, `PROOF-OF-EXPOSURE.md`, `.env`, the
  lock/audit/queue files. They live in `~/.mn-vault/`, not in the repo. (The included
  `.gitignore` blocks the common ones, but check before you commit.)
- **If `npx tsc` ever offers to install `tsc@2.0.4`, say NO** — that's an abandoned, unrelated
  package. The real compiler came from `npm install`.
- **Don't run both editions on the same machine** — pick apple *or* orange.
- **Don't trust it with real (mainnet) funds yet** — verify first (below).

**Technical — the same, precisely:**
- **Seed handling:** the seal ceremony (`vault-seal`) reads the seed from a hidden prompt and
  must be run on a trusted TTY, never proxied through an AI/agent session. The seed is encrypted
  to bytes (Argon2id → AES-256-GCM) and never logged; keeping it out of AI context is an
  operational responsibility the architecture cannot enforce for you at input time.
- **Repo hygiene:** never commit `~/.mn-vault/*` (`*.sealed*`, `edition.lock`, `audit.log`,
  `pending/`), `PROOF-OF-EXPOSURE.md`, or any `.env`. Git history is permanent — a secret in one
  commit is exposed even if deleted later. Verify with `git status` (and a `grep -rIl -E
  '[0-9a-fA-F]{64}'` scan) before the first commit.
- **Toolchain:** do not float the `@midnight-ntwrk/*` pins (see `pin-rationale` in
  `package.json`) — the signing surface was verified against exact versions; a surprise SDK bump
  can silently change signing semantics. Don't add a `preinstall` hook to this source repo (it
  has no edition identity).
- **Mutual exclusion:** apple and orange must not coexist; `claimEdition()` enforces this at
  runtime via `~/.mn-vault/edition.lock`. Running both is unsupported, not merely discouraged.
- **Trust boundary:** **not** verified end-to-end. Before a mainnet seed: a preprod testnet
  dry-run (live SDK signing path) **and** a second human cryptographer review of the
  `signIntents` per-input signing path. In scope: the AI can never *read* the seed
  (architectural). Out of scope: a same-UID attacker reading process memory, or root.

---

## Reading this repository (for contributors)

**This repo is the shared *source*, not a shippable package.** It contains the code that
**both** editions are built from. Two thin entry points wrap one shared signing core
(`src/sign-core.ts`), so the cryptography cannot differ between editions:

- 🍎 **apple** (`src/sign-once.ts`) — one-shot signer, no daemon.
- 🍊 **orange** (`src/vault.ts` + `src/approve.ts`) — warm-key daemon with out-of-band human approval.

The two installable packages are produced by `npm run build:editions`, which assembles each
edition into its own artifact (with its own `package.json` from `editions/`). **Only those
built editions carry the install-time edition guard** (`scripts/preinstall.mjs`, wired via the
`preinstall` hook in `editions/package.apple.json` / `editions/package.orange.json`). This
combined source repo intentionally has **no** `preinstall` hook, because it has no single
edition identity — it is neither apple nor orange. Do not add one here.

**The load-bearing mutual-exclusion guarantee does not depend on that install hook.** It is
enforced at **run time**: every signing entry point calls `claimEdition()` (`src/edition.ts`)
before reading the seed or opening a socket, using an atomic lock at `~/.mn-vault/edition.lock`.
So even running directly from this source tree, you cannot run both signing surfaces on one
machine — the second to start is refused. The preinstall hook is a courtesy that catches the
common case early; `claimEdition` is the actual guarantee.

**To verify the build before trusting it:** `npm install` then `npx tsc --noEmit` (this
type-checks the signing core against the pinned Midnight SDK — see `VERSION` and the
`pin-rationale` in `package.json`), then `npm test` (103 assertions; see `tests/TEST-CATALOG.md`).

---

## Two editions — pick the one that fits your workflow

**Plain:** there are two versions. You install **one** (not both). Pick based on how often
you sign things. Both do the signing the exact same way under the hood — they only differ in
*what stays running* on your machine.

**Technical:** both editions compile from one shared signing core (`sign-core.ts`), so the
cryptographic path is identical; they differ only in the *trigger model* and *resident
attack surface*. They are mutually exclusive (enforced — see "Two editions, enforced" below).

### → 🍎 Apple — `mn-vault-sign` (Path A · the default, recommended for most)

**Plain:** a **one-time signer you run by hand**. Nothing stays running in the background.
When something needs signing, *you* run one command in a trusted terminal; it unlocks, signs
once, prints the finished transaction, and shuts down — wiping the keys from memory.

**Technical:** a one-shot, human-in-the-loop signer. **No daemon, no socket** — zero
listening surface between signings. It unlocks, runs the signing pipeline once, emits the
finalized transaction, and zeroes key material on exit.

**Choose this if:** you sign **infrequently** (e.g. deploy a contract every few days). The AI
does everything else seed-free — compiling, auditing, dry-runs, building the unsigned
transaction — and you step in only for the actual signing moment.

**Why it's the default — plain:** because nothing is listening, there's **no way for the AI
(or anything else on your machine) to trigger a signature on its own.** The question "could
something *use* my seed without me?" can't even come up — there's nothing to call.

```bash
# 1. AI builds the unsigned tx (seed-free) and writes it to a file, e.g. tx.hex
# 2. YOU run, in a trusted terminal (not an AI session):
vault-sign tx.hex --purpose deploy --desc "hello-world preprod" --out finalized.hex
#    → writes finalized.hex (signed) + finalized.summary.json (a record of what you approved)
# 3. The AI (or you) proves + submits finalized.hex — it carries no key.
```

### → 🍊 Orange — `mn-vault-daemon` (Path B · opt-in, for frequent signing with approval)

**Plain:** a **warm signer** that keeps the keys ready so you don't re-unlock every time — but
it **cannot sign anything until you approve it** in a separate window. You open a second
terminal running `vault-approve`; every signing request shows up there with the details, and
you press **y** to release it. Convenient for frequent signing, but a human still okays each
one (or a batch you explicitly open). It is **never unattended** — if your approver window
isn't running, nothing can be signed.

**Technical:** a long-lived daemon holding the unlocked keys, exposing a `0600` Unix-domain
socket with three verbs (`ping`, `verifying-key`, `prepare-and-sign`). It does **not** sign on
request — after balancing and guarding a transaction it posts a pending request to an
out-of-band approver process (`vault-approve`) and **blocks until a human verdict**.
Per-signature approval is the default; an explicit, bounded batch budget (`budget N` /
`budget 10m`) is optional. No approver attached, a denial, or a timeout ⇒ **refuse**
(fail-closed).

**Choose this if:** you sign **frequently** and want warm keys, but still want a human okaying
each signature (or watching a short batch window). If you sign only occasionally, apple is
simpler.

**Why this is safe — plain:** the approval happens in a window the AI can't reach, and it's
unlocked by a **pairing code you carry in your head** — the daemon shows the code, you type it
into the approver. The AI can *ask* to sign; only someone who knows that code can *release* it,
and the code is never saved to a file.

**Technical — how the same-UID forge is prevented:** the daemon generates a ~40-bit pairing
code **in memory only** (never written to disk) and prints it; you type it into `vault-approve`.
Each verdict carries an **HMAC keyed by that pairing code**, bound to the session, the request
id, and a digest of the exact decoded transaction. A background same-UID process can read the
queue files (decoded summaries + HMACs) but **not the code** (it's only in two processes' RAM
and your head), so it cannot forge a valid "approve" — it would have to guess the code (one
online attempt per request, each request single-shot) or read another process's memory. The
honest boundary: **the only ways to sign without your approval are an out-of-scope same-UID
memory read or root.** No on-disk secret, no socket, no rate-limited online guess makes it
feasible. (Verdicts are also bound to the exact tx — a swapped transaction after approval ⇒
refuse — and must post-date the request ⇒ no pre-planted approvals.)

```bash
# Terminal 1 (start the warm-key daemon, enter master password once):
npm run start
#   prints a PAIRING CODE (e.g. K7Q2-9XPL); socket ~/.mn-vault/vault.sock (0600);
#   keys auto-clear when idle. The code lives only in memory — copy it by eye.

# Terminal 2 — a SEPARATE window YOU open (Windows: another PowerShell window):
vault-approve
#   it asks you to TYPE the pairing code from Terminal 1. After that, every signing
#   request appears here and waits for your  y/n.
#   (run only ONE approver window at a time)
#   optional batch:  budget 5   (next 5)    budget 10m   (10 minutes)    budget off
```

### The choice in one line

| | sign occasionally | sign frequently (with approval) |
|---|---|---|
| **Install** | 🍎 **`mn-vault-sign`** (Path A, default) | 🍊 **`mn-vault-daemon`** (Path B, opt-in) |
| **Plain: what's running?** | nothing, between signings | a warm signer + your approver window |
| **Technical: resident surface** | none | `0600` socket, gated by out-of-band approval |
| **Who must act to sign?** | you run the one-shot command | you press **y** in the approver window |
| **Unattended signing?** | **no** | **no — a human approves every signature/batch** |

**Plain:** not sure? Start with **apple**. If signing one-at-a-time by command gets tedious
(you're doing it often), switch to orange for warm keys — you'll still approve each signature,
just faster.

---

## Setup (same for both editions)

**Plain:** install it, run a quick check that the code matches the real Midnight libraries,
lock up your seed once, and run the test suite.

```bash
npm install                   # downloads the Midnight SDK + dependencies
npx tsc --noEmit              # type-check against the REAL libraries. Paste any errors to fix.
vault-seal preprod            # one-time: encrypt (seal) your seed. Trusted terminal, NOT an AI session.
npm test                      # runs the safety test suite (the guard, the lifecycle, exclusivity)
```

**Technical:** `npx tsc --noEmit` is the verification gate — it confirms the inferred SDK
symbols resolve against the installed packages (see "CONFIRMED vs INFERRED"). `vault-seal`
performs the one-time sealing ceremony (Argon2id + AES-256-GCM, network-bound AAD). Then run
**either** `vault-sign …` (apple) **or** `npm run start` (orange) — never both on one machine.

---

## What both editions guarantee

**Plain version first, technical underneath each:**

- **Your seed is never given out.**
  *Technical:* no socket verb, response field, or return value carries the seed or any
  derived secret key. The protocol in `types.ts` is the entire attack surface — audit that
  one file and you've seen every way data can leave.

- **It only signs what it can actually read and approve.**
  *Technical:* every transaction object that gets signed (base **and** balancing) is decoded
  and guarded first. Anything it can't fully, honestly decode is **refused (fail-closed)**.
  Output values must be plain decimal integers; any unreadable field ⇒ refuse.

- **The locked seed remembers which network it's for.**
  *Technical:* the AES-GCM **AAD binds the networkId**, so a sealed file can't be silently
  relabeled (e.g. preprod→mainnet) — tampering with the network label fails authentication.

- **The keys are never wiped in the middle of signing.**
  *Technical:* a busy-guard makes key-clearing refuse while an operation is in flight; the
  orange daemon also shuts down gracefully, finishing any in-progress signature before locking.

---

## Two editions, enforced (apple XOR orange)

**Plain:** a machine may have **only one** edition. If you want apple, remove orange; if you
want orange, remove apple. The tools enforce this themselves — they'll refuse to run if the
other edition is present, so you can't end up with two signers by accident.

**Technical:** mutual exclusion is enforced in three layers — (1) **runtime** (load-bearing):
each entry point calls `claimEdition()` first, writing `~/.mn-vault/edition.lock` and
refusing if the directory is owned by the other edition; (2) **install-time**: a `preinstall`
guard refuses `npm install` when the other edition's lock exists; (3) **artifact**: each
package's `files` allowlist physically omits the other edition's binary. This is a
safety/integrity control, **not** a cryptographic one — it does not defend against root or a
hand-edited lock (consistent with the same-UID/root out-of-scope stance). Switching editions:
remove the current one + its lock, then install the other. The sealed seed is
edition-agnostic; only the signing surface is exclusive, so **re-sealing is not required** to
switch.

---

## ⚠️ CONFIRMED vs INFERRED — read before trusting this

**Plain:** some of how this talks to the Midnight libraries is verified; some is still an
educated guess until you run the type-check (`npx tsc --noEmit`) on your machine. Where we're
unsure, the code is built to **refuse rather than guess** — it fails safe, it doesn't wing it.

**Technical — CONFIRMED** against `@midnight-ntwrk/ledger-v8` 8.0.3 on disk: `signData`,
`createKeystore`, `HDWallet.fromSeed → selectRoles → deriveKeysAt`,
`balanceUnboundTransaction → recipe → finalizeRecipe` (shape from official utils.ts). ✅

**Technical — INFERRED** (confirm with `npx tsc --noEmit`, then paste errors to fix): exact
keystore accessor names (`getVerifyingKeyHex`/`getBech32Address`); the decode path into
`UnshieldedOffer` inputs/outputs (if wrong, the guard decodes nothing and **fails closed** —
safe, but nothing signs until corrected); the `ttl` type; finalize-vs-prove ordering; and
**the per-input vs per-segment signing granularity** — the one place where being wrong is
unrecoverable, so the code makes the uncertain case **throw** rather than guess.

**Plain bottom line:** before you ever point this at a **real-money (mainnet)** seed, have a
second security expert review the signing path. One reviewer isn't enough when a mistake
can't be undone. Full detail in `HANDOFF.md`.

---

## Scope (what this protects, and what it doesn't)

- **IN — plain:** the AI can never read your seed or any key derived from it.
  *Technical:* the seed + all derived secret keys never reach any AI-reachable process.

- **OUT (by design) — plain:** this is **not** built to stop another program *you* run on
  your *own* machine from snooping the signer's memory while it's unlocked. Apple avoids most
  of this by not staying running; orange keeps keys warm but gates every signature behind your
  out-of-band approval.
  *Technical:* a malicious **same-UID** process reading vault memory is out of scope. The
  threat model is "the AI tooling I invited in," not "other processes running as me." Note the
  approval gate already closes the same-UID *USE* path (a background process can't forge a
  valid approval); what remains out of scope is same-UID *memory reading* and root. The
  upgrade kit (sandbox, peer-cred, remote/HSM signer) is parked in `HANDOFF.md`.
