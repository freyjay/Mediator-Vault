# Verifying a clean install (clone → install → typecheck → test)

This document exists so anyone — a contributor, an auditor, or future-you — can confirm
that a fresh clone of this repository downloads and builds correctly, **without needing any
prior context**. If a step here turns out to be wrong, fix THIS file: the repo should be the
source of truth, not anyone's memory.

> **Status of this doc:** written from the project authors' knowledge before the first
> end-to-end clone-test was completed. Steps marked **[EXPECTED]** are what we believe should
> happen but had not yet been confirmed on a clean machine at the time of writing. After a
> real clone-test, replace **[EXPECTED]** notes with **[CONFIRMED]** (or correct them).

---

## What "clean install" actually proves

Two separate things, and it's worth knowing which is which:

1. **Distribution integrity** — a stranger who clones the repo gets a *complete* tree (no file
   referenced-but-missing, no broken paths) and `npm install` succeeds. This catches the
   classic "works on my machine because of an uncommitted file" failure.
2. **SDK verification** — `npx tsc --noEmit` type-checks the signing core (`src/sign-core.ts`)
   against the **real, pinned Midnight SDK** packages. Until this passes on a clean install,
   the ~39 SDK symbols the signing path uses are *inferred*, not verified. This is the gate
   before trusting the vault with anything real. See `VERSION` and the `pin-rationale` field
   in `package.json`.

A green test suite (`npm test`) proves the *logic we control* is correct (103 assertions; see
`tests/TEST-CATALOG.md`). It does **not** exercise the live SDK — that is what the typecheck and,
later, a preprod testnet dry-run are for.

---

## Prerequisites

- **Node.js** — built and pinned against Node v22.x (`@types/node` is pinned to the 20.x line
  for the type surface; runtime tested on v22). Any recent LTS should work.
- **npm** — ships with Node.
- **git** — to clone.
- No global TypeScript needed — the correct compiler (`typescript` 5.9.3) installs locally via
  `npm install`. **Do not** install a global `tsc`.

---

## The steps

Run these from a SCRATCH directory (e.g. `/tmp`), NOT inside your working copy or any folder
that already has a vault installed — you want a genuinely fresh tree.

```bash
cd /tmp
git clone <REPO_URL> clone-test
cd clone-test
ls
```

**[EXPECTED]** `ls` shows the vault at the repo root: `src/ tests/ scripts/ editions/
package.json tsconfig.json VERSION README.md WORKFLOW.md HANDOFF.md`. (There may also be
scaffold leftovers like `config/ tasks/ CLAUDE.md` if they have not been removed yet — these
are harmless template files, not part of the vault.)

```bash
npm install
```

**[EXPECTED]** Installs the dependencies and ends with `0 vulnerabilities` (or a small,
reviewed count). One or two **deprecation warnings are normal** and harmless. The dependencies
that must resolve:
- `@midnight-ntwrk/ledger-v8` @ 8.0.3
- `@midnight-ntwrk/wallet-sdk-hd` @ 3.0.2
- `@midnight-ntwrk/wallet-sdk-unshielded-wallet` @ 2.1.0
- `@midnight-ntwrk/wallet-sdk-facade` @ 3.0.0
- `argon2` (^0.41.1), plus dev tooling (`typescript` 5.9.3, `tsx`, `@types/node`).

> **[EXPECTED — watch for this]** If the `@midnight-ntwrk/*` packages fail to resolve from the
> public npm registry (they may be hosted on a separate registry or require a scope config),
> `npm install` will error on those. If that happens, that is a real distribution finding:
> document the registry/config a consumer needs, or vendor the dependency. (Unconfirmed at
> time of writing — the clone-test will reveal it.)

```bash
npx tsc --noEmit
```

**[EXPECTED]** This runs the locally-installed compiler against `tsconfig.json` (strict mode,
NodeNext, `noEmit`). Two possible outcomes, both useful:
- **Silent (no output)** → the signing core type-checks against the real SDK. The inferred
  symbols are now **verified**. This is the milestone.
- **Type errors** → real mismatches between our code and the installed SDK surface. This is
  exactly what this step exists to find. The most likely areas (the symbols we could only
  infer without running the SDK): keystore accessors (`getVerifyingKeyHex` / `getBech32Address`
  / `signingKeyFromBip340` / `signData` / `signatureVerifyingKey`), `UnboundTransaction`
  (de)serialize, `Intent.deserialize` signature arguments, the
  `balanceUnboundTransaction → recipe → finalizeRecipe` shape, and per-input-vs-per-segment
  signing granularity. If errors appear here, capture them — they drive the next fix round.

> **If `npx tsc` offers to install `tsc@2.0.4`:** say **NO**. That is an abandoned, unrelated
> package. The real compiler is the `typescript` devDependency that `npm install` just placed in
> `node_modules`. If `npx` prompts to install anything, it means `npm install` did not complete —
> fix that first.

```bash
npm test
```

**[EXPECTED]** Runs all 8 suites; should report **103 assertions passed, 0 failed** (see
`tests/TEST-CATALOG.md` for the per-check catalog). These tests do not need the SDK — they
exercise the guard/signing/approval *logic* against replicated models and the real shared
helpers.

---

## What a clean run looks like (fill in after first real clone-test)

| Step | Expected | Confirmed? | Notes |
|---|---|---|---|
| `git clone` | full tree at root | ⬜ | |
| `npm install` | succeeds, deps resolve | ⬜ | watch @midnight-ntwrk registry |
| `npx tsc --noEmit` | silent OR documented errors | ⬜ | the SDK gate |
| `npm test` | 103 passed | ⬜ | |

---

## If something fails

- **A file is missing after clone** → it was probably git-ignored or never committed. Check
  `.gitignore` didn't exclude something needed, and that it was added (`git status` in your
  working copy).
- **`npm install` fails on `@midnight-ntwrk/*`** → registry/scope issue (see note above).
- **`npx tsc` reports SDK errors** → expected if the inferred symbols were wrong; capture the
  errors and treat as the next fix round. Do NOT ship to mainnet until this is clean.
- **`npm test` fails** → a logic regression; the failing assertion name maps to an entry in
  `tests/TEST-CATALOG.md`.

---

## Beyond this doc (the real finish line)

A clean clone + install + typecheck + test means the package is **distributable and its
controlled logic is sound**. It does NOT mean the vault is proven end-to-end. Before trusting
it with a mainnet seed:

1. **Preprod testnet dry-run** — seal a throwaway seed, sign one real transaction, confirm it
   submits. This is the only thing that exercises the full SDK signing path live.
2. **Second human cryptographer review** — specifically the `signIntents` per-input signing
   path (the one area where a wrong inference is unrecoverable). One reviewer is not enough for
   irreversible stakes.

See `HANDOFF.md` §6 and the "Known coverage gaps" section of `tests/TEST-CATALOG.md`.
