# mn-vault — Test Catalog (103 checks)

This catalogs every assertion in the test suite: what it verifies, how, and the
threat it defends against. It exists so a contributor can audit coverage, find
gaps, and know what a failure would mean.

**Run:** `npm test` (all suites) or `node tests/<suite>.test.mjs` (one suite).
**Count (verified):** 103 assertions across 8 suites, all passing.

> **Scope note — important for contributors.** These are unit/logic tests. The guard,
> signing-policy, decode, and approval logic are re-implemented ("replicated") inside the
> test files and exercised against crafted inputs; the *shared display/parse helpers* are
> imported from real source. This proves the **policy and wiring** are correct. It does NOT
> exercise the live Midnight SDK — `sign-core.ts` rests on ~39 inferred SDK symbols that only
> `npx tsc --noEmit` + a preprod testnet dry-run can confirm. A green suite means "the logic
> we control is correct," not "verified end-to-end against the chain."

| Suite | Checks | What it covers |
|---|---|---|
| guard | 11 | the authoritative decode+policy gate (fail-closed) |
| signing | 9 | per-input signature policy (no silent reuse) + size cap |
| lifecycle | 11 | key-clearing safety around in-flight operations |
| decode | 21 | honest decode, network/AAD, token honesty, DoS caps |
| runtime | 17 | hostile-input survival (no crash, no fail-open) |
| edition | 14 | apple-XOR-orange mutual exclusion + atomic lock |
| approval | 9 | out-of-band human approval gate (Path B) |
| display | 11 | terminal-injection sanitizer + digit grouping |

---

## 1. guard.test.mjs — 11 checks
*The guard is the authoritative gate: it decodes the balanced transaction and refuses
anything it cannot vouch for. Every check here asserts fail-closed behavior.*

**Fail-closed on unreadable/empty**
1. **empty tx (no intents) refused** — a transaction with zero intents has nothing to authorize; signing it would be a no-op signature. Refuse. *Threat: blind-signing an empty/meaningless tx.*
2. **intents present, zero offers refused (anti-blind-sign)** — intents exist but none decode to a readable unshielded offer. We cannot show the human what they'd sign, so we refuse rather than sign blindly. *Threat: signing a tx whose effect we can't display.*
3. **intent with readable offer allowed** — the positive control: a well-formed tx with a decodable offer passes. *Confirms the guard isn't refusing everything.*

**Network cross-check**
4. **mainnet request on preprod vault refused** — the request's declared network must match the vault's sealed network. Mismatch → refuse. *Threat: signing a mainnet tx with a key the user intended only for testnet.*
5. **matching network allowed** — positive control: preprod request on preprod vault passes.
6. **no network in ctx allowed (optional)** — when the request omits a network, the guard doesn't fabricate a mismatch. *Confirms optional field handled without false refusal.*

**Purpose allowlist**
7. **bad purpose refused** — `ctx.purpose` must be in the allowlist (`deploy`/`register-dust`/`interact`/`other`). `drain-wallet` is rejected. *Threat: an unconstrained purpose string bypassing intent.*

**Value ceiling (when `MN_MAX_OUTPUT_ATOMS` is set)**
8. **output over cap refused** — a single output exceeding the per-output ceiling is rejected.
9. **output under cap allowed** — positive control: under-cap output passes.
10. **R6: 3×400 (=1200) over total cap 1000 refused** — many individually-under-cap outputs that SUM past the ceiling are refused. *Threat: splitting a large drain into many small outputs to slip under a per-output cap.*
11. **R6: 2×400 (=800) under total cap 1000 allowed** — positive control: a total under the cap passes.

---

## 2. signing.test.mjs — 9 checks
*Proves the signing step applies one distinct signature per input and never reuses a
single signature across inputs — and that malformed sizes are rejected before signing.*

**No silent signature reuse (finding C)**
12. **single input uses segment sig** — one input gets its own signature.
13. **multi-input missing slots refused (no reuse)** — if some inputs lack their own signature, we refuse rather than pad with a reused one. *Threat: a tx that appears fully signed but reuses one signature, which would fail at submit (after we'd reported success) or be malformed.*
14. **multi-input with all per-input sigs allowed** — positive control: every input independently signed → pass.
15. **multi-input partial sigs refused** — partial signing (slot 1 of 2 missing) is refused.
16. **zero inputs ok** — a tx with no inputs to sign is handled without error.

**Size cap (finding R)**
17. **oversized hex refused** — input beyond the max byte cap is rejected before processing. *Threat: a same-uid caller streaming a huge payload to exhaust memory.*
18. **normal-size hex accepted** — positive control.
19. **empty hex refused** — empty input rejected.
20. **non-hex refused** — non-hexadecimal input rejected (must be a serialized tx).

---

## 3. lifecycle.test.mjs — 11 checks
*The warm-key daemon must never zero its keys out from under an in-flight signing
operation, and must clear them when genuinely idle. This suite proves the busy-guard.*

**Keys cannot be cleared mid-signing (finding J)**
21. **clearKeys() refused while op in flight** — a clear request during signing returns false (does not clear). *Threat: a race that wipes keys mid-sign, corrupting the operation.*
22. **keys still live during op (not cleared)** — confirms keys remain usable throughout the operation.
23. **in-flight op completed successfully** — the operation finishes despite the attempted clear.
24. **clearKeys() succeeds after op finishes** — once idle, clearing works.
25. **op threw as expected** — sets up the throw path.
26. **busy released after throw (not stuck busy)** — if a signing op throws, the busy flag is released (via the mutex chain), so the daemon isn't wedged. *Threat: one failed op permanently blocking the signer.*
27. **clearKeys() succeeds after a thrown op** — clearing works after a throw.
28. **signing after clear fails closed (LOCKED)** — once keys are cleared, further signing is refused with LOCKED. *Threat: signing against zeroed/garbage key memory.*
29. **idle tick skips while busy** — the idle timer does not clear keys mid-operation.
30. **idle tick clears when idle past deadline** — keys auto-clear after the idle interval.
31. **idle tick waits before deadline** — keys are NOT cleared before the idle interval elapses.

---

## 4. decode.test.mjs — 21 checks
*The decoder turns an opaque SDK transaction into a human-readable summary. It must
decode HONESTLY — never coerce garbage into a confident-looking value — and bind the
sealed file to its network. Includes the R5 DoS caps.*

**Honest decode (EE)**
32. **output with object recipient refused (false-confidence)** — a recipient that isn't a readable string is marked unreadable, and any unreadable output makes the guard refuse. *Threat: showing the human `[object Object]` or a coerced value and signing anyway.*
33. **output with readable recipient allowed** — positive control.
34. **negative value refused** — a negative value is unreadable → refuse.

**Zero-effect refusal (DD)**
35. **zero-effect deploy refused** — a tx with no inputs and no outputs for a purpose that should have effect is refused.
36. **zero-effect allowed for register-dust** — the one purpose where an empty unshielded shape is legitimate is allowed. *Confirms the exception is scoped.*

**Network normalization (KK)**
37. **typo "mainet" rejected** — an unknown network string throws (not silently accepted).
38. **"MAINNET" normalized ok** — case is normalized to the canonical id.
39. **" Preprod " trimmed+lowered** — surrounding whitespace and case are normalized.

**AAD binds networkId — tamper detection (MM)**
40. **correct network AAD decrypts** — the sealed file decrypts only with the matching network in its AAD.
41. **relabeled network AAD fails (tamper detected)** — editing the stored network label breaks decryption (GCM auth fails). *Threat: moving a sealed seed to a different network by editing the file.*

**Token-field honesty (TT)**
42. **absent token → readable (native)** — a missing token field legitimately means native.
43. **string token → readable** — a string token id is accepted.
44. **object token → UNreadable (not mislabeled native)** — a non-string token is marked unreadable rather than silently labeled native. *Threat: a custom token being displayed as native.*

**Guard normalizes ctx.network (VV)**
45. **ctx "Preprod" matches preprod (no false mismatch)** — request-side network is normalized before comparison.
46. **ctx mainnet rejected on preprod vault** — mismatch still refused after normalization.
47. **ctx unknown net rejected** — an unknown request network is refused.

**Busy as counter — overlap-safe (RR)**
48. **clear refused while 2 brackets active** — the busy guard is a counter, not a boolean, so overlapping operations are tracked correctly; clear is refused while any are active. *Threat: a boolean flag being reset by an inner op while an outer op is still running.*
49. **clear allowed after all brackets exit** — once the counter returns to zero, clearing works.

**Decode DoS caps (R5)**
50. **R5: >1000 intents → refuse (fail-closed)** — a tx with more than MAX_INTENTS is treated as undecodable. *Threat: attacker-controlled data driving an unbounded decode loop (CPU/memory DoS) while holding the mutex.*
51. **R5: >10000 outputs → refuse (fail-closed)** — more than MAX_OUTPUTS is refused.
52. **R5: normal 3-intent tx → not tripped** — positive control: a normal tx is unaffected by the caps.

---

## 5. runtime.test.mjs — 17 checks
*Throws hostile, malformed, and adversarially-shaped inputs at the guard to prove it
SURVIVES (no crash) and FAILS CLOSED (never fail-open) on every one.*

**Hostile inputs the guard must survive (PASS 7)**
53. **tx=null → refused (not crash)** — a null transaction is refused, not a crash.
54. **tx=undefined → refused** — undefined refused.
55. **tx=number → refused** — a number where a tx is expected is refused.
56. **tx=string → refused** — a bare string is refused.
57. **intents=plain object (no keys fn) → refused** — an intents value lacking a `.keys()` method yields no intents → refuse.
58. **intents.keys is not a function → refused** — same, defensively.
59. **intents.keys() throws → caught as undecodable** — an exception while enumerating is caught and converted to a refusal.
60. **intent getter throws → caught** — a throwing property getter is caught.
61. **outputs with throwing iterator → caught** — a malicious iterator that throws is caught.
62. **value = 10000-digit number → parses or refuses, no hang** — an enormous numeric string doesn't hang the parser. *Threat: algorithmic DoS via a pathological number.*
63. **value="0x10" now REFUSED (decimal-only)** — hex-looking values are refused, not silently read as 16. *Threat: a value the human reads as one number but the parser reads as another.*
64. **value="1e9" (sci notation) → refused** — scientific notation is refused (decimal-only).
65. **recipient literally "[object Object]" → refused** — the canonical coercion-garbage string is refused.
66. **ctx.purpose=object → refused** — a non-string purpose isn't in the allowlist → refuse.
67. **ctx.purpose=number → refused** — numeric purpose refused.
68. **ctx.purpose=null → refused** — null purpose refused.
69. **ctx.network=object → normalize throws → GuardError** — a non-string network is refused via the normalizer.

---

## 6. edition.test.mjs — 14 checks
*Enforces that exactly one signing edition (apple OR orange) is active on a machine,
via an atomic lock. Prevents accidentally running a daemon on an "apple-only" machine.*

**Mutual exclusion: apple XOR orange**
70. **fresh: claim sign succeeds** — on a fresh machine, the one-shot signer claims the lock.
71. **lock now says sign** — the lock records the claiming edition.
72. **re-claim sign succeeds (idempotent)** — the same edition re-claiming is a no-op success.
73. **claim daemon on a sign machine REFUSES** — the other edition is refused while the lock is held. *Threat: both signing surfaces live at once.*
74. **lock still says sign (unchanged by refused claim)** — a refused claim doesn't alter the lock.
75. **fresh: claim daemon succeeds** — daemon claims cleanly on a fresh machine.
76. **claim sign on a daemon machine REFUSES** — symmetric refusal.
77. **lock still says daemon** — unchanged by the refused claim.
78. **daemon refused while sign lock present** — explicit re-test of the cross-edition refusal.
79. **after removing lock, daemon claims successfully** — removing the lock allows switching editions.
80. **lock now says daemon (switched)** — the switch is recorded.

**Atomic exclusive claim (R1/R2)**
81. **R1/R2: second claimant cannot overwrite an existing lock** — uses atomic `O_EXCL` create; a second simultaneous claimant cannot clobber the lock. *Threat: a TOCTOU race where two starts both pass the check.*
82. **R1/R2: lock still says daemon (atomic create held)** — the original claim holds.
83. **R1/R2: unreadable lock → refuse (fail-closed)** — a torn/garbage lock file is refused rather than blindly reclaimed. *Threat: masking a second live process by overwriting a corrupt lock.*

---

## 7. approval.test.mjs — 9 checks
*Path B's out-of-band human approval gate. The daemon cannot sign until a human approves
in a separate process, authenticated by a pairing code that lives only in memory.*

**Approval gate (human-carried pairing)**
84. **correct pairing code approve → approve** — a verdict HMAC'd with the right pairing code, for the right session/tx, releases the signature.
85. **human deny → deny** — an explicit deny refuses the signature.
86. **AC1: forged approve with wrong code → DENY (code never on disk)** — an attacker who can read every queue file still cannot forge an approval, because the pairing code is never written to disk. *Threat (the central one): a same-uid process forging approvals. Closed: forgery now requires guessing the code online or reading process memory.*
87. **AC2: verdict from a different session → DENY** — a verdict bound to a different pairing session is rejected.
88. **approve for wrong digest → DENY** — an approval is bound to the exact transaction digest; a swapped tx is refused. *Threat: approving tx A but signing tx B.*
89. **AC3: verdict pre-dating the request → DENY (post-dating check)** — a verdict file created before the request was posted is rejected. *Threat: pre-planting an approve verdict for a guessed id.*
90. **no verdict before timeout → DENY** — no human response within the timeout → refuse (fail-closed).
91. **BG5: aborted wait returns deny** — when shutdown fires, a pending approval is abandoned as deny.
92. **BG5: returned promptly (≪ the 10s timeout)** — the abort is prompt, not a full-timeout hang. *Threat: Ctrl-C appearing to hang while a walked-away human never answers.*

---

## 8. display.test.mjs — 11 checks
*The approval/receipt terminal IS the security surface — the human decides based on what
they see. This suite proves a crafted transaction cannot spoof that display.*

**Terminal-injection sanitizer (AF6)**
93. **ESC (0x1b) removed** — the escape byte that begins ANSI sequences is stripped.
94. **no raw ESC sequence survives** — no `ESC[` control sequence passes through.
95. **newline/CR stripped (can't inject new prompt lines)** — newlines/carriage returns are removed so a field can't fake additional prompt lines. *Threat: injecting a fake "Approve? y" line.*
96. **BEL (0x07) stripped** — the bell character is removed.
97. **replacement char inserted for control bytes** — stripped control bytes become a visible `\uFFFD` so the human sees something was removed.
98. **legible text retained** — sanitization doesn't destroy legitimate content (addresses remain readable).

**Length cap (AF6)**
99. **over-long field capped** — an absurdly long field is truncated with a visible marker, so it can't push the prompt off-screen. *Threat: scrolling the real prompt out of view.*

**Digit grouping for magnitude readability (AF7)**
100. **5000000 → 5,000,000** — atom amounts are grouped so magnitude is readable.
101. **100 → 100 (no comma)** — small numbers are unchanged.
102. **1000000000 → 1,000,000,000** — large numbers grouped correctly.
103. **non-decimal falls back to sanitized** — a non-numeric value is sanitized rather than mis-grouped. *Threat: misreading `5000000` as 5 instead of 5 million when approving.*

---

## Known coverage gaps (where contributors should focus)

These are deliberately NOT covered by this suite and require other verification:

- **The 39 inferred SDK symbols in `sign-core.ts`** — keystore accessors, `UnboundTransaction` (de)serialize, `Intent.deserialize` signature args, `balanceUnboundTransaction`→recipe→`finalizeRecipe` shape, and per-input-vs-per-segment signing granularity. *Verify with `npx tsc --noEmit` against the installed `@midnight-ntwrk/ledger` + a preprod testnet dry-run.*
- **Per-input signing-authority semantics (R7)** — the guard cannot verify, without the SDK, that the tx isn't signing with authority over an input the user didn't intend. *Requires a second human cryptographer review of the `signIntents` path.*
- **Concurrency under a real second approver process (BG3)** — documented as "run one approver"; not exercised by an integration test.
- **The same-uid memory-read boundary** — explicitly out of scope; not testable here (it's an OS/threat-model boundary, not a logic property).
- **End-to-end integration** — these are unit tests against replicated logic; there is no test that starts the real daemon, runs the real approver, and signs a real tx. *That is the preprod dry-run's job.*
