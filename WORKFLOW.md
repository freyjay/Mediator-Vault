# mn-vault — How to use it (step-by-step)

This is the friendly walkthrough. Pick your edition, then follow that section.
Each step has a **plain** line (what you do) and a **why** line (what it's for).

---

## First: which edition did you install?

- **🍎 apple (`mn-vault-sign`)** — you sign by hand, one transaction at a time. No
  background process. *Best for occasional signing (e.g. a deploy every few days).*
- **🍊 orange (`mn-vault-daemon`)** — keys stay warm in a running signer, and you
  approve each signature from a second window. *Best for frequent signing.*

You can only have one installed at a time. Not sure? Use apple.

---

## One-time setup (both editions)

```bash
npm install                 # get the libraries
npx tsc --noEmit            # check the code matches the real Midnight SDK (paste errors if any)
vault-seal preprod          # lock your seed in the vault (do this in a trusted terminal, NOT via an AI)
```

- **Plain:** you install, run a quick check, then lock your seed once.
- **Why:** `vault-seal` encrypts your seed so it's never sitting in the open again.
  You'll type your seed once and a master password; after that the seed only ever
  appears, briefly, inside the signer.

> Do the seal step yourself in a normal terminal. Never paste your seed into an AI chat.

---

## 🍎 Apple workflow — sign one transaction

```
   ┌──────────┐     builds unsigned tx      ┌──────────────┐    you run, by hand    ┌─────────────┐
   │   AI /   │ ──────────────────────────► │   tx.hex     │ ─────────────────────► │ vault-sign  │
   │ pipeline │   (no seed involved)        │ (a file)     │                        │ (signs once)│
   └──────────┘                             └──────────────┘                        └──────┬──────┘
                                                                                            │ writes
                                                                                            ▼
                                                                                  finalized.hex (signed)
                                                                                  + finalized.summary.json
```

**Step 1 — the AI builds the unsigned transaction.** It does everything except sign
(it never touches your seed) and saves an unsigned transaction to a file, e.g. `tx.hex`.

**Step 2 — you sign it, by hand, in a trusted terminal:**
```bash
vault-sign tx.hex --purpose deploy --desc "hello-world preprod" --out finalized.hex
```
- **Plain:** this asks for your master password, shows you what's being signed, signs
  it once, writes the finished transaction, and exits.
- **Why:** because *you* ran it, you know this signature is intentional. Nothing is
  left running afterward, so nothing can sign again without you.

**Step 3 — submit it.** The AI (or you) takes `finalized.hex` and submits it to the
network. That file is already signed and carries **no** key, so it's safe to hand off.

That's the whole loop. Repeat per signature.

---

## 🍊 Orange workflow — warm keys + approve from a second window

This uses **two terminal windows**. Think of it like a card reader: the computer
*asks* to charge your card, but nothing happens until *you* press the button.

```
  TERMINAL 1  (the signer)                         TERMINAL 2  (you approve here)
  ┌─────────────────────────────┐                  ┌──────────────────────────────┐
  │  npm run start              │                  │  vault-approve               │
  │                             │                  │                              │
  │  PAIRING CODE:  K7Q2-9XPL  ─┼───── you read ───┼─► type:  K7Q2-9XPL           │
  │                             │   it & type it   │                              │
  │  (waiting for approvals…)   │                  │  paired ✓                    │
  └─────────────┬───────────────┘                  └───────────────┬──────────────┘
                │                                                   │
   AI asks to sign  ─────────────────────────────────────────────► shows you the details:
                │                                                     → recipient  amount  network
                │                                                     Approve? [y/n]
                │  ◄───────────────────────────────────────────────  you type  y
                ▼
       signs & returns the finished tx
```

**Step 1 — start the signer (Terminal 1):**
```bash
npm run start
```
- **Plain:** enter your master password once. It prints a **pairing code** (like
  `K7Q2-9XPL`) and then waits. Leave this window open.
- **Why:** the keys are now warm (ready), so you don't re-enter your password for every
  signature. The pairing code is your "this is really my signer" key for the next step.

**Step 2 — open a SECOND terminal window yourself and start the approver:**
```bash
vault-approve
```
- **Plain:** it asks you to **type the pairing code** from Terminal 1. Type it, press
  Enter. Now this window is where you approve signatures.
- **Why:** typing the code (rather than it being saved to a file) is what keeps an AI or
  other program from approving on its own — only someone who can *see* Terminal 1 and
  *type* into Terminal 2 can release a signature. On Windows, just open another
  PowerShell window and run the same command.

**Step 3 — approve as requests come in.** Each time the AI asks to sign, Terminal 2
shows you the real details:
```
🖊  SIGNATURE REQUESTED — id 3f9a…
   purpose: deploy   network: preprod
   inputs: 1   outputs: 2
     → addr1q9x…   5000000 native
     → addr1q7k…   120000  native   [balancing]
   Approve this signature? type  y  or  n
```
- **Plain:** read what it's signing. Type **y** to allow it, **n** to refuse.
- **Why:** you're seeing exactly what would be signed *before* it happens — your last
  checkpoint.

**Signing a lot at once?** In Terminal 2 you can pre-approve a short burst:
```
budget 5        # auto-approve the next 5 signatures
budget 10m      # auto-approve everything for the next 10 minutes
budget off      # back to approving one at a time
```
- **Plain:** handy when you're running a batch and watching it happen.
- **Why:** it's still you who opened the window and started the budget — keep an eye on
  it; it's not "walk away" mode.

**To stop:** type `quit` in Terminal 2 (no more approvals possible), and press Ctrl-C in
Terminal 1 to lock the signer. It finishes any signature already in progress, then locks.

---

## Good to know (the honest details)

- **One at a time.** The signer handles one signature at a time. If a request is waiting
  for your **y/n**, others wait behind it. If something's stuck, type **n** to clear it.
- **If you walk away.** An un-answered request is automatically **refused** after a couple
  of minutes (default 2). While one is waiting, the keys stay warm a bit longer than the
  idle timer alone — so answer or deny promptly.
- **No approver = no signing.** If Terminal 2 isn't running (or you typed the wrong
  pairing code), the signer can't get approvals, so nothing gets signed. That's on
  purpose — it fails safe.
- **What this protects vs. doesn't.** It stops an AI (or a stray script) from signing
  without you. It does **not** defend against someone with full control of your computer
  (root) or a program that can read another program's live memory — those are out of
  scope by design. For occasional signing, apple avoids even keeping a signer running.
- **Switching editions.** Remove one, delete `~/.mn-vault/edition.lock`, install the other.
  Your sealed seed is reused — you don't re-seal.

---

*Plain summary: apple = you run one command to sign each time. orange = a signer stays
ready and you press “y” in a second window to approve each signature. Either way, nothing
signs without you.*
