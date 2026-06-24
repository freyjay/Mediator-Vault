# mn-vault-sign  🍎 (Apple edition · Path A)

You installed the **one-shot signer**. There is **no daemon and no socket** in this
package — `dist/vault.js` is not shipped here. Nothing listens; nothing can be
triggered to sign without you.

## Use
```bash
vault-seal preprod                 # one-time: encrypt your seed (trusted terminal)
vault-sign tx.hex --purpose deploy --desc "..." --out finalized.hex
```
You run `vault-sign` by hand each time something needs signing. It unlocks, signs
once, writes the finalized tx, and exits with keys zeroed.

## Why you'd pick this
You sign **occasionally** (e.g. deploy every few days). Because nothing is listening,
the "can an AI or other process sign without me?" question cannot arise — there is no
surface to call.

## Mutual exclusivity
This machine may have **only one** edition. If you ever installed
`mn-vault-daemon` (orange), remove it first:
```bash
npm rm -g mn-vault-daemon && rm ~/.mn-vault/edition.lock
```
`vault-sign` will refuse to run if the daemon edition owns this machine — and vice
versa. If you want apple, remove orange.

The sealed seed itself is edition-agnostic; only the signing surface is exclusive.
