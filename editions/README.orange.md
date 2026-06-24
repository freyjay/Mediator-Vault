# mn-vault-daemon  🍊 (Orange edition · Path B)

You installed the **signing daemon**. It holds the unlocked keys and exposes a
`0600` Unix socket so a pipeline can request signatures without a human present
each time. The one-shot CLI (`dist/sign-once.js`) is not shipped here.

## ⚠️ The trade-off you accepted
While the daemon runs, **any process under your user account — including an AI
running as you — can request a signature** over the socket, bounded only by the
guard's policy and the rate limit. The daemon never reveals the seed and refuses
anything it can't decode, but it cannot by itself tell your legitimate pipeline
apart from another same-uid process. This is the cost of unattended automation.
If you sign only occasionally, prefer the **apple** edition (`mn-vault-sign`),
which has no listening surface at all.

## Use
```bash
vault-seal preprod                 # one-time: encrypt your seed (trusted terminal)
vault                              # start the daemon; enter master password
#   socket: ~/.mn-vault/vault.sock (0600). Keys auto-clear when idle.
#   Ctrl-C waits for any in-flight signing, then locks.
```

## Mutual exclusivity
This machine may have **only one** edition. If you ever installed `mn-vault-sign`
(apple), remove it first:
```bash
npm rm -g mn-vault-sign && rm ~/.mn-vault/edition.lock
```
The daemon will refuse to run if the apple edition owns this machine. If you want
orange, remove apple.
