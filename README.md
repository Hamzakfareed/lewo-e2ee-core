# lewo-e2ee-core

**The real encryption code that protects messages in [Lewo](https://lewohq.com) — public so you can verify it, not just take our word for it.**

Lewo is an end-to-end-encrypted messenger. This repository is its cryptographic
core: the exact code that agrees on keys and turns messages into ciphertext, so the
server — and we — cannot read them. It's open so anyone can confirm that for
themselves.

## Verify it yourself

```bash
npm install
npm test
```

**517 tests across 31 suites**, all running the real cryptographic primitives and
protocol engines — no mocks. Many are known-answer vectors (fixed inputs with
fixed, expected outputs) that confirm the math is implemented correctly, others
round-trip the actual X3DH handshake and Double Ratchet, and one is a mutation test
that deliberately breaks a cipher to prove the tests actually catch it.

## What it protects

Every conversation type is end-to-end encrypted, and the tests here exercise each:

- **1:1 & business chats** — X3DH key agreement and the Double Ratchet, with
  forward secrecy and post-compromise security.
- **Groups** — per-sender Sender Keys with replay protection.
- **Channels** — encrypted posts and comments.
- **Multiple devices** — your devices are cross-signed by your primary device to
  defend against a server-injected "ghost" device.

The server only ever holds ciphertext and public keys — never a private key.

## Scope and boundaries

This repository is the cryptography only. It contains the crypto **engines** — the
X3DH key-agreement and Double Ratchet, the group Sender-Key ratchet, the
sealed-sender wrapper, the channel/group message ciphers, and the encrypt/decrypt
pipelines — plus the primitives they run on (X25519, Ed25519, XChaCha20-Poly1305,
BLAKE2b, HKDF) and the trust mechanisms (device cross-signing, admin-signed rosters,
fingerprints, safety numbers).

What is **not** here, and lives in the private Lewo app: where keys are stored on
the device (the keychain layer), the session-lifecycle and recovery orchestration
that drives these engines, and the network transport. So this copy can't connect to
Lewo or act as a user — it's a faithful copy of the crypto exactly as the app runs
it, with the storage and plumbing left out.

A few things worth knowing, stated plainly:

- The server routes ciphertext, so it can see who talks to whom and when — there is
  no metadata protection.
- Identity uses trust-on-first-use with cryptographic checks; verify **Safety
  Numbers** for sensitive contacts.
- Groups and channels have forward secrecy but not post-compromise security.
- The core has not yet had an independent third-party audit.

The complete threat model lives in [`SECURITY.md`](SECURITY.md).

## How it's built

Lewo is built by a solo developer, with AI used as a pair-programming tool. The
encryption is tested, reviewed, and reasoned through — which is exactly why it's
here for you to read, line by line.

## Contributing & disclosure

Found something wrong, weak, or unclear? Please tell us. Report security issues
privately to **security@lewohq.com** (see [`SECURITY.md`](SECURITY.md)); anything
else is welcome as an issue.

## License

[GPL-3.0-only](LICENSE)
