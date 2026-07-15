# Security Policy

This repository is the end-to-end-encryption core of the Lewo client, published for
independent review. We welcome responsible disclosure from the security community.

## Reporting a vulnerability

Please report security vulnerabilities **privately** — do not open a public issue.

- **Email:** security@lewohq.com
- Include a description, the affected file or component, reproduction steps, and
  impact. A proof-of-concept — ideally a failing test in this repo — helps a lot.
- We acknowledge within a few business days and keep you updated through
  remediation.
- Please allow reasonable time to fix before any public disclosure.

## Scope

**In scope**

- The cryptographic primitives and their usage (`SodiumCrypto`, `AuthenticatedEncryption`).
- The protocol engines: X3DH, Double Ratchet, Sender Keys, the sealed-sender
  wrapper, the channel/group message ciphers, and the encrypt/decrypt pipelines.
- The trust mechanisms: device cross-signing, admin-signed rosters, signed-pre-key
  verification, fingerprints / Safety Numbers, and replay protection.

**Out of scope**

- The backend server and network transport (not part of this repository).
- Attacks that require an already-compromised device. Like every end-to-end system,
  Lewo cannot protect data on an endpoint an attacker already controls — keys must
  be in memory to encrypt and decrypt.

## Cryptographic guarantees

- **1:1 and business chats** — X3DH key agreement and the Double Ratchet: forward
  secrecy and post-compromise security.
- **Groups** — per-sender Sender Keys with replay protection: forward secrecy.
- **Channels** — encrypted posts and comments.
- **Multiple devices** — each device is cross-signed by your primary device, so the
  server cannot introduce an unsigned "ghost" device unnoticed.
- **Identity** — trust-on-first-use, with Safety Numbers to verify a contact out of
  band.

The server only ever holds ciphertext and public keys — never a private key.

### Design boundaries

Stated plainly, so you can reason about the model:

- The server routes ciphertext, so it can see routing metadata — who communicates
  with whom, and when.
- Post-compromise security applies to 1:1 and business chats; groups and channels
  provide forward secrecy.
- Call media is end-to-end encrypted; call signaling is not.
- This core has not yet had an independent third-party cryptographic audit —
  making that straightforward is part of why it is public.

The full threat model is in the [README](README.md#scope-and-boundaries).

## License

Released under [GPL-3.0-only](LICENSE).
