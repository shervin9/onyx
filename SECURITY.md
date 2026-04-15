# Security policy

Onyx is early-stage software. This document describes the trust model, known
limitations, and how to report security issues.

## Trust model (TOFU)

Onyx uses a **Trust-On-First-Use (TOFU)** model for its QUIC transport,
similar in spirit to how OpenSSH handles host keys.

1. On the first connection to a new host, Onyx shows the server's TLS
   certificate SHA-256 fingerprint and asks you to confirm it.
2. If you accept, the fingerprint is pinned in
   `~/.local/share/onyx/known_hosts` alongside `host:port`.
3. On every subsequent connection, the presented fingerprint must match the
   pinned one exactly.

### Fingerprint mismatch behavior

If the server presents a fingerprint that does not match the pinned value,
Onyx **fails hard**. The client refuses the connection, prints a warning
block, and does **not** silently overwrite the stored fingerprint. Trust
state is only ever updated after explicit user confirmation.

To re-trust a host after a legitimate rebuild (for example, after
reinstalling the server), remove the matching line from
`~/.local/share/onyx/known_hosts` and reconnect:

```bash
sed -i '/^host.example.com:7272 /d' ~/.local/share/onyx/known_hosts
```

### SSH bootstrap trust

The initial `onyx user@host` call uses your existing **SSH** credentials to
install or update the remote `onyx-server`. This leverages your existing SSH
`known_hosts` and key-based auth and is outside Onyx's TOFU layer.

## Current limitations

Onyx's verification guarantees are intentionally narrow. The following are
**not** claimed:

- **No CA / no WebPKI.** Certificates are self-signed; trust is purely TOFU
  pinning. This matches SSH-style usage but is weaker than a PKI-backed
  system.
- **No signed releases (yet).** Release binaries are published with SHA-256
  checksums but not cryptographically signed. Verify the checksums in
  `onyx-sha256sums.txt` against what the installer fetches.
- **Best-effort reconnect only.** In proxy mode
  (`ProxyCommand onyx proxy %h %p`), short transport drops are recovered
  within a short grace window. Longer disconnects, or disconnects during
  sensitive SSH state transitions, will terminate the underlying SSH
  session. Onyx does **not** guarantee SSH-session survival across real
  network loss — use `mosh` or native tmux/screen on the remote if you need
  that.
- **Interactive persistence is tmux-backed.** Only the interactive Onyx
  shell gets tmux-style resume; arbitrary SSH-based tools ridden over Onyx
  proxy mode do not.
- **No supply-chain attestation.** The remote `onyx-server` is either an
  uploaded prebuilt binary matched to the remote architecture or built from
  uploaded source via `cargo build --release`. The source hash is checked
  on every bootstrap, but there is no reproducible-build attestation.

## File permissions

Onyx writes state into `~/.local/share/onyx/` with a restrictive umask. The
`known_hosts` file and any private trust material are owned by the user and
not world-readable. Do not copy these files between machines.

## Reporting a vulnerability

Please do **not** file public GitHub issues for security vulnerabilities.

Email: **security@useonyx.dev**

Include:

- A description of the issue and the impact you believe it has
- Steps to reproduce, ideally with a minimal test case
- The Onyx version (`onyx --version`) and platform
- Whether the issue is already public

We aim to acknowledge new reports within a few business days. Coordinated
disclosure is preferred; we will credit reporters unless asked not to.

## Scope

In scope:

- `onyx` client and `onyx-server` remote binary
- TOFU trust handling and `known_hosts` logic
- Bootstrap flow over SSH
- QUIC/TLS handling and fallback paths
- The installer script and release artifacts

Out of scope:

- Vulnerabilities in third-party dependencies that are already tracked
  upstream (please still let us know)
- Denial-of-service that requires an already-trusted authenticated peer
- Issues in example code, docs, or the landing page that have no user
  impact
