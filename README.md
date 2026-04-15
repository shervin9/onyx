# Onyx

Stable remote shell for unreliable networks. QUIC when available, SSH when
it's not. Built for AI CLI workflows, remote development, and DevOps on
flaky links.

- **QUIC first, SSH fallback** — prefers QUIC over UDP 7272; falls back
  transparently to plain SSH when UDP is blocked (disable with
  `--no-fallback`).
- **Self-bootstrapping remote** — on first connect, Onyx provisions the
  remote `onyx-server` over SSH. It prefers uploading a prebuilt binary for
  the remote architecture and only falls back to `cargo build --release` on
  the remote when no matching prebuilt is available.
- **Interactive session persistence** — the interactive Onyx shell runs
  under tmux; short drops reconnect into the same session and scrollback
  within a 5-minute window.
- **Port forwarding** — `onyx --forward LPORT:RPORT user@host` forwards a
  local port to a remote port through the same QUIC connection (repeatable).
- **SSH `ProxyCommand` support** — `onyx proxy %h %p` lets SSH-based tools
  ride Onyx as a transport. Short transport drops are recovered
  best-effort within a 30-second window; longer drops end the underlying
  SSH session.
- **TOFU trust with fingerprint pinning** — first connect prompts for the
  server's SHA-256 fingerprint; subsequent mismatches fail hard. See
  [SECURITY.md](SECURITY.md).

## Install

### Homebrew (coming soon)

```bash
brew install shervin9/onyx/onyx
```

The tap will be available at [`shervin9/homebrew-onyx`](https://github.com/shervin9/homebrew-onyx)
once the first release is tagged. For now, use the shell installer below.

### Shell installer

```bash
curl -fsSL https://useonyx.dev/install.sh | sh
```

Installs the local `onyx` client plus the matching Linux `onyx-server`
companion binaries into `/usr/local/bin`. All artifacts are checksum-verified
against `onyx-sha256sums.txt` from the release.

**Supported platforms:** Linux x86_64, Linux arm64, macOS Apple Silicon.
A Homebrew formula for macOS arm64 is planned.

### Build from source

```bash
git clone https://github.com/shervin9/onyx
cd onyx
cargo build --release
# client:  target/release/onyx
# server:  target/release/onyx-server
```

Requires Rust 1.75+.

## Quickstart

```bash
# Interactive shell (bootstraps the server on first run)
onyx user@host

# SSH config alias
onyx dev-onyx

# Custom QUIC port
onyx user@host:7373

# Local port forwarding (repeatable)
onyx --forward 8888:8888 user@host

# Skip the remote install/start check on subsequent connects
onyx --no-bootstrap user@host

# Hard-require QUIC; do not fall back to SSH
onyx --no-fallback user@host

# Chattier terminal traffic gets batched for flaky links
onyx --low-bandwidth user@host

# SSH ProxyCommand transport for SSH-based tools
onyx proxy host 22
```

First connect to a new host prompts for fingerprint confirmation:

```
onyx: new host host:7272
  fingerprint sha256:ab12cd…
Trust this host? [y/N]
```

After confirmation the fingerprint is stored in
`~/.local/share/onyx/known_hosts` and subsequent connects are silent.

## SSH `ProxyCommand` usage

Drop this into your `~/.ssh/config` to route a host through Onyx:

```
Host dev-onyx
  HostName host.example.com
  User alice
  ProxyCommand onyx proxy %h %p
```

Then `ssh dev-onyx` transports over Onyx. Short drops (under ~30s) reconnect
automatically; longer drops terminate SSH. **This is best-effort
reconnection — not a guarantee that SSH sessions survive real network
loss.** If you need session-level persistence for arbitrary tools, use
`mosh` or run tmux/screen on the remote.

## Bootstrap and install model

Onyx is a **local-install** tool. You install `onyx` on your workstation;
the remote server is provisioned automatically.

- The client connects first over SSH and checks whether a healthy
  `onyx-server` is already running (`remote_status`). If yes, it skips
  straight to QUIC.
- Otherwise it uploads a prebuilt `onyx-server` binary matching the remote
  architecture (looked up in the installer's install dir, `target/release`,
  or a local cross-compile dir).
- If no matching prebuilt binary is available, it uploads the source and
  runs `cargo build --release` on the remote (installing Rust via `rustup`
  if needed).
- Remote install dir defaults to `~/.local/share/onyx/`, falling back to
  `/tmp/onyx` if the home path is not writable. Override with
  `ONYX_REMOTE_DIR=/path onyx user@host`.
- `--no-bootstrap` assumes the remote is already set up and skips the
  install/start check.

Onyx **does not** modify remote firewall rules. Open UDP 7272 at your
cloud provider and on the host firewall once — see below.

## Cloud firewall

Open UDP 7272 on both the cloud-provider firewall and any host firewall
(`ufw`, `firewalld`, etc.).

| Provider | Where |
|---|---|
| Hetzner | Console → Firewall → inbound UDP 7272 |
| AWS | EC2 Security Group → inbound UDP 7272 |
| GCP | VPC → Firewall rules → UDP 7272 |

One-time setup per host.

## Scroll, copy, mouse

Interactive sessions run under tmux, so all tmux shortcuts work:

| Action | Keys |
|---|---|
| Enter scroll mode | `Ctrl-b [` |
| Scroll | Arrow keys / PgUp / PgDn |
| Copy in copy mode | `y` or `Enter` |
| Mouse scroll | On by default |

## Security model

Onyx uses a **Trust-On-First-Use** model with self-signed certs and
fingerprint pinning in `~/.local/share/onyx/known_hosts`. Mismatches fail
hard; trust state is never silently updated. Full details and reporting
instructions are in [SECURITY.md](SECURITY.md).

## Known limitations

- QUIC requires UDP reachability. If UDP is blocked and `--no-fallback` is
  not set, Onyx falls back to SSH.
- Interactive persistence is tmux-backed and scoped to the interactive
  Onyx shell — not to arbitrary tools run over proxy mode.
- Proxy-mode reconnect is a best-effort short-drop recovery path, not a
  guarantee of SSH session survival.
- Release binaries are checksum-verified but not cryptographically signed.
- No reproducible build attestation for the remote server.
- GPU metrics in the tmux status bar require `nvidia-smi` on the remote
  and are best-effort.

## Uninstall

```bash
# remove the client binary
sudo rm /usr/local/bin/onyx /usr/local/bin/onyx-server-linux-*

# remove local trust + config state
rm -rf ~/.local/share/onyx ~/.config/onyx

# remove the remote install on each server
ssh user@host 'rm -rf ~/.local/share/onyx ~/.config/onyx'
```

## License

[MIT](LICENSE).
