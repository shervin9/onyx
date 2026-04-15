# onyx

A QUIC-based terminal multiplexer client/server — a faster, more reliable
replacement for mosh.

- **Instant reconnect** — survives laptop sleep, Wi-Fi switches, mobile
  roaming.  Session stays alive on the remote; you're back in tmux within
  milliseconds of reconnecting.
- **Self-bootstrapping** — runs `onyx user@host` for the first time and it
  installs + builds the server for you via SSH.  No manual setup on the remote.
- **Secure by default** — TOFU cert pinning (like SSH) after the first
  connection.  No CA required.
- **Low-bandwidth mode** — `--low-bandwidth` batches terminal traffic more
  aggressively for unstable links and AI CLI workflows.
- **Works through NAT** — QUIC over UDP punches through most NAT without
  extra firewall rules.
- **GPU-ready status bar** — tmux status bar shows live CPU, RAM, GPU%, VRAM.

---

## Install

```bash
curl -fsSL https://useonyx.dev/install.sh | sh
```

**Platforms:** Linux x86_64, Linux arm64, macOS Apple Silicon

Or download a binary directly from the
[Releases](https://github.com/shervin9/onyx/releases) page.

---

## Quickstart

```bash
# Connect to a host (bootstraps server on first run)
onyx user@192.0.2.1

# Use an SSH config alias
onyx hetzner-dev

# Custom QUIC port
onyx user@host:7373

# Skip SSH fallback if QUIC fails
onyx --no-fallback user@host

# Poor connection? Use lower-chattiness terminal batching
onyx --low-bandwidth user@host

# Transparent SSH transport for ProxyCommand
onyx proxy host 22
```

On first connect to a new host you'll see:

```
onyx: permanently added '192.0.2.1:7272' (sha256:ab12cd…) to known hosts.
```

Subsequent connects are silent unless the server certificate changes.

---

## How it works

```
onyx user@host
  │
  ├─ SSH (one round-trip) ──→ check source hash, open firewall, read fingerprint
  │                          (builds + starts server on first run)
  │
  └─ QUIC/UDP ─────────────→ persistent PTY session in tmux
                              reconnects transparently on network drop
```

The server binary is **never shipped manually**.  The client embeds the server
source at compile time and uploads + builds it when the source hash changes.
Remote files live in `~/.local/share/onyx/`.

---

## Session persistence

Disconnect and reconnect as often as you like — you always land back in the
same tmux session.

```
⚡  onyx — connection lost · 12s  reconnecting…
```

The counter shows while onyx is reconnecting.  It disappears the moment the
connection is restored.

---

## Requirements

**Client:** Linux or macOS (Apple Silicon).

**Server:** Linux (x86_64 or arm64), with:
- SSH access
- `curl` (to install Rust if not present)
- UDP port 7272 open in your cloud provider's firewall (see below)

---

## Cloud firewall

Open the UDP port explicitly. onyx no longer edits host firewalls during
bootstrap.

**Cloud-provider and host firewalls must be opened manually:**

| Provider | Where |
|---|---|
| Hetzner | Console → Firewall → inbound UDP 7272 |
| AWS | EC2 Security Group → inbound UDP 7272 |
| GCP | VPC → Firewall rules → UDP 7272 |

One-time, then you never touch it again.

---

## Scroll, copy, mouse

onyx uses tmux, so all tmux shortcuts work:

| Action | Keys |
|---|---|
| Enter scroll mode | `Ctrl-b [` |
| Scroll | Arrow keys / PgUp / PgDn |
| Copy | `y` or `Enter` in copy mode |
| Mouse scroll | Enabled by default |

---

## Known-hosts file

Cert fingerprints are stored in `~/.local/share/onyx/known_hosts`.

To remove a host (e.g. after rebuilding the server):

```bash
sed -i '/192.0.2.1:7272/d' ~/.local/share/onyx/known_hosts
```

---

## Build from source

```bash
git clone https://github.com/shervin9/onyx
cd onyx
cargo build --release
# binary at target/release/onyx
```

Requires Rust 1.75+.

---

## Roadmap

- **v0.2** — port forwarding (`--forward 8888:8888` for Jupyter / TensorBoard)
- **v0.3** — live resource metrics in status bar (GPU%, VRAM, CPU, RAM)
- **v0.4** — multi-server fan-out (`onyx gpu-1 gpu-2 gpu-3`)
- **v0.5** — file sync (`--sync ./src:/remote/src`)
