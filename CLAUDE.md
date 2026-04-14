# onyx — QUIC-based mosh replacement

A self-bootstrapping terminal multiplexer client/server over QUIC (UDP).
Connects local → remote, auto-installs itself on the remote on first run,
then reconnects transparently on network drops.

---

## Architecture

```
client (onyx)           shared (protocol)        server (onyx-server)
─────────────           ─────────────────        ───────────────────
main.rs                 lib.rs                   main.rs
 ├─ parse_args          Message enum              ├─ QUIC endpoint (quinn)
 ├─ build_target         Hello / Welcome          ├─ pty_task (per session)
 ├─ bootstrap            Resume                   │   ├─ posix_openpt PTY
 │   ├─ remote_status    Input / Output           │   ├─ tmux / shell child
 │   ├─ ensure_rust      Resize                   │   └─ broadcast output
 │   ├─ upload_and_build Close                    ├─ run_session (per stream)
 │   └─ start_server    bincode encoding          └─ gc_task (5-min expiry)
 └─ QUIC loop
     └─ try_once (SIGWINCH handled here)
```

**Transport:** QUIC (quinn 0.11, rustls 0.23/ring). TLS cert self-signed
(server generates at startup with rcgen); client skips verification (MVP).

**Port:** UDP 7272 (`DEFAULT_PORT` in `shared/src/lib.rs`).

**Session model:** PTY lives independently of the network connection.
On reconnect the client sends `Resume{session_id, resume_token}`; server
reattaches to the broadcast stream. GC kills abandoned sessions after 5 min.

---

## Workspace layout

```
Cargo.toml          workspace root (members: shared, client, server)
shared/             protocol crate — Message enum, bincode encode/decode
client/             "onyx" binary  — runs on your local / Mac machine
server/             "onyx-server"  — runs on the remote Linux host
```

---

## Build

```bash
cargo build           # debug (fast, for dev)
cargo build --release # release (for distribution)
```

The server binary is **never shipped manually**. The client embeds the server
source at compile time (`include_str!`) and uploads + builds it on the remote
via SSH, triggered automatically when the source hash changes.

---

## Running

```bash
# SSH alias from ~/.ssh/config
./target/debug/onyx my-server

# Explicit user@host
./target/debug/onyx user@host

# Custom QUIC port
./target/debug/onyx user@host:7373

# Direct QUIC — bare IP bypasses SSH entirely (no bootstrap)
./target/debug/onyx 128.140.63.67

# Don't fall back to plain SSH if QUIC fails
./target/debug/onyx --no-fallback my-server

# Custom SSH identity file
./target/debug/onyx -i ~/.ssh/id_ed25519 my-server
```

---

## Local experiment (no remote needed)

Two terminals on the same machine:

```bash
# Terminal 1 — start the server
./target/debug/onyx-server
# prints: [server] listening on 0.0.0.0:7272

# Terminal 2 — connect (bare IP = direct QUIC, zero bootstrap)
./target/debug/onyx 127.0.0.1
```

This skips all SSH steps and connects instantly. Perfect for developing new
features without needing a remote machine.

---

## Bootstrap flow (SSH mode)

### Fast path — server already running, source unchanged (common case)

```
1 SSH call: verify auth + check hash + check process → all good → done
```

Total: **one SSH connection**, no waiting, straight to QUIC.

### Slow path — first run or source changed

```
SSH call #1  remote_status()     verify auth + check hash/cargo/running
SSH call #2  open firewall       ufw + iptables (OS-level only)
SSH call #3  ensure_rust()       install via rustup (if missing)
SSH call #4  upload_and_build()  5 cat > path uploads + cargo build --release
SSH call #5  start_server()      nohup + poll server.log for "listening on"
```

Subsequent runs with unchanged source skip calls 3–5 entirely.

Remote files live in `~/.local/share/onyx/`. The FNV-1a hash of all
embedded source files (`source_hash()`) determines when a rebuild is needed.

---

## Session / tmux

Server launches tmux with session name `onyx` and a minimal config written
once to `~/.config/onyx/tmux.conf` (never overwrites `~/.tmux.conf`):

```
set-option -g mouse on
set-option -g history-limit 50000
set-option -g status-right "[onyx/quic]"
```

`tmux new-session -A -s onyx` = attach to existing session or create new.
Disconnect + reconnect always lands back in the same session.

**Scroll:** tmux copy mode — `prefix + [`, then arrow keys / PgUp / PgDn  
**Copy:** in copy mode press `y` or `Enter` (depends on tmux version)  
**Mouse:** click to focus panes, scroll wheel for scrollback  

---

## Terminal resize (SIGWINCH)

The client installs a SIGWINCH handler inside the stdin task. Every terminal
resize fires a `Message::Resize{cols, rows}` to the server, which calls
`TIOCSWINSZ` on the master PTY fd. tmux sees the SIGWINCH and redraws.

---

## Why faster than the old bootstrap

| | Before | After |
|---|---|---|
| Server running + unchanged | 5–7 SSH connections | **1 SSH connection** |
| Server not running | 5–7 SSH connections | 2 SSH connections |
| First run (build needed) | 7+ SSH connections | 5 SSH connections |
| Output on fast path | 8 lines of noise | **silent** |

---

## Connection-loss banner

When the QUIC connection drops mid-session (network blip, laptop sleep, Wi-Fi
switch), a live status line appears on the local terminal:

```
 ⚡  onyx — connection lost · 12s  reconnecting…
```

The counter updates every 250 ms. When QUIC reconnects, the banner is erased
before re-entering raw mode so tmux's next redraw is clean. After 5 minutes
without reconnect the banner clears and onyx exits (or falls back to SSH if
it never had a session).

---

## Known issues & fixes

| Issue | Root cause | Fix |
|---|---|---|
| `open terminal failed: terminal does not support clear` | `TERM` unset — server is a nohup daemon | `cmd.env("TERM", "xterm-256color")` in server |
| `Pseudo-terminal will not be allocated` SSH noise | `ssh_capture` was inheriting stderr | Changed to `stderr(null)` in `ssh_capture` and `remote_status` |
| Terminal resize had no effect | No SIGWINCH handler | SIGWINCH → `Message::Resize` inside stdin task |
| `[client] shell exited: shell exited` noise on exit | Redundant log line | Removed; clean exit is now silent |
| Bootstrap slow (5–7 SSH calls) | Separate SSH connection per check | `remote_status()` does everything in one SSH call |
| Race condition on server restart | No delay between kill and start | `sleep 0.5` after `pkill` |
| Server readiness poll too tight | 5 s total | Increased to 10 s (20 × 500 ms) |

---

## Cloud firewall (most common QUIC failure)

OS firewall (ufw/iptables) is configured automatically. **Cloud-provider
firewalls are separate and must be opened manually:**

- **Hetzner:** Console → Firewall → inbound rule: UDP 7272
- **AWS:** EC2 Security Group → inbound: UDP 7272
- **GCP:** VPC → Firewall rules → UDP 7272

Mosh works by default because providers pre-allow UDP 60001–61000. Port 7272
is not pre-allowed anywhere.

Diagnostic: when QUIC fails, the client fetches `server.log` over SSH.
`"incoming from"` in the log = UDP reaches the server (QUIC/TLS issue).
No `"incoming from"` = cloud firewall is dropping the packets.

---

## Next steps — AI/DevOps tool roadmap

### Phase 2 — port forwarding
```bash
onyx my-server --forward 8888:8888   # Jupyter / JupyterLab
onyx my-server --forward 6006:6006   # TensorBoard
onyx my-server --forward 5000:5000   # MLflow
```
Open a QUIC stream alongside the PTY stream, multiplex TCP tunnels over it.
No separate SSH `-L` needed.

### Phase 3 — resource status in status bar
tmux status bar shows live: CPU%, RAM, GPU%, VRAM (nvidia-smi), disk.
Server sends a sidecar metrics stream; client tmux plugin reads it.

### Phase 4 — multi-server
```bash
onyx gpu-1 gpu-2 gpu-3   # split panes, one per server
```
Fan out to N servers, show all in tmux windows or split layout.

### Phase 5 — file sync
```bash
onyx my-server --sync ./src:/path/to/project/src
```
Watch local directory, rsync-over-QUIC on change. Faster than scp, survives
network drops.

---

## Protocol encoding

All messages are bincode-serialized with a 4-byte little-endian length
prefix. Each QUIC stream carries one Hello/Resume + Welcome handshake, then
becomes a continuous bidirectional stream for Input/Output/Resize/Close.

---

## Remote file layout

```
~/.local/share/onyx/
  Cargo.toml              workspace manifest (server + shared)
  shared/Cargo.toml
  shared/src/lib.rs
  server/Cargo.toml
  server/src/main.rs
  target/release/onyx-server    compiled binary
  server.log                    stdout+stderr of running process
  server.pid                    PID of running process
  .server-hash                  FNV-1a hash of last-built source

~/.config/onyx/
  tmux.conf                     mouse on, 50k scrollback
```
