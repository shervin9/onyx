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
  under tmux. Reconnecting within the retention window (12 hours by default,
  in-memory) resumes the same session and scrollback. Retention is
  best-effort: if `onyx-server` restarts, detached sessions are lost.
- **Port forwarding** — `onyx --forward LPORT:RPORT user@host` forwards a
  local port to a remote port through the same QUIC connection (repeatable).
- **SSH `ProxyCommand` support** — `onyx proxy %h %p` lets SSH-based tools
  ride Onyx as a transport. Short transport drops are recovered
  best-effort within roughly two minutes; longer drops end the underlying
  SSH session. This is *not* Mosh-style persistence for arbitrary tools.
- **Resumable remote exec (`onyx exec`)** — run a command as a remote job
  whose output and lifetime survive a client disconnect. Detach with
  `--detach`, reattach with `onyx attach`, snapshot output with
  `onyx logs`, enumerate with `onyx jobs`. `--json` gives structured
  NDJSON events suitable for CI and AI tooling. See
  [Resumable remote exec](#resumable-remote-exec) below.
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

# Resumable remote exec
onyx exec host -- cargo test --workspace
onyx exec gpu-box --detach -- python train.py
onyx jobs gpu-box
onyx attach gpu-box job_a1b2c3d4e5f60718
onyx logs  gpu-box job_a1b2c3d4e5f60718
onyx exec ci --json -- ./deploy.sh
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

Then `ssh dev-onyx` transports over Onyx. Short drops (under ~2 minutes)
reconnect automatically; longer drops terminate SSH. **This is best-effort
reconnection — not a guarantee that SSH sessions survive real network
loss.** If you need session-level persistence for arbitrary tools, use
`mosh` or run tmux/screen on the remote.

## Resumable remote exec

`onyx exec` runs a command on the remote as a **resumable job**. The
remote `onyx-server` owns the child process, captures stdout and stderr
into a bounded ring buffer, and keeps the job alive across client
disconnects. You can reattach to live output, snapshot buffered output,
or enumerate jobs at any time within the retention window.

This is the feature to reach for when:

- you want a long-running command to keep running if your laptop sleeps
  or your Wi-Fi flaps
- you want CI- or agent-friendly structured output (`--json`)
- you want to fire-and-forget a training run or a deploy (`--detach`)
- you want to tail a remote job from a different machine later

### Subcommands

```bash
onyx exec   <target> [--json] [--detach] [--no-bootstrap] -- <cmd...>
onyx jobs   <target> [--json]
onyx attach <target> <job-id> [--json]
onyx logs   <target> <job-id> [--json]
```

### Typical workflow

```bash
# Kick off a long-running job and detach.
$ onyx exec gpu-box --detach -- python train.py
job_a1b2c3d4e5f60718
[onyx] detached; reattach with: onyx attach <target> job_a1b2c3d4e5f60718

# Check status from anywhere.
$ onyx jobs gpu-box
JOB ID                   STATUS     STARTED     EXIT  COMMAND
job_a1b2c3d4e5f60718     detached   4m ago      -     python train.py

# Reattach to live output (the ring buffer is replayed first).
$ onyx attach gpu-box job_a1b2c3d4e5f60718
epoch 12  loss=0.314 …
epoch 13  loss=0.298 …

# Snapshot what's buffered without subscribing to live output.
$ onyx logs gpu-box job_a1b2c3d4e5f60718 | tail -50
```

### JSON mode (for scripts, CI, and AI tooling)

`--json` emits one NDJSON event per line. Events for `onyx exec` /
`onyx attach` / `onyx logs`:

```json
{"type":"started","job_id":"job_...","started_at_unix":1700000000,"command":"cargo test"}
{"type":"stdout","seq":1,"data":"    Finished `test` profile ...\n"}
{"type":"stderr","seq":2,"data":"warning: unused variable ...\n"}
{"type":"gap","oldest_seq":42}
{"type":"finished","exit_code":0,"finished_at_unix":1700000012,"duration_ms":12000}
{"type":"error","reason":"..."}
```

`onyx jobs --json` emits one `{"type":"job", ...}` object per line with
fields `job_id`, `status`, `command`, `started_at_unix`,
`finished_at_unix`, `exit_code`, `attached`, `buffered_bytes`.

Data is rendered as lossy UTF-8 inside JSON. Binary output will contain
U+FFFD replacement characters; use plain text mode for byte-exact
capture.

### How the command is executed

Onyx runs argv directly on the remote — no implicit shell. To get
shell features (pipes, redirects, globs), invoke the shell explicitly:

```bash
onyx exec host -- sh -c 'ls | grep foo'
```

This matches `kubectl exec` / `docker exec` semantics and avoids
quoting surprises.

### Guarantees and limits

**What is strong:**

- A client disconnect does **not** kill the job — the child keeps
  running on the server.
- Jobs are addressable by `job_id` from any machine that can reach the
  same `onyx-server`.
- Up to 4 MiB of output per job is preserved in a ring buffer. When the
  buffer is full, the oldest chunks are dropped first and `onyx attach` /
  `onyx logs` tell you the starting seq so you know there was a gap.
- Finished jobs stay visible to `onyx jobs` / `onyx logs` for 1 hour
  after exit.

**What is best-effort:**

- Jobs are in-memory. If `onyx-server` restarts or the host reboots,
  all jobs and buffers are gone. For persistent-across-reboot execution,
  use systemd / launchd / nohup.
- The ring buffer is capped per job at 4 MiB. Noisy jobs that produce
  more than that will lose their oldest output.
- Exit code `137` from the client process means "job killed by signal"
  (matching the common `128 + SIGKILL` convention) — this is distinct
  from the remote child's own exit code.
- `--detach` does not start a daemon; it just drops the streaming
  stream. The server owns the lifetime either way.

Jobs are kept up to the registry cap (256 live jobs per server). When
the cap is reached, the oldest **finished** job is evicted first;
running jobs are never reaped until they exit on their own.

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
- `onyx exec` jobs are in-memory only — they do not survive
  `onyx-server` restart or host reboot.
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
