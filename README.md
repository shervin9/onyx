# Onyx

Remote shells and jobs that keep going through real-world network drops.

Onyx is a Rust CLI for resilient remote work. Use it like SSH for an
interactive shell, or use `onyx exec` for long-running remote jobs you can
detach, reattach, inspect, and stop later. It also exposes a local MCP server
so agent clients can run remote work through the same job model.

```bash
onyx user@host
onyx exec gpu-box --detach -- python train.py
onyx logs gpu-box job_xxx
```

## Why Onyx

SSH is excellent, but a flaky Wi-Fi, VPN, NAT, or laptop sleep can still leave
you with a broken terminal and uncertain job state. Onyx gives remote work a
small control plane:

- Interactive shells reconnect and resume the same remote session.
- Remote exec jobs keep running after the client disconnects.
- Job output is buffered server-side and can be streamed, attached, or read
  later.
- The MCP bridge is local-only by default, so agents can use Onyx without
  exposing a network MCP service.

## Install

```bash
brew install shervin9/onyx/onyx --formula
onyx user@host
```

Update:

```bash
brew upgrade shervin9/onyx/onyx --formula
```

On first connect, Onyx uses your existing SSH access to upload and start the
matching `onyx-server` companion binary on the remote host. Subsequent
connections reuse the running server when possible.

## Core Commands

Interactive shell:

```bash
onyx user@host
```

Run a remote command:

```bash
onyx exec prod -- ./deploy.sh
```

Detach a long job and check it later:

```bash
onyx exec gpu-box --detach -- python train.py
onyx jobs gpu-box
onyx logs gpu-box job_xxx
onyx attach gpu-box job_xxx
```

Stop a job:

```bash
onyx kill gpu-box job_xxx
```

Use a working directory, extra environment, and timeout:

```bash
onyx exec prod --cwd /srv/app --env RUST_LOG=info --timeout 60s -- cargo test
```

## MCP For Agents

Start the local stdio MCP server:

```bash
onyx mcp serve
```

Available tools:

- `onyx_exec`
- `onyx_jobs`
- `onyx_attach`
- `onyx_logs`
- `onyx_kill`

Example tool call:

```json
{"name":"onyx_exec","arguments":{"target":"hetzner-dev","command":["git","status"],"stream":true}}
```

Use `stream: true` to receive live progress events.

## How It Works

1. The local `onyx` client resolves your SSH target and bootstraps
   `onyx-server` over SSH when needed.
2. The client connects to the server over QUIC and pins the server certificate
   with Trust-On-First-Use.
3. Every QUIC stream is authorized with a per-server random token read through
   the SSH bootstrap flow.
4. Shell sessions are tmux-backed. Exec jobs are owned by the remote server and
   keep running when the client disconnects.

## Why Not Just SSH, tmux, Or mosh?

- **SSH** is the universal transport, but it does not own remote job lifecycle
  after the client disappears.
- **tmux** is great for shells. Onyx uses tmux for interactive persistence and
  adds a CLI job API around detached exec, logs, attach, kill, JSON, and MCP.
- **mosh** is excellent for interactive roaming terminals. Onyx focuses on
  remote command execution, buffered output, reconnectable jobs, and agent
  integration.

## Security Model

- Bootstrap uses your existing SSH authentication and SSH `known_hosts`.
- QUIC server identity uses TOFU certificate pinning in
  `~/.local/share/onyx/known_hosts`.
- QUIC client authorization uses a random server token stored on the remote at
  `~/.local/share/onyx/server.auth_token` with `0600` permissions.
- `onyx mcp serve` is a local stdio server. Do not expose it as a public
  network service.
- Onyx runs commands on your remote machines. Use least-privilege accounts and
  review commands before execution.

See [SECURITY.md](SECURITY.md) for the full trust model and reporting policy.

## Current Limits

- Shell persistence is tmux-backed. Without tmux, Onyx falls back to a basic
  shell mode.
- Jobs and shell metadata are in-memory on `onyx-server`; they do not survive a
  server process restart or host reboot.
- Release binaries are checksumed but not yet signed or attested.
- Direct `--no-bootstrap` usage requires `ONYX_AUTH_TOKEN` because bootstrap is
  what reads the remote server auth token automatically.

## Project Layout

- `client/` - `onyx` CLI and MCP bridge
- `server/` - remote `onyx-server`
- `shared/` - protocol types shared by client and server
- `docs/` - static documentation
- `index.html`, `style.css`, `script.js` - landing page
