# Onyx

Resilient remote execution for flaky networks.

## What is Onyx

Onyx is a remote shell and remote execution tool for unstable links.
Open an interactive shell, run commands that survive disconnects, and expose remote execution through a local MCP server for agents.

## Key features

- Auto-reconnect interactive shell with tmux-backed persistence.
- Resumable exec jobs with detach, attach, logs, and kill.
- Streaming output for CLI and MCP clients.
- Local MCP support for agent-driven remote execution.
- QUIC when available. SSH fallback when it is not.

## Install

```bash
brew install shervin9/onyx/onyx --formula
brew upgrade shervin9/onyx/onyx --formula

onyx user@host
```

`onyx` installs the local client. The remote `onyx-server` is provisioned automatically over SSH when needed.

## Usage

Run a command:

```bash
onyx exec prod -- ./deploy.sh
```

Detach and check output later:

```bash
onyx exec gpu-box --detach -- python train.py
onyx logs gpu-box job_xxx
```

Kill a job:

```bash
onyx kill gpu-box job_xxx
```

Use `cwd`, `env`, and a timeout:

```bash
onyx exec prod --cwd /srv/app --env RUST_LOG=info --timeout 60s -- cargo test
```

## MCP

Start the local MCP server:

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

Add `stream: true` to receive live output events.

## Security note

- Onyx runs commands on remote machines. Review commands before execution.
- Use a least-privilege account and narrow `sudo` rules.
- Do not expose `onyx mcp serve` publicly.
- Restrict the Onyx server port to trusted clients or a VPN.
- See [SECURITY.md](SECURITY.md) for the trust model and reporting policy.
