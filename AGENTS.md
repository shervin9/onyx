# Onyx Agent Guide
Onyx is a Rust CLI for resilient remote shell and remote execution.
The repo contains the client, remote server, and static site/docs.

## Core concepts
- `shell`: interactive session on the server's PTY (no tmux) with reconnect,
  exact missed-output replay, and remote persistence.
- `exec`: remote jobs with `detach`, `attach`, `logs`, `kill`, and `timeout`.
- `json`: `--json` on jobs commands; agents call the CLI directly.
- `streaming`: live output plus reconnect and resume progress events.

## Key commands
- `cargo build`
- `cargo test`
- `onyx exec <target> -- <cmd...>`
- `onyx jobs <target>`
- `onyx logs <target> <job_id>`
- `onyx kill <target> <job_id>`
- `onyx exec <target> --json -- <cmd...>`

## Rules
- Keep CLI UX stable.
- Avoid unnecessary dependencies.
- Preserve backward compatibility in flags, JSON output, and protocol shapes.
- Do not leak secrets, tokens, or sensitive env values in logs.
