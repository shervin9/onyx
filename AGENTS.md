# Onyx Agent Guide
Onyx is a Rust CLI for resilient remote shell and remote execution.
The repo contains the client, remote server, MCP bridge, and static site/docs.

## Core concepts
- `shell`: interactive session with reconnect and remote persistence.
- `exec`: remote jobs with `detach`, `attach`, `logs`, `kill`, and `timeout`.
- `mcp`: local stdio server exposing Onyx tools to agent clients.
- `streaming`: live output plus reconnect and resume progress events.

## Key commands
- `cargo build`
- `cargo test`
- `onyx exec <target> -- <cmd...>`
- `onyx jobs <target>`
- `onyx logs <target> <job_id>`
- `onyx kill <target> <job_id>`
- `onyx mcp serve`

## Rules
- Keep CLI UX stable.
- Avoid unnecessary dependencies.
- Preserve backward compatibility in flags, JSON output, and protocol shapes.
- Keep MCP local-only by default.
- Do not leak secrets, tokens, or sensitive env values in logs.
