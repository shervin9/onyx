# Launch Notes

Use this file as the source of truth for Product Hunt, Hacker News, and social
posts.

## One-Liner

Onyx is a Rust CLI for remote shells and jobs that keep going through
real-world network drops.

## Short Description

Onyx gives remote work a small control plane: reconnecting interactive shells,
detached remote jobs, attachable logs, job kill/list commands, and a local MCP
server for agent clients.

## Product Hunt

Name:

```text
Onyx CLI
```

Tagline:

```text
Remote shells and jobs that keep going through disconnects
```

Description:

```text
Onyx is a Rust CLI for resilient remote work. Start an interactive shell,
run detached remote jobs, reattach to output, inspect logs, kill jobs, and
expose a local MCP server for AI agents. It bootstraps over SSH, uses QUIC
when available, and stays self-hosted by default.
```

First comment:

```text
I built Onyx because I kept losing SSH sessions and long-running remote jobs
over flaky Wi-Fi, VPNs, and laptop sleep.

Onyx gives you:
- `onyx user@host` for a reconnecting remote shell
- `onyx exec host --detach -- long-job` for jobs that keep running remotely
- `onyx attach`, `onyx logs`, `onyx jobs`, and `onyx kill`
- `onyx mcp serve` for local agent integration

It bootstraps over SSH, pins the server cert with TOFU, and authorizes QUIC
streams with a per-server token. No hosted service is required.

I would especially like feedback on the CLI shape, install flow, and where
Onyx should fit beside SSH, tmux, and mosh.
```

## Hacker News

Title:

```text
Show HN: Onyx, a Rust CLI for remote shells and jobs that keep going
```

Post:

```text
I built Onyx because I kept losing SSH sessions and long-running remote jobs
over flaky Wi-Fi/VPN links.

It gives you:
- `onyx user@host` for a reconnecting remote shell
- `onyx exec host --detach -- long-job` for jobs that keep running remotely
- `onyx attach/logs/jobs/kill` for job lifecycle
- `onyx mcp serve` for local agent integration

It bootstraps over SSH, pins the server certificate with TOFU, and uses a
per-server auth token for QUIC streams. No hosted service is required.

The main tradeoff: shell/job metadata is currently in-memory on onyx-server,
so it survives client disconnects but not server restart or host reboot.

Repo: https://github.com/shervin9/onyx
Docs: https://useonyx.dev/docs/
```

## Launch Checklist

- [ ] GitHub release is tagged and binaries/checksums are attached.
- [ ] Homebrew formula installs the latest release.
- [ ] `brew install shervin9/onyx/onyx --formula` works on a clean machine.
- [ ] `onyx user@host` bootstraps and reaches a shell on a clean Linux host.
- [ ] `onyx exec host --detach -- sleep 30` returns a job id.
- [ ] `onyx jobs`, `onyx logs`, `onyx attach`, and `onyx kill` work.
- [ ] `onyx mcp serve` starts locally and does not bind a network port.
- [ ] Landing page video loads and the Product Hunt badge is visible.
- [ ] README, docs, `--help`, and `SECURITY.md` agree on install and security.
- [ ] Known limitations are visible and not hidden.
