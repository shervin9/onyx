# Changelog

## v0.3.1

### Added
- `prefix + u` grabs a URL off the current screen and copies it to your local
  clipboard via OSC 52 — wrapped lines are re-joined so long links (e.g. auth
  URLs from Claude Code) stay intact. One URL copies instantly; several show a
  built-in picker. Dependency-free (no fzf/plugins on the remote).

## v0.3.0

### Changed
- Interactive reconnect: the client now retries a dropped session for up to
  30 minutes (was 10). The disconnect indicator reads "Reconnecting…" (with
  the retry window) instead of a bare "Connection lost", in both the local
  status line and the tmux status bar.

### Added
- Resume picker: connecting with `onyx <host>` (no `--workspace`) now detects
  detached sessions on the server and offers to resume — auto-resumes when
  there's exactly one, shows a numbered picker when there are several. Skipped
  for non-interactive stdin and with the new `--new` flag (always start
  fresh).
- **`onyx agent run <target> --agent <kind> -- <prompt>`** — run a coding-agent
  CLI (claude, codex, aider, gemini) headlessly on the remote as a resumable
  exec job. Only the `claude` adapter is verified; others are best-effort.
  `--yolo` skips permission prompts.
- **`onyx audit <target>`** — durable job history persisted to SQLite on the
  server, so it survives `onyx-server` restarts (unlike the in-memory job
  registry). Jobs still `running` at restart are reconciled to `expired`.
- **`onyx diff <target>`** — `git diff` on the remote working tree, for
  reviewing what an agent (or anyone) changed. `--staged` and `--stat`
  supported.
- MCP: added `onyx_agent_run`, `onyx_audit`, `onyx_diff` tools, matching the
  new CLI subcommands.
- Copy-mode (`s` then select then Enter/y) now copies to the local system
  clipboard via OSC 52, relayed through tmux over either transport.

## v0.2.21

### Added
- **Named workspaces** — bind a name to a remote session for cross-process resume.
  - `onyx <host> --workspace <name>` (or `-w <name>`) starts/resumes a named workspace.
  - `onyx ls` lists all known workspaces with name, host, state, and short session ID.
  - `onyx attach <name>` resumes a named workspace from any terminal session.
  - Credentials persisted to `~/.onyx/workspaces.json`.

## v0.2.20

### Changed
- Calm reconnect UX: replaced animated banner with a single static status line per disconnect episode.
- Tmux status bar now reflects live QUIC connection state via `ONYX_STATE` environment variable set by the server.
- Suppressed `[mode]` eprintln during reconnects to prevent terminal corruption.
- Added `ONYX_DEBUG`-gated timing logs for QUIC handshake lifecycle.

## v0.2.19

### Added
- Landing page teaser video.
- Improved tmux mouse and scroll UX.
- Reload tmux config before Onyx attach.
