# Changelog

## v0.5.0

### Added
- **Agent Guard.** `onyx agent run --secret NAME` gives the agent a
  same-length placeholder instead of the real key. onyx-server swaps the real
  value into request headers (never bodies) only for that secret's hosts, and
  scrubs it from responses. The real value comes from your local environment
  and is kept only in server memory. With `--secret`, `--allow <host>`,
  `--allow-port <n>` or `--guard`, the agent can reach only its model API and
  the hosts you allow; blocked attempts appear in the job output. On Linux
  6.7+ Landlock confines the job to the proxy, so it cannot be bypassed.
- Landing page and docs follow the browser's light or dark setting.

### Fixed
- The source-build fallback for onyx-server now uploads every server module
  (`ports.rs` was missing, so that path failed to compile).
- Restored the original Onyx wordmark on the site.

## v0.4.0

### Added
- **Automatic port forwarding.** When a program in your shell starts
  listening on a TCP port (1024+), e.g. `npm run dev` on 3000, Onyx forwards
  it to `http://localhost:3000` on your machine (or a free local port if that
  one is busy) and closes the forward when the program stops. Detected from
  the session's own process tree, so other users' services are not exposed.
  Requires QUIC; explicit `-L` forwards still work and take precedence.
- **Links open in your local browser.** `xdg-open` and `$BROWSER` inside an
  Onyx session (e.g. `gh auth login`, `gcloud auth login`, agent sign-in
  links) open http(s) URLs on the machine you connected from. Works over QUIC
  and the SSH bridge. `ONYX_NO_OPEN=1` prints the link instead.
- **SSH bridge transport.** When UDP/QUIC is unreachable, the interactive
  session continues over `ssh <host> onyx-server bridge` (the server listens
  on a private local socket). No extra port or firewall rule; sessions still
  resume with exact replay after drops. The client alternates QUIC and the
  bridge while reconnecting, so it switches back when UDP returns.

### Fixed
- **Ctrl-C did nothing in tmux-free sessions.** onyx-server is started in the
  background, which makes it ignore SIGINT/SIGQUIT, and the shell inherited
  that. Sessions and exec jobs now start with default signal handling.
- Warp: the Auto-Warpify hook printed by remote rc files made Warp inject its
  SSH bootstrap and the remote shell exited immediately. The client now drops
  that hook from session output.
- Two terminals on the same host no longer fight over one session; a
  taken-over client exits instead of reconnecting.
- Keystrokes typed right after a reconnect were sometimes swallowed; input now
  flows through one long-lived reader, and input typed while disconnected is
  sent after reconnecting. A failed keystroke send no longer exits the client.
- A crashed client's session shows up as detached after ~15s (server QUIC idle
  timeout), so re-running `onyx <host>` resumes it with Enter.

### Changed
- **Interactive sessions are tmux-free.** The server runs a plain login shell
  on its own PTY and keeps a 2 MiB replay buffer plus a screen model per
  session. On reconnect the client sends the last output it rendered and the
  server replays exactly the bytes you missed — or repaints the screen once if
  the gap was evicted or a fresh terminal attaches (resume picker). Your
  terminal's native scrollback, selection, and copy work like plain SSH.
- Reconnect status is shown in the terminal title instead of being printed
  into the session. The client retries for up to 30 minutes; detached
  sessions are kept for 12 hours in memory (still lost on `onyx-server`
  restart).
- `onyx attach` now only means `onyx attach <target> <job-id>`.

### Removed
- tmux integration: no uploaded `tmux.conf`/`status.sh`/`url.sh`, no tmux
  status bar or GPU metrics in it, no `prefix + u` URL picker, no tmux
  copy-mode/OSC 52 relay, and no basic-mode fallback. tmux is no longer
  required on the remote. `--no-tmux` and `ONYX_NO_TMUX` are accepted as
  no-ops.
- MCP bridge (`onyx mcp serve` and all `onyx_*` tools). Agents call the CLI
  directly with `--json`, e.g. `onyx exec host --json -- cmd`.
- `onyx diff` — use `onyx exec <host> -- git diff`.
- Named workspaces (`--workspace`/`-w`, `onyx ls`, `onyx attach <name>`,
  `~/.onyx/workspaces.json`) — the resume picker on `onyx <host>` covers it.
- `--low-bandwidth`.

## v0.3.2

### Added
- `--no-tmux` (or `ONYX_NO_TMUX=1`): run a plain login shell instead of tmux,
  so the local terminal's own scrollback, selection, and copy work natively —
  for terminals without OSC 52 clipboard support (e.g. macOS Terminal.app).
  Keeps onyx's QUIC reconnect; trades away tmux persistence and the status bar.

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
