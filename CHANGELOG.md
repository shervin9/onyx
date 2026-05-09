# Changelog

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
