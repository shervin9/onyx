# CLAUDE.md

Canonical agent instructions live in `AGENTS.md`. This file is a **working
summary** so you do not have to reread the whole repo each session. If this
drifts from `AGENTS.md`, trust `AGENTS.md`.

Local-only private notes: `CLAUDE.local.md` (gitignored).

## What Onyx is

A remote shell CLI with:

- **QUIC transport** over UDP 7272 (preferred), with **SSH fallback** when
  UDP is blocked (`--no-fallback` to disable).
- **Self-bootstrapping remote**: `onyx user@host` provisions the
  `onyx-server` binary on the remote over SSH if it is missing or outdated.
- **Interactive session persistence** on the server's own PTY (no tmux):
  a per-session 2 MiB replay ring + vt100 screen model
  (`server/src/replay.rs`). Reconnect replays exactly the missed output, or
  repaints the screen once if the gap was evicted or a fresh terminal
  attaches. Native terminal scrollback/selection/copy work like SSH.
- **Server-owned jobs** (`exec`, `jobs`, `attach`, `logs`, `kill`, `audit`,
  `agent run`) with `--json` output for scripts and agents.
- **Local port forwarding** via `--forward LPORT:RPORT`.
- **SSH ProxyCommand transport** via `onyx proxy <host> <port>`.
- **TOFU fingerprint pinning** in `~/.local/share/onyx/known_hosts`.

## Repo shape

- `client/` → `onyx` binary (local CLI)
- `server/` → `onyx-server` binary (remote companion)
- `shared/` → `Message` enum and wire encoding (bincode)
- `install.sh` → shell installer, pulls release artifacts + checksums
- `Formula/onyx.rb` → Homebrew formula skeleton (tap at `shervin9/homebrew-onyx`)
- `index.html` / `style.css` / `script.js` → GitHub Pages landing page

## Bootstrap model (important — docs must match this)

1. Client SSH-calls `remote_status()` to check source hash and running
   server. If both match → skip to QUIC. No remote config files (tmux.conf
   etc.) are uploaded any more.
2. Otherwise, upload a packaged `onyx-server` matching the remote arch.
   Default lookup order: same directory as `onyx`, Homebrew/package
   `libexec`, then `ONYX_SERVER_BINARY=/path/to/onyx-server-linux-<arch>`.
3. If the packaged binary is missing, fail fast with a product error.
   Remote `cargo build --release` is developer-only and requires
   `ONYX_DEV_REMOTE_BUILD=1`.
4. Remote install dir: `ONYX_REMOTE_DIR` → `~/.local/share/onyx/` →
   `/tmp/onyx`.
5. `--no-bootstrap` skips the install/start check entirely.
6. Onyx does **not** modify remote firewalls. UDP 7272 is user-configured.

## Security model

- TOFU + SHA-256 fingerprint pinning per host:port.
- First connect prompts the user to trust the presented fingerprint.
- Mismatch on subsequent connects → **hard fail**, never auto-overwrite
  trust state.
- Trust files live in `~/.local/share/onyx/` with restrictive perms.
- No CA / WebPKI, no signed releases yet, no reproducible-build attestation.
- Reporting instructions: `SECURITY.md`.

## Product claim boundaries (keep tight)

**Say:**
- "QUIC when available, SSH when it's not."
- "Interactive sessions survive network drops and replay the output you
  missed on reconnect."
- "No tmux required; native scrollback and copy work like SSH."
- "Best-effort short-drop reconnect for proxy mode."
- "Drop-in SSH transport for existing workflows."

**Do not say:**
- "Full Mosh-level persistence for all SSH-based tools."
- "SSH sessions always survive disconnects."
- "Sessions survive onyx-server restart or host reboot" (they are in-memory).
- "Zero-trust verified PKI" (it is TOFU, not PKI).
- "Automatic firewall configuration" (Onyx never touches firewalls).

## Known limitations (keep surfacing)

- Proxy-mode reconnect window is short (~120s); longer drops end the SSH
  session underneath. Interactive-session retention is longer (client retries
  for 30 min; detached sessions kept 12h) but still in-memory — does not
  survive onyx-server restart.
- Replay ring is 2 MiB per session; a longer gap gets a one-shot screen
  repaint, not the full missed output.
- Homebrew tap is not live yet — landing page marks it clearly as
  coming soon.

## Install surfaces (keep consistent everywhere)

- Homebrew: `brew install shervin9/onyx/onyx --formula`
- Shell installer: `curl -fsSL https://useonyx.dev/install.sh | sh`
- From source: `cargo build --release` → `target/release/onyx`

If you change install wording in one place (README, landing page, SECURITY,
Homebrew README), update all of them.

## Testing expectations

- Rust changes: at minimum `cargo build` (workspace).
- Shell changes: `sh -n install.sh`.
- Landing-page JS changes: `node --check script.js`.
- Transport/bootstrap/proxy/trust changes: describe manual verification
  steps — do not claim "tested" for paths you cannot actually run.
- Static-reasoning-only changes must say so explicitly.

## Landing page guidance

- Keep the current style: minimal, premium, dark, modern, subtle,
  lightweight. Do **not** redesign.
- Vanilla HTML/CSS/JS only. Static. GitHub Pages-safe relative links
  (`./`, not `/`).
- Connection-flow pulse is positioned from real `.flow-dot` element
  rects — do not go back to percentage-based positioning.
- Mobile is first-class: hero, terminal mockup, and flow visuals must
  remain legible at 360px-wide.
- Copy must stay accurate. No fake features, no marketing fluff, no
  enterprise claims.

## Working style for this repo

- Minimal diffs. Don't rewrite code you're not changing.
- Don't add features, docstrings, or "polish" that wasn't asked for.
- When a doc claim can't be backed by the code, either change the code or
  soften the claim — do not leave the mismatch.
- Local-only notes go in `CLAUDE.local.md` / `AGENTS.local.md` /
  `CODEX.local.md` (all gitignored).
