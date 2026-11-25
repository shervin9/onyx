# Onyx Release Checklist

Pre-release smoke checklist. Run these before tagging.

## Build and test

- [ ] `cargo test --workspace` — all tests pass
- [ ] `cargo build --workspace --release` — clean, no warnings
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` — clean
- [ ] `sh -n install.sh` — shell syntax clean
- [ ] `node --check script.js` — JS syntax clean

## Fresh install

- [ ] Fresh install via `curl -fsSL https://useonyx.dev/install.sh | sh`
- [ ] Fresh install via `brew install shervin9/onyx/onyx --formula`
- [ ] `onyx --version` reports the release version

## First connect

- [ ] `onyx <target>` on a clean host bootstraps and reaches a usable shell
- [ ] Bootstrap uploads the packaged server binary; no remote Rust/cargo output appears
- [ ] Missing packaged server binary fails fast with the reinstall message
- [ ] Reconnect after a short transport drop resumes the existing session

## SSH auth and passphrase

- [ ] Passphrase-protected key: error message explains `ssh-add` clearly
- [ ] Canceled passphrase: reports a concise retry path
- [ ] ssh-agent-loaded key: connects without prompts
- [ ] Unencrypted key: connects without prompts

## Session reconnect and replay

- [ ] Host without tmux: shell opens normally; `onyx attach <target> <job_id>` works
- [ ] Output produced during a short drop is replayed exactly once on reconnect (no gaps, no duplicates)
- [ ] Gap larger than the replay buffer, or resume from a fresh terminal: screen is repainted once
- [ ] Reconnect status appears in the terminal title, not in the session output
- [ ] Native terminal scrollback, selection, and copy work
- [ ] `--no-tmux` / `ONYX_NO_TMUX=1` are accepted and ignored

## Exec lifecycle

- [ ] `onyx exec <target> -- echo hello` exits 0 with correct output
- [ ] `onyx exec <target> --timeout 2s -- sleep 10` exits 124
- [ ] `onyx exec <target> --detach -- sleep 30` returns job id immediately
- [ ] `onyx logs <target> <job_id>` shows buffered output
- [ ] `onyx kill <target> <job_id>` reports killed / already finished / not found
- [ ] `onyx jobs <target>` lists running and finished jobs clearly
- [ ] `--cwd`, `--env` flags pass through to the remote process

## JSON output

- [ ] `onyx exec <target> --json -- echo hello` prints one JSON object per line
- [ ] `onyx jobs`, `logs`, `attach`, `kill`, `audit` with `--json` emit valid JSON lines
- [ ] Kill with `--json` reports killed / already finished / not found

## Homebrew and packaging

- [ ] Formula version and sha256 match the release artifacts
- [ ] `onyx --version` output after brew install matches the tag
- [ ] Server companion binaries are installed alongside the client binary
- [ ] Homebrew installs server companion binaries into `libexec`
- [ ] `brew upgrade shervin9/onyx/onyx --formula` completes cleanly

## Bad network and doctor

- [ ] `onyx doctor <target>` reports SSH status, server state, and QUIC reachability
- [ ] UDP-blocked path surfaces a clear hint about firewall / UDP filtering
- [ ] Initial connect does not show reconnect UI; reconnect UI appears only after a live session drops
- [ ] QUIC connection-refused / handshake errors are not mislabeled as timeouts
