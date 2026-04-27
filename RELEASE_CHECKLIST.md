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

## tmux and no-tmux paths

- [ ] tmux installed: session opens with status bar; reconnect after drop returns to same window
- [ ] tmux missing: shell opens in basic mode with a clear warning; attach subcommand surfaces a helpful error

## Exec lifecycle

- [ ] `onyx exec <target> -- echo hello` exits 0 with correct output
- [ ] `onyx exec <target> --timeout 2s -- sleep 10` exits 124
- [ ] `onyx exec <target> --detach -- sleep 30` returns job id immediately
- [ ] `onyx logs <target> <job_id>` shows buffered output
- [ ] `onyx kill <target> <job_id>` reports killed / already finished / not found
- [ ] `onyx jobs <target>` lists running and finished jobs clearly
- [ ] `--cwd`, `--env` flags pass through to the remote process

## MCP streaming

- [ ] `onyx mcp serve` starts over stdio without errors
- [ ] `tools/list` returns all five expected tools
- [ ] Exec with `stream: true` forwards `stdout`, `stderr`, `reconnecting`, `resumed`, `timeout`, and `finished` progress events
- [ ] Kill returns structured `kill_result` and surfaces missing-job errors
- [ ] No stderr contamination into the JSON-RPC stdout stream

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
