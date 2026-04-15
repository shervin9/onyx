# Onyx

Stable remote shell for unreliable networks.

## Product summary

Onyx is a remote shell tool that prefers QUIC when available, falls back to SSH when needed, and is designed for AI CLI workflows, remote development, and DevOps work on unstable networks.

## Built features

- QUIC transport with automatic SSH fallback
- SSH bootstrap for remote install/start when needed
- Interactive shell sessions with tmux-backed persistence and scrollback
- Local port forwarding
- SSH `ProxyCommand` support via `onyx proxy <host> <port>`
- Proxy reconnect grace period and resume support for short transport drops
- TOFU certificate trust with `known_hosts` pinning
- Open-source landing page and install flow for GitHub Pages

## Known limitations

- Do not claim full SSH-session persistence for arbitrary tools after real network loss
- Proxy resume is a best-effort short-drop recovery path, not a blanket guarantee
- QUIC depends on UDP reachability; some environments still require SSH fallback
- Remote bootstrap may fall back to cargo build if no matching prebuilt server binary is available locally
- Homebrew should be marked clearly as unavailable until the tap/package is actually ready

## Bootstrap and install model

- `onyx` is the local client
- The remote `onyx-server` is provisioned automatically over SSH when needed
- Bootstrap should prefer uploading a matching prebuilt `onyx-server` binary
- If no matching prebuilt binary is available, bootstrap may fall back to remote cargo build
- `ONYX_REMOTE_DIR` can override the remote install dir; default is `~/.local/share/onyx`, with `/tmp/onyx` as fallback when needed
- `--no-bootstrap` skips remote install/start checks and assumes the server already exists

## Security model

- Trust model is TOFU plus stored fingerprint verification
- First connect prompts the user to trust the presented certificate fingerprint
- Subsequent connects must fail hard on mismatch; never auto-overwrite trust state
- `known_hosts` and private/trust files should use private permissions
- Keep claims precise: do not imply stronger verification, persistence, or transport guarantees than the code actually provides
- Avoid false marketing claims such as “sessions always survive disconnects” or “Mosh-level persistence for all tools”

## Plain SSH alias vs proxy alias

- Plain alias:
  Use `onyx user@server` or an SSH alias for the normal interactive Onyx shell flow
- Proxy alias:
  Use SSH `ProxyCommand onyx proxy %h %p` only for SSH-based tools that should ride Onyx as a transport layer
- Keep docs clear that these are different workflows:
  plain interactive Onyx shell vs drop-in SSH transport

## Testing expectations

- Run targeted verification for any changed path; do not stop at static reasoning
- For Rust changes, run `cargo build` at minimum; run additional manual or integration checks when the task touches transport, bootstrap, proxy, or trust logic
- For shell/install changes, at minimum run syntax checks such as `sh -n install.sh`
- For landing page changes, keep files static, lightweight, and GitHub Pages compatible; sanity-check JS syntax
- When live network or remote-host tests are not possible locally, say so explicitly

## Landing page guidance

- Keep the current design direction: minimal, premium, dark, modern, subtle, lightweight
- Preserve the established visual language; do not redesign from scratch unless explicitly asked
- Prefer plain HTML, CSS, and tiny vanilla JS only
- Keep copy short, accurate, and product-grounded
- Mobile must be treated as first-class: hero, code blocks, terminal mockups, and flow visuals should remain legible and polished
- GitHub Pages-safe links should use relative paths such as `./` instead of `/`

## Release and install guidance

- Releases should publish local client binaries and Linux `onyx-server` companion binaries used by bootstrap
- The installer should verify checksums and install only what the current release actually provides
- Do not advertise an install method as ready unless it is actually shipped and supported
- If Homebrew is not live, label it clearly as coming soon

## Accurate product claims

- Prefer exact wording over aspirational wording
- Good examples:
  “QUIC when available. SSH when it’s not.”
  “Drop-in SSH transport for existing workflows.”
  “Built for flaky networks.”
- Avoid misleading examples:
  “SSH sessions always survive disconnects.”
  “Full persistence for all SSH-based tools.”
  “Zero-trust verified PKI” unless the implementation actually does that

## Local-only notes

- If private agent-specific notes are useful, keep them in `AGENTS.local.md`, `CLAUDE.local.md`, or `CODEX.local.md`
- Do not commit private notes if they contain secrets, credentials, hostnames, or personal workflow details
