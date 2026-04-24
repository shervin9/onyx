# Onyx Release Checklist

Pre-Product-Hunt smoke checklist for first-time user paths.

## Install and update

- [ ] Fresh install via `curl -fsSL https://useonyx.dev/install.sh | sh`
- [ ] Fresh install via `brew install shervin9/onyx/onyx`
- [ ] `onyx --version` reports the release version
- [ ] Update over an existing install and confirm the new version is active

## First connect

- [ ] `onyx <target>` on a clean host with bootstrap enabled
- [ ] Bootstrap prefers a matching prebuilt server when available
- [ ] First connect reaches a usable shell without extra manual steps
- [ ] Reconnect once after a short transport drop and confirm the shell resumes

## SSH auth and passphrase

- [ ] Connect with a passphrase-protected SSH key
- [ ] Confirm the passphrase-required message explains `ssh-add` clearly
- [ ] Confirm canceled/incorrect passphrase attempts report a concise retry path

## Exec flows

- [ ] `onyx exec <target> -- echo hello`
- [ ] `onyx exec <target> --timeout 2s -- sleep 10` exits as timeout / code `124`
- [ ] `onyx exec <target> --detach -- sleep 30` returns a job id immediately
- [ ] `onyx logs <target> <job_id>` shows buffered output
- [ ] `onyx kill <target> <job_id>` reports killed / already finished / not found cleanly
- [ ] `onyx jobs <target>` shows running and finished jobs clearly

## MCP

- [ ] `onyx mcp serve` starts cleanly over stdio
- [ ] MCP `tools/list` returns the expected Onyx tools
- [ ] MCP exec streaming forwards `stdout`, `stderr`, `reconnecting`, `resumed`, `timeout`, and `finished` events
- [ ] MCP kill path returns structured kill results and surfaces missing-job errors

## Diagnostics and network edge cases

- [ ] `onyx doctor <target>` reports SSH status, server state, and QUIC reachability clearly
- [ ] Test a bad VPN / UDP-blocked path and confirm the error points to UDP firewall or network filtering
- [ ] Confirm QUIC connection-refused / handshake-failure cases do not get mislabeled as generic timeouts

