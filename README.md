# Onyx

Remote shells and jobs that keep going through real-world network drops.

Onyx is a Rust CLI for resilient remote work. Use it like SSH for an
interactive shell, or use `onyx exec` for long-running remote jobs you can
detach, reattach, inspect, and stop later. Every jobs command speaks `--json`,
so scripts and agents can drive remote work through the same job model.

```bash
onyx user@host
onyx exec gpu-box --detach -- python train.py
onyx logs gpu-box job_xxx
```

## Why Onyx

SSH is excellent, but a flaky Wi-Fi, VPN, NAT, or laptop sleep can still leave
you with a broken terminal and uncertain job state. Onyx gives remote work a
small control plane:

- Interactive shells reconnect and resume the same remote session, then
  replay exactly the output you missed.
- Remote exec jobs keep running after the client disconnects.
- Job output is buffered server-side and can be streamed, attached, or read
  later.
- No tmux, no remote config: your terminal's own scrollback, selection, and
  copy work like plain SSH.

## Install

```bash
brew install shervin9/onyx/onyx --formula
onyx user@host
```

Update:

```bash
brew upgrade shervin9/onyx/onyx --formula
```

On first connect, Onyx uses your existing SSH access to upload and start the
matching `onyx-server` companion binary on the remote host. Subsequent
connections reuse the running server when possible.

## Core Commands

Interactive shell:

```bash
onyx user@host
```

If you reconnect to a host where you have a detached session still alive on
the server, Onyx offers to resume it — it reattaches automatically when
there's just one, or shows a numbered picker when there are several. Pass
`--new` to skip that and always start a fresh session. On a dropped
connection, the client keeps retrying the same session for up to 30 minutes.

Run a remote command:

```bash
onyx exec prod -- ./deploy.sh
```

Detach a long job and check it later:

```bash
onyx exec gpu-box --detach -- python train.py
onyx jobs gpu-box
onyx logs gpu-box job_xxx
onyx attach gpu-box job_xxx
```

Stop a job:

```bash
onyx kill gpu-box job_xxx
```

Use a working directory, extra environment, and timeout:

```bash
onyx exec prod --cwd /srv/app --env RUST_LOG=info --timeout 60s -- cargo test
```

## Reconnect & Catch-Up

The interactive shell is a plain login shell on `onyx-server`'s own PTY — no
tmux. When the network drops, the shell keeps running on the server and keeps
a 2 MiB replay buffer of its output. When the client reconnects, it tells the
server the last output it rendered and the server sends back exactly the bytes
you missed. If the gap is larger than the buffer, or you resume from a fresh
terminal, the server repaints the current screen once instead.

While Onyx is reconnecting, the status is shown in your terminal's title, so
nothing is printed into the session you are catching up on. Detached sessions
are kept on the server for 12 hours (in memory) and can be resumed with
`onyx <host>`.

Because there is no tmux layer, your terminal's native scrollback,
click-drag selection, and copy work exactly like plain SSH. `--no-tmux` and
`ONYX_NO_TMUX` from older versions are still accepted and do nothing.

## Ports & Links Open Locally

Start a dev server in your Onyx shell and it is already on your machine:

```text
$ npm run dev
  ▲ Next.js ready on http://localhost:3000
[onyx] dev-de:3000 → http://localhost:3000
```

- Onyx watches the TCP ports (1024+) that programs in *your session* listen
  on and forwards each one to the same port on your localhost (or a free one
  if it is taken). The forward closes when the program stops. Needs QUIC;
  explicit `-L local:remote` forwards still work.
- `xdg-open` and `$BROWSER` inside the session open http(s) links in your
  local browser — handy for `gh auth login`, `gcloud auth login`, or an
  agent's sign-in link. Set `ONYX_NO_OPEN=1` locally to print links instead.

If UDP is blocked, the shell continues over an SSH bridge through your
existing SSH access (no extra port), with the same replay after drops.
Links still open locally; automatic port forwards need QUIC.

## Agents & Audit

Run a coding-agent CLI headlessly on a remote host, as a resumable job:

```bash
onyx agent run gpu-box --agent claude -- "fix the failing test"
```

Only the `claude` adapter is verified; `codex`/`aider`/`gemini` are
best-effort. The agent must already be installed on the remote. Add
`--yolo` to skip permission prompts (dangerous: the agent can then run
arbitrary commands unattended).

### Agent Guard: agents use your keys without seeing them

```bash
export ANTHROPIC_API_KEY=… GITHUB_TOKEN=…        # on your machine
onyx agent run dev-box --secret ANTHROPIC_API_KEY --secret GITHUB_TOKEN \
  -- "fix the flaky test and open a PR"
```

```text
[onyx guard] on · secrets: ANTHROPIC_API_KEY → api.anthropic.com; GITHUB_TOKEN → api.github.com,… · egress locked by Landlock
[onyx guard] allowed api.anthropic.com · injecting ANTHROPIC_API_KEY
[onyx guard] BLOCKED paste.example.net:443
```

- `--secret NAME` reads `NAME` from your **local** environment and sends it
  over the authenticated QUIC channel. It is kept in onyx-server's memory
  only (never on disk) and the server process is non-dumpable.
- The agent gets a **same-length placeholder** in `NAME`. A small proxy in
  onyx-server swaps the real value in **request headers only**, and only for
  that secret's hosts. Bodies are never rewritten, so an agent cannot leak the
  real key by posting its placeholder somewhere. Responses are scrubbed the
  other way, so an echoed header never reveals it.
- Well-known names have default hosts (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
  `GEMINI_API_KEY`, `GITHUB_TOKEN`/`GH_TOKEN`, `GITLAB_TOKEN`, `NPM_TOKEN`,
  `HF_TOKEN`, `OPENROUTER_API_KEY`, `SLACK_BOT_TOKEN`); anything else needs
  `--secret NAME=host1,host2`.
- **Egress allowlist.** With any guard flag the agent can reach only its model
  API, the secrets' hosts and `--allow <host>` (`*.example.com` for
  subdomains). Plain HTTP is refused. `--allow-port <n>` permits direct TCP to
  a port such as a local database. `--guard` turns this on without secrets.
- **Can't be bypassed (Linux 6.7+).** The job is confined with Landlock so it
  can open TCP connections only to the proxy and allowed ports, without root.
  On older kernels the proxy still works but is advisory, and the job output
  says so.
- HTTPS to hosts with a secret is intercepted with a per-job CA that the job
  trusts through `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`
  and friends; other allowed hosts are tunnelled untouched.

Durable job history, independent of the in-memory job registry, survives
`onyx-server` restarts:

```bash
onyx audit gpu-box --limit 25
```

## JSON For Scripts And Agents

Agents and scripts call the CLI directly. Pass `--json` to get one JSON object
per line from the jobs commands:

```bash
onyx exec hetzner-dev --json -- git status
onyx jobs hetzner-dev --json
onyx logs hetzner-dev job_xxx --json
```

## How It Works

1. The local `onyx` client resolves your SSH target and bootstraps
   `onyx-server` over SSH when needed.
2. The client connects to the server over QUIC and pins the server certificate
   with Trust-On-First-Use.
3. Every QUIC stream is authorized with a per-server random token read through
   the SSH bootstrap flow.
4. Shell sessions run on the server's own PTY with a per-session replay
   buffer. Exec jobs are owned by the remote server and keep running when the
   client disconnects.

## Why Not Just SSH, tmux, Or mosh?

- **SSH** is the universal transport, and Onyx keeps what makes it pleasant:
  a plain shell with your terminal's native scrollback, selection, and copy.
  What SSH does not do is survive a dropped connection or own remote job
  lifecycle after the client disappears.
- **tmux** keeps shells alive, but puts its own screen between you and your
  terminal — its own scrollback, copy mode, and key bindings. Onyx needs no
  tmux on the remote: the server keeps the shell alive and replays exactly the
  output you missed on reconnect.
- **mosh** is excellent for roaming terminals, but syncs screen state rather
  than the output stream, so native scrollback does not work. Onyx replays the
  missed bytes themselves and adds server-owned jobs: detached exec, logs,
  attach, kill, audit, and `--json` output.

## Security Model

- Bootstrap uses your existing SSH authentication and SSH `known_hosts`.
- QUIC server identity uses TOFU certificate pinning in
  `~/.local/share/onyx/known_hosts`.
- QUIC client authorization uses a random server token stored on the remote at
  `~/.local/share/onyx/server.auth_token` with `0600` permissions.
- Onyx runs commands on your remote machines. Use least-privilege accounts and
  review commands before execution.
- Agent Guard secrets live only in onyx-server memory for the job's lifetime.
  Other processes of the same user cannot read them (the server is
  non-dumpable); root on the server can.

See [SECURITY.md](SECURITY.md) for the full trust model and reporting policy.

## Current Limits

- Interactive sessions and their replay buffers are in-memory on
  `onyx-server`; a detached session survives network drops for up to 12 hours
  but not a server process restart or host reboot.
- Live job state and output buffers are in-memory on `onyx-server`; they do
  not survive a server process restart or host reboot. Job lifecycle history
  (`onyx audit`) is persisted separately and does survive restarts, but a
  running job is always marked `expired` on the next boot since its child
  process is gone.
- Release binaries are checksumed but not yet signed or attested.
- Direct `--no-bootstrap` usage requires `ONYX_AUTH_TOKEN` because bootstrap is
  what reads the remote server auth token automatically.

## Project Layout

- `client/` - `onyx` CLI
- `server/` - remote `onyx-server`
- `shared/` - protocol types shared by client and server
- `docs/` - static documentation
- `index.html`, `style.css`, `script.js` - landing page
