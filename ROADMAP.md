# Onyx Roadmap — The Open Control Plane for Remote AI Agents

> Status: direction approved 2026-06-08; refreshed 2026-06-26 with 2026 trend
> research (see the redesign brief). This is the source of truth for the
> AI-agent pivot. Product claims here are aspirational until the referenced
> phase ships — keep `README.md`, the landing page, and `SECURITY.md` honest
> per `CLAUDE.md` claim boundaries.

## Positioning

**The open control plane for running AI agents on your own servers.**
Run **any** coding agent (Claude Code, Codex, Gemini, OpenHands) on **any**
machine you own — resilient, auditable, and native to your editor.

The resilient QUIC/SSH transport is no longer the headline; it is the proof
point ("that's why the agent doesn't die when your laptop sleeps"). The
headline is the agent.

### Why now (trend thesis, 2026)

- **Agents moved to the server.** OpenHands sells "run in the cloud so it keeps
  going when your laptop is shut"; Cursor 2.0 runs parallel agents across
  worktrees/remote machines; Devin assigns work to cloud engineers. Onyx's
  server-owned reattachable jobs + QUIC resilience already are this.
- **Self-hosting became mandatory.** EU AI Act high-risk obligations (Aug 2026),
  Colorado AI Act (Jun 2026), and OWASP's Top 10 for Agentic Apps mean regulated
  teams must keep code private and keep an immutable record of every agent
  action. That is Onyx's open-core seam.
- **Editors went agent-agnostic via ACP.** The Agent Client Protocol (Zed →
  JetBrains, ~12M+ devs, Jan 2026 ACP Registry) is the "LSP for agents." Claude
  Code already runs in Zed through ACP. This is the "integrate with Claude Code"
  answer and the biggest distribution wave.
- **61% of engineering teams** already run AI agents in production.

### Competitive gap

Competitors are either a **heavy self-hosted platform** (OpenHands, Coder) or a
**hosted product** that wants your code on their cloud (Devin, Cursor). Onyx is
neither: a thin, self-bootstrapping (single-binary, SSH) control plane that turns
any box you can already SSH into a resilient, reattachable, auditable agent host —
without installing a platform.

### Decisions (founder)

- **Wedge:** Remote agent runner (run agent CLIs on servers as resilient,
  reattachable jobs).
- **Business shape:** Open-core (free OSS CLI; paid hosted/team governance
  layer later).
- **Primary user:** Platform / DevOps teams (governance, audit, fleets).

## Architecture: three surfaces over one governed core

Same engine underneath — the server-owned, reattachable job. Onyx now speaks to
people, agents, and editors through three front doors that share one governed
core.

- **Surface 1 — CLI** (DevOps / power users): `onyx agent run`, detach/attach/
  logs/kill, fleets, JSON output, CI-friendly.
- **Surface 2 — MCP** (local agents): a local Claude Code dispatches *remote*
  sub-agents; shipped as a one-command Claude Code **plugin** (slash commands +
  safety hooks + MCP server def).
- **Surface 3 — ACP** (editors): Onyx as an ACP agent in Zed / JetBrains —
  "remote Claude Code, via Onyx" as a first-class editor agent.
- **Governed core:** server-enforced policy + an immutable audit log shared by
  all three surfaces. The open-core seam.

## The "agent job"

An agent job is the existing server-owned, detachable, buffered `exec` job,
specialized for an LLM CLI.

| Already have                          | Becomes                                            |
| ------------------------------------- | -------------------------------------------------- |
| `ExecStart` / server-owned process    | `AgentStart` (agent kind, prompt, repo, model, budget) |
| Buffered output + reattach/logs/kill  | Same plumbing, unchanged                            |
| QUIC/SSH resilience                    | "agent survives disconnects" for free               |
| `remote_status()` probe                | also detects which agent CLIs are installed         |
| MCP bridge (`client/src/mcp.rs`)       | local Claude Code dispatches sub-agents to remotes  |

## Phases

### Phase 01 — Agent runner — SHIPPED

`onyx agent run <target> --agent claude -- "<prompt>"` wraps any agent CLI as a
resumable job (`client/src/agent.rs` adapter → `run_exec_mode`). Claude adapter
verified; codex/aider/gemini best-effort. No protocol/server changes.

### Phase 02 — Durable state — NOW

Jobs/metadata are in-memory on `onyx-server` and die on restart — the single
biggest blocker to any audit/governance claim. Move job records (and the Phase 03
audit log) to SQLite on the server. Without this we cannot honestly say
"auditable."

### Phase 03 — Governance & audit — NEXT (open-core seam)

- Server-enforced policy: command allow/deny, path scoping, egress limits, max
  budget/timeout, optional require-approval mode.
- Append-only audit log of every agent action (who, prompt, commands run, files
  changed, tokens spent) → `onyx audit <target>`.
- Approval gates: agent pauses on a risky action, operator approves from CLI/
  notification.
- Scoped per-job secret injection (API keys never logged).
- Timed to EU AI Act + OWASP Agentic Top 10.

### Phase 04 — Editor integration (ACP + plugin) — NEXT

- **ACP adapter:** Onyx as an Agent Client Protocol agent so Zed / JetBrains can
  run "remote agent via Onyx" natively (JSON-RPC over stdio, like the existing
  MCP bridge). Highest-leverage distribution bet.
- **Claude Code plugin:** one-command install bundling the MCP server def, slash
  commands, and safety hooks. Cheapest path to real users.

### Phase 05 — Fleet & triggers — NEXT

- Inventory / target groups, global `onyx agents` view, fan-out one task to N
  boxes.
- Parallel isolated agents via remote git worktrees (the Cursor 2.0 model, but
  reattachable and on your own box).
- Background-agent triggers: Slack / GitHub / Datadog → dispatch an agent job
  (alert → agent investigates on the host → opens a PR → human merges).

### Phase 06 — Hosted control plane — LATER (commercial)

CLI stays free/OSS. Paid: self-hostable web control plane — team workspaces,
RBAC, SSO/SAML, org-wide audit, cross-agent cost analytics.

## GTM

- Relaunch landing page around the agent story (keep transport claims as the
  "why it's reliable" section — do not redesign).
- Show HN / Product Hunt: "Onyx — run Claude Code on your own servers,
  resilient and auditable."
- "Running AI agents on company infra safely" guide aimed at platform engineers.

## Claim guardrails

- Do not claim "auditable" until Phase 02 + 03 ship.
- Adapters depend on third-party CLI flags — version them, degrade gracefully.
- Keep MCP local-only by default.

## Recommended next move

1. **Phase 02 — durable SQLite state.** Small, unblocks the governance story.
2. **Claude Code plugin.** Cheapest path to real users.
3. **ACP adapter prototype.** Highest-leverage 2026 integration bet.
