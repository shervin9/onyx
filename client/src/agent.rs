//! Agent adapter layer — Phase 1 of the AI-agent pivot (see `ROADMAP.md`).
//!
//! `onyx agent run` normalizes a request to run a coding-agent CLI in headless
//! (non-interactive) mode and maps it onto the concrete argv for a specific
//! tool. That argv is then dispatched through the existing exec job machinery,
//! so every agent job inherits detach/attach/logs/kill/resume for free.
//!
//! Only the Claude adapter is verified against the upstream CLI today. The
//! others are best-effort: their argv is a reasonable first guess and may
//! drift as those CLIs change, so we flag them and warn the operator rather
//! than pretend they are stable.

/// A coding-agent CLI Onyx knows how to invoke headlessly.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum AgentKind {
    Claude,
    Codex,
    Aider,
    Gemini,
}

impl AgentKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "claude" | "claude-code" => Some(AgentKind::Claude),
            "codex" => Some(AgentKind::Codex),
            "aider" => Some(AgentKind::Aider),
            "gemini" => Some(AgentKind::Gemini),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AgentKind::Claude => "claude",
            AgentKind::Codex => "codex",
            AgentKind::Aider => "aider",
            AgentKind::Gemini => "gemini",
        }
    }

    /// True when the adapter's flags are verified against the upstream CLI.
    /// Callers should warn the operator when this is false.
    pub fn verified(self) -> bool {
        matches!(self, AgentKind::Claude)
    }
}

/// Human-readable list of agent kinds for help text and error messages.
pub const SUPPORTED: &[&str] = &["claude", "codex", "aider", "gemini"];

/// A normalized request to run an agent headlessly on a remote host.
pub struct AgentRequest<'a> {
    pub kind: AgentKind,
    pub prompt: &'a str,
    pub model: Option<&'a str>,
    /// Emit machine-readable streaming events instead of plain text.
    pub json: bool,
    /// Skip the agent's permission prompts so it can act fully unattended.
    /// Dangerous: the agent can run arbitrary commands on the remote host.
    pub yolo: bool,
}

/// Build the argv that runs `req` headlessly. The first element is the binary
/// name; the rest are arguments passed through to it unchanged.
pub fn build_command(req: &AgentRequest) -> Vec<String> {
    match req.kind {
        AgentKind::Claude => build_claude(req),
        AgentKind::Codex => build_codex(req),
        AgentKind::Aider => build_aider(req),
        AgentKind::Gemini => build_gemini(req),
    }
}

fn build_claude(req: &AgentRequest) -> Vec<String> {
    // `claude -p <prompt>` runs once and exits. stream-json (with --verbose)
    // emits newline-delimited events we can parse for turns/usage/cost later.
    let mut c = vec!["claude".to_string(), "--print".to_string(), req.prompt.to_string()];
    if let Some(m) = req.model {
        c.push("--model".to_string());
        c.push(m.to_string());
    }
    if req.json {
        c.push("--output-format".to_string());
        c.push("stream-json".to_string());
        c.push("--verbose".to_string());
    }
    if req.yolo {
        c.push("--dangerously-skip-permissions".to_string());
    } else {
        // Let the agent edit files unattended, but not run arbitrary tools
        // without approval. Phase 2 replaces this with server-enforced policy.
        c.push("--permission-mode".to_string());
        c.push("acceptEdits".to_string());
    }
    c
}

// ── Onyx Guard ──────────────────────────────────────────────────────────────
//
// `--secret NAME[=host,...]` reads NAME from the *local* environment and
// sends it to the server, which hands the agent a placeholder and injects
// the real value only into request headers bound for those hosts.
// `--allow host` and `--allow-port N` widen egress; `--guard` locks egress
// down with no secrets at all. Any of them turns the guard on.

/// Raw guard flags as typed on the command line.
#[derive(Default, Clone)]
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct GuardArgs {
    pub enabled: bool,
    pub secrets: Vec<String>,
    pub allow: Vec<String>,
    pub allow_ports: Vec<u16>,
}

impl GuardArgs {
    pub fn is_on(&self) -> bool {
        self.enabled || !self.secrets.is_empty() || !self.allow.is_empty() || !self.allow_ports.is_empty()
    }
}

/// Hosts a well-known secret may go to when `--secret NAME` names no hosts.
pub fn default_secret_hosts(name: &str) -> Option<&'static [&'static str]> {
    Some(match name {
        "ANTHROPIC_API_KEY" | "ANTHROPIC_AUTH_TOKEN" | "CLAUDE_CODE_OAUTH_TOKEN" => &["api.anthropic.com"],
        "OPENAI_API_KEY" => &["api.openai.com"],
        "GEMINI_API_KEY" | "GOOGLE_API_KEY" => &["generativelanguage.googleapis.com"],
        "GITHUB_TOKEN" | "GH_TOKEN" => &["api.github.com", "github.com", "uploads.github.com"],
        "GITLAB_TOKEN" => &["gitlab.com"],
        "NPM_TOKEN" => &["registry.npmjs.org"],
        "HF_TOKEN" => &["huggingface.co"],
        "OPENROUTER_API_KEY" => &["openrouter.ai"],
        "SLACK_BOT_TOKEN" => &["slack.com"],
        _ => return None,
    })
}

/// Hosts each agent needs to work at all (model API, sign-in refresh).
pub fn agent_hosts(kind: AgentKind) -> &'static [&'static str] {
    match kind {
        AgentKind::Claude => &["api.anthropic.com", "*.anthropic.com", "claude.ai", "*.claude.ai", "*.claude.com"],
        AgentKind::Codex => &["api.openai.com", "chatgpt.com", "auth.openai.com"],
        AgentKind::Gemini => &[
            "generativelanguage.googleapis.com",
            "oauth2.googleapis.com",
            "cloudcode-pa.googleapis.com",
        ],
        AgentKind::Aider => &[],
    }
}

/// Turn the flags into a policy. `lookup` reads the local environment.
pub fn build_guard(
    kind: AgentKind,
    args: &GuardArgs,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Option<shared::GuardSpec>, String> {
    if !args.is_on() {
        return Ok(None);
    }
    let mut spec = shared::GuardSpec::default();
    for raw in &args.secrets {
        let (name, hosts) = match raw.split_once('=') {
            Some((n, h)) => (
                n.trim().to_string(),
                h.split(',').map(|x| x.trim().to_ascii_lowercase()).filter(|x| !x.is_empty()).collect::<Vec<_>>(),
            ),
            None => {
                let n = raw.trim().to_string();
                let hosts = default_secret_hosts(&n)
                    .ok_or_else(|| {
                        format!("--secret {n}: say where it may be sent, e.g. --secret {n}=api.example.com")
                    })?
                    .iter()
                    .map(|h| h.to_string())
                    .collect();
                (n, hosts)
            }
        };
        if hosts.is_empty() {
            return Err(format!("--secret {name}: no hosts given"));
        }
        let value = lookup(&name)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("--secret {name}: {name} is not set in your local environment"))?;
        if value.len() < 8 {
            return Err(format!("--secret {name}: value is too short to protect (min 8 characters)"));
        }
        spec.secrets.push(shared::GuardSecret { name, value, hosts });
    }
    let mut allow: Vec<String> = agent_hosts(kind).iter().map(|h| h.to_string()).collect();
    allow.extend(args.allow.iter().map(|h| h.trim().to_ascii_lowercase()));
    allow.dedup();
    spec.allow_hosts = allow;
    spec.allow_ports = args.allow_ports.clone();
    Ok(Some(spec))
}

// ── Best-effort adapters (unverified — see module docs) ─────────────────────

fn build_codex(req: &AgentRequest) -> Vec<String> {
    let mut c = vec!["codex".to_string(), "exec".to_string()];
    if let Some(m) = req.model {
        c.push("-m".to_string());
        c.push(m.to_string());
    }
    if req.yolo {
        c.push("--full-auto".to_string());
    }
    c.push(req.prompt.to_string());
    c
}

fn build_aider(req: &AgentRequest) -> Vec<String> {
    let mut c = vec!["aider".to_string(), "--message".to_string(), req.prompt.to_string()];
    if let Some(m) = req.model {
        c.push("--model".to_string());
        c.push(m.to_string());
    }
    if req.yolo {
        c.push("--yes-always".to_string());
    }
    c
}

fn build_gemini(req: &AgentRequest) -> Vec<String> {
    let mut c = vec!["gemini".to_string(), "-p".to_string(), req.prompt.to_string()];
    if let Some(m) = req.model {
        c.push("-m".to_string());
        c.push(m.to_string());
    }
    if req.yolo {
        c.push("--yolo".to_string());
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(kind: AgentKind) -> AgentRequest<'static> {
        AgentRequest { kind, prompt: "fix the bug", model: None, json: false, yolo: false }
    }

    #[test]
    fn parse_round_trips() {
        for name in SUPPORTED {
            let k = AgentKind::parse(name).expect("known agent");
            assert_eq!(k.as_str(), *name);
        }
        assert!(AgentKind::parse("nope").is_none());
        assert_eq!(AgentKind::parse("Claude-Code"), Some(AgentKind::Claude));
    }

    #[test]
    fn claude_is_verified_others_are_not() {
        assert!(AgentKind::Claude.verified());
        assert!(!AgentKind::Codex.verified());
        assert!(!AgentKind::Aider.verified());
        assert!(!AgentKind::Gemini.verified());
    }

    #[test]
    fn claude_headless_invocation() {
        let cmd = build_command(&req(AgentKind::Claude));
        assert_eq!(cmd[0], "claude");
        assert_eq!(cmd[1], "--print");
        assert_eq!(cmd[2], "fix the bug");
        // Default (non-yolo) keeps a permission mode rather than bypassing.
        assert!(cmd.iter().any(|a| a == "--permission-mode"));
        assert!(!cmd.iter().any(|a| a == "--dangerously-skip-permissions"));
    }

    #[test]
    fn claude_model_and_json_and_yolo() {
        let r = AgentRequest {
            kind: AgentKind::Claude,
            prompt: "ship it",
            model: Some("opus"),
            json: true,
            yolo: true,
        };
        let cmd = build_command(&r);
        assert!(cmd.windows(2).any(|w| w[0] == "--model" && w[1] == "opus"));
        assert!(cmd.windows(2).any(|w| w[0] == "--output-format" && w[1] == "stream-json"));
        assert!(cmd.iter().any(|a| a == "--dangerously-skip-permissions"));
    }

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: std::collections::HashMap<String, String> =
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn guard_off_without_flags() {
        assert!(build_guard(AgentKind::Claude, &GuardArgs::default(), env(&[])).unwrap().is_none());
    }

    #[test]
    fn guard_known_secret_uses_default_hosts_and_local_value() {
        let args = GuardArgs { secrets: vec!["GITHUB_TOKEN".into()], ..Default::default() };
        let spec = build_guard(AgentKind::Claude, &args, env(&[("GITHUB_TOKEN", "ghp_0123456789abcdef")]))
            .unwrap()
            .unwrap();
        assert_eq!(spec.secrets[0].value, "ghp_0123456789abcdef");
        assert!(spec.secrets[0].hosts.contains(&"api.github.com".to_string()));
        assert!(spec.allow_hosts.contains(&"api.anthropic.com".to_string()));
    }

    #[test]
    fn guard_custom_hosts_and_errors() {
        let args = GuardArgs {
            secrets: vec!["DEPLOY_KEY=API.example.com, cdn.example.com".into()],
            allow: vec!["pypi.org".into()],
            allow_ports: vec![5432],
            ..Default::default()
        };
        let spec = build_guard(AgentKind::Aider, &args, env(&[("DEPLOY_KEY", "abcdefgh1234")]))
            .unwrap()
            .unwrap();
        assert_eq!(spec.secrets[0].hosts, vec!["api.example.com", "cdn.example.com"]);
        assert_eq!(spec.allow_hosts, vec!["pypi.org"]);
        assert_eq!(spec.allow_ports, vec![5432]);

        let unknown = GuardArgs { secrets: vec!["MY_KEY".into()], ..Default::default() };
        assert!(build_guard(AgentKind::Claude, &unknown, env(&[("MY_KEY", "abcdefgh1234")]))
            .unwrap_err()
            .contains("say where"));
        let missing = GuardArgs { secrets: vec!["OPENAI_API_KEY".into()], ..Default::default() };
        assert!(build_guard(AgentKind::Codex, &missing, env(&[])).unwrap_err().contains("not set"));
    }

    #[test]
    fn prompt_is_never_split() {
        // The whole prompt must reach the agent as a single argv element.
        for name in SUPPORTED {
            let k = AgentKind::parse(name).unwrap();
            let cmd = build_command(&req(k));
            assert!(cmd.iter().any(|a| a == "fix the bug"), "{name} dropped the prompt");
        }
    }
}
