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
