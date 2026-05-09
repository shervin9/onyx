// ---------------------------------------------------------------------------
// Named workspace registry — ~/.onyx/workspaces.json
//
// A workspace binds a human-friendly name (like "api" or "claude-agent")
// to a persistent remote session on a specific host.  The local store keeps
// the session_id + resume_token so the client can reconnect cross-process
// without prompting for a host or UUID.
// ---------------------------------------------------------------------------

use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

#[derive(Debug, Clone)]
pub struct Workspace {
    pub name: String,
    /// Raw target string as given by the user (e.g. "user@host").
    pub host: String,
    pub session_id: String,
    pub resume_token: String,
    pub created_at: u64,
    pub last_attached_at: u64,
    /// Last known state: "connected", "detached", or "unknown".
    pub last_state: String,
}

pub struct WorkspaceStore {
    path: PathBuf,
    workspaces: Vec<Workspace>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl WorkspaceStore {
    /// Load from disk.  Returns an empty store on any read or parse error.
    pub fn load() -> Self {
        let path = workspace_path();
        let workspaces = load_from_file(&path).unwrap_or_default();
        Self { path, workspaces }
    }

    pub fn all(&self) -> &[Workspace] {
        &self.workspaces
    }

    /// Find a workspace by exact name (case-sensitive).
    pub fn find_by_name(&self, name: &str) -> Option<&Workspace> {
        self.workspaces.iter().find(|w| w.name == name)
    }

    /// Insert or update a workspace.  On update, session credentials and
    /// last_attached_at are refreshed; host and created_at are preserved.
    pub fn upsert(&mut self, name: &str, host: &str, session_id: &str, resume_token: &str) {
        let now = unix_now();
        if let Some(ws) = self.workspaces.iter_mut().find(|w| w.name == name) {
            ws.session_id = session_id.to_string();
            ws.resume_token = resume_token.to_string();
            ws.last_attached_at = now;
            ws.last_state = "connected".to_string();
        } else {
            self.workspaces.push(Workspace {
                name: name.to_string(),
                host: host.to_string(),
                session_id: session_id.to_string(),
                resume_token: resume_token.to_string(),
                created_at: now,
                last_attached_at: now,
                last_state: "connected".to_string(),
            });
        }
    }

    /// Update the last-known state without touching session credentials.
    pub fn set_state(&mut self, name: &str, state: &str) {
        if let Some(ws) = self.workspaces.iter_mut().find(|w| w.name == name) {
            ws.last_state = state.to_string();
        }
    }

    /// Persist to disk.  Best-effort: callers may ignore errors.
    pub fn save(&self) -> anyhow::Result<()> {
        save_to_file(&self.path, &self.workspaces)
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers for `onyx ls`
// ---------------------------------------------------------------------------

/// Pretty-print the workspace table to stdout.
pub fn print_workspaces(workspaces: &[Workspace]) {
    if workspaces.is_empty() {
        eprintln!("no workspaces yet.");
        eprintln!("create one:  onyx <host> --workspace <name>");
        return;
    }

    // Compute column widths (minimum 4 to fit headers).
    let w_name = workspaces.iter().map(|w| w.name.len()).max().unwrap_or(4).max(4);
    let w_host = workspaces.iter().map(|w| w.host.len()).max().unwrap_or(4).max(4);
    let w_state = workspaces.iter().map(|w| w.last_state.len()).max().unwrap_or(5).max(5);

    println!(
        "{:<w_name$}  {:<w_host$}  {:<w_state$}  SESSION",
        "NAME", "HOST", "STATE"
    );
    println!(
        "{:-<w_name$}  {:-<w_host$}  {:-<w_state$}  --------",
        "", "", ""
    );
    for ws in workspaces {
        let short_id = short_session_id(&ws.session_id);
        println!(
            "{:<w_name$}  {:<w_host$}  {:<w_state$}  {}",
            ws.name, ws.host, ws.last_state, short_id
        );
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn workspace_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".onyx").join("workspaces.json")
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn short_session_id(id: &str) -> &str {
    let n = id.len().min(8);
    &id[..n]
}

fn load_from_file(path: &PathBuf) -> Option<Vec<Workspace>> {
    let content = fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&content).ok()?;
    let arr = v["workspaces"].as_array()?;
    Some(arr.iter().filter_map(workspace_from_json).collect())
}

fn save_to_file(path: &PathBuf, workspaces: &[Workspace]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let arr: Vec<serde_json::Value> = workspaces.iter().map(workspace_to_json).collect();
    let data = serde_json::json!({ "version": 1, "workspaces": arr });
    fs::write(path, serde_json::to_string_pretty(&data)?)?;
    Ok(())
}

fn workspace_to_json(w: &Workspace) -> serde_json::Value {
    serde_json::json!({
        "name":             w.name,
        "host":             w.host,
        "session_id":       w.session_id,
        "resume_token":     w.resume_token,
        "created_at":       w.created_at,
        "last_attached_at": w.last_attached_at,
        "last_state":       w.last_state,
    })
}

fn workspace_from_json(v: &serde_json::Value) -> Option<Workspace> {
    Some(Workspace {
        name:             v["name"].as_str()?.to_string(),
        host:             v["host"].as_str()?.to_string(),
        session_id:       v["session_id"].as_str()?.to_string(),
        resume_token:     v["resume_token"].as_str()?.to_string(),
        created_at:       v["created_at"].as_u64().unwrap_or(0),
        last_attached_at: v["last_attached_at"].as_u64().unwrap_or(0),
        last_state:       v["last_state"].as_str().unwrap_or("unknown").to_string(),
    })
}
