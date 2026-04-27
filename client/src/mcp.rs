//! stdio MCP server for Onyx — local-only, unauthenticated MVP.
//!
//! Transport: JSON-RPC 2.0 over stdin/stdout (newline-delimited).
//!
//! Each tool call spawns `onyx <sub> <target> --json …` via current_exe(),
//! parses the structured NDJSON output, and returns a clean result object.
//!
//! Architecture notes for future extension:
//! - `handle_message` is transport-agnostic (string in, Option<Value> out).
//!   Wrapping it in an HTTP handler is ~20 lines.
//! - `parse_exec_stream` / `parse_jobs_ndjson` are pure functions with no I/O.
//! - Only `run_mcp_serve` and `capture` touch OS resources.

use anyhow::Result;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

// ---------------------------------------------------------------------------
// Entry point (stdio)
// ---------------------------------------------------------------------------

pub async fn run_mcp_serve() -> Result<()> {
    eprintln!("[onyx mcp] local-only, unauthenticated MVP — do not expose to network");

    let onyx_bin = std::env::current_exe()?;
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Streaming tool calls write progress notifications directly to stdout
        // before the final response. Non-streaming calls use the standard path.
        let response = if is_streaming_call(trimmed) {
            streaming_call(trimmed, &onyx_bin, &mut stdout).await
        } else {
            handle_message(trimmed, &onyx_bin).await
        };

        if let Some(resp) = response {
            let mut out = resp.to_string();
            out.push('\n');
            stdout.write_all(out.as_bytes()).await?;
            stdout.flush().await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Transport-agnostic message handler
// ---------------------------------------------------------------------------

/// Handle one JSON-RPC 2.0 request line. Returns `None` for notifications.
/// This function is transport-agnostic — the same logic works for HTTP mode.
pub async fn handle_message(line: &str, onyx_bin: &PathBuf) -> Option<Value> {
    let request: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return Some(json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {"code": -32700, "message": format!("Parse error: {e}")}
            }));
        }
    };

    let id = request.get("id").cloned();
    let method = match request.get("method").and_then(|m| m.as_str()) {
        Some(m) => m,
        None => {
            return id.map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32600, "message": "Invalid request: missing method"}
                })
            });
        }
    };

    match method {
        "initialize" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "onyx-mcp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        })),

        // Notifications — no response.
        "initialized" | "notifications/initialized" => None,

        "ping" => Some(json!({"jsonrpc": "2.0", "id": id, "result": {}})),

        "tools/list" => Some(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {"tools": tools_schema()}
        })),

        "tools/call" => {
            let params = request.get("params").cloned().unwrap_or(json!({}));
            let tool_name = match params.get("name").and_then(|n| n.as_str()) {
                Some(n) => n.to_owned(),
                None => {
                    return Some(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32602, "message": "tools/call: missing name"}
                    }));
                }
            };
            let args = params.get("arguments").cloned().unwrap_or(json!({}));

            let (result_value, is_error) = match call_tool(&tool_name, &args, onyx_bin).await {
                Ok(v) => (v, false),
                Err(e) => (mk_error("exec_failed", &e.to_string()), true),
            };

            Some(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [{"type": "text", "text": result_value.to_string()}],
                    "isError": is_error
                }
            }))
        }

        _ => id.map(|id| {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {"code": -32601, "message": format!("Method not found: {method}")}
            })
        }),
    }
}

// ---------------------------------------------------------------------------
// Tool schemas
// ---------------------------------------------------------------------------

fn tools_schema() -> Value {
    json!([
        {
            "name": "onyx_exec",
            "description": "Execute a command on a remote Onyx target. Returns structured stdout, stderr, exit_code, and duration_ms. Use detach:true for long-running jobs (returns job_id immediately). Exit code 124 means the server-side timeout fired.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Remote host or SSH config alias (e.g. hetzner-dev, user@1.2.3.4)"
                    },
                    "command": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Command and arguments, e.g. [\"cargo\", \"build\", \"--release\"]"
                    },
                    "detach": {
                        "type": "boolean",
                        "description": "Start job in background; returns job_id. Retrieve output with onyx_attach or onyx_logs."
                    },
                    "cwd": {
                        "type": "string",
                        "description": "Working directory on the remote host."
                    },
                    "env": {
                        "type": "object",
                        "description": "Extra environment variables as a KEY→VALUE map.",
                        "additionalProperties": {"type": "string"}
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "description": "Kill the job after this many milliseconds. Client receives exit code 124."
                    },
                    "stream": {
                        "type": "boolean",
                        "description": "Emit incremental events via notifications/progress instead of buffering. Each stdout/stderr chunk arrives as a separate MCP notification."
                    }
                },
                "required": ["target", "command"]
            }
        },
        {
            "name": "onyx_jobs",
            "description": "List all running and recently-finished jobs on a remote Onyx target.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Remote host or SSH config alias"
                    }
                },
                "required": ["target"]
            }
        },
        {
            "name": "onyx_attach",
            "description": "Attach to a running job and stream its output until completion. Auto-reconnects on short transport drops (up to 10 min).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Remote host or SSH config alias"},
                    "job_id": {"type": "string", "description": "Job ID from onyx_exec (detach:true) or onyx_jobs"},
                    "stream": {"type": "boolean", "description": "Emit incremental events via notifications/progress."}
                },
                "required": ["target", "job_id"]
            }
        },
        {
            "name": "onyx_logs",
            "description": "Fetch buffered log output (up to 4 MiB ring) for a job. Works for running or finished jobs. Does not stream — snapshot only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Remote host or SSH config alias"},
                    "job_id": {"type": "string", "description": "Job ID from onyx_exec (detach:true) or onyx_jobs"},
                    "stream": {"type": "boolean", "description": "Emit incremental events via notifications/progress."}
                },
                "required": ["target", "job_id"]
            }
        },
        {
            "name": "onyx_kill",
            "description": "Kill a running job on a remote Onyx target. Returns {killed: true} if the signal was sent, {killed: false} if the job was already finished or not found.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Remote host or SSH config alias"},
                    "job_id": {"type": "string", "description": "Job ID to kill"}
                },
                "required": ["target", "job_id"]
            }
        }
    ])
}

// ---------------------------------------------------------------------------
// Tool dispatch
// ---------------------------------------------------------------------------

async fn call_tool(name: &str, args: &Value, onyx_bin: &PathBuf) -> Result<Value> {
    match name {
        "onyx_exec" => exec_tool(args, onyx_bin).await,
        "onyx_jobs" => jobs_tool(args, onyx_bin).await,
        "onyx_attach" => attach_tool(args, onyx_bin).await,
        "onyx_logs" => logs_tool(args, onyx_bin).await,
        "onyx_kill" => kill_tool(args, onyx_bin).await,
        _ => Err(anyhow::anyhow!("unknown tool: {name}")),
    }
}

// ---------------------------------------------------------------------------
// Streaming: detection + routing
// ---------------------------------------------------------------------------

/// True when the JSON-RPC line is a tools/call with `arguments.stream: true`.
fn is_streaming_call(line: &str) -> bool {
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return false;
    };
    v["method"].as_str() == Some("tools/call")
        && v["params"]["arguments"]["stream"].as_bool() == Some(true)
}

/// Handle a streaming tool call: write `notifications/progress` events to
/// `stdout` as the subprocess produces output, then return the final
/// JSON-RPC response (same shape as the buffered path).
async fn streaming_call(
    line: &str,
    onyx_bin: &PathBuf,
    stdout: &mut tokio::io::Stdout,
) -> Option<Value> {
    let request: Value = serde_json::from_str(line).ok()?;
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let params = request.get("params").cloned().unwrap_or(json!({}));
    let tool_name = params["name"].as_str()?.to_string();
    let args = params.get("arguments").cloned().unwrap_or(json!({}));

    let (result, is_error) = match stream_exec_tool(&tool_name, &args, onyx_bin, &id, stdout).await
    {
        Ok(v) => (v, false),
        Err(e) => (mk_error("exec_failed", &e.to_string()), true),
    };

    Some(json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{"type": "text", "text": result.to_string()}],
            "isError": is_error
        }
    }))
}

/// Route a streaming tool call: exec/attach/logs get `capture_streaming`;
/// everything else falls back to the normal buffered `call_tool`.
async fn stream_exec_tool(
    tool_name: &str,
    args: &Value,
    onyx_bin: &PathBuf,
    request_id: &Value,
    stdout: &mut tokio::io::Stdout,
) -> Result<Value> {
    match tool_name {
        "onyx_exec" | "onyx_attach" | "onyx_logs" => {
            let mut cmd = build_exec_cmd(tool_name, args, onyx_bin)?;
            let mut result = capture_streaming(&mut cmd, request_id, stdout).await?;
            // attach/logs don't emit a started event; fill job_id from args.
            if result["job_id"].is_null() {
                if let Some(jid) = args["job_id"].as_str() {
                    result["job_id"] = json!(jid);
                }
            }
            Ok(result)
        }
        _ => call_tool(tool_name, args, onyx_bin).await,
    }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

/// Build the `onyx <sub>` command for exec/attach/logs tools.
/// Extracted so both the buffered and streaming paths share one code path.
fn build_exec_cmd(tool_name: &str, args: &Value, onyx_bin: &PathBuf) -> Result<Command> {
    match tool_name {
        "onyx_exec" => {
            let target = require_str(args, "target")?;
            let command = require_str_array(args, "command")?;
            let detach = args["detach"].as_bool().unwrap_or(false);
            let mut cmd = Command::new(onyx_bin);
            cmd.arg("exec").arg(target).arg("--json");
            if detach {
                cmd.arg("--detach");
            }
            if let Some(cwd) = args["cwd"].as_str() {
                cmd.arg("--cwd").arg(cwd);
            }
            if let Some(env_map) = args["env"].as_object() {
                for (k, v) in env_map {
                    if let Some(val) = v.as_str() {
                        cmd.arg("--env").arg(format!("{k}={val}"));
                    }
                }
            }
            if let Some(timeout_ms) = args["timeout_ms"].as_u64() {
                let secs = timeout_ms.div_ceil(1000);
                cmd.arg("--timeout").arg(format!("{secs}s"));
            }
            cmd.arg("--");
            for s in command {
                cmd.arg(s);
            }
            Ok(cmd)
        }
        "onyx_attach" => {
            let target = require_str(args, "target")?;
            let job_id = require_str(args, "job_id")?;
            let mut cmd = Command::new(onyx_bin);
            cmd.args(["attach", target, job_id, "--json"]);
            Ok(cmd)
        }
        "onyx_logs" => {
            let target = require_str(args, "target")?;
            let job_id = require_str(args, "job_id")?;
            let mut cmd = Command::new(onyx_bin);
            cmd.args(["logs", target, job_id, "--json"]);
            Ok(cmd)
        }
        _ => Err(anyhow::anyhow!("no exec command for tool: {tool_name}")),
    }
}

async fn exec_tool(args: &Value, onyx_bin: &PathBuf) -> Result<Value> {
    let mut cmd = build_exec_cmd("onyx_exec", args, onyx_bin)?;
    let (ndjson, diagnostics) = capture(&mut cmd).await?;

    let detach = args["detach"].as_bool().unwrap_or(false);
    if detach {
        let job_id = ndjson
            .lines()
            .find_map(|l| {
                let v: Value = serde_json::from_str(l.trim()).ok()?;
                if v["type"].as_str() == Some("started") {
                    Some(v["job_id"].as_str().unwrap_or("").to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();
        return Ok(json!({
            "job_id": job_id,
            "status": "detached",
            "hint": "use onyx_attach or onyx_logs to retrieve output",
            "diagnostics": diagnostics
        }));
    }

    let mut result = parse_exec_stream(&ndjson);
    result["diagnostics"] = json!(diagnostics);
    Ok(result)
}

async fn jobs_tool(args: &Value, onyx_bin: &PathBuf) -> Result<Value> {
    let target = require_str(args, "target")?;

    let mut cmd = Command::new(onyx_bin);
    cmd.args(["jobs", target, "--json"]);

    let (ndjson, diagnostics) = capture(&mut cmd).await?;

    Ok(json!({
        "jobs": parse_jobs_ndjson(&ndjson),
        "diagnostics": diagnostics
    }))
}

async fn attach_tool(args: &Value, onyx_bin: &PathBuf) -> Result<Value> {
    let job_id = require_str(args, "job_id")?;
    let mut cmd = build_exec_cmd("onyx_attach", args, onyx_bin)?;
    let (ndjson, diagnostics) = capture(&mut cmd).await?;
    let mut result = parse_exec_stream(&ndjson);
    if result["job_id"].is_null() {
        result["job_id"] = json!(job_id);
    }
    result["diagnostics"] = json!(diagnostics);
    Ok(result)
}

async fn logs_tool(args: &Value, onyx_bin: &PathBuf) -> Result<Value> {
    let job_id = require_str(args, "job_id")?;
    let mut cmd = build_exec_cmd("onyx_logs", args, onyx_bin)?;
    let (ndjson, diagnostics) = capture(&mut cmd).await?;
    let mut result = parse_exec_stream(&ndjson);
    if result["job_id"].is_null() {
        result["job_id"] = json!(job_id);
    }
    result["diagnostics"] = json!(diagnostics);
    Ok(result)
}

async fn kill_tool(args: &Value, onyx_bin: &PathBuf) -> Result<Value> {
    let target = require_str(args, "target")?;
    let job_id = require_str(args, "job_id")?;

    let mut cmd = Command::new(onyx_bin);
    cmd.args(["kill", target, job_id, "--json"]);

    let (ndjson, diagnostics) = capture(&mut cmd).await?;
    let mut result = parse_kill_result_ndjson(&ndjson)?;
    if result["job_id"].is_null() {
        result["job_id"] = json!(job_id);
    }
    result["diagnostics"] = json!(diagnostics);
    Ok(result)
}

// ---------------------------------------------------------------------------
// Subprocess capture
// ---------------------------------------------------------------------------

/// Spawn a command and return (stdout, stderr) as owned strings.
///
/// stdout = the NDJSON event stream produced by `onyx --json`
/// stderr = onyx client diagnostics (bootstrap progress, reconnect messages)
///
/// Returns Err only when stdout is empty and the process failed — that means
/// the connection/bootstrap itself broke before any NDJSON was emitted.
/// A non-zero exit with NDJSON in stdout is normal (remote command failed);
/// the caller parses the `finished`/`error` events.
async fn capture(cmd: &mut Command) -> Result<(String, String)> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = cmd.output().await?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if !output.status.success() && stdout.trim().is_empty() {
        let msg = if stderr.is_empty() {
            format!("onyx exited with status {}", output.status)
        } else {
            classify_error(&stderr)
        };
        return Err(anyhow::anyhow!("{msg}"));
    }

    Ok((stdout, stderr))
}

/// Like `capture` but reads subprocess stdout line-by-line, writing a
/// `notifications/progress` JSON-RPC notification for every meaningful event.
/// Stderr is collected concurrently to prevent deadlock on a full pipe.
/// Returns the same aggregated result as `parse_exec_stream` would.
async fn capture_streaming<W: AsyncWriteExt + Unpin>(
    cmd: &mut Command,
    request_id: &Value,
    writer: &mut W,
) -> Result<Value> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let child_stdout = child.stdout.take().expect("piped");
    let child_stderr = child.stderr.take().expect("piped");

    // Drain stderr in a background task so a full stderr pipe never blocks
    // the stdout reader and causes a deadlock.
    let stderr_task = tokio::spawn(async move {
        let mut buf = String::new();
        let mut stderr = child_stderr;
        stderr.read_to_string(&mut buf).await.ok();
        buf
    });

    let mut reader = BufReader::new(child_stdout);
    let mut line = String::new();
    let mut seq: u64 = 0;
    let mut ndjson_buf = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        ndjson_buf.push_str(trimmed);
        ndjson_buf.push('\n');

        // Forward every meaningful event as a progress notification so the
        // MCP client sees output incrementally rather than after completion.
        if let Some(notif) = progress_notification_for_event(trimmed, request_id, seq) {
            seq += 1;
            let mut out = notif.to_string();
            out.push('\n');
            writer.write_all(out.as_bytes()).await?;
            writer.flush().await?;
        }
    }

    let _ = child.wait().await;
    let stderr_str = stderr_task.await.unwrap_or_default().trim().to_string();

    if ndjson_buf.trim().is_empty() {
        let msg = if stderr_str.is_empty() {
            "onyx produced no output".to_string()
        } else {
            classify_error(&stderr_str)
        };
        return Err(anyhow::anyhow!("{msg}"));
    }

    let mut result = parse_exec_stream(&ndjson_buf);
    result["diagnostics"] = json!(stderr_str);
    Ok(result)
}

fn progress_notification_for_event(line: &str, request_id: &Value, seq: u64) -> Option<Value> {
    let event: Value = serde_json::from_str(line).ok()?;
    if !event["type"].as_str().is_some_and(is_streamable_event) {
        return None;
    }
    Some(json!({
        "jsonrpc": "2.0",
        "method": "notifications/progress",
        "params": {
            "progressToken": request_id,
            "progress": seq,
            // The event JSON is embedded as a string so the
            // client can parse it if it wants structured data.
            "message": line
        }
    }))
}

/// Events that are meaningful to forward incrementally. Informational events
/// like "reconnecting"/"resumed" are included so the client can show progress;
/// internal events ("job", etc.) are excluded.
pub fn is_streamable_event(t: &str) -> bool {
    matches!(
        t,
        "started"
            | "stdout"
            | "stderr"
            | "finished"
            | "timeout"
            | "reconnecting"
            | "resumed"
            | "gap"
            | "error"
    )
}

// ---------------------------------------------------------------------------
// NDJSON parsers (pure — no I/O, easy to test)
// ---------------------------------------------------------------------------

/// Parse the NDJSON event stream from `onyx exec/attach/logs --json`.
///
/// Result schema:
/// ```json
/// {
///   "job_id":      "job_abc…" | null,
///   "status":      "succeeded" | "failed" | "killed" | "running" | "error" | "unknown",
///   "exit_code":   0 | 1 | … | null,
///   "stdout":      "<remote stdout text>",
///   "stderr":      "<remote stderr text>",
///   "duration_ms": 1234 | null,
///   "truncated":   true   // only present when ring-buffer gap detected
///   "error":       "…"    // only present on server-side error event
/// }
/// ```
/// `diagnostics` is added by the caller (onyx client stderr).
pub fn parse_exec_stream(ndjson: &str) -> Value {
    let mut job_id: Option<String> = None;
    let mut stdout_buf = String::new();
    let mut stderr_buf = String::new();
    let mut exit_code: Value = Value::Null;
    let mut duration_ms: Value = Value::Null;
    let mut status = "unknown";
    let mut error: Option<String> = None;
    let mut truncated = false;
    let mut timed_out = false;

    for line in ndjson.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        match v["type"].as_str() {
            Some("started") => {
                job_id = v["job_id"].as_str().map(String::from);
                status = "running";
            }
            Some("stdout") => {
                if let Some(data) = v["data"].as_str() {
                    stdout_buf.push_str(data);
                }
            }
            Some("stderr") => {
                if let Some(data) = v["data"].as_str() {
                    stderr_buf.push_str(data);
                }
            }
            Some("finished") => {
                duration_ms = v["duration_ms"].clone();
                if !timed_out {
                    exit_code = v["exit_code"].clone();
                    status = match v["exit_code"].as_i64() {
                        Some(0) => "succeeded",
                        Some(_) => "failed",
                        None => "killed",
                    };
                }
            }
            Some("timeout") => {
                timed_out = true;
                exit_code = json!(124);
                status = "timed_out";
            }
            Some("error") => {
                error = v["reason"].as_str().map(String::from);
                status = "error";
            }
            Some("gap") => {
                truncated = true;
            }
            // "reconnecting", "resumed" — informational, no action needed
            _ => {}
        }
    }

    let mut obj = json!({
        "job_id":      job_id,
        "status":      status,
        "exit_code":   exit_code,
        "stdout":      stdout_buf,
        "stderr":      stderr_buf,
        "duration_ms": duration_ms,
    });

    if truncated {
        obj["truncated"] = json!(true);
    }
    if let Some(e) = error {
        obj["error"] = json!(e);
        obj["status"] = json!("error");
    }

    obj
}

fn parse_kill_result_ndjson(ndjson: &str) -> Result<Value> {
    let mut exec_error: Option<String> = None;
    for line in ndjson
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        match v["type"].as_str() {
            Some("kill_result") => {
                return Ok(json!({
                    "job_id": v["job_id"],
                    "killed": v["killed"].as_bool().unwrap_or(false),
                    "message": v["message"]
                }));
            }
            Some("error") => {
                exec_error = v["reason"].as_str().map(str::to_string);
            }
            _ => {}
        }
    }
    if let Some(reason) = exec_error {
        anyhow::bail!("{reason}");
    }
    anyhow::bail!("onyx kill produced no kill_result event")
}

/// Parse the NDJSON produced by `onyx jobs --json`.
///
/// Result schema: JSON array of job objects:
/// ```json
/// [
///   {
///     "job_id":           "job_abc…",
///     "status":           "running" | "succeeded" | "failed" | "detached" | "expired",
///     "command":          "python train.py",
///     "exit_code":        0 | 1 | … | null,
///     "started_at_unix":  1234567890,
///     "finished_at_unix": 1234567899 | null,
///     "attached":         true | false,
///     "buffered_bytes":   4096
///   }
/// ]
/// ```
pub fn parse_jobs_ndjson(ndjson: &str) -> Value {
    let jobs: Vec<Value> = ndjson
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["type"].as_str() == Some("job"))
        .map(|v| {
            json!({
                "job_id":           v["job_id"],
                "status":           v["status"],
                "command":          v["command"],
                "exit_code":        v["exit_code"],
                "started_at_unix":  v["started_at_unix"],
                "finished_at_unix": v["finished_at_unix"],
                "attached":         v["attached"],
                "buffered_bytes":   v["buffered_bytes"]
            })
        })
        .collect();

    json!(jobs)
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

fn mk_error(kind: &str, message: &str) -> Value {
    json!({"error": kind, "message": message})
}

/// Classify common onyx/network error strings into stable short tokens that
/// agents can pattern-match without parsing free-form English.
fn classify_error(stderr: &str) -> String {
    let lower = stderr.to_lowercase();
    let kind =
        if lower.contains("ssh authentication failed: the selected key requires a passphrase") {
            "passphrase_required"
        } else if lower.contains("ssh authentication failed") {
            "ssh_auth_failed"
        } else if lower.contains("quic handshake timed out") || lower.contains("udp/") {
            "udp_blocked"
        } else if lower.contains("quic handshake failed") {
            "quic_failed"
        } else if lower.contains("no address")
            || lower.contains("failed to lookup")
            || lower.contains("name or service")
        {
            "unknown_target"
        } else if lower.contains("job not found") || lower.contains("no such job") {
            "job_not_found"
        } else if lower.contains("bootstrap") {
            "bootstrap_failed"
        } else if lower.contains("connection refused")
            || lower.contains("timed out")
            || lower.contains("unreachable")
        {
            "connection_failed"
        } else {
            "exec_failed"
        };
    format!("{kind}: {stderr}")
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

fn require_str<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args[key]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing required argument: {key}"))
}

fn require_str_array<'a>(args: &'a Value, key: &str) -> Result<Vec<&'a str>> {
    args[key]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("{key} must be an array"))?
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| anyhow::anyhow!("{key} elements must be strings"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- parse_exec_stream ---------------------------------------------------

    #[test]
    fn exec_stream_success() {
        let ndjson = r#"
{"type":"started","job_id":"job_abc","started_at_unix":1000,"command":"echo hi"}
{"type":"stdout","seq":1,"data":"hello\n"}
{"type":"stdout","seq":2,"data":"world\n"}
{"type":"stderr","seq":3,"data":"warn: something\n"}
{"type":"finished","exit_code":0,"finished_at_unix":1002,"duration_ms":2000}
"#;
        let r = parse_exec_stream(ndjson);
        assert_eq!(r["job_id"], "job_abc");
        assert_eq!(r["status"], "succeeded");
        assert_eq!(r["exit_code"], 0);
        assert_eq!(r["stdout"], "hello\nworld\n");
        assert_eq!(r["stderr"], "warn: something\n");
        assert_eq!(r["duration_ms"], 2000);
        assert!(r.get("truncated").is_none());
        assert!(r.get("error").is_none());
    }

    #[test]
    fn exec_stream_failed_nonzero() {
        let ndjson = r#"
{"type":"started","job_id":"job_xyz","started_at_unix":1000,"command":"false"}
{"type":"finished","exit_code":1,"finished_at_unix":1001,"duration_ms":1000}
"#;
        let r = parse_exec_stream(ndjson);
        assert_eq!(r["status"], "failed");
        assert_eq!(r["exit_code"], 1);
        assert_eq!(r["stdout"], "");
        assert_eq!(r["stderr"], "");
    }

    #[test]
    fn exec_stream_killed_no_exit_code() {
        let ndjson = r#"
{"type":"started","job_id":"job_k","started_at_unix":1000,"command":"sleep 99"}
{"type":"finished","exit_code":null,"finished_at_unix":1005,"duration_ms":5000}
"#;
        let r = parse_exec_stream(ndjson);
        assert_eq!(r["status"], "killed");
        assert!(r["exit_code"].is_null());
    }

    #[test]
    fn exec_stream_timeout_preserves_timed_out_status_and_exit_code() {
        let ndjson = r#"
{"type":"started","job_id":"job_t","started_at_unix":1000,"command":"sleep 99"}
{"type":"timeout"}
{"type":"finished","exit_code":null,"finished_at_unix":1012,"duration_ms":12000}
"#;
        let r = parse_exec_stream(ndjson);
        assert_eq!(r["status"], "timed_out");
        assert_eq!(r["exit_code"], 124);
        assert_eq!(r["duration_ms"], 12000);
    }

    #[test]
    fn exec_stream_server_error() {
        let ndjson = r#"{"type":"error","reason":"job not found: job_xyz"}"#;
        let r = parse_exec_stream(ndjson);
        assert_eq!(r["status"], "error");
        assert_eq!(r["error"], "job not found: job_xyz");
    }

    #[test]
    fn exec_stream_gap_sets_truncated() {
        let ndjson = r#"
{"type":"started","job_id":"job_gap","started_at_unix":1000,"command":"cmd"}
{"type":"gap","oldest_seq":50}
{"type":"stdout","seq":50,"data":"recent output\n"}
{"type":"finished","exit_code":0,"finished_at_unix":1001,"duration_ms":1000}
"#;
        let r = parse_exec_stream(ndjson);
        assert_eq!(r["truncated"], true);
        assert_eq!(r["stdout"], "recent output\n");
    }

    #[test]
    fn exec_stream_detach_only_started() {
        // Detached exec: only a started event, no finished.
        let ndjson =
            r#"{"type":"started","job_id":"job_det","started_at_unix":1000,"command":"long-job"}"#;
        let r = parse_exec_stream(ndjson);
        assert_eq!(r["job_id"], "job_det");
        assert_eq!(r["status"], "running");
        assert!(r["exit_code"].is_null());
        assert!(r["duration_ms"].is_null());
    }

    #[test]
    fn exec_stream_stdout_stderr_separated() {
        let ndjson = r#"
{"type":"stdout","seq":1,"data":"out1\n"}
{"type":"stderr","seq":2,"data":"err1\n"}
{"type":"stdout","seq":3,"data":"out2\n"}
{"type":"stderr","seq":4,"data":"err2\n"}
{"type":"finished","exit_code":0,"finished_at_unix":1,"duration_ms":100}
"#;
        let r = parse_exec_stream(ndjson);
        assert_eq!(r["stdout"], "out1\nout2\n");
        assert_eq!(r["stderr"], "err1\nerr2\n");
    }

    #[test]
    fn exec_stream_ignores_unknown_types() {
        let ndjson = r#"
{"type":"reconnecting"}
{"type":"resumed","job_id":"job_r","seq":5}
{"type":"stdout","seq":6,"data":"ok\n"}
{"type":"finished","exit_code":0,"finished_at_unix":1,"duration_ms":50}
"#;
        let r = parse_exec_stream(ndjson);
        assert_eq!(r["stdout"], "ok\n");
        assert_eq!(r["status"], "succeeded");
    }

    #[test]
    fn exec_stream_empty_input() {
        let r = parse_exec_stream("");
        assert_eq!(r["status"], "unknown");
        assert!(r["job_id"].is_null());
        assert_eq!(r["stdout"], "");
        assert_eq!(r["stderr"], "");
    }

    #[test]
    fn kill_result_parser_extracts_message_and_state() {
        let parsed = parse_kill_result_ndjson(
            r#"{"type":"kill_result","job_id":"job_dead","killed":false,"message":"job job_dead already finished"}"#,
        )
        .unwrap();
        assert_eq!(parsed["job_id"], "job_dead");
        assert_eq!(parsed["killed"], false);
        assert_eq!(parsed["message"], "job job_dead already finished");
    }

    #[test]
    fn kill_result_parser_surfaces_exec_error() {
        let err = parse_kill_result_ndjson(r#"{"type":"error","reason":"job job_dead not found"}"#)
            .unwrap_err();
        assert_eq!(err.to_string(), "job job_dead not found");
    }

    // -- parse_jobs_ndjson ---------------------------------------------------

    #[test]
    fn jobs_ndjson_empty() {
        assert_eq!(parse_jobs_ndjson(""), json!([]));
    }

    #[test]
    fn jobs_ndjson_multiple() {
        let ndjson = r#"
{"type":"job","job_id":"job_a","status":"running","command":"python train.py","started_at_unix":1000,"finished_at_unix":null,"exit_code":null,"attached":true,"buffered_bytes":1024}
{"type":"job","job_id":"job_b","status":"succeeded","command":"echo done","started_at_unix":900,"finished_at_unix":901,"exit_code":0,"attached":false,"buffered_bytes":5}
"#;
        let r = parse_jobs_ndjson(ndjson);
        let arr = r.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["job_id"], "job_a");
        assert_eq!(arr[0]["status"], "running");
        assert!(arr[0]["exit_code"].is_null());
        assert_eq!(arr[1]["job_id"], "job_b");
        assert_eq!(arr[1]["exit_code"], 0);
    }

    #[test]
    fn jobs_ndjson_skips_non_job_lines() {
        let ndjson = r#"
{"type":"other","job_id":"x"}
not json at all
{"type":"job","job_id":"job_real","status":"running","command":"cmd","started_at_unix":1000,"finished_at_unix":null,"exit_code":null,"attached":false,"buffered_bytes":0}
"#;
        let r = parse_jobs_ndjson(ndjson);
        assert_eq!(r.as_array().unwrap().len(), 1);
        assert_eq!(r[0]["job_id"], "job_real");
    }

    // -- error helpers -------------------------------------------------------

    #[test]
    fn classify_unknown_target() {
        let msg = classify_error("no address resolved for bad-host");
        assert!(msg.starts_with("unknown_target:"));
    }

    #[test]
    fn classify_job_not_found() {
        let msg = classify_error("job not found: job_xyz");
        assert!(msg.starts_with("job_not_found:"));
    }

    #[test]
    fn classify_bootstrap_failed() {
        let msg = classify_error("bootstrap failed: cargo build failed");
        assert!(msg.starts_with("bootstrap_failed:"));
    }

    #[test]
    fn classify_connection_refused() {
        let msg = classify_error("connection refused (os error 111)");
        assert!(msg.starts_with("connection_failed:"));
    }

    #[test]
    fn classify_passphrase_required() {
        let msg = classify_error(
            "[onyx] SSH authentication failed: the selected key requires a passphrase.",
        );
        assert!(msg.starts_with("passphrase_required:"));
    }

    #[test]
    fn classify_udp_blocked() {
        let msg = classify_error("QUIC handshake timed out after 8 s; UDP/7272 may be blocked");
        assert!(msg.starts_with("udp_blocked:"));
    }

    #[test]
    fn mk_error_shape() {
        let e = mk_error("job_not_found", "no such job: job_xyz");
        assert_eq!(e["error"], "job_not_found");
        assert_eq!(e["message"], "no such job: job_xyz");
    }

    // -- streaming helpers ---------------------------------------------------

    #[test]
    fn streamable_event_covers_all_meaningful_types() {
        for t in [
            "started",
            "stdout",
            "stderr",
            "finished",
            "timeout",
            "reconnecting",
            "resumed",
            "gap",
            "error",
        ] {
            assert!(is_streamable_event(t), "{t} should be streamable");
        }
        assert!(
            !is_streamable_event("job"),
            "job list events are not exec events"
        );
        assert!(!is_streamable_event("kill_result"));
        assert!(!is_streamable_event("unknown_type"));
    }

    #[test]
    fn streaming_call_detects_stream_flag() {
        let streaming = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"onyx_exec","arguments":{"target":"h","command":["ls"],"stream":true}}}"#;
        let buffered = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"onyx_exec","arguments":{"target":"h","command":["ls"]}}}"#;
        let other = r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#;
        assert!(is_streaming_call(streaming));
        assert!(!is_streaming_call(buffered));
        assert!(!is_streaming_call(other));
        assert!(!is_streaming_call("not json {{{"));
    }

    #[test]
    fn progress_notification_wraps_streamable_events() {
        let notif = progress_notification_for_event(
            r#"{"type":"resumed","job_id":"job_r","seq":5}"#,
            &json!(7),
            3,
        )
        .unwrap();
        assert_eq!(notif["method"], "notifications/progress");
        assert_eq!(notif["params"]["progressToken"], 7);
        assert_eq!(notif["params"]["progress"], 3);
        assert_eq!(
            notif["params"]["message"],
            r#"{"type":"resumed","job_id":"job_r","seq":5}"#
        );
    }

    #[test]
    fn progress_notification_skips_non_streamable_events() {
        assert!(progress_notification_for_event(
            r#"{"type":"kill_result","job_id":"job_k","killed":true}"#,
            &json!(1),
            0,
        )
        .is_none());
    }

    // -- protocol layer (no subprocess) -------------------------------------

    #[tokio::test]
    async fn handle_initialize() {
        let dummy = PathBuf::from("/dev/null");
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let resp = handle_message(req, &dummy).await.unwrap();
        assert_eq!(resp["result"]["serverInfo"]["name"], "onyx-mcp");
        assert_eq!(resp["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(resp["id"], 1);
    }

    #[tokio::test]
    async fn handle_tools_list() {
        let dummy = PathBuf::from("/dev/null");
        let req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        let resp = handle_message(req, &dummy).await.unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 5);
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"onyx_exec"));
        assert!(names.contains(&"onyx_jobs"));
        assert!(names.contains(&"onyx_attach"));
        assert!(names.contains(&"onyx_logs"));
        assert!(names.contains(&"onyx_kill"));
        // Each tool must have inputSchema with required fields
        for tool in tools {
            assert!(tool["inputSchema"]["properties"]["target"].is_object());
        }
    }

    #[tokio::test]
    async fn handle_ping() {
        let dummy = PathBuf::from("/dev/null");
        let resp = handle_message(r#"{"jsonrpc":"2.0","id":9,"method":"ping"}"#, &dummy)
            .await
            .unwrap();
        assert!(resp["result"].is_object());
        assert_eq!(resp["id"], 9);
    }

    #[tokio::test]
    async fn handle_unknown_method_returns_error() {
        let dummy = PathBuf::from("/dev/null");
        let resp = handle_message(
            r#"{"jsonrpc":"2.0","id":3,"method":"unknown/method"}"#,
            &dummy,
        )
        .await
        .unwrap();
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn handle_notification_no_response() {
        let dummy = PathBuf::from("/dev/null");
        let resp = handle_message(r#"{"jsonrpc":"2.0","method":"initialized"}"#, &dummy).await;
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn handle_parse_error() {
        let dummy = PathBuf::from("/dev/null");
        let resp = handle_message("not json {{{", &dummy).await.unwrap();
        assert_eq!(resp["error"]["code"], -32700);
    }
}
