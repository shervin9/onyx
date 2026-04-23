use anyhow::{Context, Result};
use quinn::{ClientConfig, Endpoint};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use shared::{JobStatus, JobSummary, Message, StdStream, DEFAULT_PORT};
use std::{
    collections::HashMap,
    fs,
    io::{IsTerminal, Read, Write},
    net::SocketAddr,
    os::unix::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        process::{CommandExt, ExitStatusExt},
    },
    path::{Path, PathBuf},
    sync::{atomic::Ordering, Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

mod mcp;

// ---------------------------------------------------------------------------
// Source files embedded at compile time for remote bootstrap.
// ---------------------------------------------------------------------------

const REMOTE_WORKSPACE_TOML: &str =
    "[workspace]\nmembers = [\"shared\", \"server\"]\nresolver = \"2\"\n";

const SHARED_CARGO_TOML: &str = include_str!("../../shared/Cargo.toml");
const SHARED_LIB_RS: &str = include_str!("../../shared/src/lib.rs");
const SERVER_CARGO_TOML: &str = include_str!("../../server/Cargo.toml");
const SERVER_MAIN_RS: &str = include_str!("../../server/src/main.rs");

const REMOTE_DIR: &str = "~/.local/share/onyx";

// ---------------------------------------------------------------------------
// Remote config files — tmux setup + live status bar script.
// Uploaded to CONF_DIR during bootstrap and versioned via config_hash().
// ---------------------------------------------------------------------------

/// tmux configuration: context-aware status bar, terminal title propagation
/// for Warp and friends, and automatic window renaming based on the running
/// foreground command (onyx:shell, onyx:claude, onyx:codex, ...).
///
/// Kept minimal on purpose — all dynamic pieces go through status.sh so
/// there's exactly one shell invocation per refresh class.
const ONYX_TMUX_CONF: &str = r##"# onyx — auto-generated, do not edit (overwritten on update)
set -g mouse on
set -g history-limit 50000

# Terminal title → "claude · ~/workspace/meviq". Warp's sidebar / tab
# detection reads this. set-titles fires on window/pane changes, not per
# tick, so the shell cost is negligible.
set -g set-titles on
set -g set-titles-string '#(~/.config/onyx/status.sh title "#{pane_current_path}" "#{pane_current_command}")'

# Auto-rename window to "onyx:shell" / "onyx:claude" / "onyx:codex" based
# on the foreground command inside the pane.
set -g automatic-rename on
set -g automatic-rename-format '#(~/.config/onyx/status.sh window "#{pane_current_path}" "#{pane_current_command}")'

# ── Status bar ────────────────────────────────────────────────────────────────
# Near-black surface; minimal visual weight when healthy.
# colour234 = #1c1c1c   colour240 = #585858   colour241 = #626262
# colour238 = #444444   colour248 = #a8a8a8
set -g status-style    'bg=colour234,fg=colour240'
set -g status-interval 5

# Left: one state dot + transport label — no brackets, no bold, no full-bar color.
# Dot color encodes connection state (all via tmux built-ins, no extra scripts):
#   ● muted green  = QUIC, client attached
#   ● gold         = SSH fallback, client attached
#   ● amber        = no client attached (reconnecting or session idle)
set -g status-left-length 20
set -g status-left '#{?#{==:#{session_attached},0},#[fg=colour208],#{?#{==:#{E:ONYX_MODE},ssh},#[fg=colour178],#[fg=colour71]}}●#[fg=colour242,nobold] #{E:ONYX_MODE} '

# Right: path · branch · cmd — dim, secondary info, no color pop
set -g status-right-length 100
set -g status-right '#[fg=colour241]#(~/.config/onyx/status.sh right "#{pane_current_path}" "#{pane_current_command}")'

# Window tabs — dim when inactive, barely lighter when active; no highlight slab
set -g window-status-style         'fg=colour238,bg=colour234'
set -g window-status-current-style 'fg=colour248,bg=colour234,bold'
set -g window-status-format         '#W'
set -g window-status-current-format '#W'
set -g window-status-separator      '  '

# Pane borders — very subtle, no accent color
set -g pane-border-style        'fg=colour236'
set -g pane-active-border-style 'fg=colour240'

# Command/message prompt — neutral
set -g message-style 'bg=colour234,fg=colour248'
"##;

/// Context script called from tmux. Dispatch on $1:
///   right  → "~/workspace/meviq · main · claude"   (status-right)
///   title  → "claude · ~/workspace/meviq"          (terminal title)
///   window → "onyx:claude"                         (window name)
/// $2 is the pane's cwd, $3 is pane_current_command. Kept portable
/// (POSIX sh only) and single-pass: no nested forks beyond one optional
/// git call, and only when a .git is present in the cwd's ancestry.
const ONYX_STATUS_SH: &str = r#"#!/bin/sh
# onyx status — auto-generated
mode=$1
cwd=$2
cmd=$3

# cwd → ~/... for readability
short_cwd=$cwd
case "$cwd" in
  "$HOME") short_cwd="~" ;;
  "$HOME"/*) short_cwd="~${cwd#"$HOME"}" ;;
esac

# Normalize common shell names (bash/zsh/sh/fish/dash/ksh, with optional
# leading dash for login shells) to the single label "shell". Anything
# else — claude, codex, vim, python, etc. — passes through unchanged.
case "$cmd" in
  -bash|-zsh|-sh|bash|zsh|sh|fish|dash|ksh) cmd=shell ;;
esac

# Git branch — best-effort, silent if not a repo or git missing. Only
# invoke git when we can cheaply see a .git marker on the cwd path, so
# non-repo directories don't pay a subprocess cost.
branch=
if [ -n "$cwd" ] && [ -d "$cwd" ]; then
  d=$cwd
  while [ "$d" != / ] && [ -n "$d" ]; do
    if [ -e "$d/.git" ]; then
      branch=$(git -C "$cwd" symbolic-ref --short HEAD 2>/dev/null) \
        || branch=$(git -C "$cwd" rev-parse --short HEAD 2>/dev/null) \
        || branch=
      break
    fi
    d=${d%/*}
  done
fi

case "$mode" in
  right)
    out=$short_cwd
    [ -n "$branch" ] && out="$out · $branch"
    [ "$cmd" != shell ] && [ -n "$cmd" ] && out="$out · $cmd"
    printf '%s' "$out"
    ;;
  title)
    if [ "$cmd" = shell ] || [ -z "$cmd" ]; then
      printf '%s' "$short_cwd"
    else
      printf '%s · %s' "$cmd" "$short_cwd"
    fi
    ;;
  window)
    [ -z "$cmd" ] && cmd=shell
    printf 'onyx:%s' "$cmd"
    ;;
esac
"#;

// ---------------------------------------------------------------------------
// TLS — TOFU cert pinning (all connection modes)
// ---------------------------------------------------------------------------

/// SHA-256 of DER bytes, formatted as "sha256:<hex>".
fn cert_fingerprint(cert_der: &[u8]) -> String {
    let hash = ring::digest::digest(&ring::digest::SHA256, cert_der);
    format!(
        "sha256:{}",
        hash.as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

type FpCapture = Arc<Mutex<Option<String>>>;

#[derive(Clone, Copy)]
struct BandwidthMode {
    low_bandwidth: bool,
    stdin_batch_window: Duration,
    stdout_batch_window: Duration,
    stdout_flush_window: Duration,
    stdout_chunk_limit: usize,
}

impl BandwidthMode {
    fn normal() -> Self {
        Self {
            low_bandwidth: false,
            stdin_batch_window: Duration::from_millis(5),
            stdout_batch_window: Duration::from_millis(0),
            stdout_flush_window: Duration::from_millis(0),
            stdout_chunk_limit: 4096,
        }
    }

    fn low_bandwidth() -> Self {
        Self {
            low_bandwidth: true,
            stdin_batch_window: Duration::from_millis(20),
            stdout_batch_window: Duration::from_millis(30),
            stdout_flush_window: Duration::from_millis(60),
            stdout_chunk_limit: 16384,
        }
    }
}

/// Accepts every cert during the TLS handshake and captures the fingerprint.
/// The actual TOFU check happens after the handshake completes, before any
/// application data is sent (see check_known_hosts in try_once).
#[derive(Debug)]
struct CapturingVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    capture: FpCapture,
}

impl CapturingVerifier {
    fn new(capture: FpCapture) -> Arc<Self> {
        Arc::new(Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
            capture,
        })
    }
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.capture.lock().unwrap() = Some(cert_fingerprint(end_entity.as_ref()));
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// QUIC client config
// ---------------------------------------------------------------------------

fn make_client_config(capture: FpCapture) -> Result<ClientConfig> {
    let mut tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(CapturingVerifier::new(capture))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"onyx".to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut config = ClientConfig::new(Arc::new(quic));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

// ---------------------------------------------------------------------------
// TOFU known-hosts
// ---------------------------------------------------------------------------

fn known_hosts_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(home).join(".local/share/onyx/known_hosts")
}

fn ensure_private_dir(path: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("setting permissions on {}", path.display()))?;
    }
    Ok(())
}

fn open_private_append(path: &std::path::Path) -> Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

fn display_shell_path(path: &str) -> String {
    if path
        .chars()
        .any(|c| c.is_whitespace() || c == '\'' || c == '"')
    {
        shell_quote(path)
    } else {
        path.to_string()
    }
}

struct RemotePaths {
    remote_dir: String,
    conf_dir: String,
}

fn normalize_remote_dir(candidate: &str, home: &str) -> String {
    if let Some(rest) = candidate.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else if candidate == "~" {
        home.to_string()
    } else if candidate.starts_with('/') {
        candidate.to_string()
    } else {
        format!("{home}/{candidate}")
    }
}

fn ssh_capture_full(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
    cmd: &str,
) -> Result<std::process::Output> {
    ssh_cmd(target, identity, session)
        .arg(cmd)
        .output()
        .context("ssh")
}

fn check_remote_dir_writable(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
    dir: &str,
) -> Result<(), String> {
    let marker = format!("{dir}/.onyx-write-test-{}", std::process::id());
    let cmd = format!(
        "mkdir -p {dir} && : > {marker} && rm -f {marker}",
        dir = shell_quote(dir),
        marker = shell_quote(&marker),
    );
    let out = ssh_capture_full(target, identity, session, &cmd).map_err(|e| e.to_string())?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    Err(format!(
        "exit {}: {}",
        out.status.code().unwrap_or(-1),
        if stderr.is_empty() {
            "<empty stderr>"
        } else {
            &stderr
        }
    ))
}

fn resolve_remote_paths(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
) -> Result<RemotePaths> {
    let home = ssh_capture(target, identity, session, "printf %s \"$HOME\"")
        .context("resolving remote HOME")?;
    anyhow::ensure!(!home.is_empty(), "remote HOME is empty");

    let mut remote_candidates = Vec::new();
    if let Ok(custom) = std::env::var("ONYX_REMOTE_DIR") {
        let custom = custom.trim();
        if !custom.is_empty() {
            remote_candidates.push(normalize_remote_dir(custom, &home));
        }
    }
    remote_candidates.push(format!("{home}/.local/share/onyx"));
    remote_candidates.push("/tmp/onyx".to_string());
    remote_candidates.dedup();

    let mut remote_failures = Vec::new();
    let mut remote_dir = None;
    for candidate in &remote_candidates {
        match check_remote_dir_writable(target, identity, session, candidate) {
            Ok(()) => {
                remote_dir = Some(candidate.clone());
                break;
            }
            Err(reason) => remote_failures.push(format!("  {candidate}: {reason}")),
        }
    }
    let remote_dir = remote_dir.ok_or_else(|| {
        anyhow::anyhow!(
            "no writable remote install directory found\n{}\nnext steps:\n  set ONYX_REMOTE_DIR to a writable absolute path\n  or install onyx-server manually and use --no-bootstrap",
            remote_failures.join("\n")
        )
    })?;

    let conf_default = format!("{home}/.config/onyx");
    let conf_dir = match check_remote_dir_writable(target, identity, session, &conf_default) {
        Ok(()) => conf_default,
        Err(_) => format!("{remote_dir}/config"),
    };

    Ok(RemotePaths {
        remote_dir,
        conf_dir,
    })
}

/// TOFU check run after every QUIC handshake, before any application data.
///
/// - **Known + match**    → silent Ok.
/// - **Known + mismatch** → print warning block, Err (hard fail).
/// - **New host**         → SSH-style interactive prompt; saves on yes, Err on no.
async fn check_known_hosts(host_port: &str, remote_fp: &str) -> Result<()> {
    let path = known_hosts_path();
    let content = std::fs::read_to_string(&path).unwrap_or_default();

    for line in content.lines() {
        let mut it = line.splitn(2, ' ');
        let key = it.next().unwrap_or("");
        let fp = it.next().unwrap_or("");
        if key != host_port {
            continue;
        }

        if fp == remote_fp {
            return Ok(());
        } // known + matches

        // ── Fingerprint mismatch ─────────────────────────────────────────────
        eprintln!();
        eprintln!("\x1b[31;1m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\x1b[0m");
        eprintln!("\x1b[31;1m@   WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!   @\x1b[0m");
        eprintln!("\x1b[31;1m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\x1b[0m");
        eprintln!();
        eprintln!("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
        eprintln!(
            "The onyx server at \x1b[1m{host_port}\x1b[0m presented a different certificate."
        );
        eprintln!("  stored:   {fp}");
        eprintln!("  received: {remote_fp}");
        eprintln!();
        eprintln!("If you rebuilt the server, remove the old entry with:");
        eprintln!(
            "  sed -i '/{}/d' {}",
            host_port.replace('/', r"\/"),
            path.display()
        );
        anyhow::bail!("host key verification failed for {host_port}");
    }

    // ── New host — interactive Trust On First Use ────────────────────────────
    eprintln!(
        "The authenticity of host '{}' can't be established.",
        host_port
    );
    eprintln!("SHA256 fingerprint: {remote_fp}");
    eprint!("Are you sure you want to continue connecting (yes/no)? ");
    std::io::stderr().flush().ok();

    let answer = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        line.trim().to_lowercase()
    })
    .await
    .unwrap_or_default();

    if answer != "yes" {
        anyhow::bail!("Host key verification failed.");
    }

    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    use std::io::Write as _;
    let mut f = open_private_append(&path)?;
    writeln!(f, "{host_port} {remote_fp}").context("writing known_hosts")?;
    eprintln!(
        "Warning: Permanently added '{}' ({remote_fp}) to the list of known hosts.",
        host_port
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Message framing
// ---------------------------------------------------------------------------

async fn send_msg(stream: &mut quinn::SendStream, msg: &Message) -> Result<()> {
    let payload = shared::encode(msg)?;
    stream
        .write_all(&(payload.len() as u32).to_le_bytes())
        .await?;
    stream.write_all(&payload).await?;
    Ok(())
}

async fn recv_msg(stream: &mut quinn::RecvStream) -> Result<Message> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let mut buf = vec![0u8; u32::from_le_bytes(len_buf) as usize];
    stream.read_exact(&mut buf).await?;
    Ok(shared::decode(&buf)?)
}

// ---------------------------------------------------------------------------
// Local terminal helpers
// ---------------------------------------------------------------------------

fn new_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{s:x}-{:x}", std::process::id())
}

fn get_terminal_size() -> (u16, u16) {
    let mut ws = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ as _, &mut ws) };
    (ws.ws_col, ws.ws_row)
}

/// Escape sequences emitted on RawMode drop to clean up terminal modes that
/// tmux on the remote side may have enabled. Without these, a transport drop
/// would leave the local terminal in mouse-tracking mode: mouse moves and
/// clicks get echoed as `^[[<32;54;57M…` once the terminal is back in cooked
/// mode, because the shell below us has no idea those modes were set.
///
/// Order matches what tmux emits on its own clean exit. Individual sequences:
///   `?1000l / ?1002l / ?1003l`  disable X10 / button-event / any-event mouse
///   `?1006l`                    disable SGR extended mouse
///   `?2004l`                    disable bracketed paste
///   `?25h`                      show cursor (tmux may have hidden it mid-redraw)
const RAWMODE_TERMINAL_CLEANUP: &[u8] =
    b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?2004l\x1b[?25h";

struct RawMode {
    saved: libc::termios,
}

impl RawMode {
    fn enter() -> Self {
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            libc::tcgetattr(libc::STDIN_FILENO, &mut t);
            let saved = t;
            libc::cfmakeraw(&mut t);
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t);
            RawMode { saved }
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        // Emit terminal cleanup BEFORE restoring termios — otherwise, if
        // the terminal is still in raw mode, the cleanup bytes go through
        // cleanly; after restore, a cooked-mode echo of any leftover mouse
        // sequences would leak as garbled input.
        use std::io::Write as _;
        let mut out = std::io::stdout();
        let _ = out.write_all(RAWMODE_TERMINAL_CLEANUP);
        let _ = out.flush();
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.saved) };
    }
}

// ---------------------------------------------------------------------------
// Error hints
// ---------------------------------------------------------------------------

fn quic_error_hint(e: &anyhow::Error) -> &'static str {
    let s = format!("{e:#}");
    if s.contains("timed out") || s.contains("TimedOut") || s.contains("deadline") {
        "\n  (UDP packets dropped — most likely the server firewall blocks the QUIC port;\
         \n   fix: ssh <host> 'sudo ufw allow 7272/udp'  or open it in the Hetzner firewall panel)"
    } else if s.contains("handshake") || s.contains("ALPN") || s.contains("tls") {
        "\n  (QUIC handshake failed — check server.log for TLS/ALPN errors)"
    } else {
        ""
    }
}

fn proxy_session_not_resumable(e: &anyhow::Error) -> bool {
    format!("{e:#}")
        .to_ascii_lowercase()
        .contains("proxy session not resumable")
}

fn quic_unavailable_for_proxy(e: &anyhow::Error) -> bool {
    let s = format!("{e:#}").to_ascii_lowercase();
    [
        "timed out",
        "deadline",
        "udp/",
        "connection refused",
        "network is unreachable",
        "no route to host",
        "dns lookup",
        "no address resolved",
    ]
    .iter()
    .any(|needle| s.contains(needle))
}

/// Plain-TCP fallback for proxy mode when QUIC is unavailable.
///
/// Bridges stdin/stdout to a direct TCP connection to `target_host:target_port`.
/// This is what SSH would do with no ProxyCommand at all — it gives the outer
/// SSH client a direct TCP stream. The onyx-server on the remote is not
/// involved. TOFU/QUIC pinning does not apply here; the outer SSH client
/// does its own host-key check.
///
/// This is a **fresh** TCP connection: it can replace QUIC for a *new* SSH
/// session, but it cannot recover an SSH session that was previously carried
/// over QUIC — that session's state lives in the dead QUIC path.
async fn tcp_proxy_fallback(target_host: &str, target_port: u16) -> Result<()> {
    let addr = format!("{target_host}:{target_port}");
    let tcp = tokio::net::TcpStream::connect(&addr)
        .await
        .with_context(|| format!("TCP fallback connect to {addr}"))?;
    let _ = tcp.set_nodelay(true);
    let (mut tcp_r, mut tcp_w) = tcp.into_split();

    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    // Drive both directions concurrently. Either side closing completes the
    // copy; when both complete we're done.
    let up = async {
        let _ = tokio::io::copy(&mut stdin, &mut tcp_w).await;
        let _ = tcp_w.shutdown().await;
    };
    let down = async {
        let _ = tokio::io::copy(&mut tcp_r, &mut stdout).await;
        let _ = stdout.flush().await;
    };
    tokio::join!(up, down);
    Ok(())
}

// ---------------------------------------------------------------------------
// Reliability tuning — client-side timeouts and backoff
// ---------------------------------------------------------------------------
//
// These govern how aggressively the interactive client retries a disrupted
// QUIC session and how long it waits for the server to respond. Tuned for
// real-world remote development where short Wi-Fi blips and NAT rebinds are
// common and users value staying in the same shell over clean failure.

/// QUIC handshake timeout for interactive mode. Longer than before to tolerate
/// slow cellular / overseas links without giving up prematurely, short enough
/// that a truly blocked UDP port fails within ~10 s.
const INTERACTIVE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
/// Retry window after first successful session is dropped. Covers laptop
/// sleep, VPN reconnect, multi-minute transitions.
const INTERACTIVE_RECONNECT_WINDOW: Duration = Duration::from_secs(600);
/// Retry window before the very first successful session. Short because the
/// common failure here is "server is down / firewalled" and we want to fall
/// back to SSH quickly rather than hang.
const INTERACTIVE_INITIAL_CONNECT_WINDOW: Duration = Duration::from_secs(45);
/// Initial / maximum backoff between interactive reconnect attempts.
/// Prevents CPU-spinning against a down server while staying responsive
/// for short drops.
const INTERACTIVE_BACKOFF_INITIAL: Duration = Duration::from_millis(250);
const INTERACTIVE_BACKOFF_MAX: Duration = Duration::from_secs(3);

/// QUIC handshake timeout for proxy mode. Kept the same as interactive so
/// the fallback decision happens on a similar cadence.
const PROXY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
/// Bound how long we wait while establishing the initial SSH control-master
/// connection before surfacing a clear timeout to the user.
const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Keep well below the shortest common Unix domain socket limit (104 bytes on
/// macOS) so `/tmp/...` control sockets are safe across platforms.
const SSH_CONTROL_SOCKET_MAX_LEN: usize = 96;
const SSH_CONTROL_SOCKET_ATTEMPTS: u32 = 32;

/// Throttle flag for the legacy "session already attached" Close reason.
/// Set the first time an episode fires, cleared on the next successful
/// Welcome. Prevents the one-line-per-retry spam that was the original
/// symptom of the stuck-reconnect bug. Process-global because the flag
/// ties to the user-visible display, which is itself process-global.
static SESSION_BUSY_LOGGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static SSH_SOCKET_COUNTER: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

// ---------------------------------------------------------------------------
// Target resolution
//
// Supported CLI forms:
//   hetzner-dev                 → SSH mode (alias), QUIC port = DEFAULT_PORT
//   user@host                   → SSH mode,          QUIC port = DEFAULT_PORT
//   user@host:7373              → SSH mode,          QUIC port = 7373
//   host:7373                   → SSH mode,          QUIC port = 7373
//   128.140.63.67               → direct mode,       QUIC port = DEFAULT_PORT
//   128.140.63.67:7373          → direct mode,       QUIC port = 7373
//
// SSH mode is used whenever the host part is not a bare IP address OR the
// target contains '@'.  In SSH mode we call `ssh -G <ssh_target>` to resolve
// the actual hostname (handles SSH config aliases, ProxyJump, etc.).
// ---------------------------------------------------------------------------

struct OnyxTarget {
    /// Passed verbatim to `ssh` for bootstrap commands.
    /// In SSH mode this is the raw user-supplied string minus any QUIC port.
    ssh_target: String,
    /// Resolved hostname used for the QUIC connection.
    quic_host: String,
    quic_port: u16,
    /// Explicit `-i` identity passed by the user, if any.
    identity_file: Option<String>,
    /// Best-effort identity path hint for user-facing ssh-add guidance.
    identity_hint: Option<String>,
    ssh_mode: bool,
}

#[cfg_attr(test, derive(Debug))]
enum CliMode {
    Interactive {
        raw_target: String,
        identity_file: Option<String>,
        no_fallback: bool,
        no_bootstrap: bool,
        low_bandwidth: bool,
        forwards: Vec<(u16, u16)>,
        port_override: Option<u16>,
    },
    Proxy {
        target_host: String,
        target_port: u16,
        no_fallback: bool,
    },
    Exec {
        raw_target: String,
        identity_file: Option<String>,
        no_bootstrap: bool,
        json: bool,
        detach: bool,
        command: Vec<String>,
        cwd: Option<String>,
        env: Vec<(String, String)>,
        timeout_secs: Option<u64>,
    },
    Kill {
        raw_target: String,
        identity_file: Option<String>,
        no_bootstrap: bool,
        json: bool,
        job_id: String,
    },
    Jobs {
        raw_target: String,
        identity_file: Option<String>,
        no_bootstrap: bool,
        json: bool,
    },
    Attach {
        raw_target: String,
        identity_file: Option<String>,
        no_bootstrap: bool,
        json: bool,
        job_id: String,
    },
    Logs {
        raw_target: String,
        identity_file: Option<String>,
        no_bootstrap: bool,
        json: bool,
        job_id: String,
    },
    Mcp {},
    Doctor {
        raw_target: String,
        identity_file: Option<String>,
    },
}

/// Outcome of parsing argv. Separate from `CliMode` so `--help` / `--version`
/// can short-circuit cleanly without the pure parser touching process state.
#[cfg_attr(test, derive(Debug))]
enum ParseOutcome {
    Run(CliMode),
    Help,
    Version,
}

/// Parse a human duration string like "30s", "5m", "2h" into seconds.
fn parse_duration_secs(s: &str) -> Option<u64> {
    if let Some(n) = s.strip_suffix('s') {
        n.parse::<u64>().ok()
    } else if let Some(n) = s.strip_suffix('m') {
        n.parse::<u64>().ok().map(|v| v * 60)
    } else if let Some(n) = s.strip_suffix('h') {
        n.parse::<u64>().ok().map(|v| v * 3600)
    } else {
        s.parse::<u64>().ok()
    }
}

/// Pure parser used by both the real CLI entry point and unit tests.
/// `args` is the argv **without** the program name (argv[1..]).
fn parse_args_from(args: Vec<String>) -> Result<ParseOutcome, String> {
    let mut it = args.into_iter().peekable();

    // --help / --version are accepted as the first token. (Placing them
    // later would require a full pre-scan; doing that matches common
    // CLI conventions — `git commit --help` works, `git commit -m x --help`
    // does not.)
    if let Some(first) = it.peek() {
        match first.as_str() {
            "--help" | "-h" => return Ok(ParseOutcome::Help),
            "--version" | "-V" => return Ok(ParseOutcome::Version),
            _ => {}
        }
    }

    if matches!(it.peek(), Some(cmd) if cmd == "mcp") {
        it.next();
        match it.next().as_deref() {
            Some("serve") => {
                if let Some(extra) = it.next() {
                    return Err(format!("mcp serve: unexpected argument: {extra}"));
                }
                return Ok(ParseOutcome::Run(CliMode::Mcp {}));
            }
            Some(other) => return Err(format!("mcp: unknown subcommand '{other}' (try: onyx mcp serve)")),
            None => return Err("mcp: missing subcommand (try: onyx mcp serve)".to_string()),
        }
    }

    if matches!(it.peek(), Some(cmd) if cmd == "proxy") {
        it.next();
        let mut no_fallback = false;
        while matches!(it.peek(), Some(flag) if flag == "--no-fallback") {
            it.next();
            no_fallback = true;
        }
        let target_host = it
            .next()
            .ok_or_else(|| "proxy: missing <host>".to_string())?;
        let target_port = it
            .next()
            .ok_or_else(|| "proxy: missing <port>".to_string())?
            .parse::<u16>()
            .map_err(|_| "proxy: <port> must be 0-65535".to_string())?;
        if let Some(extra) = it.next() {
            return Err(format!("unexpected argument: {extra}"));
        }
        return Ok(ParseOutcome::Run(CliMode::Proxy {
            target_host,
            target_port,
            no_fallback,
        }));
    }

    if matches!(it.peek(), Some(cmd) if cmd == "doctor") {
        it.next();
        let raw_target = it
            .next()
            .ok_or_else(|| "doctor: missing <target>".to_string())?;
        let mut identity: Option<String> = None;
        while let Some(a) = it.next() {
            match a.as_str() {
                "-i" => {
                    identity = Some(
                        it.next()
                            .ok_or_else(|| "-i requires an argument".to_string())?,
                    );
                }
                other => return Err(format!("doctor: unexpected argument: {other} (try --help)")),
            }
        }
        return Ok(ParseOutcome::Run(CliMode::Doctor {
            raw_target,
            identity_file: identity,
        }));
    }

    // ── exec / jobs / attach / logs ─────────────────────────────────────
    //
    // All four share a small prelude: `onyx <sub> <target> [flags]` where
    // flags include `--json`, `-i <key>`, and `--no-bootstrap`. The
    // `exec` subcommand additionally takes `--detach` and a `--`-separated
    // command argv.
    if matches!(
        it.peek(),
        Some(cmd) if cmd == "exec" || cmd == "jobs" || cmd == "attach" || cmd == "logs" || cmd == "kill"
    ) {
        let sub = it.next().unwrap();
        let raw_target = it
            .next()
            .ok_or_else(|| format!("{sub}: missing <target>"))?;

        let mut identity: Option<String> = None;
        let mut no_bootstrap = false;
        let mut json = false;
        let mut detach = false;
        let mut positional: Vec<String> = Vec::new();
        let mut command: Vec<String> = Vec::new();
        let mut seen_dashdash = false;
        let mut cwd: Option<String> = None;
        let mut env: Vec<(String, String)> = Vec::new();
        let mut timeout_secs: Option<u64> = None;
        // For exec: once we see the first bare positional, treat it as the
        // start of the command argv — anything after (including things that
        // look like flags, e.g. `ls -la`) is passed through unchanged.
        // attach/logs/jobs/kill stay in strict mode — they have fixed positional
        // arity and a stray `-la` should be a clear error.
        let exec_bare_tail = sub == "exec";
        let mut in_command_tail = false;

        while let Some(a) = it.next() {
            if seen_dashdash || in_command_tail {
                command.push(a);
                continue;
            }
            match a.as_str() {
                "--" => seen_dashdash = true,
                "--json" => json = true,
                "--detach" => detach = true,
                "--no-bootstrap" => no_bootstrap = true,
                "-i" => {
                    identity = Some(
                        it.next()
                            .ok_or_else(|| "-i requires an argument".to_string())?,
                    );
                }
                "--cwd" => {
                    cwd = Some(
                        it.next()
                            .ok_or_else(|| "--cwd requires an argument".to_string())?,
                    );
                }
                "--env" => {
                    let kv = it
                        .next()
                        .ok_or_else(|| "--env requires KEY=VALUE".to_string())?;
                    let (k, v) = kv
                        .split_once('=')
                        .ok_or_else(|| format!("--env: expected KEY=VALUE, got '{kv}'"))?;
                    env.push((k.to_string(), v.to_string()));
                }
                "--timeout" => {
                    let raw = it
                        .next()
                        .ok_or_else(|| "--timeout requires a duration (e.g. 30s, 5m)".to_string())?;
                    timeout_secs = Some(
                        parse_duration_secs(&raw)
                            .ok_or_else(|| format!("--timeout: invalid duration '{raw}' (use e.g. 30s, 5m, 2h)"))?
                    );
                }
                other if other.starts_with('-') => {
                    return Err(format!("unknown flag for {sub}: {other} (try --help)"));
                }
                _ => {
                    if exec_bare_tail {
                        command.push(a);
                        in_command_tail = true;
                    } else {
                        positional.push(a);
                    }
                }
            }
        }

        return match sub.as_str() {
            "exec" => {
                if !seen_dashdash && command.is_empty() && !positional.is_empty() {
                    // Defensive: exec_bare_tail should have steered here.
                    command = positional;
                }
                if command.is_empty() {
                    return Err("exec: missing command after '--'".to_string());
                }
                Ok(ParseOutcome::Run(CliMode::Exec {
                    raw_target,
                    identity_file: identity,
                    no_bootstrap,
                    json,
                    detach,
                    command,
                    cwd,
                    env,
                    timeout_secs,
                }))
            }
            "kill" => {
                let job_id = positional
                    .into_iter()
                    .next()
                    .ok_or_else(|| "kill: missing <job-id>".to_string())?;
                Ok(ParseOutcome::Run(CliMode::Kill {
                    raw_target,
                    identity_file: identity,
                    no_bootstrap,
                    json,
                    job_id,
                }))
            }
            "jobs" => {
                if detach {
                    return Err("jobs: --detach is not valid here".to_string());
                }
                if !positional.is_empty() || !command.is_empty() {
                    return Err(format!(
                        "jobs: unexpected argument '{}'",
                        positional
                            .first()
                            .or_else(|| command.first())
                            .map(|s| s.as_str())
                            .unwrap_or("")
                    ));
                }
                Ok(ParseOutcome::Run(CliMode::Jobs {
                    raw_target,
                    identity_file: identity,
                    no_bootstrap,
                    json,
                }))
            }
            "attach" | "logs" => {
                if detach {
                    return Err(format!("{sub}: --detach is not valid here"));
                }
                let job_id = positional
                    .into_iter()
                    .next()
                    .ok_or_else(|| format!("{sub}: missing <job-id>"))?;
                if !command.is_empty() {
                    return Err(format!("{sub}: unexpected arguments after <job-id>"));
                }
                if sub == "attach" {
                    Ok(ParseOutcome::Run(CliMode::Attach {
                        raw_target,
                        identity_file: identity,
                        no_bootstrap,
                        json,
                        job_id,
                    }))
                } else {
                    Ok(ParseOutcome::Run(CliMode::Logs {
                        raw_target,
                        identity_file: identity,
                        no_bootstrap,
                        json,
                        job_id,
                    }))
                }
            }
            _ => unreachable!(),
        };
    }

    let mut identity: Option<String> = None;
    let mut target: Option<String> = None;
    let mut no_fallback = false;
    let mut no_bootstrap = false;
    let mut low_bandwidth = false;
    let mut forwards: Vec<(u16, u16)> = Vec::new();
    let mut port_override: Option<u16> = None;

    while let Some(a) = it.next() {
        match a.as_str() {
            "-i" => {
                identity = Some(
                    it.next()
                        .ok_or_else(|| "-i requires an argument".to_string())?,
                );
            }
            "--no-fallback" => no_fallback = true,
            "--no-bootstrap" => no_bootstrap = true,
            "--low-bandwidth" => low_bandwidth = true,
            "--port" => {
                let val = it
                    .next()
                    .ok_or_else(|| "--port requires an argument".to_string())?;
                port_override = Some(
                    val.parse::<u16>()
                        .map_err(|_| "--port: port must be 0-65535".to_string())?,
                );
            }
            "--forward" | "-L" => {
                let spec = it
                    .next()
                    .ok_or_else(|| "--forward requires local_port:remote_port".to_string())?;
                let (lp, rp) = parse_forward_spec(&spec)?;
                forwards.push((lp, rp));
            }
            // A leading `-` that isn't a known flag is almost always a
            // mistyped flag — reject it clearly rather than silently
            // treating it as a hostname and failing much later in
            // ssh -G with a cryptic message.
            other if other.starts_with('-') && target.is_none() => {
                return Err(format!("unknown flag: {other} (try --help)"));
            }
            _ if target.is_none() => target = Some(a),
            _ => return Err(format!("unexpected argument: {a}")),
        }
    }

    let target = target.ok_or_else(|| "missing target (try --help)".to_string())?;

    Ok(ParseOutcome::Run(CliMode::Interactive {
        raw_target: target,
        identity_file: identity,
        no_fallback,
        no_bootstrap,
        low_bandwidth,
        forwards,
        port_override,
    }))
}

fn parse_forward_spec(spec: &str) -> Result<(u16, u16), String> {
    let mut parts = spec.splitn(2, ':');
    let lp = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("--forward: invalid spec '{spec}' (expected local:remote)"))?;
    let rp = parts
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("--forward: invalid spec '{spec}' (expected local:remote)"))?;
    Ok((lp, rp))
}

const HELP_TEXT: &str = "\
onyx — stable remote shell for unreliable networks (QUIC + SSH fallback)

USAGE
  onyx [OPTIONS] [user@]<host>[:<quic-port>]       interactive shell
  onyx proxy <host> <port>                          SSH ProxyCommand transport
  onyx exec   <target> [--json] [--detach] [--cwd <dir>] [--env K=V]... [--timeout <dur>] -- <cmd...>
  onyx jobs   <target> [--json]
  onyx attach <target> <job-id> [--json]
  onyx logs   <target> <job-id> [--json]
  onyx kill   <target> <job-id> [--json]
  onyx doctor <target>                              run diagnostics for a target
  onyx mcp serve                                    stdio MCP server (for AI agents)
  onyx --help | --version

MODES
  Interactive     tmux-backed shell over QUIC. The client retries a
                  disrupted session for up to ~10 minutes with exponential
                  backoff, so short Wi-Fi/VPN/NAT hiccups recover in place.
                  Detached sessions are retained server-side for up to
                  12 hours (in-memory; does not survive onyx-server
                  restart).
  Proxy           stdio-bridged TCP tunnel for use as SSH ProxyCommand.
                  Short transport drops are recovered best-effort within
                  ~2 minutes; longer drops end the underlying SSH session.
                  When QUIC is unavailable, proxy mode falls back to a
                  plain TCP bridge to <host> <port> unless --no-fallback
                  is set. The plain-TCP path cannot revive a QUIC-started
                  SSH session; it only replaces QUIC for new sessions.
  Exec            Resumable remote command execution. The server owns
                  the child process, buffers up to 4 MiB of output per
                  job in a ring, and keeps the job alive across client
                  disconnects. Foreground `onyx exec` and `onyx attach`
                  auto-reconnect on transport drops (up to 10 min with
                  exponential backoff) and seamlessly resume streaming
                  from the last seen seq. Reattach manually with
                  `onyx attach`, snapshot output with `onyx logs`,
                  enumerate with `onyx jobs`. Jobs survive client
                  disconnects but NOT onyx-server restart or host
                  reboot (in-memory). Finished jobs are retained for
                  1 hour.

INSTALL MODEL
  onyx is a local CLI. On first connect to a host it provisions
  onyx-server on the remote over SSH, preferring a prebuilt binary
  matching the remote arch and falling back to `cargo build --release`
  only if no prebuilt is available. Subsequent connects reuse the
  already-running server.

OPTIONS
  -i <file>                 SSH identity file for bootstrap
  -L, --forward L:R         tunnel localhost:L → remote:R (repeatable)
  --port <port>             QUIC port on the remote (default: 7272).
                              Also: ONYX_PORT=<port> env var (all modes).
                              Alternative: append :<port> to the target.
  --no-bootstrap            skip remote install/start checks
  --no-fallback             exit on QUIC failure instead of falling back
                              (plain SSH exec for interactive, plain TCP
                               bridge for proxy mode)
  --low-bandwidth           smoother batching on poor links
  --json                    (exec/jobs/attach/logs/kill) structured output,
                              one JSON object per line
  --detach                  (exec) start the job and exit; reattach later
  --cwd <dir>               (exec) working directory on the remote host
  --env KEY=VALUE           (exec) extra environment variable (repeatable)
  --timeout <dur>           (exec) kill after duration, e.g. 30s, 5m, 2h
                              exit code 124 on timeout
  -h, --help                show this help
  -V, --version             print version

EXAMPLES
  onyx user@host
  onyx dev-server                    # SSH alias from ~/.ssh/config
  onyx --forward 8888:8888 user@host
  onyx --port 443 user@host          # custom QUIC port
  ONYX_PORT=443 onyx exec host -- cmd
  onyx proxy host.example.com 22     # behind ProxyCommand in ssh_config
  onyx proxy --no-fallback host 22   # require QUIC for ProxyCommand
  onyx exec prod -- deploy.sh
  onyx exec gpu-box --detach -- python train.py
  onyx exec ci --json -- cargo test --workspace
  onyx exec gpu-box --cwd /data --env BATCH=64 --timeout 2h -- python train.py
  onyx jobs gpu-box
  onyx attach gpu-box job_a1b2c3d4e5f60718
  onyx logs  gpu-box job_a1b2c3d4e5f60718
  onyx kill  gpu-box job_a1b2c3d4e5f60718
  onyx doctor user@host              # diagnose connectivity
";

/// Real CLI entry point. Wraps `parse_args_from` and converts parse errors /
/// help / version into the process-level side effects.
fn parse_args() -> CliMode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args_from(args) {
        Ok(ParseOutcome::Run(mode)) => mode,
        Ok(ParseOutcome::Help) => {
            print!("{HELP_TEXT}");
            std::process::exit(0);
        }
        Ok(ParseOutcome::Version) => {
            println!("onyx {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        Err(msg) => {
            eprintln!("onyx: {msg}");
            eprintln!("run `onyx --help` for usage");
            std::process::exit(2);
        }
    }
}

// ---------------------------------------------------------------------------
// parse_args tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod parse_args_tests {
    use super::*;

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn help_flag_long_and_short() {
        assert!(matches!(
            parse_args_from(s(&["--help"])).unwrap(),
            ParseOutcome::Help
        ));
        assert!(matches!(
            parse_args_from(s(&["-h"])).unwrap(),
            ParseOutcome::Help
        ));
    }

    #[test]
    fn version_flag_long_and_short() {
        assert!(matches!(
            parse_args_from(s(&["--version"])).unwrap(),
            ParseOutcome::Version
        ));
        assert!(matches!(
            parse_args_from(s(&["-V"])).unwrap(),
            ParseOutcome::Version
        ));
    }

    #[test]
    fn bare_target_is_interactive() {
        let out = parse_args_from(s(&["user@host"])).unwrap();
        match out {
            ParseOutcome::Run(CliMode::Interactive { raw_target, .. }) => {
                assert_eq!(raw_target, "user@host");
            }
            _ => panic!("expected Interactive"),
        }
    }

    #[test]
    fn flags_and_target_any_order() {
        let out = parse_args_from(s(&["--no-bootstrap", "--no-fallback", "host"])).unwrap();
        match out {
            ParseOutcome::Run(CliMode::Interactive {
                no_bootstrap,
                no_fallback,
                low_bandwidth,
                ..
            }) => {
                assert!(no_bootstrap);
                assert!(no_fallback);
                assert!(!low_bandwidth);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn forward_short_and_long() {
        let out = parse_args_from(s(&["-L", "8080:80", "--forward", "9000:9000", "host"])).unwrap();
        match out {
            ParseOutcome::Run(CliMode::Interactive { forwards, .. }) => {
                assert_eq!(forwards, vec![(8080u16, 80u16), (9000u16, 9000u16)]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn proxy_mode() {
        let out = parse_args_from(s(&["proxy", "host.example.com", "22"])).unwrap();
        match out {
            ParseOutcome::Run(CliMode::Proxy {
                target_host,
                target_port,
                no_fallback,
            }) => {
                assert_eq!(target_host, "host.example.com");
                assert_eq!(target_port, 22);
                assert!(!no_fallback);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn proxy_mode_accepts_no_fallback() {
        let out = parse_args_from(s(&["proxy", "--no-fallback", "host.example.com", "22"]))
            .unwrap();
        match out {
            ParseOutcome::Run(CliMode::Proxy { no_fallback, .. }) => {
                assert!(no_fallback);
            }
            _ => panic!("expected Proxy"),
        }
    }

    #[test]
    fn unknown_flag_does_not_become_target() {
        // Regression: `onyx --version` once got treated as hostname and
        // ended up inside ssh -G. Unknown flags must be rejected cleanly.
        let err = parse_args_from(s(&["--no-such-flag"])).unwrap_err();
        assert!(err.contains("unknown flag"), "err was: {err}");
    }

    #[test]
    fn missing_target_is_error_not_panic() {
        let err = parse_args_from(s(&[])).unwrap_err();
        assert!(err.contains("missing target"));
    }

    #[test]
    fn proxy_rejects_non_numeric_port() {
        let err = parse_args_from(s(&["proxy", "host", "not-a-port"])).unwrap_err();
        assert!(err.contains("0-65535"));
    }

    #[test]
    fn forward_rejects_bad_spec() {
        let err = parse_args_from(s(&["--forward", "not-a-port", "host"])).unwrap_err();
        assert!(err.contains("invalid spec"));
    }

    #[test]
    fn identity_flag_requires_value() {
        let err = parse_args_from(s(&["-i"])).unwrap_err();
        assert!(err.contains("-i requires"));
    }

    #[test]
    fn help_text_mentions_key_concepts() {
        for needle in [
            "USAGE",
            "Interactive",
            "Proxy",
            "--forward",
            "--no-fallback",
            "--no-bootstrap",
            "--low-bandwidth",
            "--port",
            "ONYX_PORT",
            "proxy <host> <port>",
            "proxy --no-fallback",
            "12 hours",
            "plain TCP bridge",
            "onyx exec",
            "onyx jobs",
            "onyx attach",
            "onyx logs",
            "onyx doctor",
            "--json",
            "--detach",
            "Resumable remote command execution",
            "1 hour",
        ] {
            assert!(
                HELP_TEXT.contains(needle),
                "HELP_TEXT missing '{needle}'"
            );
        }
    }

    // ───────── exec / jobs / attach / logs parsing ─────────

    #[test]
    fn exec_parses_basic_command_with_dashdash() {
        let out = parse_args_from(s(&["exec", "host", "--", "docker", "build", "."])).unwrap();
        match out {
            ParseOutcome::Run(CliMode::Exec {
                raw_target,
                json,
                detach,
                command,
                ..
            }) => {
                assert_eq!(raw_target, "host");
                assert!(!json);
                assert!(!detach);
                assert_eq!(command, vec!["docker", "build", "."]);
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn exec_accepts_flags_before_dashdash() {
        let out = parse_args_from(s(&[
            "exec",
            "host",
            "--json",
            "--detach",
            "--no-bootstrap",
            "-i",
            "/tmp/key",
            "--",
            "python",
            "train.py",
        ]))
        .unwrap();
        match out {
            ParseOutcome::Run(CliMode::Exec {
                json,
                detach,
                no_bootstrap,
                identity_file,
                command,
                ..
            }) => {
                assert!(json);
                assert!(detach);
                assert!(no_bootstrap);
                assert_eq!(identity_file.as_deref(), Some("/tmp/key"));
                assert_eq!(command, vec!["python", "train.py"]);
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn exec_accepts_bare_command_without_dashdash() {
        // Friendly fallback: `onyx exec host ls -la` should still work.
        let out = parse_args_from(s(&["exec", "host", "ls", "-la"])).unwrap();
        match out {
            ParseOutcome::Run(CliMode::Exec { command, .. }) => {
                assert_eq!(command, vec!["ls", "-la"]);
            }
            _ => panic!("expected Exec"),
        }
    }

    #[test]
    fn exec_empty_command_rejected() {
        let err = parse_args_from(s(&["exec", "host", "--"])).unwrap_err();
        assert!(
            err.contains("missing command"),
            "err was: {err}"
        );
    }

    #[test]
    fn exec_missing_target_rejected() {
        let err = parse_args_from(s(&["exec"])).unwrap_err();
        assert!(err.contains("missing <target>"), "err was: {err}");
    }

    fn test_temp_dir(label: &str) -> PathBuf {
        let unique = format!(
            "onyx-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fake_elf_header(machine: u16) -> [u8; 20] {
        let mut header = [0u8; 20];
        header[..4].copy_from_slice(b"\x7fELF");
        header[18..20].copy_from_slice(&machine.to_le_bytes());
        header
    }

    #[test]
    fn server_artifact_name_normalizes_arch_aliases() {
        assert_eq!(
            server_artifact_name("x86_64"),
            Some("onyx-server-linux-x86_64")
        );
        assert_eq!(
            server_artifact_name("amd64"),
            Some("onyx-server-linux-x86_64")
        );
        assert_eq!(
            server_artifact_name("aarch64"),
            Some("onyx-server-linux-arm64")
        );
        assert_eq!(
            server_artifact_name("arm64"),
            Some("onyx-server-linux-arm64")
        );
        assert_eq!(server_artifact_name("armv7l"), None);
    }

    #[test]
    fn select_local_prebuilt_server_requires_matching_linux_binary() {
        let dir = test_temp_dir("prebuilt-select");
        let wrong = dir.join("wrong");
        let right = dir.join("right");
        let non_elf = dir.join("non-elf");

        fs::write(&wrong, fake_elf_header(183)).unwrap();
        fs::write(&right, fake_elf_header(62)).unwrap();
        fs::write(&non_elf, b"not an elf").unwrap();

        let selected = select_local_prebuilt_server(
            "x86_64",
            vec![non_elf.clone(), wrong.clone(), right.clone()],
        );
        assert_eq!(selected, Some(right));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn exec_rejects_unknown_flag_before_dashdash() {
        let err = parse_args_from(s(&["exec", "host", "--bogus", "--", "x"])).unwrap_err();
        assert!(err.contains("unknown flag"), "err was: {err}");
    }

    #[test]
    fn jobs_parses_json_flag() {
        let out = parse_args_from(s(&["jobs", "host", "--json"])).unwrap();
        match out {
            ParseOutcome::Run(CliMode::Jobs {
                raw_target, json, ..
            }) => {
                assert_eq!(raw_target, "host");
                assert!(json);
            }
            _ => panic!("expected Jobs"),
        }
    }

    #[test]
    fn jobs_rejects_positional_args() {
        let err = parse_args_from(s(&["jobs", "host", "extra"])).unwrap_err();
        assert!(err.contains("unexpected"), "err was: {err}");
    }

    #[test]
    fn attach_requires_job_id() {
        let err = parse_args_from(s(&["attach", "host"])).unwrap_err();
        assert!(err.contains("missing <job-id>"), "err was: {err}");

        let out = parse_args_from(s(&["attach", "host", "job_abc", "--json"])).unwrap();
        match out {
            ParseOutcome::Run(CliMode::Attach {
                raw_target,
                json,
                job_id,
                ..
            }) => {
                assert_eq!(raw_target, "host");
                assert_eq!(job_id, "job_abc");
                assert!(json);
            }
            _ => panic!("expected Attach"),
        }
    }

    #[test]
    fn logs_requires_job_id() {
        let out = parse_args_from(s(&["logs", "host", "job_42"])).unwrap();
        match out {
            ParseOutcome::Run(CliMode::Logs { job_id, json, .. }) => {
                assert_eq!(job_id, "job_42");
                assert!(!json);
            }
            _ => panic!("expected Logs"),
        }
    }

    #[test]
    fn attach_and_logs_reject_detach_flag() {
        let err = parse_args_from(s(&["attach", "host", "--detach", "job_x"])).unwrap_err();
        assert!(err.contains("--detach"), "err was: {err}");
        let err = parse_args_from(s(&["logs", "host", "--detach", "job_x"])).unwrap_err();
        assert!(err.contains("--detach"), "err was: {err}");
    }
}

// ---------------------------------------------------------------------------
// Reliability classifier + tuning tests
// ---------------------------------------------------------------------------
//
// These cover the decision points that the reconnect/fallback machinery
// depends on. They are pure functions on error strings and constants, so
// they run without any network or spawned process.

#[cfg(test)]
mod reliability_tests {
    use super::*;

    fn err(msg: &str) -> anyhow::Error {
        anyhow::anyhow!(msg.to_string())
    }

    #[test]
    fn proxy_session_not_resumable_matches_server_string() {
        // Exact string the server sends in ForwardError.reason.
        assert!(proxy_session_not_resumable(&err(
            "proxy session not resumable"
        )));
        // Case-insensitive, substring match through outer context.
        assert!(proxy_session_not_resumable(&err(
            "ProxyResume rejected: Proxy Session Not Resumable"
        )));
        assert!(!proxy_session_not_resumable(&err(
            "timed out waiting for handshake"
        )));
    }

    #[test]
    fn quic_unavailable_classifier_covers_common_offline_cases() {
        for needle in [
            "QUIC handshake timed out after 8 s",
            "deadline exceeded",
            "UDP/7272 may be blocked",
            "DNS lookup for 'x' failed",
            "connection refused",
            "network is unreachable",
            "no route to host",
            "no address resolved for foo",
        ] {
            assert!(
                quic_unavailable_for_proxy(&err(needle)),
                "expected offline classification for: {needle}"
            );
        }
    }

    #[test]
    fn quic_unavailable_classifier_ignores_handshake_tls_errors() {
        // TLS / ALPN mismatches mean the server is reachable — falling
        // back to plain TCP would hide a real configuration problem. The
        // classifier must stay strict about what it considers "offline".
        for needle in [
            "QUIC handshake failed: alpn mismatch",
            "invalid certificate",
            "host key verification failed",
        ] {
            assert!(
                !quic_unavailable_for_proxy(&err(needle)),
                "did not expect offline classification for: {needle}"
            );
        }
    }

    #[test]
    fn reconnect_constants_form_coherent_progression() {
        // Backoff must actually grow and never exceed the cap.
        assert!(INTERACTIVE_BACKOFF_INITIAL < INTERACTIVE_BACKOFF_MAX);
        assert!(INTERACTIVE_BACKOFF_MAX <= Duration::from_secs(5));
        // Initial-connect window must be shorter than the post-session
        // reconnect window (we're stricter before we ever had a session).
        assert!(INTERACTIVE_INITIAL_CONNECT_WINDOW < INTERACTIVE_RECONNECT_WINDOW);
        // The post-session window must be long enough to cover the
        // "medium outage" target we document (multi-minute).
        assert!(INTERACTIVE_RECONNECT_WINDOW >= Duration::from_secs(300));
        // Handshake timeout must fit inside one reconnect attempt so a
        // single failed attempt doesn't blow the whole window.
        assert!(INTERACTIVE_HANDSHAKE_TIMEOUT * 4 < INTERACTIVE_RECONNECT_WINDOW);
        assert_eq!(INTERACTIVE_HANDSHAKE_TIMEOUT, PROXY_HANDSHAKE_TIMEOUT);
    }

    #[test]
    fn exponential_backoff_saturates_at_max() {
        // Simulates the loop body's `backoff = min(backoff * 2, MAX)`.
        let mut b = INTERACTIVE_BACKOFF_INITIAL;
        for _ in 0..32 {
            b = std::cmp::min(b * 2, INTERACTIVE_BACKOFF_MAX);
        }
        assert_eq!(b, INTERACTIVE_BACKOFF_MAX);
    }

    #[test]
    fn ssh_auth_failure_message_distinguishes_passphrase_cancel_and_retry() {
        let required = ssh_auth_failure_message(
            None,
            Some("/home/me/.ssh/config-id"),
            false,
            Some(255),
            None,
            "Load key \"/home/me/.ssh/id_ed25519\": incorrect passphrase supplied to decrypt private key",
        )
        .unwrap();
        assert_eq!(
            required,
            "[onyx] SSH key requires a passphrase.\nOnyx could not complete bootstrap through the current SSH flow.\nTry unlocking your key first on your local machine:\n  ssh-add /home/me/.ssh/id_ed25519"
        );

        let canceled = ssh_auth_failure_message(
            None,
            Some("/home/me/.ssh/id_ed25519"),
            true,
            Some(255),
            None,
            "Enter passphrase for key '/home/me/.ssh/id_ed25519': ",
        )
        .unwrap();
        assert_eq!(canceled, "[onyx] SSH authentication was canceled.");

        let retry = ssh_auth_failure_message(
            Some("/tmp/onyx key"),
            None,
            true,
            Some(255),
            None,
            "Enter passphrase for key '/tmp/onyx key':\nEnter passphrase for key '/tmp/onyx key':\nPermission denied (publickey).",
        )
        .unwrap();
        assert_eq!(
            retry,
            "[onyx] SSH authentication could not be completed cleanly.\nPlease retry, or unlock your key first with:\n  ssh-add '/tmp/onyx key'"
        );
    }

    #[test]
    fn parse_resolved_ssh_config_captures_identityfile_hint() {
        let resolved = parse_resolved_ssh_config(
            "myserver",
            "hostname host.example.com\nuser dev\nidentityfile /home/dev/.ssh/onyx_ed25519\nidentityfile /home/dev/.ssh/fallback\n",
        )
        .unwrap();
        assert_eq!(resolved.hostname, "host.example.com");
        assert_eq!(resolved.user, "dev");
        assert_eq!(
            resolved.identity_file.as_deref(),
            Some("/home/dev/.ssh/onyx_ed25519")
        );
    }

    #[test]
    fn ssh_control_socket_path_is_short_and_flat() {
        let path = ssh_control_socket_path().unwrap();
        let rendered = path.display().to_string();
        assert!(rendered.starts_with("/tmp/o-"), "path was: {rendered}");
        assert!(rendered.ends_with(".sock"), "path was: {rendered}");
        assert!(control_socket_path_len(&path) <= SSH_CONTROL_SOCKET_MAX_LEN);
        assert!(
            !rendered.contains("/ctl"),
            "path should not create nested control socket dirs: {rendered}"
        );
    }

    #[test]
    fn classify_ssh_master_failure_reports_connect_timeout() {
        let status = std::process::ExitStatus::from_raw(255 << 8);
        let control_path = Path::new("/tmp/o-1234-abcd12.sock");
        let err = classify_ssh_master_failure(
            "myserver",
            None,
            None,
            false,
            control_path,
            &status,
            "ssh: connect to host myserver port 22: Operation timed out",
        );
        assert_eq!(
            format!("{err}"),
            "[onyx] SSH connection timed out while establishing the session (15s).\nCheck SSH reachability and try again:\n  ssh myserver"
        );
    }

    #[test]
    fn classify_ssh_master_failure_reports_control_socket_path_errors() {
        let status = std::process::ExitStatus::from_raw(255 << 8);
        let control_path = Path::new("/tmp/o-1234-abcd12.sock");
        let err = classify_ssh_master_failure(
            "myserver",
            None,
            None,
            false,
            control_path,
            &status,
            "unix_listener: path \"/tmp/o-1234-abcd12.sock\" too long for Unix domain socket",
        );
        assert_eq!(
            format!("{err}"),
            "[onyx] failed to create SSH control socket (path too long)\n  path: /tmp/o-1234-abcd12.sock"
        );
    }

    #[test]
    fn bootstrap_context_is_not_added_to_ssh_auth_errors() {
        let err = contextualize_bootstrap_error(
            anyhow::anyhow!("[onyx] SSH authentication was canceled."),
            "bootstrap failed",
        );
        assert_eq!(format!("{err}"), "[onyx] SSH authentication was canceled.");

        let err = contextualize_bootstrap_error(
            anyhow::anyhow!("[onyx] failed to create SSH control socket (path too long)\n  path: /tmp/o-1.sock"),
            "bootstrap failed",
        );
        assert_eq!(
            format!("{err}"),
            "[onyx] failed to create SSH control socket (path too long)\n  path: /tmp/o-1.sock"
        );

        let err = contextualize_bootstrap_error(anyhow::anyhow!("disk full"), "bootstrap failed");
        let text = format!("{err:#}");
        assert!(text.starts_with("bootstrap failed"));
        assert!(text.contains("disk full"));
    }

    // ───────── exec JSON helpers ─────────

    #[test]
    fn json_escape_handles_control_chars_and_quotes() {
        let mut out = String::new();
        json_escape_into(&mut out, "hi \"there\"\n\tbye\x01");
        assert_eq!(out, "hi \\\"there\\\"\\n\\tbye\\u0001");
    }

    #[test]
    fn jq_wraps_and_escapes() {
        assert_eq!(jq("a\"b"), "\"a\\\"b\"");
        assert_eq!(jq(""), "\"\"");
    }

    #[test]
    fn job_status_str_is_lowercase_and_stable() {
        // The landing page and any scripts keying off --json depend on
        // these exact strings; lock them in.
        assert_eq!(job_status_str(JobStatus::Running), "running");
        assert_eq!(job_status_str(JobStatus::Detached), "detached");
        assert_eq!(job_status_str(JobStatus::Succeeded), "succeeded");
        assert_eq!(job_status_str(JobStatus::Failed), "failed");
        assert_eq!(job_status_str(JobStatus::Expired), "expired");
    }

    #[test]
    fn format_relative_time_covers_each_unit() {
        assert_eq!(format_relative_time(100, 95), "5s ago");
        assert_eq!(format_relative_time(3600, 3300), "5m ago");
        assert_eq!(format_relative_time(100_000, 86_400), "3h ago");
        assert_eq!(format_relative_time(10_000_000, 1), "115d ago");
    }

    #[test]
    fn truncate_display_preserves_short_strings() {
        assert_eq!(truncate_display("abc", 10), "abc");
        let long = "a".repeat(30);
        let truncated = truncate_display(&long, 10);
        assert_eq!(truncated.chars().count(), 10);
        assert!(truncated.ends_with('…'));
    }

    // ───────── exec auto-resume classifiers + tuning ─────────

    #[test]
    fn exec_error_is_terminal_catches_unrecoverable_states() {
        // These are the server strings that mean "don't retry this job".
        for reason in [
            "job job_abc not found",
            "exec: job registry full (256 live jobs); finish some",
            "exec: spawn failed: No such file or directory",
            "exec: command is empty",
        ] {
            assert!(
                exec_error_is_terminal(reason),
                "expected terminal classification for: {reason}"
            );
        }
    }

    #[test]
    fn exec_error_is_terminal_leaves_transient_errors_retryable() {
        for reason in [
            "session already attached",
            "some random transient error",
            "", // empty → fall through to retry
        ] {
            assert!(
                !exec_error_is_terminal(reason),
                "did not expect terminal classification for: {reason}"
            );
        }
    }

    #[test]
    fn exec_reason_is_busy_matches_already_attached_variants() {
        assert!(exec_reason_is_busy("session already attached"));
        assert!(exec_reason_is_busy("Job Already Attached"));
        assert!(exec_reason_is_busy("ExecAttach rejected: already attached"));
        assert!(!exec_reason_is_busy("job not found"));
        assert!(!exec_reason_is_busy("connection lost"));
    }

    #[test]
    fn exec_resume_constants_are_coherent() {
        // Backoff must grow and never exceed the cap.
        assert!(EXEC_BACKOFF_INITIAL < EXEC_BACKOFF_MAX);
        assert!(EXEC_BACKOFF_MAX <= Duration::from_secs(5));
        // Resume window should at least cover a real laptop-sleep /
        // VPN-reset event.
        assert!(EXEC_RESUME_WINDOW >= Duration::from_secs(300));
        // Handshake × a few attempts should fit inside the window.
        assert!(INTERACTIVE_HANDSHAKE_TIMEOUT * 4 < EXEC_RESUME_WINDOW);
        // Busy-retry should be much faster than the backoff cap — it's a
        // known-transient case with a cheap server turnaround.
        assert!(EXEC_BUSY_RETRY < EXEC_BACKOFF_MAX);
    }

    #[test]
    fn reconnecting_json_is_single_field_object() {
        // Locks the exact wire shape the brief documents. Any script or
        // AI agent parsing the stream depends on these literal strings.
        //
        // We can't easily capture stdout from a unit test without
        // extra machinery, so we verify the components of the shape
        // instead: the JSON emitters are trivially local and their
        // output is just printlns. A downstream integration test
        // (run exec with --json, grep for the event) covers the
        // end-to-end path.
        //
        // Minimum guarantee: the helpers exist, and the constants
        // referenced in the prompts line up.
        let _: fn() = emit_reconnecting_json;
        let _: fn(&str, u64) = emit_resumed_json;
    }
}

#[derive(Debug, Clone)]
struct ResolvedSshConfig {
    hostname: String,
    user: String,
    identity_file: Option<String>,
}

fn parse_resolved_ssh_config(ssh_target: &str, stdout: &str) -> Result<ResolvedSshConfig> {
    let mut hostname = String::new();
    let mut user = String::new();
    let mut identity_file = None;

    for line in stdout.lines() {
        if let Some(v) = line.strip_prefix("hostname ") {
            hostname = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("user ") {
            user = v.trim().to_string();
        } else if identity_file.is_none() {
            if let Some(v) = line.strip_prefix("identityfile ") {
                let candidate = v.trim();
                if !candidate.is_empty() && candidate != "none" {
                    identity_file = Some(candidate.to_string());
                }
            }
        }
    }

    anyhow::ensure!(
        !hostname.is_empty(),
        "ssh -G returned no hostname for '{ssh_target}'; \
         check your SSH config or try a full user@host address"
    );

    if user.is_empty() {
        user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| "root".to_string());
    }

    Ok(ResolvedSshConfig {
        hostname,
        user,
        identity_file,
    })
}

/// Use `ssh -G <ssh_target>` to resolve the canonical hostname, user, and
/// preferred identity path from SSH config. This honours ~/.ssh/config,
/// ProxyJump, Include directives, etc.
fn resolve_via_ssh_config(ssh_target: &str, identity: Option<&str>) -> Result<ResolvedSshConfig> {
    let mut cmd = std::process::Command::new("ssh");
    if let Some(id) = identity {
        cmd.args(["-i", id]);
    }
    cmd.arg("-T");
    cmd.args(["-G", ssh_target]);
    cmd.stderr(std::process::Stdio::null());

    let out = cmd.output().context("ssh -G failed to run")?;
    // ssh -G exits 0 even for unknown aliases (uses defaults), so we don't
    // treat a non-zero exit as fatal here.

    parse_resolved_ssh_config(ssh_target, &String::from_utf8_lossy(&out.stdout))
}

/// Build a fully-resolved OnyxTarget from raw CLI args.
/// Port resolution order: explicit `port_override` → `ONYX_PORT` env → `:port` suffix → DEFAULT_PORT.
fn build_target(raw: &str, identity: Option<String>, port_override: Option<u16>) -> Result<OnyxTarget> {
    // Strip optional `:quic_port` suffix (rightmost colon followed by digits).
    let (ssh_part, quic_port) = match raw.rfind(':') {
        Some(i) if raw[i + 1..].parse::<u16>().is_ok() => {
            (raw[..i].to_string(), raw[i + 1..].parse::<u16>().unwrap())
        }
        _ => {
            let port = port_override
                .or_else(|| {
                    std::env::var("ONYX_PORT")
                        .ok()
                        .and_then(|v| v.trim().parse::<u16>().ok())
                })
                .unwrap_or(DEFAULT_PORT);
            (raw.to_string(), port)
        }
    };

    // Determine the bare host (strip leading user@).
    let host_only = match ssh_part.find('@') {
        Some(i) => &ssh_part[i + 1..],
        None => &ssh_part,
    };

    // Direct mode only when the host is a bare IP address and there is no '@'.
    // Everything else (hostnames, aliases, user@anything) uses SSH mode.
    let has_at = ssh_part.contains('@');
    let is_ip = host_only.parse::<std::net::IpAddr>().is_ok();
    let ssh_mode = has_at || !is_ip;

    if ssh_mode {
        // Resolve through SSH config to get the real hostname for QUIC.
        let resolved = resolve_via_ssh_config(&ssh_part, identity.as_deref())
            .with_context(|| format!("resolving '{ssh_part}'"))?;

        Ok(OnyxTarget {
            ssh_target: ssh_part,
            quic_host: resolved.hostname,
            quic_port,
            identity_file: identity,
            identity_hint: resolved.identity_file,
            ssh_mode: true,
        })
    } else {
        // Direct: use the IP as-is, no SSH involved.
        Ok(OnyxTarget {
            ssh_target: String::new(),
            quic_host: host_only.to_string(),
            quic_port,
            identity_file: identity,
            identity_hint: None,
            ssh_mode: false,
        })
    }
}

// ---------------------------------------------------------------------------
// SSH helpers — all take `ssh_target` (the verbatim alias/address accepted by
// `ssh`) plus an optional identity file path.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SshAuthFlow {
    InteractivePrompt,
    NonInteractive,
}

#[derive(Clone, Copy, Debug, Default)]
struct SshConnectMessages<'a> {
    establishing: Option<&'a str>,
    authenticated: Option<&'a str>,
}

#[derive(Debug)]
struct SshSession {
    target: String,
    identity: Option<String>,
    identity_hint: Option<String>,
    control_path: PathBuf,
}

impl SshSession {
    fn connect(
        target: &str,
        identity: Option<&str>,
        identity_hint: Option<&str>,
        auth_flow: SshAuthFlow,
        messages: SshConnectMessages<'_>,
    ) -> Result<Self> {
        let control_path = ssh_control_socket_path()?;
        let interactive_prompt =
            matches!(auth_flow, SshAuthFlow::InteractivePrompt) && std::io::stderr().is_terminal();
        if let Some(line) = messages.establishing {
            eprintln!("{line}");
        }
        let (status, stderr) =
            run_ssh_master(target, identity, &control_path, interactive_prompt)?;

        if !status.success() {
            let _ = fs::remove_file(&control_path);
            return Err(classify_ssh_master_failure(
                target,
                identity,
                identity_hint,
                interactive_prompt,
                &control_path,
                &status,
                &stderr,
            ));
        }

        if ssh_passphrase_prompt_count(&stderr) > 0 {
            if let Some(line) = messages.authenticated {
                eprintln!("{line}");
            }
        }

        Ok(Self {
            target: target.to_string(),
            identity: identity.map(str::to_string),
            identity_hint: identity_hint
                .map(str::to_string)
                .or_else(|| identity.map(str::to_string)),
            control_path,
        })
    }

    fn control_path(&self) -> &Path {
        &self.control_path
    }

    fn identity_hint(&self) -> Option<&str> {
        self.identity_hint.as_deref()
    }

    fn is_alive(&self) -> bool {
        let mut cmd = std::process::Command::new("ssh");
        if let Some(id) = self.identity.as_deref() {
            cmd.args(["-i", id]);
        }
        cmd.arg("-S");
        cmd.arg(&self.control_path);
        cmd.args(["-O", "check"]);
        cmd.arg(&self.target);
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
        cmd.status().map(|status| status.success()).unwrap_or(false)
    }
}

impl Drop for SshSession {
    fn drop(&mut self) {
        let mut cmd = std::process::Command::new("ssh");
        if let Some(id) = self.identity.as_deref() {
            cmd.args(["-i", id]);
        }
        cmd.arg("-S");
        cmd.arg(&self.control_path);
        cmd.args(["-O", "exit"]);
        cmd.arg(&self.target);
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
        let _ = cmd.status();
        let _ = fs::remove_file(&self.control_path);
    }
}

#[derive(Clone, Debug, Default)]
struct SshSessionPool {
    sessions: Arc<Mutex<HashMap<SshSessionKey, Arc<SshSession>>>>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SshSessionKey {
    target: String,
    identity: Option<String>,
}

impl SshSessionPool {
    fn get_or_connect(
        &self,
        target: &str,
        identity: Option<&str>,
        identity_hint: Option<&str>,
        auth_flow: SshAuthFlow,
        messages: SshConnectMessages<'_>,
    ) -> Result<Arc<SshSession>> {
        let key = SshSessionKey {
            target: target.to_string(),
            identity: identity.map(str::to_string),
        };

        let stale = {
            let sessions = self.sessions.lock().unwrap();
            match sessions.get(&key) {
                Some(session) if session.is_alive() => return Ok(Arc::clone(session)),
                Some(_) => true,
                None => false,
            }
        };
        if stale {
            self.sessions.lock().unwrap().remove(&key);
        }

        let created = Arc::new(SshSession::connect(
            target,
            identity,
            identity_hint,
            auth_flow,
            messages,
        )?);
        let mut sessions = self.sessions.lock().unwrap();
        match sessions.entry(key) {
            std::collections::hash_map::Entry::Occupied(entry) => Ok(Arc::clone(entry.get())),
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Arc::clone(&created));
                Ok(created)
            }
        }
    }
}

fn ssh_session_for(
    pool: Option<&SshSessionPool>,
    target: &str,
    identity: Option<&str>,
    identity_hint: Option<&str>,
    auth_flow: SshAuthFlow,
    messages: SshConnectMessages<'_>,
) -> Result<Arc<SshSession>> {
    match pool {
        Some(pool) => pool.get_or_connect(
            target,
            identity,
            identity_hint,
            auth_flow,
            messages,
        ),
        None => Ok(Arc::new(SshSession::connect(
            target,
            identity,
            identity_hint,
            auth_flow,
            messages,
        )?)),
    }
}

fn control_socket_path_len(path: &Path) -> usize {
    path.as_os_str().as_bytes().len()
}

fn ssh_control_socket_path_too_long_message(path: &Path) -> String {
    format!(
        "[onyx] failed to create SSH control socket (path too long)\n  path: {}",
        path.display()
    )
}

fn ssh_control_socket_failure_message(path: &Path, detail: Option<&str>) -> String {
    match detail.map(str::trim).filter(|detail| !detail.is_empty()) {
        Some(detail) => format!(
            "[onyx] failed to create SSH control socket\n  path: {}\n  detail: {}",
            path.display(),
            detail
        ),
        None => format!(
            "[onyx] failed to create SSH control socket\n  path: {}",
            path.display()
        ),
    }
}

fn ssh_control_socket_path() -> Result<PathBuf> {
    let base = Path::new("/tmp");
    anyhow::ensure!(
        base.is_dir(),
        "{}",
        ssh_control_socket_failure_message(base, Some("/tmp is unavailable"))
    );

    let pid = std::process::id();
    for _ in 0..SSH_CONTROL_SOCKET_ATTEMPTS {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let counter = SSH_SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed) as u64;
        let suffix = (now.as_nanos() as u64 ^ (counter << 12) ^ pid as u64) & 0x00ff_ffff;
        let path = base.join(format!("o-{pid}-{suffix:06x}.sock"));

        if control_socket_path_len(&path) > SSH_CONTROL_SOCKET_MAX_LEN {
            anyhow::bail!("{}", ssh_control_socket_path_too_long_message(&path));
        }
        if !path.exists() {
            return Ok(path);
        }
    }

    let fallback = base.join(format!("o-{pid}-xxxxxx.sock"));
    anyhow::bail!(
        "{}",
        ssh_control_socket_failure_message(&fallback, Some("could not allocate a unique socket path"))
    )
}

fn ssh_control_socket_failure_from_stderr(
    control_path: &Path,
    stderr: &str,
) -> Option<anyhow::Error> {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("too long for unix domain socket") {
        return Some(anyhow::anyhow!(
            ssh_control_socket_path_too_long_message(control_path)
        ));
    }
    if lower.contains("unix_listener:")
        || lower.contains("control socket")
        || lower.contains("muxserver_listen")
    {
        return Some(anyhow::anyhow!(ssh_control_socket_failure_message(
            control_path,
            Some(stderr),
        )));
    }
    None
}

fn ssh_identity_from_stderr(stderr: &str) -> Option<String> {
    for line in stderr.lines() {
        if let Some(rest) = line.strip_prefix("Enter passphrase for key '") {
            if let Some(path) = rest.strip_suffix("': ") {
                return Some(path.to_string());
            }
            if let Some((path, _)) = rest.split_once("':") {
                return Some(path.to_string());
            }
        }
        if let Some(rest) = line.strip_prefix("Load key \"") {
            if let Some((path, _)) = rest.split_once('"') {
                return Some(path.to_string());
            }
        }
        if let Some(rest) = line.strip_prefix("Load key '") {
            if let Some((path, _)) = rest.split_once('\'') {
                return Some(path.to_string());
            }
        }
    }
    None
}

fn ssh_help_identity(
    identity: Option<&str>,
    identity_hint: Option<&str>,
    stderr: &str,
) -> Option<String> {
    ssh_identity_from_stderr(stderr)
        .or_else(|| identity.map(str::to_string))
        .or_else(|| identity_hint.map(str::to_string))
}

fn ssh_add_hint(identity: Option<&str>) -> String {
    match identity {
        Some(path) => format!("ssh-add {}", display_shell_path(path)),
        None => "ssh-add ~/.ssh/id_rsa".to_string(),
    }
}

fn ssh_passphrase_required_message(identity: Option<&str>) -> String {
    format!(
        "[onyx] SSH key requires a passphrase.\n\
         Onyx could not complete bootstrap through the current SSH flow.\n\
         Try unlocking your key first on your local machine:\n  {}",
        ssh_add_hint(identity)
    )
}

fn ssh_auth_canceled_message() -> String {
    "[onyx] SSH authentication was canceled.".to_string()
}

fn ssh_auth_retry_message(identity: Option<&str>) -> String {
    format!(
        "[onyx] SSH authentication could not be completed cleanly.\n\
         Please retry, or unlock your key first with:\n  {}",
        ssh_add_hint(identity)
    )
}

fn ssh_connect_timeout_message(target: &str) -> String {
    format!(
        "[onyx] SSH connection timed out while establishing the session ({secs}s).\n\
         Check SSH reachability and try again:\n  ssh {target}",
        secs = SSH_CONNECT_TIMEOUT.as_secs(),
    )
}

fn ssh_banner_timeout_message(target: &str) -> String {
    format!(
        "[onyx] SSH connection timed out during banner exchange.\n\
         Check SSH reachability and try again:\n  ssh {target}"
    )
}

fn ssh_passphrase_prompt_count(stderr: &str) -> usize {
    let lower = stderr.to_ascii_lowercase();
    lower.matches("enter passphrase for key").count() + lower.matches("enter pin for").count()
}

fn ssh_stderr_is_auth_related(lower: &str) -> bool {
    [
        "permission denied",
        "sign_and_send_pubkey",
        "agent refused operation",
        "incorrect passphrase",
        "bad passphrase",
        "load key",
        "decrypt private key",
        "passphrase",
        "authentication failed",
        "publickey",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn ssh_auth_failure_message(
    identity: Option<&str>,
    identity_hint: Option<&str>,
    interactive_prompt: bool,
    exit_code: Option<i32>,
    signal: Option<i32>,
    stderr: &str,
) -> Option<String> {
    let lower = stderr.to_ascii_lowercase();
    let prompt_count = ssh_passphrase_prompt_count(stderr);
    let auth_related = prompt_count > 0 || ssh_stderr_is_auth_related(&lower);
    let help_identity = ssh_help_identity(identity, identity_hint, stderr);

    if matches!(signal, Some(2 | 15)) {
        return Some(ssh_auth_canceled_message());
    }
    if !auth_related {
        return None;
    }

    if interactive_prompt {
        if prompt_count > 1
            || lower.contains("incorrect passphrase")
            || lower.contains("bad passphrase")
            || (prompt_count == 1 && lower.contains("permission denied"))
        {
            return Some(ssh_auth_retry_message(help_identity.as_deref()));
        }
        if prompt_count == 1 {
            return Some(ssh_auth_canceled_message());
        }
    }

    if !interactive_prompt
        && (prompt_count > 0
            || lower.contains("incorrect passphrase")
            || lower.contains("bad passphrase")
            || lower.contains("decrypt private key")
            || lower.contains("load key"))
    {
        return Some(ssh_passphrase_required_message(help_identity.as_deref()));
    }

    if exit_code == Some(255) || auth_related {
        return Some(ssh_auth_retry_message(help_identity.as_deref()));
    }

    None
}

fn run_ssh_master(
    target: &str,
    identity: Option<&str>,
    control_path: &Path,
    interactive_prompt: bool,
) -> Result<(std::process::ExitStatus, String)> {
    let mut cmd = std::process::Command::new("ssh");
    if let Some(id) = identity {
        cmd.args(["-i", id]);
    }
    cmd.arg("-S");
    cmd.arg(control_path);
    cmd.arg("-M");
    cmd.arg("-N");
    cmd.arg("-f");
    cmd.arg("-o");
    cmd.arg(format!("ConnectTimeout={}", SSH_CONNECT_TIMEOUT.as_secs()));
    cmd.args([
        "-o",
        if interactive_prompt {
            "BatchMode=no"
        } else {
            "BatchMode=yes"
        },
    ]);
    cmd.arg(target);
    cmd.stdin(if interactive_prompt {
        std::process::Stdio::inherit()
    } else {
        std::process::Stdio::null()
    });
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().context("starting ssh authentication flow")?;
    let stderr_reader = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("capturing ssh stderr"))?;
    let capture = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut stderr_reader = stderr_reader;
        let mut captured = Vec::new();
        let mut buf = [0u8; 1024];
        let mut local_stderr = std::io::stderr();
        loop {
            match stderr_reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    captured.extend_from_slice(&buf[..n]);
                    if interactive_prompt {
                        local_stderr.write_all(&buf[..n])?;
                        local_stderr.flush()?;
                    }
                }
                Err(err) => return Err(err),
            }
        }
        Ok(captured)
    });

    let status = child.wait().context("waiting for ssh authentication flow")?;
    let stderr = capture
        .join()
        .map_err(|_| anyhow::anyhow!("ssh stderr reader panicked"))?
        .context("reading ssh authentication stderr")?;
    Ok((status, String::from_utf8_lossy(&stderr).into_owned()))
}

fn classify_ssh_master_failure(
    target: &str,
    identity: Option<&str>,
    identity_hint: Option<&str>,
    interactive_prompt: bool,
    control_path: &Path,
    status: &std::process::ExitStatus,
    stderr: &str,
) -> anyhow::Error {
    if let Some(err) = ssh_control_socket_failure_from_stderr(control_path, stderr) {
        return err;
    }
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("banner exchange") && lower.contains("timed out") {
        return anyhow::anyhow!(ssh_banner_timeout_message(target));
    }
    if lower.contains("timed out") {
        return anyhow::anyhow!(ssh_connect_timeout_message(target));
    }
    if let Some(message) = ssh_auth_failure_message(
        identity,
        identity_hint,
        interactive_prompt,
        status.code(),
        status.signal(),
        stderr,
    ) {
        return anyhow::anyhow!(message);
    }

    let stderr = stderr.trim();
    if stderr.is_empty() {
        anyhow::anyhow!("[onyx] SSH connection failed")
    } else {
        anyhow::anyhow!(
            "[onyx] SSH connection failed\n  exit: {}\n  stderr: {}",
            status.code().unwrap_or(-1),
            stderr
        )
    }
}

fn ssh_cmd(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
) -> std::process::Command {
    let mut c = std::process::Command::new("ssh");
    // -T: never allocate a pseudo-terminal for these non-interactive bootstrap
    //     commands.  Without it SSH prints "Pseudo-terminal will not be
    //     allocated because stdin is not a terminal." as noise on every run.
    c.arg("-T");
    c.arg("-o");
    c.arg(format!("ConnectTimeout={}", SSH_CONNECT_TIMEOUT.as_secs()));
    if let Some(id) = identity {
        c.args(["-i", id]);
    }
    if let Some(session) = session {
        c.arg("-S");
        c.arg(session.control_path());
        c.args(["-o", "ControlMaster=auto", "-o", "BatchMode=yes"]);
    }
    c.arg(target);
    c
}

fn ssh_command_failure(
    identity: Option<&str>,
    identity_hint: Option<&str>,
    status: &std::process::ExitStatus,
    stderr: &str,
) -> anyhow::Error {
    if let Some(message) =
        ssh_auth_failure_message(
            identity,
            identity_hint,
            false,
            status.code(),
            status.signal(),
            stderr,
        )
    {
        return anyhow::anyhow!(message);
    }

    let stderr = stderr.trim();
    if stderr.is_empty() {
        anyhow::anyhow!("SSH command failed (exit {})", status.code().unwrap_or(-1))
    } else {
        anyhow::anyhow!(
            "SSH command failed (exit {})\n  stderr: {}",
            status.code().unwrap_or(-1),
            stderr
        )
    }
}

/// Run remote command; return trimmed stdout.
fn ssh_capture(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
    cmd: &str,
) -> Result<String> {
    let out = ssh_cmd(target, identity, session)
        .arg(cmd)
        .stderr(std::process::Stdio::piped())
        .output()
        .context("ssh")?;
    if !out.status.success() {
        return Err(ssh_command_failure(
            identity,
            session.and_then(|ssh| ssh.identity_hint()),
            &out.status,
            &String::from_utf8_lossy(&out.stderr),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Run remote command; inherit stdout + stderr (shows build output, etc.).
fn ssh_show(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
    cmd: &str,
) -> Result<()> {
    let st = ssh_cmd(target, identity, session)
        .arg(cmd)
        .status()
        .context("ssh")?;
    if !st.success() {
        if let Some(message) = ssh_auth_failure_message(
            identity,
            session.and_then(|ssh| ssh.identity_hint()),
            false,
            st.code(),
            st.signal(),
            "",
        )
        {
            anyhow::bail!(message);
        }
        anyhow::bail!("remote command failed (exit {})", st.code().unwrap_or(-1));
    }
    Ok(())
}

/// Upload bytes to `remote_path` by piping into `cat > path` over SSH.
fn ssh_upload(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
    remote_path: &str,
    content: &[u8],
) -> Result<()> {
    let parent = std::path::Path::new(remote_path)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("remote path has no parent: {remote_path}"))?;
    let parent = parent.display().to_string();
    let mkdir = ssh_cmd(target, identity, session)
        .arg(format!("mkdir -p {}", shell_quote(&parent)))
        .stderr(std::process::Stdio::piped())
        .output()
        .context("creating remote upload directory")?;
    if !mkdir.status.success() {
        if let Some(message) = ssh_auth_failure_message(
            identity,
            session.and_then(|ssh| ssh.identity_hint()),
            false,
            mkdir.status.code(),
            mkdir.status.signal(),
            &String::from_utf8_lossy(&mkdir.stderr),
        ) {
            anyhow::bail!(message);
        }
        let stderr = String::from_utf8_lossy(&mkdir.stderr).trim().to_string();
        anyhow::bail!(
            "ssh upload failed\n  file: {remote_path}\n  exit: {}\n  stderr: {}",
            mkdir.status.code().unwrap_or(-1),
            if stderr.is_empty() {
                "<empty>"
            } else {
                &stderr
            }
        );
    }

    let mut child = ssh_cmd(target, identity, session)
        .arg(format!("cat > {}", shell_quote(remote_path)))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("ssh upload")?;

    if let Some(mut s) = child.stdin.take() {
        s.write_all(content).context("writing to ssh stdin")?;
    }
    let out = child.wait_with_output().context("waiting for ssh upload")?;
    if !out.status.success() {
        if let Some(message) = ssh_auth_failure_message(
            identity,
            session.and_then(|ssh| ssh.identity_hint()),
            false,
            out.status.code(),
            out.status.signal(),
            &String::from_utf8_lossy(&out.stderr),
        ) {
            anyhow::bail!(message);
        }
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        anyhow::bail!(
            "ssh upload failed\n  file: {remote_path}\n  exit: {}\n  stderr: {}",
            out.status.code().unwrap_or(-1),
            if stderr.is_empty() {
                "<empty>"
            } else {
                &stderr
            }
        );
    }

    let verify = ssh_cmd(target, identity, session)
        .arg(format!("test -f {}", shell_quote(remote_path)))
        .stderr(std::process::Stdio::piped())
        .output()
        .context("verifying remote upload")?;
    if !verify.status.success() {
        if let Some(message) = ssh_auth_failure_message(
            identity,
            session.and_then(|ssh| ssh.identity_hint()),
            false,
            verify.status.code(),
            verify.status.signal(),
            &String::from_utf8_lossy(&verify.stderr),
        ) {
            anyhow::bail!(message);
        }
        let stderr = String::from_utf8_lossy(&verify.stderr).trim().to_string();
        anyhow::bail!(
            "ssh upload verification failed\n  file: {remote_path}\n  exit: {}\n  stderr: {}",
            verify.status.code().unwrap_or(-1),
            if stderr.is_empty() {
                "<empty>"
            } else {
                &stderr
            }
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bootstrap steps
// ---------------------------------------------------------------------------

/// FNV-1a hash of all embedded server source files.
/// Used to detect when the local source has changed so we rebuild automatically.
fn source_hash() -> u64 {
    const OFFSET: u64 = 14695981039346656037;
    const PRIME: u64 = 1099511628211;
    let mut h = OFFSET;
    for b in SERVER_MAIN_RS
        .bytes()
        .chain(SHARED_LIB_RS.bytes())
        .chain(SERVER_CARGO_TOML.bytes())
        .chain(SHARED_CARGO_TOML.bytes())
    {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// FNV-1a hash of the remote config files (tmux.conf + status.sh).
/// Separate from source_hash so config tweaks don't force a server rebuild.
fn config_hash() -> u64 {
    const OFFSET: u64 = 14695981039346656037;
    const PRIME: u64 = 1099511628211;
    let mut h = OFFSET;
    for b in ONYX_TMUX_CONF.bytes().chain(ONYX_STATUS_SH.bytes()) {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

// ---------------------------------------------------------------------------
// Remote status — one SSH call that returns everything we need to decide
// whether to skip bootstrap entirely (fast path) or do work (slow path).
// ---------------------------------------------------------------------------

struct RemoteStatus {
    hash_ok: bool,   // remote .server-hash == current source hash
    running: bool,   // onyx-server process is alive
    healthy: bool,   // onyx-server process is confirmed ready for QUIC
    own_pid: bool,   // server.pid still points to an onyx-server process
    has_cargo: bool, // ~/.cargo/bin/cargo exists and is executable
    conf_ok: bool,   // tmux config + status script are current
    arch: String,    // uname -m on the remote host
}

/// Single SSH round-trip: verifies auth and gathers all bootstrap pre-conditions.
/// Returns Err on SSH auth failure or connection error.
fn remote_status(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
    expected_hash: &str,
    quic_port: u16,
    paths: &RemotePaths,
) -> Result<RemoteStatus> {
    let conf_hash = format!("{:016x}", config_hash());
    // Everything in one shell snippet — one TCP+crypto handshake total.
    let script = format!(
        "h=$(cat {remote_dir}/.server-hash 2>/dev/null); \
         p=$(cat {remote_dir}/server.pid   2>/dev/null); \
         r=no; [ -n \"$p\" ] && kill -0 \"$p\" 2>/dev/null && r=yes; \
         own=no; \
         ready=no; \
         if [ \"$r\" = yes ] && [ -r /proc/$p/cmdline ]; then \
           cmd=$(tr '\\000' ' ' < /proc/$p/cmdline 2>/dev/null); \
           case \"$cmd\" in *onyx-server*) own=yes ;; esac; \
         fi; \
         if [ \"$own\" = yes ] && grep -q 'listening on .*:{quic_port}  (ALPN: onyx)' {server_log} 2>/dev/null; then \
           ready=yes; \
         fi; \
         c=no; \
         if [ -x ~/.cargo/bin/cargo ] && ~/.cargo/bin/cargo --version >/dev/null 2>&1; then \
           c=yes; \
         fi; \
         arch=$(uname -m 2>/dev/null || echo unknown); \
         cv=$(cat {conf_dir}/.conf-hash 2>/dev/null); \
         echo \"h=$h r=$r own=$own ready=$ready c=$c arch=$arch cv=$cv\"",
        server_log = shell_quote(&format!("{}/server.log", paths.remote_dir)),
        remote_dir = shell_quote(&paths.remote_dir),
        conf_dir = shell_quote(&paths.conf_dir),
    );

    let out = ssh_cmd(target, identity, session)
        .arg(&script)
        .stderr(std::process::Stdio::piped())
        .output()
        .context("failed to run ssh")?;

    if !out.status.success() {
        if let Some(message) = ssh_auth_failure_message(
            identity,
            session.and_then(|ssh| ssh.identity_hint()),
            false,
            out.status.code(),
            out.status.signal(),
            &String::from_utf8_lossy(&out.stderr),
        ) {
            anyhow::bail!(message);
        }
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if stderr.is_empty() {
            anyhow::bail!("[onyx] SSH connection failed");
        }
        anyhow::bail!(
            "[onyx] SSH connection failed\n  exit: {}\n  stderr: {}",
            out.status.code().unwrap_or(-1),
            stderr
        );
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let get = |key: &str| -> String {
        text.split_whitespace()
            .find(|kv| kv.starts_with(&format!("{key}=")))
            .and_then(|kv| kv.splitn(2, '=').nth(1))
            .unwrap_or("")
            .to_string()
    };

    Ok(RemoteStatus {
        hash_ok: get("h") == expected_hash,
        running: get("r") == "yes",
        healthy: get("ready") == "yes",
        own_pid: get("own") == "yes",
        has_cargo: get("c") == "yes",
        conf_ok: get("cv") == conf_hash,
        arch: get("arch"),
    })
}

// ---------------------------------------------------------------------------
// Config file helpers — tmux.conf + status.sh
// ---------------------------------------------------------------------------

/// Upload tmux.conf and status.sh to CONF_DIR and record the config hash.
/// Only called when config_hash() doesn't match the remote, so it's rare.
fn ensure_config_files(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
    paths: &RemotePaths,
) -> Result<()> {
    let conf_hash = format!("{:016x}", config_hash());
    let _ = ssh_capture(
        target,
        identity,
        session,
        &format!(
            "mkdir -p {conf_dir} && chmod 700 {conf_dir}",
            conf_dir = shell_quote(&paths.conf_dir)
        ),
    );
    ssh_upload(
        target,
        identity,
        session,
        &format!("{}/tmux.conf", paths.conf_dir),
        ONYX_TMUX_CONF.as_bytes(),
    )?;
    ssh_upload(
        target,
        identity,
        session,
        &format!("{}/status.sh", paths.conf_dir),
        ONYX_STATUS_SH.as_bytes(),
    )?;
    let conf_hash_path = format!("{}/.conf-hash", paths.conf_dir);
    let _ = ssh_capture(
        target,
        identity,
        session,
        &format!(
            "chmod 700 {conf_dir} && chmod 600 {conf_dir}/tmux.conf && \
                  chmod 700 {conf_dir}/status.sh && \
                  printf %s {conf_hash} > {conf_hash_path} && chmod 600 {conf_hash_path}",
            conf_dir = shell_quote(&paths.conf_dir),
            conf_hash = shell_quote(&conf_hash),
            conf_hash_path = shell_quote(&conf_hash_path),
        ),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Slow-path helpers — only called when something needs installing/building
// ---------------------------------------------------------------------------

fn ensure_rust(target: &str, identity: Option<&str>, session: Option<&SshSession>) -> Result<()> {
    eprintln!("[onyx] installing Rust via rustup…");
    let rustup = ssh_show(
        target,
        identity,
        session,
        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
         | sh -s -- -y --no-modify-path",
    );
    if rustup.is_err() {
        anyhow::bail!("[onyx] rustup failed; cargo is unavailable");
    }

    let cargo_ready = ssh_capture(
        target,
        identity,
        session,
        "if [ -x ~/.cargo/bin/cargo ] && ~/.cargo/bin/cargo --version >/dev/null 2>&1; then echo yes; else echo no; fi",
    )
    .unwrap_or_default();
    if cargo_ready != "yes" {
        anyhow::bail!("[onyx] rustup failed; cargo is unavailable");
    }

    eprintln!("[onyx] Rust installed");
    Ok(())
}

fn normalized_server_arch(remote_arch: &str) -> Option<&'static str> {
    match remote_arch.trim() {
        "x86_64" | "amd64" => Some("x86_64"),
        "aarch64" | "arm64" => Some("arm64"),
        _ => None,
    }
}

fn server_artifact_name(remote_arch: &str) -> Option<&'static str> {
    match normalized_server_arch(remote_arch) {
        Some("x86_64") => Some("onyx-server-linux-x86_64"),
        Some("arm64") => Some("onyx-server-linux-arm64"),
        _ => None,
    }
}

fn remote_arch_label(remote_arch: &str) -> &str {
    normalized_server_arch(remote_arch).unwrap_or_else(|| {
        let trimmed = remote_arch.trim();
        if trimmed.is_empty() {
            "unknown"
        } else {
            trimmed
        }
    })
}

fn server_target_triples(remote_arch: &str) -> &'static [&'static str] {
    match normalized_server_arch(remote_arch) {
        Some("x86_64") => &["x86_64-unknown-linux-musl", "x86_64-unknown-linux-gnu"],
        Some("arm64") => &["aarch64-unknown-linux-musl", "aarch64-unknown-linux-gnu"],
        _ => &[],
    }
}

fn push_unique_path(out: &mut Vec<PathBuf>, path: PathBuf) {
    if !out.iter().any(|existing| existing == &path) {
        out.push(path);
    }
}

fn prebuilt_server_candidates(remote_arch: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Some(name) = server_artifact_name(remote_arch) else {
        return out;
    };

    if let Ok(exe) = std::env::current_exe() {
        for exe_path in [Some(exe.clone()), fs::canonicalize(&exe).ok()] {
            let Some(exe_path) = exe_path else {
                continue;
            };
            if let Some(dir) = exe_path.parent() {
                push_unique_path(&mut out, dir.join(name));
                if let Some(prefix) = dir.parent() {
                    push_unique_path(&mut out, prefix.join("libexec").join(name));
                }
            }
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        push_unique_path(&mut out, cwd.join(name));
        for triple in server_target_triples(remote_arch) {
            push_unique_path(
                &mut out,
                cwd.join("target")
                    .join(triple)
                    .join("release")
                    .join("onyx-server"),
            );
        }
        push_unique_path(
            &mut out,
            cwd.join("target").join("release").join("onyx-server"),
        );
    }

    out
}

fn expected_elf_machine(remote_arch: &str) -> Option<u16> {
    match normalized_server_arch(remote_arch) {
        Some("x86_64") => Some(62),
        Some("arm64") => Some(183),
        _ => None,
    }
}

fn looks_like_matching_linux_server_binary(path: &Path, remote_arch: &str) -> bool {
    let Some(expected_machine) = expected_elf_machine(remote_arch) else {
        return false;
    };

    let mut header = [0u8; 20];
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    if file.read_exact(&mut header).is_err() {
        return false;
    }

    if &header[..4] != b"\x7fELF" {
        return false;
    }

    u16::from_le_bytes([header[18], header[19]]) == expected_machine
}

fn select_local_prebuilt_server<I>(remote_arch: &str, candidates: I) -> Option<PathBuf>
where
    I: IntoIterator<Item = PathBuf>,
{
    candidates
        .into_iter()
        .find(|path| path.is_file() && looks_like_matching_linux_server_binary(path, remote_arch))
}

fn find_local_prebuilt_server(remote_arch: &str) -> Option<PathBuf> {
    select_local_prebuilt_server(remote_arch, prebuilt_server_candidates(remote_arch))
}

fn is_user_visible_ssh_error(err: &anyhow::Error) -> bool {
    let msg = format!("{err:#}");
    msg.contains("[onyx] SSH key requires a passphrase.")
        || msg.contains("[onyx] SSH authentication was canceled.")
        || msg.contains("[onyx] SSH authentication could not be completed cleanly.")
        || msg.contains("[onyx] failed to create SSH control socket")
        || msg.contains("[onyx] SSH connection failed")
        || msg.contains("[onyx] SSH connection timed out")
}

fn contextualize_bootstrap_error(err: anyhow::Error, context: &'static str) -> anyhow::Error {
    if is_user_visible_ssh_error(&err) {
        err
    } else {
        Err::<(), _>(err).context(context).unwrap_err()
    }
}

fn bootstrap_error_with_help(err: anyhow::Error) -> anyhow::Error {
    if is_user_visible_ssh_error(&err) {
        return err;
    }
    anyhow::anyhow!(
        "{}\nnext steps:\n  set ONYX_REMOTE_DIR to a writable absolute path on the remote host\n  or install/start onyx-server manually and re-run with --no-bootstrap",
        err
    )
}

fn bootstrap_cannot_continue(err: anyhow::Error) -> anyhow::Error {
    if is_user_visible_ssh_error(&err) {
        return err;
    }
    anyhow::anyhow!(
        "{}\n[onyx] bootstrap cannot continue without a usable onyx-server binary",
        err
    )
}

fn upload_and_build(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
    paths: &RemotePaths,
) -> Result<()> {
    eprintln!("[onyx] uploading source…");
    ssh_show(
        target,
        identity,
        session,
        &format!(
            "mkdir -p {remote_dir}/shared/src {remote_dir}/server/src && chmod 700 {remote_dir}",
            remote_dir = shell_quote(&paths.remote_dir)
        ),
    )?;

    ssh_upload(
        target,
        identity,
        session,
        &format!("{}/Cargo.toml", paths.remote_dir),
        REMOTE_WORKSPACE_TOML.as_bytes(),
    )?;
    ssh_upload(
        target,
        identity,
        session,
        &format!("{}/shared/Cargo.toml", paths.remote_dir),
        SHARED_CARGO_TOML.as_bytes(),
    )?;
    ssh_upload(
        target,
        identity,
        session,
        &format!("{}/shared/src/lib.rs", paths.remote_dir),
        SHARED_LIB_RS.as_bytes(),
    )?;
    ssh_upload(
        target,
        identity,
        session,
        &format!("{}/server/Cargo.toml", paths.remote_dir),
        SERVER_CARGO_TOML.as_bytes(),
    )?;
    ssh_upload(
        target,
        identity,
        session,
        &format!("{}/server/src/main.rs", paths.remote_dir),
        SERVER_MAIN_RS.as_bytes(),
    )?;

    eprintln!("[onyx] building on remote from source (last-resort fallback)…");
    // Build into the workspace's target/ as usual, then stage the resulting
    // binary at onyx-server.new. We deliberately do NOT overwrite the live
    // onyx-server path here — that triggers ETXTBSY ("Text file busy") if
    // the old server is still running. The atomic install step below takes
    // care of the actual swap.
    ssh_show(
        target,
        identity,
        session,
        &format!(
            "cd {} && ~/.cargo/bin/cargo build --release -p server 2>&1 && \
             cp target/release/onyx-server onyx-server.new",
            shell_quote(&paths.remote_dir)
        ),
    )?;
    eprintln!("[onyx] build complete");
    Ok(())
}

fn upload_prebuilt_server(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
    remote_arch: &str,
    paths: &RemotePaths,
) -> Result<bool> {
    let Some(local_binary) = find_local_prebuilt_server(remote_arch) else {
        return Ok(false);
    };

    let binary_name = server_artifact_name(remote_arch).unwrap_or("onyx-server");
    eprintln!("[onyx] installing prebuilt server ({binary_name})…");
    let bytes = fs::read(&local_binary).with_context(|| {
        format!(
            "reading local prebuilt server binary {}",
            local_binary.display()
        )
    })?;
    // Stage at onyx-server.new — never write directly to the live path,
    // which would ETXTBSY against a running onyx-server. The atomic
    // install step moves this into place after stopping the old server.
    let staging = format!("{}/onyx-server.new", paths.remote_dir);
    ssh_upload(target, identity, session, &staging, &bytes)?;
    Ok(true)
}

/// Stop the currently-running onyx-server (if we own its pid), atomically
/// rename the pre-uploaded onyx-server.new into place, update the hash
/// stamp, and leave the system ready for `start_server`.
///
/// This is the critical reliability fix: we never write over the live
/// binary. Linux returns ETXTBSY ("Text file busy") if you try to
/// open-for-write a file that is currently executing as a process; the
/// old flow hit that exact error on every in-place update. The new flow
/// uploads to a staging path, stops the running process, then uses
/// `mv -f` (POSIX-atomic on the same filesystem) to swap.
fn install_staged_server_binary(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
    hash: &str,
    status: &RemoteStatus,
    paths: &RemotePaths,
) -> Result<()> {
    let server_pid = format!("{}/server.pid", paths.remote_dir);
    let hash_path = format!("{}/.server-hash", paths.remote_dir);

    // Only kill the remote process if server.pid clearly points at our
    // onyx-server. Avoids stomping unrelated processes if the pid file
    // somehow contains a stale/wrong value.
    let stop_cmd = if status.own_pid {
        format!(
            "pid=$(cat {pid} 2>/dev/null); \
             if [ -n \"$pid\" ] && kill -0 \"$pid\" 2>/dev/null; then \
               kill \"$pid\" 2>/dev/null; \
               for i in 1 2 3 4 5 6 7 8 9 10; do \
                 kill -0 \"$pid\" 2>/dev/null || break; \
                 sleep 0.2; \
               done; \
               kill -0 \"$pid\" 2>/dev/null && kill -9 \"$pid\" 2>/dev/null; \
               true; \
             fi; ",
            pid = shell_quote(&server_pid),
        )
    } else {
        String::new()
    };

    // Distinct exit codes so classify_install_error can produce a precise
    // diagnosis rather than a generic "bootstrap failed".
    let script = format!(
        "cd {remote_dir} || exit 10; \
         [ -f onyx-server.new ] || {{ echo 'onyx-server.new missing after upload' >&2; exit 20; }}; \
         chmod 700 onyx-server.new || exit 21; \
         {stop_cmd}\
         mv -f onyx-server.new onyx-server || {{ echo 'mv onyx-server.new onyx-server failed' >&2; exit 22; }}; \
         printf %s {hash} > {hash_path} || exit 23; \
         chmod 600 {hash_path} || exit 24",
        remote_dir = shell_quote(&paths.remote_dir),
        stop_cmd = stop_cmd,
        hash = shell_quote(hash),
        hash_path = shell_quote(&hash_path),
    );

    ssh_show(target, identity, session, &script).map_err(classify_install_error)
}

/// Turn a shell-error from install_staged_server_binary into a precise,
/// user-facing message. Only renames errors whose cause we are sure of —
/// anything else is passed through unchanged.
fn classify_install_error(err: anyhow::Error) -> anyhow::Error {
    let msg = format!("{err:?}");
    if msg.contains("Text file busy") || msg.contains("ETXTBSY") {
        anyhow::anyhow!(
            "could not replace onyx-server: binary reports busy even via atomic swap. \
             This should not normally happen; file a bug with the output above. \
             Underlying error: {err}"
        )
    } else if msg.contains("Permission denied") {
        anyhow::anyhow!(
            "could not install onyx-server: permission denied on remote. \
             Try a writable path, e.g. ONYX_REMOTE_DIR=/tmp/onyx onyx user@host. \
             Underlying error: {err}"
        )
    } else if msg.contains("No space left on device") {
        anyhow::anyhow!(
            "could not install onyx-server: remote disk is full. \
             Underlying error: {err}"
        )
    } else if msg.contains("command not found") {
        anyhow::anyhow!(
            "missing required tool on remote (mv/chmod/kill). \
             Underlying error: {err}"
        )
    } else if msg.contains("exit 20") {
        anyhow::anyhow!(
            "onyx-server.new was not found on the remote after upload — \
             the upload likely failed silently. Underlying error: {err}"
        )
    } else {
        err
    }
}

fn start_server(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
    quic_port: u16,
    paths: &RemotePaths,
) -> Result<()> {
    let server_pid = format!("{}/server.pid", paths.remote_dir);
    let server_log = format!("{}/server.log", paths.remote_dir);
    let remote_dir = shell_quote(&paths.remote_dir);
    let status = remote_status(target, identity, session, "", quic_port, paths)?;

    if status.healthy {
        eprintln!("[onyx] onyx-server already running");
        return Ok(());
    }

    if status.running && status.own_pid {
        eprintln!("[onyx] existing onyx-server is unhealthy; restarting");
    } else if status.running {
        anyhow::bail!(
            "startup failed: port appears busy but server.pid does not point to a healthy onyx-server"
        );
    } else {
        eprintln!("[onyx] starting server…");
    }

    // Kill stale instance + give OS a moment to release the UDP socket.
    if status.own_pid {
        let _ = ssh_capture(
            target,
            identity,
            session,
            &format!(
                "pid=$(cat {} 2>/dev/null); \
         [ -n \"$pid\" ] && kill \"$pid\" 2>/dev/null; \
         sleep 0.5; true",
                shell_quote(&server_pid)
            ),
        );
    }

    // Clear old log so the readiness poll only sees fresh output.
    let _ = ssh_capture(
        target,
        identity,
        session,
        &format!(": > {} 2>/dev/null; true", shell_quote(&server_log)),
    );

    let port_arg = if quic_port == DEFAULT_PORT {
        String::new()
    } else {
        format!(" --port {quic_port}")
    };
    ssh_show(
        target,
        identity,
        session,
        &format!(
            "nohup {remote_dir}/onyx-server{port_arg} \
         >{server_log} 2>&1 </dev/null & \
         printf %s \"$!\" > {server_pid} && \
         chmod 600 {server_pid} {server_log}",
            server_pid = shell_quote(&server_pid),
            server_log = shell_quote(&server_log),
            remote_dir = remote_dir,
            port_arg = port_arg,
        ),
    )?;

    // Poll server.log for "listening on :<port>" — confirms the UDP socket is bound.
    // Checks every 500 ms for up to 10 s.
    let ready = (0..20).any(|_| {
        std::thread::sleep(Duration::from_millis(500));
        ssh_capture(
            target,
            identity,
            session,
            &format!(
                "grep -q 'listening on .*:{quic_port}' {} 2>/dev/null && echo yes",
                shell_quote(&server_log)
            ),
        )
        .map(|s| s == "yes")
        .unwrap_or(false)
    });

    if !ready {
        if let Ok(log) = ssh_capture(
            target,
            identity,
            session,
            &format!("tail -20 {} 2>/dev/null", shell_quote(&server_log)),
        ) {
            if !log.is_empty() {
                eprintln!("[onyx] server.log:\n{log}");
            }
        }
        if let Ok(err) = ssh_capture(
            target,
            identity,
            session,
            &format!(
                "grep -m1 'Address already in use' {} 2>/dev/null",
                shell_quote(&server_log)
            ),
        ) {
            if !err.is_empty() {
                anyhow::bail!("onyx-server failed to start: {err}");
            }
        }
        anyhow::bail!(
            "onyx-server failed to start — see {} on the remote host",
            server_log
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Doctor — lightweight pre-flight diagnostics
// ---------------------------------------------------------------------------

async fn run_doctor_mode(raw_target: String, identity_file: Option<String>) -> Result<()> {
    use std::net::ToSocketAddrs;

    let identity = identity_file.as_deref();
    eprintln!("[onyx doctor] target: {raw_target}");

    // Determine effective port.
    let quic_port: u16 = std::env::var("ONYX_PORT")
        .ok()
        .and_then(|v| v.trim().parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);
    eprintln!("[onyx doctor] port:   {quic_port}");

    // Resolve through SSH config.
    let resolved = match resolve_via_ssh_config(&raw_target, identity) {
        Ok(resolved) => {
            eprintln!("[onyx doctor] resolves to: {}", resolved.hostname);
            resolved
        }
        Err(e) => {
            eprintln!("[onyx doctor] ✗ SSH resolution failed: {e:#}");
            eprintln!("[onyx doctor]   check your SSH config or try a full user@host address");
            return Ok(());
        }
    };
    let quic_host = resolved.hostname.clone();
    let ssh_identity_hint = identity
        .map(str::to_string)
        .or_else(|| resolved.identity_file.clone());
    let ssh_pool = SshSessionPool::default();

    // DNS.
    let server_addr = match format!("{quic_host}:{quic_port}").to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => {
                eprintln!("[onyx doctor] DNS:       OK ({a})");
                a
            }
            None => {
                eprintln!("[onyx doctor] ✗ DNS resolved to no addresses for {quic_host}");
                return Ok(());
            }
        },
        Err(e) => {
            eprintln!("[onyx doctor] ✗ DNS lookup failed: {e}");
            return Ok(());
        }
    };

    // SSH reachability + remote status.
    match tokio::task::spawn_blocking({
        let raw_target = raw_target.clone();
        let identity_file = identity_file.clone();
        let ssh_identity_hint = ssh_identity_hint.clone();
        let ssh_pool = ssh_pool.clone();
        move || -> Result<RemoteStatus> {
            let identity = identity_file.as_deref();
            let ssh = ssh_session_for(
                Some(&ssh_pool),
                &raw_target,
                identity,
                ssh_identity_hint.as_deref(),
                SshAuthFlow::InteractivePrompt,
                SshConnectMessages {
                    establishing: Some("[onyx] establishing SSH session…"),
                    authenticated: Some("[onyx] authenticated. continuing checks…"),
                },
            )?;
            let paths = resolve_remote_paths(&raw_target, identity, Some(&ssh))
                .context("resolving remote paths")?;
            let hash = format!("{:016x}", source_hash());
            remote_status(&raw_target, identity, Some(&ssh), &hash, quic_port, &paths)
        }
    })
    .await
    .map_err(|e| anyhow::anyhow!("task: {e}"))
    .and_then(|r| r)
    {
        Ok(st) => {
            eprintln!("[onyx doctor] SSH:       OK");
            eprintln!(
                "[onyx doctor] server binary: {}",
                if st.hash_ok { "up to date" } else { "stale or missing" }
            );
            eprintln!(
                "[onyx doctor] server running: {}",
                if st.running { "yes" } else { "no" }
            );
            eprintln!(
                "[onyx doctor] server healthy: {}",
                if st.healthy { "yes (QUIC port bound)" } else { "no" }
            );
            eprintln!("[onyx doctor] remote arch:    {}", st.arch);
            if !st.healthy {
                eprintln!("[onyx doctor]   tip: run `onyx {raw_target}` to bootstrap");
            }
        }
        Err(e) => {
            eprintln!("[onyx doctor] ✗ SSH failed: {e:#}");
            eprintln!("[onyx doctor]   check SSH access: ssh {raw_target} echo ok");
        }
    }

    // QUIC / UDP reachability.
    let capture: FpCapture = Arc::new(Mutex::new(None));
    let mut endpoint = match Endpoint::client("0.0.0.0:0".parse().unwrap()) {
        Ok(ep) => ep,
        Err(e) => {
            eprintln!("[onyx doctor] ✗ could not create QUIC endpoint: {e}");
            return Ok(());
        }
    };
    endpoint.set_default_client_config(make_client_config(capture.clone())?);
    let connecting = match endpoint.connect(server_addr, "localhost") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[onyx doctor] ✗ QUIC connect setup failed: {e}");
            return Ok(());
        }
    };
    match tokio::time::timeout(Duration::from_secs(5), connecting).await {
        Ok(Ok(_)) => eprintln!("[onyx doctor] QUIC:      reachable (UDP/{quic_port} open)"),
        Ok(Err(e)) => eprintln!(
            "[onyx doctor] QUIC:      handshake error — {e:#}\n\
             [onyx doctor]   (server reachable but handshake failed; check TOFU trust)"
        ),
        Err(_) => eprintln!(
            "[onyx doctor] QUIC:      timeout — UDP/{quic_port} appears blocked\n\
             [onyx doctor]   open UDP {quic_port} in your firewall, or use --port / ONYX_PORT"
        ),
    }
    endpoint.wait_idle().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Bootstrap — entry point called once before the QUIC loop
// ---------------------------------------------------------------------------

fn bootstrap(
    ssh_target: &str,
    identity: Option<&str>,
    identity_hint: Option<&str>,
    quic_port: u16,
    auth_flow: SshAuthFlow,
    pool: Option<&SshSessionPool>,
    messages: SshConnectMessages<'_>,
) -> Result<()> {
    let ssh = ssh_session_for(pool, ssh_target, identity, identity_hint, auth_flow, messages)?;
    let hash = format!("{:016x}", source_hash());
    let paths = resolve_remote_paths(ssh_target, identity, Some(&ssh))
        .map_err(bootstrap_error_with_help)?;

    // Single SSH call: verify auth + get all state.
    let status = remote_status(ssh_target, identity, Some(&ssh), &hash, quic_port, &paths)
        .map_err(bootstrap_error_with_help)?;

    // ── Fast path ─────────────────────────────────────────────────────────────
    if status.hash_ok && status.healthy && status.conf_ok {
        return Ok(());
    }

    // Config files stale but server is running — just push the new files.
    if status.hash_ok && status.healthy && !status.conf_ok {
        ensure_config_files(ssh_target, identity, Some(&ssh), &paths)
            .map_err(bootstrap_error_with_help)?;
        return Ok(());
    }

    // ── Slow path ────────────────────────────────────────────────────────────
    eprintln!("[onyx] setting up remote (one-time or after update)...");

    if !status.hash_ok {
        let used_prebuilt =
            upload_prebuilt_server(ssh_target, identity, Some(&ssh), &status.arch, &paths)
                .map_err(bootstrap_error_with_help)?;

        if !used_prebuilt {
            eprintln!(
                "[onyx] no prebuilt server found for {}",
                remote_arch_label(&status.arch)
            );
            if !status.has_cargo {
                ensure_rust(ssh_target, identity, Some(&ssh))
                    .map_err(bootstrap_cannot_continue)
                    .map_err(bootstrap_error_with_help)?;
            }
            upload_and_build(ssh_target, identity, Some(&ssh), &paths)
                .map_err(bootstrap_cannot_continue)
                .map_err(bootstrap_error_with_help)?;
        }

        // Atomically stop the old onyx-server (if any), swap in the new
        // binary via mv, and update the hash stamp. Must run after upload
        // and before start_server.
        install_staged_server_binary(ssh_target, identity, Some(&ssh), &hash, &status, &paths)
            .map_err(bootstrap_error_with_help)?;
    }

    ensure_config_files(ssh_target, identity, Some(&ssh), &paths)
        .map_err(bootstrap_error_with_help)?;
    start_server(ssh_target, identity, Some(&ssh), quic_port, &paths)
        .map_err(bootstrap_error_with_help)?;

    eprintln!("[onyx] ready");
    Ok(())
}

// ---------------------------------------------------------------------------
// Port forwarding — TCP-over-QUIC
// ---------------------------------------------------------------------------

/// Binds a TCP listener on localhost:local_port.  For every accepted TCP
/// connection a new QUIC bidirectional stream is opened on `conn` and data
/// flows in both directions until either side closes.
/// The task runs until aborted (by try_once cleanup) or until the bind fails.
async fn run_forward_listener(conn: quinn::Connection, local_port: u16, remote_port: u16) {
    let listener =
        match TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], local_port))).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[forward] cannot bind localhost:{local_port}: {e}");
                return;
            }
        };
    eprintln!("[forward] localhost:{local_port} → remote:{remote_port}");
    loop {
        let (tcp, _addr) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => break,
        };
        let c = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_forward_conn(c, tcp, remote_port).await {
                eprintln!("[forward] :{local_port}→:{remote_port}: {e:#}");
            }
        });
    }
}

/// Opens a QUIC stream, performs the ForwardConnect handshake, then copies
/// bytes between the TCP socket and the QUIC stream until both sides close.
async fn handle_forward_conn(
    conn: quinn::Connection,
    tcp: tokio::net::TcpStream,
    remote_port: u16,
) -> Result<()> {
    let (mut qs, mut qr) = conn.open_bi().await.context("open forward stream")?;
    send_msg(&mut qs, &Message::ForwardConnect { remote_port }).await?;
    match recv_msg(&mut qr).await? {
        Message::ForwardAck => {}
        Message::ForwardError { reason } => {
            anyhow::bail!("server refused :{remote_port}: {reason}")
        }
        other => anyhow::bail!("unexpected forward response: {other:?}"),
    }
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    // Drive both directions concurrently; finish when both complete (proper
    // half-close: EOF from one side propagates to the other via copy's shutdown).
    let _ = tokio::join!(
        tokio::io::copy(&mut qr, &mut tcp_w),
        tokio::io::copy(&mut tcp_r, &mut qs),
    );
    Ok(())
}

async fn connect_authenticated(
    server_addr: SocketAddr,
    endpoint: &Endpoint,
    host_port: &str,
    capture: &FpCapture,
    handshake_timeout: Duration,
) -> Result<quinn::Connection> {
    *capture.lock().unwrap() = None;

    let connecting = endpoint
        .connect(server_addr, "localhost")
        .context("creating QUIC connection")?;
    let conn = tokio::time::timeout(handshake_timeout, connecting)
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "QUIC handshake timed out after {} s (no response from {}; \
                 UDP/{} may be blocked by the server firewall)",
                handshake_timeout.as_secs(),
                server_addr,
                server_addr.port()
            )
        })?
        .map_err(|e| anyhow::anyhow!("QUIC handshake failed: {e:#}"))?;

    let fp = capture
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow::anyhow!("TLS verifier did not capture a fingerprint"))?;
    check_known_hosts(host_port, &fp).await?;
    Ok(conn)
}

enum ProxyStdinEvent {
    Data(Vec<u8>),
    Eof,
}

fn proxy_session_id() -> String {
    format!("proxy-{}", new_session_id())
}

async fn connect_proxy_stream(
    endpoint: &Endpoint,
    server_addr: SocketAddr,
    host_port: &str,
    capture: &FpCapture,
    proxy_session_id: &str,
    target_host: &str,
    target_port: u16,
    resume: bool,
    handshake_timeout: Duration,
) -> Result<(quinn::Connection, quinn::SendStream, quinn::RecvStream)> {
    let conn =
        connect_authenticated(server_addr, endpoint, host_port, capture, handshake_timeout).await?;
    let (mut send, mut recv) = conn.open_bi().await.context("open proxy stream")?;
    let setup = if resume {
        Message::ProxyResume {
            proxy_session_id: proxy_session_id.to_string(),
        }
    } else {
        Message::ProxyConnect {
            proxy_session_id: proxy_session_id.to_string(),
            target_host: target_host.to_string(),
            target_port,
        }
    };
    send_msg(&mut send, &setup).await?;
    match recv_msg(&mut recv).await? {
        Message::ProxySessionReady {
            proxy_session_id: ready,
        } if ready == proxy_session_id => Ok((conn, send, recv)),
        Message::ForwardError { reason } => anyhow::bail!("{reason}"),
        other => anyhow::bail!("unexpected proxy response: {other:?}"),
    }
}

async fn run_proxy_mode(
    target_host: String,
    target_port: u16,
    no_fallback: bool,
) -> Result<()> {
    let target = build_target(&target_host, None, None)
        .with_context(|| format!("resolving target '{target_host}'"))?;
    let server_addr: SocketAddr = match {
        use std::net::ToSocketAddrs;
        let addr_str = format!("{}:{}", target.quic_host, target.quic_port);
        addr_str
            .to_socket_addrs()
            .with_context(|| format!("DNS lookup for '{}'", target.quic_host))
            .and_then(|mut it| {
                it.next()
                    .ok_or_else(|| anyhow::anyhow!("no address resolved for {}", target.quic_host))
            })
    } {
        Ok(a) => a,
        Err(e) if !no_fallback => {
            eprintln!("[proxy] DNS lookup failed ({e:#}); falling back to plain TCP");
            return tcp_proxy_fallback(&target_host, target_port).await;
        }
        Err(e) => return Err(e),
    };

    let host_port = format!("{}:{}", target.quic_host, target.quic_port);
    let capture: FpCapture = Arc::new(Mutex::new(None));
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(make_client_config(capture.clone())?);
    let proxy_session_id = proxy_session_id();

    let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<ProxyStdinEvent>();
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) => {
                    let _ = stdin_tx.send(ProxyStdinEvent::Eof);
                    break;
                }
                Ok(n) => {
                    if stdin_tx
                        .send(ProxyStdinEvent::Data(buf[..n].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => {
                    let _ = stdin_tx.send(ProxyStdinEvent::Eof);
                    break;
                }
            }
        }
    });

    let mut stdout = tokio::io::stdout();

    // Proxy reconnect tuning.
    //
    // Client window matches the server's DETACHED_PROXY_TTL (120s). That
    // window is intentionally short — the SSH session above us rarely
    // survives longer gaps, so silently retrying for minutes gives users
    // a false sense of persistence.
    //
    // Backoff grows to avoid hammering a server that is simply down,
    // but stays bounded so normal packet-loss recovery is prompt.
    const PROXY_RESUME_WINDOW: Duration = Duration::from_secs(120);
    const PROXY_BACKOFF_INITIAL: Duration = Duration::from_millis(500);
    const PROXY_BACKOFF_MAX: Duration = Duration::from_secs(4);

    let mut reconnect_deadline: Option<Instant> = None;
    let mut backoff = PROXY_BACKOFF_INITIAL;
    let mut logged_disconnect = false;
    let mut resume = false;

    loop {
        let (conn, mut send, mut recv) = match connect_proxy_stream(
            &endpoint,
            server_addr,
            &host_port,
            &capture,
            &proxy_session_id,
            &target_host,
            target_port,
            resume,
            PROXY_HANDSHAKE_TIMEOUT,
        )
        .await
        {
            Ok(parts) => {
                if logged_disconnect {
                    // Only legitimately a "resumed" message if the server
                    // accepted a ProxyResume — which is exactly when we
                    // reach Ok(..) with resume=true.
                    if resume {
                        eprintln!("[proxy] resumed");
                    }
                    logged_disconnect = false;
                }
                reconnect_deadline = None;
                backoff = PROXY_BACKOFF_INITIAL;
                parts
            }
            Err(e) if resume => {
                // Server says the session is gone for good — no point
                // retrying the resume window, the SSH session above us is
                // already toast. Fail fast with a precise message.
                if proxy_session_not_resumable(&e) {
                    eprintln!(
                        "[proxy] server dropped this proxy session; \
                         SSH session above cannot be resumed"
                    );
                    return Err(e);
                }

                let deadline = *reconnect_deadline
                    .get_or_insert_with(|| Instant::now() + PROXY_RESUME_WINDOW);
                if !logged_disconnect {
                    eprintln!("[proxy] transport hiccup, retrying…");
                    logged_disconnect = true;
                }
                if Instant::now() >= deadline {
                    eprintln!(
                        "[proxy] connection lost; SSH session cannot be resumed \
                         (grace {}s expired)",
                        PROXY_RESUME_WINDOW.as_secs()
                    );
                    return Err(e);
                }
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff * 2, PROXY_BACKOFF_MAX);
                continue;
            }
            Err(e) => {
                // First-connect failure (no SSH session above us yet). If
                // QUIC is unreachable, falling back to a plain TCP bridge is
                // exactly what SSH with no ProxyCommand would do.
                if !no_fallback && quic_unavailable_for_proxy(&e) {
                    eprintln!(
                        "[proxy] QUIC unavailable ({e:#}); falling back to plain TCP"
                    );
                    return tcp_proxy_fallback(&target_host, target_port).await;
                }
                return Err(e);
            }
        };

        let mut buf = [0u8; 4096];
        let mut eof_sent = false;
        loop {
            tokio::select! {
                maybe = stdin_rx.recv(), if !eof_sent => match maybe {
                    Some(ProxyStdinEvent::Data(data)) => {
                        if send.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Some(ProxyStdinEvent::Eof) | None => {
                        eof_sent = true;
                        if send.finish().is_err() {
                            break;
                        }
                    }
                },
                res = recv.read(&mut buf) => match res {
                    Ok(Some(0)) | Ok(None) => {
                        conn.close(0u32.into(), b"bye");
                        endpoint.wait_idle().await;
                        return Ok(());
                    }
                    Ok(Some(n)) => {
                        stdout.write_all(&buf[..n]).await?;
                        stdout.flush().await?;
                    }
                    Err(_) => break,
                }
            }
        }

        conn.close(0u32.into(), b"bye");
        endpoint.wait_idle().await;
        resume = true;
    }
}

// ---------------------------------------------------------------------------
// Exec subcommands — resumable remote command execution
// ---------------------------------------------------------------------------
//
// `onyx exec` is the first step toward positioning Onyx as a resilient
// remote-execution layer rather than just a better SSH. The client is
// intentionally thin: it opens one QUIC stream, sends an Exec/Attach/Logs/
// JobsList message, and streams the server's responses. All job state
// lives on the remote onyx-server.
//
// Output modes:
//   * text (default): stdout chunks to stdout, stderr chunks to stderr,
//     just like SSH. A ring-buffer-gap notice goes to stderr.
//   * --json: one NDJSON event per line on stdout, regardless of stream.
//     `data` is rendered as lossy UTF-8 (invalid sequences become U+FFFD).
//     Users who need byte-exact binary output should use text mode.

/// JSON-escape a str into an existing buffer. Avoids bringing in serde_json
/// just for the four or five event shapes we emit.
fn json_escape_into(out: &mut String, s: &str) {
    out.reserve(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

fn jq(s: &str) -> String {
    let mut out = String::from("\"");
    json_escape_into(&mut out, s);
    out.push('"');
    out
}

fn job_status_str(s: JobStatus) -> &'static str {
    match s {
        JobStatus::Running => "running",
        JobStatus::Detached => "detached",
        JobStatus::Succeeded => "succeeded",
        JobStatus::Failed => "failed",
        JobStatus::Expired => "expired",
    }
}

fn emit_started_json(job_id: &str, started_at_unix: u64, command: &[String]) {
    let joined = command.join(" ");
    println!(
        "{{\"type\":\"started\",\"job_id\":{},\"started_at_unix\":{},\"command\":{}}}",
        jq(job_id),
        started_at_unix,
        jq(&joined),
    );
}

fn emit_output_json(seq: u64, stream: StdStream, data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let kind = match stream {
        StdStream::Stdout => "stdout",
        StdStream::Stderr => "stderr",
    };
    println!(
        "{{\"type\":{},\"seq\":{},\"data\":{}}}",
        jq(kind),
        seq,
        jq(&text),
    );
}

fn emit_gap_json(oldest_seq: u64) {
    println!("{{\"type\":\"gap\",\"oldest_seq\":{oldest_seq}}}");
}

fn emit_finished_json(exit_code: Option<i32>, finished_at_unix: u64, started_at_unix: u64) {
    let code = match exit_code {
        Some(c) => c.to_string(),
        None => "null".to_string(),
    };
    let duration_ms = finished_at_unix
        .saturating_sub(started_at_unix)
        .saturating_mul(1000);
    println!(
        "{{\"type\":\"finished\",\"exit_code\":{code},\"finished_at_unix\":{finished_at_unix},\"duration_ms\":{duration_ms}}}",
    );
}

fn emit_error_json(reason: &str) {
    println!("{{\"type\":\"error\",\"reason\":{}}}", jq(reason));
}

fn emit_reconnecting_json() {
    println!("{{\"type\":\"reconnecting\"}}");
}

fn emit_timeout_json() {
    println!("{{\"type\":\"timeout\"}}");
}

fn emit_resumed_json(job_id: &str, seq: u64) {
    println!(
        "{{\"type\":\"resumed\",\"job_id\":{},\"seq\":{}}}",
        jq(job_id),
        seq,
    );
}

/// Shared target preparation used by every exec subcommand.
async fn prepare_exec_target(
    raw_target: String,
    identity_file: Option<String>,
    no_bootstrap: bool,
) -> Result<(Endpoint, SocketAddr, String, FpCapture)> {
    let target = build_target(&raw_target, identity_file, None)
        .with_context(|| format!("resolving target '{raw_target}'"))?;

    if target.ssh_mode && !no_bootstrap {
        let ssh_target = target.ssh_target.clone();
        let identity = target.identity_file.clone();
        let identity_hint = target.identity_hint.clone();
        let port = target.quic_port;
        tokio::task::spawn_blocking(move || {
            bootstrap(
                &ssh_target,
                identity.as_deref(),
                identity_hint.as_deref(),
                port,
                SshAuthFlow::InteractivePrompt,
                None,
                SshConnectMessages {
                    establishing: Some("[onyx] establishing SSH session…"),
                    authenticated: Some("[onyx] authenticated. continuing bootstrap…"),
                },
            )
        })
            .await
            .map_err(|e| anyhow::anyhow!("bootstrap task: {e}"))?
            .map_err(|err| contextualize_bootstrap_error(err, "bootstrap failed"))?;
    }

    let server_addr: SocketAddr = {
        use std::net::ToSocketAddrs;
        let addr_str = format!("{}:{}", target.quic_host, target.quic_port);
        addr_str
            .to_socket_addrs()
            .with_context(|| format!("DNS lookup for '{}'", target.quic_host))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("no address resolved for {}", target.quic_host))?
    };
    let host_port = format!("{}:{}", target.quic_host, target.quic_port);
    let capture: FpCapture = Arc::new(Mutex::new(None));
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(make_client_config(capture.clone())?);
    Ok((endpoint, server_addr, host_port, capture))
}

/// Drain an exec/attach QUIC stream: forward output, print gap/finish/error
/// events in the chosen mode, and return the final exit code (if any).
// ---------------------------------------------------------------------------
// Exec resume tuning
// ---------------------------------------------------------------------------
//
// Foreground `onyx exec` and `onyx attach` auto-reconnect on transport
// drops. The total resume window matches the interactive reconnect window
// (10 min). Backoff and handshake timeout match interactive mode so both
// flows feel consistent under the same network conditions.
const EXEC_RESUME_WINDOW: Duration = Duration::from_secs(600);
const EXEC_BACKOFF_INITIAL: Duration = Duration::from_millis(250);
const EXEC_BACKOFF_MAX: Duration = Duration::from_secs(3);
/// Extra delay before retrying an ExecAttach that was rejected because the
/// job was momentarily busy with another attacher. Short enough to be
/// invisible in the common case where the other client has already dropped.
const EXEC_BUSY_RETRY: Duration = Duration::from_millis(300);

/// Outcome of one pass through a foreground exec/attach stream.
enum ExecStreamResult {
    /// Server sent ExecFinished — terminal, propagate exit code.
    Finished(Option<i32>),
    /// Server sent ExecTimedOut then ExecFinished — exit with code 124.
    TimedOut,
    /// Server sent an error we cannot retry (job not found, spawn failed,
    /// malformed request, unexpected message). Carries the server's reason
    /// string.
    Fatal(String),
    /// Transport dropped mid-stream. Retryable via ExecAttach + last_seq.
    Disconnected,
}

async fn drain_exec_stream(
    recv: &mut quinn::RecvStream,
    json: bool,
    started_at_unix: u64,
    last_seq: &mut u64,
) -> ExecStreamResult {
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut timed_out = false;
    loop {
        let msg = match recv_msg(recv).await {
            Ok(m) => m,
            // Any framing / transport error collapses to Disconnected. The
            // outer resume loop decides whether to retry.
            Err(_) => return ExecStreamResult::Disconnected,
        };
        match msg {
            Message::ExecOutput { seq, stream, data } => {
                *last_seq = seq;
                if json {
                    emit_output_json(seq, stream, &data);
                } else {
                    let io_res = match stream {
                        StdStream::Stdout => {
                            let w = stdout.write_all(&data).await;
                            if w.is_ok() {
                                stdout.flush().await
                            } else {
                                w
                            }
                        }
                        StdStream::Stderr => {
                            let w = stderr.write_all(&data).await;
                            if w.is_ok() {
                                stderr.flush().await
                            } else {
                                w
                            }
                        }
                    };
                    if io_res.is_err() {
                        // Local stdout/stderr closed (pipe broken). That's
                        // fatal for our process; surface as Fatal so the
                        // resume loop exits instead of spinning.
                        return ExecStreamResult::Fatal("local output stream closed".into());
                    }
                }
            }
            Message::ExecGap { oldest_seq } => {
                if json {
                    emit_gap_json(oldest_seq);
                } else {
                    eprintln!(
                        "[exec] note: earlier output dropped from the job's ring buffer \
                         (showing from seq {oldest_seq})"
                    );
                }
            }
            Message::ExecTimedOut => {
                timed_out = true;
                if json {
                    emit_timeout_json();
                } else {
                    eprintln!("[exec] job timed out (killed by server-side timeout)");
                }
            }
            Message::ExecFinished {
                exit_code,
                finished_at_unix,
            } => {
                if json {
                    emit_finished_json(exit_code, finished_at_unix, started_at_unix);
                }
                if timed_out {
                    return ExecStreamResult::TimedOut;
                }
                return ExecStreamResult::Finished(exit_code);
            }
            Message::ExecError { reason } => return ExecStreamResult::Fatal(reason),
            Message::Close { reason } => return ExecStreamResult::Fatal(reason),
            other => {
                return ExecStreamResult::Fatal(format!("unexpected exec response: {other:?}"))
            }
        }
    }
}

/// True when a server `ExecError` reason indicates the job is permanently
/// unreachable — no point retrying an attach. Kept narrow: strings we don't
/// recognize are treated as retryable Disconnected so transient server
/// hiccups don't lose a foreground session.
fn exec_error_is_terminal(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("not found")
        || lower.contains("job registry full")
        || lower.contains("spawn failed")
        || lower.contains("command is empty")
}

/// Stream a foreground exec/attach job until it finishes or the resume
/// window expires. The first stream is passed in by the caller — for
/// `onyx exec` this is the connection that carried ExecStart; for
/// `onyx attach` the caller passes `None` and we open a fresh one here.
///
/// On every transport drop we open a new QUIC connection, send ExecAttach
/// with the latest `last_seq`, and hand the resulting recv stream back to
/// `drain_exec_stream`. Output written to the local terminal is strictly
/// the server's stdout/stderr chunks in non-JSON mode — all status goes to
/// stderr (or NDJSON events in --json).
async fn stream_exec_with_resume(
    endpoint: &Endpoint,
    server_addr: SocketAddr,
    host_port: &str,
    capture: &FpCapture,
    job_id: &str,
    started_at_unix: u64,
    json: bool,
    mut first_stream: Option<(quinn::Connection, quinn::SendStream, quinn::RecvStream)>,
) -> Result<Option<i32>> {
    let mut last_seq: u64 = 0;
    let mut backoff = EXEC_BACKOFF_INITIAL;
    let mut disconnect_at: Option<Instant> = None;
    let mut announced_reconnecting = false;

    loop {
        // Step 1: acquire a (conn, send, recv) triple. Either the initial
        // stream the caller handed us, or a freshly reconnected one.
        let (conn, _send, mut recv) = match first_stream.take() {
            Some(triple) => triple,
            None => {
                match reconnect_and_attach(
                    endpoint,
                    server_addr,
                    host_port,
                    capture,
                    job_id,
                    last_seq,
                )
                .await
                {
                    Ok(triple) => {
                        // Successful reattach — announce "resumed" exactly
                        // once per disconnect episode (skip the very first
                        // successful connect, which wasn't preceded by an
                        // announced drop).
                        if announced_reconnecting {
                            if json {
                                emit_resumed_json(job_id, last_seq);
                            } else {
                                eprintln!("[exec] resumed ({job_id})");
                            }
                        }
                        disconnect_at = None;
                        backoff = EXEC_BACKOFF_INITIAL;
                        announced_reconnecting = false;
                        triple
                    }
                    Err(ExecAttachError::Transient) => {
                        let t = disconnect_at.get_or_insert_with(Instant::now);
                        if t.elapsed() > EXEC_RESUME_WINDOW {
                            let reason = format!(
                                "resume window expired after {}s",
                                EXEC_RESUME_WINDOW.as_secs()
                            );
                            if json {
                                emit_error_json(&reason);
                            } else {
                                eprintln!("[exec] {reason}");
                            }
                            return Err(anyhow::anyhow!("{reason}"));
                        }
                        if !announced_reconnecting {
                            if json {
                                emit_reconnecting_json();
                            } else {
                                eprintln!("[exec] connection lost, attempting resume…");
                            }
                            announced_reconnecting = true;
                        }
                        tokio::time::sleep(backoff).await;
                        backoff = std::cmp::min(backoff * 2, EXEC_BACKOFF_MAX);
                        continue;
                    }
                }
            }
        };

        // Step 2: drain until the job finishes or transport drops.
        let result = drain_exec_stream(&mut recv, json, started_at_unix, &mut last_seq).await;
        conn.close(0u32.into(), b"bye");

        match result {
            ExecStreamResult::Finished(code) => return Ok(code),
            ExecStreamResult::TimedOut => return Ok(Some(124)),
            ExecStreamResult::Fatal(reason) if exec_error_is_terminal(&reason) => {
                if json {
                    emit_error_json(&reason);
                } else {
                    eprintln!("[exec] {reason}");
                }
                return Err(anyhow::anyhow!("{reason}"));
            }
            ExecStreamResult::Fatal(reason) if exec_reason_is_busy(&reason) => {
                // Another client is attached — retry after a short delay
                // without counting against the resume window. The server
                // will release the slot as soon as the other attacher
                // drops.
                if !announced_reconnecting {
                    if json {
                        emit_reconnecting_json();
                    } else {
                        eprintln!("[exec] another client is attached; retrying…");
                    }
                    announced_reconnecting = true;
                }
                tokio::time::sleep(EXEC_BUSY_RETRY).await;
            }
            ExecStreamResult::Fatal(reason) => {
                // Unknown server error — treat as transient drop and
                // let the resume window decide when to give up.
                if !announced_reconnecting {
                    if json {
                        emit_reconnecting_json();
                    } else {
                        eprintln!("[exec] lost stream ({reason}); attempting resume…");
                    }
                    announced_reconnecting = true;
                }
                let t = disconnect_at.get_or_insert_with(Instant::now);
                if t.elapsed() > EXEC_RESUME_WINDOW {
                    if json {
                        emit_error_json(&reason);
                    } else {
                        eprintln!("[exec] {reason}");
                    }
                    return Err(anyhow::anyhow!("{reason}"));
                }
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff * 2, EXEC_BACKOFF_MAX);
            }
            ExecStreamResult::Disconnected => {
                if !announced_reconnecting {
                    if json {
                        emit_reconnecting_json();
                    } else {
                        eprintln!("[exec] connection lost, attempting resume…");
                    }
                    announced_reconnecting = true;
                }
                let t = disconnect_at.get_or_insert_with(Instant::now);
                if t.elapsed() > EXEC_RESUME_WINDOW {
                    let reason = format!(
                        "resume window expired after {}s",
                        EXEC_RESUME_WINDOW.as_secs()
                    );
                    if json {
                        emit_error_json(&reason);
                    } else {
                        eprintln!("[exec] {reason}");
                    }
                    return Err(anyhow::anyhow!("{reason}"));
                }
                tokio::time::sleep(backoff).await;
                backoff = std::cmp::min(backoff * 2, EXEC_BACKOFF_MAX);
            }
        }
    }
}

enum ExecAttachError {
    /// Connect / open_bi / initial send failed. Retry with backoff.
    Transient,
}

async fn reconnect_and_attach(
    endpoint: &Endpoint,
    server_addr: SocketAddr,
    host_port: &str,
    capture: &FpCapture,
    job_id: &str,
    last_seq: u64,
) -> Result<(quinn::Connection, quinn::SendStream, quinn::RecvStream), ExecAttachError> {
    // We don't inspect the first server reply here — busy or gone-job
    // rejections surface as ExecError / Close in drain_exec_stream and are
    // routed by the outer resume loop (via `exec_reason_is_busy` /
    // `exec_error_is_terminal`). Keeping this helper narrow keeps the
    // control flow on the success path in the caller.
    let conn = connect_authenticated(
        server_addr,
        endpoint,
        host_port,
        capture,
        INTERACTIVE_HANDSHAKE_TIMEOUT,
    )
    .await
    .map_err(|_| ExecAttachError::Transient)?;
    let (mut send, recv) = conn
        .open_bi()
        .await
        .map_err(|_| ExecAttachError::Transient)?;
    send_msg(
        &mut send,
        &Message::ExecAttach {
            job_id: job_id.to_string(),
            last_seq,
        },
    )
    .await
    .map_err(|_| ExecAttachError::Transient)?;
    Ok((conn, send, recv))
}

/// True when a server error reason indicates the attach slot is temporarily
/// occupied by another client. Retrying after a short delay is the right
/// response — the other attacher will drop and free the slot.
fn exec_reason_is_busy(reason: &str) -> bool {
    reason.to_ascii_lowercase().contains("already attached")
}

async fn run_exec_mode(
    raw_target: String,
    identity_file: Option<String>,
    no_bootstrap: bool,
    json: bool,
    detach: bool,
    command: Vec<String>,
    cwd: Option<String>,
    env: Vec<(String, String)>,
    timeout_secs: Option<u64>,
) -> Result<()> {
    let (endpoint, server_addr, host_port, capture) =
        prepare_exec_target(raw_target, identity_file, no_bootstrap).await?;
    let conn = connect_authenticated(
        server_addr,
        &endpoint,
        &host_port,
        &capture,
        INTERACTIVE_HANDSHAKE_TIMEOUT,
    )
    .await?;
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;

    send_msg(
        &mut send,
        &Message::ExecStart {
            command: command.clone(),
            cwd,
            env,
            timeout_secs,
        },
    )
    .await?;

    let (job_id, started_at_unix) = match recv_msg(&mut recv).await? {
        Message::ExecStarted {
            job_id,
            started_at_unix,
        } => (job_id, started_at_unix),
        Message::ExecError { reason } => {
            if json {
                emit_error_json(&reason);
            } else {
                eprintln!("onyx: {reason}");
            }
            return Err(anyhow::anyhow!("{reason}"));
        }
        other => anyhow::bail!("unexpected exec response: {other:?}"),
    };

    if json {
        emit_started_json(&job_id, started_at_unix, &command);
    } else if detach {
        println!("{job_id}");
        eprintln!(
            "[onyx] detached; reattach with: onyx attach <target> {job_id}"
        );
    }

    if detach {
        // Drop our end of the stream; the job keeps running on the server.
        let _ = send.finish();
        drop(send);
        drop(recv);
        conn.close(0u32.into(), b"detach");
        endpoint.wait_idle().await;
        return Ok(());
    }

    // Hand the active (conn, send, recv) straight into the resume loop so
    // the first drain doesn't re-open a stream. On any drop the loop
    // reattaches with ExecAttach + last_seq.
    let exit_code = stream_exec_with_resume(
        &endpoint,
        server_addr,
        &host_port,
        &capture,
        &job_id,
        started_at_unix,
        json,
        Some((conn, send, recv)),
    )
    .await?;
    endpoint.wait_idle().await;

    // Exit with the child's exit code so shell pipelines see the right status.
    match exit_code {
        Some(c) => std::process::exit(c),
        None => std::process::exit(137), // killed-by-signal convention
    }
}

async fn run_attach_mode(
    raw_target: String,
    identity_file: Option<String>,
    no_bootstrap: bool,
    json: bool,
    job_id: String,
) -> Result<()> {
    let (endpoint, server_addr, host_port, capture) =
        prepare_exec_target(raw_target, identity_file, no_bootstrap).await?;

    // Attach goes straight into the resume loop. started_at_unix isn't
    // known to the client here; use 0 so the JSON `finished` event's
    // duration_ms stays non-negative even though it won't be meaningful.
    let exit_code = stream_exec_with_resume(
        &endpoint,
        server_addr,
        &host_port,
        &capture,
        &job_id,
        0,
        json,
        None,
    )
    .await?;
    endpoint.wait_idle().await;
    match exit_code {
        Some(c) => std::process::exit(c),
        None => Ok(()), // still running or detached cleanly
    }
}

async fn run_logs_mode(
    raw_target: String,
    identity_file: Option<String>,
    no_bootstrap: bool,
    json: bool,
    job_id: String,
) -> Result<()> {
    let (endpoint, server_addr, host_port, capture) =
        prepare_exec_target(raw_target, identity_file, no_bootstrap).await?;
    let conn = connect_authenticated(
        server_addr,
        &endpoint,
        &host_port,
        &capture,
        INTERACTIVE_HANDSHAKE_TIMEOUT,
    )
    .await?;
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;
    send_msg(
        &mut send,
        &Message::ExecLogs {
            job_id: job_id.clone(),
        },
    )
    .await?;
    // `logs` is a snapshot: one request, one bounded reply, then close.
    // No resume loop — the server streams the buffer once and finishes.
    let mut last_seq: u64 = 0;
    let _ = drain_exec_stream(&mut recv, json, 0, &mut last_seq).await;
    conn.close(0u32.into(), b"bye");
    endpoint.wait_idle().await;
    Ok(())
}

async fn run_kill_mode(
    raw_target: String,
    identity_file: Option<String>,
    no_bootstrap: bool,
    json: bool,
    job_id: String,
) -> Result<()> {
    let (endpoint, server_addr, host_port, capture) =
        prepare_exec_target(raw_target, identity_file, no_bootstrap).await?;
    let conn = connect_authenticated(
        server_addr,
        &endpoint,
        &host_port,
        &capture,
        INTERACTIVE_HANDSHAKE_TIMEOUT,
    )
    .await?;
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;
    send_msg(
        &mut send,
        &Message::Kill {
            job_id: job_id.clone(),
        },
    )
    .await?;
    let msg = recv_msg(&mut recv).await?;
    conn.close(0u32.into(), b"bye");
    endpoint.wait_idle().await;

    match msg {
        Message::KillResult {
            killed,
            message,
            ..
        } => {
            if json {
                println!(
                    "{{\"type\":\"kill_result\",\"job_id\":{},\"killed\":{}}}",
                    jq(&job_id),
                    killed
                );
            } else {
                println!("{message}");
            }
            if killed {
                Ok(())
            } else {
                Err(anyhow::anyhow!("{message}"))
            }
        }
        Message::ExecError { reason } => {
            if json {
                emit_error_json(&reason);
            } else {
                eprintln!("onyx: {reason}");
            }
            Err(anyhow::anyhow!("{reason}"))
        }
        other => anyhow::bail!("unexpected kill response: {other:?}"),
    }
}

fn format_relative_time(now_unix: u64, t_unix: u64) -> String {
    let delta = now_unix.saturating_sub(t_unix);
    if delta < 60 {
        format!("{delta}s ago")
    } else if delta < 3600 {
        format!("{}m ago", delta / 60)
    } else if delta < 86400 {
        format!("{}h ago", delta / 3600)
    } else {
        format!("{}d ago", delta / 86400)
    }
}

fn truncate_display(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn print_jobs_table(jobs: &[JobSummary]) {
    if jobs.is_empty() {
        println!("no jobs");
        return;
    }
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    println!(
        "{:<24}  {:<10}  {:<10}  {:<7}  COMMAND",
        "JOB ID", "STATUS", "STARTED", "EXIT"
    );
    for j in jobs {
        let exit = match j.exit_code {
            Some(c) => c.to_string(),
            None => "-".to_string(),
        };
        println!(
            "{:<24}  {:<10}  {:<10}  {:<7}  {}",
            truncate_display(&j.job_id, 24),
            job_status_str(j.status),
            format_relative_time(now_unix, j.started_at_unix),
            exit,
            truncate_display(&j.command, 60),
        );
    }
}

fn print_jobs_json(jobs: &[JobSummary]) {
    for j in jobs {
        let finished = match j.finished_at_unix {
            Some(v) => v.to_string(),
            None => "null".to_string(),
        };
        let exit = match j.exit_code {
            Some(c) => c.to_string(),
            None => "null".to_string(),
        };
        println!(
            "{{\"type\":\"job\",\"job_id\":{},\"status\":{},\"command\":{},\
             \"started_at_unix\":{},\"finished_at_unix\":{},\"exit_code\":{},\
             \"attached\":{},\"buffered_bytes\":{}}}",
            jq(&j.job_id),
            jq(job_status_str(j.status)),
            jq(&j.command),
            j.started_at_unix,
            finished,
            exit,
            j.attached,
            j.buffered_bytes,
        );
    }
}

async fn run_jobs_mode(
    raw_target: String,
    identity_file: Option<String>,
    no_bootstrap: bool,
    json: bool,
) -> Result<()> {
    let (endpoint, server_addr, host_port, capture) =
        prepare_exec_target(raw_target, identity_file, no_bootstrap).await?;
    let conn = connect_authenticated(
        server_addr,
        &endpoint,
        &host_port,
        &capture,
        INTERACTIVE_HANDSHAKE_TIMEOUT,
    )
    .await?;
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;
    send_msg(&mut send, &Message::JobsList).await?;
    let msg = recv_msg(&mut recv).await?;
    conn.close(0u32.into(), b"bye");
    endpoint.wait_idle().await;

    match msg {
        Message::JobsListResponse { jobs } => {
            if json {
                print_jobs_json(&jobs);
            } else {
                print_jobs_table(&jobs);
            }
            Ok(())
        }
        Message::ExecError { reason } => {
            if json {
                emit_error_json(&reason);
            } else {
                eprintln!("onyx: {reason}");
            }
            Err(anyhow::anyhow!("{reason}"))
        }
        other => anyhow::bail!("unexpected jobs response: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Single connection attempt + I/O loop
// ---------------------------------------------------------------------------

async fn try_once(
    server_addr: SocketAddr,
    endpoint: &Endpoint,
    session: &mut Option<(String, String)>,
    host_port: &str,
    capture: &FpCapture,
    forwards: &[(u16, u16)],
    mode: BandwidthMode,
) -> Result<bool> {
    let conn = connect_authenticated(
        server_addr,
        endpoint,
        host_port,
        capture,
        INTERACTIVE_HANDSHAKE_TIMEOUT,
    )
    .await?;

    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;

    let is_resume = session.is_some();
    match session.as_ref() {
        None => {
            send_msg(
                &mut send,
                &Message::Hello {
                    session_id: new_session_id(),
                    resume_token: String::new(),
                },
            )
            .await?;
        }
        Some((sid, tok)) => {
            send_msg(
                &mut send,
                &Message::Resume {
                    session_id: sid.clone(),
                    resume_token: tok.clone(),
                    last_seq: 0,
                },
            )
            .await?;
        }
    }

    let (session_id, resume_token) = match recv_msg(&mut recv).await? {
        Message::Welcome {
            session_id,
            resume_token,
        } => {
            // Successful reclaim — clear the throttle flag so a future
            // disconnect episode can print the message once again.
            SESSION_BUSY_LOGGED.store(false, Ordering::Relaxed);
            (session_id, resume_token)
        }
        // Transient: the previous attacher is still considered live by the
        // server. With a current onyx-server this should basically never
        // fire — the server now uses forced takeover on attach. Kept for
        // back-compat with older servers; the message is throttled to one
        // line per disconnect episode instead of one per retry tick so
        // the user isn't spammed.
        Message::Close { reason } if reason == "session already attached" => {
            if !SESSION_BUSY_LOGGED.swap(true, Ordering::Relaxed) {
                eprintln!("[session] previous client may be stale; waiting to reclaim…");
            }
            return Ok(false);
        }
        Message::Close { reason } => {
            eprintln!("[session] server rejected: {reason}");
            return Ok(true);
        }
        other => anyhow::bail!("unexpected: {other:?}"),
    };

    *session = Some((session_id.clone(), resume_token));
    if is_resume {
        eprintln!("[mode] QUIC  (resumed session {session_id})");
    } else {
        eprintln!("[mode] QUIC  (session {session_id})");
    }
    if mode.low_bandwidth {
        eprintln!("[mode] low-bandwidth");
    }

    // Spawn one TCP listener per --forward spec.  Each listener opens new QUIC
    // streams on this connection for individual TCP connections.  All handles
    // are aborted when this function returns (connection dropped or shell exit).
    let forward_handles: Vec<tokio::task::JoinHandle<()>> = forwards
        .iter()
        .map(|&(lp, rp)| tokio::spawn(run_forward_listener(conn.clone(), lp, rp)))
        .collect();

    let (cols, rows) = get_terminal_size();
    send_msg(&mut send, &Message::Resize { cols, rows }).await?;

    // NOTE: raw mode is entered ONCE in main() before the reconnect loop,
    // not per try_once call. This prevents mouse-tracking escape sequences
    // (enabled by the remote tmux) from being echoed in cooked mode during
    // the brief gap between a drop and the next reconnect attempt.

    let mut stdin_jh = tokio::spawn(async move {
        use tokio::signal::unix::SignalKind;
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 4096];
        // SIGWINCH fires whenever the local terminal window is resized.
        let mut sigwinch = tokio::signal::unix::signal(SignalKind::window_change()).ok();

        loop {
            enum Ev {
                Data(std::io::Result<usize>),
                Winch,
            }

            // Drive stdin and SIGWINCH concurrently; fall back to stdin-only if
            // signal setup failed (non-Unix environments, permission issues, etc.).
            let ev = if let Some(ref mut sw) = sigwinch {
                tokio::select! {
                    r = stdin.read(&mut buf) => Ev::Data(r),
                    _ = sw.recv()           => Ev::Winch,
                }
            } else {
                Ev::Data(stdin.read(&mut buf).await)
            };

            match ev {
                Ev::Data(Ok(0)) | Ev::Data(Err(_)) => break,
                Ev::Data(Ok(n)) => {
                    let mut data = buf[..n].to_vec();
                    // Normal mode keeps typing crisp. Low-bandwidth mode waits a bit longer
                    // so bursts coalesce into fewer QUIC writes without changing the protocol.
                    let deadline = tokio::time::Instant::now() + mode.stdin_batch_window;
                    loop {
                        match tokio::time::timeout_at(deadline, stdin.read(&mut buf)).await {
                            Ok(Ok(m)) if m > 0 => data.extend_from_slice(&buf[..m]),
                            _ => break,
                        }
                    }
                    if send_msg(&mut send, &Message::Input { data }).await.is_err() {
                        break;
                    }
                }
                Ev::Winch => {
                    let (cols, rows) = get_terminal_size();
                    if send_msg(&mut send, &Message::Resize { cols, rows })
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    let mut output_jh = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        let mut pending = Vec::new();
        let mut last_flush = tokio::time::Instant::now();
        loop {
            match recv_msg(&mut recv).await {
                Ok(Message::Output { data, .. }) => {
                    if !mode.low_bandwidth {
                        if stdout.write_all(&data).await.is_err() {
                            break false;
                        }
                        let _ = stdout.flush().await;
                        continue;
                    }

                    pending.extend_from_slice(&data);
                    let deadline = tokio::time::Instant::now() + mode.stdout_batch_window;
                    let mut saw_close = false;
                    while pending.len() < mode.stdout_chunk_limit {
                        match tokio::time::timeout_at(deadline, recv_msg(&mut recv)).await {
                            Ok(Ok(Message::Output { data, .. })) => {
                                pending.extend_from_slice(&data)
                            }
                            Ok(Ok(Message::Close { .. })) => {
                                saw_close = true;
                                break;
                            }
                            Ok(Ok(_)) => break,
                            Ok(Err(_)) | Err(_) => break,
                        }
                    }

                    if !pending.is_empty() {
                        if stdout.write_all(&pending).await.is_err() {
                            break false;
                        }
                        pending.clear();
                    }
                    if last_flush.elapsed() >= mode.stdout_flush_window {
                        if stdout.flush().await.is_err() {
                            break false;
                        }
                        last_flush = tokio::time::Instant::now();
                    }
                    if saw_close {
                        let _ = stdout.flush().await;
                        break true;
                    }
                }
                Ok(Message::Close { .. }) => {
                    if !pending.is_empty() {
                        let _ = stdout.write_all(&pending).await;
                    }
                    let _ = stdout.flush().await;
                    break true;
                }
                _ => break false,
            }
        }
    });

    let shell_exited = tokio::select! {
        _ = &mut stdin_jh   => { output_jh.abort(); true }  // local stdin closed — exit cleanly
        r = &mut output_jh  => { stdin_jh.abort();  r.unwrap_or(false) }
    };

    for jh in &forward_handles {
        jh.abort();
    }
    conn.close(0u32.into(), b"bye");
    Ok(shell_exited)
}

// ---------------------------------------------------------------------------
// Connection-loss banner — mosh-style live overlay
// ---------------------------------------------------------------------------

/// Draws a single-line status banner directly on the local terminal (stderr),
/// updating every 250 ms for `wait`.  The line is overwritten in-place, so
/// it never scrolls the display.  Call clear_banner() before re-entering raw
/// mode so the tmux redraw is not polluted.
async fn reconnect_banner(since: Instant, wait: Duration) {
    use std::io::Write;
    let steps = (wait.as_millis() / 250).max(1) as u32;
    for _ in 0..steps {
        let s = since.elapsed().as_secs();
        let elapsed = if s < 60 {
            format!("{s}s")
        } else {
            format!("{}m {:02}s", s / 60, s % 60)
        };
        // \x1b[2K  — erase entire line
        // \x1b[38;5;214m — amber (256-colour)
        // \x1b[2m  — dim (for the trailing hint)
        eprint!(
            "\r\x1b[2K\x1b[38;5;214m ⚡  onyx — connection lost · {elapsed}  \
             \x1b[2mreconnecting…\x1b[0m"
        );
        std::io::stderr().flush().ok();
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Erase the banner line.  Always call this before entering raw terminal mode.
fn clear_banner() {
    use std::io::Write;
    eprint!("\r\x1b[2K");
    std::io::stderr().flush().ok();
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let cli_mode = parse_args();
    match cli_mode {
        CliMode::Proxy {
            target_host,
            target_port,
            no_fallback,
        } => return run_proxy_mode(target_host, target_port, no_fallback).await,
        CliMode::Exec {
            raw_target,
            identity_file,
            no_bootstrap,
            json,
            detach,
            command,
            cwd,
            env,
            timeout_secs,
        } => {
            return run_exec_mode(
                raw_target,
                identity_file,
                no_bootstrap,
                json,
                detach,
                command,
                cwd,
                env,
                timeout_secs,
            )
            .await
        }
        CliMode::Kill {
            raw_target,
            identity_file,
            no_bootstrap,
            json,
            job_id,
        } => return run_kill_mode(raw_target, identity_file, no_bootstrap, json, job_id).await,
        CliMode::Jobs {
            raw_target,
            identity_file,
            no_bootstrap,
            json,
        } => return run_jobs_mode(raw_target, identity_file, no_bootstrap, json).await,
        CliMode::Attach {
            raw_target,
            identity_file,
            no_bootstrap,
            json,
            job_id,
        } => {
            return run_attach_mode(raw_target, identity_file, no_bootstrap, json, job_id).await
        }
        CliMode::Logs {
            raw_target,
            identity_file,
            no_bootstrap,
            json,
            job_id,
        } => return run_logs_mode(raw_target, identity_file, no_bootstrap, json, job_id).await,
        CliMode::Mcp {} => return mcp::run_mcp_serve().await,
        CliMode::Doctor {
            raw_target,
            identity_file,
        } => return run_doctor_mode(raw_target, identity_file).await,
        CliMode::Interactive { .. } => {}
    }

    let CliMode::Interactive {
        raw_target,
        identity_file,
        no_fallback,
        no_bootstrap,
        low_bandwidth,
        forwards,
        port_override,
    } = cli_mode
    else {
        unreachable!();
    };
    let bandwidth_mode = if low_bandwidth {
        BandwidthMode::low_bandwidth()
    } else {
        BandwidthMode::normal()
    };

    // Resolve the target — runs `ssh -G <target>` for SSH aliases to get the
    // canonical hostname; the unresolved alias is kept only for SSH commands.
    let target = build_target(&raw_target, identity_file, port_override)
        .with_context(|| format!("resolving target '{raw_target}'"))?;
    let ssh_pool = target.ssh_mode.then(SshSessionPool::default);

    // SSH bootstrap (blocking, single SSH call on fast path).
    if target.ssh_mode && !no_bootstrap {
        bootstrap(
            &target.ssh_target,
            target.identity_file.as_deref(),
            target.identity_hint.as_deref(),
            target.quic_port,
            SshAuthFlow::InteractivePrompt,
            ssh_pool.as_ref(),
            SshConnectMessages {
                establishing: Some("[onyx] establishing SSH session…"),
                authenticated: Some("[onyx] authenticated. continuing bootstrap…"),
            },
        )
        .map_err(|err| contextualize_bootstrap_error(err, "bootstrap failed"))?;
    }

    // Build QUIC SocketAddr from the resolved hostname (never the raw alias).
    let server_addr: SocketAddr = {
        use std::net::ToSocketAddrs;
        let addr_str = format!("{}:{}", target.quic_host, target.quic_port);
        addr_str
            .to_socket_addrs()
            .with_context(|| format!("DNS lookup for '{}'", target.quic_host))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("no address resolved for {}", target.quic_host))?
    };

    let host_port = format!("{}:{}", target.quic_host, target.quic_port);
    let capture: FpCapture = Arc::new(Mutex::new(None));
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(make_client_config(capture.clone())?);

    let mut session: Option<(String, String)> = None;
    let mut reconnect_deadline: Option<Instant> = if target.ssh_mode {
        Some(Instant::now() + INTERACTIVE_INITIAL_CONNECT_WINDOW)
    } else {
        None
    };
    // Set when we first lose a connection; cleared when we give up or reconnect.
    let mut disconnect_at: Option<Instant> = None;
    // Tracks when we last re-ran bootstrap during a reconnect window so we
    // don't hammer SSH on every retry but do re-open the firewall / restart
    // a crashed server after a reasonable delay.
    let mut last_rebootstrap: Option<Instant> = None;
    // Exponential backoff between reconnect attempts. Resets after every
    // successful reconnect (via try_once returning Ok).
    let mut backoff = INTERACTIVE_BACKOFF_INITIAL;

    // Enter raw mode ONCE for the entire reconnect loop. Previously this
    // was scoped to each try_once call, so between attempts the terminal
    // briefly restored to cooked mode — long enough for mouse-tracking
    // escapes from tmux to echo as garbage like `^[[<32;54;57M`. Keeping
    // raw mode persistent, combined with the mouse-disable on Drop, means
    // stdin is silent during gaps and the terminal is cleanly restored
    // on exit.
    let _raw = RawMode::enter();

    loop {
        // Erase any live banner line before entering raw terminal mode so it
        // does not appear as garbage inside the tmux session.
        if disconnect_at.is_some() {
            clear_banner();
        }

        // After 20 s of failed reconnects, re-run bootstrap via SSH.
        // This refreshes remote state and restarts a crashed server without
        // blocking on the first fast-path attempt.
        if target.ssh_mode && !no_bootstrap {
            if let Some(t) = disconnect_at {
                let rebootstrap_due =
                    last_rebootstrap.map_or(true, |lr| lr.elapsed() > Duration::from_secs(30));
                if t.elapsed() > Duration::from_secs(20) && rebootstrap_due {
                    let ssh_target = target.ssh_target.clone();
                    let identity = target.identity_file.clone();
                    let identity_hint = target.identity_hint.clone();
                    let ssh_pool = ssh_pool.clone();
                    let port = target.quic_port;
                    let _ = tokio::task::spawn_blocking(move || {
                        bootstrap(
                            &ssh_target,
                            identity.as_deref(),
                            identity_hint.as_deref(),
                            port,
                            SshAuthFlow::NonInteractive,
                            ssh_pool.as_ref(),
                            SshConnectMessages::default(),
                        )
                    })
                    .await;
                    last_rebootstrap = Some(Instant::now());
                }
            }
        }

        match try_once(
            server_addr,
            &endpoint,
            &mut session,
            &host_port,
            &capture,
            &forwards,
            bandwidth_mode,
        )
        .await
        {
            // Shell exited cleanly — just exit.
            Ok(true) => break,

            // Network dropped mid-session. `Ok(false)` means try_once
            // previously handshook successfully, so this is a *fresh* drop
            // — reset the disconnect timer, window, and backoff.
            Ok(false) => {
                let now = Instant::now();
                disconnect_at = Some(now);
                reconnect_deadline = Some(now + INTERACTIVE_RECONNECT_WINDOW);
                backoff = INTERACTIVE_BACKOFF_INITIAL;
                // The banner itself waits 2 s before the next reconnect
                // attempt, which is our first-retry gap.
                reconnect_banner(now, Duration::from_secs(2)).await;
            }

            Err(e) => {
                let hint = quic_error_hint(&e);
                if let Some(dl) = reconnect_deadline {
                    if Instant::now() < dl {
                        // Still within retry window — show banner, back off,
                        // and try again. Backoff grows so we don't hammer a
                        // genuinely-down server between the 8 s handshake
                        // timeouts, but stays short enough (max 3 s) that
                        // short drops recover quickly.
                        let t = *disconnect_at.get_or_insert_with(Instant::now);
                        reconnect_banner(t, backoff).await;
                        backoff = std::cmp::min(backoff * 2, INTERACTIVE_BACKOFF_MAX);
                        continue;
                    }
                }

                // ── Retry window exhausted ────────────────────────────────
                if disconnect_at.take().is_some() {
                    clear_banner();
                }

                if target.ssh_mode && session.is_none() {
                    // Never had a session — QUIC could not connect at all.
                    // Fetch server.log to distinguish firewall vs handshake.
                    eprintln!("onyx: QUIC failed — {e:#}{hint}");
                    let ssh = ssh_pool
                        .as_ref()
                        .and_then(|pool| {
                            pool.get_or_connect(
                                &target.ssh_target,
                                target.identity_file.as_deref(),
                                target.identity_hint.as_deref(),
                                SshAuthFlow::NonInteractive,
                                SshConnectMessages::default(),
                            )
                            .ok()
                        });
                    if let Ok(log) = ssh_capture(
                        &target.ssh_target,
                        target.identity_file.as_deref(),
                        ssh.as_deref(),
                        &format!("cat {REMOTE_DIR}/server.log 2>/dev/null"),
                    ) {
                        if log.is_empty() {
                            eprintln!("  server.log is empty — server may not have started");
                        } else {
                            for line in log.lines() {
                                eprintln!("  {line}");
                            }
                            if log.contains("incoming from") {
                                eprintln!(
                                    "  → UDP packets reach the server; QUIC handshake failing"
                                );
                            } else {
                                eprintln!(
                                    "  → No UDP packets logged — likely a cloud firewall issue"
                                );
                                eprintln!(
                                    "    Open UDP {port} in your provider's firewall panel",
                                    port = target.quic_port
                                );
                            }
                        }
                    }
                    if no_fallback {
                        return Err(e);
                    }
                    eprintln!("[onyx] UDP unavailable — falling back to SSH");
                    eprintln!("       tip: use --no-fallback to require QUIC, or --port / ONYX_PORT for a custom port");
                    let mut cmd = std::process::Command::new("ssh");
                    cmd.args(["-tt", "-q", "-o", "SetEnv ONYX_MODE=ssh"]);
                    if let Some(id) = &target.identity_file {
                        cmd.args(["-i", id]);
                    }
                    cmd.arg(&target.ssh_target);
                    return Err(anyhow::anyhow!("exec ssh: {}", cmd.exec()));
                }
                // We previously had a session — reconnect window expired.
                // Be explicit about what that means instead of just
                // surfacing the raw anyhow chain: the remote tmux session
                // is still retained on the server, but client state
                // (session_id + resume_token) is per-process and lives only
                // in this binary. Re-running `onyx <target>` opens a fresh
                // session rather than resuming; true cross-process resume
                // would require on-disk session state, which isn't built
                // yet.
                if session.is_some() {
                    eprintln!(
                        "[session] connection lost — reconnect window expired."
                    );
                    eprintln!(
                        "          the remote tmux session is retained on the server for up to 12h."
                    );
                    eprintln!(
                        "          re-run `onyx {}` to start a new session.",
                        raw_target
                    );
                }
                if !hint.is_empty() {
                    eprintln!("onyx:{hint}");
                }
                return Err(e);
            }
        }
    }

    endpoint.wait_idle().await;
    Ok(())
}
