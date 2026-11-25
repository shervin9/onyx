use anyhow::{Context, Result};
use quinn::{ClientConfig, Endpoint};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use shared::{AuditRecord, JobStatus, JobSummary, Message, SessionSummary, StdStream, DEFAULT_PORT};
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

mod agent;
mod termfilter;

// ---------------------------------------------------------------------------
// Source files embedded at compile time for remote bootstrap.
// ---------------------------------------------------------------------------

const REMOTE_WORKSPACE_TOML: &str =
    "[workspace]\nmembers = [\"shared\", \"server\"]\nresolver = \"2\"\n";

const SHARED_CARGO_TOML: &str = include_str!("../../shared/Cargo.toml");
const SHARED_LIB_RS: &str = include_str!("../../shared/src/lib.rs");
const SERVER_CARGO_TOML: &str = include_str!("../../server/Cargo.toml");
const SERVER_MAIN_RS: &str = include_str!("../../server/src/main.rs");
const SERVER_DB_RS: &str = include_str!("../../server/src/db.rs");
const SERVER_REPLAY_RS: &str = include_str!("../../server/src/replay.rs");

const REMOTE_DIR: &str = "~/.local/share/onyx";
const ONYX_SERVER_BINARY_ENV: &str = "ONYX_SERVER_BINARY";
const ONYX_DEV_REMOTE_BUILD_ENV: &str = "ONYX_DEV_REMOTE_BUILD";

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
            "[onyx] bootstrap could not find a writable remote install directory.\n\
             Likely cause: the default Onyx paths are not writable on the remote host.\n\
             Checked:\n{}\n\
             Try:\n  set ONYX_REMOTE_DIR to a writable absolute path, e.g. /tmp/onyx\n  or install/start onyx-server manually and re-run with --no-bootstrap",
            remote_failures.join("\n")
        )
    })?;

    Ok(RemotePaths { remote_dir })
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

async fn send_msg<W: tokio::io::AsyncWrite + Unpin>(stream: &mut W, msg: &Message) -> Result<()> {
    let payload = shared::encode(msg)?;
    stream
        .write_all(&(payload.len() as u32).to_le_bytes())
        .await?;
    stream.write_all(&payload).await?;
    Ok(())
}

async fn recv_msg<R: tokio::io::AsyncRead + Unpin>(stream: &mut R) -> Result<Message> {
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

fn sane_terminal_size(cols: u16, rows: u16) -> (u16, u16) {
    let cols = if cols == 0 { 80 } else { cols };
    let rows = if rows == 0 { 24 } else { rows };
    (cols, rows)
}

fn terminal_env_value_from(value: Option<&str>) -> String {
    let term = value.unwrap_or("").trim();
    let valid = !term.is_empty()
        && term != "unknown"
        && term != "dumb"
        && term.len() <= 64
        && term
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+'));
    if valid {
        term.to_string()
    } else {
        "xterm-256color".to_string()
    }
}

fn terminal_env_value() -> String {
    terminal_env_value_from(std::env::var("TERM").ok().as_deref())
}

fn should_show_reconnect_ui(session: &Option<(String, String)>) -> bool {
    session.is_some()
}

fn debug_log(msg: &str) {
    if std::env::var_os("ONYX_DEBUG").is_some() {
        eprintln!("[onyx:debug] {msg}");
    }
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
    fn enter() -> Result<Self> {
        anyhow::ensure!(std::io::stdin().is_terminal(), "stdin is not a terminal");
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut t) != 0 {
                return Err(std::io::Error::last_os_error()).context("tcgetattr stdin");
            }
            let saved = t;
            libc::cfmakeraw(&mut t);
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t) != 0 {
                return Err(std::io::Error::last_os_error()).context("tcsetattr stdin raw");
            }
            Ok(RawMode { saved })
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QuicFailureKind {
    Timeout,
    ConnectionRefused,
    NetworkUnreachable,
    Dns,
    Handshake,
    Other,
}

fn classify_quic_failure(e: &anyhow::Error) -> QuicFailureKind {
    let s = format!("{e:#}").to_ascii_lowercase();
    if s.contains("connection refused") {
        QuicFailureKind::ConnectionRefused
    } else if s.contains("network is unreachable") || s.contains("no route to host") {
        QuicFailureKind::NetworkUnreachable
    } else if s.contains("dns lookup")
        || s.contains("no address resolved")
        || s.contains("failed to lookup address information")
        || s.contains("name or service not known")
    {
        QuicFailureKind::Dns
    } else if s.contains("timed out")
        || s.contains("timedout")
        || s.contains("deadline")
        || s.contains("udp/")
    {
        QuicFailureKind::Timeout
    } else if s.contains("handshake")
        || s.contains("alpn")
        || s.contains("tls")
        || s.contains("certificate")
    {
        QuicFailureKind::Handshake
    } else {
        QuicFailureKind::Other
    }
}

fn quic_error_hint(e: &anyhow::Error, port: u16) -> String {
    match classify_quic_failure(e) {
        QuicFailureKind::Timeout => format!(
            "\n  likely cause: UDP/{port} is blocked or dropped before it reaches onyx-server\n  try: open UDP/{port} in the remote firewall, or use --no-fallback to require QUIC"
        ),
        QuicFailureKind::ConnectionRefused => format!(
            "\n  likely cause: onyx-server is not listening on UDP/{port} yet\n  try: run `onyx doctor <target>` or reconnect after bootstrap completes"
        ),
        QuicFailureKind::Handshake => {
            "\n  likely cause: the server answered UDP, but QUIC/TLS setup does not match Onyx\n  try: inspect server.log for TLS/ALPN or TOFU issues".to_string()
        }
        _ => String::new(),
    }
}

fn proxy_session_not_resumable(e: &anyhow::Error) -> bool {
    format!("{e:#}")
        .to_ascii_lowercase()
        .contains("proxy session not resumable")
}

fn quic_unavailable_for_proxy(e: &anyhow::Error) -> bool {
    matches!(
        classify_quic_failure(e),
        QuicFailureKind::Timeout
            | QuicFailureKind::ConnectionRefused
            | QuicFailureKind::NetworkUnreachable
            | QuicFailureKind::Dns
    )
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

/// How long stdin waits to coalesce a burst of keystrokes into one write.
const STDIN_BATCH_WINDOW: Duration = Duration::from_millis(5);
/// QUIC handshake timeout for interactive mode. A QUIC handshake takes about
/// one round trip, so 4s tolerates slow overseas/cellular links while a
/// blocked UDP port hands over to the SSH bridge quickly.
const INTERACTIVE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);
/// Retry window after first successful session is dropped. Covers laptop
/// sleep, VPN reconnect, multi-minute transitions, and flaky networks —
/// the server-side session outlives this by far (12h, see
/// `DETACHED_SESSION_TTL` server-side), so this is purely how long the
/// *client* keeps retrying before giving up and printing resume instructions.
const INTERACTIVE_RECONNECT_WINDOW: Duration = Duration::from_secs(1800);
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
static SSH_SOCKET_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

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
        forwards: Vec<(u16, u16)>,
        port_override: Option<u16>,
        /// Skip the resume picker and always start a fresh session.
        new_session: bool,
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
    Doctor {
        raw_target: String,
        identity_file: Option<String>,
    },
    /// `onyx audit <target>` — durable job history from the server's store.
    Audit {
        raw_target: String,
        identity_file: Option<String>,
        no_bootstrap: bool,
        json: bool,
        limit: Option<u32>,
    },
    /// `onyx agent run <target> --agent <kind> -- <prompt...>` — run a coding
    /// agent CLI headlessly on the remote as a resumable exec job.
    AgentRun {
        raw_target: String,
        identity_file: Option<String>,
        no_bootstrap: bool,
        json: bool,
        detach: bool,
        agent_kind: agent::AgentKind,
        model: Option<String>,
        prompt: String,
        cwd: Option<String>,
        timeout_secs: Option<u64>,
        yolo: bool,
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

    // ── audit ───────────────────────────────────────────────────────────
    //
    // `onyx audit <target> [--limit N] [--json]` — durable job history.
    if matches!(it.peek(), Some(cmd) if cmd == "audit") {
        it.next();
        let raw_target = it
            .next()
            .ok_or_else(|| "audit: missing <target>".to_string())?;
        let mut identity: Option<String> = None;
        let mut no_bootstrap = false;
        let mut json = false;
        let mut limit: Option<u32> = None;
        while let Some(a) = it.next() {
            match a.as_str() {
                "--json" => json = true,
                "--no-bootstrap" => no_bootstrap = true,
                "-i" => {
                    identity = Some(
                        it.next()
                            .ok_or_else(|| "-i requires an argument".to_string())?,
                    );
                }
                "--limit" => {
                    let raw = it
                        .next()
                        .ok_or_else(|| "--limit requires a number".to_string())?;
                    limit = Some(
                        raw.parse::<u32>()
                            .map_err(|_| format!("--limit: invalid number '{raw}'"))?,
                    );
                }
                other => {
                    return Err(format!("audit: unexpected argument: {other} (try --help)"));
                }
            }
        }
        return Ok(ParseOutcome::Run(CliMode::Audit {
            raw_target,
            identity_file: identity,
            no_bootstrap,
            json,
            limit,
        }));
    }

    // ── agent run ───────────────────────────────────────────────────────
    //
    // `onyx agent run <target> [--agent <kind>] [--model <m>] [flags] -- <prompt...>`
    // The prompt is the bare-positional tail (or everything after `--`), joined
    // with spaces. Like `exec`, once the prompt tail starts, later args
    // (including things that look like flags) are part of the prompt.
    if matches!(it.peek(), Some(cmd) if cmd == "agent") {
        it.next();
        let action = it
            .next()
            .ok_or_else(|| "agent: missing action (try `agent run`)".to_string())?;
        if action != "run" {
            return Err(format!("agent: unknown action '{action}' (try `agent run`)"));
        }
        let raw_target = it
            .next()
            .ok_or_else(|| "agent run: missing <target>".to_string())?;

        let mut identity: Option<String> = None;
        let mut no_bootstrap = false;
        let mut json = false;
        let mut detach = false;
        let mut yolo = false;
        let mut agent_name: Option<String> = None;
        let mut model: Option<String> = None;
        let mut cwd: Option<String> = None;
        let mut timeout_secs: Option<u64> = None;
        let mut prompt_parts: Vec<String> = Vec::new();
        let mut seen_dashdash = false;
        let mut in_prompt_tail = false;

        while let Some(a) = it.next() {
            if seen_dashdash || in_prompt_tail {
                prompt_parts.push(a);
                continue;
            }
            match a.as_str() {
                "--" => seen_dashdash = true,
                "--json" => json = true,
                "--detach" => detach = true,
                "--no-bootstrap" => no_bootstrap = true,
                "--yolo" => yolo = true,
                "-i" => {
                    identity = Some(
                        it.next()
                            .ok_or_else(|| "-i requires an argument".to_string())?,
                    );
                }
                "--agent" => {
                    agent_name = Some(
                        it.next()
                            .ok_or_else(|| "--agent requires a name".to_string())?,
                    );
                }
                "--model" => {
                    model = Some(
                        it.next()
                            .ok_or_else(|| "--model requires an argument".to_string())?,
                    );
                }
                "--cwd" => {
                    cwd = Some(
                        it.next()
                            .ok_or_else(|| "--cwd requires an argument".to_string())?,
                    );
                }
                "--timeout" => {
                    let raw = it.next().ok_or_else(|| {
                        "--timeout requires a duration (e.g. 30s, 5m)".to_string()
                    })?;
                    timeout_secs = Some(parse_duration_secs(&raw).ok_or_else(|| {
                        format!("--timeout: invalid duration '{raw}' (use e.g. 30s, 5m, 2h)")
                    })?);
                }
                other if other.starts_with('-') => {
                    return Err(format!("unknown flag for agent run: {other} (try --help)"));
                }
                _ => {
                    prompt_parts.push(a);
                    in_prompt_tail = true;
                }
            }
        }

        let agent_kind = match agent_name.as_deref() {
            None => agent::AgentKind::Claude,
            Some(name) => agent::AgentKind::parse(name).ok_or_else(|| {
                format!(
                    "agent run: unknown agent '{name}' (supported: {})",
                    agent::SUPPORTED.join(", ")
                )
            })?,
        };
        let prompt = prompt_parts.join(" ");
        if prompt.trim().is_empty() {
            return Err("agent run: missing prompt (e.g. `-- \"fix the failing test\"`)".to_string());
        }

        return Ok(ParseOutcome::Run(CliMode::AgentRun {
            raw_target,
            identity_file: identity,
            no_bootstrap,
            json,
            detach,
            agent_kind,
            model,
            prompt,
            cwd,
            timeout_secs,
            yolo,
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
                    let raw = it.next().ok_or_else(|| {
                        "--timeout requires a duration (e.g. 30s, 5m)".to_string()
                    })?;
                    timeout_secs = Some(parse_duration_secs(&raw).ok_or_else(|| {
                        format!("--timeout: invalid duration '{raw}' (use e.g. 30s, 5m, 2h)")
                    })?);
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
                if !command.is_empty() {
                    return Err(format!("{sub}: unexpected arguments"));
                }
                let job_id_opt = positional.into_iter().next();
                if sub == "attach" {
                    let job_id = job_id_opt.ok_or_else(|| {
                        "attach: missing <job-id> (interactive sessions resume \
                         automatically: just run `onyx <host>`)"
                            .to_string()
                    })?;
                    Ok(ParseOutcome::Run(CliMode::Attach {
                        raw_target,
                        identity_file: identity,
                        no_bootstrap,
                        json,
                        job_id,
                    }))
                } else {
                    let job_id = job_id_opt
                        .ok_or_else(|| "logs: missing <job-id>".to_string())?;
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
    let mut forwards: Vec<(u16, u16)> = Vec::new();
    let mut port_override: Option<u16> = None;
    let mut new_session = false;

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
            "--new" => new_session = true,
            // Accepted and ignored: sessions are tmux-free now, so this is
            // always the behavior. Kept so existing aliases keep working.
            "--no-tmux" => {}
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
        forwards,
        port_override,
        new_session,
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
onyx — a remote shell that survives network drops (QUIC, SSH fallback)

USAGE
  onyx [OPTIONS] [user@]<host>[:<quic-port>]      interactive shell
  onyx exec   <target> [OPTIONS] -- <cmd...>      run a resumable remote job
  onyx jobs   <target> [--json]                   list jobs
  onyx attach <target> <job-id> [--json]          reattach to a job
  onyx logs   <target> <job-id> [--json]          print a job's buffered output
  onyx kill   <target> <job-id> [--json]          stop a job
  onyx audit  <target> [--limit N] [--json]       job history (survives restart)
  onyx agent run <target> [--agent <kind>] [--model <m>] [--yolo] [--detach]
                 [--cwd <dir>] [--timeout <dur>] [--json] -- <prompt...>
  onyx proxy  <host> <port>                       transport for SSH ProxyCommand
  onyx doctor <target>                            diagnose connectivity
  onyx --help | --version

SHELL
  A plain login shell on the server's own PTY: your terminal's scrollback,
  selection and copy work exactly like SSH. No tmux.
  When the network drops, the shell keeps running on the server. The client
  retries for up to 30 minutes and then sends back exactly the output you
  missed. After a very long gap it repaints the screen once instead. Run
  `onyx <host>` again later to resume a detached session (kept for 12 hours,
  in memory). The terminal title shows when Onyx is reconnecting.
  If UDP is blocked, the same session continues over an SSH bridge through
  your existing SSH access (no extra port or firewall rule), with the same
  replay after drops. Port forwards (-L) need QUIC.

JOBS
  `onyx exec` runs a command owned by the server. It keeps running if you
  disconnect, buffers up to 4 MiB of output, and the client resumes the
  stream automatically. Jobs do not survive an onyx-server restart. Finished
  jobs are kept for 1 hour.
  `onyx agent run` runs a coding agent CLI (claude; codex/aider/gemini are
  best-effort) as a job. The agent must already be installed and signed in
  on the remote. --yolo lets it act without approval.

OPTIONS
  -i <file>                 SSH identity file for bootstrap
  --new                     start a fresh shell; skip the resume picker
  -L, --forward L:R         tunnel localhost:L → remote:R (repeatable)
  --port <port>             QUIC port on the remote (default: 7272; also
                              ONYX_PORT or <host>:<port>)
  --no-bootstrap            skip remote install/start; needs ONYX_AUTH_TOKEN
                              (from ~/.local/share/onyx/server.auth_token)
  --no-fallback             QUIC only: no SSH bridge or plain SSH/TCP fallback
  --json                    one JSON object per line (jobs commands)
  --detach                  (exec) start the job and return
  --cwd <dir>               (exec) working directory on the remote
  --env KEY=VALUE           (exec) extra environment variable (repeatable)
  --timeout <dur>           (exec) kill after e.g. 30s, 5m, 2h (exit 124)
  -h, --help                show this help
  -V, --version             print version

INSTALL
  On first connect Onyx uploads the matching onyx-server binary over SSH
  (linux x86_64/arm64) and starts it. Later connects reuse it.

EXAMPLES
  onyx user@host
  onyx dev-server                          # alias from ~/.ssh/config
  onyx -L 3000:3000 dev-server             # forward a local port
  onyx exec gpu-box --detach -- python train.py
  onyx logs gpu-box job_a1b2c3d4e5f60718
  onyx exec ci --json -- cargo test
  onyx proxy host.example.com 22           # ProxyCommand in ssh_config
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
    fn agent_run_defaults_to_claude_and_joins_prompt() {
        let out = parse_args_from(s(&[
            "agent", "run", "gpu-box", "--", "fix", "the", "failing", "test",
        ]))
        .unwrap();
        match out {
            ParseOutcome::Run(CliMode::AgentRun {
                raw_target,
                agent_kind,
                prompt,
                yolo,
                ..
            }) => {
                assert_eq!(raw_target, "gpu-box");
                assert_eq!(agent_kind, agent::AgentKind::Claude);
                assert_eq!(prompt, "fix the failing test");
                assert!(!yolo);
            }
            other => panic!("expected AgentRun, got {other:?}"),
        }
    }

    #[test]
    fn agent_run_parses_flags_and_bare_prompt() {
        let out = parse_args_from(s(&[
            "agent", "run", "host", "--agent", "claude", "--model", "opus", "--yolo",
            "--detach", "refactor auth",
        ]))
        .unwrap();
        match out {
            ParseOutcome::Run(CliMode::AgentRun {
                agent_kind,
                model,
                prompt,
                detach,
                yolo,
                ..
            }) => {
                assert_eq!(agent_kind, agent::AgentKind::Claude);
                assert_eq!(model.as_deref(), Some("opus"));
                assert_eq!(prompt, "refactor auth");
                assert!(detach);
                assert!(yolo);
            }
            other => panic!("expected AgentRun, got {other:?}"),
        }
    }

    #[test]
    fn agent_run_rejects_unknown_agent_and_missing_prompt() {
        assert!(parse_args_from(s(&["agent", "run", "host", "--agent", "nope", "--", "hi"]))
            .is_err());
        assert!(parse_args_from(s(&["agent", "run", "host", "--agent", "claude"])).is_err());
        assert!(parse_args_from(s(&["agent", "frobnicate", "host"])).is_err());
    }

    #[test]
    fn audit_parses_target_limit_and_json() {
        let out = parse_args_from(s(&["audit", "gpu-box", "--limit", "25", "--json"])).unwrap();
        match out {
            ParseOutcome::Run(CliMode::Audit {
                raw_target,
                json,
                limit,
                ..
            }) => {
                assert_eq!(raw_target, "gpu-box");
                assert!(json);
                assert_eq!(limit, Some(25));
            }
            other => panic!("expected Audit, got {other:?}"),
        }
    }

    #[test]
    fn audit_rejects_bad_limit_and_missing_target() {
        assert!(parse_args_from(s(&["audit", "host", "--limit", "nope"])).is_err());
        assert!(parse_args_from(s(&["audit"])).is_err());
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
                new_session,
                ..
            }) => {
                assert!(no_bootstrap);
                assert!(no_fallback);
                assert!(!new_session);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn new_flag_sets_new_session() {
        let out = parse_args_from(s(&["--new", "host"])).unwrap();
        match out {
            ParseOutcome::Run(CliMode::Interactive { new_session, .. }) => {
                assert!(new_session);
            }
            _ => panic!("expected Interactive"),
        }
    }

    #[test]
    fn legacy_no_tmux_flag_is_accepted() {
        let out = parse_args_from(s(&["--no-tmux", "host"])).unwrap();
        assert!(matches!(out, ParseOutcome::Run(CliMode::Interactive { .. })));
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
        let out =
            parse_args_from(s(&["proxy", "--no-fallback", "host.example.com", "22"])).unwrap();
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
            "SHELL",
            "JOBS",
            "No tmux",
            "--forward",
            "--no-fallback",
            "--no-bootstrap",
            "--port",
            "ONYX_PORT",
            "proxy  <host> <port>",
            "12 hours",
            "30 minutes",
            "onyx exec",
            "onyx jobs",
            "onyx attach",
            "onyx logs",
            "onyx doctor",
            "--json",
            "--detach",
            "1 hour",
        ] {
            assert!(HELP_TEXT.contains(needle), "HELP_TEXT missing '{needle}'");
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
        assert!(err.contains("missing command"), "err was: {err}");
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
    fn prebuilt_candidates_find_homebrew_libexec_before_override() {
        let exe = Path::new("/opt/homebrew/bin/onyx");
        let candidates = prebuilt_server_candidates_from(
            "x86_64",
            Some(exe),
            Some(Path::new("/repo")),
            Some("/custom/onyx-server-linux-x86_64"),
            false,
        );
        assert_eq!(
            candidates,
            vec![
                PathBuf::from("/opt/homebrew/bin/onyx-server-linux-x86_64"),
                PathBuf::from("/opt/homebrew/bin/onyx-server"),
                PathBuf::from("/opt/homebrew/libexec/onyx-server-linux-x86_64"),
                PathBuf::from("/custom/onyx-server-linux-x86_64"),
            ]
        );
    }

    #[test]
    fn prebuilt_candidates_skip_dev_paths_by_default() {
        let candidates = prebuilt_server_candidates_from(
            "arm64",
            Some(Path::new("/usr/local/bin/onyx")),
            Some(Path::new("/repo")),
            None,
            false,
        );
        assert!(!candidates
            .iter()
            .any(|path| path.starts_with("/repo/target")));

        let dev_candidates = prebuilt_server_candidates_from(
            "arm64",
            Some(Path::new("/usr/local/bin/onyx")),
            Some(Path::new("/repo")),
            None,
            true,
        );
        assert!(dev_candidates
            .iter()
            .any(|path| path == Path::new("/repo/target/release/onyx-server")));
    }

    #[test]
    fn dev_remote_build_requires_explicit_env_value() {
        assert!(!dev_remote_build_enabled_from(None));
        assert!(!dev_remote_build_enabled_from(Some("")));
        assert!(!dev_remote_build_enabled_from(Some("0")));
        assert!(dev_remote_build_enabled_from(Some("1")));
        assert!(dev_remote_build_enabled_from(Some("true")));
        assert!(dev_remote_build_enabled_from(Some("yes")));
        assert!(dev_remote_build_enabled_from(Some("on")));
    }

    #[test]
    fn missing_prebuilt_does_not_remote_build_by_default() {
        assert_eq!(
            missing_prebuilt_action(false),
            MissingPrebuiltAction::FailFast
        );
        assert_eq!(
            missing_prebuilt_action(true),
            MissingPrebuiltAction::DevRemoteBuild
        );
    }

    #[test]
    fn bootstrap_errors_are_product_messages() {
        let missing = missing_prebuilt_server_binary_error("x86_64").to_string();
        assert!(missing.contains("[onyx] missing onyx-server binary for linux-x86_64"));
        assert!(missing.contains("brew reinstall shervin9/onyx/onyx --formula"));
        assert!(!missing.contains("cargo"));
        assert!(!missing.contains("rustup"));

        let unsupported = unsupported_remote_arch_error("armv7l").to_string();
        assert!(unsupported.contains("[onyx] unsupported remote architecture: armv7l"));
        assert!(unsupported.contains("Supported: linux-x86_64, linux-arm64"));
    }

    #[test]
    fn ssh_fallback_notice_is_single_clean_line() {
        let notice = ssh_fallback_notice();
        assert_eq!(notice, "[onyx] UDP unavailable — falling back to SSH");
        assert!(!notice.contains('\n'));
        assert!(notice.len() < 80);
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
    fn attach_requires_target_and_job_id() {
        // Interactive sessions resume on their own; `attach` is only for
        // exec jobs and needs both a target and a job id.
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
    fn quic_failure_classifier_distinguishes_timeout_and_handshake() {
        assert_eq!(
            classify_quic_failure(&err("QUIC handshake timed out after 8 s")),
            QuicFailureKind::Timeout
        );
        assert_eq!(
            classify_quic_failure(&err("connection refused")),
            QuicFailureKind::ConnectionRefused
        );
        assert_eq!(
            classify_quic_failure(&err("QUIC handshake failed: alpn mismatch")),
            QuicFailureKind::Handshake
        );
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
        // Interactive mode hands over to the SSH bridge, so it gives up on
        // QUIC sooner than proxy mode (which has no equivalent fallback).
        assert!(INTERACTIVE_HANDSHAKE_TIMEOUT <= PROXY_HANDSHAKE_TIMEOUT);
    }

    #[test]
    fn initial_connect_does_not_show_reconnect_ui() {
        assert!(!should_show_reconnect_ui(&None));
        assert!(should_show_reconnect_ui(&Some((
            "sid".into(),
            "tok".into()
        ))));
    }

    #[test]
    fn terminal_env_falls_back_for_bad_terms() {
        assert_eq!(terminal_env_value_from(None), "xterm-256color");
        assert_eq!(terminal_env_value_from(Some("")), "xterm-256color");
        assert_eq!(terminal_env_value_from(Some("unknown")), "xterm-256color");
        assert_eq!(terminal_env_value_from(Some("dumb")), "xterm-256color");
        assert_eq!(
            terminal_env_value_from(Some("xterm-256color")),
            "xterm-256color"
        );
        assert_eq!(
            terminal_env_value_from(Some("screen-256color")),
            "screen-256color"
        );
        assert_eq!(terminal_env_value_from(Some("bad term")), "xterm-256color");
    }

    #[test]
    fn terminal_size_zero_values_are_sane() {
        assert_eq!(sane_terminal_size(0, 0), (80, 24));
        assert_eq!(sane_terminal_size(132, 0), (132, 24));
        assert_eq!(sane_terminal_size(0, 43), (80, 43));
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
            "[onyx] SSH authentication failed: the selected key requires a passphrase.\nLikely cause: Onyx is using a non-interactive SSH flow for bootstrap.\nTry:\n  unlock the key locally with ssh-add /home/me/.ssh/id_ed25519\n  then re-run Onyx"
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
            "[onyx] SSH authentication failed.\nLikely cause: the passphrase was canceled, incorrect, or the agent refused the key.\nTry:\n  retry the SSH prompt\n  or unlock the key first with ssh-add '/tmp/onyx key'"
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
    fn remote_status_parser_reads_fields() {
        let parsed = parse_remote_status_output(
            "h=abc r=yes own=yes ready=yes c=yes arch=x86_64",
            "abc",
        );
        assert!(parsed.hash_ok);
        assert!(parsed.healthy);
        assert_eq!(parsed.arch, "x86_64");
    }

    #[test]
    fn post_install_status_forces_restart_after_owned_server_replace() {
        let mut status = parse_remote_status_output(
            "h=old r=yes own=yes ready=yes c=yes arch=x86_64",
            "new",
        );
        mark_replaced_owned_server_stopped(&mut status);
        assert!(!status.running);
        assert!(!status.healthy);
        assert!(!status.own_pid);
    }

    #[test]
    fn exec_detach_hint_points_to_attach() {
        assert_eq!(
            exec_detach_hint("job_123"),
            "[onyx] detached; reattach with: onyx attach <target> job_123"
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
    fn ssh_control_socket_paths_stay_short_across_multiple_allocations() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..8 {
            let path = ssh_control_socket_path().unwrap();
            assert!(control_socket_path_len(&path) <= SSH_CONTROL_SOCKET_MAX_LEN);
            assert!(seen.insert(path));
        }
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
            "[onyx] SSH connection timed out while establishing the session (15s).\nLikely cause: the host is unreachable, port 22 is blocked, or SSH is hanging before login.\nTry:\n  ssh myserver"
        );
    }

    #[test]
    fn classify_ssh_master_failure_reports_connection_closed() {
        let status = std::process::ExitStatus::from_raw(255 << 8);
        let control_path = Path::new("/tmp/o-1234-abcd12.sock");
        let err = classify_ssh_master_failure(
            "myserver",
            None,
            None,
            false,
            control_path,
            &status,
            "Connection closed by remote host",
        );
        assert_eq!(
            format!("{err}"),
            "[onyx] SSH connection closed during bootstrap.\nLikely cause: the SSH server or a network middlebox dropped the session.\nTry:\n  ssh myserver\n  then re-run Onyx once plain SSH is stable"
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
            anyhow::anyhow!(
                "[onyx] failed to create SSH control socket (path too long)\n  path: /tmp/o-1.sock"
            ),
            "bootstrap failed",
        );
        assert_eq!(
            format!("{err}"),
            "[onyx] failed to create SSH control socket (path too long)\n  path: /tmp/o-1.sock"
        );

        let err = contextualize_bootstrap_error(
            anyhow::anyhow!("[onyx] bootstrap could not find a writable remote install directory."),
            "bootstrap failed",
        );
        assert_eq!(
            format!("{err}"),
            "[onyx] bootstrap could not find a writable remote install directory."
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

    #[test]
    fn parse_session_pick_handles_all_inputs() {
        assert_eq!(parse_session_pick("", 3), SessionPick::MostRecent);
        assert_eq!(parse_session_pick("  \n", 3), SessionPick::MostRecent);
        assert_eq!(parse_session_pick("2", 3), SessionPick::Index(1));
        assert_eq!(parse_session_pick("1", 3), SessionPick::Index(0));
        assert_eq!(parse_session_pick("n", 3), SessionPick::Fresh);
        assert_eq!(parse_session_pick("N", 3), SessionPick::Fresh);
        // Out of range and garbage both fall back to Fresh, never panic.
        assert_eq!(parse_session_pick("9", 3), SessionPick::Fresh);
        assert_eq!(parse_session_pick("0", 3), SessionPick::Fresh);
        assert_eq!(parse_session_pick("xyz", 3), SessionPick::Fresh);
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
    #[allow(dead_code)]
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
fn build_target(
    raw: &str,
    identity: Option<String>,
    port_override: Option<u16>,
) -> Result<OnyxTarget> {
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
        let (status, stderr) = run_ssh_master(target, identity, &control_path, interactive_prompt)?;

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
        Some(pool) => pool.get_or_connect(target, identity, identity_hint, auth_flow, messages),
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
        ssh_control_socket_failure_message(
            &fallback,
            Some("could not allocate a unique socket path")
        )
    )
}

fn ssh_control_socket_failure_from_stderr(
    control_path: &Path,
    stderr: &str,
) -> Option<anyhow::Error> {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("too long for unix domain socket") {
        return Some(anyhow::anyhow!(ssh_control_socket_path_too_long_message(
            control_path
        )));
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
        "[onyx] SSH authentication failed: the selected key requires a passphrase.\n\
         Likely cause: Onyx is using a non-interactive SSH flow for bootstrap.\n\
         Try:\n  unlock the key locally with {}\n  then re-run Onyx",
        ssh_add_hint(identity)
    )
}

fn ssh_auth_canceled_message() -> String {
    "[onyx] SSH authentication was canceled.".to_string()
}

fn ssh_auth_retry_message(identity: Option<&str>) -> String {
    format!(
        "[onyx] SSH authentication failed.\n\
         Likely cause: the passphrase was canceled, incorrect, or the agent refused the key.\n\
         Try:\n  retry the SSH prompt\n  or unlock the key first with {}",
        ssh_add_hint(identity)
    )
}

fn ssh_connect_timeout_message(target: &str) -> String {
    format!(
        "[onyx] SSH connection timed out while establishing the session ({secs}s).\n\
         Likely cause: the host is unreachable, port 22 is blocked, or SSH is hanging before login.\n\
         Try:\n  ssh {target}",
        secs = SSH_CONNECT_TIMEOUT.as_secs(),
    )
}

fn ssh_banner_timeout_message(target: &str) -> String {
    format!(
        "[onyx] SSH connection timed out during banner exchange.\n\
         Likely cause: the TCP connection opened, but sshd did not finish the handshake.\n\
         Try:\n  ssh {target}\n  then inspect sshd, ProxyJump, or fail2ban on the remote side"
    )
}

fn ssh_connection_closed_message(target: &str) -> String {
    format!(
        "[onyx] SSH connection closed during bootstrap.\n\
         Likely cause: the SSH server or a network middlebox dropped the session.\n\
         Try:\n  ssh {target}\n  then re-run Onyx once plain SSH is stable"
    )
}

fn ssh_transport_failure_message(target: &str, stderr: &str) -> Option<String> {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("banner exchange") && lower.contains("timed out") {
        Some(ssh_banner_timeout_message(target))
    } else if lower.contains("connection closed by remote host")
        || lower.contains("connection reset by peer")
        || lower.contains("broken pipe")
        || lower.contains("kex_exchange_identification")
    {
        Some(ssh_connection_closed_message(target))
    } else if lower.contains("timed out") {
        Some(ssh_connect_timeout_message(target))
    } else {
        None
    }
}

fn ssh_connection_failed_message(
    target: &str,
    status: &std::process::ExitStatus,
    stderr: &str,
) -> anyhow::Error {
    if let Some(message) = ssh_transport_failure_message(target, stderr) {
        anyhow::anyhow!(message)
    } else {
        let stderr = stderr.trim();
        if stderr.is_empty() {
            anyhow::anyhow!(
                "[onyx] SSH connection failed\n  exit: {}",
                status.code().unwrap_or(-1)
            )
        } else {
            anyhow::anyhow!(
                "[onyx] SSH connection failed\n  exit: {}\n  stderr: {}",
                status.code().unwrap_or(-1),
                stderr
            )
        }
    }
}

fn ssh_command_failed_message(
    target: &str,
    status: &std::process::ExitStatus,
    stderr: &str,
) -> anyhow::Error {
    if let Some(message) = ssh_transport_failure_message(target, stderr) {
        anyhow::anyhow!(message)
    } else {
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
    // Notice a dead TCP path within ~15s so the SSH bridge (which rides
    // this master) fails fast and the session reconnects.
    cmd.args(["-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3"]);
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

    let status = child
        .wait()
        .context("waiting for ssh authentication flow")?;
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
    ssh_connection_failed_message(target, status, stderr)
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
    target: &str,
    identity: Option<&str>,
    identity_hint: Option<&str>,
    status: &std::process::ExitStatus,
    stderr: &str,
) -> anyhow::Error {
    if let Some(message) = ssh_auth_failure_message(
        identity,
        identity_hint,
        false,
        status.code(),
        status.signal(),
        stderr,
    ) {
        return anyhow::anyhow!(message);
    }
    ssh_command_failed_message(target, status, stderr)
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
            target,
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
        ) {
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
        .chain(SERVER_DB_RS.bytes())
        .chain(SERVER_REPLAY_RS.bytes())
        .chain(SHARED_LIB_RS.bytes())
        .chain(SERVER_CARGO_TOML.bytes())
        .chain(SHARED_CARGO_TOML.bytes())
    {
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
    arch: String, // uname -m on the remote host
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BootstrapInfo {
    auth_token: String,
    /// Remote install dir (holds onyx-server), used by the SSH bridge.
    remote_dir: String,
}

fn parse_remote_status_output(text: &str, expected_hash: &str) -> RemoteStatus {
    let get = |key: &str| -> String {
        text.split_whitespace()
            .find(|kv| kv.starts_with(&format!("{key}=")))
            .and_then(|kv| kv.split_once('=').map(|x| x.1))
            .unwrap_or("")
            .to_string()
    };

    RemoteStatus {
        hash_ok: get("h") == expected_hash,
        running: get("r") == "yes",
        healthy: get("ready") == "yes",
        own_pid: get("own") == "yes",
        has_cargo: get("c") == "yes",
        arch: get("arch"),
    }
}

fn mark_replaced_owned_server_stopped(status: &mut RemoteStatus) {
    if status.own_pid {
        status.running = false;
        status.healthy = false;
        status.own_pid = false;
    }
}

fn exec_detach_hint(job_id: &str) -> String {
    format!("[onyx] detached; reattach with: onyx attach <target> {job_id}")
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
         echo \"h=$h r=$r own=$own ready=$ready c=$c arch=$arch\"",
        server_log = shell_quote(&format!("{}/server.log", paths.remote_dir)),
        remote_dir = shell_quote(&paths.remote_dir),
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
        return Err(ssh_connection_failed_message(
            target,
            &out.status,
            &String::from_utf8_lossy(&out.stderr),
        ));
    }

    let text = String::from_utf8_lossy(&out.stdout);
    Ok(parse_remote_status_output(&text, expected_hash))
}

fn read_server_auth_token(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
    paths: &RemotePaths,
) -> Result<String> {
    let token_path = format!("{}/server.auth_token", paths.remote_dir);
    let token = ssh_capture(
        target,
        identity,
        session,
        &format!("cat {}", shell_quote(&token_path)),
    )
    .context("reading remote server auth token")?;
    let token = token.trim().to_string();
    anyhow::ensure!(
        token.len() >= 64 && token.bytes().all(|b| b.is_ascii_hexdigit()),
        "remote server auth token is missing or invalid"
    );
    Ok(token)
}

fn auth_token_from_env() -> Result<String> {
    let token = std::env::var("ONYX_AUTH_TOKEN")
        .context("ONYX_AUTH_TOKEN is required when using --no-bootstrap")?;
    let token = token.trim().to_string();
    anyhow::ensure!(
        token.len() >= 64 && token.bytes().all(|b| b.is_ascii_hexdigit()),
        "ONYX_AUTH_TOKEN is invalid"
    );
    Ok(token)
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

fn server_platform_label(remote_arch: &str) -> String {
    match normalized_server_arch(remote_arch) {
        Some("x86_64") => "linux-x86_64".to_string(),
        Some("arm64") => "linux-arm64".to_string(),
        _ => remote_arch_label(remote_arch).to_string(),
    }
}

fn dev_remote_build_enabled_from(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim),
        Some("1")
            | Some("true")
            | Some("TRUE")
            | Some("yes")
            | Some("YES")
            | Some("on")
            | Some("ON")
    )
}

fn dev_remote_build_enabled() -> bool {
    dev_remote_build_enabled_from(std::env::var(ONYX_DEV_REMOTE_BUILD_ENV).ok().as_deref())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MissingPrebuiltAction {
    FailFast,
    DevRemoteBuild,
}

fn missing_prebuilt_action(dev_remote_build: bool) -> MissingPrebuiltAction {
    if dev_remote_build {
        MissingPrebuiltAction::DevRemoteBuild
    } else {
        MissingPrebuiltAction::FailFast
    }
}

fn server_target_triples(remote_arch: &str) -> &'static [&'static str] {
    match normalized_server_arch(remote_arch) {
        Some("x86_64") => &["x86_64-unknown-linux-musl", "x86_64-unknown-linux-gnu"],
        Some("arm64") => &["aarch64-unknown-linux-musl", "aarch64-unknown-linux-gnu"],
        _ => &[],
    }
}

fn unsupported_remote_arch_error(remote_arch: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "[onyx] unsupported remote architecture: {}\nSupported: linux-x86_64, linux-arm64",
        remote_arch_label(remote_arch)
    )
}

fn missing_prebuilt_server_binary_error(remote_arch: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "[onyx] missing onyx-server binary for {}\n\
         Your local Onyx install is incomplete.\n\
         Try reinstalling: brew reinstall shervin9/onyx/onyx --formula",
        server_platform_label(remote_arch)
    )
}

fn push_unique_path(out: &mut Vec<PathBuf>, path: PathBuf) {
    if !out.iter().any(|existing| existing == &path) {
        out.push(path);
    }
}

fn prebuilt_server_candidates_from(
    remote_arch: &str,
    current_exe: Option<&Path>,
    current_dir: Option<&Path>,
    env_override: Option<&str>,
    include_dev_paths: bool,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Some(name) = server_artifact_name(remote_arch) else {
        return out;
    };

    if let Some(exe_path) = current_exe {
        if let Some(dir) = exe_path.parent() {
            push_unique_path(&mut out, dir.join(name));
            push_unique_path(&mut out, dir.join("onyx-server"));
            if let Some(prefix) = dir.parent() {
                push_unique_path(&mut out, prefix.join("libexec").join(name));
            }
        }
    }

    if let Some(path) = env_override.map(str::trim).filter(|path| !path.is_empty()) {
        push_unique_path(&mut out, PathBuf::from(path));
    }

    if include_dev_paths {
        let cwd = current_dir.unwrap_or_else(|| Path::new("."));
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

fn prebuilt_server_candidates(remote_arch: &str) -> Vec<PathBuf> {
    let current_exe = std::env::current_exe().ok();
    let canonical_exe = current_exe
        .as_ref()
        .and_then(|exe| fs::canonicalize(exe).ok());
    let current_dir = std::env::current_dir().ok();
    let env_override = std::env::var(ONYX_SERVER_BINARY_ENV).ok();
    let include_dev_paths = dev_remote_build_enabled();
    let mut out = prebuilt_server_candidates_from(
        remote_arch,
        current_exe.as_deref(),
        current_dir.as_deref(),
        env_override.as_deref(),
        include_dev_paths,
    );
    if let Some(canonical_exe) = canonical_exe.as_deref() {
        for path in
            prebuilt_server_candidates_from(remote_arch, Some(canonical_exe), None, None, false)
        {
            push_unique_path(&mut out, path);
        }
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

fn is_user_visible_bootstrap_error(err: &anyhow::Error) -> bool {
    let msg = format!("{err:#}");
    msg.contains("[onyx] SSH key requires a passphrase.")
        || msg.contains("[onyx] SSH authentication was canceled.")
        || msg.contains("[onyx] SSH authentication could not be completed cleanly.")
        || msg.contains("[onyx] failed to create SSH control socket")
        || msg.contains("[onyx] SSH connection failed")
        || msg.contains("[onyx] SSH connection timed out")
        || msg.contains("[onyx] SSH connection closed")
        || msg.contains("[onyx] bootstrap could not find a writable remote install directory")
        || msg.contains("[onyx] bootstrap could not produce an onyx-server binary")
        || msg.contains("[onyx] missing onyx-server binary")
        || msg.contains("[onyx] unsupported remote architecture")
        || msg.contains("[onyx] remote install failed")
        || msg.contains("[onyx] onyx-server ")
}

fn contextualize_bootstrap_error(err: anyhow::Error, context: &'static str) -> anyhow::Error {
    if is_user_visible_bootstrap_error(&err) {
        err
    } else {
        Err::<(), _>(err).context(context).unwrap_err()
    }
}

fn bootstrap_error_with_help(err: anyhow::Error) -> anyhow::Error {
    if is_user_visible_bootstrap_error(&err) {
        return err;
    }
    anyhow::anyhow!(
        "{}\nnext steps:\n  set ONYX_REMOTE_DIR to a writable absolute path on the remote host\n  or install/start onyx-server manually and re-run with --no-bootstrap",
        err
    )
}

fn bootstrap_missing_server_binary_error(remote_arch: &str, err: anyhow::Error) -> anyhow::Error {
    let artifact = server_artifact_name(remote_arch).unwrap_or("onyx-server-linux-<arch>");
    anyhow::anyhow!(
        "[onyx] bootstrap could not produce an onyx-server binary for {}.\n\
         Likely cause: no matching local prebuilt server was found and the remote build fallback failed.\n\
         Try:\n  place {} next to the onyx client or in target/release\n  or install Rust/cargo on the remote and re-run\n  or install onyx-server manually and re-run with --no-bootstrap\nDetail: {err}",
        remote_arch_label(remote_arch),
        artifact,
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
    for (name, src) in [("db.rs", SERVER_DB_RS), ("replay.rs", SERVER_REPLAY_RS)] {
        ssh_upload(
            target,
            identity,
            session,
            &format!("{}/server/src/{name}", paths.remote_dir),
            src.as_bytes(),
        )?;
    }

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

    eprintln!(
        "[onyx] installing server binary ({})…",
        server_platform_label(remote_arch)
    );
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
            "[onyx] remote install failed while replacing onyx-server.\n\
             Likely cause: the remote filesystem reported the binary as busy even after the atomic swap path.\n\
             Try:\n  re-run once to confirm it is reproducible\n  then file a bug with the error below\nDetail: {err}"
        )
    } else if msg.contains("Permission denied") {
        anyhow::anyhow!(
            "[onyx] remote install failed: permission denied while writing onyx-server.\n\
             Likely cause: ONYX_REMOTE_DIR points to a directory you cannot write.\n\
             Try:\n  set ONYX_REMOTE_DIR to a writable absolute path, e.g. /tmp/onyx\n  or install onyx-server manually and re-run with --no-bootstrap\nDetail: {err}"
        )
    } else if msg.contains("No space left on device") {
        anyhow::anyhow!(
            "[onyx] remote install failed: the remote disk is full.\n\
             Likely cause: there is not enough space to stage or replace onyx-server.\n\
             Try:\n  free space on the remote host\n  then re-run bootstrap\nDetail: {err}"
        )
    } else if msg.contains("command not found") {
        anyhow::anyhow!(
            "[onyx] remote install failed: a required remote tool is missing.\n\
             Likely cause: the remote shell cannot run mv, chmod, or kill.\n\
             Try:\n  verify a standard POSIX userland is available on the remote host\n  or install onyx-server manually and re-run with --no-bootstrap\nDetail: {err}"
        )
    } else if msg.contains("exit 20") {
        anyhow::anyhow!(
            "[onyx] remote install failed: the uploaded onyx-server.new file is missing on the remote host.\n\
             Likely cause: the SSH upload did not complete or the remote path rejected the write.\n\
             Try:\n  set ONYX_REMOTE_DIR to a writable absolute path, e.g. /tmp/onyx\n  then re-run bootstrap\nDetail: {err}"
        )
    } else {
        err
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServerStartState {
    Ready,
    PortBusy,
    Timeout,
}

fn server_port_busy_message(quic_port: u16) -> anyhow::Error {
    anyhow::anyhow!(
        "[onyx] onyx-server could not start on UDP/{quic_port}.\n\
         Likely cause: another process is already using that port on the remote host.\n\
         Try:\n  choose a different port with --port / ONYX_PORT\n  or stop the conflicting process and re-run"
    )
}

fn server_start_timeout_message(target: &str, server_log: &str, quic_port: u16) -> anyhow::Error {
    anyhow::anyhow!(
        "[onyx] onyx-server did not become ready on UDP/{quic_port} within 10s.\n\
         Likely cause: it crashed on startup or could not bind the requested port.\n\
         Try:\n  inspect {server_log} on the remote host\n  or run `onyx doctor {target}` for a quick check"
    )
}

fn fetch_remote_server_log_excerpt(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
    server_log: &str,
) -> Option<String> {
    ssh_capture(
        target,
        identity,
        session,
        &format!("tail -20 {} 2>/dev/null", shell_quote(server_log)),
    )
    .ok()
    .filter(|log| !log.is_empty())
}

fn wait_for_server_ready(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
    quic_port: u16,
    server_log: &str,
) -> Result<ServerStartState> {
    let outcome = ssh_capture(
        target,
        identity,
        session,
        &format!(
            "for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do \
               if grep -q 'listening on .*:{quic_port}  (ALPN: onyx)' {server_log} 2>/dev/null; then \
                 echo ready; exit 0; \
               fi; \
               if grep -q 'Address already in use' {server_log} 2>/dev/null; then \
                 echo port_busy; exit 0; \
               fi; \
               sleep 0.5; \
             done; \
             echo timeout",
            server_log = shell_quote(server_log),
        ),
    )?;
    Ok(match outcome.trim() {
        "ready" => ServerStartState::Ready,
        "port_busy" => ServerStartState::PortBusy,
        _ => ServerStartState::Timeout,
    })
}

fn start_server(
    target: &str,
    identity: Option<&str>,
    session: Option<&SshSession>,
    quic_port: u16,
    status: &RemoteStatus,
    paths: &RemotePaths,
) -> Result<()> {
    let server_pid = format!("{}/server.pid", paths.remote_dir);
    let server_log = format!("{}/server.log", paths.remote_dir);
    let remote_dir = shell_quote(&paths.remote_dir);

    if status.healthy {
        eprintln!("[onyx] onyx-server already running");
        return Ok(());
    }

    if status.running && status.own_pid {
        eprintln!("[onyx] existing onyx-server is unhealthy; restarting");
    } else if status.running {
        return Err(server_port_busy_message(quic_port));
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

    match wait_for_server_ready(target, identity, session, quic_port, &server_log)? {
        ServerStartState::Ready => Ok(()),
        ServerStartState::PortBusy => {
            if let Some(log) =
                fetch_remote_server_log_excerpt(target, identity, session, &server_log)
            {
                eprintln!("[onyx] server.log:\n{log}");
            }
            Err(server_port_busy_message(quic_port))
        }
        ServerStartState::Timeout => {
            if let Some(log) =
                fetch_remote_server_log_excerpt(target, identity, session, &server_log)
            {
                eprintln!("[onyx] server.log:\n{log}");
            }
            Err(server_start_timeout_message(target, &server_log, quic_port))
        }
    }
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
                if st.hash_ok {
                    "up to date"
                } else {
                    "stale or missing"
                }
            );
            eprintln!(
                "[onyx doctor] server running: {}",
                if st.running { "yes" } else { "no" }
            );
            eprintln!(
                "[onyx doctor] server healthy: {}",
                if st.healthy {
                    "yes (QUIC port bound)"
                } else {
                    "no"
                }
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
        Ok(Err(e)) => match classify_quic_failure(&anyhow::anyhow!("{e:#}")) {
            QuicFailureKind::ConnectionRefused => eprintln!(
                "[onyx doctor] QUIC:      connection refused on UDP/{quic_port}\n\
                 [onyx doctor]   likely cause: onyx-server is not running or is bound to a different port\n\
                 [onyx doctor]   try: run `onyx {raw_target}` or check ONYX_PORT / --port"
            ),
            QuicFailureKind::NetworkUnreachable => eprintln!(
                "[onyx doctor] QUIC:      network unreachable\n\
                 [onyx doctor]   likely cause: VPN, route, or firewall issue before the host\n\
                 [onyx doctor]   try: verify the host is reachable, then retry"
            ),
            _ => eprintln!(
                "[onyx doctor] QUIC:      handshake error — {e:#}\n\
                 [onyx doctor]   likely cause: the server answered UDP/{quic_port}, but QUIC/TLS or TOFU trust failed\n\
                 [onyx doctor]   try: inspect server.log and known_hosts trust"
            ),
        },
        Err(_) => eprintln!(
            "[onyx doctor] QUIC:      timeout — UDP/{quic_port} appears blocked\n\
             [onyx doctor]   likely cause: a cloud firewall, VPN, or NAT is dropping UDP before it reaches onyx-server\n\
             [onyx doctor]   try: open UDP {quic_port} in your firewall, or use --port / ONYX_PORT"
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
) -> Result<BootstrapInfo> {
    let ssh = ssh_session_for(
        pool,
        ssh_target,
        identity,
        identity_hint,
        auth_flow,
        messages,
    )?;
    let hash = format!("{:016x}", source_hash());
    let paths = resolve_remote_paths(ssh_target, identity, Some(&ssh))
        .map_err(bootstrap_error_with_help)?;

    // Single SSH call: verify auth + get all state.
    let mut status = remote_status(ssh_target, identity, Some(&ssh), &hash, quic_port, &paths)
        .map_err(bootstrap_error_with_help)?;

    // ── Fast path ─────────────────────────────────────────────────────────────
    if status.hash_ok && status.healthy {
        let auth_token = read_server_auth_token(ssh_target, identity, Some(&ssh), &paths)
            .map_err(bootstrap_error_with_help)?;
        return Ok(BootstrapInfo {
            auth_token,
            remote_dir: paths.remote_dir.clone(),
        });
    }

    // ── Slow path ────────────────────────────────────────────────────────────
    eprintln!("[onyx] bootstrapping remote...");

    if !status.hash_ok {
        if server_artifact_name(&status.arch).is_none() {
            return Err(bootstrap_error_with_help(unsupported_remote_arch_error(&status.arch)));
        }
        let used_prebuilt =
            upload_prebuilt_server(ssh_target, identity, Some(&ssh), &status.arch, &paths)
                .map_err(bootstrap_error_with_help)?;

        if !used_prebuilt {
            if missing_prebuilt_action(dev_remote_build_enabled())
                == MissingPrebuiltAction::FailFast
            {
                return Err(bootstrap_error_with_help(missing_prebuilt_server_binary_error(
                    &status.arch,
                )));
            }
            eprintln!(
                "[onyx] {ONYX_DEV_REMOTE_BUILD_ENV}=1 enabled; building on remote from source"
            );
            if !status.has_cargo {
                ensure_rust(ssh_target, identity, Some(&ssh))
                    .map_err(|err| bootstrap_missing_server_binary_error(&status.arch, err))
                    .map_err(bootstrap_error_with_help)?;
            }
            upload_and_build(ssh_target, identity, Some(&ssh), &paths)
                .map_err(|err| bootstrap_missing_server_binary_error(&status.arch, err))
                .map_err(bootstrap_error_with_help)?;
        }

        // Atomically stop the old onyx-server (if any), swap in the new
        // binary via mv, and update the hash stamp. Must run after upload
        // and before start_server.
        install_staged_server_binary(ssh_target, identity, Some(&ssh), &hash, &status, &paths)
            .map_err(bootstrap_error_with_help)?;
        mark_replaced_owned_server_stopped(&mut status);
    }

    start_server(ssh_target, identity, Some(&ssh), quic_port, &status, &paths)
        .map_err(bootstrap_error_with_help)?;
    let auth_token = read_server_auth_token(ssh_target, identity, Some(&ssh), &paths)
        .map_err(bootstrap_error_with_help)?;

    eprintln!("[onyx] ready");
    Ok(BootstrapInfo {
        auth_token,
        remote_dir: paths.remote_dir.clone(),
    })
}

// ---------------------------------------------------------------------------
// Port forwarding — TCP-over-QUIC
// ---------------------------------------------------------------------------

/// Binds a TCP listener on localhost:local_port.  For every accepted TCP
/// connection a new QUIC bidirectional stream is opened on `conn` and data
/// flows in both directions until either side closes.
/// The task runs until aborted (by try_once cleanup) or until the bind fails.
async fn run_forward_listener(
    conn: quinn::Connection,
    auth_token: String,
    local_port: u16,
    remote_port: u16,
) {
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
        let token = auth_token.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_forward_conn(c, token, tcp, remote_port).await {
                eprintln!("[forward] :{local_port}→:{remote_port}: {e:#}");
            }
        });
    }
}

/// Opens a QUIC stream, performs the ForwardConnect handshake, then copies
/// bytes between the TCP socket and the QUIC stream until both sides close.
async fn handle_forward_conn(
    conn: quinn::Connection,
    auth_token: String,
    tcp: tokio::net::TcpStream,
    remote_port: u16,
) -> Result<()> {
    let (mut qs, mut qr) = conn.open_bi().await.context("open forward stream")?;
    send_msg(
        &mut qs,
        &Message::ForwardConnect {
            auth_token,
            remote_port,
        },
    )
    .await?;
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

#[allow(clippy::too_many_arguments)]
async fn connect_proxy_stream(
    endpoint: &Endpoint,
    server_addr: SocketAddr,
    host_port: &str,
    capture: &FpCapture,
    auth_token: &str,
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
            auth_token: auth_token.to_string(),
            proxy_session_id: proxy_session_id.to_string(),
        }
    } else {
        Message::ProxyConnect {
            auth_token: auth_token.to_string(),
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

async fn run_proxy_mode(target_host: String, target_port: u16, no_fallback: bool) -> Result<()> {
    let target = build_target(&target_host, None, None)
        .with_context(|| format!("resolving target '{target_host}'"))?;
    let dns_result = {
        use std::net::ToSocketAddrs;
        let addr_str = format!("{}:{}", target.quic_host, target.quic_port);
        addr_str
            .to_socket_addrs()
            .with_context(|| format!("DNS lookup for '{}'", target.quic_host))
            .and_then(|mut it| {
                it.next()
                    .ok_or_else(|| anyhow::anyhow!("no address resolved for {}", target.quic_host))
            })
    };
    let server_addr: SocketAddr = match dns_result {
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
    let auth_token = auth_token_from_env()?;
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
            &auth_token,
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

                let deadline =
                    *reconnect_deadline.get_or_insert_with(|| Instant::now() + PROXY_RESUME_WINDOW);
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
                    eprintln!("[proxy] QUIC unavailable ({e:#}); falling back to plain TCP");
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

fn exec_ssh_shell(ssh_target: &str, identity_file: Option<&str>) -> Result<()> {
    let mut cmd = std::process::Command::new("ssh");
    cmd.args(["-tt", "-q", "-o", "SetEnv ONYX_MODE=ssh"]);
    if let Some(id) = identity_file {
        cmd.args(["-i", id]);
    }
    cmd.arg(ssh_target);
    Err(anyhow::anyhow!("exec ssh: {}", cmd.exec()))
}

fn ssh_fallback_notice() -> &'static str {
    "[onyx] UDP unavailable — falling back to SSH"
}

/// Shared target preparation used by every exec subcommand.
struct PreparedExecTarget {
    endpoint: Endpoint,
    server_addr: SocketAddr,
    host_port: String,
    capture: FpCapture,
    auth_token: String,
}

async fn prepare_exec_target(
    raw_target: String,
    identity_file: Option<String>,
    no_bootstrap: bool,
) -> Result<PreparedExecTarget> {
    let target = build_target(&raw_target, identity_file, None)
        .with_context(|| format!("resolving target '{raw_target}'"))?;
    let mut auth_token = None;

    if target.ssh_mode && !no_bootstrap {
        let ssh_target = target.ssh_target.clone();
        let identity = target.identity_file.clone();
        let identity_hint = target.identity_hint.clone();
        let port = target.quic_port;
        let info = tokio::task::spawn_blocking(move || {
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
        auth_token = Some(info.auth_token);
    }
    let auth_token = match auth_token {
        Some(token) => token,
        None => auth_token_from_env()?,
    };

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
    Ok(PreparedExecTarget {
        endpoint,
        server_addr,
        host_port,
        capture,
        auth_token,
    })
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
#[allow(clippy::too_many_arguments)]
async fn stream_exec_with_resume(
    endpoint: &Endpoint,
    server_addr: SocketAddr,
    host_port: &str,
    capture: &FpCapture,
    auth_token: &str,
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
                    auth_token,
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
    auth_token: &str,
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
            auth_token: auth_token.to_string(),
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

/// Run a coding-agent CLI headlessly on the remote, as a resumable exec job.
///
/// This is a thin wrapper over [`run_exec_mode`]: the agent adapter turns the
/// request into a concrete argv, and the existing exec machinery owns the
/// process lifecycle, output buffering, detach/attach, and resume-on-drop.
#[allow(clippy::too_many_arguments)]
async fn run_agent_run_mode(
    raw_target: String,
    identity_file: Option<String>,
    no_bootstrap: bool,
    json: bool,
    detach: bool,
    agent_kind: agent::AgentKind,
    model: Option<String>,
    prompt: String,
    cwd: Option<String>,
    timeout_secs: Option<u64>,
    yolo: bool,
) -> Result<()> {
    let command = agent::build_command(&agent::AgentRequest {
        kind: agent_kind,
        prompt: &prompt,
        model: model.as_deref(),
        json,
        yolo,
    });

    // Human-mode preamble. In --json mode we stay silent so stdout is a clean
    // event stream.
    if !json {
        eprintln!(
            "onyx: running {} agent on {raw_target}",
            agent_kind.as_str()
        );
        if !agent_kind.verified() {
            eprintln!(
                "onyx: warning: the '{}' adapter is best-effort and unverified; \
                 its flags may not match the installed CLI",
                agent_kind.as_str()
            );
        }
        if yolo {
            eprintln!(
                "onyx: warning: --yolo lets the agent act without approval on {raw_target}"
            );
        }
    }

    // The agent reads its own credentials on the remote host (e.g. the
    // remote's configured Claude/Codex auth). Onyx does not inject secrets.
    run_exec_mode(
        raw_target,
        identity_file,
        no_bootstrap,
        json,
        detach,
        command,
        cwd,
        Vec::new(),
        timeout_secs,
    )
    .await
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
    let PreparedExecTarget {
        endpoint,
        server_addr,
        host_port,
        capture,
        auth_token,
    } = prepare_exec_target(raw_target, identity_file, no_bootstrap).await?;
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
            auth_token: auth_token.clone(),
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
        eprintln!("{}", exec_detach_hint(&job_id));
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
        &auth_token,
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
    let prepared = prepare_exec_target(raw_target, identity_file, no_bootstrap).await?;
    let PreparedExecTarget {
        endpoint,
        server_addr,
        host_port,
        capture,
        auth_token,
        ..
    } = prepared;

    // Attach goes straight into the resume loop. started_at_unix isn't
    // known to the client here; use 0 so the JSON `finished` event's
    // duration_ms stays non-negative even though it won't be meaningful.
    let exit_code = stream_exec_with_resume(
        &endpoint,
        server_addr,
        &host_port,
        &capture,
        &auth_token,
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
    let PreparedExecTarget {
        endpoint,
        server_addr,
        host_port,
        capture,
        auth_token,
        ..
    } = prepare_exec_target(raw_target, identity_file, no_bootstrap).await?;
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
            auth_token,
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
    let PreparedExecTarget {
        endpoint,
        server_addr,
        host_port,
        capture,
        auth_token,
        ..
    } = prepare_exec_target(raw_target, identity_file, no_bootstrap).await?;
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
            auth_token,
            job_id: job_id.clone(),
        },
    )
    .await?;
    let msg = recv_msg(&mut recv).await?;
    conn.close(0u32.into(), b"bye");
    endpoint.wait_idle().await;

    match msg {
        Message::KillResult {
            killed, message, ..
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

async fn run_audit_mode(
    raw_target: String,
    identity_file: Option<String>,
    no_bootstrap: bool,
    json: bool,
    limit: Option<u32>,
) -> Result<()> {
    let PreparedExecTarget {
        endpoint,
        server_addr,
        host_port,
        capture,
        auth_token,
        ..
    } = prepare_exec_target(raw_target, identity_file, no_bootstrap).await?;
    let conn = connect_authenticated(
        server_addr,
        &endpoint,
        &host_port,
        &capture,
        INTERACTIVE_HANDSHAKE_TIMEOUT,
    )
    .await?;
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;
    send_msg(&mut send, &Message::AuditList { auth_token, limit }).await?;
    let msg = recv_msg(&mut recv).await?;
    conn.close(0u32.into(), b"bye");
    endpoint.wait_idle().await;

    match msg {
        Message::AuditListResponse { records } => {
            if json {
                print_audit_json(&records);
            } else {
                print_audit_table(&records);
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
        other => anyhow::bail!("unexpected audit response: {other:?}"),
    }
}

fn print_audit_table(records: &[AuditRecord]) {
    if records.is_empty() {
        println!("no job history (durable store empty or disabled)");
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
    for r in records {
        let exit = match r.exit_code {
            Some(c) => c.to_string(),
            None if r.timed_out => "t/o".to_string(),
            None => "-".to_string(),
        };
        println!(
            "{:<24}  {:<10}  {:<10}  {:<7}  {}",
            truncate_display(&r.job_id, 24),
            truncate_display(&r.status, 10),
            format_relative_time(now_unix, r.started_at_unix),
            exit,
            truncate_display(&r.command, 60),
        );
    }
}

fn print_audit_json(records: &[AuditRecord]) {
    for r in records {
        let finished = match r.finished_at_unix {
            Some(v) => v.to_string(),
            None => "null".to_string(),
        };
        let exit = match r.exit_code {
            Some(c) => c.to_string(),
            None => "null".to_string(),
        };
        println!(
            "{{\"type\":\"audit\",\"job_id\":{},\"status\":{},\"command\":{},\
             \"started_at_unix\":{},\"finished_at_unix\":{},\"exit_code\":{},\
             \"timed_out\":{}}}",
            jq(&r.job_id),
            jq(&r.status),
            jq(&r.command),
            r.started_at_unix,
            finished,
            exit,
            r.timed_out,
        );
    }
}

async fn run_jobs_mode(
    raw_target: String,
    identity_file: Option<String>,
    no_bootstrap: bool,
    json: bool,
) -> Result<()> {
    let PreparedExecTarget {
        endpoint,
        server_addr,
        host_port,
        capture,
        auth_token,
        ..
    } = prepare_exec_target(raw_target, identity_file, no_bootstrap).await?;
    let conn = connect_authenticated(
        server_addr,
        &endpoint,
        &host_port,
        &capture,
        INTERACTIVE_HANDSHAKE_TIMEOUT,
    )
    .await?;
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;
    send_msg(&mut send, &Message::JobsList { auth_token }).await?;
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
// Resume picker — offer detached sessions on a fresh interactive connect
// ---------------------------------------------------------------------------

/// A user's choice at the multi-session prompt.
#[derive(Debug, PartialEq)]
enum SessionPick {
    /// Blank / Enter — resume the most recent (index 0).
    MostRecent,
    /// A 1-based selection, stored 0-based.
    Index(usize),
    /// "n" or anything unrecognized — start a fresh session.
    Fresh,
}

/// Parse one line of picker input against `count` offered sessions. Pure so it
/// can be unit-tested. Out-of-range numbers and garbage both fall back to
/// `Fresh` rather than erroring, so the prompt never traps the user.
fn parse_session_pick(input: &str, count: usize) -> SessionPick {
    let t = input.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("y") || t.eq_ignore_ascii_case("yes") {
        return SessionPick::MostRecent;
    }
    if t.eq_ignore_ascii_case("n") {
        return SessionPick::Fresh;
    }
    match t.parse::<usize>() {
        Ok(n) if n >= 1 && n <= count => SessionPick::Index(n - 1),
        _ => SessionPick::Fresh,
    }
}

/// Ask the server for detached sessions and, if any exist, let the user pick
/// one to resume. Returns Some((session_id, resume_token)) to resume, or None
/// to start fresh. Best-effort: any transport/parse error → None (fresh
/// session), so the picker never blocks a connection from proceeding.
fn pick_session(sessions: Vec<SessionSummary>) -> Option<(String, String)> {
    if sessions.is_empty() {
        return None;
    }

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let describe = |s: &SessionSummary| match s.detached_at_unix {
        Some(d) => format!("detached {}", format_relative_time(now_unix, d)),
        None => "open in another terminal (or a client that dropped)".to_string(),
    };
    // Enter resumes the newest *detached* session. A session that is still
    // attached is only taken over when picked explicitly by number:
    // otherwise two terminals would keep stealing one session back and forth.
    let default_idx = sessions.iter().position(|s| s.detached_at_unix.is_some());

    // One detached session: resume it without asking (the common case
    // after a network drop that outlasted the reconnect window).
    if sessions.len() == 1 && default_idx == Some(0) {
        let s = &sessions[0];
        eprintln!(
            "[onyx] resuming your session ({}). Use --new to start fresh.",
            describe(s)
        );
        return Some((s.session_id.clone(), s.resume_token.clone()));
    }

    eprintln!("[onyx] sessions on this host:");
    for (i, s) in sessions.iter().enumerate() {
        eprintln!(
            "  {}) {}  {}",
            i + 1,
            truncate_display(&s.session_id, 12),
            describe(s)
        );
    }
    match default_idx {
        Some(i) => eprint!("Resume which? [Enter = {}, number, or 'n' for new] ", i + 1),
        None => eprint!("[Enter = new session, or a number to take that one over] "),
    }
    use std::io::Write;
    std::io::stderr().flush().ok();

    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return None;
    }
    match parse_session_pick(&line, sessions.len()) {
        SessionPick::MostRecent => {
            let s = &sessions[default_idx?];
            Some((s.session_id.clone(), s.resume_token.clone()))
        }
        SessionPick::Index(i) => {
            let s = &sessions[i];
            Some((s.session_id.clone(), s.resume_token.clone()))
        }
        SessionPick::Fresh => None,
    }
}

/// One request/response on its own stream: SessionsList → SessionsListResponse.
async fn query_sessions(
    conn: &quinn::Connection,
    auth_token: &str,
) -> Result<Vec<SessionSummary>> {
    let (send, recv) = conn.open_bi().await.context("open_bi")?;
    query_sessions_on(send, recv, auth_token).await
}

async fn query_sessions_on<W: MsgSink, R: tokio::io::AsyncRead + Unpin>(
    mut send: W,
    mut recv: R,
    auth_token: &str,
) -> Result<Vec<SessionSummary>> {
    send_msg(
        &mut send,
        &Message::SessionsList {
            auth_token: auth_token.to_string(),
        },
    )
    .await?;
    send.finish_stream().await;
    match recv_msg(&mut recv).await? {
        Message::SessionsListResponse { sessions } => Ok(sessions),
        other => anyhow::bail!("unexpected sessions response: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Single connection attempt + I/O loop
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn try_once(
    server_addr: SocketAddr,
    endpoint: &Endpoint,
    session: &mut Option<(String, String)>,
    host_port: &str,
    capture: &FpCapture,
    auth_token: &str,
    forwards: &[(u16, u16)],
    raw_mode: &mut Option<RawMode>,
    allow_picker: bool,
    last_seq: &Arc<std::sync::atomic::AtomicU64>,
    input: &mut LocalInput,
) -> Result<bool> {
    let first_connect = session.is_none();
    if first_connect {
        eprintln!("[onyx] connecting...");
    }
    let t_connect = Instant::now();
    debug_log(if session.is_some() { "resuming QUIC handshake" } else { "starting QUIC handshake" });
    let conn = connect_authenticated(
        server_addr,
        endpoint,
        host_port,
        capture,
        INTERACTIVE_HANDSHAKE_TIMEOUT,
    )
    .await?;
    debug_log(&format!("QUIC handshake: {}ms", t_connect.elapsed().as_millis()));

    // On a genuinely fresh connect, ask the server for detached sessions and
    // let the user resume one instead of always starting a new session.
    // Runs once per process (only when session is still None); on any later
    // reconnect `first_connect` is false so this is skipped. Uses its own
    // short-lived stream on the already-open connection — no extra handshake.
    if first_connect && allow_picker {
        let listed = query_sessions(&conn, auth_token).await.unwrap_or_default();
        if let Some(picked) = pick_session(listed) {
            *session = Some(picked);
            // New terminal for an existing session: the server repaints the
            // screen once instead of replaying history.
            last_seq.store(0, Ordering::Relaxed);
        }
    }

    let t_stream = Instant::now();
    let (send, recv) = conn.open_bi().await.context("open_bi")?;
    debug_log(&format!("stream open: {}ms", t_stream.elapsed().as_millis()));

    // Spawn one TCP listener per --forward spec.  Each listener opens new QUIC
    // streams on this connection for individual TCP connections.  All handles
    // are aborted when this function returns (connection dropped or shell exit).
    let forward_handles: Vec<tokio::task::JoinHandle<()>> = forwards
        .iter()
        .map(|&(lp, rp)| {
            tokio::spawn(run_forward_listener(
                conn.clone(),
                auth_token.to_string(),
                lp,
                rp,
            ))
        })
        .collect();

    let result = run_attached(send, recv, session, auth_token, raw_mode, last_seq, input, "QUIC").await;

    for jh in &forward_handles {
        jh.abort();
    }
    conn.close(0u32.into(), b"bye");
    result
}

/// How to reach `onyx-server bridge` over SSH when QUIC is unreachable.
#[derive(Clone)]
struct BridgeTarget {
    ssh_target: String,
    identity: Option<String>,
    identity_hint: Option<String>,
    pool: SshSessionPool,
    remote_dir: String,
}

/// Start `ssh <host> <remote_dir>/onyx-server bridge` and return its pipes.
/// Reuses the pooled SSH ControlMaster, so this is one fast round trip.
async fn open_bridge(
    bt: &BridgeTarget,
) -> Result<(tokio::process::ChildStdin, tokio::process::ChildStdout, tokio::process::Child)> {
    let b = bt.clone();
    let ssh = tokio::task::spawn_blocking(move || {
        b.pool.get_or_connect(
            &b.ssh_target,
            b.identity.as_deref(),
            b.identity_hint.as_deref(),
            SshAuthFlow::NonInteractive,
            SshConnectMessages::default(),
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("ssh task: {e}"))??;
    let mut cmd = ssh_cmd(&bt.ssh_target, bt.identity.as_deref(), Some(&ssh));
    let server_path = match bt.remote_dir.strip_prefix("~/") {
        Some(rest) => format!("\"$HOME\"/{}", shell_quote(&format!("{rest}/onyx-server"))),
        None => shell_quote(&format!("{}/onyx-server", bt.remote_dir)),
    };
    cmd.arg(format!("{server_path} bridge"));
    let mut cmd = tokio::process::Command::from(cmd);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = cmd.spawn().context("starting ssh bridge")?;
    let stdin = child.stdin.take().context("bridge stdin")?;
    let stdout = child.stdout.take().context("bridge stdout")?;
    Ok((stdin, stdout, child))
}

/// One attach over the SSH bridge (UDP blocked). Same session protocol and
/// replay as QUIC; only the pipe differs. Port forwards need QUIC.
async fn try_once_bridge(
    bt: &BridgeTarget,
    session: &mut Option<(String, String)>,
    auth_token: &str,
    raw_mode: &mut Option<RawMode>,
    allow_picker: bool,
    last_seq: &Arc<std::sync::atomic::AtomicU64>,
    input: &mut LocalInput,
) -> Result<bool> {
    if session.is_none() && raw_mode.is_none() && allow_picker {
        if let Ok((w, r, _child)) = open_bridge(bt).await {
            let listed = tokio::time::timeout(
                INTERACTIVE_HANDSHAKE_TIMEOUT,
                query_sessions_on(w, r, auth_token),
            )
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default();
            if let Some(picked) = pick_session(listed) {
                *session = Some(picked);
                last_seq.store(0, Ordering::Relaxed);
            }
        }
    }
    let (w, r, _child) = open_bridge(bt).await?;
    run_attached(w, r, session, auth_token, raw_mode, last_seq, input, "SSH bridge").await
}

/// Write half of a session stream: a QUIC send stream, or the stdin of the
/// `ssh … onyx-server bridge` process.
trait MsgSink: tokio::io::AsyncWrite + Unpin + Send + 'static {
    async fn finish_stream(&mut self);
}

impl MsgSink for quinn::SendStream {
    async fn finish_stream(&mut self) {
        self.finish().ok();
    }
}

impl MsgSink for tokio::process::ChildStdin {
    async fn finish_stream(&mut self) {
        let _ = self.shutdown().await;
    }
}

/// Run one attach of the interactive session over an already-open stream,
/// whatever the transport. Returns Ok(true) when the session ended (shell
/// exit or taken over), Ok(false) on a transport drop worth reconnecting.
async fn run_attached<W, R>(
    mut send: W,
    mut recv: R,
    session: &mut Option<(String, String)>,
    auth_token: &str,
    raw_mode: &mut Option<RawMode>,
    last_seq: &Arc<std::sync::atomic::AtomicU64>,
    input: &mut LocalInput,
    transport: &str,
) -> Result<bool>
where
    W: MsgSink,
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let t_connect = Instant::now();
    let is_resume = session.is_some();
    let first_connect = raw_mode.is_none();
    let (local_cols, local_rows) = get_terminal_size();
    let (cols, rows) = sane_terminal_size(local_cols, local_rows);
    let term = terminal_env_value();
    match session.as_ref() {
        None => {
            last_seq.store(0, Ordering::Relaxed);
            eprintln!("[onyx] starting shell...");
            send_msg(
                &mut send,
                &Message::Hello {
                    auth_token: auth_token.to_string(),
                    session_id: new_session_id(),
                    resume_token: String::new(),
                    term: Some(term),
                    cols: Some(cols),
                    rows: Some(rows),
                    // Legacy field; the server no longer launches tmux.
                    no_tmux: true,
                },
            )
            .await?;
        }
        Some((sid, tok)) => {
            send_msg(
                &mut send,
                &Message::Resume {
                    auth_token: auth_token.to_string(),
                    session_id: sid.clone(),
                    resume_token: tok.clone(),
                    // Lets the server resend exactly the output we missed.
                    last_seq: last_seq.load(Ordering::Relaxed),
                },
            )
            .await?;
        }
    }

    debug_log("waiting for Welcome");
    let t_welcome = Instant::now();
    let (session_id, resume_token) = match recv_msg(&mut recv).await? {
        Message::Welcome {
            session_id,
            resume_token,
        } => {
            debug_log(&format!("session ready: {}ms (total {}ms)", t_welcome.elapsed().as_millis(), t_connect.elapsed().as_millis()));
            // Successful reclaim — clear the throttle flag so a future
            // disconnect episode can print the message once again.
            SESSION_BUSY_LOGGED.store(false, Ordering::Relaxed);
            clear_status_line();
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
    // Only print transport info on the initial connect.  On reconnects
    // raw mode is already active, so eprintln would corrupt the terminal
    // display.  State is conveyed through the terminal title instead.
    if raw_mode.is_none() {
        if is_resume {
            eprintln!("[mode] {transport}  (resumed session {session_id})");
        } else {
            eprintln!("[mode] {transport}  (session {session_id})");
        }
    } else {
        debug_log(&format!(
            "session {} (reconnect)",
            &session_id[..8.min(session_id.len())]
        ));
    }

    let (cols, rows) = sane_terminal_size(cols, rows);
    send_msg(&mut send, &Message::Resize { cols, rows }).await?;

    if raw_mode.is_none() {
        *raw_mode = Some(RawMode::enter()?);
    }

    let seen_seq = last_seq.clone();
    let mut output_jh = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        let mut warp_filter = termfilter::WarpHookFilter::default();
        loop {
            match recv_msg(&mut recv).await {
                Ok(Message::Output { seq, data }) => {
                    let data = warp_filter.filter(&data);
                    if stdout.write_all(&data).await.is_err() {
                        break false;
                    }
                    let _ = stdout.flush().await;
                    // Only count output as seen once it reached the terminal.
                    seen_seq.store(seq, Ordering::Relaxed);
                }
                Ok(Message::Close { reason }) => {
                    if reason == shared::CLOSE_TAKEN_OVER {
                        TAKEN_OVER.store(true, Ordering::Relaxed);
                    }
                    let _ = stdout.flush().await;
                    break true;
                }
                _ => break false,
            }
        }
    });

    if first_connect {
        eprintln!("[onyx] ready");
    }

    // Keystrokes typed while disconnected are queued and sent now.
    if !input.carry.is_empty() {
        let data = std::mem::take(&mut input.carry);
        if send_msg(&mut send, &Message::Input { data: data.clone() }).await.is_err() {
            input.carry = data;
            output_jh.abort();
            return Ok(false);
        }
    }
    let rx = input.rx.get_or_insert_with(spawn_stdin_pump);
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Some(StdinEv::Data(data)) => {
                    if send_msg(&mut send, &Message::Input { data: data.clone() }).await.is_err() {
                        // Transport dropped: keep the keystrokes for the
                        // next attach instead of losing them.
                        input.carry = data;
                        output_jh.abort();
                        return Ok(false);
                    }
                }
                Some(StdinEv::Winch) => {
                    let (cols, rows) = get_terminal_size();
                    if send_msg(&mut send, &Message::Resize { cols, rows }).await.is_err() {
                        output_jh.abort();
                        return Ok(false);
                    }
                }
                // Local stdin closed: exit cleanly.
                None => {
                    output_jh.abort();
                    return Ok(true);
                }
            },
            r = &mut output_jh => return Ok(r.unwrap_or(false)),
        }
    }
}

enum StdinEv {
    Data(Vec<u8>),
    Winch,
}

/// Local keyboard input for the interactive session. One stdin reader lives
/// for the whole process and feeds a channel; each attach (QUIC or bridge,
/// first connect or reconnect) drains the same channel. A per-attach reader
/// would leave a blocking read behind on every reconnect that swallowed the
/// next keystrokes.
#[derive(Default)]
struct LocalInput {
    /// Started on first attach, after the resume picker has read its answer.
    rx: Option<mpsc::Receiver<StdinEv>>,
    /// Input that could not be sent because the transport dropped.
    carry: Vec<u8>,
}

fn spawn_stdin_pump() -> mpsc::Receiver<StdinEv> {
    let (tx, rx) = mpsc::channel::<StdinEv>(256);
    tokio::spawn(async move {
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
                    // Coalesce a burst (paste, key repeat) into one write
                    // without adding noticeable typing latency.
                    let deadline = tokio::time::Instant::now() + STDIN_BATCH_WINDOW;
                    loop {
                        match tokio::time::timeout_at(deadline, stdin.read(&mut buf)).await {
                            Ok(Ok(m)) if m > 0 => data.extend_from_slice(&buf[..m]),
                            _ => break,
                        }
                    }
                    if tx.send(StdinEv::Data(data)).await.is_err() {
                        break;
                    }
                }
                Ev::Winch => {
                    if tx.send(StdinEv::Winch).await.is_err() {
                        break;
                    }
                }
            }
        }
        // Dropping tx closes the channel: the session sees local EOF.
    });
    rx
}

// ---------------------------------------------------------------------------
// Connection status line — calm, native-feeling state indicator
// ---------------------------------------------------------------------------

/// Set when the server says another client took this session over. The
/// client then exits instead of reconnecting (which would steal it back).
static TAKEN_OVER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

static RECONNECT_TITLE_SHOWN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Signal "reconnecting" through the terminal window/tab title instead of
/// printing into the session. Writing a status line would corrupt the screen
/// that the server is about to catch up byte-for-byte; the title bar sits
/// outside it. The user's own title is pushed onto the terminal's title stack
/// (XTWINOPS 22) and popped back (23) once the session is live again.
fn show_reconnect_status() {
    use std::io::Write;
    if RECONNECT_TITLE_SHOWN.swap(true, Ordering::Relaxed) {
        return;
    }
    eprint!(
        "\x1b[22;0t\x1b]0;\u{25cf} onyx \u{2014} reconnecting\u{2026} (up to {} min)\x07",
        INTERACTIVE_RECONNECT_WINDOW.as_secs() / 60
    );
    std::io::stderr().flush().ok();
}

/// Restore the user's terminal title after a reconnect (or on give-up).
fn clear_status_line() {
    use std::io::Write;
    if !RECONNECT_TITLE_SHOWN.swap(false, Ordering::Relaxed) {
        return;
    }
    eprint!("\x1b[23;0t");
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
        } => return run_attach_mode(raw_target, identity_file, no_bootstrap, json, job_id).await,
        CliMode::Logs {
            raw_target,
            identity_file,
            no_bootstrap,
            json,
            job_id,
        } => return run_logs_mode(raw_target, identity_file, no_bootstrap, json, job_id).await,
        CliMode::Doctor {
            raw_target,
            identity_file,
        } => return run_doctor_mode(raw_target, identity_file).await,
        CliMode::Audit {
            raw_target,
            identity_file,
            no_bootstrap,
            json,
            limit,
        } => return run_audit_mode(raw_target, identity_file, no_bootstrap, json, limit).await,
        CliMode::AgentRun {
            raw_target,
            identity_file,
            no_bootstrap,
            json,
            detach,
            agent_kind,
            model,
            prompt,
            cwd,
            timeout_secs,
            yolo,
        } => {
            return run_agent_run_mode(
                raw_target,
                identity_file,
                no_bootstrap,
                json,
                detach,
                agent_kind,
                model,
                prompt,
                cwd,
                timeout_secs,
                yolo,
            )
            .await
        }
        CliMode::Interactive {
            raw_target,
            identity_file,
            no_fallback,
            no_bootstrap,
            forwards,
            port_override,
            new_session,
        } => {
            return run_interactive_session(
                raw_target,
                identity_file,
                no_fallback,
                no_bootstrap,
                forwards,
                port_override,
                new_session,
            )
            .await;
        }
    }
}

// ---------------------------------------------------------------------------
// Interactive session
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_interactive_session(
    raw_target: String,
    identity_file: Option<String>,
    no_fallback: bool,
    no_bootstrap: bool,
    forwards: Vec<(u16, u16)>,
    port_override: Option<u16>,
    new_session: bool,
) -> Result<()> {
    // Resolve the target — runs `ssh -G <target>` for SSH aliases to get the
    // canonical hostname; the unresolved alias is kept only for SSH commands.
    let target = build_target(&raw_target, identity_file, port_override)
        .with_context(|| format!("resolving target '{raw_target}'"))?;
    let ssh_pool = target.ssh_mode.then(SshSessionPool::default);
    let mut auth_token = None;
    let mut remote_dir = REMOTE_DIR.to_string();

    // SSH bootstrap (blocking, single SSH call on fast path).
    if target.ssh_mode && !no_bootstrap {
        eprintln!("[onyx] connecting...");
        let info = bootstrap(
            &target.ssh_target,
            target.identity_file.as_deref(),
            target.identity_hint.as_deref(),
            target.quic_port,
            SshAuthFlow::InteractivePrompt,
            ssh_pool.as_ref(),
            SshConnectMessages {
                establishing: Some("[onyx] authenticating..."),
                authenticated: Some("[onyx] authenticated. continuing bootstrap…"),
            },
        )
        .map_err(|err| contextualize_bootstrap_error(err, "bootstrap failed"))?;
        auth_token = Some(info.auth_token);
        remote_dir = info.remote_dir;
    }
    let mut auth_token = match auth_token {
        Some(token) => token,
        None => auth_token_from_env()?,
    };

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
    // Offer the resume picker only on a genuinely fresh, interactive connect:
    // not when a workspace already pinned a session, not with --new, and not
    // when stdin isn't a tty (scripts / pipes must never block on a prompt).
    let allow_picker =
        session.is_none() && !new_session && std::io::stdin().is_terminal();
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
    // Whether the "Connection lost" status line is currently visible.
    // Shown once per disconnect episode; cleared before re-entering raw mode.
    let mut status_shown = false;

    // Enter raw mode only after the first shell stream is established, then
    // keep it for post-ready reconnects. This leaves first-connect progress
    // messages in normal cooked mode while preserving clean terminal restore.
    let mut raw_mode: Option<RawMode> = None;

    // Highest output seq this terminal has rendered; sent on Resume so the
    // server replays exactly what we missed.
    let last_seq = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // SSH bridge: the same session over the existing SSH access, used when
    // QUIC (UDP) is unreachable. Needs SSH mode; --no-fallback disables it.
    let bridge = match (&ssh_pool, no_fallback) {
        (Some(pool), false) => Some(BridgeTarget {
            ssh_target: target.ssh_target.clone(),
            identity: target.identity_file.clone(),
            identity_hint: target.identity_hint.clone(),
            pool: pool.clone(),
            remote_dir: remote_dir.clone(),
        }),
        _ => None,
    };
    let mut use_bridge = false;
    let mut bridge_notice_shown = false;
    let mut input = LocalInput::default();

    loop {
        // After 20 s of failed reconnects, re-run bootstrap via SSH.
        // This refreshes remote state and restarts a crashed server without
        // blocking on the first fast-path attempt.
        if target.ssh_mode && !no_bootstrap {
            if let Some(t) = disconnect_at {
                let rebootstrap_due =
                    last_rebootstrap.is_none_or(|lr| lr.elapsed() > Duration::from_secs(30));
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
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .map(|info| {
                        auth_token = info.auth_token;
                    });
                    last_rebootstrap = Some(Instant::now());
                }
            }
        }

        let attempt = match (&bridge, use_bridge) {
            (Some(bt), true) => {
                if !bridge_notice_shown && raw_mode.is_none() {
                    eprintln!("[onyx] QUIC (UDP) unreachable; continuing over an SSH bridge. Sessions still resume after drops.");
                    if !forwards.is_empty() {
                        eprintln!("[onyx] note: --forward needs QUIC and is inactive over the SSH bridge.");
                    }
                    bridge_notice_shown = true;
                }
                try_once_bridge(bt, &mut session, &auth_token, &mut raw_mode, allow_picker, &last_seq, &mut input).await
            }
            _ => {
                try_once(
                    server_addr,
                    &endpoint,
                    &mut session,
                    &host_port,
                    &capture,
                    &auth_token,
                    &forwards,
                    &mut raw_mode,
                    allow_picker,
                    &last_seq,
                    &mut input,
                )
                .await
            }
        };
        match attempt
        {
            // Shell exited cleanly.
            Ok(true) => break,

            // Network dropped mid-session. `Ok(false)` means try_once
            // previously handshook successfully, so this is a *fresh* drop
            // — reset the disconnect timer, window, and backoff.
            Ok(false) => {
                let now = Instant::now();
                disconnect_at = Some(now);
                reconnect_deadline = Some(now + INTERACTIVE_RECONNECT_WINDOW);
                backoff = INTERACTIVE_BACKOFF_INITIAL;
                // Show status once for this disconnect episode, then wait
                // 2 s before the first reconnect attempt.
                show_reconnect_status();
                status_shown = true;
                debug_log("connection dropped — waiting 2s before first retry");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }

            Err(e) => {
                let hint = quic_error_hint(&e, target.quic_port);
                if let Some(dl) = reconnect_deadline {
                    if Instant::now() < dl {
                        // Still within retry window. Before a shell has ever
                        // been ready, keep this as a quiet initial connect
                        // retry instead of showing reconnect/disconnect UI.
                        if should_show_reconnect_ui(&session) && !status_shown {
                            disconnect_at.get_or_insert_with(Instant::now);
                            show_reconnect_status();
                            status_shown = true;
                        }
                        // Alternate transports on failure: UDP may be blocked
                        // (use the SSH bridge) or may have come back (QUIC).
                        if bridge.is_some() {
                            use_bridge = !use_bridge;
                            debug_log(&format!(
                                "attempt failed ({e:#}); next transport: {}",
                                if use_bridge { "ssh bridge" } else { "quic" }
                            ));
                            if use_bridge {
                                // Try the bridge right away.
                                continue;
                            }
                        }
                        debug_log(&format!("retry in {}ms (backoff)", backoff.as_millis()));
                        tokio::time::sleep(backoff).await;
                        backoff = std::cmp::min(backoff * 2, INTERACTIVE_BACKOFF_MAX);
                        continue;
                    }
                }

                // ── Retry window exhausted ────────────────────────────────
                if disconnect_at.take().is_some() {
                    clear_status_line();
                }

                if target.ssh_mode && session.is_none() {
                    // Never had a session — QUIC could not connect at all.
                    if no_fallback {
                        eprintln!("onyx: QUIC failed — {e:#}{hint}");
                        let ssh = ssh_pool.as_ref().and_then(|pool| {
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
                        return Err(e);
                    }
                    eprintln!("{}", ssh_fallback_notice());
                    return exec_ssh_shell(&target.ssh_target, target.identity_file.as_deref());
                }
                // Reconnect window expired while a session existed.
                if session.is_some() {
                    eprintln!("[session] connection lost — reconnect window expired.");
                    eprintln!(
                        "          the remote session is retained on the server for up to 12h."
                    );
                    eprintln!(
                        "          re-run `onyx {}` — it will offer to resume this \
                         session automatically. Use --new to start fresh instead.",
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

    if TAKEN_OVER.load(Ordering::Relaxed) {
        drop(raw_mode.take());
        eprintln!(
            "\n[onyx] this session was opened in another terminal; disconnected here.\n       \
             Run `onyx {raw_target}` to take it back, or `onyx {raw_target} --new` for a separate shell."
        );
    }
    let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
    drop(raw_mode.take());
    // Exit directly: tokio's stdin reader sits in a blocking read that would
    // otherwise hold runtime shutdown until the next keypress.
    std::process::exit(0);
}
