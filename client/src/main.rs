use anyhow::{Context, Result};
use quinn::{ClientConfig, Endpoint};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use shared::{Message, DEFAULT_PORT};
use std::{
    fs,
    io::Write,
    net::SocketAddr,
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

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

/// tmux configuration: dark theme, mouse, 50k scrollback, live metrics bar.
/// Single-quoted style strings avoid Rust raw-string `"#` termination issues.
const ONYX_TMUX_CONF: &str = r#"# onyx — auto-generated, do not edit (overwritten on update)
set -g mouse on
set -g history-limit 50000
set -g status-style                'bg=colour235,fg=colour250'
set -g status-interval             2
set -g status-left                 '#[fg=colour214,bold] * onyx #[fg=colour240,nobold] | '
set -g status-left-length          16
set -g status-right                '#[fg=colour244]#(~/.config/onyx/status.sh)#[fg=colour214] quic '
set -g status-right-length         80
set -g window-status-current-style 'fg=colour214,bold'
set -g pane-border-style           'fg=colour238'
set -g pane-active-border-style    'fg=colour214'
set -g message-style               'bg=colour235,fg=colour214'
"#;

/// Status bar script — runs on the remote server every 2 s inside tmux.
/// Shows GPU (if nvidia-smi present), CPU load, and RAM usage.
const ONYX_STATUS_SH: &str = r#"#!/bin/sh
# onyx status — auto-generated
cpu=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null)
ram=$(free -h 2>/dev/null | awk '/Mem:/{printf "%s/%s", $3, $2}')
gpu=$(nvidia-smi --query-gpu=utilization.gpu,memory.used \
    --format=csv,noheader,nounits 2>/dev/null | head -1 | \
    awk -F', ' '{gsub(/ /,"",$1); printf "gpu %s%%  vram %.0fG  ",$1,$2/1024}')
printf "%scpu %s  ram %s  " "$gpu" "$cpu" "$ram"
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
    cmd: &str,
) -> Result<std::process::Output> {
    ssh_cmd(target, identity).arg(cmd).output().context("ssh")
}

fn check_remote_dir_writable(
    target: &str,
    identity: Option<&str>,
    dir: &str,
) -> Result<(), String> {
    let marker = format!("{dir}/.onyx-write-test-{}", std::process::id());
    let cmd = format!(
        "mkdir -p {dir} && : > {marker} && rm -f {marker}",
        dir = shell_quote(dir),
        marker = shell_quote(&marker),
    );
    let out = ssh_capture_full(target, identity, &cmd).map_err(|e| e.to_string())?;
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

fn resolve_remote_paths(target: &str, identity: Option<&str>) -> Result<RemotePaths> {
    let home =
        ssh_capture(target, identity, "printf %s \"$HOME\"").context("resolving remote HOME")?;
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
        match check_remote_dir_writable(target, identity, candidate) {
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
    let conf_dir = match check_remote_dir_writable(target, identity, &conf_default) {
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
    identity_file: Option<String>,
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
    },
    Proxy {
        target_host: String,
        target_port: u16,
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
        }));
    }

    let mut identity: Option<String> = None;
    let mut target: Option<String> = None;
    let mut no_fallback = false;
    let mut no_bootstrap = false;
    let mut low_bandwidth = false;
    let mut forwards: Vec<(u16, u16)> = Vec::new();

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
  onyx --help | --version

MODES
  Interactive     tmux-backed shell over QUIC; short reconnects resume the
                  same session. Detached sessions are retained server-side
                  for up to 12 hours (in-memory; does not survive
                  onyx-server restart).
  Proxy           stdio-bridged TCP tunnel for use as SSH ProxyCommand.
                  Short transport drops are recovered best-effort within
                  ~2 minutes; longer drops end the underlying SSH session.

INSTALL MODEL
  onyx is a local CLI. On first connect to a host it provisions
  onyx-server on the remote over SSH, preferring a prebuilt binary
  matching the remote arch and falling back to `cargo build --release`
  only if no prebuilt is available. Subsequent connects reuse the
  already-running server.

OPTIONS
  -i <file>                 SSH identity file for bootstrap
  -L, --forward L:R         tunnel localhost:L → remote:R (repeatable)
  --no-bootstrap            skip remote install/start checks
  --no-fallback             exit on QUIC failure instead of falling back to SSH
  --low-bandwidth           smoother batching on poor links
  -h, --help                show this help
  -V, --version             print version

EXAMPLES
  onyx user@host
  onyx dev-server                    # SSH alias from ~/.ssh/config
  onyx --forward 8888:8888 user@host
  onyx proxy host.example.com 22     # behind ProxyCommand in ssh_config
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
            }) => {
                assert_eq!(target_host, "host.example.com");
                assert_eq!(target_port, 22);
            }
            _ => panic!(),
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
            "proxy <host> <port>",
        ] {
            assert!(
                HELP_TEXT.contains(needle),
                "HELP_TEXT missing '{needle}'"
            );
        }
    }
}

/// Use `ssh -G <ssh_target>` to resolve the canonical hostname and user.
/// This honours ~/.ssh/config, ProxyJump, Include directives, etc.
fn resolve_via_ssh_config(ssh_target: &str, identity: Option<&str>) -> Result<(String, String)> {
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

    let text = String::from_utf8_lossy(&out.stdout);
    let mut hostname = String::new();
    let mut user = String::new();

    for line in text.lines() {
        if let Some(v) = line.strip_prefix("hostname ") {
            hostname = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("user ") {
            user = v.trim().to_string();
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

    Ok((hostname, user))
}

/// Build a fully-resolved OnyxTarget from raw CLI args.
fn build_target(raw: &str, identity: Option<String>) -> Result<OnyxTarget> {
    // Strip optional `:quic_port` suffix (rightmost colon followed by digits).
    let (ssh_part, quic_port) = match raw.rfind(':') {
        Some(i) if raw[i + 1..].parse::<u16>().is_ok() => {
            (raw[..i].to_string(), raw[i + 1..].parse::<u16>().unwrap())
        }
        _ => (raw.to_string(), DEFAULT_PORT),
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
        let (quic_host, _user) = resolve_via_ssh_config(&ssh_part, identity.as_deref())
            .with_context(|| format!("resolving '{ssh_part}'"))?;

        Ok(OnyxTarget {
            ssh_target: ssh_part,
            quic_host,
            quic_port,
            identity_file: identity,
            ssh_mode: true,
        })
    } else {
        // Direct: use the IP as-is, no SSH involved.
        Ok(OnyxTarget {
            ssh_target: String::new(),
            quic_host: host_only.to_string(),
            quic_port,
            identity_file: identity,
            ssh_mode: false,
        })
    }
}

// ---------------------------------------------------------------------------
// SSH helpers — all take `ssh_target` (the verbatim alias/address accepted by
// `ssh`) plus an optional identity file path.
// ---------------------------------------------------------------------------

fn ssh_cmd(target: &str, identity: Option<&str>) -> std::process::Command {
    let mut c = std::process::Command::new("ssh");
    // -T: never allocate a pseudo-terminal for these non-interactive bootstrap
    //     commands.  Without it SSH prints "Pseudo-terminal will not be
    //     allocated because stdin is not a terminal." as noise on every run.
    c.arg("-T");
    if let Some(id) = identity {
        c.args(["-i", id]);
    }
    c.arg(target);
    c
}

/// Run remote command; return trimmed stdout.  Stderr is suppressed — we only
/// care about the output, not SSH banners or pseudo-terminal warnings.
fn ssh_capture(target: &str, identity: Option<&str>, cmd: &str) -> Result<String> {
    let out = ssh_cmd(target, identity)
        .arg(cmd)
        .stderr(std::process::Stdio::null())
        .output()
        .context("ssh")?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Run remote command; inherit stdout + stderr (shows build output, etc.).
fn ssh_show(target: &str, identity: Option<&str>, cmd: &str) -> Result<()> {
    let st = ssh_cmd(target, identity).arg(cmd).status().context("ssh")?;
    if !st.success() {
        if st.code() == Some(255) {
            anyhow::bail!("SSH authentication failed for '{target}'");
        }
        anyhow::bail!("remote command failed (exit {})", st.code().unwrap_or(-1));
    }
    Ok(())
}

/// Upload bytes to `remote_path` by piping into `cat > path` over SSH.
fn ssh_upload(
    target: &str,
    identity: Option<&str>,
    remote_path: &str,
    content: &[u8],
) -> Result<()> {
    let parent = std::path::Path::new(remote_path)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("remote path has no parent: {remote_path}"))?;
    let parent = parent.display().to_string();
    let mkdir = ssh_cmd(target, identity)
        .arg(format!("mkdir -p {}", shell_quote(&parent)))
        .stderr(std::process::Stdio::piped())
        .output()
        .context("creating remote upload directory")?;
    if !mkdir.status.success() {
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

    let mut child = ssh_cmd(target, identity)
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

    let verify = ssh_cmd(target, identity)
        .arg(format!("test -f {}", shell_quote(remote_path)))
        .stderr(std::process::Stdio::piped())
        .output()
        .context("verifying remote upload")?;
    if !verify.status.success() {
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
    has_cargo: bool, // ~/.cargo/bin/cargo exists
    conf_ok: bool,   // tmux config + status script are current
    arch: String,    // uname -m on the remote host
}

/// Single SSH round-trip: verifies auth and gathers all bootstrap pre-conditions.
/// Returns Err on SSH auth failure or connection error.
fn remote_status(
    target: &str,
    identity: Option<&str>,
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
         c=no; [ -f ~/.cargo/bin/cargo ] && c=yes; \
         arch=$(uname -m 2>/dev/null || echo unknown); \
         cv=$(cat {conf_dir}/.conf-hash 2>/dev/null); \
         echo \"h=$h r=$r own=$own ready=$ready c=$c arch=$arch cv=$cv\"",
        server_log = shell_quote(&format!("{}/server.log", paths.remote_dir)),
        remote_dir = shell_quote(&paths.remote_dir),
        conf_dir = shell_quote(&paths.conf_dir),
    );

    let out = ssh_cmd(target, identity)
        .arg(&script)
        .stderr(std::process::Stdio::null())
        .output()
        .context("failed to run ssh")?;

    if !out.status.success() {
        if out.status.code() == Some(255) {
            anyhow::bail!(
                "SSH authentication failed for '{}' — check your key/credentials",
                target
            );
        }
        anyhow::bail!(
            "SSH connection failed (exit {})",
            out.status.code().unwrap_or(-1)
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
fn ensure_config_files(target: &str, identity: Option<&str>, paths: &RemotePaths) -> Result<()> {
    let conf_hash = format!("{:016x}", config_hash());
    let _ = ssh_capture(
        target,
        identity,
        &format!(
            "mkdir -p {conf_dir} && chmod 700 {conf_dir}",
            conf_dir = shell_quote(&paths.conf_dir)
        ),
    );
    ssh_upload(
        target,
        identity,
        &format!("{}/tmux.conf", paths.conf_dir),
        ONYX_TMUX_CONF.as_bytes(),
    )?;
    ssh_upload(
        target,
        identity,
        &format!("{}/status.sh", paths.conf_dir),
        ONYX_STATUS_SH.as_bytes(),
    )?;
    let conf_hash_path = format!("{}/.conf-hash", paths.conf_dir);
    let _ = ssh_capture(
        target,
        identity,
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

fn ensure_rust(target: &str, identity: Option<&str>) -> Result<()> {
    eprintln!("  installing Rust via rustup...");
    ssh_show(
        target,
        identity,
        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
         | sh -s -- -y --no-modify-path",
    )
    .context("Rust installation failed on remote")?;
    eprintln!("  Rust installed");
    Ok(())
}

fn server_artifact_name(remote_arch: &str) -> Option<&'static str> {
    match remote_arch {
        "x86_64" | "amd64" => Some("onyx-server-linux-x86_64"),
        "aarch64" | "arm64" => Some("onyx-server-linux-arm64"),
        _ => None,
    }
}

fn prebuilt_server_candidates(remote_arch: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Some(name) = server_artifact_name(remote_arch) else {
        return out;
    };

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(dir.join(name));
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        out.push(cwd.join(name));
        out.push(cwd.join("target").join("release").join("onyx-server"));
        match remote_arch {
            "x86_64" | "amd64" => out.push(
                cwd.join("target")
                    .join("x86_64-unknown-linux-musl")
                    .join("release")
                    .join("onyx-server"),
            ),
            "aarch64" | "arm64" => out.push(
                cwd.join("target")
                    .join("aarch64-unknown-linux-musl")
                    .join("release")
                    .join("onyx-server"),
            ),
            _ => {}
        }
    }

    out
}

fn find_local_prebuilt_server(remote_arch: &str) -> Option<PathBuf> {
    prebuilt_server_candidates(remote_arch)
        .into_iter()
        .find(|path| path.is_file())
}

fn bootstrap_error_with_help(err: anyhow::Error) -> anyhow::Error {
    anyhow::anyhow!(
        "{}\nnext steps:\n  set ONYX_REMOTE_DIR to a writable absolute path on the remote host\n  or install/start onyx-server manually and re-run with --no-bootstrap",
        err
    )
}

fn upload_and_build(
    target: &str,
    identity: Option<&str>,
    paths: &RemotePaths,
) -> Result<()> {
    eprintln!("  uploading source...");
    ssh_show(
        target,
        identity,
        &format!(
            "mkdir -p {remote_dir}/shared/src {remote_dir}/server/src && chmod 700 {remote_dir}",
            remote_dir = shell_quote(&paths.remote_dir)
        ),
    )?;

    ssh_upload(
        target,
        identity,
        &format!("{}/Cargo.toml", paths.remote_dir),
        REMOTE_WORKSPACE_TOML.as_bytes(),
    )?;
    ssh_upload(
        target,
        identity,
        &format!("{}/shared/Cargo.toml", paths.remote_dir),
        SHARED_CARGO_TOML.as_bytes(),
    )?;
    ssh_upload(
        target,
        identity,
        &format!("{}/shared/src/lib.rs", paths.remote_dir),
        SHARED_LIB_RS.as_bytes(),
    )?;
    ssh_upload(
        target,
        identity,
        &format!("{}/server/Cargo.toml", paths.remote_dir),
        SERVER_CARGO_TOML.as_bytes(),
    )?;
    ssh_upload(
        target,
        identity,
        &format!("{}/server/src/main.rs", paths.remote_dir),
        SERVER_MAIN_RS.as_bytes(),
    )?;

    eprintln!("  building onyx-server (this takes a minute on first run)...");
    // Build into the workspace's target/ as usual, then stage the resulting
    // binary at onyx-server.new. We deliberately do NOT overwrite the live
    // onyx-server path here — that triggers ETXTBSY ("Text file busy") if
    // the old server is still running. The atomic install step below takes
    // care of the actual swap.
    ssh_show(
        target,
        identity,
        &format!(
            "cd {} && ~/.cargo/bin/cargo build --release -p server 2>&1 && \
             cp target/release/onyx-server onyx-server.new",
            shell_quote(&paths.remote_dir)
        ),
    )?;
    eprintln!("  build complete");
    Ok(())
}

fn upload_prebuilt_server(
    target: &str,
    identity: Option<&str>,
    remote_arch: &str,
    paths: &RemotePaths,
) -> Result<bool> {
    let Some(local_binary) = find_local_prebuilt_server(remote_arch) else {
        return Ok(false);
    };

    let binary_name = server_artifact_name(remote_arch).unwrap_or("onyx-server");
    eprintln!("  uploading prebuilt onyx-server ({binary_name})...");
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
    ssh_upload(target, identity, &staging, &bytes)?;
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

    ssh_show(target, identity, &script).map_err(classify_install_error)
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
    quic_port: u16,
    paths: &RemotePaths,
) -> Result<()> {
    let server_pid = format!("{}/server.pid", paths.remote_dir);
    let server_log = format!("{}/server.log", paths.remote_dir);
    let remote_dir = shell_quote(&paths.remote_dir);
    let status = remote_status(target, identity, "", quic_port, paths)?;

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
        eprintln!("  starting onyx-server...");
    }

    // Kill stale instance + give OS a moment to release the UDP socket.
    if status.own_pid {
        let _ = ssh_capture(
            target,
            identity,
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
        &format!(": > {} 2>/dev/null; true", shell_quote(&server_log)),
    );

    ssh_show(
        target,
        identity,
        &format!(
            "nohup {remote_dir}/onyx-server \
         >{server_log} 2>&1 </dev/null & \
         printf %s \"$!\" > {server_pid} && \
         chmod 600 {server_pid} {server_log}",
            server_pid = shell_quote(&server_pid),
            server_log = shell_quote(&server_log),
            remote_dir = remote_dir
        ),
    )?;

    // Poll server.log for "listening on" — confirms the UDP socket is bound.
    // Checks every 500 ms for up to 10 s.
    let ready = (0..20).any(|_| {
        std::thread::sleep(Duration::from_millis(500));
        ssh_capture(
            target,
            identity,
            &format!(
                "grep -q 'listening on' {} 2>/dev/null && echo yes",
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
            &format!("tail -20 {} 2>/dev/null", shell_quote(&server_log)),
        ) {
            if !log.is_empty() {
                eprintln!("[onyx] server.log:\n{log}");
            }
        }
        if let Ok(err) = ssh_capture(
            target,
            identity,
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
// Bootstrap — entry point called once before the QUIC loop
// ---------------------------------------------------------------------------

fn bootstrap(ssh_target: &str, identity: Option<&str>, quic_port: u16) -> Result<()> {
    let hash = format!("{:016x}", source_hash());
    let paths = resolve_remote_paths(ssh_target, identity).map_err(bootstrap_error_with_help)?;

    // Single SSH call: verify auth + get all state.
    let status = remote_status(ssh_target, identity, &hash, quic_port, &paths)
        .context("cannot reach remote")
        .map_err(bootstrap_error_with_help)?;

    // ── Fast path ─────────────────────────────────────────────────────────────
    if status.hash_ok && status.healthy && status.conf_ok {
        return Ok(());
    }

    // Config files stale but server is running — just push the new files.
    if status.hash_ok && status.healthy && !status.conf_ok {
        ensure_config_files(ssh_target, identity, &paths).map_err(bootstrap_error_with_help)?;
        return Ok(());
    }

    // ── Slow path ────────────────────────────────────────────────────────────
    eprintln!("[onyx] setting up remote (one-time or after update)...");

    if !status.hash_ok {
        let used_prebuilt = upload_prebuilt_server(ssh_target, identity, &status.arch, &paths)
            .map_err(bootstrap_error_with_help)?;

        if !used_prebuilt {
            eprintln!(
                "  no local prebuilt onyx-server for remote arch {}; falling back to cargo build",
                status.arch
            );
            if !status.has_cargo {
                ensure_rust(ssh_target, identity).map_err(bootstrap_error_with_help)?;
            }
            upload_and_build(ssh_target, identity, &paths).map_err(bootstrap_error_with_help)?;
        }

        // Atomically stop the old onyx-server (if any), swap in the new
        // binary via mv, and update the hash stamp. Must run after upload
        // and before start_server.
        install_staged_server_binary(ssh_target, identity, &hash, &status, &paths)
            .map_err(bootstrap_error_with_help)?;
    }

    ensure_config_files(ssh_target, identity, &paths).map_err(bootstrap_error_with_help)?;
    start_server(ssh_target, identity, quic_port, &paths).map_err(bootstrap_error_with_help)?;

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
) -> Result<quinn::Connection> {
    *capture.lock().unwrap() = None;

    let connecting = endpoint
        .connect(server_addr, "localhost")
        .context("creating QUIC connection")?;
    let conn = tokio::time::timeout(Duration::from_secs(5), connecting)
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "QUIC handshake timed out after 5 s (no response from {}; \
                 UDP/{} may be blocked by the server firewall)",
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
) -> Result<(quinn::Connection, quinn::SendStream, quinn::RecvStream)> {
    let conn = connect_authenticated(server_addr, endpoint, host_port, capture).await?;
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

async fn run_proxy_mode(target_host: String, target_port: u16) -> Result<()> {
    let target = build_target(&target_host, None)
        .with_context(|| format!("resolving target '{target_host}'"))?;
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
            Err(e) => return Err(e),
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
    let conn = connect_authenticated(server_addr, endpoint, host_port, capture).await?;

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
        } => (session_id, resume_token),
        Message::Close { reason } => {
            eprintln!("[client] server rejected: {reason}");
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

    let _raw = RawMode::enter();

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
    if let CliMode::Proxy {
        target_host,
        target_port,
    } = cli_mode
    {
        return run_proxy_mode(target_host, target_port).await;
    }

    let CliMode::Interactive {
        raw_target,
        identity_file,
        no_fallback,
        no_bootstrap,
        low_bandwidth,
        forwards,
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
    let target = build_target(&raw_target, identity_file)
        .with_context(|| format!("resolving target '{raw_target}'"))?;

    // SSH bootstrap (blocking, single SSH call on fast path).
    if target.ssh_mode && !no_bootstrap {
        bootstrap(
            &target.ssh_target,
            target.identity_file.as_deref(),
            target.quic_port,
        )
        .context("bootstrap failed")?;
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
        Some(Instant::now() + Duration::from_secs(30))
    } else {
        None
    };
    // Set when we first lose a connection; cleared when we give up or reconnect.
    let mut disconnect_at: Option<Instant> = None;
    // Tracks when we last re-ran bootstrap during a reconnect window so we
    // don't hammer SSH on every retry but do re-open the firewall / restart
    // a crashed server after a reasonable delay.
    let mut last_rebootstrap: Option<Instant> = None;

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
                    let port = target.quic_port;
                    let _ = tokio::task::spawn_blocking(move || {
                        bootstrap(&ssh_target, identity.as_deref(), port)
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

            // Network dropped mid-session.
            Ok(false) => {
                let t = *disconnect_at.get_or_insert_with(Instant::now);
                reconnect_deadline = Some(Instant::now() + Duration::from_secs(300));
                reconnect_banner(t, Duration::from_secs(2)).await;
            }

            Err(e) => {
                let hint = quic_error_hint(&e);
                if let Some(dl) = reconnect_deadline {
                    if Instant::now() < dl {
                        // Still within retry window — show banner and try again.
                        let t = *disconnect_at.get_or_insert_with(Instant::now);
                        reconnect_banner(t, Duration::from_secs(2)).await;
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
                    if let Ok(log) = ssh_capture(
                        &target.ssh_target,
                        target.identity_file.as_deref(),
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
                    eprintln!("  falling back to plain SSH…");
                    let mut cmd = std::process::Command::new("ssh");
                    cmd.args(["-tt", "-q", "-o", "SetEnv ONYX_MODE=ssh"]);
                    if let Some(id) = &target.identity_file {
                        cmd.args(["-i", id]);
                    }
                    cmd.arg(&target.ssh_target);
                    return Err(anyhow::anyhow!("exec ssh: {}", cmd.exec()));
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
