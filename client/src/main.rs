use anyhow::{Context, Result};
use quinn::{ClientConfig, Endpoint};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use shared::{Message, DEFAULT_PORT};
use std::{io::Write, net::SocketAddr, os::unix::process::CommandExt, sync::{Arc, Mutex}, time::{Duration, Instant}};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------------------
// Source files embedded at compile time for remote bootstrap.
// ---------------------------------------------------------------------------

const REMOTE_WORKSPACE_TOML: &str =
    "[workspace]\nmembers = [\"shared\", \"server\"]\nresolver = \"2\"\n";

const SHARED_CARGO_TOML: &str  = include_str!("../../shared/Cargo.toml");
const SHARED_LIB_RS: &str      = include_str!("../../shared/src/lib.rs");
const SERVER_CARGO_TOML: &str  = include_str!("../../server/Cargo.toml");
const SERVER_MAIN_RS: &str     = include_str!("../../server/src/main.rs");

const REMOTE_DIR: &str  = "~/.local/share/onyx";
const CONF_DIR: &str    = "~/.config/onyx";

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
    format!("sha256:{}", hash.as_ref().iter().map(|b| format!("{b:02x}")).collect::<String>())
}

type FpCapture = Arc<Mutex<Option<String>>>;

/// Accepts every cert during the TLS handshake and captures the fingerprint.
/// The actual TOFU check happens after the handshake completes, before any
/// application data is sent (see check_known_hosts in try_once).
#[derive(Debug)]
struct CapturingVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    capture:  FpCapture,
}

impl CapturingVerifier {
    fn new(capture: FpCapture) -> Arc<Self> {
        Arc::new(Self { provider: Arc::new(rustls::crypto::ring::default_provider()), capture })
    }
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>],
        _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error>
    {
        *self.capture.lock().unwrap() = Some(cert_fingerprint(end_entity.as_ref()));
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error>
    { rustls::crypto::verify_tls12_signature(message, cert, dss,
        &self.provider.signature_verification_algorithms) }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error>
    { rustls::crypto::verify_tls13_signature(message, cert, dss,
        &self.provider.signature_verification_algorithms) }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
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

/// TOFU check run after every QUIC handshake, before any application data.
///
/// - **Known + match**    → silent Ok.
/// - **Known + mismatch** → print warning block, Err (hard fail).
/// - **New host**         → SSH-style interactive prompt; saves on yes, Err on no.
async fn check_known_hosts(host_port: &str, remote_fp: &str) -> Result<()> {
    let path    = known_hosts_path();
    let content = std::fs::read_to_string(&path).unwrap_or_default();

    for line in content.lines() {
        let mut it = line.splitn(2, ' ');
        let key = it.next().unwrap_or("");
        let fp  = it.next().unwrap_or("");
        if key != host_port { continue; }

        if fp == remote_fp { return Ok(()); } // known + matches

        // ── Fingerprint mismatch ─────────────────────────────────────────────
        eprintln!();
        eprintln!("\x1b[31;1m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\x1b[0m");
        eprintln!("\x1b[31;1m@   WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!   @\x1b[0m");
        eprintln!("\x1b[31;1m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\x1b[0m");
        eprintln!();
        eprintln!("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
        eprintln!("The onyx server at \x1b[1m{host_port}\x1b[0m presented a different certificate.");
        eprintln!("  stored:   {fp}");
        eprintln!("  received: {remote_fp}");
        eprintln!();
        eprintln!("If you rebuilt the server, remove the old entry with:");
        eprintln!("  sed -i '/{}/d' {}", host_port.replace('/', r"\/"), path.display());
        anyhow::bail!("host key verification failed for {host_port}");
    }

    // ── New host — interactive Trust On First Use ────────────────────────────
    eprintln!("The authenticity of host '{}' can't be established.", host_port);
    eprintln!("SHA256 fingerprint: {remote_fp}");
    eprint!("Are you sure you want to continue connecting (yes/no)? ");
    std::io::stderr().flush().ok();

    let answer = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok();
        line.trim().to_lowercase()
    }).await.unwrap_or_default();

    if answer != "yes" {
        anyhow::bail!("Host key verification failed.");
    }

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path)
        .context("opening known_hosts")?;
    writeln!(f, "{host_port} {remote_fp}").context("writing known_hosts")?;
    eprintln!("Warning: Permanently added '{}' ({remote_fp}) to the list of known hosts.", host_port);

    Ok(())
}

// ---------------------------------------------------------------------------
// Message framing
// ---------------------------------------------------------------------------

async fn send_msg(stream: &mut quinn::SendStream, msg: &Message) -> Result<()> {
    let payload = shared::encode(msg)?;
    stream.write_all(&(payload.len() as u32).to_le_bytes()).await?;
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
    let s = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    format!("{s:x}-{:x}", std::process::id())
}

fn get_terminal_size() -> (u16, u16) {
    let mut ws = libc::winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
    unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ as _, &mut ws) };
    (ws.ws_col, ws.ws_row)
}

struct RawMode { saved: libc::termios }

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

/// Parse CLI arguments; return (raw_target, identity_file, no_fallback).
fn parse_args() -> (String, Option<String>, bool) {
    let mut args = std::env::args().skip(1).peekable();
    let mut identity: Option<String> = None;
    let mut target: Option<String> = None;
    let mut no_fallback = false;

    while let Some(a) = args.next() {
        if a == "-i" {
            identity = args.next().or_else(|| {
                eprintln!("onyx: -i requires an argument");
                std::process::exit(1);
            });
        } else if a == "--no-fallback" {
            no_fallback = true;
        } else if target.is_none() {
            target = Some(a);
        } else {
            eprintln!("onyx: unexpected argument: {a}");
            std::process::exit(1);
        }
    }

    let target = target.unwrap_or_else(|| {
        eprintln!("Usage: onyx [--no-fallback] [-i identity_file] [user@]<host>[:<quic-port>]");
        eprintln!("  hetzner-dev                   SSH alias → bootstrap + QUIC");
        eprintln!("  user@host[:port]              SSH bootstrap + QUIC");
        eprintln!("  128.140.63.67[:port]          direct QUIC (no SSH)");
        eprintln!("  --no-fallback                 exit on QUIC failure instead of falling back to SSH");
        std::process::exit(1);
    });

    (target, identity, no_fallback)
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

    anyhow::ensure!(!hostname.is_empty(),
        "ssh -G returned no hostname for '{ssh_target}'; \
         check your SSH config or try a full user@host address");

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
        None    => &ssh_part,
    };

    // Direct mode only when the host is a bare IP address and there is no '@'.
    // Everything else (hostnames, aliases, user@anything) uses SSH mode.
    let has_at   = ssh_part.contains('@');
    let is_ip    = host_only.parse::<std::net::IpAddr>().is_ok();
    let ssh_mode = has_at || !is_ip;

    if ssh_mode {
        // Resolve through SSH config to get the real hostname for QUIC.
        let (quic_host, _user) =
            resolve_via_ssh_config(&ssh_part, identity.as_deref())
                .with_context(|| format!("resolving '{ssh_part}'"))?;

        Ok(OnyxTarget { ssh_target: ssh_part, quic_host, quic_port, identity_file: identity, ssh_mode: true })
    } else {
        // Direct: use the IP as-is, no SSH involved.
        Ok(OnyxTarget {
            ssh_target: String::new(),
            quic_host:  host_only.to_string(),
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
    let st = ssh_cmd(target, identity)
        .arg(cmd)
        .status()
        .context("ssh")?;
    if !st.success() {
        if st.code() == Some(255) {
            anyhow::bail!("SSH authentication failed for '{target}'");
        }
        anyhow::bail!("remote command failed (exit {})", st.code().unwrap_or(-1));
    }
    Ok(())
}


/// Upload bytes to `remote_path` by piping into `cat > path` over SSH.
/// Path uses `~` which the remote shell expands — do not quote it.
fn ssh_upload(target: &str, identity: Option<&str>, remote_path: &str, content: &[u8]) -> Result<()> {
    let mut child = ssh_cmd(target, identity)
        .arg(format!("cat > {remote_path}"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("ssh upload")?;

    if let Some(mut s) = child.stdin.take() {
        s.write_all(content).context("writing to ssh stdin")?;
    }
    let st = child.wait()?;
    anyhow::ensure!(st.success(), "ssh upload to {remote_path} failed");
    Ok(())
}

// ---------------------------------------------------------------------------
// Bootstrap steps
// ---------------------------------------------------------------------------

/// FNV-1a hash of all embedded server source files.
/// Used to detect when the local source has changed so we rebuild automatically.
fn source_hash() -> u64 {
    const OFFSET: u64 = 14695981039346656037;
    const PRIME:  u64 = 1099511628211;
    let mut h = OFFSET;
    for b in SERVER_MAIN_RS.bytes()
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
    const PRIME:  u64 = 1099511628211;
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
    hash_ok:   bool,   // remote .server-hash == current source hash
    running:   bool,   // onyx-server process is alive
    has_cargo: bool,   // ~/.cargo/bin/cargo exists
    conf_ok:   bool,   // tmux config + status script are current
}

/// Single SSH round-trip: verifies auth and gathers all bootstrap pre-conditions.
/// Returns Err on SSH auth failure or connection error.
fn remote_status(target: &str, identity: Option<&str>, expected_hash: &str, quic_port: u16)
    -> Result<RemoteStatus>
{
    let conf_hash = format!("{:016x}", config_hash());
    // Everything in one shell snippet — one TCP+crypto handshake total.
    let script = format!(
        "h=$(cat {REMOTE_DIR}/.server-hash 2>/dev/null); \
         p=$(cat {REMOTE_DIR}/server.pid   2>/dev/null); \
         r=no; [ -n \"$p\" ] && kill -0 \"$p\" 2>/dev/null && r=yes; \
         c=no; [ -f ~/.cargo/bin/cargo ] && c=yes; \
         cv=$(cat {CONF_DIR}/.conf-hash 2>/dev/null); \
         sudo ufw allow {quic_port}/udp >/dev/null 2>&1; \
         sudo iptables -C INPUT -p udp --dport {quic_port} -j ACCEPT 2>/dev/null || \
         sudo iptables -I INPUT -p udp --dport {quic_port} -j ACCEPT 2>/dev/null; \
         echo \"h=$h r=$r c=$c cv=$cv\""
    );

    let out = ssh_cmd(target, identity)
        .arg(&script)
        .stderr(std::process::Stdio::null())
        .output()
        .context("failed to run ssh")?;

    if !out.status.success() {
        if out.status.code() == Some(255) {
            anyhow::bail!(
                "SSH authentication failed for '{}' — check your key/credentials", target
            );
        }
        anyhow::bail!("SSH connection failed (exit {})", out.status.code().unwrap_or(-1));
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let get  = |key: &str| -> String {
        text.split_whitespace()
            .find(|kv| kv.starts_with(&format!("{key}=")))
            .and_then(|kv| kv.splitn(2, '=').nth(1))
            .unwrap_or("")
            .to_string()
    };

    Ok(RemoteStatus {
        hash_ok:   get("h") == expected_hash,
        running:   get("r") == "yes",
        has_cargo: get("c") == "yes",
        conf_ok:   get("cv") == conf_hash,
    })
}

// ---------------------------------------------------------------------------
// Config file helpers — tmux.conf + status.sh
// ---------------------------------------------------------------------------

/// Upload tmux.conf and status.sh to CONF_DIR and record the config hash.
/// Only called when config_hash() doesn't match the remote, so it's rare.
fn ensure_config_files(target: &str, identity: Option<&str>) -> Result<()> {
    let conf_hash = format!("{:016x}", config_hash());
    let _ = ssh_capture(target, identity, &format!("mkdir -p {CONF_DIR}"));
    ssh_upload(target, identity, &format!("{CONF_DIR}/tmux.conf"),  ONYX_TMUX_CONF.as_bytes())?;
    ssh_upload(target, identity, &format!("{CONF_DIR}/status.sh"),  ONYX_STATUS_SH.as_bytes())?;
    let _ = ssh_capture(target, identity,
        &format!("chmod +x {CONF_DIR}/status.sh && \
                  echo '{conf_hash}' > {CONF_DIR}/.conf-hash"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Slow-path helpers — only called when something needs installing/building
// ---------------------------------------------------------------------------

fn ensure_rust(target: &str, identity: Option<&str>) -> Result<()> {
    eprintln!("  installing Rust via rustup...");
    ssh_show(target, identity,
        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
         | sh -s -- -y --no-modify-path")
        .context("Rust installation failed on remote")?;
    eprintln!("  Rust installed");
    Ok(())
}

fn upload_and_build(target: &str, identity: Option<&str>, hash: &str) -> Result<()> {
    eprintln!("  uploading source...");
    ssh_show(target, identity,
        &format!("mkdir -p {REMOTE_DIR}/shared/src {REMOTE_DIR}/server/src"))?;

    ssh_upload(target, identity, &format!("{REMOTE_DIR}/Cargo.toml"),         REMOTE_WORKSPACE_TOML.as_bytes())?;
    ssh_upload(target, identity, &format!("{REMOTE_DIR}/shared/Cargo.toml"),  SHARED_CARGO_TOML.as_bytes())?;
    ssh_upload(target, identity, &format!("{REMOTE_DIR}/shared/src/lib.rs"),  SHARED_LIB_RS.as_bytes())?;
    ssh_upload(target, identity, &format!("{REMOTE_DIR}/server/Cargo.toml"),  SERVER_CARGO_TOML.as_bytes())?;
    ssh_upload(target, identity, &format!("{REMOTE_DIR}/server/src/main.rs"), SERVER_MAIN_RS.as_bytes())?;

    eprintln!("  building onyx-server (this takes a minute on first run)...");
    ssh_show(target, identity,
        &format!("cd {REMOTE_DIR} && ~/.cargo/bin/cargo build --release -p server 2>&1"))?;
    eprintln!("  build complete");

    let _ = ssh_capture(target, identity,
        &format!("echo '{hash}' > {REMOTE_DIR}/.server-hash"));
    Ok(())
}

fn start_server(target: &str, identity: Option<&str>) -> Result<()> {
    eprintln!("  starting onyx-server...");

    // Kill stale instance + give OS a moment to release the UDP socket.
    let _ = ssh_capture(target, identity, &format!(
        "pid=$(cat {REMOTE_DIR}/server.pid 2>/dev/null); \
         [ -n \"$pid\" ] && kill \"$pid\" 2>/dev/null; \
         pkill -f onyx-server 2>/dev/null; \
         sleep 0.5; true"
    ));

    // Clear old log so the readiness poll only sees fresh output.
    let _ = ssh_capture(target, identity,
        &format!(": > {REMOTE_DIR}/server.log 2>/dev/null; true"));

    ssh_show(target, identity, &format!(
        "nohup {REMOTE_DIR}/target/release/onyx-server \
         >{REMOTE_DIR}/server.log 2>&1 </dev/null & \
         echo $! > {REMOTE_DIR}/server.pid"
    ))?;

    // Poll server.log for "listening on" — confirms the UDP socket is bound.
    // Checks every 500 ms for up to 10 s.
    let ready = (0..20).any(|_| {
        std::thread::sleep(Duration::from_millis(500));
        ssh_capture(target, identity, &format!(
            "grep -q 'listening on' {REMOTE_DIR}/server.log 2>/dev/null && echo yes"
        )).map(|s| s == "yes").unwrap_or(false)
    });

    if !ready {
        if let Ok(log) = ssh_capture(target, identity,
                &format!("tail -20 {REMOTE_DIR}/server.log 2>/dev/null")) {
            if !log.is_empty() {
                eprintln!("[onyx] server.log:\n{log}");
            }
        }
        anyhow::bail!(
            "onyx-server failed to start — see {REMOTE_DIR}/server.log on the remote host"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bootstrap — entry point called once before the QUIC loop
// ---------------------------------------------------------------------------

fn bootstrap(ssh_target: &str, identity: Option<&str>, quic_port: u16) -> Result<()> {
    let hash = format!("{:016x}", source_hash());

    // Single SSH call: verify auth + get all state.
    let status = remote_status(ssh_target, identity, &hash, quic_port)
        .context("cannot reach remote")?;

    // ── Fast path ─────────────────────────────────────────────────────────────
    if status.hash_ok && status.running && status.conf_ok {
        return Ok(());
    }

    // Config files stale but server is running — just push the new files.
    if status.hash_ok && status.running && !status.conf_ok {
        ensure_config_files(ssh_target, identity)?;
        return Ok(());
    }

    // ── Slow path ────────────────────────────────────────────────────────────
    eprintln!("[onyx] setting up remote (one-time or after update)...");

    if !status.has_cargo {
        ensure_rust(ssh_target, identity)?;
    }

    if !status.hash_ok {
        upload_and_build(ssh_target, identity, &hash)?;
    }

    ensure_config_files(ssh_target, identity)?;
    start_server(ssh_target, identity)?;

    eprintln!("[onyx] ready");
    Ok(())
}

// ---------------------------------------------------------------------------
// Single connection attempt + I/O loop
// ---------------------------------------------------------------------------

async fn try_once(
    server_addr: SocketAddr,
    endpoint:    &Endpoint,
    session:     &mut Option<(String, String)>,
    host_port:   &str,
    capture:     &FpCapture,
) -> Result<bool> {
    // Clear any fingerprint left over from a previous attempt.
    *capture.lock().unwrap() = None;

    let connecting = endpoint.connect(server_addr, "localhost")
        .context("creating QUIC connection")?;
    let conn = tokio::time::timeout(Duration::from_secs(5), connecting)
        .await
        .map_err(|_| anyhow::anyhow!(
            "QUIC handshake timed out after 5 s (no response from {}; \
             UDP/{} may be blocked by the server firewall)",
            server_addr, server_addr.port()
        ))?
        .map_err(|e| anyhow::anyhow!("QUIC handshake failed: {e:#}"))?;

    // TOFU check — happens before any application data is sent.
    // The verifier captured the cert fingerprint during the TLS handshake.
    let fp = capture.lock().unwrap().clone()
        .ok_or_else(|| anyhow::anyhow!("TLS verifier did not capture a fingerprint"))?;
    check_known_hosts(host_port, &fp).await?;

    let (mut send, mut recv) = conn.open_bi().await.context("open_bi")?;

    let is_resume = session.is_some();
    match session.as_ref() {
        None => {
            send_msg(&mut send, &Message::Hello {
                session_id: new_session_id(),
                resume_token: String::new(),
            }).await?;
        }
        Some((sid, tok)) => {
            send_msg(&mut send, &Message::Resume {
                session_id: sid.clone(),
                resume_token: tok.clone(),
                last_seq: 0,
            }).await?;
        }
    }

    let (session_id, resume_token) = match recv_msg(&mut recv).await? {
        Message::Welcome { session_id, resume_token } => (session_id, resume_token),
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
            enum Ev { Data(std::io::Result<usize>), Winch }

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
                    // Drain any additional input arriving within 5 ms (paste batching).
                    // Normal typing never triggers this window; pastes arrive as a burst.
                    let deadline = tokio::time::Instant::now() + Duration::from_millis(5);
                    loop {
                        match tokio::time::timeout_at(deadline, stdin.read(&mut buf)).await {
                            Ok(Ok(m)) if m > 0 => data.extend_from_slice(&buf[..m]),
                            _ => break,
                        }
                    }
                    if send_msg(&mut send, &Message::Input { data }).await.is_err() { break; }
                }
                Ev::Winch => {
                    let (cols, rows) = get_terminal_size();
                    if send_msg(&mut send, &Message::Resize { cols, rows }).await.is_err() { break; }
                }
            }
        }
    });

    let mut output_jh = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        loop {
            match recv_msg(&mut recv).await {
                Ok(Message::Output { data, .. }) => {
                    if stdout.write_all(&data).await.is_err() { break false; }
                    let _ = stdout.flush().await;
                }
                Ok(Message::Close { .. }) => {
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
    rustls::crypto::ring::default_provider().install_default().ok();

    let (raw_target, identity_file, no_fallback) = parse_args();

    // Resolve the target — runs `ssh -G <target>` for SSH aliases to get the
    // canonical hostname; the unresolved alias is kept only for SSH commands.
    let target = build_target(&raw_target, identity_file)
        .with_context(|| format!("resolving target '{raw_target}'"))?;

    // SSH bootstrap (blocking, single SSH call on fast path).
    if target.ssh_mode {
        bootstrap(&target.ssh_target, target.identity_file.as_deref(), target.quic_port)
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

    let mut session:            Option<(String, String)> = None;
    let mut reconnect_deadline: Option<Instant>          = if target.ssh_mode {
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
        // This re-opens iptables rules that were flushed and restarts the
        // server if it crashed — without blocking on the first fast-path attempt.
        if target.ssh_mode {
            if let Some(t) = disconnect_at {
                let rebootstrap_due = last_rebootstrap
                    .map_or(true, |lr| lr.elapsed() > Duration::from_secs(30));
                if t.elapsed() > Duration::from_secs(20) && rebootstrap_due {
                    let ssh_target = target.ssh_target.clone();
                    let identity   = target.identity_file.clone();
                    let port       = target.quic_port;
                    let _ = tokio::task::spawn_blocking(move || {
                        bootstrap(&ssh_target, identity.as_deref(), port)
                    }).await;
                    last_rebootstrap = Some(Instant::now());
                }
            }
        }

        match try_once(server_addr, &endpoint, &mut session, &host_port, &capture).await {
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
                        &target.ssh_target, target.identity_file.as_deref(),
                        &format!("cat {REMOTE_DIR}/server.log 2>/dev/null"),
                    ) {
                        if log.is_empty() {
                            eprintln!("  server.log is empty — server may not have started");
                        } else {
                            for line in log.lines() { eprintln!("  {line}"); }
                            if log.contains("incoming from") {
                                eprintln!("  → UDP packets reach the server; QUIC handshake failing");
                            } else {
                                eprintln!("  → No UDP packets logged — likely a cloud firewall issue");
                                eprintln!("    Open UDP {port} in your provider's firewall panel",
                                          port = target.quic_port);
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
