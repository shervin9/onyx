//! Onyx Guard: a secrets broker and egress gate for agent jobs.
//!
//! An agent gets same-length *placeholders* instead of real secrets. Its
//! HTTPS traffic goes through a small proxy inside onyx-server:
//!
//! * a host on the allowlist that has no secret is tunnelled untouched;
//! * a host a secret is bound to is intercepted with a per-job CA, and the
//!   placeholder is swapped for the real value **in request headers only**
//!   (never in bodies, so an agent cannot publish the real value by posting
//!   its placeholder somewhere). Responses are scrubbed the other way, so an
//!   echoed header never reveals the real value;
//! * everything else is refused with a 403 and reported in the job's output.
//!
//! On Linux 6.7+ the job is also confined with Landlock so it can only open
//! TCP connections to the proxy (plus ports the user allowed). That makes
//! the proxy impossible to bypass, without root. Real values live only in
//! this process's memory, never on disk, and the process is marked
//! non-dumpable so other same-user processes cannot read its memory.

use anyhow::{bail, Context, Result};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use shared::GuardSpec;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const MAX_HEAD: usize = 64 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// After this many block reports for one host, stop repeating them.
const MAX_BLOCK_REPORTS: u32 = 3;

const CA_BUNDLE_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

// ── Policy ──────────────────────────────────────────────────────────────

struct Secret {
    name: String,
    real: Vec<u8>,
    fake: Vec<u8>,
    hosts: Vec<String>,
}

struct Policy {
    secrets: Vec<Secret>,
    allow: Vec<String>,
}

impl Policy {
    fn allowed(&self, host: &str) -> bool {
        self.allow.iter().any(|p| host_matches(p, host))
            || self
                .secrets
                .iter()
                .any(|s| s.hosts.iter().any(|p| host_matches(p, host)))
    }

    fn secrets_for(&self, host: &str) -> Vec<&Secret> {
        self.secrets
            .iter()
            .filter(|s| s.hosts.iter().any(|p| host_matches(p, host)))
            .collect()
    }
}

/// `example.com` matches only itself; `*.example.com` matches any subdomain.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.len() > suffix.len() + 1
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
    } else {
        pattern == host
    }
}

/// Same-length stand-in for `real`. A well-known, non-secret prefix such as
/// `sk-ant-api03-` or `ghp_` is kept so SDKs that sniff key formats still
/// work; the rest is random.
pub fn make_placeholder(real: &str) -> Result<String> {
    if real.len() < 8 {
        bail!("secret is too short to protect (need at least 8 characters)");
    }
    if !real.bytes().all(|b| b.is_ascii_graphic()) {
        bail!("secret must be printable ASCII without spaces");
    }
    let head = &real[..real.len().min(14)];
    let keep = head
        .rfind(['-', '_'])
        .map(|i| i + 1)
        .filter(|&i| {
            real.len() - i >= 12
                && real[..i]
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
        .unwrap_or(0);
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let rng = SystemRandom::new();
    loop {
        let mut raw = vec![0u8; real.len() - keep];
        rng.fill(&mut raw)
            .map_err(|_| anyhow::anyhow!("random generator failed"))?;
        let mut out = real[..keep].to_string();
        out.extend(raw.iter().map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char));
        if out != real {
            return Ok(out);
        }
    }
}

// ── Streaming replacement ───────────────────────────────────────────────

/// Replaces equal-length byte patterns in a stream. Only holds back a tail
/// that could still become a match, so streamed responses are not delayed.
pub struct Replacer {
    pairs: Vec<(Vec<u8>, Vec<u8>)>,
    carry: Vec<u8>,
}

impl Replacer {
    pub fn new(pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        debug_assert!(pairs.iter().all(|(a, b)| a.len() == b.len() && !a.is_empty()));
        Self { pairs, carry: Vec::new() }
    }

    pub fn feed(&mut self, input: &[u8]) -> Vec<u8> {
        self.carry.extend_from_slice(input);
        let mut buf = std::mem::take(&mut self.carry);
        replace_all(&mut buf, &self.pairs);
        let hold = self
            .pairs
            .iter()
            .map(|(from, _)| partial_suffix(&buf, from))
            .max()
            .unwrap_or(0);
        self.carry = buf.split_off(buf.len() - hold);
        buf
    }

    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.carry)
    }
}

fn replace_all(buf: &mut [u8], pairs: &[(Vec<u8>, Vec<u8>)]) {
    for (from, to) in pairs {
        let mut i = 0;
        while i + from.len() <= buf.len() {
            if &buf[i..i + from.len()] == from.as_slice() {
                buf[i..i + from.len()].copy_from_slice(to);
                i += from.len();
            } else {
                i += 1;
            }
        }
    }
}

/// Length of the longest suffix of `buf` that is a proper prefix of `pat`.
fn partial_suffix(buf: &[u8], pat: &[u8]) -> usize {
    let max = buf.len().min(pat.len() - 1);
    (1..=max).rev().find(|&n| buf[buf.len() - n..] == pat[..n]).unwrap_or(0)
}

// ── Guard lifecycle ─────────────────────────────────────────────────────

pub struct Guard {
    /// Environment for the job: placeholders, proxy and CA settings.
    pub env: Vec<(String, String)>,
    /// One-line description of what is enforced, for the job's output.
    pub banner: String,
    landlock: Option<LandlockRuleset>,
    dir: PathBuf,
    listener_task: tokio::task::JoinHandle<()>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.listener_task.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Guard {
    /// Start the proxy for one job. Guard events (allowed/blocked hosts) are
    /// sent to `events` as ready-to-print lines.
    pub async fn start(
        spec: GuardSpec,
        job_dir: &Path,
        events: mpsc::UnboundedSender<String>,
    ) -> Result<Self> {
        // Keep same-user processes (including the agent) out of our memory.
        #[cfg(target_os = "linux")]
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }

        let mut env = Vec::new();
        let mut secrets = Vec::new();
        let mut seen = HashSet::new();
        for s in spec.secrets {
            if !valid_env_name(&s.name) {
                bail!("guard: invalid secret name '{}'", s.name);
            }
            if !seen.insert(s.name.clone()) {
                bail!("guard: secret '{}' given twice", s.name);
            }
            if s.hosts.is_empty() {
                bail!("guard: secret '{}' has no allowed hosts", s.name);
            }
            for h in &s.hosts {
                if h.trim_start_matches("*.").parse::<std::net::IpAddr>().is_ok() {
                    bail!("guard: secret '{}' must be bound to host names, not IPs", s.name);
                }
            }
            let fake = make_placeholder(&s.value)
                .with_context(|| format!("guard: secret '{}'", s.name))?;
            env.push((s.name.clone(), fake.clone()));
            secrets.push(Secret {
                name: s.name,
                real: s.value.into_bytes(),
                fake: fake.into_bytes(),
                hosts: s.hosts,
            });
        }
        let policy = Policy {
            secrets,
            allow: spec.allow_hosts,
        };

        std::fs::create_dir_all(job_dir)?;
        let ca = Ca::new()?;
        let ca_path = job_dir.join("guard-ca.pem");
        std::fs::write(&ca_path, ca.cert.pem())?;
        let bundle_path = job_dir.join("guard-bundle.pem");
        let system_bundle = CA_BUNDLE_PATHS.iter().find(|p| Path::new(p).is_file());
        let roots = load_roots(system_bundle.copied())?;
        if let Some(sys) = system_bundle {
            let mut bundle = std::fs::read(sys)?;
            bundle.extend_from_slice(b"\n");
            bundle.extend_from_slice(ca.cert.pem().as_bytes());
            std::fs::write(&bundle_path, bundle)?;
        }

        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();

        let proxy = format!("http://127.0.0.1:{port}");
        for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
            env.push((k.into(), proxy.clone()));
        }
        for k in ["NO_PROXY", "no_proxy"] {
            env.push((k.into(), "localhost,127.0.0.1,::1".into()));
        }
        // Node 24+ only honours proxy variables for fetch() with this set.
        env.push(("NODE_USE_ENV_PROXY".into(), "1".into()));
        env.push(("NODE_EXTRA_CA_CERTS".into(), ca_path.display().to_string()));
        if system_bundle.is_some() {
            let b = bundle_path.display().to_string();
            for k in ["SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "DENO_CERT"] {
                env.push((k.into(), b.clone()));
            }
        }
        env.push(("ONYX_GUARD".into(), "1".into()));

        let mut direct_ports: Vec<u16> = vec![port];
        direct_ports.extend(spec.allow_ports.iter().copied());
        let landlock = LandlockRuleset::connect_only(&direct_ports);

        let names: Vec<String> = policy
            .secrets
            .iter()
            .map(|s| format!("{} → {}", s.name, s.hosts.join(",")))
            .collect();
        let mut banner = String::from("[onyx guard] on");
        if !names.is_empty() {
            banner.push_str(&format!(" · secrets: {}", names.join("; ")));
        }
        if !policy.allow.is_empty() {
            banner.push_str(&format!(" · also allowed: {}", policy.allow.join(", ")));
        }
        banner.push_str(match &landlock {
            Some(_) => " · egress locked by Landlock",
            None => " · egress via proxy only (Landlock network rules need Linux 6.7+)",
        });

        let state = Arc::new(ProxyState {
            policy,
            ca,
            leaf_cache: Mutex::new(HashMap::new()),
            upstream: Arc::new(upstream_config(roots)?),
            events,
            reported: Mutex::new(HashMap::new()),
        });
        let listener_task = tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else { break };
                let state = state.clone();
                tokio::spawn(async move {
                    let _ = handle_client(sock, state).await;
                });
            }
        });

        Ok(Guard {
            env,
            banner,
            landlock,
            dir: job_dir.to_path_buf(),
            listener_task,
        })
    }

    /// Prepare the child so it confines itself right before exec.
    pub fn confine(&self, cmd: &mut tokio::process::Command) {
        if let Some(rs) = &self.landlock {
            let fd = rs.fd;
            // SAFETY: only async-signal-safe syscalls run in the child.
            unsafe {
                cmd.pre_exec(move || landlock_apply(fd));
            }
        }
    }
}

fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && !name.as_bytes()[0].is_ascii_digit()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

// ── Proxy ───────────────────────────────────────────────────────────────

struct ProxyState {
    policy: Policy,
    ca: Ca,
    leaf_cache: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
    upstream: Arc<rustls::ClientConfig>,
    events: mpsc::UnboundedSender<String>,
    /// host → number of times reported (allowed hosts are reported once).
    reported: Mutex<HashMap<String, u32>>,
}

impl ProxyState {
    fn report_allowed(&self, host: &str, secrets: &[&Secret]) {
        let mut r = self.reported.lock().unwrap();
        let key = format!("+{host}");
        if r.contains_key(&key) {
            return;
        }
        r.insert(key, 1);
        let line = if secrets.is_empty() {
            format!("[onyx guard] allowed {host}\n")
        } else {
            let names: Vec<&str> = secrets.iter().map(|s| s.name.as_str()).collect();
            format!("[onyx guard] allowed {host} · injecting {}\n", names.join(", "))
        };
        let _ = self.events.send(line);
    }

    fn report_blocked(&self, what: &str) {
        let mut r = self.reported.lock().unwrap();
        let n = r.entry(format!("-{what}")).or_insert(0);
        *n += 1;
        if *n <= MAX_BLOCK_REPORTS {
            let more = if *n == MAX_BLOCK_REPORTS { " (further attempts not shown)" } else { "" };
            let _ = self
                .events
                .send(format!("[onyx guard] BLOCKED {what}{more}\n"));
        }
    }
}

async fn handle_client(mut sock: TcpStream, state: Arc<ProxyState>) -> Result<()> {
    let head = read_head(&mut sock).await?;
    let line = head.split(|&b| b == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    if !method.eq_ignore_ascii_case("CONNECT") {
        let host = target
            .strip_prefix("http://")
            .and_then(|r| r.split(['/', ':']).next())
            .unwrap_or(&target)
            .to_string();
        state.report_blocked(&format!("http://{host} (plain HTTP)"));
        return deny(
            &mut sock,
            &format!("onyx guard: plain HTTP to {host} is blocked; use https\n"),
        )
        .await;
    }

    let Some((host, port)) = split_host_port(&target) else {
        return deny(&mut sock, "onyx guard: bad CONNECT target\n").await;
    };
    if !state.policy.allowed(&host) {
        state.report_blocked(&format!("{host}:{port}"));
        return deny(
            &mut sock,
            &format!(
                "onyx guard: {host} is not on this job's allowlist. \
                 Ask the user to rerun with --allow {host}\n"
            ),
        )
        .await;
    }

    let upstream = match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), port))).await {
        Ok(Ok(s)) => s,
        _ => {
            sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await?;
            return Ok(());
        }
    };
    sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

    let secrets = state.policy.secrets_for(&host);
    state.report_allowed(&host, &secrets);
    if secrets.is_empty() {
        let (mut a, mut b) = (sock, upstream);
        let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
        return Ok(());
    }
    intercept(sock, upstream, &host, &secrets, &state).await
}

async fn intercept(
    sock: TcpStream,
    upstream: TcpStream,
    host: &str,
    secrets: &[&Secret],
    state: &ProxyState,
) -> Result<()> {
    let server_cfg = state.leaf_for(host)?;
    let agent_tls = tokio_rustls::TlsAcceptor::from(server_cfg).accept(sock).await?;
    let name = ServerName::try_from(host.to_string())?;
    let up_tls = tokio_rustls::TlsConnector::from(state.upstream.clone())
        .connect(name, upstream)
        .await?;

    let inject: Vec<(Vec<u8>, Vec<u8>)> =
        secrets.iter().map(|s| (s.fake.clone(), s.real.clone())).collect();
    // Scrub *every* real value from responses, not just this host's.
    let scrub: Vec<(Vec<u8>, Vec<u8>)> = state
        .policy
        .secrets
        .iter()
        .map(|s| (s.real.clone(), s.fake.clone()))
        .collect();

    let (agent_r, mut agent_w) = tokio::io::split(agent_tls);
    let (mut up_r, mut up_w) = tokio::io::split(up_tls);

    let requests = async move {
        let r = forward_requests(BufReader::new(agent_r), &mut up_w, &inject).await;
        let _ = up_w.shutdown().await;
        r
    };
    let responses = async move {
        let mut rep = Replacer::new(scrub);
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = up_r.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let out = rep.feed(&buf[..n]);
            agent_w.write_all(&out).await?;
        }
        agent_w.write_all(&rep.finish()).await?;
        agent_w.shutdown().await?;
        anyhow::Ok(())
    };
    let _ = tokio::join!(requests, responses);
    Ok(())
}

/// Forward HTTP/1.1 requests, substituting placeholders in header blocks
/// only. Bodies (Content-Length or chunked) pass through byte for byte.
async fn forward_requests<R, W>(mut r: BufReader<R>, w: &mut W, inject: &[(Vec<u8>, Vec<u8>)]) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let mut head = Vec::new();
        loop {
            let n = r.read_until(b'\n', &mut head).await?;
            if n == 0 {
                return Ok(());
            }
            if head == b"\r\n" || head == b"\n" {
                head.clear(); // stray CRLF between requests
                continue;
            }
            if head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n") {
                break;
            }
            if head.len() > MAX_HEAD {
                bail!("request head too large");
            }
        }
        replace_all(&mut head, inject);
        w.write_all(&head).await?;

        let info = parse_head(&head);
        if info.upgrade {
            tokio::io::copy(&mut r, w).await?;
            return Ok(());
        }
        if info.chunked {
            loop {
                let mut line = Vec::new();
                if r.read_until(b'\n', &mut line).await? == 0 {
                    return Ok(());
                }
                w.write_all(&line).await?;
                let size_str = String::from_utf8_lossy(&line);
                let size_str = size_str.split(';').next().unwrap_or("").trim();
                let size = u64::from_str_radix(size_str, 16).context("bad chunk size")?;
                if size == 0 {
                    // trailers, then the empty line
                    loop {
                        let mut t = Vec::new();
                        if r.read_until(b'\n', &mut t).await? == 0 {
                            return Ok(());
                        }
                        w.write_all(&t).await?;
                        if t == b"\r\n" || t == b"\n" {
                            break;
                        }
                    }
                    break;
                }
                copy_exact(&mut r, w, size + 2).await?; // data + CRLF
            }
        } else if let Some(n) = info.content_length {
            copy_exact(&mut r, w, n).await?;
        }
        w.flush().await?;
    }
}

async fn copy_exact<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(r: &mut R, w: &mut W, n: u64) -> Result<()> {
    let copied = tokio::io::copy(&mut r.take(n), w).await?;
    if copied != n {
        bail!("body ended early");
    }
    Ok(())
}

struct HeadInfo {
    content_length: Option<u64>,
    chunked: bool,
    upgrade: bool,
}

fn parse_head(head: &[u8]) -> HeadInfo {
    let text = String::from_utf8_lossy(head);
    let mut info = HeadInfo { content_length: None, chunked: false, upgrade: false };
    for line in text.lines().skip(1) {
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_ascii_lowercase());
        match k.as_str() {
            "content-length" => info.content_length = v.parse().ok(),
            "transfer-encoding" => info.chunked = v.split(',').any(|t| t.trim() == "chunked"),
            "connection" => info.upgrade |= v.split(',').any(|t| t.trim() == "upgrade"),
            _ => {}
        }
    }
    info
}

async fn read_head(sock: &mut TcpStream) -> Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    // Byte-at-a-time so nothing after the CONNECT head is consumed.
    while !head.ends_with(b"\r\n\r\n") && !head.ends_with(b"\n\n") {
        if sock.read(&mut byte).await? == 0 {
            bail!("client closed");
        }
        head.push(byte[0]);
        if head.len() > 8192 {
            bail!("proxy request head too large");
        }
    }
    Ok(head)
}

async fn deny(sock: &mut TcpStream, msg: &str) -> Result<()> {
    let resp = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}",
        msg.len()
    );
    sock.write_all(resp.as_bytes()).await?;
    let _ = sock.shutdown().await;
    Ok(())
}

pub fn split_host_port(target: &str) -> Option<(String, u16)> {
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        (h, p)
    } else {
        target.rsplit_once(':')?
    };
    let port = port.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host.trim_end_matches('.').to_ascii_lowercase(), port))
}

// ── TLS ─────────────────────────────────────────────────────────────────

struct Ca {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl Ca {
    fn new() -> Result<Self> {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
        let key = KeyPair::generate()?;
        let mut p = CertificateParams::new(Vec::<String>::new())?;
        p.distinguished_name
            .push(DnType::CommonName, "Onyx Guard per-job CA");
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
        let cert = p.self_signed(&key)?;
        Ok(Self { cert, key })
    }
}

impl ProxyState {
    fn leaf_for(&self, host: &str) -> Result<Arc<rustls::ServerConfig>> {
        if let Some(c) = self.leaf_cache.lock().unwrap().get(host) {
            return Ok(c.clone());
        }
        use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};
        let key = KeyPair::generate()?;
        let mut p = CertificateParams::new(vec![host.to_string()])?;
        p.distinguished_name.push(DnType::CommonName, host);
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = p.signed_by(&key, &self.ca.cert, &self.ca.key)?;
        let chain = vec![leaf.der().clone(), self.ca.cert.der().clone()];
        let key_der = PrivateKeyDer::try_from(key.serialize_der()).map_err(|e| anyhow::anyhow!(e))?;
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key_der)?;
        // HTTP/1.1 keeps headers as plain text we can rewrite.
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        self.leaf_cache.lock().unwrap().insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }
}

fn load_roots(bundle: Option<&str>) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    if let Some(path) = bundle {
        for cert in CertificateDer::pem_file_iter(path)?.flatten() {
            let _ = roots.add(cert);
        }
    }
    Ok(roots)
}

fn upstream_config(roots: rustls::RootCertStore) -> Result<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

// ── Landlock (Linux 6.7+, ABI 4: TCP connect rules) ─────────────────────

struct LandlockRuleset {
    fd: i32,
}

impl Drop for LandlockRuleset {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(target_os = "linux")]
mod ll {
    pub const SYS_CREATE_RULESET: libc::c_long = 444;
    pub const SYS_ADD_RULE: libc::c_long = 445;
    pub const SYS_RESTRICT_SELF: libc::c_long = 446;
    pub const CREATE_RULESET_VERSION: u32 = 1;
    pub const RULE_NET_PORT: u32 = 2;
    pub const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

    #[repr(C)]
    pub struct RulesetAttr {
        pub handled_access_fs: u64,
        pub handled_access_net: u64,
    }

    #[repr(C, packed)]
    pub struct NetPortAttr {
        pub allowed_access: u64,
        pub port: u64,
    }
}

impl LandlockRuleset {
    /// A ruleset that allows TCP connect only to `ports`. None when the
    /// kernel does not support Landlock network rules.
    #[cfg(target_os = "linux")]
    fn connect_only(ports: &[u16]) -> Option<Self> {
        use ll::*;
        unsafe {
            let abi = libc::syscall(
                SYS_CREATE_RULESET,
                std::ptr::null::<RulesetAttr>(),
                0usize,
                CREATE_RULESET_VERSION,
            );
            if abi < 4 {
                return None;
            }
            let attr = RulesetAttr {
                handled_access_fs: 0,
                handled_access_net: ACCESS_NET_CONNECT_TCP,
            };
            let fd = libc::syscall(
                SYS_CREATE_RULESET,
                &attr as *const RulesetAttr,
                std::mem::size_of::<RulesetAttr>(),
                0u32,
            );
            if fd < 0 {
                return None;
            }
            let rs = LandlockRuleset { fd: fd as i32 };
            for &port in ports {
                let rule = NetPortAttr {
                    allowed_access: ACCESS_NET_CONNECT_TCP,
                    port: port as u64,
                };
                if libc::syscall(SYS_ADD_RULE, rs.fd, RULE_NET_PORT, &rule as *const NetPortAttr, 0u32) != 0 {
                    return None;
                }
            }
            Some(rs)
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn connect_only(_ports: &[u16]) -> Option<Self> {
        None
    }
}

/// Runs in the forked child before exec: async-signal-safe syscalls only.
#[cfg(target_os = "linux")]
fn landlock_apply(fd: i32) -> std::io::Result<()> {
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::syscall(ll::SYS_RESTRICT_SELF, fd, 0u32) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        libc::close(fd);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn landlock_apply(_fd: i32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_patterns() {
        assert!(host_matches("api.github.com", "API.GitHub.com."));
        assert!(!host_matches("github.com", "api.github.com"));
        assert!(host_matches("*.github.com", "api.github.com"));
        assert!(!host_matches("*.github.com", "github.com"));
        assert!(!host_matches("*.github.com", "evilgithub.com"));
    }

    #[test]
    fn placeholder_keeps_length_and_public_prefix_only() {
        let real = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let fake = make_placeholder(real).unwrap();
        assert_eq!(fake.len(), real.len());
        assert!(fake.starts_with("sk-ant-api03-"));
        assert_ne!(fake, real);

        let real = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
        let fake = make_placeholder(real).unwrap();
        assert!(fake.starts_with("ghp_") && fake.len() == real.len() && fake != real);

        // Mixed-case or short tails: keep nothing.
        let real = "Secret_abcdefghijklmnop";
        assert!(!make_placeholder(real).unwrap().starts_with("Secret_"));
        assert!(make_placeholder("short").is_err());
        assert!(make_placeholder("has space in it").is_err());
    }

    #[test]
    fn replacer_handles_split_patterns_without_holding_unrelated_bytes() {
        let mut r = Replacer::new(vec![(b"SECRET42".to_vec(), b"xxxxxxxx".to_vec())]);
        let mut out = r.feed(b"data: hello\n");
        assert_eq!(out, b"data: hello\n"); // nothing held back
        out = r.feed(b"key=SEC");
        assert_eq!(out, b"key="); // possible prefix held
        out.extend(r.feed(b"RET42 end"));
        out.extend(r.finish());
        assert_eq!(out, b"key=xxxxxxxx end");
    }

    #[test]
    fn connect_targets() {
        assert_eq!(split_host_port("api.github.com:443"), Some(("api.github.com".into(), 443)));
        assert_eq!(split_host_port("[::1]:8080"), Some(("::1".into(), 8080)));
        assert_eq!(split_host_port("nohost"), None);
    }

    #[tokio::test]
    async fn headers_get_secrets_bodies_do_not() {
        let inject = vec![(b"FAKEFAKE".to_vec(), b"REALREAL".to_vec())];
        let req = b"POST /gists HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer FAKEFAKE\r\nContent-Length: 8\r\n\r\nFAKEFAKE\
GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nX-Key: FAKEFAKE\r\n\r\n8\r\nFAKEFAKE\r\n0\r\n\r\n";
        let mut out = Vec::new();
        forward_requests(BufReader::new(&req[..]), &mut out, &inject).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Authorization: Bearer REALREAL"));
        assert!(text.contains("X-Key: REALREAL"));
        assert!(text.contains("\r\n\r\nFAKEFAKE")); // CL body untouched
        assert!(text.contains("8\r\nFAKEFAKE\r\n0")); // chunked body untouched
        assert_eq!(text.len(), req.len());
    }
}
