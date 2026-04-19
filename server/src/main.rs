use anyhow::{Context, Result};
use quinn::{Endpoint, ServerConfig};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use shared::{JobStatus, JobSummary, Message, StdStream, DEFAULT_PORT};
use std::{
    collections::{HashMap, VecDeque},
    ffi::CStr,
    net::SocketAddr,
    os::unix::{io::FromRawFd, process::CommandExt},
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, oneshot, watch, Notify};

// ---------------------------------------------------------------------------
// Session retention tuning
// ---------------------------------------------------------------------------
//
// Retention windows govern how long a detached session's in-process state
// (PTY task, output broadcast, resume token) is kept alive waiting for the
// client to reconnect. These are **best-effort, in-memory** guarantees:
//
//   - If the onyx-server process dies (host reboot, OOM, kill), every
//     detached session is lost regardless of retention window.
//   - If the shell process under the PTY exits on its own, the session
//     ends immediately — retention has no bearing.
//
// Interactive retention is long because the session is cheap to keep
// around and the user-facing cost of losing it is high. Proxy retention is
// shorter because the SSH session underneath won't survive a long gap
// anyway (TCPKeepAlive, proto timers), so pretending otherwise would
// mislead users. See SECURITY.md / README.md for the documented claim.

/// How long a detached interactive session's state is retained
/// before GC reaps it.
const DETACHED_SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60); // 12h
/// How long a detached proxy session's target TCP socket is kept alive
/// waiting for the client to resume. Longer than before, but still
/// short — SSH state above us rarely survives longer gaps.
const DETACHED_PROXY_TTL: Duration = Duration::from_secs(120);
/// How often the GC sweep runs.
const GC_INTERVAL: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Exec (job) tuning
// ---------------------------------------------------------------------------
//
// `onyx exec` runs a command as a resumable job. The server owns the child
// process; the client streams output over a QUIC stream. A client disconnect
// does NOT terminate the job — the user can reattach with `onyx attach` or
// read captured output with `onyx logs` until the retention window expires.
//
// Guarantees:
//   * Jobs survive client disconnect (strong — the child keeps running).
//   * Output is preserved in a bounded ring buffer per job; anything beyond
//     the cap is dropped oldest-first and the attach path reports the gap.
//   * Jobs do NOT survive onyx-server restart or host reboot (in-memory).

/// Upper bound on buffered output per job. Picked so typical CI-ish commands
/// (build logs, test output) fit comfortably, while a pathological job that
/// prints GiB/s doesn't exhaust the server's memory. Chunks are dropped
/// oldest-first once the buffer is full; the attach path reports the gap.
const JOB_BUFFER_CAP_BYTES: usize = 4 * 1024 * 1024; // 4 MiB per job

/// Retention for a job after its child process exits. During this window
/// `onyx jobs`, `onyx logs`, and `onyx attach` can still reach it.
const FINISHED_JOB_TTL: Duration = Duration::from_secs(60 * 60); // 1h

/// Max jobs to keep in memory total. New submissions past this cap reap the
/// oldest finished job first; if all jobs are running, the request is
/// rejected with a clear error.
const JOB_REGISTRY_CAP: usize = 256;

// ---------------------------------------------------------------------------
// TLS / QUIC setup
// ---------------------------------------------------------------------------

/// SHA-256 of the cert DER, formatted as "sha256:<hex>".
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

fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn random_token() -> Result<String> {
    let mut buf = [0u8; 32];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| anyhow::anyhow!("generating random session token failed"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Load a persistent self-signed cert from disk, or generate + save a new one.
/// Returns (ServerConfig, fingerprint_string).
/// The fingerprint is also written to server.fingerprint so the client can
/// read it during bootstrap and perform TOFU cert pinning.
fn make_server_config() -> Result<(ServerConfig, String)> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let data_dir = std::path::PathBuf::from(&home).join(".local/share/onyx");
    std::fs::create_dir_all(&data_dir).context("creating data dir")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700))
            .context("setting data dir permissions")?;
    }

    let cert_path = data_dir.join("server.crt");
    let key_path = data_dir.join("server.key");

    // Load existing cert+key, or generate and persist a new pair.
    let (cert_der, key_der): (Vec<u8>, Vec<u8>) = if cert_path.exists() && key_path.exists() {
        (
            std::fs::read(&cert_path).context("reading server.crt")?,
            std::fs::read(&key_path).context("reading server.key")?,
        )
    } else {
        let certified = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .context("generating self-signed certificate")?;
        let cert = certified.cert.der().to_vec();
        let key = certified.key_pair.serialize_der();
        write_private_file(&cert_path, &cert)?;
        write_private_file(&key_path, &key)?;
        (cert, key)
    };

    let fingerprint = cert_fingerprint(&cert_der);
    // Write fingerprint so bootstrap can read it via SSH and send to client.
    write_private_file(&data_dir.join("server.fingerprint"), fingerprint.as_bytes())?;

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("building TLS config")?;
    tls.alpn_protocols = vec![b"onyx".to_vec()];
    let quic =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).context("wrapping for QUIC")?;
    Ok((ServerConfig::with_crypto(Arc::new(quic)), fingerprint))
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
// PTY helpers
// ---------------------------------------------------------------------------

fn open_pty() -> Result<(libc::c_int, libc::c_int)> {
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    anyhow::ensure!(master >= 0, "posix_openpt failed");
    anyhow::ensure!(unsafe { libc::grantpt(master) } == 0, "grantpt failed");
    anyhow::ensure!(unsafe { libc::unlockpt(master) } == 0, "unlockpt failed");
    let slave_path = unsafe {
        let ptr = libc::ptsname(master);
        anyhow::ensure!(!ptr.is_null(), "ptsname failed");
        CStr::from_ptr(ptr).to_owned()
    };
    let slave = unsafe { libc::open(slave_path.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if slave < 0 {
        unsafe { libc::close(master) };
        anyhow::bail!("open slave pty failed");
    }
    Ok((master, slave))
}

/// Owns a raw fd; closes on drop.
struct OwnedFd(libc::c_int);
impl std::os::unix::io::AsRawFd for OwnedFd {
    fn as_raw_fd(&self) -> libc::c_int {
        self.0
    }
}
impl Drop for OwnedFd {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

// ---------------------------------------------------------------------------
// Session types
// ---------------------------------------------------------------------------

enum PtyCmd {
    Input(Vec<u8>),
    Resize(u16, u16),
}

struct SessionMeta {
    resume_token: String,
    pty_cmd_tx: mpsc::Sender<PtyCmd>,
    output_tx: broadcast::Sender<(u64, Vec<u8>)>,
    /// Sending on this kills the PTY task (used by GC).
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Set when client disconnects; None while a client is attached.
    detached_at: Option<Instant>,
    /// Forced-takeover channel: when a new Hello/Resume arrives, it
    /// signals this to evict whatever handler currently owns the session
    /// stream. The old handler exits without touching `detached_at` or
    /// `takeover_tx` (those are now owned by the new handler), so a client
    /// that reconnects after a transport drop can reclaim its session
    /// immediately instead of waiting for the server to notice the dead
    /// TCP path.
    ///
    /// This is what fixes the "stuck on session already attached" loop:
    /// previously, if the old handler was blocked on `output_rx.recv()`
    /// with no PTY output, it never set `detached_at`, and every Resume
    /// was rejected. Takeover breaks that deadlock deterministically.
    takeover_tx: Option<oneshot::Sender<()>>,
    /// Monotonic attach counter. Each Hello/Resume bumps this and
    /// captures its own value; on exit the handler only writes back to
    /// `detached_at`/`takeover_tx` if it is still current (epoch
    /// matches). Ensures an evicted old handler cannot race-overwrite
    /// state owned by the new handler.
    attach_epoch: u64,
}

type Sessions = Arc<Mutex<HashMap<String, SessionMeta>>>;

struct ProxySessionMeta {
    input_tx: mpsc::Sender<Vec<u8>>,
    output_tx: broadcast::Sender<Vec<u8>>,
    shutdown_tx: watch::Sender<bool>,
    detached_at: Option<Instant>,
    attached: Arc<AtomicBool>,
    attach_notify: Arc<Notify>,
}

type ProxySessions = Arc<Mutex<HashMap<String, ProxySessionMeta>>>;

// ---------------------------------------------------------------------------
// Exec — one job per `onyx exec` invocation
// ---------------------------------------------------------------------------
//
// A job owns:
//   * the running child process (spawned under `sh -c <joined cmd>`)
//   * a bounded ring buffer of output chunks, each tagged (seq, stream)
//   * a `version` watch channel that ticks on every append and on finish
//
// Attachers read from the buffer under the mutex (no races on seq allocation
// or buffer ordering) and then wait on `version_rx.changed()` for the next
// update. This avoids the duplicate-or-miss window that `broadcast` has when
// a new subscriber joins while a send is in flight.

#[derive(Clone)]
struct OutputChunk {
    seq: u64,
    stream: StdStream,
    data: Vec<u8>,
}

struct JobMeta {
    job_id: String,
    /// Raw argv the job was spawned with. Kept alongside command_display so
    /// future features (re-run, export) can reconstruct the original
    /// argument list losslessly instead of re-parsing the display string.
    #[allow(dead_code)]
    command: Vec<String>,
    command_display: String,
    status: JobStatus,
    started_at: Instant,
    started_at_unix: u64,
    finished_at: Option<Instant>,
    finished_at_unix: Option<u64>,
    exit_code: Option<i32>,
    /// Ring of output chunks ordered oldest-to-newest. Total `data` byte
    /// count never exceeds JOB_BUFFER_CAP_BYTES.
    buffer: VecDeque<OutputChunk>,
    buffer_bytes: usize,
    /// seq of the oldest chunk still in `buffer`. 1-indexed; 0 means empty.
    oldest_seq: u64,
    /// seq of the newest chunk ever produced (whether or not still buffered).
    last_seq: u64,
    /// Monotonically increases on every append and on finish. Attachers
    /// subscribe to this watch to be woken on new activity; the actual
    /// payload is read from `buffer` under the lock.
    version_tx: watch::Sender<u64>,
    /// Number of stream handlers currently attached to this job.
    attach_count: u32,
    /// Send `()` to kill the job early (not wired to a user-facing command
    /// yet; used only by registry-cap eviction and shutdown).
    shutdown_tx: Option<oneshot::Sender<()>>,
}

type Jobs = Arc<Mutex<HashMap<String, JobMeta>>>;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn new_job_id() -> Result<String> {
    let mut buf = [0u8; 8];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| anyhow::anyhow!("generating random job id failed"))?;
    Ok(format!(
        "job_{}",
        buf.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

/// Append a chunk to a job's ring buffer, evicting oldest entries until the
/// byte cap is respected, and bump the version watch so attachers wake.
///
/// Caller must hold the `Jobs` lock. The chunk's `seq` must equal
/// `meta.last_seq + 1`.
fn job_push_chunk(meta: &mut JobMeta, stream: StdStream, data: Vec<u8>) {
    meta.last_seq += 1;
    let seq = meta.last_seq;
    let len = data.len();
    meta.buffer.push_back(OutputChunk { seq, stream, data });
    meta.buffer_bytes += len;

    while meta.buffer_bytes > JOB_BUFFER_CAP_BYTES {
        if let Some(evicted) = meta.buffer.pop_front() {
            meta.buffer_bytes = meta.buffer_bytes.saturating_sub(evicted.data.len());
            meta.oldest_seq = meta
                .buffer
                .front()
                .map(|c| c.seq)
                .unwrap_or(meta.last_seq + 1);
        } else {
            break;
        }
    }
    if meta.oldest_seq == 0 {
        meta.oldest_seq = seq;
    }
    let _ = meta.version_tx.send(meta.last_seq);
}

fn summarize_job(meta: &JobMeta) -> JobSummary {
    JobSummary {
        job_id: meta.job_id.clone(),
        command: meta.command_display.clone(),
        status: meta.status,
        started_at_unix: meta.started_at_unix,
        finished_at_unix: meta.finished_at_unix,
        exit_code: meta.exit_code,
        attached: meta.attach_count > 0,
        buffered_bytes: meta.buffer_bytes as u64,
    }
}

// ---------------------------------------------------------------------------
// PTY task — runs for the lifetime of the shell, independent of any connection
// ---------------------------------------------------------------------------

async fn pty_task(
    async_master: tokio::io::unix::AsyncFd<std::fs::File>,
    mut child: std::process::Child,
    mut cmd_rx: mpsc::Receiver<PtyCmd>,
    output_tx: broadcast::Sender<(u64, Vec<u8>)>,
    mut shutdown_rx: oneshot::Receiver<()>,
    sessions: Sessions,
    session_id: String,
) {
    use std::os::unix::io::AsRawFd;
    let mut seq: u64 = 0;
    let mut buf = [0u8; 4096];

    'pump: loop {
        tokio::select! {
            biased;

            // GC / explicit shutdown signal
            _ = &mut shutdown_rx => break 'pump,

            // PTY has output → send to broadcast (discarded when no client is subscribed)
            guard = async_master.readable() => {
                let mut guard = match guard { Ok(g) => g, Err(_) => break 'pump };
                match guard.try_io(|inner| {
                    let n = unsafe {
                        libc::read(
                            inner.get_ref().as_raw_fd(),
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                        )
                    };
                    if n == -1 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
                }) {
                    Ok(Ok(0)) => break 'pump,
                    Ok(Ok(n)) => {
                        seq += 1;
                        // Ignore SendError: no receivers = client disconnected, discard output.
                        // This keeps draining the PTY so the shell never stalls.
                        let _ = output_tx.send((seq, buf[..n].to_vec()));
                    }
                    Ok(Err(e)) if e.kind() != std::io::ErrorKind::WouldBlock => break 'pump,
                    _ => {} // WouldBlock or TryIoError: retry
                }
            }

            // Input / resize from client
            Some(cmd) = cmd_rx.recv() => {
                let fd = async_master.get_ref().as_raw_fd();
                match cmd {
                    PtyCmd::Input(data) => {
                        let mut off = 0;
                        while off < data.len() {
                            let n = unsafe {
                                libc::write(
                                    fd,
                                    data[off..].as_ptr() as *const libc::c_void,
                                    data.len() - off,
                                )
                            };
                            if n <= 0 { break 'pump; }
                            off += n as usize;
                        }
                    }
                    PtyCmd::Resize(cols, rows) => {
                        let ws = libc::winsize {
                            ws_col: cols, ws_row: rows, ws_xpixel: 0, ws_ypixel: 0,
                        };
                        unsafe { libc::ioctl(fd, libc::TIOCSWINSZ as _, &ws); }
                        println!("[server] resize → {cols}×{rows}");
                    }
                }
            }
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    sessions.lock().unwrap().remove(&session_id);
    println!("[server] session {session_id}: shell exited");
}

// ---------------------------------------------------------------------------
// Port forwarding — one task per individual TCP connection
// ---------------------------------------------------------------------------

/// Connects to localhost:remote_port on the server, sends ForwardAck, then
/// pipes bytes between the QUIC stream and the TCP connection until either
/// side closes.
async fn run_forward(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    remote_port: u16,
) -> Result<()> {
    let tcp = match tokio::net::TcpStream::connect(std::net::SocketAddr::from((
        [127, 0, 0, 1],
        remote_port,
    )))
    .await
    {
        Ok(s) => {
            send_msg(&mut send, &Message::ForwardAck).await?;
            s
        }
        Err(e) => {
            send_msg(
                &mut send,
                &Message::ForwardError {
                    reason: e.to_string(),
                },
            )
            .await
            .ok();
            return Ok(());
        }
    };
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let _ = tokio::join!(
        tokio::io::copy(&mut recv, &mut tcp_w),
        tokio::io::copy(&mut tcp_r, &mut send),
    );
    Ok(())
}

fn shutdown_changed(
    shutdown_rx: &mut watch::Receiver<bool>,
) -> impl std::future::Future<Output = Result<(), watch::error::RecvError>> + '_ {
    shutdown_rx.changed()
}

async fn proxy_reader_task(
    mut tcp_r: tokio::net::tcp::OwnedReadHalf,
    output_tx: broadcast::Sender<Vec<u8>>,
    attached: Arc<AtomicBool>,
    attach_notify: Arc<Notify>,
    shutdown_tx: watch::Sender<bool>,
    proxy_sessions: ProxySessions,
    proxy_session_id: String,
) {
    let mut shutdown_rx = shutdown_tx.subscribe();
    let mut buf = [0u8; 4096];

    loop {
        if !attached.load(Ordering::SeqCst) {
            tokio::select! {
                _ = attach_notify.notified() => continue,
                res = shutdown_changed(&mut shutdown_rx) => {
                    if res.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }

        let n = tokio::select! {
            res = tcp_r.read(&mut buf) => match res {
                Ok(n) => n,
                Err(_) => break,
            },
            res = shutdown_changed(&mut shutdown_rx) => {
                if res.is_err() || *shutdown_rx.borrow() {
                    break;
                }
                continue;
            }
        };

        if n == 0 {
            break;
        }

        let _ = output_tx.send(buf[..n].to_vec());
    }

    let _ = shutdown_tx.send(true);
    proxy_sessions.lock().unwrap().remove(&proxy_session_id);
}

async fn proxy_writer_task(
    mut tcp_w: tokio::net::tcp::OwnedWriteHalf,
    mut input_rx: mpsc::Receiver<Vec<u8>>,
    shutdown_tx: watch::Sender<bool>,
) {
    let mut shutdown_rx = shutdown_tx.subscribe();
    loop {
        tokio::select! {
            maybe = input_rx.recv() => match maybe {
                Some(data) => {
                    if tcp_w.write_all(&data).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            res = shutdown_changed(&mut shutdown_rx) => {
                if res.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }
    let _ = shutdown_tx.send(true);
    let _ = tcp_w.shutdown().await;
}

async fn run_proxy_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    proxy_sessions: ProxySessions,
    proxy_session_id: String,
    last_attach: bool,
) -> Result<()> {
    let (input_tx, mut output_rx, attach_notify) = {
        let mut locked = proxy_sessions.lock().unwrap();
        let meta = locked
            .get_mut(&proxy_session_id)
            .ok_or_else(|| anyhow::anyhow!("proxy session not found"))?;
        meta.detached_at = None;
        meta.attached.store(true, Ordering::SeqCst);
        (
            meta.input_tx.clone(),
            meta.output_tx.subscribe(),
            meta.attach_notify.clone(),
        )
    };
    attach_notify.notify_waiters();

    send_msg(
        &mut send,
        &Message::ProxySessionReady {
            proxy_session_id: proxy_session_id.clone(),
        },
    )
    .await?;

    if !last_attach {
        eprintln!("[proxy {proxy_session_id}] resumed");
    }

    let input_task = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(0)) | Ok(None) => break,
                Ok(Some(n)) => {
                    if input_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    loop {
        match output_rx.recv().await {
            Ok(data) => {
                if send.write_all(&data).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Closed) => {
                send.finish().ok();
                input_task.abort();
                return Ok(());
            }
            Err(broadcast::error::RecvError::Lagged(_)) => {}
        }
    }

    input_task.abort();
    let became_detached = {
        let mut locked = proxy_sessions.lock().unwrap();
        match locked.get_mut(&proxy_session_id) {
            Some(meta) => {
                meta.detached_at = Some(Instant::now());
                meta.attached.store(false, Ordering::SeqCst);
                true
            }
            None => false,
        }
    };
    if became_detached {
        let secs = DETACHED_PROXY_TTL.as_secs();
        println!("[proxy {proxy_session_id}] detached (resume grace {secs}s)");
    }
    send.finish().ok();
    Ok(())
}

async fn handle_proxy_message(
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    proxy_sessions: ProxySessions,
    msg: Message,
) -> Result<()> {
    match msg {
        Message::ProxyConnect {
            proxy_session_id,
            target_host,
            target_port,
        } => {
            if proxy_sessions
                .lock()
                .unwrap()
                .contains_key(&proxy_session_id)
            {
                send_msg(
                    &mut send,
                    &Message::ForwardError {
                        reason: "proxy session already exists".into(),
                    },
                )
                .await
                .ok();
                anyhow::bail!("proxy session already exists");
            }

            let tcp =
                match tokio::net::TcpStream::connect((target_host.as_str(), target_port)).await {
                    Ok(s) => s,
                    Err(e) => {
                        let mut send = send;
                        send_msg(
                            &mut send,
                            &Message::ForwardError {
                                reason: e.to_string(),
                            },
                        )
                        .await
                        .ok();
                        return Ok(());
                    }
                };

            let (tcp_r, tcp_w) = tcp.into_split();
            let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(128);
            let (output_tx, _) = broadcast::channel::<Vec<u8>>(128);
            let (shutdown_tx, _) = watch::channel(false);
            let attached = Arc::new(AtomicBool::new(false));
            let attach_notify = Arc::new(Notify::new());

            proxy_sessions.lock().unwrap().insert(
                proxy_session_id.clone(),
                ProxySessionMeta {
                    input_tx,
                    output_tx: output_tx.clone(),
                    shutdown_tx: shutdown_tx.clone(),
                    detached_at: None,
                    attached: attached.clone(),
                    attach_notify: attach_notify.clone(),
                },
            );

            tokio::spawn(proxy_reader_task(
                tcp_r,
                output_tx,
                attached,
                attach_notify,
                shutdown_tx.clone(),
                proxy_sessions.clone(),
                proxy_session_id.clone(),
            ));
            tokio::spawn(proxy_writer_task(tcp_w, input_rx, shutdown_tx));

            let ttl = DETACHED_PROXY_TTL.as_secs();
            println!(
                "[proxy {proxy_session_id}] started → {target_host}:{target_port} \
                 (resume grace {ttl}s)"
            );
            run_proxy_stream(send, recv, proxy_sessions, proxy_session_id, true).await
        }
        Message::ProxyResume { proxy_session_id } => {
            let can_resume = {
                let locked = proxy_sessions.lock().unwrap();
                match locked.get(&proxy_session_id) {
                    Some(meta)
                        if meta.detached_at.is_some() && !meta.attached.load(Ordering::SeqCst) =>
                    {
                        true
                    }
                    _ => false,
                }
            };
            if !can_resume {
                let mut send = send;
                send_msg(
                    &mut send,
                    &Message::ForwardError {
                        reason: "proxy session not resumable".into(),
                    },
                )
                .await
                .ok();
                anyhow::bail!("proxy resume rejected");
            }

            run_proxy_stream(send, recv, proxy_sessions, proxy_session_id, false).await
        }
        other => anyhow::bail!("unexpected proxy message: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Exec — job runner + handlers
// ---------------------------------------------------------------------------
//
// The job runner drains stdout and stderr from the child into the ring
// buffer. We read both pipes concurrently under a single tokio::select! so
// order-of-arrival between the two streams is preserved (every chunk still
// gets a unique seq, so attachers can distinguish them).

async fn job_runner(
    jobs: Jobs,
    job_id: String,
    mut child: tokio::process::Child,
    mut stdout: tokio::process::ChildStdout,
    mut stderr: tokio::process::ChildStderr,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let mut out_buf = [0u8; 8192];
    let mut err_buf = [0u8; 8192];
    let mut stdout_done = false;
    let mut stderr_done = false;

    loop {
        tokio::select! {
            biased;

            _ = &mut shutdown_rx => {
                let _ = child.start_kill();
                break;
            }

            n = stdout.read(&mut out_buf), if !stdout_done => {
                match n {
                    Ok(0) | Err(_) => stdout_done = true,
                    Ok(n) => {
                        let mut locked = jobs.lock().unwrap();
                        if let Some(meta) = locked.get_mut(&job_id) {
                            job_push_chunk(meta, StdStream::Stdout, out_buf[..n].to_vec());
                        }
                    }
                }
            }

            n = stderr.read(&mut err_buf), if !stderr_done => {
                match n {
                    Ok(0) | Err(_) => stderr_done = true,
                    Ok(n) => {
                        let mut locked = jobs.lock().unwrap();
                        if let Some(meta) = locked.get_mut(&job_id) {
                            job_push_chunk(meta, StdStream::Stderr, err_buf[..n].to_vec());
                        }
                    }
                }
            }

            // Only wait() once both pipes are drained so we don't miss
            // late output between exit-notification and pipe close.
            status = child.wait(), if stdout_done && stderr_done => {
                let (code, status_enum) = match status {
                    Ok(s) => {
                        let code = s.code();
                        let st = match code {
                            Some(0) => JobStatus::Succeeded,
                            _ => JobStatus::Failed,
                        };
                        (code, st)
                    }
                    Err(_) => (None, JobStatus::Failed),
                };

                let mut locked = jobs.lock().unwrap();
                if let Some(meta) = locked.get_mut(&job_id) {
                    meta.status = status_enum;
                    meta.exit_code = code;
                    meta.finished_at = Some(Instant::now());
                    meta.finished_at_unix = Some(unix_now());
                    // Bump version one last time so attachers wake and see
                    // the finished state.
                    let v = meta.last_seq + 1;
                    let _ = meta.version_tx.send(v);
                    println!(
                        "[job {}] finished exit={:?} status={:?}",
                        meta.job_id, meta.exit_code, meta.status
                    );
                }
                return;
            }
        }
    }

    // Shutdown path — drain as much as we can, then record as Failed.
    let _ = child.wait().await;
    let mut locked = jobs.lock().unwrap();
    if let Some(meta) = locked.get_mut(&job_id) {
        if matches!(meta.status, JobStatus::Running | JobStatus::Detached) {
            meta.status = JobStatus::Failed;
            meta.finished_at = Some(Instant::now());
            meta.finished_at_unix = Some(unix_now());
            let v = meta.last_seq + 1;
            let _ = meta.version_tx.send(v);
            println!("[job {}] killed by server shutdown", meta.job_id);
        }
    }
}

/// Evict the oldest finished job if the registry is full. Returns true if we
/// made room, false if the registry is entirely full of running jobs (in
/// which case the caller should refuse the new submission).
fn evict_oldest_finished(jobs: &mut HashMap<String, JobMeta>) -> bool {
    if jobs.len() < JOB_REGISTRY_CAP {
        return true;
    }
    let victim = jobs
        .iter()
        .filter(|(_, m)| matches!(m.status, JobStatus::Succeeded | JobStatus::Failed))
        .min_by_key(|(_, m)| m.finished_at.unwrap_or(m.started_at))
        .map(|(id, _)| id.clone());
    if let Some(id) = victim {
        jobs.remove(&id);
        true
    } else {
        false
    }
}

async fn handle_exec_start(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    jobs: Jobs,
    command: Vec<String>,
) -> Result<()> {
    if command.is_empty() {
        send_msg(
            &mut send,
            &Message::ExecError {
                reason: "exec: command is empty".into(),
            },
        )
        .await
        .ok();
        anyhow::bail!("empty exec command");
    }

    let job_id = new_job_id()?;
    let command_display = command.join(" ");

    // Spawn the child. We run argv directly (no shell) for predictability —
    // users who need pipes or redirects pass `sh -c '<pipeline>'` as argv
    // explicitly. Matches kubectl / docker exec semantics.
    let mut cmd = tokio::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // Prevent stray PTY inheritance; this is a non-interactive job.
    cmd.kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let reason = format!("exec: spawn failed: {e}");
            send_msg(
                &mut send,
                &Message::ExecError {
                    reason: reason.clone(),
                },
            )
            .await
            .ok();
            anyhow::bail!(reason);
        }
    };

    let stdout = child.stdout.take().expect("stdout piped");
    let stderr = child.stderr.take().expect("stderr piped");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (version_tx, _version_rx) = watch::channel(0u64);
    let started_at_unix = unix_now();

    let had_room = {
        let mut locked = jobs.lock().unwrap();
        evict_oldest_finished(&mut locked)
    };
    if !had_room {
        let _ = child.start_kill();
        let reason = format!(
            "exec: job registry full ({JOB_REGISTRY_CAP} live jobs); \
             finish/clear some before submitting more"
        );
        send_msg(
            &mut send,
            &Message::ExecError {
                reason: reason.clone(),
            },
        )
        .await
        .ok();
        anyhow::bail!(reason);
    }
    {
        let mut locked = jobs.lock().unwrap();
        locked.insert(
            job_id.clone(),
            JobMeta {
                job_id: job_id.clone(),
                command: command.clone(),
                command_display: command_display.clone(),
                status: JobStatus::Running,
                started_at: Instant::now(),
                started_at_unix,
                finished_at: None,
                finished_at_unix: None,
                exit_code: None,
                buffer: VecDeque::new(),
                buffer_bytes: 0,
                oldest_seq: 0,
                last_seq: 0,
                version_tx,
                attach_count: 0,
                shutdown_tx: Some(shutdown_tx),
            },
        );
    }

    println!("[job {job_id}] started: {command_display}");

    // Ack so the client gets the id immediately (important for --detach).
    send_msg(
        &mut send,
        &Message::ExecStarted {
            job_id: job_id.clone(),
            started_at_unix,
        },
    )
    .await?;

    // Spawn the runner — it lives past this stream handler's exit, so
    // `--detach` works: the client can drop the stream and come back later.
    let jobs_bg = jobs.clone();
    let job_id_bg = job_id.clone();
    tokio::spawn(async move {
        job_runner(jobs_bg, job_id_bg, child, stdout, stderr, shutdown_rx).await;
    });

    // Stream live output until either the client drops or the job finishes.
    stream_job_output(&mut send, &mut recv, &jobs, &job_id, 0).await
}

/// Core streaming loop used by both `ExecStart` (foreground exec) and
/// `ExecAttach`. Reads chunks > `last_seen` from the job buffer and streams
/// them to the client; waits on the version watch for new activity; ends by
/// sending `ExecFinished` once the job has exited.
async fn stream_job_output(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    jobs: &Jobs,
    job_id: &str,
    mut last_seen: u64,
) -> Result<()> {
    let attach_subscribe: Option<watch::Receiver<u64>> = {
        let mut locked = jobs.lock().unwrap();
        locked.get_mut(job_id).map(|meta| {
            meta.attach_count += 1;
            meta.version_tx.subscribe()
        })
    };
    let (mut version_rx, _attach_guard) = match attach_subscribe {
        Some(rx) => (rx, AttachGuard::new(jobs.clone(), job_id.to_string())),
        None => {
            send_msg(
                send,
                &Message::ExecError {
                    reason: format!("job {job_id} not found"),
                },
            )
            .await
            .ok();
            anyhow::bail!("attach: unknown job {job_id}");
        }
    };

    // Report replay gap if client asked for seqs older than we have.
    let mut replay_gap: Option<u64> = None;
    {
        let locked = jobs.lock().unwrap();
        if let Some(meta) = locked.get(job_id) {
            if meta.oldest_seq > 0 && last_seen + 1 < meta.oldest_seq {
                replay_gap = Some(meta.oldest_seq);
            }
        }
    }
    if let Some(oldest_seq) = replay_gap {
        send_msg(send, &Message::ExecGap { oldest_seq }).await?;
        last_seen = oldest_seq - 1;
    }

    // Also listen for client-side Close so we exit the loop if the user
    // interrupts the stream but the job continues.
    let recv_done = false;

    loop {
        // Snapshot new chunks + finished state under the lock, then send
        // outside the lock.
        let (batch, finished_marker): (Vec<OutputChunk>, Option<(Option<i32>, u64)>) = {
            let locked = jobs.lock().unwrap();
            let meta = match locked.get(job_id) {
                Some(m) => m,
                None => break,
            };
            let batch: Vec<OutputChunk> = meta
                .buffer
                .iter()
                .filter(|c| c.seq > last_seen)
                .cloned()
                .collect();
            let finished = matches!(
                meta.status,
                JobStatus::Succeeded | JobStatus::Failed | JobStatus::Expired
            );
            let marker = if finished {
                Some((meta.exit_code, meta.finished_at_unix.unwrap_or(unix_now())))
            } else {
                None
            };
            (batch, marker)
        };

        for chunk in batch {
            send_msg(
                send,
                &Message::ExecOutput {
                    seq: chunk.seq,
                    stream: chunk.stream,
                    data: chunk.data,
                },
            )
            .await?;
            last_seen = chunk.seq;
        }

        if let Some((exit_code, finished_at_unix)) = finished_marker {
            send_msg(
                send,
                &Message::ExecFinished {
                    exit_code,
                    finished_at_unix,
                },
            )
            .await?;
            return Ok(());
        }

        // Block until either the job produces more or the client closes.
        tokio::select! {
            res = version_rx.changed() => {
                if res.is_err() {
                    // watch sender was dropped — the job was removed from
                    // the registry (expired / evicted). Treat as finished.
                    send_msg(
                        send,
                        &Message::ExecFinished {
                            exit_code: None,
                            finished_at_unix: unix_now(),
                        },
                    )
                    .await
                    .ok();
                    return Ok(());
                }
            }
            _ = recv.read_chunk(1, false), if !recv_done => {
                // Client closed the request stream — that's OK, the job
                // keeps running. In practice clients hold the recv-side
                // open until done, so this only fires when the user
                // SIGINTs the CLI. We treat it as "no more client
                // interest" and return early; the job continues in the
                // background, reachable via onyx attach / onyx logs.
                return Ok(());
            }
        }
    }

    Ok(())
}

/// Decrements the attach counter on drop so `JobSummary.attached` stays
/// accurate across normal exits, client cancellations, and panics.
struct AttachGuard {
    jobs: Jobs,
    job_id: String,
    active: bool,
}

impl AttachGuard {
    fn new(jobs: Jobs, job_id: String) -> Self {
        Self {
            jobs,
            job_id,
            active: true,
        }
    }
}

impl Drop for AttachGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Some(meta) = self.jobs.lock().unwrap().get_mut(&self.job_id) {
            if meta.attach_count > 0 {
                meta.attach_count -= 1;
            }
            // If the job is still live and nobody is attached, surface it
            // as Detached for `onyx jobs`.
            if meta.attach_count == 0 && matches!(meta.status, JobStatus::Running) {
                meta.status = JobStatus::Detached;
            } else if meta.attach_count > 0 && matches!(meta.status, JobStatus::Detached) {
                meta.status = JobStatus::Running;
            }
        }
    }
}

async fn handle_exec_attach(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    jobs: Jobs,
    job_id: String,
    last_seq: u64,
) -> Result<()> {
    // Flip Detached → Running on the metadata side when a client reattaches;
    // AttachGuard handles the reverse on drop.
    let exists = {
        let mut locked = jobs.lock().unwrap();
        match locked.get_mut(&job_id) {
            Some(meta) => {
                if matches!(meta.status, JobStatus::Detached) {
                    meta.status = JobStatus::Running;
                }
                true
            }
            None => false,
        }
    };
    if !exists {
        send_msg(
            &mut send,
            &Message::ExecError {
                reason: format!("job {job_id} not found"),
            },
        )
        .await
        .ok();
        anyhow::bail!("attach: unknown job {job_id}");
    }
    stream_job_output(&mut send, &mut recv, &jobs, &job_id, last_seq).await
}

async fn handle_exec_logs(
    mut send: quinn::SendStream,
    _recv: quinn::RecvStream,
    jobs: Jobs,
    job_id: String,
) -> Result<()> {
    let snapshot: Option<(Vec<OutputChunk>, u64, Option<(Option<i32>, u64)>)> = {
        let locked = jobs.lock().unwrap();
        locked.get(&job_id).map(|meta| {
            let chunks: Vec<OutputChunk> = meta.buffer.iter().cloned().collect();
            let finished = matches!(
                meta.status,
                JobStatus::Succeeded | JobStatus::Failed | JobStatus::Expired
            );
            let marker = if finished {
                Some((meta.exit_code, meta.finished_at_unix.unwrap_or(unix_now())))
            } else {
                None
            };
            (chunks, meta.oldest_seq, marker)
        })
    };
    let (chunks, oldest_seq, finished_state) = match snapshot {
        Some(s) => s,
        None => {
            send_msg(
                &mut send,
                &Message::ExecError {
                    reason: format!("job {job_id} not found"),
                },
            )
            .await
            .ok();
            anyhow::bail!("logs: unknown job {job_id}");
        }
    };

    if oldest_seq > 1 {
        // The buffer doesn't start from seq 1 → output was truncated. Tell
        // the client so it can note the gap to the user.
        send_msg(&mut send, &Message::ExecGap { oldest_seq }).await?;
    }

    for chunk in chunks {
        send_msg(
            &mut send,
            &Message::ExecOutput {
                seq: chunk.seq,
                stream: chunk.stream,
                data: chunk.data,
            },
        )
        .await?;
    }

    if let Some((exit_code, finished_at_unix)) = finished_state {
        send_msg(
            &mut send,
            &Message::ExecFinished {
                exit_code,
                finished_at_unix,
            },
        )
        .await?;
    }
    send.finish().ok();
    Ok(())
}

async fn handle_jobs_list(mut send: quinn::SendStream, jobs: Jobs) -> Result<()> {
    let summaries: Vec<JobSummary> = {
        let locked = jobs.lock().unwrap();
        let mut v: Vec<JobSummary> = locked.values().map(summarize_job).collect();
        v.sort_by_key(|s| std::cmp::Reverse(s.started_at_unix));
        v
    };
    send_msg(
        &mut send,
        &Message::JobsListResponse { jobs: summaries },
    )
    .await?;
    send.finish().ok();
    Ok(())
}

// ---------------------------------------------------------------------------
// Stream dispatcher — reads first message and routes to PTY or forward handler
// ---------------------------------------------------------------------------

async fn handle_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    sessions: Sessions,
    proxy_sessions: ProxySessions,
    jobs: Jobs,
) -> Result<()> {
    let first = recv_msg(&mut recv).await.context("reading first message")?;
    match first {
        Message::ForwardConnect { remote_port } => run_forward(send, recv, remote_port).await,
        Message::ProxyConnect { .. } | Message::ProxyResume { .. } => {
            handle_proxy_message(send, recv, proxy_sessions, first).await
        }
        Message::ExecStart { command } => handle_exec_start(send, recv, jobs, command).await,
        Message::ExecAttach { job_id, last_seq } => {
            handle_exec_attach(send, recv, jobs, job_id, last_seq).await
        }
        Message::ExecLogs { job_id } => handle_exec_logs(send, recv, jobs, job_id).await,
        Message::JobsList => handle_jobs_list(send, jobs).await,
        msg => run_session(send, recv, sessions, msg).await,
    }
}

// ---------------------------------------------------------------------------
// Connection stream handler — one per QUIC stream (Hello or Resume)
// ---------------------------------------------------------------------------

async fn run_session(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    sessions: Sessions,
    msg: Message,
) -> Result<()> {
    let session_id: String = match msg {
        // ── New session ──────────────────────────────────────────────────────
        Message::Hello { session_id, .. } => {
            let (master_raw, slave_raw) = open_pty().context("open_pty")?;
            let slave = OwnedFd(slave_raw);

            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
            // Launch tmux with onyx's config (uploaded by bootstrap client).
            // Falls back to a bare minimal config if the file isn't there yet
            // (e.g. direct-mode connections that skipped bootstrap).
            let tmux_cmd = format!(
                "if command -v tmux >/dev/null 2>&1; then \
                     conf=~/.config/onyx/tmux.conf; \
                     if [ ! -f \"$conf\" ]; then \
                         mkdir -p ~/.config/onyx; \
                         printf 'set -g mouse on\\nset -g history-limit 50000\\nset -g status-style bg=colour234,fg=colour240\\nset -g pane-border-style fg=colour236\\nset -g pane-active-border-style fg=colour240\\n' > \"$conf\"; \
                     fi; \
                     tmux -f \"$conf\" new-session -A -s \"onyx-{session_id}\" -e ONYX_MODE=quic; \
                 else \
                     echo '[onyx] tip: install tmux for scroll, copy-paste and session persistence'; \
                     exec \"$ONYX_LOGIN_SHELL\"; \
                 fi"
            );
            let mut cmd = std::process::Command::new("sh");
            cmd.arg("-c").arg(&tmux_cmd);
            // ONYX_MODE=quic is inherited by the exec-$SHELL fallback path.
            cmd.env("ONYX_MODE", "quic");
            cmd.env("ONYX_LOGIN_SHELL", shell);
            // TERM must be set explicitly: onyx-server starts as a daemon (nohup, no
            // controlling terminal) so TERM is unset in its environment.  tmux refuses
            // to start without a recognisable TERM value and prints
            // "open terminal failed: terminal does not support clear".
            cmd.env("TERM", "xterm-256color");
            // SAFETY: runs in the forked child (single-threaded) before exec.
            unsafe {
                cmd.pre_exec(move || {
                    libc::setsid();
                    libc::ioctl(slave_raw, libc::TIOCSCTTY as _, 0_i32);
                    libc::dup2(slave_raw, 0);
                    libc::dup2(slave_raw, 1);
                    libc::dup2(slave_raw, 2);
                    if slave_raw > 2 {
                        libc::close(slave_raw);
                    }
                    Ok(())
                });
            }
            use std::process::Stdio;
            let child = cmd
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .context("spawning shell")?;
            drop(slave); // parent closes slave; child has it via dup2

            unsafe {
                let f = libc::fcntl(master_raw, libc::F_GETFL);
                libc::fcntl(master_raw, libc::F_SETFL, f | libc::O_NONBLOCK);
            }
            let async_master =
                tokio::io::unix::AsyncFd::new(unsafe { std::fs::File::from_raw_fd(master_raw) })?;

            let (cmd_tx, cmd_rx) = mpsc::channel::<PtyCmd>(64);
            let (out_tx, _) = broadcast::channel::<(u64, Vec<u8>)>(512);
            let (shut_tx, shut_rx) = oneshot::channel::<()>();

            // Clone out_tx for the PTY task before moving the original into SessionMeta.
            let out_tx_task = out_tx.clone();

            sessions.lock().unwrap().insert(
                session_id.clone(),
                SessionMeta {
                    resume_token: random_token()?,
                    pty_cmd_tx: cmd_tx,
                    output_tx: out_tx,
                    shutdown_tx: Some(shut_tx),
                    detached_at: None,
                    // Takeover channel + epoch are installed by the
                    // common attach path below, so Hello and Resume share
                    // one path for takeover semantics.
                    takeover_tx: None,
                    attach_epoch: 0,
                },
            );

            let sessions2 = sessions.clone();
            let sid2 = session_id.clone();
            tokio::spawn(pty_task(
                async_master,
                child,
                cmd_rx,
                out_tx_task,
                shut_rx,
                sessions2,
                sid2,
            ));

            println!("[session {session_id}] started");
            session_id
        }

        // ── Reconnect ────────────────────────────────────────────────────────
        Message::Resume {
            session_id,
            resume_token,
            ..
        } => {
            // Validate under the lock; never hold the guard across an await.
            //
            // We no longer reject a Resume for "session already attached".
            // Instead, the common attach block below always takes over —
            // signals the previous handler's oneshot and claims the
            // session. This makes reconnect after a transport drop
            // deterministic and bounded, instead of waiting for the old
            // handler (which may be blocked on output_rx.recv() with no
            // PTY activity) to notice the dead connection.
            let reject: Option<String> = {
                let locked = sessions.lock().unwrap();
                match locked.get(&session_id) {
                    None => Some("session not found".into()),
                    Some(meta) if meta.resume_token != resume_token => Some("invalid token".into()),
                    Some(_) => None,
                }
            }; // MutexGuard dropped here

            if let Some(reason) = reject {
                send_msg(
                    &mut send,
                    &Message::Close {
                        reason: reason.clone(),
                    },
                )
                .await
                .ok();
                anyhow::bail!("resume rejected: {reason}");
            }
            println!("[session {session_id}] resumed");
            session_id
        }

        other => {
            send_msg(
                &mut send,
                &Message::Close {
                    reason: "expected Hello or Resume".into(),
                },
            )
            .await
            .ok();
            anyhow::bail!("unexpected first message: {other:?}");
        }
    };

    // Common attach path: signal the previous attach handler to exit
    // (forced takeover), install our takeover channel, bump the attach
    // epoch, and capture channel handles. After this block we own the
    // session's "currently attached" state until we either exit normally
    // (at which point we clear it if we are still current) or are
    // evicted by a newer attach (at which point we leave state alone).
    let (takeover_tx, mut takeover_rx) = oneshot::channel::<()>();
    let (mut output_rx, cmd_tx, resume_token, my_epoch) = {
        let mut locked = sessions.lock().unwrap();
        let meta = locked
            .get_mut(&session_id)
            .ok_or_else(|| anyhow::anyhow!("session disappeared before handshake"))?;

        // Evict the previous handler if one is attached.
        if let Some(old) = meta.takeover_tx.take() {
            let _ = old.send(());
            println!("[session {session_id}] reclaimed (evicted previous attacher)");
        }
        meta.takeover_tx = Some(takeover_tx);
        meta.attach_epoch = meta.attach_epoch.wrapping_add(1);
        meta.detached_at = None;
        let epoch = meta.attach_epoch;

        (
            meta.output_tx.subscribe(),
            meta.pty_cmd_tx.clone(),
            meta.resume_token.clone(),
            epoch,
        )
    };

    send_msg(
        &mut send,
        &Message::Welcome {
            session_id: session_id.clone(),
            resume_token,
        },
    )
    .await?;

    // Client → PTY (runs in a separate task so we can drive the output loop here)
    let mut input_task = tokio::spawn(async move {
        loop {
            match recv_msg(&mut recv).await {
                Ok(Message::Input { data }) => {
                    if cmd_tx.send(PtyCmd::Input(data)).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Resize { cols, rows }) => {
                    if cmd_tx.send(PtyCmd::Resize(cols, rows)).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Close { .. }) | Err(_) => break,
                Ok(other) => eprintln!("[server] unexpected: {other:?}"),
            }
        }
    });

    // Three-way select: detect eviction by a newer attach, detect a dead
    // client stream (input_task exits as soon as recv_msg errors — faster
    // than waiting for the next PTY output to surface the failed send),
    // and drive PTY→client output. The old single-loop on output_rx.recv()
    // would hang forever on quiet shells after a transport drop; this
    // fixes the "stuck on session already attached" root cause.
    let exit_reason: &'static str = 'pump: loop {
        tokio::select! {
            biased;

            _ = &mut takeover_rx => {
                // Newer attach took over. Leave meta state alone — it is
                // now owned by the new handler.
                input_task.abort();
                send.finish().ok();
                println!(
                    "[session {session_id}] attach epoch {my_epoch} evicted by newer attach"
                );
                return Ok(());
            }

            res = &mut input_task => {
                // Client input stream closed — either a graceful Close or
                // a broken transport. Fall through to the detached path.
                let _ = res;
                break 'pump "client stream closed";
            }

            msg = output_rx.recv() => {
                match msg {
                    Ok((seq, data)) => {
                        if send_msg(&mut send, &Message::Output { seq, data })
                            .await
                            .is_err()
                        {
                            break 'pump "send to client failed";
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Shell exited; pty_task already removed the
                        // session. Nothing to mark as detached.
                        send_msg(
                            &mut send,
                            &Message::Close {
                                reason: "shell exited".into(),
                            },
                        )
                        .await
                        .ok();
                        send.finish().ok();
                        input_task.abort();
                        return Ok(());
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Client too slow; some frames dropped, keep going.
                    }
                }
            }
        }
    };

    // Client disconnected. Only update meta if we are still the current
    // attacher — otherwise a newer handler already owns the state and we
    // would race-overwrite it.
    input_task.abort();
    {
        let mut locked = sessions.lock().unwrap();
        if let Some(meta) = locked.get_mut(&session_id) {
            if meta.attach_epoch == my_epoch {
                meta.detached_at = Some(Instant::now());
                meta.takeover_tx = None;
                let hrs = DETACHED_SESSION_TTL.as_secs() / 3600;
                println!(
                    "[session {session_id}] detached (retention {hrs}h, reason: {exit_reason})"
                );
            } else {
                println!(
                    "[session {session_id}] epoch {my_epoch} retired ({exit_reason}; current epoch {})",
                    meta.attach_epoch
                );
            }
        }
    }
    send.finish().ok();
    Ok(())
}

// ---------------------------------------------------------------------------
// GC task — reaps sessions detached past their retention window.
//
// Only sessions with a set `detached_at` are ever considered. Healthy
// attached sessions are never touched.
// ---------------------------------------------------------------------------

async fn gc_task(sessions: Sessions, proxy_sessions: ProxySessions, jobs: Jobs) {
    loop {
        tokio::time::sleep(GC_INTERVAL).await;
        let now = Instant::now();
        {
            let mut locked = sessions.lock().unwrap();
            let expired: Vec<String> = locked
                .iter()
                .filter_map(|(id, meta)| {
                    meta.detached_at
                        .filter(|&t| now.duration_since(t) >= DETACHED_SESSION_TTL)
                        .map(|_| id.clone())
                })
                .collect();
            for id in &expired {
                if let Some(mut meta) = locked.remove(id) {
                    if let Some(tx) = meta.shutdown_tx.take() {
                        let _ = tx.send(());
                    }
                    println!("[session {id}] expired");
                }
            }
        }

        let expired_proxy: Vec<String> = {
            let locked = proxy_sessions.lock().unwrap();
            locked
                .iter()
                .filter_map(|(id, meta)| {
                    meta.detached_at
                        .filter(|&t| now.duration_since(t) >= DETACHED_PROXY_TTL)
                        .map(|_| id.clone())
                })
                .collect()
        };
        for id in &expired_proxy {
            if let Some(meta) = proxy_sessions.lock().unwrap().remove(id) {
                let _ = meta.shutdown_tx.send(true);
                println!("[proxy {id}] grace expired");
            }
        }

        // Finished exec jobs stay around for FINISHED_JOB_TTL so `onyx
        // logs` / `onyx jobs` can still see them. Running jobs are never
        // reaped here; they leave the registry when the child exits.
        let expired_jobs: Vec<String> = {
            let locked = jobs.lock().unwrap();
            locked
                .iter()
                .filter_map(|(id, meta)| {
                    meta.finished_at
                        .filter(|&t| now.duration_since(t) >= FINISHED_JOB_TTL)
                        .map(|_| id.clone())
                })
                .collect()
        };
        for id in &expired_jobs {
            if let Some(meta) = jobs.lock().unwrap().remove(id) {
                drop(meta.shutdown_tx);
                println!("[job {id}] expired (retention 1h)");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

async fn handle_connection(
    incoming: quinn::Incoming,
    sessions: Sessions,
    proxy_sessions: ProxySessions,
    jobs: Jobs,
) -> Result<()> {
    let remote = incoming.remote_address();
    println!("[server] incoming from {remote} (pre-handshake)");

    let connecting = incoming.accept().context("accept")?;
    let conn = connecting
        .await
        .map_err(|e| {
            eprintln!("[server] handshake FAILED from {remote}: {e:#}");
            e
        })
        .context("handshake")?;
    println!("[server] handshake OK   from {remote}");

    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let s = sessions.clone();
                let p = proxy_sessions.clone();
                let j = jobs.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(send, recv, s, p, j).await {
                        eprintln!("[server] stream error: {e:#}");
                    }
                });
            }
            Err(e) => {
                println!("[server] connection from {remote} closed: {e}");
                break;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let proxy_sessions: ProxySessions = Arc::new(Mutex::new(HashMap::new()));
    let jobs: Jobs = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(gc_task(
        sessions.clone(),
        proxy_sessions.clone(),
        jobs.clone(),
    ));

    let quic_port: u16 = {
        let mut args = std::env::args().skip(1);
        let mut port = None;
        while let Some(a) = args.next() {
            if a == "--port" {
                port = args.next().and_then(|v| v.parse::<u16>().ok());
            }
        }
        port.or_else(|| {
            std::env::var("ONYX_PORT")
                .ok()
                .and_then(|v| v.trim().parse::<u16>().ok())
        })
        .unwrap_or(DEFAULT_PORT)
    };
    let addr: SocketAddr = format!("0.0.0.0:{quic_port}").parse()?;
    let (server_cfg, fingerprint) = make_server_config()?;
    let endpoint = Endpoint::server(server_cfg, addr)?;
    let bound = endpoint.local_addr()?;
    println!("[server] listening on {bound}  (ALPN: onyx)");
    println!("[server] fingerprint  {fingerprint}");

    while let Some(incoming) = endpoint.accept().await {
        let s = sessions.clone();
        let p = proxy_sessions.clone();
        let j = jobs.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, s, p, j).await {
                eprintln!("[server] connection error: {e:#}");
            }
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests for the job ring buffer
// ---------------------------------------------------------------------------
//
// These exercise the pure-logic pieces of the exec layer without spawning a
// process or opening a QUIC connection. The ring-buffer invariants are the
// ones most likely to regress silently (gap reporting depends on them).

#[cfg(test)]
mod job_tests {
    use super::*;

    fn mk_meta() -> JobMeta {
        let (tx, _rx) = watch::channel(0u64);
        let (shut_tx, _shut_rx) = oneshot::channel();
        JobMeta {
            job_id: "job_test".into(),
            command: vec!["true".into()],
            command_display: "true".into(),
            status: JobStatus::Running,
            started_at: Instant::now(),
            started_at_unix: 0,
            finished_at: None,
            finished_at_unix: None,
            exit_code: None,
            buffer: VecDeque::new(),
            buffer_bytes: 0,
            oldest_seq: 0,
            last_seq: 0,
            version_tx: tx,
            attach_count: 0,
            shutdown_tx: Some(shut_tx),
        }
    }

    #[test]
    fn seqs_are_monotonic_and_oldest_seq_tracks_first_chunk() {
        let mut m = mk_meta();
        job_push_chunk(&mut m, StdStream::Stdout, b"hello".to_vec());
        job_push_chunk(&mut m, StdStream::Stderr, b"world".to_vec());
        assert_eq!(m.last_seq, 2);
        assert_eq!(m.oldest_seq, 1);
        assert_eq!(m.buffer.len(), 2);
        assert_eq!(m.buffer_bytes, 10);
    }

    #[test]
    fn buffer_evicts_oldest_when_cap_exceeded_and_reports_gap() {
        let mut m = mk_meta();
        // Push chunks just under the cap, then push one that forces eviction.
        let chunk_size = 1024 * 1024; // 1 MiB
        for _ in 0..4 {
            job_push_chunk(&mut m, StdStream::Stdout, vec![0u8; chunk_size]);
        }
        assert_eq!(m.last_seq, 4);
        assert_eq!(m.oldest_seq, 1);
        // Next push triggers at least one eviction.
        job_push_chunk(&mut m, StdStream::Stdout, vec![0u8; chunk_size]);
        assert_eq!(m.last_seq, 5);
        assert!(
            m.oldest_seq > 1,
            "expected gap after cap-triggered eviction, oldest_seq={}",
            m.oldest_seq
        );
        assert!(
            m.buffer_bytes <= JOB_BUFFER_CAP_BYTES,
            "buffer_bytes exceeds cap: {}",
            m.buffer_bytes
        );
    }

    #[test]
    fn version_watch_bumps_on_every_push() {
        let mut m = mk_meta();
        let mut rx = m.version_tx.subscribe();
        assert_eq!(*rx.borrow_and_update(), 0);
        job_push_chunk(&mut m, StdStream::Stdout, b"a".to_vec());
        assert_eq!(*rx.borrow_and_update(), 1);
        job_push_chunk(&mut m, StdStream::Stdout, b"b".to_vec());
        assert_eq!(*rx.borrow_and_update(), 2);
    }

    #[test]
    fn evict_oldest_finished_prefers_finished_jobs() {
        let mut map: HashMap<String, JobMeta> = HashMap::new();
        // Running job, should NOT be evicted.
        let mut r = mk_meta();
        r.job_id = "job_running".into();
        map.insert(r.job_id.clone(), r);
        // Finished job, should be evicted when at cap.
        let mut f = mk_meta();
        f.job_id = "job_finished".into();
        f.status = JobStatus::Succeeded;
        f.finished_at = Some(Instant::now());
        map.insert(f.job_id.clone(), f);

        // Not at cap: no-op, returns true.
        assert!(evict_oldest_finished(&mut map));
        assert_eq!(map.len(), 2);

        // Fake cap by adding placeholders so the map is full. Fast path
        // through the cap check works off `len() < JOB_REGISTRY_CAP`.
        for i in 0..(JOB_REGISTRY_CAP - 2) {
            let mut m = mk_meta();
            m.job_id = format!("job_filler_{i}");
            m.status = JobStatus::Succeeded;
            m.finished_at = Some(Instant::now());
            map.insert(m.job_id.clone(), m);
        }
        assert_eq!(map.len(), JOB_REGISTRY_CAP);
        assert!(evict_oldest_finished(&mut map));
        assert!(map.len() < JOB_REGISTRY_CAP);
        assert!(map.contains_key("job_running"));
    }
}

#[cfg(test)]
mod session_takeover_tests {
    //! Pure-logic tests for the forced-takeover handshake on SessionMeta.
    //! No real QUIC, no real PTY — these exercise the epoch / takeover_tx
    //! state transitions under the mutex, which is where the
    //! "stuck on session already attached" bug lived.
    use super::*;

    fn mk_session() -> SessionMeta {
        // The channels themselves are not exercised by these tests; we
        // only care about takeover_tx / attach_epoch / detached_at state.
        let (pty_tx, _pty_rx) = mpsc::channel::<PtyCmd>(1);
        let (out_tx, _out_rx) = broadcast::channel::<(u64, Vec<u8>)>(1);
        let (shut_tx, _shut_rx) = oneshot::channel::<()>();
        SessionMeta {
            resume_token: "tok".into(),
            pty_cmd_tx: pty_tx,
            output_tx: out_tx,
            shutdown_tx: Some(shut_tx),
            detached_at: Some(Instant::now()),
            takeover_tx: None,
            attach_epoch: 0,
        }
    }

    /// Simulates one run_session attach: evict previous takeover (if any),
    /// install our own, bump epoch, clear detached_at. Returns our epoch
    /// and the previous takeover_tx so the test can verify delivery.
    fn do_attach(meta: &mut SessionMeta) -> (u64, oneshot::Receiver<()>) {
        let (tx, rx) = oneshot::channel::<()>();
        let evicted = meta.takeover_tx.take();
        if let Some(evicted) = evicted {
            let _ = evicted.send(());
        }
        meta.takeover_tx = Some(tx);
        meta.attach_epoch = meta.attach_epoch.wrapping_add(1);
        meta.detached_at = None;
        (meta.attach_epoch, rx)
    }

    #[test]
    fn second_attach_signals_first_via_takeover_channel() {
        let mut meta = mk_session();
        let (epoch_a, mut rx_a) = do_attach(&mut meta);
        assert_eq!(epoch_a, 1);
        assert!(meta.detached_at.is_none());
        // rx_a not yet fired.
        assert!(rx_a.try_recv().is_err());

        let (epoch_b, _rx_b) = do_attach(&mut meta);
        assert_eq!(epoch_b, 2);
        // The previous attacher should now observe a takeover signal —
        // exactly the wake-up that rescues the old run_session's
        // blocked output_rx.recv() and lets it exit cleanly.
        assert!(rx_a.try_recv().is_ok());
    }

    #[test]
    fn old_attacher_exit_respects_epoch_and_leaves_newer_state_alone() {
        let mut meta = mk_session();
        let (epoch_a, _rx_a) = do_attach(&mut meta);
        let (epoch_b, _rx_b) = do_attach(&mut meta);
        assert_ne!(epoch_a, epoch_b);

        // Old attacher (epoch_a) now trying to mark detached must find
        // that it's no longer current and leave state alone. Simulate the
        // epoch check from run_session's exit path:
        if meta.attach_epoch == epoch_a {
            panic!("old attacher should not still be current");
        }
        // Takeover is owned by the newer attacher; detached_at stays None.
        assert!(meta.takeover_tx.is_some());
        assert!(meta.detached_at.is_none());
    }

    #[test]
    fn epoch_wraps_monotonically_and_never_collides_in_practice() {
        // We use wrapping_add to avoid panic on overflow — even at one
        // attach/s this would take 500 billion years to roll over, so a
        // real collision is astronomically unlikely, but it's worth
        // locking in the shape of the counter anyway.
        let mut meta = mk_session();
        meta.attach_epoch = u64::MAX - 1;
        let (e0, _) = do_attach(&mut meta);
        let (e1, _) = do_attach(&mut meta);
        let (e2, _) = do_attach(&mut meta);
        assert_eq!(e0, u64::MAX);
        assert_eq!(e1, 0);
        assert_eq!(e2, 1);
    }
}
