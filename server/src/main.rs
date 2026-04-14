use anyhow::{Context, Result};
use quinn::{Endpoint, ServerConfig};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use shared::{Message, DEFAULT_PORT};
use std::{
    collections::HashMap,
    ffi::CStr,
    net::SocketAddr,
    os::unix::{io::FromRawFd, process::CommandExt},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{broadcast, mpsc, oneshot};

// ---------------------------------------------------------------------------
// TLS / QUIC setup
// ---------------------------------------------------------------------------

/// SHA-256 of the cert DER, formatted as "sha256:<hex>".
fn cert_fingerprint(cert_der: &[u8]) -> String {
    let hash = ring::digest::digest(&ring::digest::SHA256, cert_der);
    format!("sha256:{}", hash.as_ref().iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// Load a persistent self-signed cert from disk, or generate + save a new one.
/// Returns (ServerConfig, fingerprint_string).
/// The fingerprint is also written to server.fingerprint so the client can
/// read it during bootstrap and perform TOFU cert pinning.
fn make_server_config() -> Result<(ServerConfig, String)> {
    let home     = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let data_dir = std::path::PathBuf::from(&home).join(".local/share/onyx");
    std::fs::create_dir_all(&data_dir).context("creating data dir")?;

    let cert_path = data_dir.join("server.crt");
    let key_path  = data_dir.join("server.key");

    // Load existing cert+key, or generate and persist a new pair.
    let (cert_der, key_der): (Vec<u8>, Vec<u8>) =
        if cert_path.exists() && key_path.exists() {
            (std::fs::read(&cert_path).context("reading server.crt")?,
             std::fs::read(&key_path).context("reading server.key")?)
        } else {
            let certified = rcgen::generate_simple_self_signed(
                vec!["localhost".to_string(), "127.0.0.1".to_string()]
            ).context("generating self-signed certificate")?;
            let cert = certified.cert.der().to_vec();
            let key  = certified.key_pair.serialize_der();
            std::fs::write(&cert_path, &cert).context("writing server.crt")?;
            std::fs::write(&key_path,  &key).context("writing server.key")?;
            (cert, key)
        };

    let fingerprint = cert_fingerprint(&cert_der);
    // Write fingerprint so bootstrap can read it via SSH and send to client.
    std::fs::write(data_dir.join("server.fingerprint"), &fingerprint)
        .context("writing server.fingerprint")?;

    let key  = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let cert = rustls::pki_types::CertificateDer::from(cert_der);
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("building TLS config")?;
    tls.alpn_protocols = vec![b"onyx".to_vec()];
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .context("wrapping for QUIC")?;
    Ok((ServerConfig::with_crypto(Arc::new(quic)), fingerprint))
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
}

type Sessions = Arc<Mutex<HashMap<String, SessionMeta>>>;

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
    let tcp = match tokio::net::TcpStream::connect(
        std::net::SocketAddr::from(([127, 0, 0, 1], remote_port))
    ).await {
        Ok(s) => {
            send_msg(&mut send, &Message::ForwardAck).await?;
            s
        }
        Err(e) => {
            send_msg(&mut send, &Message::ForwardError { reason: e.to_string() }).await.ok();
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

// ---------------------------------------------------------------------------
// Stream dispatcher — reads first message and routes to PTY or forward handler
// ---------------------------------------------------------------------------

async fn handle_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    sessions: Sessions,
) -> Result<()> {
    let first = recv_msg(&mut recv).await.context("reading first message")?;
    match first {
        Message::ForwardConnect { remote_port } => run_forward(send, recv, remote_port).await,
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
                         printf 'set -g mouse on\\nset -g history-limit 50000\\n' > \"$conf\"; \
                     fi; \
                     tmux -f \"$conf\" new-session -A -s \"onyx-{session_id}\" -e ONYX_MODE=quic; \
                 else \
                     echo '[onyx] tip: install tmux for scroll, copy-paste and session persistence'; \
                     exec {shell}; \
                 fi"
            );
            let mut cmd = std::process::Command::new("sh");
            cmd.arg("-c").arg(&tmux_cmd);
            // ONYX_MODE=quic is inherited by the exec-$SHELL fallback path.
            cmd.env("ONYX_MODE", "quic");
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
                    if slave_raw > 2 { libc::close(slave_raw); }
                    Ok(())
                });
            }
            use std::process::Stdio;
            let child = cmd
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
                .spawn().context("spawning shell")?;
            drop(slave); // parent closes slave; child has it via dup2

            unsafe {
                let f = libc::fcntl(master_raw, libc::F_GETFL);
                libc::fcntl(master_raw, libc::F_SETFL, f | libc::O_NONBLOCK);
            }
            let async_master = tokio::io::unix::AsyncFd::new(
                unsafe { std::fs::File::from_raw_fd(master_raw) },
            )?;

            let (cmd_tx, cmd_rx) = mpsc::channel::<PtyCmd>(64);
            let (out_tx, _) = broadcast::channel::<(u64, Vec<u8>)>(512);
            let (shut_tx, shut_rx) = oneshot::channel::<()>();

            // Clone out_tx for the PTY task before moving the original into SessionMeta.
            let out_tx_task = out_tx.clone();

            sessions.lock().unwrap().insert(
                session_id.clone(),
                SessionMeta {
                    resume_token: format!("tok-{session_id}"),
                    pty_cmd_tx: cmd_tx,
                    output_tx: out_tx,
                    shutdown_tx: Some(shut_tx),
                    detached_at: None,
                },
            );

            let sessions2 = sessions.clone();
            let sid2 = session_id.clone();
            tokio::spawn(pty_task(async_master, child, cmd_rx, out_tx_task, shut_rx, sessions2, sid2));

            println!("[server] new session {session_id}");
            session_id
        }

        // ── Reconnect ────────────────────────────────────────────────────────
        Message::Resume { session_id, resume_token, .. } => {
            // Validate under the lock; never hold the guard across an await.
            let reject: Option<String> = {
                let mut locked = sessions.lock().unwrap();
                match locked.get_mut(&session_id) {
                    None => Some("session not found".into()),
                    Some(meta) if meta.resume_token != resume_token => Some("invalid token".into()),
                    Some(meta) => {
                        meta.detached_at = None;
                        None
                    }
                }
            }; // MutexGuard dropped here

            if let Some(reason) = reject {
                send_msg(&mut send, &Message::Close { reason: reason.clone() }).await.ok();
                anyhow::bail!("resume rejected: {reason}");
            }
            println!("[server] reattached to session {session_id}");
            session_id
        }

        other => {
            send_msg(&mut send, &Message::Close { reason: "expected Hello or Resume".into() })
                .await.ok();
            anyhow::bail!("unexpected first message: {other:?}");
        }
    };

    // Get channels — same code path for Hello and Resume.
    let (mut output_rx, cmd_tx, resume_token) = {
        let locked = sessions.lock().unwrap();
        let meta = locked
            .get(&session_id)
            .ok_or_else(|| anyhow::anyhow!("session disappeared before handshake"))?;
        (meta.output_tx.subscribe(), meta.pty_cmd_tx.clone(), meta.resume_token.clone())
    };

    send_msg(&mut send, &Message::Welcome {
        session_id: session_id.clone(),
        resume_token,
    })
    .await?;

    // Client → PTY (runs in a separate task so we can drive the output loop here)
    let input_task = tokio::spawn(async move {
        loop {
            match recv_msg(&mut recv).await {
                Ok(Message::Input { data }) => {
                    if cmd_tx.send(PtyCmd::Input(data)).await.is_err() { break; }
                }
                Ok(Message::Resize { cols, rows }) => {
                    if cmd_tx.send(PtyCmd::Resize(cols, rows)).await.is_err() { break; }
                }
                Ok(Message::Close { .. }) | Err(_) => break,
                Ok(other) => eprintln!("[server] unexpected: {other:?}"),
            }
        }
    });

    // PTY → client
    loop {
        match output_rx.recv().await {
            Ok((seq, data)) => {
                if send_msg(&mut send, &Message::Output { seq, data }).await.is_err() {
                    break; // client disconnected
                }
            }
            Err(broadcast::error::RecvError::Closed) => {
                // Shell exited; pty_task already removed the session.
                send_msg(&mut send, &Message::Close { reason: "shell exited".into() })
                    .await.ok();
                send.finish().ok();
                input_task.abort();
                return Ok(());
            }
            Err(broadcast::error::RecvError::Lagged(_)) => {
                // Client was too slow and some frames were dropped; keep going.
            }
        }
    }

    // Client disconnected (send_msg failed above).
    input_task.abort();
    if let Some(meta) = sessions.lock().unwrap().get_mut(&session_id) {
        meta.detached_at = Some(Instant::now());
        println!("[server] session {session_id}: detached, GC in 5 min");
    }
    send.finish().ok();
    Ok(())
}

// ---------------------------------------------------------------------------
// GC task — runs every 30 s, kills sessions detached for > 5 min
// ---------------------------------------------------------------------------

async fn gc_task(sessions: Sessions) {
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
        let now = Instant::now();
        let mut locked = sessions.lock().unwrap();
        let expired: Vec<String> = locked
            .iter()
            .filter_map(|(id, meta)| {
                meta.detached_at
                    .filter(|&t| now.duration_since(t) >= Duration::from_secs(300))
                    .map(|_| id.clone())
            })
            .collect();
        for id in &expired {
            if let Some(mut meta) = locked.remove(id) {
                if let Some(tx) = meta.shutdown_tx.take() {
                    let _ = tx.send(());
                }
                println!("[server] session {id}: GC expired");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------

async fn handle_connection(incoming: quinn::Incoming, sessions: Sessions) -> Result<()> {
    let remote = incoming.remote_address();
    println!("[server] incoming from {remote} (pre-handshake)");

    let connecting = incoming.accept().context("accept")?;
    let conn = connecting.await.map_err(|e| {
        eprintln!("[server] handshake FAILED from {remote}: {e:#}");
        e
    }).context("handshake")?;
    println!("[server] handshake OK   from {remote}");

    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let s = sessions.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(send, recv, s).await {
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
    rustls::crypto::ring::default_provider().install_default().ok();

    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    tokio::spawn(gc_task(sessions.clone()));

    let addr: SocketAddr = format!("0.0.0.0:{DEFAULT_PORT}").parse()?;
    let (server_cfg, fingerprint) = make_server_config()?;
    let endpoint = Endpoint::server(server_cfg, addr)?;
    let bound = endpoint.local_addr()?;
    println!("[server] listening on {bound}  (ALPN: onyx)");
    println!("[server] fingerprint  {fingerprint}");

    while let Some(incoming) = endpoint.accept().await {
        let s = sessions.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, s).await {
                eprintln!("[server] connection error: {e:#}");
            }
        });
    }
    Ok(())
}
