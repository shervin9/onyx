use serde::{Deserialize, Serialize};

/// Default QUIC port for onyx.
pub const DEFAULT_PORT: u16 = 7272;

/// `Close.reason` sent to a client whose interactive session was taken over
/// by another client. The evicted client must exit, not reconnect.
pub const CLOSE_TAKEN_OVER: &str = "session taken over by another client";

/// Client feature bits sent in Hello/Resume `features`. The server only sends
/// the matching server→client messages to clients that declare them, so
/// older clients never receive a message variant they cannot decode.
pub const FEATURE_PORTS: u32 = 1 << 0;
pub const FEATURE_OPEN_URL: u32 = 1 << 1;

/// Onyx Guard: secrets and egress policy for one agent job.
///
/// The client sends real secret values over the authenticated QUIC channel;
/// the server keeps them in memory only, hands the job same-length
/// placeholders, and swaps them back in request headers bound for the
/// secret's own hosts. Every other destination is refused.
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardSpec {
    pub secrets: Vec<GuardSecret>,
    /// Extra hosts the job may reach (no secret is ever sent to them).
    /// `*.example.com` matches subdomains of example.com.
    pub allow_hosts: Vec<String>,
    /// TCP ports the job may connect to directly, bypassing the proxy
    /// (for example a local database or dev server).
    pub allow_ports: Vec<u16>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardSecret {
    /// Environment variable name the job sees (holding the placeholder).
    pub name: String,
    pub value: String,
    /// Hosts this secret may be sent to.
    pub hosts: Vec<String>,
}

// Never print secret values, even in debug logs.
impl std::fmt::Debug for GuardSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardSecret")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("hosts", &self.hosts)
            .finish()
    }
}

impl std::fmt::Debug for GuardSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardSpec")
            .field("secrets", &self.secrets)
            .field("allow_hosts", &self.allow_hosts)
            .field("allow_ports", &self.allow_ports)
            .finish()
    }
}

/// Which standard stream an exec output chunk came from.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum StdStream {
    Stdout,
    Stderr,
}

/// Lifecycle of an `onyx exec` job.
///
/// - `Running`: process is live, client may or may not be attached.
/// - `Detached`: process is live, no client is attached. (Same semantics as
///   `Running` for scheduling purposes; exposed as a distinct state because
///   users care about the difference.)
/// - `Succeeded` / `Failed`: process exited (0 / non-zero). Output remains
///   readable via `onyx logs` until retention expires.
/// - `Expired`: GC'd. Only surfaces if a client asks about a job after the
///   retention window.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum JobStatus {
    Running,
    Detached,
    Succeeded,
    Failed,
    Expired,
}

/// One row in `onyx jobs <target>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSummary {
    pub job_id: String,
    /// Reconstructed command line for display — the argv joined with spaces.
    pub command: String,
    pub status: JobStatus,
    pub started_at_unix: u64,
    pub finished_at_unix: Option<u64>,
    pub exit_code: Option<i32>,
    /// True when some client is currently streaming output.
    pub attached: bool,
    /// Current size of the per-job output ring buffer, in bytes.
    pub buffered_bytes: u64,
}

/// One row in `onyx audit <target>` — a durable job record from the server's
/// SQLite store. Unlike `JobSummary` (live, in-memory) these survive restarts
/// and outlive the in-memory retention window. `status` is the persisted
/// string (e.g. "running", "succeeded", "failed", "expired").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub job_id: String,
    /// Reconstructed command line for display — the argv joined with spaces.
    pub command: String,
    pub status: String,
    pub started_at_unix: u64,
    pub finished_at_unix: Option<u64>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
}

/// One detached interactive session on the server, as returned by
/// `Message::SessionsList` — lets a fresh client discover and resume a prior
/// session instead of always starting a new tmux session on connect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub resume_token: String,
    pub started_at_unix: u64,
    /// None means the session is currently attached (should not normally
    /// appear here — the server only lists detached sessions).
    pub detached_at_unix: Option<u64>,
}

/// All messages exchanged between client and server over QUIC streams.
/// Each stream carries exactly one request/response pair (Step 1).
/// Later steps will extend this to a continuous bidirectional stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Client → Server: open or attempt to resume a session.
    Hello {
        #[serde(default)]
        auth_token: String,
        session_id: String,
        /// Empty = new session. Non-empty = resume attempt.
        resume_token: String,
        /// Client terminal type for the remote PTY. Older servers ignore this.
        #[serde(default)]
        term: Option<String>,
        /// Initial terminal width. Older servers ignore this.
        #[serde(default)]
        cols: Option<u16>,
        /// Initial terminal height. Older servers ignore this.
        #[serde(default)]
        rows: Option<u16>,
        /// Run a plain login shell instead of tmux (native terminal
        /// scrollback/selection; no tmux persistence or status bar). Only
        /// meaningful on a new session. Older servers ignore this.
        #[serde(default)]
        no_tmux: bool,
        /// FEATURE_* bits this client understands. Trailing, so older
        /// servers simply ignore it.
        #[serde(default)]
        features: u32,
    },
    /// Server → Client: acknowledge Hello and supply the resume token.
    Welcome {
        session_id: String,
        resume_token: String,
    },
    /// Client → Server: resume after reconnect, supply last received seq.
    Resume {
        #[serde(default)]
        auth_token: String,
        session_id: String,
        resume_token: String,
        last_seq: u64,
        /// FEATURE_* bits this client understands (see Hello).
        #[serde(default)]
        features: u32,
    },
    /// Client → Server: list detached interactive sessions, for the client's
    /// resume picker on a fresh connect (no pinned session/workspace yet).
    SessionsList {
        #[serde(default)]
        auth_token: String,
    },
    /// Server → Client: response to SessionsList, newest-detached-first.
    SessionsListResponse { sessions: Vec<SessionSummary> },
    /// Client → Server: raw PTY input bytes.
    Input { data: Vec<u8> },
    /// Server → Client: raw PTY output bytes, sequenced for gap-free resume.
    Output { seq: u64, data: Vec<u8> },
    /// Client → Server: terminal resize event.
    Resize { cols: u16, rows: u16 },
    /// Either direction: graceful shutdown.
    Close { reason: String },
    /// Client → Server: open a TCP tunnel to remote_port on the server host.
    ForwardConnect {
        #[serde(default)]
        auth_token: String,
        remote_port: u16,
    },
    /// Client → Server: open a TCP connection to target_host:target_port from the server.
    ProxyConnect {
        #[serde(default)]
        auth_token: String,
        proxy_session_id: String,
        target_host: String,
        target_port: u16,
    },
    /// Client → Server: resume a proxy session after a short QUIC interruption.
    ProxyResume {
        #[serde(default)]
        auth_token: String,
        proxy_session_id: String,
    },
    /// Server → Client: proxy session is ready for transparent byte forwarding.
    ProxySessionReady { proxy_session_id: String },
    /// Server → Client: tunnel accepted, remote TCP connection established.
    ForwardAck,
    /// Server → Client: tunnel rejected (port unreachable, refused, etc.).
    ForwardError { reason: String },

    // ──── onyx exec ─────────────────────────────────────────────────────
    //
    // Resumable remote command execution. The server runs `sh -c <argv
    // joined>` (so pipes/redirects work like SSH), buffers output in a
    // bounded ring per job, and broadcasts chunks to any currently-attached
    // client. A client disconnect does NOT kill the job; the user can
    // reattach with `onyx attach` or read captured output with `onyx logs`.
    //
    /// Client → Server: start a new job. The server allocates a job_id.
    ExecStart {
        #[serde(default)]
        auth_token: String,
        command: Vec<String>,
        /// Optional working directory on the remote host.
        cwd: Option<String>,
        /// Extra environment variables for this job only (KEY, VALUE pairs).
        env: Vec<(String, String)>,
        /// Kill the job after this many seconds (None = no limit).
        timeout_secs: Option<u64>,
        /// Run the job under Onyx Guard (secrets broker + egress allowlist).
        #[serde(default)]
        guard: Option<GuardSpec>,
    },
    /// Client → Server: attach to an existing job. Server replays any
    /// buffered output with seq > last_seq, then streams new chunks.
    ExecAttach {
        #[serde(default)]
        auth_token: String,
        job_id: String,
        last_seq: u64,
    },
    /// Client → Server: snapshot-dump the job's full buffered output and
    /// final status, then close. Does not subscribe to live output.
    ExecLogs {
        #[serde(default)]
        auth_token: String,
        job_id: String,
    },
    /// Client → Server: enumerate jobs known to this server.
    JobsList {
        #[serde(default)]
        auth_token: String,
    },
    /// Server → Client: job accepted and started.
    ExecStarted {
        job_id: String,
        started_at_unix: u64,
    },
    /// Server → Client: one chunk of captured output.
    ExecOutput {
        seq: u64,
        stream: StdStream,
        data: Vec<u8>,
    },
    /// Server → Client: replay buffer truncated below the requested
    /// last_seq. The oldest currently-buffered seq is supplied so the
    /// client can decide how to frame the gap for the user.
    ExecGap { oldest_seq: u64 },
    /// Server → Client: job finished. `exit_code` is None when the process
    /// was killed by a signal (e.g. OOM, kill -9).
    ExecFinished {
        exit_code: Option<i32>,
        finished_at_unix: u64,
    },
    /// Server → Client: response to JobsList.
    JobsListResponse { jobs: Vec<JobSummary> },
    /// Client → Server: read persisted job history (durable audit log).
    AuditList {
        #[serde(default)]
        auth_token: String,
        #[serde(default)]
        limit: Option<u32>,
    },
    /// Server → Client: response to AuditList, newest first.
    AuditListResponse { records: Vec<AuditRecord> },
    /// Server → Client: exec-layer error (job not found, spawn failed, ...).
    ExecError { reason: String },
    /// Server → Client: job was killed by the server-side timeout.
    ExecTimedOut,
    /// Client → Server: kill a running job.
    Kill {
        #[serde(default)]
        auth_token: String,
        job_id: String,
    },
    /// Server → Client: result of a Kill request.
    KillResult {
        job_id: String,
        killed: bool,
        message: String,
    },
    // New variants go at the end: bincode encodes the variant index.
    /// Server → Client (session stream, FEATURE_PORTS): the full set of TCP
    /// ports currently listening inside this session's process tree.
    PortsUpdate { ports: Vec<u16> },
    /// Server → Client (session stream, FEATURE_OPEN_URL): a program in the
    /// session asked to open this URL (xdg-open / $BROWSER).
    OpenUrl { url: String },
    /// `onyx-server open` → server (local socket): open `url` on the client
    /// attached to `session_id`.
    OpenUrlRequest {
        auth_token: String,
        session_id: String,
        url: String,
    },
}

/// Serialize a message to bytes (length-prefix framing is caller's job).
pub fn encode(msg: &Message) -> Result<Vec<u8>, bincode::Error> {
    bincode::serialize(msg)
}

/// Deserialize bytes back into a message.
pub fn decode(buf: &[u8]) -> Result<Message, bincode::Error> {
    bincode::deserialize(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(msg: Message) -> Message {
        let bytes = encode(&msg).expect("encode failed");
        decode(&bytes).expect("decode failed")
    }

    #[test]
    fn default_port_value() {
        assert_eq!(DEFAULT_PORT, 7272);
    }

    #[test]
    fn decode_garbage_returns_error() {
        assert!(decode(&[0xFF, 0xFE, 0x00, 0x01]).is_err());
    }

    #[test]
    fn hello_round_trip() {
        let msg = Message::Hello {
            auth_token: "tok".into(),
            session_id: "sess-1".into(),
            resume_token: "".into(),
            term: Some("xterm-256color".into()),
            cols: Some(220),
            rows: Some(50),
            no_tmux: true,
            features: FEATURE_PORTS | FEATURE_OPEN_URL,
        };
        assert!(matches!(
            round_trip(msg),
            Message::Hello { session_id, cols: Some(220), rows: Some(50), no_tmux: true, features: 3, .. }
            if session_id == "sess-1"
        ));
    }

    #[test]
    fn hello_defaults_for_optional_fields() {
        // Verify that optional fields can be None without breaking encode/decode.
        let msg = Message::Hello {
            auth_token: String::new(),
            session_id: "s".into(),
            resume_token: String::new(),
            term: None,
            cols: None,
            rows: None,
            no_tmux: false,
            features: 0,
        };
        assert!(matches!(
            round_trip(msg),
            Message::Hello { term: None, cols: None, rows: None, .. }
        ));
    }

    #[test]
    fn welcome_round_trip() {
        let msg = Message::Welcome {
            session_id: "sid".into(),
            resume_token: "rtok".into(),
        };
        assert!(matches!(
            round_trip(msg),
            Message::Welcome { resume_token, .. } if resume_token == "rtok"
        ));
    }

    #[test]
    fn port_and_url_messages_round_trip() {
        assert!(matches!(
            round_trip(Message::PortsUpdate { ports: vec![3000, 5173] }),
            Message::PortsUpdate { ports } if ports == vec![3000, 5173]
        ));
        assert!(matches!(
            round_trip(Message::OpenUrl { url: "https://x.test/a".into() }),
            Message::OpenUrl { url } if url == "https://x.test/a"
        ));
    }

    #[test]
    fn resume_round_trip() {
        let msg = Message::Resume {
            auth_token: "t".into(),
            session_id: "s".into(),
            resume_token: "r".into(),
            last_seq: 42,
            features: FEATURE_OPEN_URL,
        };
        assert!(matches!(
            round_trip(msg),
            Message::Resume { last_seq: 42, .. }
        ));
    }

    #[test]
    fn input_round_trip() {
        let data = b"ls -la\n".to_vec();
        let msg = Message::Input { data: data.clone() };
        assert!(matches!(round_trip(msg), Message::Input { data: d } if d == data));
    }

    #[test]
    fn output_round_trip() {
        let msg = Message::Output { seq: 99, data: vec![1, 2, 3] };
        assert!(matches!(round_trip(msg), Message::Output { seq: 99, data: d } if d == [1, 2, 3]));
    }

    #[test]
    fn resize_round_trip() {
        let msg = Message::Resize { cols: 80, rows: 24 };
        assert!(matches!(round_trip(msg), Message::Resize { cols: 80, rows: 24 }));
    }

    #[test]
    fn close_round_trip() {
        let msg = Message::Close { reason: "done".into() };
        assert!(matches!(round_trip(msg), Message::Close { reason } if reason == "done"));
    }

    #[test]
    fn forward_connect_round_trip() {
        let msg = Message::ForwardConnect { auth_token: String::new(), remote_port: 8080 };
        assert!(matches!(round_trip(msg), Message::ForwardConnect { remote_port: 8080, .. }));
    }

    #[test]
    fn forward_ack_round_trip() {
        assert!(matches!(round_trip(Message::ForwardAck), Message::ForwardAck));
    }

    #[test]
    fn forward_error_round_trip() {
        let msg = Message::ForwardError { reason: "refused".into() };
        assert!(matches!(round_trip(msg), Message::ForwardError { reason } if reason == "refused"));
    }

    #[test]
    fn proxy_connect_round_trip() {
        let msg = Message::ProxyConnect {
            auth_token: String::new(),
            proxy_session_id: "ps1".into(),
            target_host: "example.com".into(),
            target_port: 443,
        };
        assert!(matches!(
            round_trip(msg),
            Message::ProxyConnect { target_port: 443, target_host, .. } if target_host == "example.com"
        ));
    }

    #[test]
    fn proxy_resume_round_trip() {
        let msg = Message::ProxyResume {
            auth_token: String::new(),
            proxy_session_id: "ps2".into(),
        };
        assert!(matches!(
            round_trip(msg),
            Message::ProxyResume { proxy_session_id, .. } if proxy_session_id == "ps2"
        ));
    }

    #[test]
    fn proxy_session_ready_round_trip() {
        let msg = Message::ProxySessionReady { proxy_session_id: "ps3".into() };
        assert!(matches!(
            round_trip(msg),
            Message::ProxySessionReady { proxy_session_id } if proxy_session_id == "ps3"
        ));
    }

    #[test]
    fn exec_start_round_trip() {
        let msg = Message::ExecStart {
            auth_token: String::new(),
            command: vec!["cargo".into(), "test".into()],
            cwd: Some("/home/user".into()),
            env: vec![("RUST_LOG".into(), "info".into())],
            timeout_secs: Some(60),
            guard: None,
        };
        assert!(matches!(
            round_trip(msg),
            Message::ExecStart { timeout_secs: Some(60), cwd: Some(c), .. } if c == "/home/user"
        ));
    }

    #[test]
    fn exec_start_carries_guard_and_debug_redacts_secrets() {
        let spec = GuardSpec {
            secrets: vec![GuardSecret {
                name: "GITHUB_TOKEN".into(),
                value: "ghp_supersecretvalue123".into(),
                hosts: vec!["api.github.com".into()],
            }],
            allow_hosts: vec!["*.npmjs.org".into()],
            allow_ports: vec![5432],
        };
        assert!(!format!("{spec:?}").contains("supersecret"));
        let msg = Message::ExecStart {
            auth_token: String::new(),
            command: vec!["claude".into()],
            cwd: None,
            env: vec![],
            timeout_secs: None,
            guard: Some(spec.clone()),
        };
        assert!(!format!("{msg:?}").contains("supersecret"));
        assert!(matches!(round_trip(msg), Message::ExecStart { guard: Some(g), .. } if g == spec));
    }

    #[test]
    fn exec_attach_round_trip() {
        let msg = Message::ExecAttach {
            auth_token: String::new(),
            job_id: "job-abc".into(),
            last_seq: 7,
        };
        assert!(matches!(
            round_trip(msg),
            Message::ExecAttach { job_id, last_seq: 7, .. } if job_id == "job-abc"
        ));
    }

    #[test]
    fn exec_logs_round_trip() {
        let msg = Message::ExecLogs { auth_token: String::new(), job_id: "jid".into() };
        assert!(matches!(round_trip(msg), Message::ExecLogs { job_id, .. } if job_id == "jid"));
    }

    #[test]
    fn jobs_list_round_trip() {
        let msg = Message::JobsList { auth_token: String::new() };
        assert!(matches!(round_trip(msg), Message::JobsList { .. }));
    }

    #[test]
    fn exec_started_round_trip() {
        let msg = Message::ExecStarted { job_id: "j1".into(), started_at_unix: 1_700_000_000 };
        assert!(matches!(
            round_trip(msg),
            Message::ExecStarted { started_at_unix: 1_700_000_000, .. }
        ));
    }

    #[test]
    fn exec_output_round_trip() {
        let msg = Message::ExecOutput {
            seq: 5,
            stream: StdStream::Stderr,
            data: b"error!".to_vec(),
        };
        assert!(matches!(
            round_trip(msg),
            Message::ExecOutput { seq: 5, stream: StdStream::Stderr, .. }
        ));
    }

    #[test]
    fn exec_gap_round_trip() {
        let msg = Message::ExecGap { oldest_seq: 3 };
        assert!(matches!(round_trip(msg), Message::ExecGap { oldest_seq: 3 }));
    }

    #[test]
    fn exec_finished_round_trip_zero_exit() {
        let msg = Message::ExecFinished { exit_code: Some(0), finished_at_unix: 1_700_000_001 };
        assert!(matches!(
            round_trip(msg),
            Message::ExecFinished { exit_code: Some(0), .. }
        ));
    }

    #[test]
    fn exec_finished_round_trip_signal_killed() {
        // exit_code is None when killed by a signal
        let msg = Message::ExecFinished { exit_code: None, finished_at_unix: 1_700_000_002 };
        assert!(matches!(round_trip(msg), Message::ExecFinished { exit_code: None, .. }));
    }

    #[test]
    fn jobs_list_response_round_trip() {
        let jobs = vec![JobSummary {
            job_id: "j2".into(),
            command: "echo hi".into(),
            status: JobStatus::Succeeded,
            started_at_unix: 100,
            finished_at_unix: Some(200),
            exit_code: Some(0),
            attached: false,
            buffered_bytes: 42,
        }];
        let msg = Message::JobsListResponse { jobs };
        assert!(matches!(
            round_trip(msg),
            Message::JobsListResponse { jobs } if jobs.len() == 1 && jobs[0].job_id == "j2"
        ));
    }

    #[test]
    fn sessions_list_round_trip() {
        let msg = Message::SessionsList { auth_token: "tok".into() };
        assert!(matches!(round_trip(msg), Message::SessionsList { .. }));
    }

    #[test]
    fn sessions_list_response_round_trip() {
        let sessions = vec![SessionSummary {
            session_id: "s1".into(),
            resume_token: "rt".into(),
            started_at_unix: 100,
            detached_at_unix: Some(200),
        }];
        let msg = Message::SessionsListResponse { sessions };
        assert!(matches!(
            round_trip(msg),
            Message::SessionsListResponse { sessions }
                if sessions.len() == 1 && sessions[0].session_id == "s1"
        ));
    }

    #[test]
    fn audit_list_round_trip() {
        let msg = Message::AuditList { auth_token: "tok".into(), limit: Some(50) };
        assert!(matches!(
            round_trip(msg),
            Message::AuditList { limit: Some(50), .. }
        ));
    }

    #[test]
    fn audit_list_response_round_trip() {
        let records = vec![AuditRecord {
            job_id: "j9".into(),
            command: "claude -p fix".into(),
            status: "expired".into(),
            started_at_unix: 100,
            finished_at_unix: None,
            exit_code: None,
            timed_out: false,
        }];
        let msg = Message::AuditListResponse { records };
        assert!(matches!(
            round_trip(msg),
            Message::AuditListResponse { records }
                if records.len() == 1 && records[0].status == "expired"
        ));
    }

    #[test]
    fn exec_error_round_trip() {
        let msg = Message::ExecError { reason: "not found".into() };
        assert!(matches!(round_trip(msg), Message::ExecError { reason } if reason == "not found"));
    }

    #[test]
    fn exec_timed_out_round_trip() {
        assert!(matches!(round_trip(Message::ExecTimedOut), Message::ExecTimedOut));
    }

    #[test]
    fn kill_round_trip() {
        let msg = Message::Kill { auth_token: String::new(), job_id: "kill-me".into() };
        assert!(matches!(round_trip(msg), Message::Kill { job_id, .. } if job_id == "kill-me"));
    }

    #[test]
    fn kill_result_killed_round_trip() {
        let msg = Message::KillResult {
            job_id: "k1".into(),
            killed: true,
            message: "done".into(),
        };
        assert!(matches!(
            round_trip(msg),
            Message::KillResult { killed: true, job_id, .. } if job_id == "k1"
        ));
    }

    #[test]
    fn kill_result_not_found_round_trip() {
        let msg = Message::KillResult {
            job_id: "k2".into(),
            killed: false,
            message: "not found".into(),
        };
        assert!(matches!(
            round_trip(msg),
            Message::KillResult { killed: false, .. }
        ));
    }

    #[test]
    fn job_status_all_variants_survive_round_trip() {
        for status in [
            JobStatus::Running,
            JobStatus::Detached,
            JobStatus::Succeeded,
            JobStatus::Failed,
            JobStatus::Expired,
        ] {
            let job = JobSummary {
                job_id: "x".into(),
                command: "x".into(),
                status,
                started_at_unix: 0,
                finished_at_unix: None,
                exit_code: None,
                attached: false,
                buffered_bytes: 0,
            };
            let bytes = encode(&Message::JobsListResponse { jobs: vec![job] }).unwrap();
            if let Message::JobsListResponse { jobs } = decode(&bytes).unwrap() {
                assert_eq!(jobs[0].status, status);
            } else {
                panic!("unexpected variant");
            }
        }
    }

    #[test]
    fn encode_produces_non_empty_bytes() {
        let bytes = encode(&Message::ForwardAck).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn same_message_encodes_to_same_bytes() {
        let msg = || Message::Resize { cols: 80, rows: 24 };
        assert_eq!(encode(&msg()).unwrap(), encode(&msg()).unwrap());
    }
}
