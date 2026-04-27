use serde::{Deserialize, Serialize};

/// Default QUIC port for onyx.
pub const DEFAULT_PORT: u16 = 7272;

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

/// All messages exchanged between client and server over QUIC streams.
/// Each stream carries exactly one request/response pair (Step 1).
/// Later steps will extend this to a continuous bidirectional stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Client → Server: open or attempt to resume a session.
    Hello {
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
    },
    /// Server → Client: acknowledge Hello and supply the resume token.
    Welcome {
        session_id: String,
        resume_token: String,
    },
    /// Client → Server: resume after reconnect, supply last received seq.
    Resume {
        session_id: String,
        resume_token: String,
        last_seq: u64,
    },
    /// Client → Server: raw PTY input bytes.
    Input { data: Vec<u8> },
    /// Server → Client: raw PTY output bytes, sequenced for gap-free resume.
    Output { seq: u64, data: Vec<u8> },
    /// Client → Server: terminal resize event.
    Resize { cols: u16, rows: u16 },
    /// Either direction: graceful shutdown.
    Close { reason: String },
    /// Client → Server: open a TCP tunnel to remote_port on the server host.
    ForwardConnect { remote_port: u16 },
    /// Client → Server: open a TCP connection to target_host:target_port from the server.
    ProxyConnect {
        proxy_session_id: String,
        target_host: String,
        target_port: u16,
    },
    /// Client → Server: resume a proxy session after a short QUIC interruption.
    ProxyResume { proxy_session_id: String },
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
        command: Vec<String>,
        /// Optional working directory on the remote host.
        cwd: Option<String>,
        /// Extra environment variables for this job only (KEY, VALUE pairs).
        env: Vec<(String, String)>,
        /// Kill the job after this many seconds (None = no limit).
        timeout_secs: Option<u64>,
    },
    /// Client → Server: attach to an existing job. Server replays any
    /// buffered output with seq > last_seq, then streams new chunks.
    ExecAttach { job_id: String, last_seq: u64 },
    /// Client → Server: snapshot-dump the job's full buffered output and
    /// final status, then close. Does not subscribe to live output.
    ExecLogs { job_id: String },
    /// Client → Server: enumerate jobs known to this server.
    JobsList,
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
    /// Server → Client: exec-layer error (job not found, spawn failed, ...).
    ExecError { reason: String },
    /// Server → Client: job was killed by the server-side timeout.
    ExecTimedOut,
    /// Client → Server: kill a running job.
    Kill { job_id: String },
    /// Server → Client: result of a Kill request.
    KillResult {
        job_id: String,
        killed: bool,
        message: String,
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
