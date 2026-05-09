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
        };
        assert!(matches!(
            round_trip(msg),
            Message::Hello { session_id, cols: Some(220), rows: Some(50), .. }
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
    fn resume_round_trip() {
        let msg = Message::Resume {
            auth_token: "t".into(),
            session_id: "s".into(),
            resume_token: "r".into(),
            last_seq: 42,
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
        };
        assert!(matches!(
            round_trip(msg),
            Message::ExecStart { timeout_secs: Some(60), cwd: Some(c), .. } if c == "/home/user"
        ));
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
