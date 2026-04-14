use serde::{Deserialize, Serialize};

/// Default QUIC port for onyx.
pub const DEFAULT_PORT: u16 = 7272;

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
}

/// Serialize a message to bytes (length-prefix framing is caller's job).
pub fn encode(msg: &Message) -> Result<Vec<u8>, bincode::Error> {
    bincode::serialize(msg)
}

/// Deserialize bytes back into a message.
pub fn decode(buf: &[u8]) -> Result<Message, bincode::Error> {
    bincode::deserialize(buf)
}
