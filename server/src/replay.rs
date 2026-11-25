//! Native session persistence: lets a reconnecting client catch up without tmux.
//!
//! Every chunk the PTY produces is appended here with a monotonically
//! increasing `seq`, and it is also fed into a lightweight terminal emulator
//! (`vt100`) that tracks what the screen currently looks like. When a client
//! reconnects it reports the last `seq` it rendered, and we pick one of two
//! ways to bring it up to date:
//!
//! * **Replay**: the bytes it missed are still buffered, so we resend exactly
//!   those bytes. The client's terminal renders them as if the connection had
//!   never dropped. Native scrollback and selection stay intact, like plain SSH.
//! * **Snapshot**: the gap is too old (it fell out of the ring), or the client
//!   is a fresh terminal attaching to an existing session. We send escape codes
//!   that repaint the current screen once. That covers full-screen apps such as
//!   vim or a coding-agent TUI too.

use std::collections::VecDeque;
use std::num::NonZeroU16;

/// Upper bound on buffered PTY output per interactive session. Large enough
/// to cover the output of a long Wi-Fi drop on a busy shell, small enough that
/// hundreds of idle sessions stay cheap.
pub const SESSION_REPLAY_CAP_BYTES: usize = 2 * 1024 * 1024; // 2 MiB

/// How a reconnecting client should be brought up to date.
#[derive(Debug, PartialEq, Eq)]
pub enum CatchUp {
    /// Client already has everything.
    UpToDate,
    /// Exact bytes the client missed, in order.
    Replay(Vec<u8>),
    /// Escape codes that repaint the current screen from scratch.
    Snapshot(Vec<u8>),
}

pub struct SessionOutput {
    chunks: VecDeque<(u64, Vec<u8>)>,
    bytes: usize,
    cap_bytes: usize,
    last_seq: u64,
    screen: vt100::Parser,
}

fn nz(v: u16) -> NonZeroU16 {
    NonZeroU16::new(v).unwrap_or(NonZeroU16::MIN)
}

impl SessionOutput {
    pub fn new(rows: u16, cols: u16) -> Self {
        Self::with_cap(rows, cols, SESSION_REPLAY_CAP_BYTES)
    }

    pub fn with_cap(rows: u16, cols: u16, cap_bytes: usize) -> Self {
        Self {
            chunks: VecDeque::new(),
            bytes: 0,
            cap_bytes,
            last_seq: 0,
            // No emulator scrollback: snapshots only repaint the visible
            // screen. History lives in the client's own terminal.
            screen: vt100::Parser::new(nz(rows), nz(cols), 0),
        }
    }

    /// Record a chunk of PTY output and return the `seq` assigned to it.
    pub fn push(&mut self, data: &[u8]) -> u64 {
        self.last_seq += 1;
        self.screen.process(data);
        self.bytes += data.len();
        self.chunks.push_back((self.last_seq, data.to_vec()));
        // Keep at least the newest chunk even if it alone exceeds the cap.
        while self.bytes > self.cap_bytes && self.chunks.len() > 1 {
            if let Some((_, old)) = self.chunks.pop_front() {
                self.bytes -= old.len();
            }
        }
        self.last_seq
    }

    pub fn resize(&mut self, rows: u16, cols: u16) {
        self.screen.set_size(nz(rows), nz(cols));
    }

    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    fn oldest_seq(&self) -> u64 {
        self.chunks
            .front()
            .map(|(seq, _)| *seq)
            .unwrap_or(self.last_seq + 1)
    }

    /// Decide how to bring a client that has rendered up to `client_seq` back
    /// in sync. `fresh_terminal` means the client has nothing on screen (for
    /// example `onyx attach` from a new terminal), so a single repaint is
    /// cleaner than dumping megabytes of history.
    pub fn catch_up(&self, client_seq: u64, fresh_terminal: bool) -> CatchUp {
        if fresh_terminal {
            return if self.last_seq == 0 {
                CatchUp::UpToDate
            } else {
                CatchUp::Snapshot(self.snapshot())
            };
        }
        if client_seq >= self.last_seq {
            return CatchUp::UpToDate;
        }
        if client_seq + 1 >= self.oldest_seq() {
            let mut out = Vec::new();
            for (seq, data) in &self.chunks {
                if *seq > client_seq {
                    out.extend_from_slice(data);
                }
            }
            CatchUp::Replay(out)
        } else {
            CatchUp::Snapshot(self.snapshot())
        }
    }

    /// Escape codes that reproduce the current screen: alternate-screen mode,
    /// visible contents, cursor, and input modes (bracketed paste, keypad, …).
    pub fn snapshot(&self) -> Vec<u8> {
        let screen = self.screen.screen();
        let mut out = Vec::new();
        if screen.alternate_screen() {
            out.extend_from_slice(b"\x1b[?1049h");
        }
        out.extend_from_slice(screen.state_formatted().as_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn up_to_date_when_client_has_everything() {
        let mut out = SessionOutput::new(24, 80);
        out.push(b"hello");
        assert_eq!(out.catch_up(1, false), CatchUp::UpToDate);
    }

    #[test]
    fn replays_exact_missed_bytes() {
        let mut out = SessionOutput::new(24, 80);
        out.push(b"one ");
        out.push(b"two ");
        out.push(b"three");
        assert_eq!(out.catch_up(1, false), CatchUp::Replay(b"two three".to_vec()));
    }

    #[test]
    fn falls_back_to_snapshot_when_gap_was_evicted() {
        let mut out = SessionOutput::with_cap(24, 80, 8);
        out.push(b"aaaa");
        out.push(b"bbbb");
        out.push(b"cccc"); // evicts "aaaa"
        match out.catch_up(0, false) {
            CatchUp::Snapshot(bytes) => {
                let s = String::from_utf8_lossy(&bytes);
                assert!(s.contains("bbbbcccc"), "snapshot should repaint screen: {s:?}");
            }
            other => panic!("expected snapshot, got {other:?}"),
        }
    }

    #[test]
    fn fresh_terminal_gets_snapshot_not_history() {
        let mut out = SessionOutput::new(24, 80);
        out.push(b"$ ls\r\nfile\r\n$ ");
        assert!(matches!(out.catch_up(0, true), CatchUp::Snapshot(_)));
        let empty = SessionOutput::new(24, 80);
        assert_eq!(empty.catch_up(0, true), CatchUp::UpToDate);
    }

    #[test]
    fn snapshot_restores_alternate_screen() {
        let mut out = SessionOutput::new(24, 80);
        out.push(b"\x1b[?1049hfullscreen app");
        let snap = out.snapshot();
        assert!(snap.starts_with(b"\x1b[?1049h"));
    }

    #[test]
    fn oversized_single_chunk_is_kept() {
        let mut out = SessionOutput::with_cap(24, 80, 4);
        out.push(b"0123456789");
        assert_eq!(out.catch_up(0, false), CatchUp::Replay(b"0123456789".to_vec()));
    }
}
