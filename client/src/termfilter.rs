//! Strips Warp's "warpify" hook sequences from remote output.
//!
//! Warp asks remote shells to print a DCS hook (`ESC P $ f {json} ST`) from
//! the user's rc file ("Auto-Warpify"). When Warp sees it, it assumes it is
//! driving a plain SSH session and types its own bootstrap script into the
//! shell's input. Inside an Onyx session that bootstrap does not apply, and
//! the remote shell exits right after starting. Other terminals ignore the
//! hook, so dropping it keeps Onyx a plain, terminal-native shell everywhere.
//!
//! Output arrives in arbitrary chunks, so a hook can be split across chunk
//! boundaries. This filter is a small state machine that holds back at most
//! the few bytes of a possible hook prefix until the next chunk decides it.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Normal,
    /// Saw ESC.
    Esc,
    /// Saw ESC P.
    EscP,
    /// Saw ESC P $.
    EscPDollar,
    /// Inside a Warp hook; dropping bytes until ST.
    InHook,
    /// Inside a Warp hook and just saw ESC (possible `ESC \` terminator).
    InHookEsc,
}

const ESC: u8 = 0x1b;
/// 8-bit String Terminator, which Warp's rc snippet uses.
const ST8: u8 = 0x9c;

pub struct WarpHookFilter {
    state: State,
}

impl Default for WarpHookFilter {
    fn default() -> Self {
        Self { state: State::Normal }
    }
}

impl WarpHookFilter {
    pub fn filter(&mut self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        for &b in input {
            self.state = match self.state {
                State::Normal => {
                    if b == ESC {
                        State::Esc
                    } else {
                        out.push(b);
                        State::Normal
                    }
                }
                State::Esc => match b {
                    b'P' => State::EscP,
                    _ => {
                        out.push(ESC);
                        self.reprocess(b, &mut out)
                    }
                },
                State::EscP => match b {
                    b'$' => State::EscPDollar,
                    _ => {
                        out.extend_from_slice(&[ESC, b'P']);
                        self.reprocess(b, &mut out)
                    }
                },
                State::EscPDollar => match b {
                    b'f' => State::InHook,
                    _ => {
                        out.extend_from_slice(&[ESC, b'P', b'$']);
                        self.reprocess(b, &mut out)
                    }
                },
                State::InHook => match b {
                    ST8 => State::Normal,
                    ESC => State::InHookEsc,
                    _ => State::InHook,
                },
                State::InHookEsc => match b {
                    b'\\' => State::Normal,
                    ESC => State::InHookEsc,
                    _ => State::InHook,
                },
            };
        }
        out
    }

    /// Handle a byte that broke a partial prefix: it may itself start a new one.
    fn reprocess(&self, b: u8, out: &mut Vec<u8>) -> State {
        if b == ESC {
            State::Esc
        } else {
            out.push(b);
            State::Normal
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOOK: &[u8] =
        b"\x1bP$f{\"hook\": \"SourcedRcFileForWarp\", \"value\": { \"shell\": \"bash\" }}\x9c";

    #[test]
    fn passes_plain_output_and_escape_sequences() {
        let mut f = WarpHookFilter::default();
        let s = b"hello \x1b[1;32mgreen\x1b[0m \x1bPq#0;1\x1b\\ done";
        assert_eq!(f.filter(s), s.to_vec());
    }

    #[test]
    fn strips_hook_with_8bit_terminator() {
        let mut f = WarpHookFilter::default();
        let mut s = b"before ".to_vec();
        s.extend_from_slice(HOOK);
        s.extend_from_slice(b"$ ");
        assert_eq!(f.filter(&s), b"before $ ".to_vec());
    }

    #[test]
    fn strips_hook_with_esc_backslash_terminator() {
        let mut f = WarpHookFilter::default();
        assert_eq!(f.filter(b"a\x1bP$f{\"x\":1}\x1b\\b"), b"ab".to_vec());
    }

    #[test]
    fn strips_hook_split_across_every_byte() {
        let mut f = WarpHookFilter::default();
        let mut s = b"x".to_vec();
        s.extend_from_slice(HOOK);
        s.extend_from_slice(b"y\x1b[0m");
        let mut out = Vec::new();
        for b in &s {
            out.extend(f.filter(&[*b]));
        }
        assert_eq!(out, b"xy\x1b[0m".to_vec());
    }

    #[test]
    fn partial_prefix_then_other_sequence_is_preserved() {
        let mut f = WarpHookFilter::default();
        let mut out = f.filter(b"ok\x1bP");
        out.extend(f.filter(b"q-sixel\x1b\\"));
        assert_eq!(out, b"ok\x1bPq-sixel\x1b\\".to_vec());
        let mut out = f.filter(b"\x1b\x1b[A");
        out.extend(f.filter(b""));
        assert_eq!(out, b"\x1b\x1b[A".to_vec());
    }
}
