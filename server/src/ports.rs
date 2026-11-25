//! Detects TCP ports listening inside an interactive session.
//!
//! The shell runs as a session leader (`setsid`), so everything it starts
//! (`npm run dev`, `python -m http.server`, …) shares its session id unless it
//! deliberately daemonizes. We find those processes in /proc, collect the
//! socket inodes they hold, and match them against listening sockets in
//! /proc/net/tcp{,6}. Linux only; elsewhere the set is always empty.

use std::collections::BTreeSet;

/// Ports below this are almost never dev servers and often need root.
const MIN_PORT: u16 = 1024;

#[cfg(target_os = "linux")]
pub fn session_listening_ports(session_leader: u32) -> BTreeSet<u16> {
    use std::collections::HashMap;

    let mut listening: HashMap<u64, u16> = HashMap::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(table) {
            for (inode, port) in parse_listening(&text) {
                listening.insert(inode, port);
            }
        }
    }
    let mut ports = BTreeSet::new();
    if listening.is_empty() {
        return ports;
    }
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return ports;
    };
    for entry in procs.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        if parse_session_id(&stat) != Some(session_leader) {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                if let Some(inode) = socket_inode(&target.to_string_lossy()) {
                    if let Some(port) = listening.get(&inode) {
                        ports.insert(*port);
                    }
                }
            }
        }
    }
    ports
}

#[cfg(not(target_os = "linux"))]
pub fn session_listening_ports(_session_leader: u32) -> BTreeSet<u16> {
    BTreeSet::new()
}

/// (inode, port) for every LISTEN socket in a /proc/net/tcp{,6} table.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_listening(table: &str) -> Vec<(u64, u16)> {
    let mut out = Vec::new();
    for line in table.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // sl local_address rem_address st tx:rx tr:when retrnsmt uid timeout inode
        if cols.len() < 10 || cols[3] != "0A" {
            continue;
        }
        let Some((_, port_hex)) = cols[1].rsplit_once(':') else {
            continue;
        };
        let (Ok(port), Ok(inode)) = (u16::from_str_radix(port_hex, 16), cols[9].parse::<u64>())
        else {
            continue;
        };
        if port >= MIN_PORT && inode != 0 {
            out.push((inode, port));
        }
    }
    out
}

/// Session id (field 6) from /proc/<pid>/stat. The command name in field 2
/// may contain spaces or parentheses, so parse after the last ')'.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_session_id(stat: &str) -> Option<u32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    // rest: " state ppid pgrp session ..."
    rest.split_whitespace().nth(3)?.parse().ok()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listen_rows_only() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   \
   0: 00000000:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0 100 0 0 10 0\n   \
   1: 0100007F:1F90 0100007F:D3A2 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0 20 4 30 10 -1\n   \
   2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 333 1 0 100 0 0 10 0\n";
        // 0x0BB8 = 3000 listening; 0x1F90 is ESTABLISHED; 22 is below MIN_PORT.
        assert_eq!(parse_listening(table), vec![(12345, 3000)]);
    }

    #[test]
    fn session_id_survives_odd_command_names() {
        let stat = "4242 (node (next dev)) S 4200 4242 4100 34816 4242 4194304 0";
        assert_eq!(parse_session_id(stat), Some(4100));
    }

    #[test]
    fn socket_links_only() {
        assert_eq!(socket_inode("socket:[98765]"), Some(98765));
        assert_eq!(socket_inode("/dev/pts/3"), None);
        assert_eq!(socket_inode("pipe:[1]"), None);
    }
}
