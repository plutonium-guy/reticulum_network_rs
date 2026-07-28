use reticulum_tokio::driver::{DriverSnapshot, InterfaceSnapshot};

const MAX_LOG_ENTRIES: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub dest: [u8; 16],
    pub hops: u8,
    pub seen: u32,
    pub last_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Roster,
    Input,
    Log,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    Sys,
    Tx,
    Rx,
    Announce,
    Delivered,
    Err,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub kind: LogKind,
    pub at_secs: u64,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppState {
    pub identity: [u8; 16],
    pub roster: Vec<Peer>,
    pub selected: usize,
    pub log: Vec<LogEntry>,
    pub input: String,
    pub interfaces: Vec<InterfaceSnapshot>,
    pub focus: Focus,
    pub show_help: bool,
}

impl AppState {
    pub fn new(identity: [u8; 16]) -> Self {
        Self {
            identity,
            roster: Vec::new(),
            selected: 0,
            log: Vec::new(),
            input: String::new(),
            interfaces: Vec::new(),
            focus: Focus::Input,
            show_help: false,
        }
    }

    pub fn on_announce(&mut self, dest: [u8; 16], hops: u8, now: u64) {
        let selected = self.selected_peer();
        match self.roster.iter_mut().find(|peer| peer.dest == dest) {
            Some(peer) => {
                peer.hops = hops;
                peer.seen = peer.seen.saturating_add(1);
                peer.last_secs = now;
            }
            None => self.roster.push(Peer {
                dest,
                hops,
                seen: 1,
                last_secs: now,
            }),
        }
        self.sort_roster(selected);
        self.log(
            LogKind::Announce,
            format!("{} via {hops} hop(s)", short_hash(&dest)),
            now,
        );
    }

    pub fn on_message(&mut self, dest: [u8; 16], text: impl Into<String>, now: u64) {
        self.log(
            LogKind::Rx,
            format!("{}: {}", short_hash(&dest), text.into()),
            now,
        );
    }

    pub fn on_delivered(&mut self, hash: [u8; 32], now: u64) {
        self.log(
            LogKind::Delivered,
            format!("packet {} delivered", short_hash(&hash)),
            now,
        );
    }

    pub fn on_error(&mut self, text: impl Into<String>, now: u64) {
        self.log(LogKind::Err, text, now);
    }

    pub fn apply_snapshot(&mut self, snapshot: DriverSnapshot, now: u64) {
        let selected = self.selected_peer();
        self.identity = snapshot.identity_hash;
        self.interfaces = snapshot.interfaces;
        for path in snapshot.paths {
            if let Some(peer) = self
                .roster
                .iter_mut()
                .find(|peer| peer.dest == path.destination)
            {
                peer.hops = path.hops;
                peer.last_secs = peer.last_secs.max(path.timestamp);
            } else {
                self.roster.push(Peer {
                    dest: path.destination,
                    hops: path.hops,
                    seen: 1,
                    last_secs: path.timestamp.min(now),
                });
            }
        }
        self.sort_roster(selected);
    }

    pub fn select_next(&mut self) {
        if !self.roster.is_empty() {
            self.selected = (self.selected + 1) % self.roster.len();
        }
    }

    pub fn select_prev(&mut self) {
        if !self.roster.is_empty() {
            self.selected = self
                .selected
                .checked_sub(1)
                .unwrap_or(self.roster.len() - 1);
        }
    }

    pub fn selected_peer(&self) -> Option<[u8; 16]> {
        self.roster.get(self.selected).map(|peer| peer.dest)
    }

    pub fn push_input(&mut self, character: char) {
        if !character.is_control() {
            self.input.push(character);
        }
    }

    pub fn backspace(&mut self) {
        self.input.pop();
    }

    pub fn take_input(&mut self) -> String {
        std::mem::take(&mut self.input)
    }

    pub fn log(&mut self, kind: LogKind, text: impl Into<String>, now: u64) {
        if self.log.len() == MAX_LOG_ENTRIES {
            self.log.remove(0);
        }
        self.log.push(LogEntry {
            kind,
            at_secs: now,
            text: text.into(),
        });
    }

    fn sort_roster(&mut self, selected: Option<[u8; 16]>) {
        self.roster.sort_unstable_by(|left, right| {
            right
                .last_secs
                .cmp(&left.last_secs)
                .then(left.dest.cmp(&right.dest))
        });
        self.selected = selected
            .and_then(|dest| self.roster.iter().position(|peer| peer.dest == dest))
            .unwrap_or(0);
    }
}

pub fn short_hash(hash: &[u8]) -> String {
    let visible = hash.len().min(6);
    hex::encode(&hash[..visible])
}

#[cfg(test)]
mod tests {
    use reticulum_tokio::driver::PathSnapshot;

    use super::*;

    fn destination(value: u8) -> [u8; 16] {
        [value; 16]
    }

    #[test]
    fn announce_upserts_and_sorts_by_recency() {
        let mut state = AppState::new([0; 16]);
        state.on_announce(destination(1), 2, 10);
        state.on_announce(destination(2), 1, 20);
        state.on_announce(destination(1), 1, 30);

        assert_eq!(state.roster.len(), 2);
        assert_eq!(state.roster[0].dest, destination(1));
        assert_eq!(state.roster[0].seen, 2);
        assert_eq!(state.roster[0].hops, 1);
    }

    #[test]
    fn selection_wraps_in_both_directions() {
        let mut state = AppState::new([0; 16]);
        state.on_announce(destination(1), 1, 10);
        state.on_announce(destination(2), 1, 20);
        state.selected = 0;

        state.select_prev();
        assert_eq!(state.selected, 1);
        state.select_next();
        assert_eq!(state.selected, 0);
    }

    #[test]
    fn snapshot_adds_unseen_paths() {
        let mut state = AppState::new([0; 16]);
        state.apply_snapshot(
            DriverSnapshot {
                identity_hash: destination(9),
                interfaces: vec![InterfaceSnapshot {
                    id: 3,
                    online: true,
                    rx_packets: 1,
                    rx_bytes: 2,
                    tx_packets: 3,
                    tx_bytes: 4,
                }],
                paths: vec![PathSnapshot {
                    destination: destination(4),
                    interface: 3,
                    next_hop_transport_id: None,
                    hops: 2,
                    expires_at: 100,
                    timestamp: 40,
                }],
            },
            50,
        );

        assert_eq!(state.identity, destination(9));
        assert_eq!(state.interfaces.len(), 1);
        assert_eq!(state.roster[0].dest, destination(4));
    }

    #[test]
    fn taking_input_clears_it() {
        let mut state = AppState::new([0; 16]);
        state.push_input('h');
        state.push_input('i');

        assert_eq!(state.take_input(), "hi");
        assert!(state.input.is_empty());
    }
}
