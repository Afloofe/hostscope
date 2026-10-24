use std::time::Duration;

use crate::BEACON_INTERVAL;

pub const MISSED_BEFORE_DEAD: u32 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {

    Alive {

        seq: u64,
    },

    Lossy {

        missing: u64,

        seq: u64,
    },

    Silent {

        since: Duration,

        last_seq: u64,
    },

    Unknown,
}

impl Verdict {

    pub fn message(&self) -> String {
        match self {
            Verdict::Alive { seq } => format!("the agent is beaconing, last sequence {seq}"),
            Verdict::Lossy { missing, seq } => format!(
                "the agent is alive — sequence {seq} arrived — but {missing} beacon(s) never \
                 did. That is the LINK, not the host: the agent was running to send the ones \
                 that got here"
            ),
            Verdict::Silent { since, last_seq } => format!(
                "NOTHING from the agent for {}s, after sequence {last_seq}. An attacker who \
                 disables auditing can kill the agent without leaving a local trace; they \
                 cannot make it keep talking to this console. Treat the host as compromised and \
                 the agent as gone until something says otherwise",
                since.as_secs()
            ),
            Verdict::Unknown => "no beacon has arrived yet, so nothing is known about the agent. \
                                 This is not the same as the agent being healthy"
                .to_string(),
        }
    }

    pub const fn is_alarming(&self) -> bool {
        matches!(self, Verdict::Silent { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Beat {

    Fresh,

    Restarted,

    Stale,
}

impl Beat {

    pub const fn proves_life(self) -> bool {
        matches!(self, Beat::Fresh | Beat::Restarted)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Liveness {

    pub run: Option<u64>,

    pub retired: Vec<u64>,

    pub stale: u64,

    pub restarts: u64,

    pub last_seq: Option<u64>,

    pub missing: u64,

    pub received: u64,
}

impl Liveness {

    pub fn beacon(&mut self, run: u64, seq: u64) -> Beat {
        self.received += 1;
        if self.retired.contains(&run) {
            self.stale += 1;
            return Beat::Stale;
        }
        match (self.run, self.last_seq) {
            (Some(current), _) if current != run => {

                self.retired.push(current);
                self.run = Some(run);
                self.last_seq = Some(seq);
                self.missing = 0;
                self.restarts += 1;
                Beat::Restarted
            }
            (_, None) => {
                self.run = Some(run);
                self.last_seq = Some(seq);
                Beat::Fresh
            }
            (_, Some(last)) if seq > last => {

                self.missing += seq.saturating_sub(last).saturating_sub(1);
                self.last_seq = Some(seq);
                Beat::Fresh
            }
            _ => {
                self.stale += 1;
                Beat::Stale
            }
        }
    }

    pub fn judge(&self, since_last: Duration) -> Verdict {
        let Some(seq) = self.last_seq else {
            return Verdict::Unknown;
        };
        let dead_after = BEACON_INTERVAL * MISSED_BEFORE_DEAD;
        if since_last > dead_after {
            return Verdict::Silent { since: since_last, last_seq: seq };
        }
        if self.missing > 0 {
            return Verdict::Lossy { missing: self.missing, seq };
        }
        Verdict::Alive { seq }
    }

    pub const fn dead_after() -> Duration {
        Duration::from_secs(BEACON_INTERVAL.as_secs() * MISSED_BEFORE_DEAD as u64)
    }
}
