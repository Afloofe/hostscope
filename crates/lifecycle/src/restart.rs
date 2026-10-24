#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {

    Relaunch,

    Backoff {

        wait_ms: u64,
    },

    GiveUp {

        attempts: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {

    pub burst: usize,

    pub window_ms: u64,

    pub backoff_ms: u64,

    pub peer_standby_ms: u64,

    pub held_ms: u64,
}

impl Default for Policy {

    fn default() -> Self {
        Policy { burst: 5, window_ms: 10_000, backoff_ms: 250, peer_standby_ms: 10_000, held_ms: 5_000 }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct History {

    attempts: Vec<u64>,
}

impl History {

    pub const fn new() -> Self {
        History { attempts: Vec::new() }
    }

    pub fn record(&mut self, now_ms: u64) {
        self.attempts.push(now_ms);
    }

    pub fn in_window(&self, now_ms: u64, window_ms: u64) -> usize {
        self.attempts.iter().filter(|t| now_ms.saturating_sub(**t) < window_ms).count()
    }

    pub fn last(&self) -> Option<u64> {
        self.attempts.last().copied()
    }

    pub fn prune(&mut self, now_ms: u64, window_ms: u64) {
        self.attempts.retain(|t| now_ms.saturating_sub(*t) < window_ms);
    }
}

pub fn next(policy: &Policy, history: &History, now_ms: u64) -> Next {
    let attempts = history.in_window(now_ms, policy.window_ms);
    if attempts >= policy.burst {
        return Next::GiveUp { attempts };
    }
    match history.last() {
        Some(last) => {
            let since = now_ms.saturating_sub(last);
            if since < policy.backoff_ms {
                Next::Backoff { wait_ms: policy.backoff_ms - since }
            } else {
                Next::Relaunch
            }
        }

        None => Next::Relaunch,
    }
}
