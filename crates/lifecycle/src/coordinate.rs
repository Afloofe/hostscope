use crate::lease::Lease;
use crate::watch::{find_by, Claim, Target};

#[derive(Debug)]
pub struct Coordinator {

    digest: String,

    me: u32,

    held: Option<Lease>,

    last_error: Option<String>,
}

impl Coordinator {

    pub fn new(digest: &str, me: u32) -> Self {
        Coordinator {
            digest: digest.to_string(),
            me,
            held: None,
            last_error: None,
        }
    }

    pub const fn holds_claim(&self) -> bool {
        self.held.is_some()
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub fn claim(&mut self, dead_argv: &[String]) -> Claim {
        self.last_error = None;

        if self.held.is_some() {
            return Claim::Mine;
        }

        match Lease::try_acquire(&self.digest, dead_argv) {
            Ok(Some(lease)) => {
                self.held = Some(lease);

                match self.find_agent(dead_argv) {
                    Some(t) => Claim::Adopted(t),
                    None => Claim::Mine,
                }
            }

            Ok(None) => match self.find_agent(dead_argv) {
                Some(t) => Claim::Adopted(t),
                None => Claim::Peer,
            },

            Err(e) => {
                self.last_error = Some(e);
                Claim::Peer
            }
        }
    }

    fn find_agent(&self, argv: &[String]) -> Option<Target> {
        find_by(&self.digest, argv, self.me)
    }
}
