use crate::held::{HeldFinding, HeldStore};

#[derive(Debug, Clone)]
pub struct Rejudged {

    pub sweep: String,

    pub findings: Vec<HeldFinding>,

    pub gaps: Vec<String>,

    pub basis: String,
}

#[derive(Debug, Clone)]
pub enum Outcome {

    Carried {

        kind: String,

        what: String,
    },

    Judged(Rejudged),

    Unjudged {

        sweep: String,

        why: String,
    },
}

pub type Peers<'a> = &'a dyn Fn(&[u8; 32]) -> Option<HeldStore>;

pub trait Rejudge {

    fn rejudge(&self, store: &HeldStore, peers: Peers<'_>) -> Outcome;

    fn facts(&self, _store: &HeldStore) -> crate::joins::Facts {
        crate::joins::Facts::default()
    }

    fn flow(&self, _fw: &dyn std::any::Any, _host: &dyn std::any::Any, _ask: &crate::joins::FlowAsk<'_>) -> Option<crate::joins::FlowReport> {
        None
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoRejudge;

impl Rejudge for NoRejudge {
    fn rejudge(&self, _: &HeldStore, _: Peers<'_>) -> Outcome {
        Outcome::Carried {
            kind: "sealed-custody".to_string(),
            what: "this fold has no judge: the store verified and is carried, and nothing in it was judged".to_string(),
        }
    }
}

pub fn finding(n: usize, sweep: &str, severity: crate::queue::Sev, subject: &str, what: &str, why: &str) -> HeldFinding {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    for part in [sweep, severity.token(), subject, what, why] {
        h.update(part.as_bytes());
        h.update([0x1f]);
    }
    HeldFinding {
        seq: n as u64,
        digest: h.finalize().into(),
        source: sweep.to_string(),
        severity,
        severity_raw: severity.token().to_string(),
        subject: subject.to_string(),
        locus: subject.to_string(),
        what: what.to_string(),
        why: why.to_string(),
        files: Vec::new(),
    }
}
