use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {

    pub items: BTreeMap<String, String>,

    pub gaps: Vec<String>,

    pub scope: u32,

    pub legacy: BTreeMap<String, Option<String>>,
}

impl Snapshot {

    pub fn record_with_legacy(&mut self, now: BTreeMap<String, String>, was: BTreeMap<String, String>) {
        let keys: BTreeSet<&String> = now.keys().chain(was.keys()).collect();
        for k in keys {
            if now.get(k) != was.get(k) {
                self.legacy.insert(k.clone(), was.get(k).cloned());
            }
        }
        self.items.extend(now);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {

    pub key: String,

    pub before: Option<String>,

    pub after: Option<String>,
}
