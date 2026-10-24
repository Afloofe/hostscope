use std::collections::VecDeque;

use super::filterlog::Line;

pub const MAX_ENTRIES: usize = 50_000;

pub const PHYSMEM_PERCENT: u64 = 2;

pub const ENTRY_BYTES: u64 = 512;

pub const ASSUMED_PHYSMEM: u64 = 512 * 1024 * 1024;

pub fn capacity(physmem: Option<u64>) -> usize {
    let mem = physmem.unwrap_or(ASSUMED_PHYSMEM);
    let by_mem = mem / 100 * PHYSMEM_PERCENT / ENTRY_BYTES;
    usize::try_from(by_mem).unwrap_or(usize::MAX).min(MAX_ENTRIES)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {

    pub seq: u64,

    pub new: bool,

    pub line: Line,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ring {
    cap: usize,
    entries: VecDeque<Entry>,
    evicted: u64,
    oldest_evicted: Option<String>,
    next: u64,
}

impl Ring {

    pub fn new(cap: usize) -> Ring {
        Ring { cap, entries: VecDeque::new(), evicted: 0, oldest_evicted: None, next: 0 }
    }

    pub fn push(&mut self, line: Line, new: bool) {
        if self.cap == 0 {
            self.evicted += 1;
            self.next += 1;
            return;
        }
        if self.entries.len() >= self.cap {
            if let Some(old) = self.entries.pop_front() {
                if self.oldest_evicted.is_none() {
                    self.oldest_evicted = Some(old.line.ts);
                }
                self.evicted += 1;
            }
        }
        self.entries.push_back(Entry { seq: self.next, new, line });
        self.next += 1;
    }

    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.cap
    }

    pub fn evicted(&self) -> (u64, Option<&str>) {
        (self.evicted, self.oldest_evicted.as_deref())
    }

    pub fn span(&self) -> Option<(&str, &str)> {
        Some((self.entries.front()?.line.ts.as_str(), self.entries.back()?.line.ts.as_str()))
    }
}
