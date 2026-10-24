#![cfg_attr(not(target_os = "windows"), forbid(unsafe_code))]
#![cfg_attr(target_os = "windows", allow(unsafe_code))]
#![cfg_attr(target_os = "windows", deny(unsafe_op_in_unsafe_fn))]

pub mod acl;
pub mod console;
pub mod authenticode;
pub mod com;
pub mod dllhijack;
pub mod drift;
pub mod modules;
pub mod reg;
pub mod rng;
pub mod etw;
pub mod evtlog;
pub mod streams;
pub mod sysmon;
pub mod usn;
pub mod wmi;
pub mod accounts;
pub mod acquire;
pub mod facts;
pub mod overview;
pub mod persist;
pub mod posture;
pub mod procexec;
pub mod procwatch;
pub mod provenance;
pub mod trust;

pub use facts::{Facts, Flag, Integrity, Reading};
pub use posture::{
    assess, AdversaryCeiling, AgentCeiling, Finding, Posture, Severity, Standing,
};

pub fn report() -> Posture {
    assess(acquire::facts())
}
