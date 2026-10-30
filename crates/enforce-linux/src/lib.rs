#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

mod action;
mod apply;
mod guards;
mod outcome;
mod paths;
mod revert;

pub use action::{ModuleSighting, PersistKind, RemovalAction};
pub use guards::{infrastructure_role, ProcId, ProtectSet, TargetKind};
pub use outcome::{
    ApplyOptions, Failure, Outcome, Plan, ProtectReason, RefuseCause, Refusal, UndoKind,
    UndoRecord, DEFAULT_VAULT,
};
pub use paths::{daemon_reload, snapshot, udev_reload};
pub use paths::open_unredirected;
pub use revert::{undo, undo_with};

pub(crate) use paths::{
    path_refusal, resolve_tool,
    run_tool,
};

pub mod acquire;
pub mod account;
pub mod pam_validate;
pub mod bootparam;
pub mod deceive;
pub mod sidecar;
pub mod uninstall;
pub mod exec;
pub mod persistence;

pub mod strip;

pub mod anchor;

pub mod journal;
pub mod modprotect;

pub mod fwallow;

pub mod restore_watch;
pub mod group;

pub fn preview(action: &RemovalAction) -> Plan {
    action.plan()
}

pub fn execute(action: &RemovalAction, opts: &ApplyOptions) -> Outcome {
    let protect = ProtectSet::gather();
    action.apply(opts, &protect)
}
