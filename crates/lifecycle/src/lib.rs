#![cfg_attr(not(target_os = "linux"), forbid(unsafe_code))]
#![cfg_attr(target_os = "linux", allow(unsafe_code))]
#![cfg_attr(target_os = "linux", deny(unsafe_op_in_unsafe_fn))]

pub mod image;
pub mod coordinate;
pub mod lease;
pub mod mechanism;
pub mod restart;

#[cfg(target_os = "linux")]
pub mod watch;
