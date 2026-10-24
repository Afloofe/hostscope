use crate::btf::{self, NotFound};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookState {

    Available {

        variant: &'static str,

        params: u32,
    },

    UnknownPrototype {

        params: u32,
    },

    Missing,

    Undetermined,
}

impl HookState {

    pub fn usable(&self) -> bool {
        matches!(self, HookState::Available { .. })
    }
}

struct Hook {
    name: &'static str,

    known: &'static [(u32, &'static str)],

    capability: &'static str,
}

const HOOKS: &[Hook] = &[

    Hook {
        name: "bpf_lsm_inode_setattr",
        known: &[(2, "pre-6.12"), (3, "6.12-and-later")],
        capability: "denying truncation of the evidence store",
    },

    Hook {
        name: "bpf_lsm_kernel_load_data",
        known: &[(1, "rhel8-4.18"), (2, "upstream")],
        capability: "denying in-memory module load and kexec",
    },
    Hook {
        name: "bpf_lsm_kernel_read_file",
        known: &[(2, "rhel8-4.18"), (3, "upstream")],
        capability: "denying module and firmware reads",
    },

    Hook { name: "bpf_lsm_task_kill", known: &[], capability: "self-protection against signals" },
    Hook { name: "bpf_lsm_file_open", known: &[], capability: "denying file access" },
    Hook { name: "bpf_lsm_socket_connect", known: &[], capability: "network egress containment" },
    Hook { name: "bpf_lsm_inode_unlink", known: &[], capability: "denying evidence deletion" },
    Hook { name: "bpf_lsm_inode_rename", known: &[], capability: "denying evidence rename" },
    Hook { name: "bpf_lsm_bprm_check_security", known: &[], capability: "denying execution" },
    Hook { name: "bpf_lsm_ptrace_access_check", known: &[], capability: "self-protection against ptrace" },
    Hook { name: "bpf_lsm_bpf", known: &[], capability: "denying BPF programs to an attacker" },
    Hook { name: "bpf_lsm_path_unlink", known: &[], capability: "denying unlink by path" },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookReport {

    pub name: &'static str,

    pub capability: &'static str,

    pub state: HookState,
}

pub fn report() -> Vec<HookReport> {
    let names: Vec<&str> = HOOKS.iter().map(|h| h.name).collect();
    let protos = btf::vmlinux()
        .map_err(|_| NotFound::NotBtf)
        .and_then(|blob| btf::prototypes(&blob, &names));

    HOOKS
        .iter()
        .enumerate()
        .map(|(i, hook)| HookReport {
            name: hook.name,
            capability: hook.capability,
            state: match &protos {

                Err(_) => HookState::Undetermined,
                Ok(found) => match found.get(i).and_then(Option::as_ref) {
                    None => HookState::Missing,
                    Some(p) => classify(hook, p.params),
                },
            },
        })
        .collect()
}

fn classify(hook: &Hook, params: u32) -> HookState {

    if params == u32::MAX {
        return HookState::UnknownPrototype { params };
    }
    match hook.known.iter().find(|(n, _)| *n == params) {
        Some((_, variant)) => HookState::Available { variant, params },

        None if hook.known.is_empty() => HookState::Available { variant: "single", params },
        None => HookState::UnknownPrototype { params },
    }
}
