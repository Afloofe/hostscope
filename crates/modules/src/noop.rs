use core::fmt;

use hemostat_buildinfo::{ActionClass, ModuleId};

use crate::{is_built, refusal_message};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeverApplied {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotBuilt {

    pub class: ActionClass,

    pub variant: &'static str,
}

impl fmt::Display for NotBuilt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&refusal_message(self.class, self.variant))
    }
}

#[derive(Debug)]
pub struct PerimeterBlock {
    sealed: (),
}

impl PerimeterBlock {

    pub const CLASS: ActionClass = ActionClass::PerimeterBlock;

    pub const fn compiled_out() -> Option<Self> {
        if is_built(ModuleId::EnfPerimeter) {
            None
        } else {
            Some(PerimeterBlock { sealed: () })
        }
    }

    pub fn apply(&self, variant: &'static str) -> Result<NeverApplied, NotBuilt> {
        let () = self.sealed;
        Err(NotBuilt { class: Self::CLASS, variant })
    }
}

#[derive(Debug)]
pub struct PerimeterStateKill {
    sealed: (),
}

impl PerimeterStateKill {

    pub const CLASS: ActionClass = ActionClass::PerimeterStateKill;

    pub const fn compiled_out() -> Option<Self> {
        if is_built(ModuleId::EnfPerimeterKill) {
            None
        } else {
            Some(PerimeterStateKill { sealed: () })
        }
    }

    pub fn apply(&self, variant: &'static str) -> Result<NeverApplied, NotBuilt> {
        let () = self.sealed;
        Err(NotBuilt { class: Self::CLASS, variant })
    }
}
