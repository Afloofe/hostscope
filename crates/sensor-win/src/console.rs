#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Console::{GetConsoleOutputCP, SetConsoleOutputCP};

#[cfg(target_os = "windows")]
const CP_UTF8: u32 = 65001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {

    AlreadyUtf8,

    Switched(u32),

    Refused {

        from: u32,

        error: u32,
    },
}

impl Encoding {

    pub const fn is_utf8(self) -> bool {
        matches!(self, Encoding::AlreadyUtf8 | Encoding::Switched(_))
    }
}

#[cfg(target_os = "windows")]
pub fn use_utf8_output() -> Encoding {

    let before = unsafe { GetConsoleOutputCP() };
    if before == CP_UTF8 || before == 0 {
        return Encoding::AlreadyUtf8;
    }

    let ok = unsafe { SetConsoleOutputCP(CP_UTF8) };
    if ok == 0 {

        let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        return Encoding::Refused { from: before, error };
    }
    Encoding::Switched(before)
}
