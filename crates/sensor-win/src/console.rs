#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{INVALID_HANDLE_VALUE, TRUE};
#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Console::{
    FlushConsoleInputBuffer, GetConsoleMode, GetConsoleOutputCP, GetStdHandle, SetConsoleCtrlHandler,
    SetConsoleOutputCP, CONSOLE_MODE, STD_INPUT_HANDLE,
};

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

#[cfg(target_os = "windows")]
pub fn ignore_ctrl_c() -> bool {

    unsafe { SetConsoleCtrlHandler(None, TRUE) != 0 }
}

#[cfg(target_os = "windows")]
pub fn discard_typeahead() {

    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if input.is_null() || input == INVALID_HANDLE_VALUE {
        return;
    }
    let mut mode: CONSOLE_MODE = 0;

    if unsafe { GetConsoleMode(input, &mut mode) } == 0 {
        return;
    }

    unsafe { FlushConsoleInputBuffer(input) };
}
