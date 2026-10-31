use std::io;
use std::time::Duration;

use crate::render::Frame;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawKey {

    Char(char),

    Enter,

    Esc,

    Backspace,

    Tab,

    BackTab,

    Up,

    Down,

    Left,

    Right,

    PageUp,

    PageDown,

    Home,

    End,

    Delete,

    F(u8),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Mods {

    pub ctrl: bool,

    pub alt: bool,

    pub shift: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawEvent {

    Key(RawKey, Mods),

    PointerMove {

        x: i32,

        y: i32,
    },

    PointerDown {

        x: i32,

        y: i32,
    },

    Wheel {

        up: bool,
    },

    Resized {

        width: u32,

        height: u32,
    },

    Close,
}

pub trait Backend {

    fn size(&self) -> (u32, u32);

    fn poll(&mut self, timeout: Duration) -> io::Result<Option<RawEvent>>;

    fn present(&mut self, frame: &Frame) -> io::Result<()>;

    fn wants_pointer(&self) -> bool;

    fn scale_floor(&self) -> u32 {
        1
    }

    fn release(&mut self) {}
}
