use std::io;

use ratatui_core::buffer::Buffer;
use ratatui_core::layout::Rect;

use crate::chrome::Hits;
use crate::input::Input;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceEvent {

    In(Input),

    Resize,

    Close,
}

pub trait Surface {

    fn area(&mut self) -> io::Result<Rect>;

    fn next(&mut self, idle: bool) -> io::Result<Option<SurfaceEvent>>;

    fn present(&mut self, buf: &Buffer, hits: &Hits) -> io::Result<()>;

    fn release(&mut self) {}
}
