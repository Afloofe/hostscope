#![cfg(target_os = "windows")]

use core::cell::{Cell, RefCell};
use core::ffi::c_void;
use core::ptr::{null, null_mut, with_exposed_provenance, NonNull};
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{FALSE, HINSTANCE, HWND, LPARAM, LRESULT, RECT, WAIT_FAILED, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, CreateSolidBrush, DeleteObject, EndPaint, FillRect, GetDC, GetDeviceCaps, InvalidateRect, ReleaseDC,
    StretchDIBits, UpdateWindow, ValidateRect, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HDC, LOGPIXELSX,
    PAINTSTRUCT, SRCCOPY,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyState, SetFocus, VIRTUAL_KEY, VK_0, VK_ADD, VK_BACK, VK_CONTROL, VK_DELETE, VK_DOWN, VK_END, VK_ESCAPE,
    VK_F1, VK_F12, VK_F4, VK_HOME, VK_LEFT, VK_MENU, VK_NEXT, VK_NUMPAD0, VK_OEM_MINUS, VK_OEM_PLUS, VK_PRIOR,
    VK_RETURN, VK_RIGHT, VK_SHIFT, VK_SUBTRACT, VK_TAB, VK_UP,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRectEx, CreateWindowExW, DefWindowProcW, DestroyWindow, DisableProcessWindowsGhosting,
    DispatchMessageW, GetClientRect, GetWindowLongPtrW, LoadCursorW, MsgWaitForMultipleObjects, PeekMessageW,
    RegisterClassExW, SetForegroundWindow, SetProcessDPIAware, SetWindowLongPtrW, SetWindowPos, ShowWindow,
    SystemParametersInfoW, TranslateMessage, UnregisterClassW, CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT,
    GWLP_USERDATA, HTCLIENT, IDC_ARROW, MA_ACTIVATEANDEAT, MSG, PM_REMOVE, QS_ALLINPUT, SC_KEYMENU, SIZE_MINIMIZED,
    SPI_GETWORKAREA, SWP_NOACTIVATE, SWP_NOZORDER, SW_SHOW, WHEEL_DELTA, WM_CHAR, WM_CLOSE, WM_DPICHANGED,
    WM_ERASEBKGND, WM_KEYDOWN, WM_KEYFIRST, WM_KEYLAST, WM_LBUTTONDOWN, WM_MOUSEACTIVATE, WM_MOUSEFIRST,
    WM_MOUSELAST, WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_NCCREATE, WM_NCDESTROY, WM_PAINT, WM_QUIT, WM_SIZE, WM_SYSCHAR,
    WM_SYSCOMMAND, WM_SYSKEYDOWN, WNDCLASSEXW, WS_EX_APPWINDOW, WS_OVERLAPPEDWINDOW,
};

use crate::gui_window_logic::{self as logic, Bounds, KeyDown, KeyMods, Typing, Wheel};
pub use crate::gui_window_logic::{WinEvent, WinKey};

const _: () = {
    assert!(logic::VK_BACK == VK_BACK);
    assert!(logic::VK_TAB == VK_TAB);
    assert!(logic::VK_RETURN == VK_RETURN);
    assert!(logic::VK_ESCAPE == VK_ESCAPE);
    assert!(logic::VK_PRIOR == VK_PRIOR);
    assert!(logic::VK_NEXT == VK_NEXT);
    assert!(logic::VK_END == VK_END);
    assert!(logic::VK_HOME == VK_HOME);
    assert!(logic::VK_LEFT == VK_LEFT);
    assert!(logic::VK_UP == VK_UP);
    assert!(logic::VK_RIGHT == VK_RIGHT);
    assert!(logic::VK_DOWN == VK_DOWN);
    assert!(logic::VK_DELETE == VK_DELETE);
    assert!(logic::VK_0 == VK_0);
    assert!(logic::VK_NUMPAD0 == VK_NUMPAD0);
    assert!(logic::VK_ADD == VK_ADD);
    assert!(logic::VK_SUBTRACT == VK_SUBTRACT);
    assert!(logic::VK_F1 == VK_F1);
    assert!(logic::VK_F4 == VK_F4);
    assert!(logic::VK_F12 == VK_F12);
    assert!(logic::VK_OEM_PLUS == VK_OEM_PLUS);
    assert!(logic::VK_OEM_MINUS == VK_OEM_MINUS);
    assert!(logic::SC_KEYMENU == SC_KEYMENU as usize);
    assert!(logic::WHEEL_NOTCH as u32 == WHEEL_DELTA);
    assert!(logic::HTCLIENT as u32 == HTCLIENT);
};

const PUMP_LIMIT: usize = 1024;

#[derive(Default)]
struct Shared {

    events: RefCell<VecDeque<WinEvent>>,

    frame: RefCell<Frame>,

    size: Cell<(u32, u32)>,

    typing: Cell<Typing>,

    wheel: Cell<Wheel>,

    destroyed: Cell<bool>,
}

#[derive(Default)]
struct Frame {
    width: u32,
    height: u32,

    pixels: Vec<u32>,
}

impl Shared {

    fn push(&self, event: WinEvent) {
        if let Ok(mut events) = self.events.try_borrow_mut() {
            logic::enqueue(&mut events, event);
        }
    }

    fn pop(&self) -> Option<WinEvent> {
        self.events.try_borrow_mut().ok()?.pop_front()
    }

    fn has_events(&self) -> bool {
        self.events.try_borrow().is_ok_and(|events| !events.is_empty())
    }
}

struct Class {

    name: Vec<u16>,
    instance: HINSTANCE,
}

impl Class {
    fn register(instance: HINSTANCE) -> io::Result<Class> {

        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = logic::wide(&format!("HemostatGuiWindow{n}"));

        let cursor = unsafe { LoadCursorW(null_mut(), IDC_ARROW) };
        let class = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,

            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(window_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: instance,
            hIcon: null_mut(),
            hCursor: cursor,

            hbrBackground: null_mut(),
            lpszMenuName: null(),
            lpszClassName: name.as_ptr(),
            hIconSm: null_mut(),
        };

        if unsafe { RegisterClassExW(&class) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Class { name, instance })
    }
}

impl Drop for Class {
    fn drop(&mut self) {

        unsafe { UnregisterClassW(self.name.as_ptr(), self.instance) };
    }
}

pub struct Window {
    hwnd: HWND,

    shared: NonNull<Shared>,

    dpi: u32,

    _class: Class,
}

impl Window {

    pub fn open(title: &str) -> io::Result<Window> {
        let mut session = 0u32;

        let read = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) } != 0;
        if logic::refuses_session(read.then_some(session)) {
            return Err(io::Error::new(io::ErrorKind::Unsupported, logic::SESSION_ZERO));
        }

        unsafe { DisableProcessWindowsGhosting() };

        unsafe { SetProcessDPIAware() };

        let instance = unsafe { GetModuleHandleW(null()) };
        if instance.is_null() {
            return Err(io::Error::last_os_error());
        }
        let class = Class::register(instance)?;
        let dpi = system_dpi();
        let place = initial_placement(dpi);
        let (x, y) = place.origin.unwrap_or((CW_USEDEFAULT, CW_USEDEFAULT));
        let (width, height) = place.size;
        let title = logic::wide(title);
        let shared = NonNull::from(Box::leak(Box::new(Shared::default())));

        let hwnd = unsafe {
            CreateWindowExW(
                WS_EX_APPWINDOW,
                class.name.as_ptr(),
                title.as_ptr(),
                WS_OVERLAPPEDWINDOW,
                x,
                y,
                width,
                height,
                null_mut(),
                null_mut(),
                instance,
                shared.as_ptr().cast::<c_void>().cast_const(),
            )
        };
        if hwnd.is_null() {
            let refused = io::Error::last_os_error();

            drop(unsafe { Box::from_raw(shared.as_ptr()) });
            return Err(refused);
        }

        let window = Window { hwnd, shared, dpi, _class: class };

        unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, shared.as_ptr().expose_provenance() as isize) };

        if let Some(size) = client_size(hwnd) {
            window.shared().size.set(size);
        }

        unsafe {
            ShowWindow(hwnd, SW_SHOW);
            SetForegroundWindow(hwnd);
            UpdateWindow(hwnd);
        }
        Ok(window)
    }

    pub fn size(&self) -> (u32, u32) {
        self.shared().size.get()
    }

    pub fn scale_floor(&self) -> u32 {
        logic::dpi_scale(self.dpi)
    }

    pub fn poll(&mut self, timeout: Duration) -> io::Result<Option<WinEvent>> {
        let start = Instant::now();
        loop {
            if let Some(event) = self.shared().pop() {
                return Ok(Some(event));
            }
            let settled = self.pump();
            if let Some(event) = self.shared().pop() {
                return Ok(Some(event));
            }
            let left = timeout.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Ok(None);
            }

            if !settled {
                continue;
            }

            let woke = unsafe { MsgWaitForMultipleObjects(0, null(), FALSE, logic::wait_millis(left), QS_ALLINPUT) };
            if woke == WAIT_FAILED {
                return Err(io::Error::last_os_error());
            }
        }
    }

    pub fn present(&mut self, width: u32, height: u32, pixels: &[u32]) -> io::Result<()> {
        let n = logic::frame_len(width, height, pixels.len())?;
        if self.shared().destroyed.get() {

            return Ok(());
        }
        {
            let mut frame = self
                .shared()
                .frame
                .try_borrow_mut()
                .map_err(|_| io::Error::other("the window is still painting the previous frame"))?;
            frame.width = width;
            frame.height = height;
            frame.pixels.clear();
            frame.pixels.extend_from_slice(pixels.get(..n).unwrap_or_default());
        }

        unsafe {
            InvalidateRect(self.hwnd, null(), FALSE);
            UpdateWindow(self.hwnd);
        }
        Ok(())
    }

    pub fn forget_input(&mut self) {
        for (first, last) in [(WM_KEYFIRST, WM_KEYLAST), (WM_MOUSEFIRST, WM_MOUSELAST)] {
            for _ in 0..PUMP_LIMIT {
                let mut msg = MSG::default();

                if unsafe { PeekMessageW(&mut msg, null_mut(), first, last, PM_REMOVE) } == 0 {
                    break;
                }
            }
        }
        if let Ok(mut events) = self.shared().events.try_borrow_mut() {
            logic::forget_input(&mut events);
        }
    }

    fn pump(&self) -> bool {
        for _ in 0..PUMP_LIMIT {
            if self.shared().has_events() {
                return true;
            }
            let mut msg = MSG::default();

            if unsafe { PeekMessageW(&mut msg, null_mut(), 0, 0, PM_REMOVE) } == 0 {
                return true;
            }
            if msg.message == WM_QUIT {

                self.shared().push(WinEvent::Close);
                continue;
            }

            unsafe {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        self.shared().has_events()
    }

    fn shared(&self) -> &Shared {

        unsafe { self.shared.as_ref() }
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        if !self.shared().destroyed.get() {

            unsafe { DestroyWindow(self.hwnd) };
        }
        if !self.shared().destroyed.get() {

            unsafe { SetWindowLongPtrW(self.hwnd, GWLP_USERDATA, 0) };
        }

        drop(unsafe { Box::from_raw(self.shared.as_ptr()) });
    }
}

unsafe extern "system" fn window_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if msg == WM_NCCREATE {
        let create = with_exposed_provenance::<CREATESTRUCTW>(lparam as usize);

        let create = unsafe { create.as_ref() };
        if let Some(create) = create {

            unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, create.lpCreateParams.expose_provenance() as isize) };
        }
    } else {

        let stored = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
        let state = with_exposed_provenance::<Shared>(stored as usize);

        let shared = unsafe { state.as_ref() };
        if let Some(result) = shared.and_then(|shared| on_message(hwnd, shared, msg, wparam, lparam)) {
            return result;
        }
    }

    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

fn on_message(hwnd: HWND, shared: &Shared, msg: u32, wparam: WPARAM, lparam: LPARAM) -> Option<LRESULT> {
    match msg {
        WM_PAINT => {
            paint(hwnd, shared);
            Some(0)
        }

        WM_ERASEBKGND => Some(1),
        WM_SIZE => {

            if wparam != SIZE_MINIMIZED as WPARAM {
                let (width, height) = logic::size_from_lparam(lparam);
                shared.size.set((width, height));
                shared.push(WinEvent::Resized { width, height });
            }
            Some(0)
        }

        WM_CLOSE => {
            shared.push(WinEvent::Close);
            Some(0)
        }
        WM_NCDESTROY => {

            unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
            shared.destroyed.set(true);

            shared.push(WinEvent::Close);
            None
        }
        WM_DPICHANGED => {
            follow_dpi(hwnd, lparam);
            Some(0)
        }
        WM_KEYDOWN | WM_SYSKEYDOWN => {
            let mods = modifiers();
            let mut typing = shared.typing.get();
            let decision = typing.key_down(logic::key_from_wparam(wparam), logic::scan_from_lparam(lparam), mods);
            shared.typing.set(typing);
            match decision {
                KeyDown::Report(event) => {
                    shared.push(event);
                    Some(0)
                }
                KeyDown::Pass => None,
            }
        }
        WM_CHAR | WM_SYSCHAR => {
            let unit = logic::key_from_wparam(wparam);

            if msg == WM_SYSCHAR && unit == u16::from(b' ') {
                return None;
            }
            let mut typing = shared.typing.get();
            let typed = typing.char_unit(unit, logic::scan_from_lparam(lparam), modifiers());
            shared.typing.set(typing);
            if let Some(event) = typed {
                shared.push(event);
            }

            Some(0)
        }
        WM_SYSCOMMAND if logic::swallows_menu_key(wparam, lparam) => Some(0),

        WM_MOUSEACTIVATE if logic::eats_activating_click(logic::hit_test_from_lparam(lparam)) => {
            Some(MA_ACTIVATEANDEAT as LRESULT)
        }
        WM_MOUSEMOVE => {
            let (x, y) = logic::point_from_lparam(lparam);
            shared.push(WinEvent::PointerMove { x, y });
            Some(0)
        }
        WM_LBUTTONDOWN => {
            let (x, y) = logic::point_from_lparam(lparam);
            shared.push(WinEvent::PointerDown { x, y });

            unsafe { SetFocus(hwnd) };
            Some(0)
        }
        WM_MOUSEWHEEL => {
            let mut wheel = shared.wheel.get();
            let notches = wheel.feed(logic::wheel_delta(wparam));
            shared.wheel.set(wheel);
            for _ in 0..notches.count {
                shared.push(WinEvent::Wheel { up: notches.up });
            }
            Some(0)
        }
        _ => None,
    }
}

fn modifiers() -> KeyMods {
    KeyMods { ctrl: held(VK_CONTROL), alt: held(VK_MENU), shift: held(VK_SHIFT) }
}

fn held(vk: VIRTUAL_KEY) -> bool {

    let state = unsafe { GetKeyState(i32::from(vk)) };

    state < 0
}

fn paint(hwnd: HWND, shared: &Shared) {
    let mut ps = PAINTSTRUCT::default();

    let hdc = unsafe { BeginPaint(hwnd, &mut ps) };
    if hdc.is_null() {

        unsafe { ValidateRect(hwnd, null()) };
        return;
    }
    let client = client_size(hwnd).unwrap_or_else(|| shared.size.get());
    draw(hdc, shared, client);

    unsafe { EndPaint(hwnd, &ps) };
}

fn draw(hdc: HDC, shared: &Shared, client: (u32, u32)) {

    let Ok(frame) = shared.frame.try_borrow() else {
        return;
    };
    let drawn = (frame.width, frame.height);
    let complete = logic::frame_len(frame.width, frame.height, frame.pixels.len()).is_ok();
    if let (Ok(width), Ok(height), true) = (i32::try_from(frame.width), i32::try_from(frame.height), complete) {
        if width > 0 && height > 0 {
            let info = dib_info(width, height);

            unsafe {
                StretchDIBits(
                    hdc,
                    0,
                    0,
                    width,
                    height,
                    0,
                    0,
                    width,
                    height,
                    frame.pixels.as_ptr().cast::<c_void>(),
                    &info,
                    DIB_RGB_COLORS,
                    SRCCOPY,
                )
            };
        }
    }
    let colour = logic::margin_colour(&frame.pixels);
    drop(frame);
    let margins = logic::margins(drawn, client);
    if margins.iter().all(Option::is_none) {
        return;
    }

    let brush = unsafe { CreateSolidBrush(logic::colorref(colour)) };
    if brush.is_null() {
        return;
    }
    for margin in margins.into_iter().flatten() {
        let rect = RECT { left: margin.left, top: margin.top, right: margin.right, bottom: margin.bottom };

        unsafe { FillRect(hdc, &rect, brush) };
    }

    unsafe { DeleteObject(brush) };
}

fn dib_info(width: i32, height: i32) -> BITMAPINFO {
    BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width,

            biHeight: height.saturating_neg(),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..BITMAPINFOHEADER::default()
        },
        ..BITMAPINFO::default()
    }
}

fn follow_dpi(hwnd: HWND, lparam: LPARAM) {
    let suggested = with_exposed_provenance::<RECT>(lparam as usize);

    let suggested = unsafe { suggested.as_ref() }.copied();
    let Some(r) = suggested else {
        return;
    };

    unsafe {
        SetWindowPos(
            hwnd,
            null_mut(),
            r.left,
            r.top,
            r.right.saturating_sub(r.left),
            r.bottom.saturating_sub(r.top),
            SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
}

fn client_size(hwnd: HWND) -> Option<(u32, u32)> {
    let mut r = RECT::default();

    if unsafe { GetClientRect(hwnd, &mut r) } == 0 {
        return None;
    }
    let side = |from: i32, to: i32| u32::try_from(to.saturating_sub(from)).unwrap_or(0);
    Some((side(r.left, r.right), side(r.top, r.bottom)))
}

fn system_dpi() -> u32 {

    let hdc = unsafe { GetDC(null_mut()) };
    if hdc.is_null() {
        return logic::BASE_DPI;
    }

    let dpi = unsafe { GetDeviceCaps(hdc, LOGPIXELSX as i32) };

    unsafe { ReleaseDC(null_mut(), hdc) };
    u32::try_from(dpi).ok().filter(|&d| d > 0).unwrap_or(logic::BASE_DPI)
}

fn initial_placement(dpi: u32) -> logic::Placement {
    let mut work = RECT::default();

    let read = unsafe { SystemParametersInfoW(SPI_GETWORKAREA, 0, (&raw mut work).cast::<c_void>(), 0) } != 0;
    let work = read.then_some(Bounds { left: work.left, top: work.top, right: work.right, bottom: work.bottom });
    let (want_w, want_h) = logic::preferred_client(dpi);
    let mut outer = RECT { left: 0, top: 0, right: want_w, bottom: want_h };

    let adjusted = unsafe { AdjustWindowRectEx(&mut outer, WS_OVERLAPPEDWINDOW, FALSE, WS_EX_APPWINDOW) } != 0;
    let frame = if adjusted {
        (
            outer.right.saturating_sub(outer.left).saturating_sub(want_w),
            outer.bottom.saturating_sub(outer.top).saturating_sub(want_h),
        )
    } else {
        (0, 0)
    };
    logic::placement_for(work, frame, (want_w, want_h))
}
