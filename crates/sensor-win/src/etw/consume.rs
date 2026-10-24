#![cfg(target_os = "windows")]

use super::catalog::{Consumption, Lane, Provider};
use super::session::{buffers_for, enable_failure, session_name, Stats};
use core::ffi::c_void;
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND};
use windows_sys::Win32::System::Diagnostics::Etw::*;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

type GuidKey = (u32, u16, u16, [u8; 8]);

#[derive(Debug, Default)]
struct Counters {
    events: u64,

    by_provider: std::collections::HashMap<GuidKey, u64>,

    by_event: std::collections::HashMap<(u32, u16), u64>,
}

unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }

    let rec = unsafe { &*record };
    let ctx = rec.UserContext as *mut Counters;
    if ctx.is_null() {
        return;
    }

    let c = unsafe { &mut *ctx };
    c.events += 1;
    let g = rec.EventHeader.ProviderId;
    let id = rec.EventHeader.EventDescriptor.Id;
    *c.by_provider.entry((g.data1, g.data2, g.data3, g.data4)).or_insert(0) += 1;
    *c.by_event.entry((g.data1, id)).or_insert(0) += 1;
}

struct Props {
    buf: Vec<u8>,
}

impl Props {

    fn new(name: &str, lane: Lane, cpus: u32, realtime: bool) -> Self {
        let name_w = wide(name);
        let head = core::mem::size_of::<EVENT_TRACE_PROPERTIES>();
        let name_bytes = name_w.len() * 2;
        let total = head + name_bytes;
        let mut buf = vec![0u8; total];

        let b = buffers_for(lane, cpus);

        unsafe {
            let p = buf.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>();
            (*p).Wnode.BufferSize = total as u32;
            (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;

            (*p).Wnode.ClientContext = 1;
            (*p).BufferSize = b.size_kb;
            (*p).MinimumBuffers = b.minimum;
            (*p).MaximumBuffers = b.maximum;
            (*p).FlushTimer = b.flush_secs;
            (*p).LogFileMode = if realtime { EVENT_TRACE_REAL_TIME_MODE } else { 0 };

            (*p).LoggerNameOffset = head as u32;
        }

        let tail = unsafe {
            core::slice::from_raw_parts(name_w.as_ptr().cast::<u8>(), name_bytes)
        };
        buf[head..head + name_bytes].copy_from_slice(tail);
        Props { buf }
    }

    fn as_mut_ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.buf.as_mut_ptr().cast()
    }
}

pub fn stop_stale(name: &str) -> u32 {
    let mut props = Props::new(name, Lane::P0, 1, true);
    let name_w = wide(name);

    unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            name_w.as_ptr(),
            props.as_mut_ptr(),
            EVENT_TRACE_CONTROL_STOP,
        )
    }
}

pub fn consume(lane: Lane, providers: &[&Provider], secs: u64, cpus: u32) -> Result<Stats, String> {
    let name = session_name(lane);
    let name_w = wide(name);
    let mut stats = Stats::default();

    let cleaned = stop_stale(name);
    if cleaned != ERROR_SUCCESS && cleaned != ERROR_WMI_INSTANCE_NOT_FOUND {

    }

    let mut props = Props::new(name, lane, cpus, true);
    let mut handle = CONTROLTRACE_HANDLE { Value: 0 };

    let rc = unsafe { StartTraceW(&mut handle, name_w.as_ptr(), props.as_mut_ptr()) };
    if rc == ERROR_ALREADY_EXISTS {
        return Err(format!(
            "an ETW session named {name} already exists and could not be stopped — something \
             else is using it, or this process lacks the privilege to control it"
        ));
    }
    if rc != ERROR_SUCCESS {
        return Err(format!(
            "could not start the ETW session {name}: error {rc}{}",
            if rc == 5 { " (needs SYSTEM or an administrator)" } else { "" }
        ));
    }

    let mut enabled: Vec<GuidKey> = Vec::new();
    for p in providers {
        if !matches!(p.consumption, Consumption::PrivateSession) {
            stats.providers_failed.push(format!(
                "{} cannot be consumed on a private session and was not enabled",
                p.name
            ));
            continue;
        }
        let Some((d1, d2, d3, d4)) = p.guid.to_fields() else {
            stats.providers_failed.push(format!("{} has an unparseable GUID", p.name));
            continue;
        };
        let guid = windows_sys::core::GUID { data1: d1, data2: d2, data3: d3, data4: d4 };

        let rc = unsafe {
            EnableTraceEx2(
                handle,
                &guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                p.level,
                p.keywords,
                0,
                0,
                core::ptr::null(),
            )
        };
        if rc == ERROR_SUCCESS {
            stats.providers_enabled.push(p.name.to_string());
            enabled.push((d1, d2, d3, d4));
        } else {
            stats.providers_failed.push(enable_failure(p, rc));
        }
    }

    let counters = Box::new(Counters::default());
    let counters_ptr = Box::into_raw(counters);

    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { core::mem::zeroed() };
    logfile.LoggerName = name_w.as_ptr() as *mut u16;
    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(on_event);
    logfile.Context = counters_ptr.cast::<c_void>();

    let trace = unsafe { OpenTraceW(&mut logfile) };

    if trace.Value == u64::MAX {
        let _ = stop_stale(name);

        drop(unsafe { Box::from_raw(counters_ptr) });
        return Err(format!("could not open the ETW session {name} as a consumer"));
    }

    let handle_for_thread = trace;
    let worker = std::thread::spawn(move || {

        unsafe { ProcessTrace(&handle_for_thread, 1, core::ptr::null(), core::ptr::null()) }
    });

    std::thread::sleep(std::time::Duration::from_secs(secs));

    let mut stop_props = Props::new(name, lane, cpus, true);

    unsafe {
        ControlTraceW(handle, name_w.as_ptr(), stop_props.as_mut_ptr(), EVENT_TRACE_CONTROL_STOP);
    }

    unsafe { CloseTrace(trace) };
    let _ = worker.join();

    unsafe {
        let p = stop_props.as_mut_ptr();
        stats.events_lost = (*p).EventsLost;
        stats.buffers_lost = (*p).RealTimeBuffersLost;
    }

    let counters = unsafe { Box::from_raw(counters_ptr) };
    stats.delivered =
        enabled.iter().map(|g| counters.by_provider.get(g).copied().unwrap_or(0)).collect();
    stats.events = stats.delivered.iter().sum();
    stats.unattributed = counters.events.saturating_sub(stats.events);
    Ok(stats)
}
