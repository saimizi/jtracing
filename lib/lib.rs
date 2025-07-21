#[allow(unused)]
use {
    error_stack::{Report, Result, ResultExt},
    jlogger_tracing::{jdebug, jerror, jinfo, jwarn},
    std::{
        ffi::{CStr, CString},
        fmt::Display,
        fs::{self, File},
        io::{BufRead, BufReader, BufWriter, Write},
        path::{Path, PathBuf},
        sync::atomic::{AtomicPtr, Ordering},
    },
};

pub mod error;
pub mod kprobe;
pub mod symbolanalyzer;
pub mod tracelog;

pub use error::JtraceError;
pub use kprobe::Kprobe;
pub use symbolanalyzer::ElfFile;
pub use symbolanalyzer::ExecMap;
pub use symbolanalyzer::KernelMap;
pub use symbolanalyzer::KernelSymbolEntry;
pub use symbolanalyzer::NmSymbolType;
pub use symbolanalyzer::SymbolAnalyzer;
pub use tracelog::TraceLog;

pub fn writeln_proc(f: &str, s: &str, append: bool) -> Result<(), JtraceError> {
    unsafe {
        let c_file = CString::new(f).map_err(|_| Report::new(JtraceError::InvalidData))?;
        let mut mode = CString::new("w").unwrap();
        if append {
            mode = CString::new("a").unwrap();
        }
        let fp = libc::fopen(c_file.as_ptr(), mode.as_ptr());

        if fp.is_null() {
            return Err(Report::new(JtraceError::IOError)).attach_printable(format!(
                "Failed to open {} to write {} ({})",
                f,
                s,
                std::io::Error::last_os_error()
            ));
        }

        let c_buf = CString::new(s).map_err(|_| Report::new(JtraceError::InvalidData))?;
        let ret = libc::fwrite(
            c_buf.as_ptr() as *const libc::c_void,
            c_buf.as_bytes().len(),
            1,
            fp,
        ) as i32;

        if ret < 0 {
            return Err(Report::new(JtraceError::IOError)).attach_printable(format!(
                "Failed to write {} ({})",
                f,
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

pub fn writeln_str_file(f: &str, s: &str, append: bool) -> Result<(), JtraceError> {
    let fp = Path::new(f);

    if !fp.is_file() {
        return Err(Report::new(JtraceError::InvalidData))
            .attach_printable(format!("File {} not exist.", f));
    }

    let file = fs::OpenOptions::new()
        .write(true)
        .append(append)
        .open(fp)
        .map_err(|_| Report::new(JtraceError::IOError))
        .attach_printable(format!("Failed to open {}", f))?;

    let mut ns = String::from(s);
    if !ns.ends_with('\n') {
        ns.push('\n')
    }

    if ns == "\n" {
        writeln_proc(f, s, append)?;
    }

    let mut writer = BufWriter::new(file);

    writer
        .write(ns.as_bytes())
        .map_err(|_| Report::new(JtraceError::IOError))
        .attach_printable(format!("Failed write {} to {}", ns, f))?;

    writer
        .flush()
        .map_err(|_| Report::new(JtraceError::IOError))
        .attach_printable(format!("Failed write {} to {}", ns, f))?;

    Ok(())
}

pub fn trace_top_dir() -> Result<&'static str, JtraceError> {
    static TRACING_TOP: AtomicPtr<String> = AtomicPtr::<String>::new(std::ptr::null_mut());

    let mut top = TRACING_TOP.load(Ordering::Acquire);
    if top.is_null() {
        let file = fs::OpenOptions::new()
            .read(true)
            .open(Path::new("/proc/mounts"))
            .map_err(|_| Report::new(JtraceError::IOError))?;
        let mut lines = BufReader::new(file).lines();

        while let Some(Ok(l)) = lines.next() {
            let entries: Vec<&str> = l.split(' ').collect();

            if entries[0] != "debugfs" {
                continue;
            }

            let mut trace_top = String::from(entries[1]);
            trace_top.push_str("/tracing");
            top = Box::into_raw(Box::new(trace_top));
            TRACING_TOP.store(top, Ordering::Release);
            break;
        }
    }

    if top.is_null() {
        Err(Report::new(JtraceError::InvalidData)).attach_printable("trace top directory not found")
    } else {
        Ok(unsafe { &*top })
    }
}

pub fn tracepoints() -> Result<&'static str, JtraceError> {
    static TRACEPOINTS: AtomicPtr<String> = AtomicPtr::<String>::new(std::ptr::null_mut());

    let mut tracepoints = TRACEPOINTS.load(Ordering::Acquire);
    if tracepoints.is_null() {
        let mut trace_points = String::new();
        let mut events_dir = trace_top_dir()?.to_string();
        events_dir.push_str("/events");

        let mut path_dir =
            fs::read_dir(events_dir).map_err(|_| Report::new(JtraceError::IOError))?;

        while let Some(Ok(entry)) = path_dir.next() {
            if let Ok(d) = entry.file_type() {
                if !d.is_dir() {
                    continue;
                }

                if let Some(d) = entry.file_name().to_str() {
                    let category = String::from(d);

                    if let Ok(mut internal) = fs::read_dir(entry.path()) {
                        while let Some(Ok(entry)) = internal.next() {
                            if let Ok(d) = entry.file_type() {
                                if !d.is_dir() {
                                    continue;
                                }

                                if let Some(tp) = entry.file_name().to_str() {
                                    let tracepoint = format!("{}:{}\n", category, tp);
                                    //jdebug!("find tracepoint {}", tracepoint);
                                    trace_points.push_str(&tracepoint);
                                }
                            }
                        }
                    }
                }
            }
        }
        if !trace_points.is_empty() {
            tracepoints = Box::into_raw(Box::new(trace_points));
            TRACEPOINTS.store(tracepoints, Ordering::Release);
        }
    }

    if !tracepoints.is_null() {
        Ok(unsafe { &*tracepoints })
    } else {
        Err(Report::new(JtraceError::InvalidData)).attach_printable("Trace points are not found.")
    }
}

pub fn bump_memlock_rlimit() {
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };

        libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit as *const libc::rlimit);
    }
}

/// # Safety
///
/// This function might dereference a raw pointer.
pub unsafe fn bytes_to_string(b: *const i8) -> String {
    let ret = String::from("INVALID");

    #[cfg(target_arch = "aarch64")]
    let b = std::mem::transmute(b);

    if let Ok(s) = CStr::from_ptr(b).to_str() {
        return s.to_owned();
    }
    ret
}

pub fn tid_to_pid(tid: i32) -> Option<i32> {
    use std::fs;
    use std::io::{self, BufRead};

    // 'Tgid' is the process id.
    let status_path = format!("/proc/{}/status", tid);
    let file = fs::File::open(&status_path).ok()?;
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        let line = line.ok()?;
        if line.starts_with("Tgid:") {
            let pid_str = line.trim_start_matches("Tgid:").trim();
            return pid_str.parse::<i32>().ok();
        }
    }
    None
}
