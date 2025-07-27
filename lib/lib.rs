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
        sync::{
            atomic::{AtomicPtr, Ordering},
            OnceLock,
        },
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

        // Ensure file is closed even if write fails
        libc::fclose(fp);

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
    static TRACING_TOP: OnceLock<String> = OnceLock::new();

    if let Some(s) = TRACING_TOP.get() {
        return Ok(s);
    }

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

        // Safe because we're the only ones initializing this
        unsafe {
            TRACING_TOP.set(trace_top).unwrap_unchecked();
        }
        break;
    }

    TRACING_TOP.get().map(|s| s.as_str()).ok_or_else(|| {
        Report::new(JtraceError::InvalidData).attach_printable("debugfs mount point not found")
    })
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

/// Safely converts a C string pointer to a Rust String
///
/// # Safety
/// The pointer must be valid and point to a null-terminated C string
pub unsafe fn bytes_to_string(b: *const i8) -> String {
    if b.is_null() {
        return String::from("(null)");
    }

    #[cfg(target_arch = "aarch64")]
    let b = std::mem::transmute::<*const i8, *const i8>(b);

    CStr::from_ptr(b)
        .to_str()
        .map(|s| s.to_owned())
        .unwrap_or_else(|_| String::from("(invalid)"))
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
/// Safely converts a C string pointer to a Rust String with error reporting
///
/// # Safety
/// The pointer must be valid and point to a null-terminated C string
pub unsafe fn bytes_to_string_with_error(b: *const i8) -> Result<String, JtraceError> {
    if b.is_null() {
        return Err(Report::new(JtraceError::InvalidData))
            .attach_printable("Null pointer passed to bytes_to_string");
    }

    #[cfg(target_arch = "aarch64")]
    let b = std::mem::transmute::<*const i8, *const i8>(b);

    CStr::from_ptr(b)
        .to_str()
        .map(|s| s.to_owned())
        .map_err(|_| {
            Report::new(JtraceError::InvalidData)
                .attach_printable("Failed to convert C string to UTF-8")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn test_writeln_proc() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();

        // Test writing to file
        writeln_proc(path, "test content", false).unwrap();

        // Verify content
        let mut content = String::new();
        File::open(path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "test content");

        // Test append mode
        writeln_proc(path, " appended", true).unwrap();
        content.clear();
        File::open(path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "test content appended");
    }

    #[test]
    fn test_writeln_str_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();

        // Test writing with newline handling
        writeln_str_file(path, "test line", false).unwrap();

        // Verify content has newline
        let mut content = String::new();
        File::open(path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "test line\n");

        // Test empty string case
        writeln_str_file(path, "", true).unwrap();
        content.clear();
        File::open(path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "test line\n\n");
    }

    #[test]
    fn test_bytes_to_string() {
        // Test valid C string
        let c_str = CString::new("test string").unwrap();
        let result = unsafe { bytes_to_string(c_str.as_ptr()) };
        assert_eq!(result, "test string");

        // Test null pointer
        assert_eq!(unsafe { bytes_to_string(std::ptr::null()) }, "(null)");
    }

    #[test]
    fn test_bytes_to_string_with_error() {
        // Test valid C string
        let c_str = CString::new("test string").unwrap();
        let result = unsafe { bytes_to_string_with_error(c_str.as_ptr()) }.unwrap();
        assert_eq!(result, "test string");

        // Test null pointer error
        let err = unsafe { bytes_to_string_with_error(std::ptr::null()) }.unwrap_err();
        assert!(matches!(err.current_context(), JtraceError::InvalidData));
    }

    #[test]
    fn test_tid_to_pid() {
        // Test with current process ID (should return same value)
        let tid = std::process::id() as i32;
        let pid = tid_to_pid(tid).unwrap();
        assert_eq!(pid, tid);

        // Test invalid thread ID
        assert!(tid_to_pid(-1).is_none());
    }

    #[test]
    fn test_trace_top_dir() {
        // Skip test if debugfs isn't mounted
        if fs::metadata("/sys/kernel/debug").is_err() {
            return;
        }

        // Should find debugfs mount point
        let path = trace_top_dir().unwrap();
        assert!(path.ends_with("/tracing"));

        // Should be cached on subsequent calls
        let path2 = trace_top_dir().unwrap();
        assert_eq!(path, path2);
    }
}
