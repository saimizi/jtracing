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

/// Writes a string to a file in `/proc` or similar system directory with control over append/truncate behavior.
///
/// This function:
/// 1. Opens the file with write permissions, creating it if it doesn't exist
/// 2. Controls whether to append or truncate based on the `append` parameter
/// 3. Writes the string contents exactly as provided (does not add newlines)
/// 4. Ensures the write is flushed to disk
///
/// Parameters:
/// - `f`: Path to the file (typically in /proc or /sys)
/// - `s`: String content to write
/// - `append`: If true, appends to existing content. If false, truncates file first.
///
/// Returns:
/// - Ok(()) on success
/// - Err(JtraceError::IOError) if any file operation fails
///
/// Notes:
/// - Unlike `writeln_str_file`, this does NOT automatically add newlines
/// - Creates the file if it doesn't exist
/// - Useful for writing to pseudo-files in /proc and /sys
pub fn writeln_proc(f: &str, s: &str, append: bool) -> Result<(), JtraceError> {
    use std::fs::OpenOptions;
    use std::io::Write;

    // Open file with options based on append mode
    let mut file = OpenOptions::new()
        .write(true)
        .create(true) // Create file if it doesn't exist
        .append(append) // Append if requested
        .truncate(!append) // Truncate only if not in append mode
        .open(f)
        .map_err(|e| {
            Report::new(JtraceError::IOError)
                .attach_printable(format!("Failed to open {}: {}", f, e))
        })?;

    // Write the raw string bytes (no automatic newline)
    file.write_all(s.as_bytes()).map_err(|e| {
        Report::new(JtraceError::IOError)
            .attach_printable(format!("Failed to write to {}: {}", f, e))
    })?;

    // Ensure data is flushed to disk
    file.flush().map_err(|e| {
        Report::new(JtraceError::IOError).attach_printable(format!("Failed to flush {}: {}", f, e))
    })?;

    Ok(())
}

/// Writes a string to a file with automatic newline handling.
///
/// This function:
/// 1. Verifies the file exists
/// 2. Automatically appends a newline if the string doesn't end with one
/// 3. Writes the content with proper error handling
///
/// Parameters:
/// - `f`: Path to the file
/// - `s`: String content to write
/// - `append`: If true, appends to existing content. If false, truncates file first.
///
/// Returns:
/// - Ok(()) on success
/// - Err(JtraceError::InvalidData) if file doesn't exist
/// - Err(JtraceError::IOError) on any I/O error
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

/// Finds and caches the path to the kernel tracing directory.
///
/// This function:
/// 1. Locates the debugfs mount point by reading /proc/mounts
/// 2. Appends "/tracing" to get the full tracing directory path
/// 3. Caches the result in a static OnceLock for future calls
///
/// Typical return values:
/// - On success: "/sys/kernel/debug/tracing" (path may vary)
/// - On error: Returns JtraceError::InvalidData if debugfs not mounted
///             or JtraceError::IOError if /proc/mounts can't be read
///
/// The result is cached after first successful call for performance.
/// Subsequent calls will return the cached path without filesystem access.
pub fn trace_top_dir() -> Result<&'static str, JtraceError> {
    static TRACING_TOP: OnceLock<String> = OnceLock::new();

    // Return cached value if available
    if let Some(s) = TRACING_TOP.get() {
        return Ok(s);
    }

    // Read /proc/mounts to find debugfs mount point
    let file = fs::OpenOptions::new()
        .read(true)
        .open(Path::new("/proc/mounts"))
        .map_err(|_| Report::new(JtraceError::IOError))?;
    let mut lines = BufReader::new(file).lines();

    while let Some(Ok(l)) = lines.next() {
        let entries: Vec<&str> = l.split(' ').collect();

        // Skip non-debugfs entries
        if entries[0] != "debugfs" {
            continue;
        }

        // Found debugfs mount - build tracing path
        let mut trace_top = String::from(entries[1]);
        trace_top.push_str("/tracing");

        // Store in OnceLock (safe because we're the only initializer)
        unsafe {
            TRACING_TOP.set(trace_top).unwrap_unchecked();
        }
        break;
    }

    // Return cached value or error if debugfs not found
    TRACING_TOP.get().map(|s| s.as_str()).ok_or_else(|| {
        Report::new(JtraceError::InvalidData).attach_printable("debugfs mount point not found")
    })
}

/// Discovers and caches all available kernel tracepoints.
///
/// Scans the tracing events directory to find all tracepoints in format "category:name".
/// The results are cached after first discovery for performance.
///
/// Returns:
/// - Ok(&str) with newline-separated list of tracepoints on success
/// - Err(JtraceError::IOError) if events directory can't be read
/// - Err(JtraceError::InvalidData) if no tracepoints found
///
/// Example return value:
/// "sched:sched_switch\nsched:sched_wakeup\n..."
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

/// Increases the memlock resource limit to maximum.
///
/// This is typically needed for BPF programs that lock memory for maps.
/// Uses RLIM_INFINITY for both current and max limits.
///
/// Safety: Uses unsafe libc calls but is safe as it doesn't violate memory safety.
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

    CStr::from_ptr(b as *const libc::c_char)
        .to_str()
        .map(|s| s.to_owned())
        .unwrap_or_else(|_| String::from("(invalid)"))
}

/// Converts a thread ID (TID) to its parent process ID (PID).
///
/// Reads /proc/[tid]/status to find the Tgid field which represents the PID.
///
/// Parameters:
/// - `tid`: Thread ID to look up
///
/// Returns:
/// - Some(pid) if status file exists and contains Tgid
/// - None if thread doesn't exist or status can't be read
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

    CStr::from_ptr(b as *const libc::c_char)
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

        // Test creating new file
        let new_path = format!("{}.new", path);
        writeln_proc(&new_path, "new file", false).unwrap();
        assert!(Path::new(&new_path).exists());

        // Test empty string
        writeln_proc(path, "", true).unwrap();
        content.clear();
        File::open(path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "test content appended");

        // Test non-ASCII but valid UTF-8 content
        let s = "こんにちは"; // "Hello" in Japanese
        writeln_proc(path, s, false).unwrap();

        // Verify the content was written correctly
        content.clear();
        File::open(path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "こんにちは");

        // Test error cases
        // Invalid path (directory)
        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path().to_str().unwrap();
        assert!(writeln_proc(dir_path, "test", false).is_err());

        // Read-only file
        let ro_file = tempfile::NamedTempFile::new().unwrap();
        let ro_path = ro_file.path();
        let mut perms = fs::metadata(ro_path).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(ro_path, perms).unwrap();
        assert!(writeln_proc(ro_path.to_str().unwrap(), "test", false).is_err());
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
