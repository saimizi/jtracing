#[allow(unused)]
use {
    error_stack::{Report, Result, ResultExt},
    std::{
        ffi::{CStr, CString},
        fmt::Display,
        path::{Path, PathBuf},
    },
    tokio::{
        fs::{self, File},
        io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter},
        sync::mpsc::{self, Receiver, Sender},
        task::JoinHandle,
    },
};

pub mod error;
pub mod kprobe;
pub mod symbolanalyzer;
pub mod tracelog;

pub use error::JtraceError;
use error_stack::IntoReport;
pub use kprobe::{set_tracing_top, Kprobe};
pub use symbolanalyzer::ElfFile;
pub use symbolanalyzer::ExecMap;
pub use symbolanalyzer::KernelMap;
pub use symbolanalyzer::KernelSymbolEntry;
pub use symbolanalyzer::NmSymbolType;
pub use symbolanalyzer::SymbolAnalyzer;
pub use tracelog::TraceLog;

pub fn writeln_proc(f: &str, s: &str, append: bool) -> Result<(), JtraceError> {
    unsafe {
        let c_file = CString::new(f)
            .into_report()
            .change_context(JtraceError::InvalidData)?;
        let mut mode = CString::new("w").unwrap();
        if append {
            mode = CString::new("a").unwrap();
        }
        let fp = libc::fopen(c_file.as_ptr(), mode.as_ptr());

        if fp.is_null() {
            return Err(JtraceError::IOError)
                .into_report()
                .attach_printable(format!(
                    "Failed to open {} to write {} ({})",
                    f,
                    s,
                    std::io::Error::last_os_error()
                ));
        }

        let c_buf = CString::new(s)
            .into_report()
            .change_context(JtraceError::InvalidData)?;
        let ret = libc::fwrite(
            c_buf.as_ptr() as *const libc::c_void,
            c_buf.as_bytes().len(),
            1,
            fp,
        ) as i32;

        if ret < 0 {
            return Err(JtraceError::IOError)
                .into_report()
                .attach_printable(format!(
                    "Failed to write {} ({})",
                    f,
                    std::io::Error::last_os_error()
                ));
        }
    }
    Ok(())
}

pub async fn writeln_str_file(f: &str, s: &str, append: bool) -> Result<(), JtraceError> {
    let fp = Path::new(f);

    if !fp.is_file() {
        return Err(JtraceError::InvalidData)
            .into_report()
            .attach_printable(format!("File {} not exist.", f));
    }

    let file = fs::OpenOptions::new()
        .write(true)
        .append(append)
        .open(fp)
        .await
        .into_report()
        .change_context(JtraceError::IOError)
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
        .await
        .into_report()
        .change_context(JtraceError::IOError)
        .attach_printable(format!("Failed write {} to {}", ns, f))?;

    writer
        .flush()
        .await
        .into_report()
        .change_context(JtraceError::IOError)
        .attach_printable(format!("Failed write {} to {}", ns, f))?;

    Ok(())
}

pub async fn trace_top_dir() -> Result<String, JtraceError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .open(Path::new("/proc/mounts"))
        .await
        .into_report()
        .change_context(JtraceError::IOError)?;

    let mut lines = BufReader::new(file).lines();

    while let Some(l) = &lines
        .next_line()
        .await
        .into_report()
        .change_context(JtraceError::IOError)?
    {
        let entries: Vec<&str> = l.split(' ').collect();
        if entries[0] != "debugfs" {
            continue;
        }

        let mut tracing_dir = String::from(entries[1]);
        tracing_dir.push_str("/tracing");

        return Ok(tracing_dir);
    }

    Err(JtraceError::InvalidData)
        .into_report()
        .attach_printable("trace_pipe not found")
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
