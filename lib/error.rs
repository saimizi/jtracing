#[allow(unused)]
use {
    error_stack::{Report, Result, ResultExt},
    jlogger_tracing::{
        jdebug, jerror, jinfo, jtrace, jwarn, JloggerBuilder, LevelFilter, LogTimeFormat,
    },
    libc::{c_char, c_void},
    std::{
        boxed::Box,
        ffi::{CStr, CString},
        fmt::Display,
        sync::atomic::{AtomicI32, Ordering},
    },
};

#[derive(Debug)]
pub enum JtraceError {
    InvalidData,
    IOError,
    BPFError,
    SymbolAnalyzerError,
    UnExpected,
    ParseFailed {
        line: String,
        position: usize,
    },
    // New symbol analyzer specific errors
    PermissionDenied {
        path: String,
    },
    InvalidDebugLink {
        file: String,
        debug_file: String,
    },
    SymbolCacheError {
        operation: String,
    },
    AddressOutOfRange {
        addr: u64,
        max_size: usize,
    },
    // Output-specific errors
    FileError {
        path: std::path::PathBuf,
        operation: String,
        source: String,
    },
    OutputError {
        message: String,
    },
}

impl Display for JtraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JtraceError::FileError {
                path,
                operation,
                source,
            } => {
                write!(
                    f,
                    "File operation '{}' failed for '{}': {}",
                    operation,
                    path.display(),
                    source
                )
            }
            JtraceError::OutputError { message } => {
                write!(f, "Output error: {}", message)
            }
            _ => {
                let (code, desc) = error_desc(self);
                write!(f, "{}({}).", code, desc)
            }
        }
    }
}

impl std::error::Error for JtraceError {}

pub fn error_desc(error: &JtraceError) -> (i32, &'static str) {
    match error {
        JtraceError::InvalidData => (-1, "Invalid data"),
        JtraceError::IOError => (-2, "IO error"),
        JtraceError::BPFError => (-3, "BPF error"),
        JtraceError::SymbolAnalyzerError => (-4, "SymbolAnalyzer error"),
        JtraceError::UnExpected => (-5, "UnExpected error"),
        JtraceError::ParseFailed { .. } => (-6, "Parse failed"),
        JtraceError::PermissionDenied { .. } => (-7, "Permission denied"),
        JtraceError::InvalidDebugLink { .. } => (-8, "Invalid debug link"),
        JtraceError::SymbolCacheError { .. } => (-9, "Symbol cache error"),
        JtraceError::AddressOutOfRange { .. } => (-10, "Address out of range"),
        JtraceError::FileError { .. } => (-11, "File operation error"),
        JtraceError::OutputError { .. } => (-12, "Output error"),
    }
}
