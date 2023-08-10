#[allow(unused)]
use {
    error_stack::{IntoReport, Report, Result, ResultExt},
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
    SymbolAnalyzerError,
}

impl Display for JtraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (code, desc) = error_desc(self);
        write!(f, "{}({}).", code, desc)
    }
}

impl std::error::Error for JtraceError {}

pub fn error_desc(error: &JtraceError) -> (i32, &'static str) {
    match error {
        JtraceError::InvalidData => (-1, "Invalid data"),
        JtraceError::IOError => (-2, "IO error"),
        JtraceError::SymbolAnalyzerError => (-3, "SymbolAnalyzer error"),
    }
}
