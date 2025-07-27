#[allow(unused)]
use {
    crate::{trace_top_dir, writeln_proc, writeln_str_file, JtraceError},
    error_stack::{Report, Result, ResultExt},
    jlogger_tracing::{
        jdebug, jerror, jinfo, jtrace, jwarn, JloggerBuilder, LevelFilter, LogTimeFormat,
    },
    once_cell::sync::Lazy,
    rand::{thread_rng, Rng},
    std::{
        fmt::Display,
        path::{Path, PathBuf},
        sync::atomic::{AtomicPtr, Ordering},
    },
    tokio::{
        fs::{self, File},
        io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        sync::mpsc::{self, Receiver, Sender},
        task::JoinHandle,
    },
};

/// Gets the global tracing directory path, initializing it if needed.
///
/// Uses atomic operations to safely initialize and share a static TracePath.
/// The path is derived from trace_top_dir() and cached for future calls.
///
/// Returns:
/// - Ok(&TracePath) on success
/// - Err(JtraceError) if tracing directory can't be determined
pub fn get_tracing_top() -> Result<&'static TracePath, JtraceError> {
    static TRACING_PATH: AtomicPtr<TracePath> = AtomicPtr::new(std::ptr::null_mut());

    let mut tp = TRACING_PATH.load(Ordering::Acquire);

    if tp.is_null() {
        tp = Box::into_raw(Box::new(TracePath {
            top: trace_top_dir()?.to_string(),
        }));

        TRACING_PATH.store(tp, Ordering::Release);
    }

    Ok(unsafe { &*tp })
}

/// Represents paths to key tracing subsystem files/directories.
///
/// Provides convenience methods to construct paths to:
/// - The tracing root directory
/// - kprobe control files
/// - Tracing enable/disable files
#[derive(Debug)]
pub struct TracePath {
    top: String,
}

impl TracePath {
    /// Gets the root tracing directory path (e.g. "/sys/kernel/debug/tracing")
    pub fn tracing_top(&self) -> &str {
        &self.top
    }

    /// Gets path to the kprobe enable control file
    pub fn kprobe_enable(&self) -> String {
        format!("{}/events/kprobes/enable", self.top)
    }

    /// Gets path to the kprobe events definition file
    pub fn kprobe_events(&self) -> String {
        format!("{}/kprobe_events", self.top)
    }

    /// Gets path to the global tracing enable/disable control file
    pub fn tracing_on(&self) -> String {
        format!("{}/tracing_on", self.top)
    }
}

/// Represents a kernel probe (kprobe) with its configuration.
///
/// Handles:
/// - Probe registration/unregistration
/// - Argument specification
/// - Enable/disable control
/// - Group management
#[derive(Debug)]
pub struct Kprobe {
    group: String,
    fname: String,
    tracing_top: String,
    args: Vec<String>,
}

impl Kprobe {
    /// Creates a new Kprobe instance.
    ///
    /// Parameters:
    /// - group: Optional probe group name (auto-generated if None)
    /// - fname: Function name to probe (e.g. "do_sys_open")
    ///
    /// Returns:
    /// - Ok(Kprobe) on success
    /// - Err(JtraceError::InvalidData) if tracing directory invalid
    pub fn new(group: Option<&str>, fname: &str) -> Result<Self, JtraceError> {
        let group = group.map(String::from).unwrap_or_else(|| {
            let mut rng = rand::thread_rng();
            let i: u32 = rng.gen_range(0..1024);
            format!("probe{}_{}", i, fname)
        });

        let tracing_top = get_tracing_top()?.tracing_top();

        let p = Path::new(tracing_top);
        if p.is_dir() {
            Ok(Kprobe {
                group,
                fname: String::from(fname),
                tracing_top: String::from(tracing_top),
                args: Vec::<String>::new(),
            })
        } else {
            Err(Report::new(JtraceError::InvalidData))
                .attach_printable("Tracing directory not found.")
        }
    }

    /// Adds an argument specification to the probe.
    ///
    /// Arguments follow kprobe syntax (e.g. "+0(%di):u32" for first argument as u32)
    pub fn add_arg(&mut self, arg: &str) {
        self.args.push(String::from(arg));
    }

    /// Registers the probe in the kernel by writing to kprobe_events.
    ///
    /// Checks for duplicate probes and adds a 1 second delay after registration.
    ///
    /// Returns:
    /// - Ok(()) on success
    /// - Err(JtraceError::InvalidData) if probe already exists
    /// - Err(JtraceError::IOError) on write failure
    pub async fn build(&self) -> Result<(), JtraceError> {
        let mut kprobe = format!("p:{} {}", self.group, self.fname);

        for arg in &self.args {
            let s = format!(" {}", arg);
            kprobe.push_str(&s);
        }

        let kprobe_events = format!("{}/kprobe_events", self.tracing_top);
        if let Ok(probes) = fs::read_to_string(&kprobe_events).await {
            let entry = format!("p:{}/{} {}", self.group, self.fname, self.fname);

            if probes.contains(&entry) {
                return Err(Report::new(JtraceError::InvalidData))
                    .attach_printable(format!("{} kprobe already added", self.group));
            }

            writeln_str_file(&kprobe_events, &kprobe, true)?;
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        Ok(())
    }

    /// Enables all tracing and kprobes globally.
    ///
    /// Writes "1" to both the kprobe enable and tracing_on files.
    pub fn tracing_start() -> Result<(), JtraceError> {
        writeln_str_file(&get_tracing_top()?.kprobe_enable(), "1", false)?;
        writeln_str_file(&get_tracing_top()?.tracing_on(), "1", false)
    }

    /// Disables all tracing and kprobes globally.
    ///
    /// Writes "0" to both the tracing_on and kprobe enable files.
    pub fn tracing_stop() -> Result<(), JtraceError> {
        writeln_str_file(&get_tracing_top()?.tracing_on(), "0", false)?;
        writeln_str_file(&get_tracing_top()?.kprobe_enable(), "0", false)
    }

    /// Clears all kprobe definitions by truncating kprobe_events.
    ///
    /// Note: This affects ALL kprobes system-wide.
    pub fn clear_kprobe_event() -> Result<(), JtraceError> {
        writeln_str_file(&get_tracing_top()?.kprobe_events(), "", false)
    }

    /// Enables this specific probe group.
    ///
    /// Writes "1" to the group's enable file.
    pub fn enable(&self) -> Result<(), JtraceError> {
        let enable = format!(
            "{}/events/kprobes/{}/enable",
            get_tracing_top()?.tracing_top(),
            self.group
        );
        writeln_str_file(&enable, "1", false)
    }

    /// Disables this specific probe group.
    ///
    /// Writes "0" to the group's enable file.
    pub fn disable(&self) -> Result<(), JtraceError> {
        let enable = format!(
            "{}/events/kprobes/{}/enable",
            get_tracing_top()?.tracing_top(),
            self.group
        );
        writeln_str_file(&enable, "0", false)
    }

    /// Gets this probe's group name.
    pub fn group(&self) -> &str {
        self.group.as_str()
    }

    /// Cleans up the probe by disabling and removing it.
    ///
    /// Automatically called when the probe is dropped.
    /// Logs warnings/errors through jlogger if cleanup fails.
    pub async fn exit(self) {
        let kprobe_events = format!("{}/kprobe_events", get_tracing_top().unwrap().tracing_top());

        if let Ok(probes) = fs::read_to_string(&kprobe_events).await {
            let mut entry = format!("p:kprobes/{} {}", self.group, self.fname);
            for arg in &self.args {
                let s = format!(" {}", arg);
                entry.push_str(&s);
            }

            if probes.contains(&entry) {
                self.disable().unwrap();
                if let Err(e) = writeln_str_file(&kprobe_events, "", false) {
                    jerror!("Failed to disable kprobe {}: {:?}", self.group, e);
                }
            } else {
                jwarn!("No kprobe {} found.", self.group);
            }
        }
    }
}
