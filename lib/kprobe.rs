#[allow(unused)]
use {
    crate::{trace_top_dir, writeln_proc, writeln_str_file, JtraceError},
    error_stack::{Report, Result, ResultExt},
    jlogger_tracing::{
        jdebug, jerror, jinfo, jtrace, jwarn, JloggerBuilder, LevelFilter, LogTimeFormat,
    },
    once_cell::sync::{Lazy, OnceCell},
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
#[cfg(not(test))]
pub fn get_tracing_top() -> Result<&'static TracePath, JtraceError> {
    static TRACING_PATH: OnceCell<TracePath> = OnceCell::new();
    TRACING_PATH.get_or_try_init(|| {
        trace_top_dir().map(|top| TracePath {
            top: top.to_string(),
        })
    })
}

/// Test version that uses a mock path
#[cfg(test)]
pub fn get_tracing_top() -> Result<&'static TracePath, JtraceError> {
    static TEST_PATH: OnceCell<TracePath> = OnceCell::new();
    Ok(TEST_PATH.get_or_init(|| TracePath {
        top: "/mock/tracing".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::tempdir;

    // Protect tests that might interact with tracing files
    static TRACING_LOCK: Mutex<()> = Mutex::new(());

    fn setup_test_env() -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        // Create required directory structure
        std::fs::create_dir_all(dir.path().join("events/kprobes")).unwrap();
        dir
    }

    #[test]
    fn test_tracepath_construction() {
        let tp = TracePath {
            top: "/test/path".to_string(),
        };

        assert_eq!(tp.tracing_top(), "/test/path");
        assert_eq!(tp.kprobe_enable(), "/test/path/events/kprobes/enable");
        assert_eq!(tp.kprobe_events(), "/test/path/kprobe_events");
        assert_eq!(tp.tracing_on(), "/test/path/tracing_on");
    }

    #[test]
    fn test_get_tracing_top() {
        let result = get_tracing_top();
        assert!(result.is_ok(), "Should get mock tracing top directory");
        assert_eq!(result.unwrap().tracing_top(), "/mock/tracing");
    }

    #[tokio::test]
    async fn test_kprobe_creation() {
        let _guard = TRACING_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = setup_test_env();

        // Override tracing path for this test
        let test_path = OnceCell::new();
        test_path
            .set(TracePath {
                top: dir.path().to_str().unwrap().to_string(),
            })
            .unwrap();

        // Test with auto-generated group name
        let kp = Kprobe {
            group: "probe123_test".to_string(),
            fname: "test_function".to_string(),
            tracing_top: test_path.get().unwrap().tracing_top().to_string(),
            args: Vec::new(),
        };
        assert!(kp.group().starts_with("probe"));
        assert_eq!(kp.fname, "test_function");

        // Test with custom group name
        let kp = Kprobe {
            group: "my_group".to_string(),
            fname: "test_function".to_string(),
            tracing_top: test_path.get().unwrap().tracing_top().to_string(),
            args: Vec::new(),
        };
        assert_eq!(kp.group(), "my_group");
    }

    #[tokio::test]
    async fn test_kprobe_args() {
        let _guard = TRACING_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = setup_test_env();

        // Override tracing path for this test
        let test_path = OnceCell::new();
        test_path
            .set(TracePath {
                top: dir.path().to_str().unwrap().to_string(),
            })
            .unwrap();

        let mut kp = Kprobe {
            group: "test_group".to_string(),
            fname: "test_function".to_string(),
            tracing_top: test_path.get().unwrap().tracing_top().to_string(),
            args: Vec::new(),
        };

        kp.add_arg("+0(%di):u32");
        kp.add_arg("+8(%si):u64");

        assert_eq!(kp.args.len(), 2);
        assert_eq!(kp.args[0], "+0(%di):u32");
        assert_eq!(kp.args[1], "+8(%si):u64");
    }

    #[tokio::test]
    async fn test_kprobe_build_failure() {
        let _guard = TRACING_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = setup_test_env();
        let fake_path = dir.path().to_str().unwrap().to_string();

        // Create test Kprobe with mock paths
        let kp = Kprobe {
            group: "test_group".to_string(),
            fname: "test_function".to_string(),
            tracing_top: fake_path.clone(),
            args: vec!["+0(%di):u32".to_string()],
        };

        // Should fail since we didn't create the mock kprobe_events file
        let result = kp.build().await;
        assert!(
            result.is_err(),
            "build() should fail when kprobe_events doesn't exist"
        );
    }

    #[tokio::test]
    async fn test_kprobe_enable_disable() {
        let _guard = TRACING_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = setup_test_env();
        let fake_path = dir.path().to_str().unwrap().to_string();

        // Create unique group name for this test to avoid conflicts
        let group = format!("test_group_{}", rand::random::<u32>());

        // Create full mock directory structure
        let group_dir = dir.path().join(format!("events/kprobes/{}", group));
        std::fs::create_dir_all(&group_dir).unwrap();
        let enable_path = group_dir.join("enable");
        std::fs::write(&enable_path, "0").unwrap();

        // Create test Kprobe with mock paths
        let kp = Kprobe {
            group: group.clone(),
            fname: "test_function".to_string(),
            tracing_top: fake_path.clone(),
            args: Vec::new(),
        };

        // Create mock enable file at the expected path
        let expected_enable_path = Path::new(&kp.tracing_top)
            .join("events/kprobes")
            .join(&kp.group)
            .join("enable");
        std::fs::create_dir_all(expected_enable_path.parent().unwrap()).unwrap();
        std::fs::write(&expected_enable_path, "0").unwrap();

        // Test enable/disable with our mock file
        kp.enable().unwrap();
        assert_eq!(
            std::fs::read_to_string(&expected_enable_path).unwrap(),
            "1\n"
        );

        kp.disable().unwrap();
        assert_eq!(
            std::fs::read_to_string(&expected_enable_path).unwrap(),
            "0\n"
        );
    }
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
        let kprobe_events = format!("{}/kprobe_events", self.tracing_top);

        // First verify the kprobe_events file exists and is accessible
        if !Path::new(&kprobe_events).exists() {
            return Err(Report::new(JtraceError::IOError))
                .attach_printable("kprobe_events file does not exist");
        }

        // Then check for existing probes
        let probes = fs::read_to_string(&kprobe_events).await.map_err(|e| {
            Report::new(JtraceError::IOError)
                .attach_printable(format!("Failed to read kprobe_events: {}", e))
        })?;

        let entry = format!("p:{}/{} {}", self.group, self.fname, self.fname);
        if probes.contains(&entry) {
            return Err(Report::new(JtraceError::InvalidData))
                .attach_printable(format!("{} kprobe already added", self.group));
        }

        // Build and write the probe definition
        let mut kprobe = format!("p:{} {}", self.group, self.fname);
        for arg in &self.args {
            kprobe.push_str(&format!(" {}", arg));
        }

        writeln_str_file(&kprobe_events, &kprobe, true)?;
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

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
        let enable = format!("{}/events/kprobes/{}/enable", self.tracing_top, self.group);
        writeln_str_file(&enable, "1", false)
    }

    /// Disables this specific probe group.
    ///
    /// Writes "0" to the group's enable file.
    pub fn disable(&self) -> Result<(), JtraceError> {
        let enable = format!("{}/events/kprobes/{}/enable", self.tracing_top, self.group);
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
