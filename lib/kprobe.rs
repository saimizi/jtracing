use error_stack::IntoReport;

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

pub fn get_tracing_top() -> Result<&'static TracePath, JtraceError> {
    static TRACING_PATH: AtomicPtr<TracePath> = AtomicPtr::new(std::ptr::null_mut());

    let mut tp = TRACING_PATH.load(Ordering::Acquire);

    if tp == std::ptr::null_mut() {
        tp = Box::into_raw(Box::new(TracePath {
            top: trace_top_dir()?.to_string(),
        }));

        TRACING_PATH.store(tp, Ordering::Release);
    }

    Ok(unsafe { &*tp })
}

pub struct TracePath {
    top: String,
}

impl TracePath {
    pub fn tracing_top(&self) -> &str {
        &self.top
    }

    pub fn kprobe_enable(&self) -> String {
        format!("{}/events/kprobes/enable", self.top)
    }

    pub fn kprobe_events(&self) -> String {
        format!("{}/kprobe_events", self.top)
    }

    pub fn tracing_on(&self) -> String {
        format!("{}/tracing_on", self.top)
    }
}

pub struct Kprobe {
    group: String,
    fname: String,
    tracing_top: String,
    args: Vec<String>,
}

impl Kprobe {
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
            Err(JtraceError::InvalidData)
                .into_report()
                .attach_printable("Tracing directory not found.")
        }
    }

    pub fn add_arg(&mut self, arg: &str) {
        self.args.push(String::from(arg));
    }

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
                return Err(JtraceError::InvalidData)
                    .into_report()
                    .attach_printable(format!("{} kprobe already added", self.group));
            }

            writeln_str_file(&kprobe_events, &kprobe, true)?;
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        Ok(())
    }

    pub fn tracing_start() -> Result<(), JtraceError> {
        writeln_str_file(&get_tracing_top()?.kprobe_enable(), "1", false)?;
        writeln_str_file(&get_tracing_top()?.tracing_on(), "1", false)
    }

    pub fn tracing_stop() -> Result<(), JtraceError> {
        writeln_str_file(&get_tracing_top()?.tracing_on(), "0", false)?;
        writeln_str_file(&get_tracing_top()?.kprobe_enable(), "0", false)
    }

    pub fn clear_kprobe_event() -> Result<(), JtraceError> {
        writeln_str_file(&get_tracing_top()?.kprobe_events(), "", false)
    }

    pub fn enable(&self) -> Result<(), JtraceError> {
        let enable = format!(
            "{}/events/kprobes/{}/enable",
            get_tracing_top()?.tracing_top(),
            self.group
        );
        writeln_str_file(&enable, "1", false)
    }

    pub fn disable(&self) -> Result<(), JtraceError> {
        let enable = format!(
            "{}/events/kprobes/{}/enable",
            get_tracing_top()?.tracing_top(),
            self.group
        );
        writeln_str_file(&enable, "0", false)
    }

    pub fn group(&self) -> &str {
        self.group.as_str()
    }

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
