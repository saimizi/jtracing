use error_stack::IntoReport;

#[allow(unused)]
use {
    crate::{writeln_proc, writeln_str_file, JtraceError},
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

static TRACING_TOP: Lazy<AtomicPtr<TracePath>> = Lazy::new(|| {
    let tp = Box::into_raw(Box::new(TracePath {
        top: String::from("/sys/kernel/debug/tracing"),
    }));

    AtomicPtr::new(tp)
});

pub fn set_tracing_top(top: &str) {
    let tp = Box::into_raw(Box::new(TracePath {
        top: top.to_string(),
    }));

    let old = TRACING_TOP.swap(tp, Ordering::Release);
    drop(unsafe { Box::from_raw(old) })
}

pub fn get_tracing_top() -> &'static TracePath {
    let tp = TRACING_TOP.load(Ordering::Acquire);
    unsafe { &*tp }
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

        let tracing_top = get_tracing_top().tracing_top();

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

            writeln_str_file(&kprobe_events, &kprobe, true).await?;
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        Ok(())
    }

    pub async fn tracing_start() -> Result<(), JtraceError> {
        writeln_str_file(&get_tracing_top().kprobe_enable(), "1", false).await?;
        writeln_str_file(&get_tracing_top().tracing_on(), "1", false).await
    }

    pub async fn tracing_stop() -> Result<(), JtraceError> {
        writeln_str_file(&get_tracing_top().tracing_on(), "0", false).await?;
        writeln_str_file(&get_tracing_top().kprobe_enable(), "0", false).await
    }

    pub async fn clear_kprobe_event() -> Result<(), JtraceError> {
        writeln_str_file(&get_tracing_top().kprobe_events(), "", false).await
    }

    pub async fn enable(&self) -> Result<(), JtraceError> {
        let enable = format!(
            "{}/events/kprobes/{}/enable",
            get_tracing_top().tracing_top(),
            self.group
        );
        writeln_str_file(&enable, "1", false).await
    }

    pub async fn disable(&self) -> Result<(), JtraceError> {
        let enable = format!(
            "{}/events/kprobes/{}/enable",
            get_tracing_top().tracing_top(),
            self.group
        );
        writeln_str_file(&enable, "0", false).await
    }

    pub fn group(&self) -> &str {
        self.group.as_str()
    }

    pub async fn exit(self) {
        let kprobe_events = format!("{}/kprobe_events", get_tracing_top().tracing_top());

        if let Ok(probes) = fs::read_to_string(&kprobe_events).await {
            let mut entry = format!("p:kprobes/{} {}", self.group, self.fname);
            for arg in &self.args {
                let s = format!(" {}", arg);
                entry.push_str(&s);
            }

            if probes.contains(&entry) {
                self.disable().await.unwrap();
                if let Err(e) = writeln_str_file(&kprobe_events, "", false).await {
                    jerror!("Failed to disable kprobe {}: {:?}", self.group, e);
                }
            } else {
                jwarn!("No kprobe {} found.", self.group);
            }
        }
    }
}
