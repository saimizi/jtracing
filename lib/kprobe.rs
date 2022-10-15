//cspell:word Kprobe fname narg kprobes
#[allow(unused)]
use {
    crate::{writeln_proc, writeln_str_file},
    anyhow::{Context, Error, Result},
    jlogger::{jdebug, jerror, jinfo, jwarn, JloggerBuilder},
    log::{debug, error, info, warn, LevelFilter},
    rand::{thread_rng, Rng},
    std::{
        fmt::Display,
        path::{Path, PathBuf},
    },
    tokio::{
        fs::{self, File},
        io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        sync::mpsc::{self, Receiver, Sender},
        task::JoinHandle,
    },
};

pub struct Kprobe {
    group: String,
    fname: String,
    tracing_top: String,
    args: Vec<String>,
}

impl Kprobe {
    pub fn new(group: Option<&str>, fname: &str, tracing_dir: Option<&str>) -> Result<Self> {
        let group = group.map(String::from).unwrap_or_else(|| {
            let mut rng = rand::thread_rng();
            let i: u32 = rng.gen_range(0..1024);
            format!("probe{}_{}", i, fname)
        });
        let tracing_top = tracing_dir.unwrap_or("/sys/kernel/debug/tracing");

        let p = Path::new(tracing_top);
        if p.is_dir() {
            Ok(Kprobe {
                group,
                fname: String::from(fname),
                tracing_top: String::from(tracing_top),
                args: Vec::<String>::new(),
            })
        } else {
            Err(Error::msg("Tracing directory not found."))
        }
    }

    pub fn add_arg(&mut self, arg: &str) {
        self.args.push(String::from(arg));
    }

    pub async fn build(&self) -> Result<()> {
        let mut kprobe = format!("p:{} {}", self.group, self.fname);

        for arg in &self.args {
            let narg = format!(" {}", arg);
            kprobe.push_str(&narg);
        }

        let kprobe_events = format!("{}/kprobe_events", self.tracing_top);
        if let Ok(probes) = fs::read_to_string(&kprobe_events).await {
            let entry = format!("p:{}/{} {}", self.group, self.fname, self.fname);

            if probes.contains(&entry) {
                return Err(Error::msg(format!("{} kprobe already added", self.group)));
            }

            writeln_str_file(&kprobe_events, &kprobe, true).await?;
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        Ok(())
    }

    pub async fn enable(&self) -> Result<()> {
        let enable = format!("{}/events/kprobes/{}/enable", self.tracing_top, self.group);
        writeln_str_file(&enable, "1", false).await
    }

    pub async fn disable(&self) -> Result<()> {
        let enable = format!("{}/events/kprobes/{}/enable", self.tracing_top, self.group);
        writeln_str_file(&enable, "0", false).await
    }

    pub fn group(&self) -> &str {
        self.group.as_str()
    }

    pub async fn exit(self) {
        let kprobe_events = format!("{}/kprobe_events", self.tracing_top);

        if let Ok(probes) = fs::read_to_string(&kprobe_events).await {
            let mut entry = format!("p:kprobes/{} {}", self.group, self.fname);
            for arg in &self.args {
                let narg = format!(" {}", arg);
                entry.push_str(&narg);
            }

            if probes.contains(&entry) {
                self.disable().await.unwrap();
                let removed = probes.replace(&entry, "");
                if let Err(e) = writeln_str_file(&kprobe_events, &removed, false).await {
                    error!("Failed to disable kprobe {}: {}", self.group, e);
                }
            } else {
                warn!("No kprobe {} found.", self.group);
            }
        }
    }
}
