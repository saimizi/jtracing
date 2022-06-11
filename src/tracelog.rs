#[allow(unused)]
use {
    crate::{trace_top_dir, writeln_str_file},
    anyhow::{Error, Result},
    jlogger::{jdebug, jerror, jinfo, jwarn, JloggerBuilder},
    log::{debug, error, info, warn, LevelFilter},
    std::path::Path,
    tokio::{
        fs::File,
        io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, BufReader},
        sync::mpsc::{self, Receiver, Sender},
        task::JoinHandle,
    },
};

pub struct TraceLog {
    thread_handler: Option<JoinHandle<Result<()>>>,
    receiver: Receiver<String>,
    ctrl_sender: Sender<bool>,
}

async fn read_oneline(
    sender: Sender<String>,
    mut reader: BufReader<File>,
    mut ctrl: Receiver<bool>,
) -> Result<()> {
    loop {
        let mut buf = String::new();

        tokio::select! {
            Ok(_) = reader.read_line(&mut buf) => {
                sender.send(buf).await?;
            },

            _ret = ctrl.recv() => {
                break;
            }

        }
    }

    Ok(())
}

impl TraceLog {
    pub async fn new() -> Result<Self> {
        let mut trace_pipe = trace_top_dir().await?;
        trace_pipe.push_str("/trace_pipe");

        let trace_pipe_path = Path::new(&trace_pipe);
        if trace_pipe_path.is_file() {
            let file = File::open(trace_pipe_path).await?;
            let reader = BufReader::new(file);
            let (sender, receiver) = mpsc::channel::<String>(100);
            let (ctrl_sender, ctrl_receiver) = mpsc::channel::<bool>(100);

            let thread_handler =
                tokio::spawn(async move { read_oneline(sender, reader, ctrl_receiver).await });

            return Ok(TraceLog {
                thread_handler: Some(thread_handler),
                receiver,
                ctrl_sender,
            });
        }

        Err(Error::msg("trace_pipe not found"))
    }

    pub async fn trace_print(&mut self) -> Result<String> {
        let log = self
            .receiver
            .recv()
            .await
            .ok_or_else(|| Error::msg("nodata"))?;
        Ok(log)
    }

    pub async fn trace_fields(&mut self) -> Result<(String, u32, u8, String, f32, String)> {
        let mut task = String::new();
        let mut pid = u32::MAX;
        let mut cpu = u8::MAX;
        let mut flag = String::new();
        let mut msg = String::new();
        let mut ts = 0_f32;

        let log = self
            .receiver
            .recv()
            .await
            .ok_or_else(|| Error::msg("Trace terminated"))?;

        let entries = log.split(' ').collect::<Vec<&str>>().into_iter();

        for (_i, t) in entries.enumerate() {
            if t.trim().is_empty() {
                continue;
            }

            if task.is_empty() {
                let p = t.rfind('-').unwrap();
                task = t[0..p].to_string();
                pid = t[p + 1..]
                    .parse()
                    .map_err(|e| Error::msg(format!("{}", e)))?;
                continue;
            }

            if cpu == u8::MAX {
                cpu = t
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse()
                    .map_err(|e| Error::msg(format!("{}", e)))?;
                continue;
            }

            if flag.is_empty() {
                flag = t.to_string();
                continue;
            }

            if ts == 0_f32 {
                ts = t
                    .trim_end_matches(':')
                    .parse()
                    .map_err(|e| Error::msg(format!("{}", e)))?;
                continue;
            }

            if !msg.is_empty() {
                msg.push(' ');
            }
            msg.push_str(t);
            
        }

        Ok((
            task,
            pid,
            cpu,
            flag,
            ts,
            msg.trim_start_matches("0:")
                .trim_end_matches('\n')
                .trim()
                .to_owned(),
        ))
    }

    pub async fn terminate(mut self) {
        if self.ctrl_sender.send(false).await.is_ok() {
            if let Some(handle) = self.thread_handler.take() {
                let _ = handle.await;
            }
        }
    }
}
