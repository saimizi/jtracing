//cspell:word oneline errlog tsplitter rfind
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
            .ok_or_else(|| Error::msg("no data"))?;
        Ok(log)
    }

    pub async fn trace_fields(&mut self) -> Result<(String, u32, u8, String, f32, String)> {
        let task;
        let pid;
        let mut msg = String::new();

        let log = self
            .receiver
            .recv()
            .await
            .ok_or_else(|| Error::msg("Trace terminated"))?;

        let mut to_process = log.as_str();
        let errlog = || Error::msg(format!("Invalid log string : {}", &log));
        let mut splitter = to_process.find('[').ok_or_else(errlog)?;

        {
            let task_pid_str = &to_process[..splitter];
            jdebug!("task_pid_str: {}", task_pid_str);
            let tsplitter = task_pid_str.rfind('-').ok_or_else(errlog)?;
            task = String::from(task_pid_str[..tsplitter].trim());
            pid = task_pid_str[tsplitter + 1..].trim().parse()?;
        }

        to_process = &to_process[splitter + 1..];
        jdebug!("log str: {}", to_process);
        splitter = to_process.find("] ").ok_or_else(errlog)?;
        let cpu = to_process[..splitter].parse()?;

        to_process = &to_process[splitter + 2..];
        splitter = to_process.find(' ').ok_or_else(errlog)?;
        let flag = String::from(to_process[..splitter].trim());

        to_process = &to_process[splitter + 1..];
        splitter = to_process.find(':').ok_or_else(errlog)?;
        let ts = to_process[..splitter].trim().parse()?;

        to_process = &to_process[splitter + 1..];
        msg.push_str(to_process.trim());

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
