#[allow(unused)]
use {
    crate::{trace_top_dir, writeln_proc, writeln_str_file, JtraceError},
    error_stack::{IntoReport, Report, Result, ResultExt},
    jlogger_tracing::{
        jdebug, jerror, jinfo, jtrace, jwarn, JloggerBuilder, LevelFilter, LogTimeFormat,
    },
    std::path::Path,
    tokio::{
        fs::File,
        io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, BufReader},
        sync::mpsc::{self, Receiver, Sender},
        task::JoinHandle,
        time::{timeout, Duration, Instant},
    },
};

pub struct TraceLog {
    thread_handler: Option<JoinHandle<Result<(), JtraceError>>>,
    receiver: Receiver<String>,
    ctrl_sender: Sender<bool>,
}

async fn read_oneline(
    sender: Sender<String>,
    mut reader: BufReader<File>,
    mut ctrl: Receiver<bool>,
) -> Result<(), JtraceError> {
    loop {
        let mut buf = String::new();

        tokio::select! {
            Ok(_) = reader.read_line(&mut buf) => {
                sender.send(buf).await.into_report().change_context(JtraceError::IOError)?;
            },

            _ret = ctrl.recv() => {
                jinfo!("Quit");
                break;
            }

        }
    }

    Ok(())
}

impl TraceLog {
    pub async fn new() -> Result<Self, JtraceError> {
        let mut trace_pipe = trace_top_dir().await?;
        trace_pipe.push_str("/trace_pipe");

        let trace_pipe_path = Path::new(&trace_pipe);
        if trace_pipe_path.is_file() {
            let file = File::open(trace_pipe_path)
                .await
                .into_report()
                .change_context(JtraceError::IOError)?;
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

        Err(JtraceError::InvalidData)
            .into_report()
            .attach_printable("trace_pipe not found")
    }

    pub async fn trace_print(&mut self) -> Result<String, JtraceError> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| JtraceError::IOError)
            .into_report()
            .attach_printable("No data")
    }

    pub async fn trace_fields(
        &mut self,
    ) -> Result<(String, u32, u8, String, f32, String), JtraceError> {
        let task;
        let pid;
        let mut msg = String::new();

        let log = self
            .receiver
            .recv()
            .await
            .ok_or_else(|| JtraceError::IOError)
            .into_report()
            .attach_printable("Trace terminated")?;

        let mut to_process = log.as_str();
        let err_log = format!("Invalid log string : {}", &log);
        let mut splitter = to_process
            .find('[')
            .ok_or_else(|| JtraceError::InvalidData)
            .into_report()
            .attach_printable(err_log.clone())?;

        {
            let task_pid_str = &to_process[..splitter];
            jdebug!("task_pid_str: {}", task_pid_str);
            let splitter = task_pid_str
                .rfind('-')
                .ok_or_else(|| JtraceError::InvalidData)
                .into_report()
                .attach_printable(err_log.clone())?;
            task = String::from(task_pid_str[..splitter].trim());
            pid = task_pid_str[splitter + 1..]
                .trim()
                .parse()
                .into_report()
                .change_context(JtraceError::InvalidData)
                .attach_printable(err_log.clone())?;
        }

        to_process = &to_process[splitter + 1..];
        jdebug!("log str: {}", to_process);
        splitter = to_process
            .find("] ")
            .ok_or_else(|| JtraceError::InvalidData)
            .into_report()
            .attach_printable(err_log.clone())?;
        let cpu = to_process[..splitter]
            .parse()
            .into_report()
            .change_context(JtraceError::InvalidData)
            .attach_printable(err_log.clone())?;

        to_process = &to_process[splitter + 2..];
        splitter = to_process
            .find(' ')
            .ok_or_else(|| JtraceError::InvalidData)
            .into_report()
            .attach_printable(err_log.clone())?;
        let flag = String::from(to_process[..splitter].trim());

        to_process = &to_process[splitter + 1..];
        splitter = to_process
            .find(':')
            .ok_or_else(|| JtraceError::InvalidData)
            .into_report()
            .attach_printable(err_log.clone())?;
        let ts = to_process[..splitter]
            .trim()
            .parse()
            .into_report()
            .change_context(JtraceError::InvalidData)
            .attach_printable(err_log.clone())?;

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
                let _ = timeout(Duration::from_millis(300), handle).await;
            }
        }
    }
}
