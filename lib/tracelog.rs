#[allow(unused)]
use {
    crate::{trace_top_dir, writeln_proc, writeln_str_file, JtraceError},
    error_stack::{Report, Result, ResultExt},
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

const DEFAULT_CHANNEL_SIZE: usize = 100;
const TERMINATION_TIMEOUT_MS: u64 = 300;
const TRACE_PIPE_PATH: &str = "/trace_pipe";

/// TraceLog provides async functionality to read and parse Linux trace_pipe output.
///
/// Expected trace format: `task_name-pid [cpu] flags timestamp: message`
/// Example: `systemd-1 [000] .N.. 12345.678901: some_trace_message`
pub struct TraceLog {
    thread_handler: Option<JoinHandle<Result<(), JtraceError>>>,
    receiver: Receiver<String>,
    ctrl_sender: Sender<bool>,
}

impl TraceLog {
    async fn read_oneline(
        sender: Sender<String>,
        mut reader: BufReader<File>,
        mut ctrl: Receiver<bool>,
    ) -> Result<(), JtraceError> {
        loop {
            let mut buf = String::new();

            tokio::select! {
                Ok(_) = reader.read_line(&mut buf) => {
                    sender.send(buf).await.map_err(|_| Report::new(JtraceError::IOError))?;
                },

                _ret = ctrl.recv() => {
                    jinfo!("Quit");
                    break;
                }

            }
        }

        Ok(())
    }
    /// Creates a new TraceLog instance that reads from the kernel's trace_pipe.
    ///
    /// Opens `/sys/kernel/debug/tracing/trace_pipe` and starts an async reader task.
    ///
    /// # Returns
    /// - `Ok(TraceLog)` on success
    /// - `Err(JtraceError::IOError)` if trace_pipe cannot be opened
    /// - `Err(JtraceError::InvalidData)` if trace_pipe not found
    pub async fn new() -> Result<Self, JtraceError> {
        let mut trace_pipe = trace_top_dir()?.to_string();
        trace_pipe.push_str(TRACE_PIPE_PATH);

        let trace_pipe_path = Path::new(&trace_pipe);
        if trace_pipe_path.is_file() {
            let file = File::open(trace_pipe_path)
                .await
                .map_err(|_| Report::new(JtraceError::IOError))?;
            let reader = BufReader::new(file);
            let (sender, receiver) = mpsc::channel::<String>(DEFAULT_CHANNEL_SIZE);
            let (ctrl_sender, ctrl_receiver) = mpsc::channel::<bool>(DEFAULT_CHANNEL_SIZE);

            let thread_handler =
                tokio::spawn(
                    async move { Self::read_oneline(sender, reader, ctrl_receiver).await },
                );

            return Ok(TraceLog {
                thread_handler: Some(thread_handler),
                receiver,
                ctrl_sender,
            });
        }

        Err(Report::new(JtraceError::InvalidData)).attach_printable("trace_pipe not found")
    }

    /// Reads the next raw trace line from the trace_pipe.
    ///
    /// # Returns
    /// - `Ok(String)` containing the raw trace line
    /// - `Err(JtraceError::IOError)` if no data available or channel closed
    pub async fn trace_print(&mut self) -> Result<String, JtraceError> {
        self.receiver
            .recv()
            .await
            .ok_or(Report::new(JtraceError::IOError))
            .attach_printable("No data")
    }

    /// Parses the next trace line into structured fields.
    ///
    /// Expects format: `task_name-pid [cpu] flags timestamp: message`
    ///
    /// # Returns
    /// A tuple containing: `(task_name, pid, cpu, flags, timestamp, message)`
    /// - `task_name`: Process/task name (String)
    /// - `pid`: Process ID (u32)
    /// - `cpu`: CPU number (u8)
    /// - `flags`: Trace flags (String)
    /// - `timestamp`: Timestamp in seconds (f32)
    /// - `message`: Trace message content (String)
    ///
    /// # Errors
    /// - `JtraceError::IOError` if trace terminated
    /// - `JtraceError::InvalidData` if parsing fails
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
            .ok_or(Report::new(JtraceError::IOError))
            .attach_printable("Trace terminated")?;

        let mut to_process = log.as_str();
        let original_line = log.clone();
        let mut splitter = to_process
            .find('[')
            .ok_or(Report::new(JtraceError::ParseFailed {
                line: original_line.clone(),
                position: 0,
            }))
            .attach_printable("Missing '[' in trace line")?;

        {
            let task_pid_str = &to_process[..splitter];
            jdebug!("task_pid_str: {}", task_pid_str);
            let splitter = task_pid_str
                .rfind('-')
                .ok_or(Report::new(JtraceError::ParseFailed {
                    line: original_line.clone(),
                    position: task_pid_str.len(),
                }))
                .attach_printable("Missing '-' separator between task and pid")?;
            task = String::from(task_pid_str[..splitter].trim());
            pid = task_pid_str[splitter + 1..]
                .trim()
                .parse()
                .map_err(|_| {
                    Report::new(JtraceError::ParseFailed {
                        line: original_line.clone(),
                        position: splitter + 1,
                    })
                })
                .attach_printable("Invalid PID format")?;
        }

        to_process = &to_process[splitter + 1..];
        jdebug!("log str: {}", to_process);
        splitter = to_process
            .find("] ")
            .ok_or(Report::new(JtraceError::ParseFailed {
                line: original_line.clone(),
                position: original_line.len() - to_process.len(),
            }))
            .attach_printable("Missing '] ' after CPU number")?;
        let cpu = to_process[..splitter]
            .parse()
            .map_err(|_| {
                Report::new(JtraceError::ParseFailed {
                    line: original_line.clone(),
                    position: original_line.len() - to_process.len(),
                })
            })
            .attach_printable("Invalid CPU number format")?;

        to_process = &to_process[splitter + 2..];
        splitter = to_process
            .find(' ')
            .ok_or(Report::new(JtraceError::ParseFailed {
                line: original_line.clone(),
                position: original_line.len() - to_process.len(),
            }))
            .attach_printable("Missing space after flags")?;
        let flag = String::from(to_process[..splitter].trim());

        to_process = &to_process[splitter + 1..];
        splitter = to_process
            .find(':')
            .ok_or(Report::new(JtraceError::ParseFailed {
                line: original_line.clone(),
                position: original_line.len() - to_process.len(),
            }))
            .attach_printable("Missing ':' after timestamp")?;
        let ts = to_process[..splitter]
            .trim()
            .parse()
            .map_err(|_| {
                Report::new(JtraceError::ParseFailed {
                    line: original_line.clone(),
                    position: original_line.len() - to_process.len(),
                })
            })
            .attach_printable("Invalid timestamp format")?;

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

    /// Terminates the trace reading task and cleans up resources.
    ///
    /// Sends a termination signal to the reader task and waits up to 300ms
    /// for graceful shutdown.
    pub async fn terminate(mut self) {
        if self.ctrl_sender.send(false).await.is_ok() {
            if let Some(handle) = self.thread_handler.take() {
                let _ = timeout(Duration::from_millis(TERMINATION_TIMEOUT_MS), handle).await;
            }
        }
    }
}
