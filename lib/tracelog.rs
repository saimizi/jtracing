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

/// Parses a trace line into structured fields.
///
/// Expects format: `task_name-pid [cpu] flags timestamp: message`
///
/// # Returns
/// A tuple containing: `(task_name, pid, cpu, flags, timestamp, message)`
///
/// # Errors
/// - `JtraceError::ParseFailed` with line and position context for parsing failures
pub fn parse_trace_line(line: &str) -> Result<(String, u32, u8, String, f32, String), JtraceError> {
    let original_line = line.to_string();
    let mut to_process = line;

    // Find the opening bracket for CPU
    let mut splitter = to_process
        .find('[')
        .ok_or(Report::new(JtraceError::ParseFailed {
            line: original_line.clone(),
            position: 0,
        }))
        .attach_printable("Missing '[' in trace line")?;

    // Parse task name and PID
    let task_pid_str = &to_process[..splitter];
    let task_pid_splitter = task_pid_str
        .rfind('-')
        .ok_or(Report::new(JtraceError::ParseFailed {
            line: original_line.clone(),
            position: task_pid_str.len(),
        }))
        .attach_printable("Missing '-' separator between task and pid")?;

    let task = String::from(task_pid_str[..task_pid_splitter].trim());
    let pid = task_pid_str[task_pid_splitter + 1..]
        .trim()
        .parse()
        .map_err(|_| {
            Report::new(JtraceError::ParseFailed {
                line: original_line.clone(),
                position: task_pid_splitter + 1,
            })
        })
        .attach_printable("Invalid PID format")?;

    // Parse CPU number
    to_process = &to_process[splitter + 1..];
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

    // Parse flags
    to_process = &to_process[splitter + 2..];
    splitter = to_process
        .find(' ')
        .ok_or(Report::new(JtraceError::ParseFailed {
            line: original_line.clone(),
            position: original_line.len() - to_process.len(),
        }))
        .attach_printable("Missing space after flags")?;

    let flags = String::from(to_process[..splitter].trim());

    // Parse timestamp
    to_process = &to_process[splitter + 1..];
    splitter = to_process
        .find(':')
        .ok_or(Report::new(JtraceError::ParseFailed {
            line: original_line.clone(),
            position: original_line.len() - to_process.len(),
        }))
        .attach_printable("Missing ':' after timestamp")?;

    let timestamp = to_process[..splitter]
        .trim()
        .parse()
        .map_err(|_| {
            Report::new(JtraceError::ParseFailed {
                line: original_line.clone(),
                position: original_line.len() - to_process.len(),
            })
        })
        .attach_printable("Invalid timestamp format")?;

    // Extract message
    to_process = &to_process[splitter + 1..];
    let message = to_process
        .trim_end_matches('\n')
        .trim()
        .trim_start_matches("0:")
        .to_owned();

    Ok((task, pid, cpu, flags, timestamp, message))
}

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
        let log = self
            .receiver
            .recv()
            .await
            .ok_or(Report::new(JtraceError::IOError))
            .attach_printable("Trace terminated")?;

        parse_trace_line(&log)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_trace_line_valid() {
        let line = "systemd-1 [000] .N.. 12345.678901: some_trace_message";
        let result = parse_trace_line(line).unwrap();

        assert_eq!(result.0, "systemd"); // task name
        assert_eq!(result.1, 1); // pid
        assert_eq!(result.2, 0); // cpu
        assert_eq!(result.3, ".N.."); // flags
        assert_eq!(result.4, 12345.678901); // timestamp
        assert_eq!(result.5, "some_trace_message"); // message
    }

    #[test]
    fn test_parse_trace_line_complex_task_name() {
        let line = "kworker/0:2-events-123 [002] .... 98765.432100: worker_task_executed";
        let result = parse_trace_line(line).unwrap();

        assert_eq!(result.0, "kworker/0:2-events"); // task name with dashes
        assert_eq!(result.1, 123); // pid
        assert_eq!(result.2, 2); // cpu
        assert_eq!(result.3, "...."); // flags
        assert_eq!(result.4, 98765.432100); // timestamp
        assert_eq!(result.5, "worker_task_executed"); // message
    }

    #[test]
    fn test_parse_trace_line_with_message_prefix() {
        let line = "bash-1234 [001] d... 54321.123456: 0:trace_event_occurred\n";
        let result = parse_trace_line(line).unwrap();

        assert_eq!(result.0, "bash"); // task name
        assert_eq!(result.1, 1234); // pid
        assert_eq!(result.2, 1); // cpu
        assert_eq!(result.3, "d..."); // flags
        assert_eq!(result.4, 54321.123456); // timestamp
        assert_eq!(result.5, "trace_event_occurred"); // message (0: prefix removed, newline trimmed)
    }

    #[test]
    fn test_parse_trace_line_missing_bracket() {
        let line = "systemd-1 000] .N.. 12345.678901: some_trace_message";
        let result = parse_trace_line(line);

        assert!(result.is_err());
        if let Err(err) = result {
            if let JtraceError::ParseFailed {
                line: err_line,
                position,
            } = err.current_context()
            {
                assert_eq!(err_line, line);
                assert_eq!(*position, 0);
            } else {
                panic!("Expected ParseFailed error");
            }
        }
    }

    #[test]
    fn test_parse_trace_line_missing_dash() {
        let line = "systemd1 [000] .N.. 12345.678901: some_trace_message";
        let result = parse_trace_line(line);

        assert!(result.is_err());
        if let Err(err) = result {
            if let JtraceError::ParseFailed {
                line: err_line,
                position,
            } = err.current_context()
            {
                assert_eq!(err_line, line);
                assert_eq!(*position, 9); // length of "systemd1 " (including space)
            } else {
                panic!("Expected ParseFailed error");
            }
        }
    }

    #[test]
    fn test_parse_trace_line_invalid_pid() {
        let line = "systemd-abc [000] .N.. 12345.678901: some_trace_message";
        let result = parse_trace_line(line);

        assert!(result.is_err());
        if let Err(err) = result {
            if let JtraceError::ParseFailed {
                line: err_line,
                position,
            } = err.current_context()
            {
                assert_eq!(err_line, line);
                assert_eq!(*position, 8); // position after the dash
            } else {
                panic!("Expected ParseFailed error");
            }
        }
    }

    #[test]
    fn test_parse_trace_line_missing_closing_bracket() {
        let line = "systemd-1 [000 .N.. 12345.678901: some_trace_message";
        let result = parse_trace_line(line);

        assert!(result.is_err());
        if let Err(err) = result {
            if let JtraceError::ParseFailed { .. } = err.current_context() {
                // Should fail when looking for "] "
            } else {
                panic!("Expected ParseFailed error");
            }
        }
    }

    #[test]
    fn test_parse_trace_line_invalid_cpu() {
        let line = "systemd-1 [abc] .N.. 12345.678901: some_trace_message";
        let result = parse_trace_line(line);

        assert!(result.is_err());
        if let Err(err) = result {
            if let JtraceError::ParseFailed { .. } = err.current_context() {
                // Should fail when parsing CPU number
            } else {
                panic!("Expected ParseFailed error");
            }
        }
    }

    #[test]
    fn test_parse_trace_line_missing_space_after_flags() {
        let line = "systemd-1 [000] .N..12345.678901: some_trace_message";
        let result = parse_trace_line(line);

        assert!(result.is_err());
        if let Err(err) = result {
            if let JtraceError::ParseFailed { .. } = err.current_context() {
                // Should fail when looking for space after flags
            } else {
                panic!("Expected ParseFailed error");
            }
        }
    }

    #[test]
    fn test_parse_trace_line_missing_colon() {
        let line = "systemd-1 [000] .N.. 12345.678901 some_trace_message";
        let result = parse_trace_line(line);

        assert!(result.is_err());
        if let Err(err) = result {
            if let JtraceError::ParseFailed { .. } = err.current_context() {
                // Should fail when looking for ':'
            } else {
                panic!("Expected ParseFailed error");
            }
        }
    }

    #[test]
    fn test_parse_trace_line_invalid_timestamp() {
        let line = "systemd-1 [000] .N.. abc.def: some_trace_message";
        let result = parse_trace_line(line);

        assert!(result.is_err());
        if let Err(err) = result {
            if let JtraceError::ParseFailed { .. } = err.current_context() {
                // Should fail when parsing timestamp
            } else {
                panic!("Expected ParseFailed error");
            }
        }
    }

    #[test]
    fn test_parse_trace_line_empty_message() {
        let line = "systemd-1 [000] .N.. 12345.678901: ";
        let result = parse_trace_line(line).unwrap();

        assert_eq!(result.0, "systemd");
        assert_eq!(result.1, 1);
        assert_eq!(result.2, 0);
        assert_eq!(result.3, ".N..");
        assert_eq!(result.4, 12345.678901);
        assert_eq!(result.5, ""); // empty message
    }

    #[test]
    fn test_parse_trace_line_whitespace_handling() {
        let line = "systemd-1 [000] .N.. 12345.678901:   some_trace_message  ";
        let result = parse_trace_line(line).unwrap();

        assert_eq!(result.0, "systemd"); // task name trimmed
        assert_eq!(result.1, 1);
        assert_eq!(result.2, 0);
        assert_eq!(result.3, ".N.."); // flags trimmed
        assert_eq!(result.4, 12345.678901); // timestamp trimmed
        assert_eq!(result.5, "some_trace_message"); // message trimmed
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_CHANNEL_SIZE, 100);
        assert_eq!(TERMINATION_TIMEOUT_MS, 300);
        assert_eq!(TRACE_PIPE_PATH, "/trace_pipe");
    }
}
