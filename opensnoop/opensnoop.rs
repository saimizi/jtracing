#[allow(unused)]
use {
    clap::Parser,
    error_stack::{Report, Result, ResultExt},
    jlogger_tracing::{
        jdebug, jerror, jinfo, jtrace, jwarn, JloggerBuilder, LevelFilter, LogTimeFormat,
    },
    std::{
        fmt::Display,
        fs,
        path::{Path, PathBuf},
    },
    tokio::{
        fs::File,
        io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, BufReader},
        signal,
        sync::mpsc::{self, Receiver, Sender},
        sync::oneshot,
        task::JoinHandle,
        time::{timeout, Duration, Instant},
    },
    tracelib::{trace_top_dir, writeln_str_file, JtraceError, Kprobe, TraceLog},
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Trace duration in seconds
    #[clap(short = 'd', long = "duration")]
    duration: Option<u64>,

    /// Trace PID
    #[clap(short = 'p', long = "pid")]
    pid: Option<u32>,

    /// Trace COMMAND
    #[clap(short = 'c', long = "command")]
    command: Option<String>,

    #[clap(short, long, action=clap::ArgAction::Count)]
    verbose: u8,
}

async fn wait_to_finish(start: Instant, duration_s: Option<u64>) -> Result<(), JtraceError> {
    let wait_ctrc = signal::ctrl_c();

    if let Some(s) = duration_s {
        let to = Duration::from_secs(s) - start.elapsed();
        if !to.is_zero() {
            timeout(to, wait_ctrc)
                .await
                .map_err(|_| Report::new(JtraceError::IOError))?
                .map_err(|_| Report::new(JtraceError::IOError))
        } else {
            Ok(())
        }
    } else {
        signal::ctrl_c()
            .await
            .map_err(|_| Report::new(JtraceError::IOError))
    }
}

async fn async_main() -> Result<(), JtraceError> {
    let cli = Cli::parse();

    let max_level = match cli.verbose {
        0 => LevelFilter::INFO,
        1 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    JloggerBuilder::new()
        .max_level(max_level)
        .log_runtime(false)
        .build();

    let mut duration = None;
    if let Some(d) = cli.duration {
        duration = Some(d);
    }

    if let Some(p) = cli.pid {
        jinfo!("Tracing PID {} ...", p);
    }

    if let Some(ref c) = cli.command {
        jinfo!("Tracing command {} ...", c);
    }

    let current_tracer = format!("{}/current_tracer", trace_top_dir()?);

    writeln_str_file(&current_tracer, "nop", false)?;

    let fns = vec!["do_sys_open", "do_sys_openat2"];
    let mut probes = vec![];
    for fname in fns {
        jinfo!("Setup tracing for {}", fname);
        if let Ok(mut kp) = Kprobe::new(None, fname) {
            kp.add_arg("file=+0($arg2):string");
            kp.add_arg("flag=+0($arg3):x32");
            kp.add_arg("mode=+0($arg4):x32");
            kp.build().await?;
            kp.enable()?;

            probes.push(kp);
        }
    }

    let mut tlog = TraceLog::new().await?;

    println!();
    println!(
        "{:<12} {:15} {:<8} {:<30}",
        "TimeStamp", "Task", "PID", "OpenedFile"
    );
    println!("{}", "=".repeat(80));

    let start = tokio::time::Instant::now();
    Kprobe::tracing_start()?;
    loop {
        tokio::select! {
            //Ok(log) = tlog.trace_print() => print!("{}", log),
             result = tlog.trace_fields() => {
                 match result {
                    Ok((task, pid, _cpu, _flag, ts, msg)) => {
                        #[allow(clippy::never_loop)]
                        loop {
                            let mut fname = String::new();
                            let mut flag = String::new();
                            let mut mode = String::new();
                            let mut iter = msg.split(' ').collect::<Vec<&str>>().into_iter();
                            iter.next();
                            iter.next();

                            if let Some(s) = iter.next() {
                                fname.push_str(s);
                            } else {
                                break;
                            }

                            if let Some(s) = iter.next() {
                                flag.push_str(s);
                            } else {
                                break;
                            }

                            if let Some(s) = iter.next() {
                                mode.push_str(s);
                            } else {
                                break;
                            }

                            if let Some(tpid) = cli.pid {
                                if tpid != pid {
                                    break;
                                }
                            }

                            if let Some(ref c) = cli.command {
                                if task.len() >= 15 {
                                    if !c.starts_with(&task) {
                                        break;
                                    }
                                } else if c != &task {
                                        break;
                                }
                            }

                            println!("{:<12} {:15} {:<8} {:<30}",ts, task, pid, fname);
                            break;
                        }

                    },
                    Err(e) => eprintln!("Error: {}", e),
                 }
            },
            _result = wait_to_finish(start, duration) => {
                Kprobe::tracing_stop()?;
                Kprobe::clear_kprobe_event()?;
                break;
            },

        }
    }

    tlog.terminate().await;

    Ok(())
}

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        if let Err(e) = async_main().await {
            jerror!("Error: {:?}", e);
        }
    });

    rt.shutdown_background();
}
