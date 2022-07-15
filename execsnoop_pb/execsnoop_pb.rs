#[allow(unused)]
use {
    anyhow::{Context, Error, Result},
    jlogger::{jdebug, jerror, jinfo, jwarn, JloggerBuilder},
    log::{debug, error, info, warn},
};

use {
    clap::Parser,
    libbpf_rs::{set_print, PerfBufferBuilder, PrintLevel},
    plain::Plain,
    std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    tracelib::{bump_memlock_rlimit, bytes_to_string},
};

#[path = "bpf/execsnoop_pb.skel.rs"]
mod execsnoop_pb;
use execsnoop_pb::*;

fn print_to_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => log::debug!("{}", msg),
        PrintLevel::Info => log::info!("{}", msg),
        PrintLevel::Warn => log::warn!("{}", msg),
    }
}

#[derive(Parser, Debug)]
struct Cli {
    ///Trace process lives at least <DURATION> ms.
    #[clap(short, default_value_t = 0_u64)]
    duration: u64,

    ///Verbose
    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,

    ///Use timestamp instead of date time.
    #[clap(short = 't', long)]
    timestamp: bool,

    ///Show fork() trace.
    #[clap(short = 'f', long)]
    fork_info: bool,
}

type Event = execsnoop_pb_bss_types::event;
unsafe impl Plain for Event {}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let max_level = match cli.verbose {
        0 => log::LevelFilter::Off,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Off,
    };

    JloggerBuilder::new()
        .max_level(max_level)
        .log_time(false)
        .log_runtime(false)
        .build();

    bump_memlock_rlimit();

    let skel_builder = ExecsnoopPbSkelBuilder::default();
    set_print(Some((PrintLevel::Debug, print_to_log)));

    let mut open_skel = skel_builder.open().with_context(|| "Failed to open bpf.")?;

    open_skel.rodata().min_duration_ns = cli.duration * 1000000_u64;

    let mut skel = open_skel.load().with_context(|| "Faild to load bpf")?;

    let start = chrono::Local::now();
    let show_timestamp = cli.timestamp;
    let handle_event = move |_cpu: i32, data: &[u8]| {
        let mut event = Event::default();
        plain::copy_from_bytes(&mut event, data).expect("Corrupted event data");

        let now = chrono::Local::now();
        let timestamp_us = (now.timestamp_nanos() - start.timestamp_nanos()) / 1000;

        let signals = "HUP INT QUIT ILL TRAP ABRT BUS FPE KILL USR1 SEGV USR2 PIPE ALRM TERM STKFLT CHLD CONT STOP TSTP TTIN TTOU URG XCPU XFSZ VTALRM PROF WINCH POLL PWR SYS"
            .split(' ').collect::<Vec<&str>>();

        if event.event_type == 1 {
            let signal_info = {
                if event.last_sig != -1 {
                    format!(
                        "[{}={} <- {}({})]",
                        signals[event.last_sig as usize - 1],
                        event.last_sig,
                        unsafe { bytes_to_string(event.last_sig_comm.as_ptr()) },
                        event.last_signal_pid
                    )
                } else {
                    String::new()
                }
            };

            let fork_info = {
                if event.flag & 0x1 == 0x1 {
                    unsafe { format!("[{}]", bytes_to_string(event.comm2.as_ptr())) }
                } else {
                    String::new()
                }
            };

            if show_timestamp {
                print!(
                    "{:<20.6}{:<7}{:<16}{:<8}{:<8}{:<8}[{}]{}{}",
                    timestamp_us as f64 / 1000000_f64,
                    "EXIT",
                    unsafe { bytes_to_string(event.comm.as_ptr()) },
                    event.tid,
                    event.pid,
                    event.ppid,
                    event.exit_code,
                    signal_info,
                    fork_info,
                );
            } else {
                print!(
                    "{:<20}{:<7}{:<16}{:<8}{:<8}{:<8}[{}]{}{}",
                    now.format("%Y-%m-%d %H:%M:%S"),
                    "EXIT",
                    unsafe { bytes_to_string(event.comm.as_ptr()) },
                    event.tid,
                    event.pid,
                    event.ppid,
                    event.exit_code,
                    signal_info,
                    fork_info
                );
            }

            if event.duration_ns > 0 {
                print!(" ({}ms)", event.duration_ns / 1000000_u64);
            }
            println!();
        } else if event.event_type == 0 {
            let arg0 = unsafe { bytes_to_string(event.arg0.as_ptr()) };
            let filename = unsafe { bytes_to_string(event.filename.as_ptr()) };
            let mut args = String::new();

            if !filename.is_empty() {
                args.push_str(&filename);
            } else {
                args.push_str(&arg0);
            }

            args.push(' ');
            args.push_str(unsafe { &bytes_to_string(event.arg1.as_ptr()) });
            args.push(' ');
            args.push_str(unsafe { &bytes_to_string(event.arg2.as_ptr()) });
            args.push(' ');
            args.push_str(unsafe { &bytes_to_string(event.arg3.as_ptr()) });
            args.push(' ');
            args.push_str(unsafe { &bytes_to_string(event.arg4.as_ptr()) });
            args.push(' ');
            args.push_str(unsafe { &bytes_to_string(event.arg5.as_ptr()) });

            let fork_info = {
                if event.flag & 0x1 == 0x1 {
                    unsafe { format!("[{}]", bytes_to_string(event.comm2.as_ptr())) }
                } else {
                    String::new()
                }
            };

            if show_timestamp {
                print!(
                    "{:<20.6}{:<7}{:<16}{:<8}{:<8}{:<8}{}: {}",
                    timestamp_us as f64 / 1000000_f64,
                    "EXEC",
                    unsafe { bytes_to_string(event.comm.as_ptr()) },
                    event.tid,
                    event.pid,
                    event.ppid,
                    fork_info,
                    args
                );
            } else {
                print!(
                    "{:<20}{:<7}{:<16}{:<8}{:<8}{:<8}{}: {}",
                    now.format("%Y-%m-%d %H:%M:%S"),
                    "EXEC",
                    unsafe { bytes_to_string(event.comm.as_ptr()) },
                    event.tid,
                    event.pid,
                    event.ppid,
                    fork_info,
                    args
                );
            }

            if event.duration_ns > 0 {
                print!(" ({}ms)", event.duration_ns / 1000000_u64);
            }
            println!();
        } else if event.event_type == 2 {
            if cli.fork_info {
                if show_timestamp {
                    print!(
                        "{:<20.6}{:<7}{:<16}{:<8}{:<8}{:<8}",
                        timestamp_us as f64 / 1000000_f64,
                        "FORK",
                        unsafe { bytes_to_string(event.comm.as_ptr()) },
                        event.tid,
                        event.pid,
                        event.ppid,
                    );
                } else {
                    print!(
                        "{:<20}{:<7}{:<16}{:<8}{:<8}{:<8}",
                        now.format("%Y-%m-%d %H:%M:%S"),
                        "FORK",
                        unsafe { bytes_to_string(event.comm.as_ptr()) },
                        event.tid,
                        event.pid,
                        event.ppid,
                    );
                }

                if event.duration_ns > 0 {
                    print!(" ({}ms)", event.duration_ns / 1000000_u64);
                }
                println!();
            };
        };
    };

    let perbuf = PerfBufferBuilder::new(skel.maps().pb())
        .sample_cb(handle_event)
        .pages(8) // 4k * 8 (pb map)
        .build()
        .with_context(|| "Failed to create perf buffer")?;

    skel.attach().with_context(|| "Faild to load bpf")?;

    println!(
        "{:<20}{:<7}{:<16}{:<8}{:<8}{:<8}FILENAME/EXIT CODE/FORK INFO",
        "TIME", "EVENT", "COMM", "TID", "PID", "PPID"
    );

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        // ctrl-c will fail perbuf.poll()
        let _ = perbuf.poll(std::time::Duration::from_millis(100));
    }

    Ok(())
}
