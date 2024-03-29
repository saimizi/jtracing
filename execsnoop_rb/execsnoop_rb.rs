#[allow(unused)]
use {
    clap::Parser,
    error_stack::{Report, Result, ResultExt},
    jlogger_tracing::{
        jdebug, jerror, jinfo, jtrace, jwarn, JloggerBuilder, LevelFilter, LogTimeFormat,
    },
    libbpf_rs::{
        set_print,
        skel::{OpenSkel, Skel, SkelBuilder},
        PrintLevel, RingBufferBuilder,
    },
    plain::Plain,
    std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    tracelib::{bump_memlock_rlimit, bytes_to_string, JtraceError},
};

#[path = "bpf/execsnoop_rb.skel.rs"]
mod execsnoop_rb;
use execsnoop_rb::*;

fn print_to_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => jdebug!("{}", msg.trim_end_matches('\n')),
        PrintLevel::Info => jinfo!("{}", msg.trim_end_matches('\n')),
        PrintLevel::Warn => jwarn!("{}", msg.trim_end_matches('\n')),
    }
}

#[derive(Parser, Debug)]
struct Cli {
    ///Trace EXIT event for processes lives at least <DURATION> ms.
    #[clap(short, default_value_t = 0_u64)]
    duration: u64,

    ///Verbose
    #[clap(short, long, action=clap::ArgAction::Count)]
    verbose: usize,

    ///Use timestamp instead of date time.
    #[clap(short = 'r', long)]
    timestamp: bool,

    ///Show exec trace.
    ///This is default when no other event specified.
    #[clap(short = 'E', long)]
    exec_event: bool,

    ///Show fork trace.
    #[clap(short = 'f', long)]
    fork_event: bool,

    ///Show thread trace.
    #[clap(short = 't', long)]
    thread: bool,

    ///Show exit trace.
    #[clap(short = 'e', long)]
    exit_event: bool,

    ///show PPID info.
    #[clap(long)]
    ppid: bool,
}

type Event = execsnoop_rb_bss_types::event;
unsafe impl Plain for Event {}

fn main() -> Result<(), JtraceError> {
    let cli = Cli::parse();
    let max_level = match cli.verbose {
        0 => LevelFilter::OFF,
        1 => LevelFilter::ERROR,
        2 => LevelFilter::WARN,
        3 => LevelFilter::INFO,
        4 => LevelFilter::DEBUG,
        _ => LevelFilter::OFF,
    };

    JloggerBuilder::new()
        .max_level(max_level)
        .log_runtime(false)
        .build();

    bump_memlock_rlimit();

    let skel_builder = ExecsnoopRbSkelBuilder::default();
    set_print(Some((PrintLevel::Debug, print_to_log)));

    let mut open_skel = skel_builder
        .open()
        .map_err(|_| Report::new(JtraceError::IOError))
        .attach_printable("Failed to open bpf.")?;

    open_skel.rodata().min_duration_ns = cli.duration * 1000000_u64;

    let mut skel = open_skel
        .load()
        .map_err(|_| Report::new(JtraceError::IOError))
        .attach_printable("Failed to load bpf")?;

    let start = chrono::Local::now();
    let show_timestamp = cli.timestamp;
    let handle_event = move |data: &[u8]| -> i32 {
        let mut event = Event::default();
        plain::copy_from_bytes(&mut event, data).expect("Corrupted event data");

        let now = chrono::Local::now();
        let timestamp_us = (now.timestamp_nanos() - start.timestamp_nanos()) / 1000;

        let signals = "HUP INT QUIT ILL TRAP ABRT BUS FPE KILL USR1 SEGV USR2 PIPE ALRM TERM STKFLT CHLD CONT STOP TSTP TTIN TTOU URG XCPU XFSZ VTALRM PROF WINCH POLL PWR SYS"
            .split(' ').collect::<Vec<&str>>();

        let print_timestamp = || {
            if show_timestamp {
                print!("{:<10.6}", timestamp_us as f64 / 1000000_f64);
            } else {
                print!("{:<20}", now.format("%Y-%m-%d %H:%M:%S"));
            }
        };

        let print_mark = |mark: &str| {
            print!(" {:<7}", mark);
        };

        let print_comm = || {
            print!(" {:<16}", unsafe { bytes_to_string(event.comm.as_ptr()) });
        };

        let print_id = |id: i32| {
            print!(" {:<8}", id);
        };

        if event.event_type == 1 {
            if !cli.exit_event {
                return 0;
            }

            if !cli.thread && event.tid != event.pid {
                return 0;
            }
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

            print_timestamp();
            print_mark("EXIT");
            print_comm();
            if cli.thread {
                print_id(event.tid);
            }
            print_id(event.pid);
            if cli.ppid {
                print_id(event.ppid);
            }
            print!(" [{}]", event.exit_code);
            if !signal_info.is_empty() {
                print!(" {}", signal_info);
            }
            if !fork_info.is_empty() {
                print!(" {}", fork_info);
            }

            if event.duration_ns > 0 {
                print!(" ({}ms)", event.duration_ns / 1000000_u64);
            }
            println!();
        } else if event.event_type == 0 {
            if !cli.exec_event && (cli.fork_event || cli.exit_event) {
                return 0;
            }

            if !cli.thread && event.tid != event.pid {
                return 0;
            }

            let mut arg_parsed = vec![];

            let mut parsed_cnt = 0;
            let mut index = 0;

            jdebug!(args_count = event.args_count);
            while parsed_cnt < event.args_count {
                let p = &event.args[index..index + 16];
                let arg = unsafe { bytes_to_string(std::mem::transmute(p.as_ptr())) };
                arg_parsed.push(arg.clone());

                jdebug!(parsed_cnt = parsed_cnt, index = index, arg = arg);
                parsed_cnt += 1;
                index += 16;
            }
            if arg_parsed.is_empty() {
                let filename = unsafe { bytes_to_string(event.filename.as_ptr()) };
                if !filename.is_empty() {
                    arg_parsed.push(filename);
                }
            }

            let args_str = arg_parsed.join(" ");

            let fork_info = {
                if event.flag & 0x1 == 0x1 {
                    unsafe { format!("[{}]", bytes_to_string(event.comm2.as_ptr())) }
                } else {
                    String::new()
                }
            };

            print_timestamp();
            print_mark("EXEC");
            print_comm();
            if cli.thread {
                print_id(event.tid);
            }
            print_id(event.pid);
            if cli.ppid {
                print_id(event.ppid);
            }
            if !fork_info.is_empty() {
                print!(" {}", fork_info);
            }

            if !args_str.is_empty() {
                print!(" {}", args_str);
            }

            if event.duration_ns > 0 {
                print!(" ({}ms)", event.duration_ns / 1000000_u64);
            }
            println!();
        } else if event.event_type == 2 {
            if !cli.fork_event {
                return 0;
            }

            print_timestamp();
            print_mark("FORK");
            print_comm();
            if cli.thread {
                print_id(event.tid);
            }
            print_id(event.pid);
            if cli.ppid {
                print_id(event.ppid);
            }

            print!(" {}->{}", event.parent_pid, event.child_pid);

            if event.duration_ns > 0 {
                print!(" ({}ms)", event.duration_ns / 1000000_u64);
            }
            println!();
        };

        0
    };

    let mut rbuilder = RingBufferBuilder::new();
    let map = skel.maps();
    rbuilder
        .add(map.rb(), handle_event)
        .map_err(|_| Report::new(JtraceError::IOError))?;
    let ringbuf = rbuilder
        .build()
        .map_err(|_| Report::new(JtraceError::IOError))
        .attach_printable("Failed to create ring buffer")?;

    skel.attach()
        .map_err(|_| Report::new(JtraceError::IOError))
        .attach_printable("Failed to load bpf")?;

    let print_timestamp_str = || {
        if cli.timestamp {
            print!("{:<10}", "TIME");
        } else {
            print!("{:<20}", "TIME");
        }
    };

    let print_mark_str = |mark: &str| {
        print!(" {:<7}", mark);
    };

    let print_comm_str = || {
        print!(" {:<16}", "COMM");
    };

    let print_id_str = |id: &str| {
        print!(" {:<8}", id);
    };

    print_timestamp_str();
    print_mark_str("EVENT");
    print_comm_str();

    if cli.thread {
        print_id_str("TID");
    }

    print_id_str("PID");

    if cli.ppid {
        print_id_str("PPID");
    }

    println!(" INFO");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::Release);
    })
    .map_err(|_| Report::new(JtraceError::IOError))?;

    while running.load(Ordering::Acquire) {
        let _ = ringbuf.poll(std::time::Duration::from_millis(100));
    }

    Ok(())
}
