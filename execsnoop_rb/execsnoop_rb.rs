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
#[command(
    about = "A utility to trace process's fork, exec and exit events.",
    version,
    after_help = "
Examples:
    # Trace fork event.
    execsnoop_rb -f

    # Trace exec event
    execsnoop_rb
    execsnoop_rb -E

    # Trace exit event
    execsnoop_rb
    execsnoop_rb -e

    # Trace All event
    execsnoop_rb -Efe --ppid
    execsnoop_rb -Erfet --ppid

Output Examples:
    1. FORK event
        Trace fork() system call.

        TIME                 EVENT   COMM             PID      INFO
        2024-09-15 09:54:34  FORK    execsnoop_rb     626377   626377->626378

        Note:
          The \"X->Y\" in INFO field shows the parent thread id and the forked child process id.
          Since PID is the id of the thread group leader which may be different to the thread
          which actually executes fork(), PID is not alway equal to \"X\".

          If X is not equal to PID, the new process is forked from a thread. You can enable
          displaying thread id with \"-t\" option and confirm that \"X\" always matches the TID.

    2. EXEC event
        Trace execev() system call.

        TIME                 EVENT   COMM             PID      INFO
        2024-09-15 10:27:43  EXEC    nvim             632565   [nvim] /usr/bin/xsel --nodetach -i -b

        Note:
          INFO field shows what kind of a command is executed by the parent process whose name is
          displayed inside the square brackets.

    3. EXIT event
        Trace exit() system call.

        TIME                 EVENT   COMM             PID      INFO
        2024-09-15 10:47:36  EXIT    rustc            636490   [0]
        2024-09-15 10:47:38  EXIT    ld               636573   [0] [collect2] (458ms)
        2024-09-15 10:47:38  EXIT    collect2         636572   [0] [cc] (460ms)
        2024-09-15 10:47:38  EXIT    cc               636571   [0] [rustc] (466ms)
        2024-09-15 10:55:26  EXIT    top              637839   [0] [INT=2 <- kworker/u16:3(633411)] [fish] (2539ms)

        Note
          The format of INFO filed is as follow:

            [RETURN CODE] [SIGNAL INFO] [PARENT COMM] (LIVE DURATION)

          - RETURN CODE
            Always displayed, normally 0 means a graceful exit.

          - SIGNAL INFO
            Only displayed when the process exited because of a signal. the signal information is
            displayed in following format:

                SIGNAL_NAME=SIGNAL_NUMBER <- SENDER_NAME (SENDER_PID)

          - PARENT COMM
            The name of process who forked the current exited process. This information is only displayed
            when the FORK event was captured.

          - LIVE DURATION
            The time of the current process has been alive. This information is only displayed when
            the FORK event was captured.

    By combing the usage of FORK, EXEC and EXIT events, you can trace the whole lifetime of a command.

        TIME                 EVENT   COMM             PID      PPID     INFO
        2024-09-15 11:14:37  FORK    starship         643370   632315   643373->643379
        2024-09-15 11:14:37  EXEC    starship         643379   643370   [starship] /usr/bin/python --version
        2024-09-15 11:14:37  EXIT    python           643379   643370   [0] [starship] (5ms)

    In this example, \"starship\" forked a process to execute \"/usr/bin/python --version\" which took 5ms.

"
)]
struct Cli {
    ///Trace EXIT event for processes lives at least <DURATION> ms.
    #[clap(short, default_value_t = 0_u64)]
    duration: u64,

    ///Verbose
    #[clap(short, long, action=clap::ArgAction::Count)]
    verbose: u8,

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
        let timestamp_us = (now.timestamp_nanos_opt().unwrap() - start.timestamp_nanos_opt().unwrap()) / 1000;

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
