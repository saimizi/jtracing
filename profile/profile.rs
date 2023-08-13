#[allow(unused)]
use {
    clap::Parser,
    error_stack::{IntoReport, Report, Result, ResultExt},
    jlogger_tracing::{
        jdebug, jerror, jinfo, jtrace, jwarn, JloggerBuilder, LevelFilter, LogTimeFormat,
    },
    libbpf_rs::{
        libbpf_sys::perf_buffer,
        set_print,
        skel::{OpenSkel, Skel, SkelBuilder},
        PerfBufferBuilder, PrintLevel,
    },
    perf_event_open_sys as perf_sys,
    plain::Plain,
    std::{
        cell::RefCell,
        collections::HashMap,
        fs,
        io::{self, Write},
        process,
        rc::Rc,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    },
    tracelib::{bump_memlock_rlimit, bytes_to_string, ExecMap, JtraceError, SymbolAnalyzer},
};

#[path = "bpf/profile.skel.rs"]
mod profile;
use profile::*;

fn print_to_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => jdebug!("{}", msg.trim_end_matches('\n')),
        PrintLevel::Info => jinfo!("{}", msg.trim_end_matches('\n')),
        PrintLevel::Warn => jwarn!("{}", msg.trim_end_matches('\n')),
    }
}

#[derive(Parser, Debug)]
struct Cli {
    ///Trace internal
    #[clap(short, long)]
    duration: Option<u64>,

    ///Target process id to be traced
    #[clap(short, long)]
    pid: Option<u32>,

    ///Id of CPU to be traced
    #[clap(short, long)]
    cpu: Option<Vec<u32>>,

    ///Trace profile program self.
    #[clap(long)]
    trace_self: bool,

    ///Skip tracing idle task (PID==0)
    #[clap(long)]
    trace_idle: bool,

    ///Profiling frequency
    #[clap(short = 'F', long, default_value_t = 99_u64)]
    frequency: u64,

    ///Fold format, one line per stack for flame graphs
    #[clap(short, long)]
    fold: bool,

    ///Log file to store fold format output.
    #[clap(long, default_value_t=String::from("profile.fold"))]
    fold_file: String,

    ///Verbose
    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,
}

type Event = profile_bss_types::event;
unsafe impl Plain for Event {}

fn main() -> Result<(), JtraceError> {
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

    bump_memlock_rlimit();

    let cpu_num = std::thread::available_parallelism().unwrap().get();
    let skel_builder = ProfileSkelBuilder::default();
    set_print(Some((PrintLevel::Debug, print_to_log)));

    let mut open_skel = skel_builder
        .open()
        .into_report()
        .change_context(JtraceError::IOError)
        .attach_printable("Failed to open bpf.")?;

    if !cli.trace_idle {
        open_skel.data().skip_idle = 0;
    }

    if !cli.trace_self {
        open_skel.data().skip_self = process::id() as i32;
    }

    let mut skel = open_skel
        .load()
        .into_report()
        .change_context(JtraceError::IOError)
        .attach_printable("Failed to load bpf")?;

    let events: Rc<RefCell<Vec<Event>>> = Rc::new(RefCell::new(Vec::new()));
    let maps = Rc::new(RefCell::new(HashMap::new()));
    {
        let events_c = events.clone();
        let maps_c = maps.clone();
        let handle_event = move |_cpu: i32, data: &[u8]| {
            let mut entry = Event::default();
            plain::copy_from_bytes(&mut entry, data).expect("Corrupted data");

            if let Ok(em) = ExecMap::new(entry.pid) {
                maps_c.borrow_mut().insert(entry.pid, em);
                events_c.borrow_mut().push(entry)
            }

            print!("  Retrieve {} events\r", events_c.borrow().len());
            io::stdout().flush().unwrap();
        };

        let perfbuf = PerfBufferBuilder::new(skel.maps().pb())
            .sample_cb(handle_event)
            .pages(16) // 4k * 16
            .build()
            .into_report()
            .change_context(JtraceError::IOError)
            .attach_printable("Failed to create perf buffer")?;

        let mut attrs = perf_sys::bindings::perf_event_attr {
            type_: perf_sys::bindings::PERF_TYPE_HARDWARE,
            config: perf_sys::bindings::PERF_COUNT_HW_CPU_CYCLES as u64,
            sample_type: perf_sys::bindings::PERF_SAMPLE_RAW,
            ..Default::default()
        };

        attrs.__bindgen_anon_1.sample_freq = cli.frequency;
        attrs.set_freq(1);

        let mut links = vec![];

        let pid = cli.pid.map(|a| a as i32).unwrap_or(-1);
        let mut target_cpu: Vec<i32> = (0..cpu_num).map(|a| a as i32).collect();

        if let Some(c) = cli.cpu {
            target_cpu.retain(|&a| c.iter().any(|&b| a == b as i32));
        }

        if pid == -1 {
            jinfo!(
                "Sampling ALL processes on CPU {:?} at {}Hz",
                target_cpu,
                cli.frequency
            );
        } else {
            jinfo!(
                "Sampling pid {} on CPU {:?} at {}Hz",
                pid,
                target_cpu,
                cli.frequency
            );
        }

        let mut group_fd = -1;
        for cpu in target_cpu {
            let pfd = unsafe {
                perf_sys::perf_event_open(
                    &mut attrs,
                    pid,
                    cpu,
                    -1,
                    perf_sys::bindings::PERF_FLAG_FD_CLOEXEC as u64,
                )
            };
            assert!(pfd > 0);

            if group_fd == -1 {
                group_fd = pfd;
            }

            links.push(
                skel.progs_mut()
                    .do_perf_event()
                    .attach_perf_event(pfd)
                    .into_report()
                    .change_context(JtraceError::BPFError)?,
            );
        }

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc::set_handler(move || {
            r.store(false, Ordering::Release);
        })
        .into_report()
        .change_context(JtraceError::IOError)?;

        let timeout = cli
            .duration
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(u64::MAX));

        let start = Instant::now();
        while running.load(Ordering::Acquire) {
            let _ = perfbuf.poll(timeout);
            if start.elapsed() >= timeout {
                break;
            }
        }

        perfbuf.consume().unwrap();
        for mut l in links {
            l.disconnect();
        }
    }

    if !events.borrow().is_empty() {
        println!();
        jinfo!("Processing data...");
        process_data(events, maps, cli.fold, &cli.fold_file)?;
    } else {
        jinfo!("No data captured.");
    }

    Ok(())
}

pub fn process_data(
    events: Rc<RefCell<Vec<Event>>>,
    map: Rc<RefCell<HashMap<u32, ExecMap>>>,
    fold: bool,
    fold_file_name: &str,
) -> Result<(), JtraceError> {
    let symanalyzer = SymbolAnalyzer::new(None).change_context(JtraceError::SymbolAnalyzerError)?;

    let mut no = 0;
    let total = events.borrow().len();
    let _ = fs::remove_file(fold_file_name);
    let mut fold_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open(fold_file_name)
        .into_report()
        .change_context(JtraceError::IOError)?;

    for event in events.borrow_mut().iter_mut() {
        let comm = unsafe { bytes_to_string(event.comm.as_ptr()) };
        let pid = event.pid;
        let tid = event.tid;
        let cpu = event.cpu_id;
        let ustack_sz = (event.ustack_sz / 8) as usize;
        let kstack_sz = (event.kstack_sz / 8) as usize;
        let ustack = &mut event.ustack[0..ustack_sz];
        let kstack = &mut event.kstack[0..kstack_sz];

        if !fold {
            no += 1;

            println!("{:3} CPU:{} Comm:{} PID:{} TID:{}", no, cpu, comm, pid, tid);

            if kstack_sz > 0 {
                //println!("  Kernel Stack ({}):", kstack_sz);
                for addr in kstack.iter().take(kstack_sz) {
                    let p_name = symanalyzer
                        .ksymbol(*addr)
                        .unwrap_or("[unknown]".to_string());
                    println!("    {:x}  {}", addr, p_name);
                }
            }

            if kstack_sz > 0 && ustack_sz > 0 {
                println!("    ----");
            }

            if ustack_sz > 0 {
                //println!("  User Stack ({}):", ustack_sz);
                for addr in ustack.iter().take(ustack_sz) {
                    let (offset, p_name, file) = if let Some(em) = map.borrow_mut().get_mut(&pid) {
                        em.symbol(*addr).unwrap_or((
                            0,
                            "[unknown]".to_string(),
                            "[unknown]".to_string(),
                        ))
                    } else {
                        (0, "[unknown]".to_string(), "[unknown]".to_string())
                    };

                    println!("    {:x}(+{})  {} {}", addr, offset, p_name, file);
                }
            }

            println!();
        } else {
            ustack.reverse();
            kstack.reverse();

            no += 1;
            print!("  Write {}/{} records to {}\r", no, total, fold_file_name);
            io::stdout().flush().unwrap();

            let mut fold_result = String::new();
            fold_result.push_str(&comm);
            fold_result.push(';');
            if ustack_sz == 0 {
                fold_result.push_str("[Missed User Stack]");
                fold_result.push(';');
            } else {
                for addr in ustack.iter().take(ustack_sz) {
                    let (_offset, p_name, _file) = if let Some(em) = map.borrow_mut().get_mut(&pid)
                    {
                        em.symbol(*addr).unwrap_or((
                            0,
                            "[unknown]".to_string(),
                            "[unknown]".to_string(),
                        ))
                    } else {
                        (0, "[unknown]".to_string(), "[unknown]".to_string())
                    };

                    fold_result.push_str(&p_name);
                    fold_result.push(';');
                }
            }

            if kstack_sz == 0 {
                fold_result.push_str("[Missed Kernel Stack]");
                fold_result.push(';');
            } else {
                for addr in kstack.iter().take(kstack_sz) {
                    let p_name = symanalyzer
                        .ksymbol(*addr)
                        .unwrap_or("[unknown]".to_string());
                    fold_result.push_str(&p_name);
                    fold_result.push(';');
                }
            }

            fold_result = fold_result.trim_end_matches(';').to_string();
            fold_result.push_str(&format!(" {}\n", pid));

            fold_file
                .write(fold_result.as_bytes())
                .into_report()
                .change_context(JtraceError::IOError)?;
            fold_file
                .flush()
                .into_report()
                .change_context(JtraceError::IOError)?;
        }
    }

    if fold {
        println!();
        jinfo!("Written to {}", fold_file_name);
    }
    Ok(())
}
