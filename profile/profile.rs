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
        io::{self, Write},
        rc::Rc,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
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
    ///Trace process lives at least <DURATION> ms.
    #[clap(short, default_value_t = 0_u64)]
    duration: u64,

    ///Trace process lives at least <DURATION> ms.
    #[clap(short, long)]
    pid: Option<u32>,

    ///Verbose
    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,
}

type Event = profile_bss_types::event;
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

    let cpu_num = std::thread::available_parallelism().unwrap().get();
    jinfo!(cpu_num = cpu_num);

    let skel_builder = ProfileSkelBuilder::default();
    set_print(Some((PrintLevel::Debug, print_to_log)));

    let mut open_skel = skel_builder
        .open()
        .into_report()
        .change_context(JtraceError::IOError)
        .attach_printable("Failed to open bpf.")?;

    open_skel.bss().trace_idle = 0;
    open_skel.data().target_pid = cli.pid.map(|a| a as i32).unwrap_or(-1);

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

        let obj = skel.object_mut();
        let prog = obj.prog_mut("do_perf_event").unwrap();
        let mut attrs = perf_sys::bindings::perf_event_attr::default();
        attrs.type_ = perf_sys::bindings::PERF_TYPE_HARDWARE;
        attrs.config = perf_sys::bindings::PERF_COUNT_HW_CPU_CYCLES as u64;
        attrs.sample_type = perf_sys::bindings::PERF_SAMPLE_RAW;
        attrs.__bindgen_anon_1.sample_freq = 49;
        attrs.set_freq(1);

        let mut links = vec![];

        for cpu in 0..cpu_num {
            let pfd = unsafe {
                perf_sys::perf_event_open(
                    &mut attrs,
                    -1,
                    cpu as i32,
                    -1,
                    perf_sys::bindings::PERF_FLAG_FD_CLOEXEC as u64,
                )
            };
            assert!(pfd > 0);

            links.push(
                prog.attach_perf_event(pfd)
                    .expect("Failed to attach perf event."),
            );
        }

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc::set_handler(move || {
            r.store(false, Ordering::Release);
        })
        .into_report()
        .change_context(JtraceError::IOError)?;

        while running.load(Ordering::Acquire) {
            let _ = perfbuf.poll(std::time::Duration::from_secs(u64::MAX));
        }

        perfbuf.consume().unwrap();
        for mut l in links {
            l.disconnect();
        }
    }

    println!();
    jinfo!("Processing data...");

    process_data(events, maps)
}

pub fn process_data(
    events: Rc<RefCell<Vec<Event>>>,
    map: Rc<RefCell<HashMap<u32, ExecMap>>>,
) -> Result<(), JtraceError> {
    let symanalyzer = SymbolAnalyzer::new(None).change_context(JtraceError::SymbolAnalyzerError)?;

    let mut no = 0;

    for event in events.borrow_mut().iter_mut() {
        let comm = unsafe { bytes_to_string(event.comm.as_ptr()) };
        let pid = event.pid;
        let tid = event.tid;
        let cpu = event.cpu_id;
        let ustack_sz = (event.ustack_sz / 8) as usize;
        let kstack_sz = (event.kstack_sz / 8) as usize;
        let ustack = &mut event.ustack[0..ustack_sz];
        let kstack = &mut event.kstack[0..kstack_sz];

        no += 1;

        println!("{:3} CPU:{} Comm:{} PID:{} TID:{}", no, cpu, comm, pid, tid);

        if kstack_sz > 0 {
            //println!("  Kernel Stack ({}):", kstack_sz);
            for f in 0..kstack_sz as usize {
                let addr = kstack[f];
                let p_name = symanalyzer.ksymbol(addr).unwrap_or("Unknown".to_string());
                println!("    {:x}  {}", addr, p_name);
            }
        }

        if kstack_sz > 0 && ustack_sz > 0 {
            println!("    ----");
        }

        if ustack_sz > 0 {
            //println!("  User Stack ({}):", ustack_sz);
            for f in 0..ustack_sz as usize {
                let addr = ustack[f];

                let (offset, p_name, file) = if let Some(em) = map.borrow_mut().get_mut(&pid) {
                    em.symbol(addr)
                        .unwrap_or((0, "Unknown".to_string(), "Unknown".to_string()))
                } else {
                    (0, "Unknown".to_string(), "Unknown".to_string())
                };

                println!("    {:x}(+{})  {} {}", addr, offset, p_name, file);
            }
        }

        println!();
    }
    Ok(())
}
