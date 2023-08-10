#[allow(unused)]
use {
    byteorder::ByteOrder,
    byteorder::NativeEndian,
    clap::Parser,
    error_stack::{IntoReport, Result, ResultExt},
    jlogger_tracing::{
        jdebug, jerror, jinfo, jtrace, jwarn, JloggerBuilder, LevelFilter, LogTimeFormat,
    },
    libbpf_rs::{
        set_print,
        skel::{OpenSkel, SkelBuilder},
        MapFlags, PerfBufferBuilder, PrintLevel,
    },
    plain::Plain,
    regex::Regex,
    std::error::Error,
    std::fmt::Display,
    std::{
        collections::HashMap,
        fs,
        io::{BufRead, BufReader},
        path::Path,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Instant,
    },
    tracelib::{
        bump_memlock_rlimit, bytes_to_string, ElfFile, ExecMap, KernelMap, NmSymbolType,
        SymbolAnalyzer,
    },
};

#[path = "bpf/funccount.skel.rs"]
mod funccount;
use funccount::*;

#[derive(Debug)]
enum FuncCountError {
    BPFError,
    SymbolAnalyzerError,
    InvalidParameter,
    Unexpected,
}

impl Error for FuncCountError {}

impl Display for FuncCountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error_str = match self {
            FuncCountError::SymbolAnalyzerError => "SymbolAnalyzerError",
            FuncCountError::InvalidParameter => "InvalidParameter",
            FuncCountError::BPFError => "BPFBuilderError",
            FuncCountError::Unexpected => "Unexpected",
        };

        write!(f, "{}", error_str)
    }
}

type StackEvent = funccount_bss_types::stacktrace_event;
unsafe impl Plain for StackEvent {}

type ExecTraceEvent = funccount_bss_types::exectrace_event;
unsafe impl Plain for ExecTraceEvent {}

fn print_to_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => jtrace!("{}", msg.trim_matches('\n')),
        PrintLevel::Info => jinfo!("{}", msg.trim_matches('\n')),
        PrintLevel::Warn => jwarn!("{}", msg.trim_matches('\n')),
    }
}

#[derive(Parser, Debug)]
struct Cli {
    ///Trace for <DURATION> seconds (0 disabled).
    #[clap(short, default_value_t = 0_u64)]
    duration: u64,

    ///Verbose.
    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,

    ///Show symbol address.
    #[clap(short = 'a')]
    addr: bool,

    ///Show file information.
    #[clap(short = 'f')]
    file: bool,

    ///Show stack information.
    #[clap(short = 's')]
    stack: bool,

    ///Trace function execution.
    #[clap(short = 'e')]
    exec: bool,

    ///Only show first <COUNT> results.
    #[clap(short = 'c', long)]
    count: Option<u32>,

    ///Show relative time to previous record.
    #[clap(short = 'r')]
    relative: bool,

    ///Only trace process with specified PID.
    #[clap(short = 'p', long)]
    pid: Option<i32>,

    ///File that store symbols to be traced.
    ///one symbol per line
    #[clap(short = 'S', long = "symbol-file")]
    symbol_file: Option<String>,

    #[clap()]
    args: Vec<String>,
}

struct TraceResult {
    stack: HashMap<String, Vec<StackTraceResult>>,
    exec: Vec<ExecTraceResult>,
}

struct ExecTraceResult {
    pid: u32,
    ts: u64,
    comm: String,
    probe: String,
}

struct StackTraceResult {
    cnt: u64,
    stack: StackEvent,
    kstack: Vec<(u64, String)>,
    ustack: Vec<(u64, String, String)>,
}

fn probe_name(event: &StackTraceResult) -> &str {
    if !event.kstack.is_empty() {
        event.kstack.first().unwrap().1.as_str()
    } else if !event.ustack.is_empty() {
        event.ustack.first().unwrap().1.as_str()
    } else {
        "Unknown"
    }
}

fn process_events(
    cli: &Cli,
    maps: &mut FunccountMaps,
    result: &mut TraceResult,
    symanalyzer: &mut SymbolAnalyzer,
    exec_map_hash: &mut HashMap<u32, ExecMap>,
) -> Result<(), FuncCountError> {
    if cli.exec {
        let exec_time = maps.exec_time();
        let show_limit = cli.count.unwrap_or(u32::MAX);

        for key in exec_time.keys() {
            let mut entry = ExecTraceEvent::default();
            plain::copy_from_bytes(&mut entry, &key).expect("Corrupted event data");
            let ts: u64 = NativeEndian::read_u64(&entry.ts);
            let probe_addr = NativeEndian::read_u64(&entry.frame0);

            let mut probe = String::from("Unknown");
            if entry.frame0_type == 0 {
                if let Ok(p_name) = symanalyzer.ksymbol(probe_addr) {
                    probe = p_name;
                }
            } else if let Ok((_, p_name, _file)) = symanalyzer.usymbol(entry.pid, probe_addr) {
                probe = p_name;
            }

            result.exec.push(ExecTraceResult {
                pid: entry.pid,
                ts,
                comm: unsafe { bytes_to_string(entry.comm.as_ptr()) },
                probe,
            });

            if result.exec.len() >= show_limit as usize {
                break;
            }
        }

        result.exec.sort_by(|a, b| a.ts.partial_cmp(&b.ts).unwrap());
    } else {
        let stack_cnt = maps.stack_cnt();
        let stack_map = maps.stack_map();
        let mut sym_hash = HashMap::new();
        let mut pid_sym_hash: HashMap<(u32, u64), (u64, String, String)> = HashMap::new();

        for key in stack_cnt.keys() {
            if let Ok(Some(data)) = stack_cnt.lookup(&key, MapFlags::ANY) {
                let mut stack = StackEvent::default();
                plain::copy_from_bytes(&mut stack, &key).expect("Corrupted event data");

                let mut cnt = 0_u64;
                plain::copy_from_bytes(&mut cnt, &data).expect("Corrupted event data");

                let mut kstack = vec![];
                let mut ustack = vec![];

                if stack.kstack > 0 {
                    if let Ok(Some(ks)) =
                        stack_map.lookup(&stack.kstack.to_ne_bytes(), MapFlags::ANY)
                    {
                        let num = ks.len() / 8;
                        let mut i = 0_usize;

                        while i < num {
                            let addr = NativeEndian::read_u64(&ks[8 * i..8 * (i + 1)]);
                            if addr == 0 {
                                break;
                            }

                            let sym = sym_hash.entry(addr).or_insert(
                                symanalyzer
                                    .ksymbol(addr)
                                    .change_context(FuncCountError::SymbolAnalyzerError)?,
                            );
                            kstack.push((addr, sym.to_string()));

                            i += 1;
                        }
                    }
                }

                if stack.ustack > 0 {
                    if let Ok(Some(us)) =
                        stack_map.lookup(&stack.ustack.to_ne_bytes(), MapFlags::ANY)
                    {
                        let num = us.len() / 8;
                        let mut i = 0_usize;

                        while i < num {
                            let addr = NativeEndian::read_u64(&us[8 * i..8 * (i + 1)]);
                            if addr == 0 {
                                break;
                            }
                            i += 1;

                            if let Some((sym_addr, sym_name, filename)) =
                                pid_sym_hash.get(&(stack.pid, addr))
                            {
                                ustack.push((
                                    *sym_addr,
                                    sym_name.to_string(),
                                    filename.to_string(),
                                ));
                                continue;
                            }

                            if let Some(em) = exec_map_hash.get_mut(&stack.pid) {
                                if let Ok((sym_addr, sym_name, filename)) = em.symbol(addr) {
                                    pid_sym_hash.insert(
                                        (stack.pid, addr),
                                        (sym_addr, sym_name.clone(), filename.clone()),
                                    );
                                    ustack.push((sym_addr, sym_name, filename));
                                    continue;
                                }
                            }

                            pid_sym_hash.insert(
                                (stack.pid, addr),
                                (addr, "[unknown]".to_string(), "[unknown]".to_string()),
                            );
                            ustack.push((addr, "[unknown]".to_string(), "[unknown]".to_string()));
                        }
                    }
                }

                let stack_trace_result = StackTraceResult {
                    cnt,
                    stack,
                    kstack,
                    ustack,
                };

                let str_vec = result
                    .stack
                    .entry(probe_name(&stack_trace_result).to_string())
                    .or_insert(Vec::new());
                str_vec.push(stack_trace_result);
            }
        }
    }
    Ok(())
}

fn print_result(cli: &Cli, result: &mut TraceResult, runtime_s: u64) -> Result<(), FuncCountError> {
    let runtime_s = if runtime_s == 0 { 1 } else { runtime_s };

    println!();

    let show_limit = cli.count.unwrap_or(u32::MAX);

    if !result.exec.is_empty() {
        let mut show_count = 0;

        println!("{:<12} {:<5} {:20} ", "Timestamp", "PID", "Command");
        let mut ts_previous = 0_u64;
        for event in &result.exec {
            let ts = event.ts / 1000;
            let ts_show;

            if cli.relative {
                if ts_previous == 0 {
                    ts_show = 0;
                } else {
                    ts_show = ts - ts_previous;
                }
                ts_previous = ts;
            } else {
                ts_show = ts;
            }

            println!(
                "{:<12.6} {:<5} {:20} {}",
                ts_show as f64 / 1000000_f64,
                event.pid,
                event.comm,
                event.probe
            );

            show_count += 1;
            if show_count >= show_limit {
                break;
            }
        }
    }

    if !result.stack.is_empty() {
        let mut show_count = 0;

        for (_, (probe_name, result_stack)) in result.stack.iter_mut().enumerate() {
            result_stack.sort_by(|a, b| b.cnt.partial_cmp(&a.cnt).unwrap());

            let mut total_cnt = 0;
            result_stack.iter().for_each(|a| total_cnt += a.cnt);

            println!(
                "PROBE: {} COUNTS: {}, {} COUNTS/s",
                probe_name,
                total_cnt,
                total_cnt / runtime_s
            );
            println!(
                "  {:<5} {:20} {:<8} {:9} {:9}",
                "PID", "COMMAND", "COUNTS", "PERCENT", "COUNTS/s"
            );

            if !cli.stack {
                let mut pid_cnt = HashMap::new();

                for event in result_stack {
                    let pid = event.stack.pid;
                    let comm = unsafe { bytes_to_string(event.stack.comm.as_ptr()) };
                    let cnt = event.cnt;

                    let (_comm_, cnt_) = pid_cnt.entry(pid).or_insert((comm, 0_u64));
                    *cnt_ += cnt;
                }

                for (_, (pid, (comm, cnt))) in pid_cnt.iter().enumerate() {
                    println!(
                        "  {:<5} {:20} {:<8} {:5.2}% {:9}",
                        pid,
                        comm,
                        cnt,
                        (*cnt as f64 / total_cnt as f64) * 100_f64,
                        cnt / runtime_s
                    );
                }
            } else {
                for event in result_stack {
                    let pid = event.stack.pid;
                    let comm = unsafe { bytes_to_string(event.stack.comm.as_ptr()) };
                    let cnt = event.cnt;

                    println!(
                        "{:<5} {:20} {:<8} {:5.2}% {:9}",
                        pid,
                        comm,
                        cnt,
                        (cnt as f64 / total_cnt as f64) * 100_f64,
                        cnt / runtime_s
                    );

                    let mut fno = 0;
                    for (addr, sym) in event.kstack.iter() {
                        if cli.addr {
                            println!("    {:3} {:20x} {}", fno, addr, sym);
                        } else {
                            println!("    {:3} {}", fno, sym);
                        }

                        fno -= 1;
                    }

                    for (addr, symname, filename) in event.ustack.iter() {
                        let mut filename_str = String::new();
                        if cli.file {
                            filename_str = format!("({})", filename);
                        }

                        if cli.addr {
                            println!("    {:3} {:20x} {} {}", fno, addr, symname, filename_str);
                        } else {
                            println!("    {:3} {} {}", fno, symname, filename_str);
                        }

                        fno -= 1;
                    }

                    show_count += 1;
                    if show_count >= show_limit {
                        break;
                    }
                }
            }

            println!();
        }

        return Ok(());
    }

    Ok(())
}

fn main() -> Result<(), FuncCountError> {
    let mut cli = Cli::parse();
    let max_level = match cli.verbose {
        0 => LevelFilter::INFO,
        _ => LevelFilter::DEBUG,
    };

    JloggerBuilder::new()
        .max_level(max_level)
        .log_runtime(false)
        .build();

    bump_memlock_rlimit();

    let skel_builder = FunccountSkelBuilder::default();
    set_print(Some((PrintLevel::Debug, print_to_log)));

    let mut open_skel = skel_builder
        .open()
        .into_report()
        .change_context(FuncCountError::BPFError)
        .attach_printable("Failed to open bpf")?;

    open_skel.bss().self_pid = std::process::id() as i32;

    if let Some(pid) = cli.pid {
        open_skel.bss().target_pid = pid;
    } else {
        open_skel.bss().target_pid = -1;
    }

    if cli.exec {
        open_skel.bss().trace_type = 1;

        if cli.stack {
            jwarn!("Show stack option -s is unused when using -e.");
            cli.stack = false;
        }
    } else if cli.relative {
        jwarn!("Show relative time option -r is unused when -e is unused.");
        cli.relative = false;
    }

    if !cli.stack && cli.addr {
        jwarn!("Show addr option -a is unused when -s is unused.");
        cli.addr = false;
    }

    if !cli.stack && cli.file {
        jwarn!("Show file option -f is unused when -s is unused.");
        cli.file = false;
    }

    let mut skel = open_skel
        .load()
        .into_report()
        .change_context(FuncCountError::BPFError)
        .attach_printable("Failed to load bpf")?;

    let mut result = TraceResult {
        stack: HashMap::new(),
        exec: Vec::new(),
    };

    let mut links = vec![];
    let mut exec_map_hash = HashMap::<u32, ExecMap>::new();
    let runtime_s;
    {
        let exec_map_hash_ref = &mut exec_map_hash;

        let handle_exec_trace = move |_cpu: i32, data: &[u8]| {
            let pid = NativeEndian::read_u32(data);

            match ExecMap::new(pid) {
                Ok(em) => {
                    exec_map_hash_ref.insert(pid, em);
                }
                Err(e) => {
                    if pid != 0 {
                        jwarn!("Failed to read maps for pid {}: {}", pid, e)
                    }
                }
            }
        };

        let perfbuf = PerfBufferBuilder::new(skel.maps().exectrace_pb())
            .sample_cb(handle_exec_trace)
            .pages(2)
            .build()
            .into_report()
            .change_context(FuncCountError::BPFError)
            .attach_printable("Failed to create perf buffer")?;

        let km = KernelMap::new(None)
            .change_context(FuncCountError::Unexpected)
            .attach_printable("Failed to load kernel map")?;

        let tracepoints: Vec<&str> = include_str!("tracepoints").split('\n').collect();
        let mut sym_to_trace = &cli.args;
        let mut sym_to_trace_vec = vec![];

        if sym_to_trace.is_empty() {
            let sf = match cli.symbol_file {
                Some(ref a) => a.clone(),
                None => "./funccount.sym".to_owned(),
            };

            let sfp = Path::new(&sf);
            if sfp.is_file() {
                println!("Search symbols from {}", sf);

                if let Ok(f) = fs::File::open(sfp) {
                    let mut buf = String::new();
                    let mut reader = BufReader::new(f);

                    loop {
                        match reader.read_line(&mut buf) {
                            Ok(s) if s > 0 => sym_to_trace_vec.push(buf.clone()),
                            _ => break,
                        }
                    }

                    sym_to_trace = &sym_to_trace_vec;
                }
            }
        }

        if sym_to_trace.is_empty() {
            return Err(FuncCountError::InvalidParameter)
                .into_report()
                .attach_printable("No symbol found");
        }

        for arg in sym_to_trace {
            let mut processed = false;

            jdebug!("arg: {}", arg);

            let tre = Regex::new(r"t:(.+):(.+)")
                .into_report()
                .change_context(FuncCountError::Unexpected)?;

            if tre.is_match(arg) {
                for g in tre.captures_iter(arg) {
                    let pattern = format!("^{}:{}$", &g[1], &g[2]);
                    let re = Regex::new(&pattern)
                        .into_report()
                        .change_context(FuncCountError::Unexpected)?;

                    let mut tps = vec![];

                    for &tp in &tracepoints {
                        if re.is_match(tp) {
                            let tmp: Vec<&str> = tp.split(':').collect();
                            tps.push((tmp[0], tmp[1]));
                        }
                    }

                    if tps.is_empty() {
                        return Err(FuncCountError::InvalidParameter)
                            .into_report()
                            .attach_printable(format!("Invalid symbol: {}", arg));
                    }

                    println!("Attaching {} Tracepoint.", tps.len());
                    for (tp_category, tp_name) in tps.iter() {
                        match skel
                            .progs_mut()
                            .stacktrace_tp()
                            .attach_tracepoint(tp_category, tp_name)
                        {
                            Ok(link) => links.push(link),
                            Err(e) => {
                                jwarn!(
                                    "Failed to attach {}/{}: {}, skipped",
                                    tp_category,
                                    tp_name,
                                    e
                                )
                            }
                        }
                    }
                    processed = true;
                }
            }
            if processed {
                continue;
            }

            let mut pid = -1;
            if let Some(p) = cli.pid {
                if p > 0 {
                    pid = p;
                }
            }

            let tre = Regex::new(r"u:(.+):(.+)")
                .into_report()
                .change_context(FuncCountError::Unexpected)?;

            if tre.is_match(arg) {
                for g in tre.captures_iter(arg) {
                    let file = &g[1];
                    let elf =
                        ElfFile::new(file).change_context(FuncCountError::SymbolAnalyzerError)?;

                    let pattern = format!("^{}$", &g[2]);
                    let re = Regex::new(&pattern)
                        .into_report()
                        .change_context(FuncCountError::Unexpected)?;

                    let mut symbols = vec![];
                    for &sy in elf.symbol_vec().iter() {
                        if re.is_match(sy.name()) {
                            symbols.push((sy.name(), sy.start()));
                        }
                    }

                    if symbols.is_empty() {
                        return Err(FuncCountError::InvalidParameter)
                            .into_report()
                            .attach_printable(format!("Invalid symbol: {}", arg));
                    }

                    let num = symbols.len();
                    if num > 100 {
                        jwarn!(
                            "Tracing too many uprobe symbols ({}) maybe not what you want.",
                            num
                        );
                    } else {
                        println!("Attaching {} Uprobes.", symbols.len());
                    }

                    for (symbol, offset) in symbols {
                        /*
                         * Parameter
                         *  pid > 0: target process to trace
                         *  pid == 0 : trace self
                         *  pid == -1 : trace all processes
                         * See bpf_program__attach_uprobe()
                         */
                        let link = skel
                            .progs_mut()
                            .stacktrace_ub()
                            .attach_uprobe(false, pid, file, offset as usize)
                            .into_report()
                            .change_context(FuncCountError::BPFError)
                            .attach_printable(format!(
                                "Failed to attach {}({:x}) with pid {}",
                                symbol, offset, pid
                            ))?;
                        links.push(link);
                    }
                }
                processed = true;
            }

            if processed {
                continue;
            }

            let tre = Regex::new(r"(k:)*(.+)")
                .into_report()
                .change_context(FuncCountError::Unexpected)?;

            if tre.is_match(arg) {
                for g in tre.captures_iter(arg) {
                    let mut func_names = vec![];
                    let pattern = format!("^{}$", &g[2]);
                    let re = Regex::new(&pattern)
                        .into_report()
                        .change_context(FuncCountError::Unexpected)?;

                    for &sy in km.symbol_vec().iter() {
                        if sy.ktype() != NmSymbolType::Text {
                            continue;
                        }
                        if re.is_match(sy.name()) {
                            func_names.push(sy.name());
                        }
                    }

                    if func_names.is_empty() {
                        return Err(FuncCountError::InvalidParameter)
                            .into_report()
                            .attach_printable(format!("No symbol found in `{}`", arg));
                    }

                    let num = func_names.len();
                    if num > 100 {
                        jwarn!(
                            "Tracing too many kprobe symbols ({}) maybe not what you want.",
                            num
                        );
                    } else {
                        println!("Attaching {} Kprobes.", num);
                    }

                    for func_name in func_names {
                        match skel
                            .progs_mut()
                            .stacktrace_kb()
                            .attach_kprobe(false, func_name)
                        {
                            Ok(link) => links.push(link),
                            Err(e) => jwarn!("Failed to attach {}: {}, skipped.", func_name, e),
                        }
                    }
                    processed = true;
                }
            }
            if processed {
                continue;
            }
        }

        if links.is_empty() {
            return Err(FuncCountError::Unexpected)
                .into_report()
                .attach_printable("No traceable symbol found");
        }

        let start = Instant::now();
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();

        ctrlc::set_handler(move || {
            r.store(false, Ordering::Release);
        })
        .into_report()
        .change_context(FuncCountError::Unexpected)?;

        if cli.duration > 0 {
            println!(
                "Tracing {} symbols for {} seconds, Type Ctrl-C to stop.",
                links.len(),
                cli.duration
            );
        } else {
            println!("Tracing {} symbols... Type Ctrl-C to stop.", links.len());
        }

        let mut timeout = if cli.duration > 0 {
            cli.duration * 1000
        } else {
            100
        };

        while running.load(Ordering::Acquire) {
            let _ = perfbuf.poll(std::time::Duration::from_millis(timeout));

            if cli.duration > 0 {
                let passed = start.elapsed().as_millis() as u64;
                if passed > cli.duration * 1000 {
                    break;
                } else {
                    timeout = cli.duration * 1000 - passed;
                }
            }
        }

        // libbpf uses BPF_LINK_DETACH to detach, but this API is supported from linux-5.18
        // detach will fail in old kernel.
        for link in links {
            match link.detach() {
                Ok(()) => {}
                Err(_e) => {}
            }
        }

        // Time here may be incorrect when detach() failed.
        runtime_s = start.elapsed().as_secs();
    }

    println!("Tracing finished, Processing data...");
    let mut symanalyzer =
        SymbolAnalyzer::new(None).change_context(FuncCountError::SymbolAnalyzerError)?;

    process_events(
        &cli,
        &mut skel.maps(),
        &mut result,
        &mut symanalyzer,
        &mut exec_map_hash,
    )?;

    print_result(&cli, &mut result, runtime_s)?;
    Ok(())
}
