#[allow(unused)]
use {
    byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt},
    clap::Parser,
    error_stack::{Report, Result, ResultExt},
    jlogger_tracing::{
        jdebug, jerror, jinfo, jtrace, jwarn, JloggerBuilder, LevelFilter, LogTimeFormat,
    },
    libbpf_rs::{
        set_print,
        skel::{OpenSkel, SkelBuilder},
        MapFlags, PrintLevel,
    },
    plain::Plain,
    std::{
        collections::HashMap,
        io::{self, BufRead, BufReader, Cursor},
        mem,
        path::Path,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    },
    tracelib::{bump_memlock_rlimit, bytes_to_string, tid_to_pid, ElfFile, ExecMap, JtraceError},
};

#[path = "bpf/malloc_free.skel.rs"]
mod malloc_free;
use malloc_free::*;

type MallocRecord = malloc_free_bss_types::malloc_record;
unsafe impl Plain for MallocRecord {}
type MallocEvent = malloc_free_bss_types::malloc_event;
unsafe impl Plain for MallocEvent {}

fn find_libc_path_from_proc_maps() -> Option<String> {
    let maps_path = format!("/proc/{}/maps", std::process::id());
    let file = match std::fs::File::open(&maps_path) {
        Ok(f) => f,
        Err(e) => {
            jwarn!("Failed to open {}: {}", maps_path, e);
            return None;
        }
    };

    let reader = BufReader::new(file);
    for line in reader.lines() {
        if let Ok(l) = line {
            if l.contains("libc.so.6") && l.contains(".so") {
                // Extract the path, which is usually the last part of the line after a space
                if let Some(path_str) = l.split_whitespace().last() {
                    jinfo!("Found libc.so.6 in proc maps: {}", path_str);
                    return Some(path_str.to_string());
                }
            }
        }
    }
    None
}

fn find_libc_path() -> Option<String> {
    if let Some(path) = find_libc_path_from_proc_maps() {
        return Some(path);
    }

    let common_paths = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/libc.so.6",
        "/lib/libc.so.6",
    ];

    for path_str in &common_paths {
        let path = Path::new(path_str);
        if path.exists() {
            jinfo!("Found libc.so.6 at {}", path_str);
            return Some(path_str.to_string());
        }
    }
    None
}

fn print_to_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => jtrace!("{}", msg.trim_matches('\n')),
        PrintLevel::Info => jinfo!("{}", msg.trim_matches('\n')),
        PrintLevel::Warn => jwarn!("{}", msg.trim_matches('\n')),
    }
}

#[derive(Parser, Debug, Default)]
#[command(
    about = "A utility to trace malloc/free calls.",
    version,
    after_help = "
Examples:
    malloc_free -d 10 -l /lib/x86_64-linux-gnu/
    malloc_free -d 10 -m
    malloc_free -l /lib/x86_64-linux-gnu/ -p 3226
    malloc_free --max-events 16384 --max-records 2048 -s

Output Examples:
    No   PID      Alloc    Free     Real     Real.max   Req.max  Comm
    1    3226     460240   452224   8016     13088      3680     Xorg
--------
No:         Record index.
PID:        PID of process.
Alloc:      Total bytes allocated.
Free:       Total bytes freed.
Real:       Bytes not freed.
Real.max:   Maximum bytes process used at the moment.
Req.max:    Maximum bytes process required at the moment.
"
)]
struct Cli {
    ///Trace for <DURATION> seconds (0 disabled).
    #[clap(short, default_value_t = 0_u64)]
    duration: u64,

    ///Verbose.
    #[clap(short, long, action=clap::ArgAction::Count)]
    verbose: u8,

    ///Show call path for max-size malloc() call.
    #[clap(short, long)]
    max_malloc_path: bool,

    ///Only trace process with specified PID.
    #[clap(short = 'p', long)]
    pid: Option<i32>,

    ///Specify libc path.
    #[clap(short = 'l', long)]
    libpath: Option<String>,

    ///Trace malloc path that is not freed.
    #[clap(short = 't', long)]
    trace_path: bool,

    ///Trace full malloc/free path.
    #[clap(short = 'T', long)]
    trace_full_path: bool,

    ///Maximum malloc events to track (default: 8192).
    #[clap(long, default_value_t = 8192_u32)]
    max_events: u32,

    ///Maximum process records to track (default: 1024).
    #[clap(long, default_value_t = 1024_u32)]
    max_records: u32,

    ///Maximum stack frames to capture (default: 128).
    #[clap(long, default_value_t = 128_u32)]
    max_stack_depth: u32,

    ///Show statistics and map utilization.
    #[clap(short = 's', long)]
    show_stats: bool,
}

fn process_events(cli: &Cli, maps: &mut MallocFreeMaps) -> Result<(), JtraceError> {
    if cli.trace_path || cli.trace_full_path {
        let malloc_events = maps.malloc_event_records();
        let mut events = HashMap::new();
        for key in malloc_events.keys() {
            if let Some(data) = malloc_events
                .lookup(&key, MapFlags::ANY)
                .change_context(JtraceError::BPFError)?
            {
                let mut event = MallocEvent::default();
                plain::copy_from_bytes(&mut event, &data).expect("Corrupted event data");
                events.insert(key, event);
            }
        }

        let mut idx = 1_usize;
        println!("{:<4} {:<8}", "No", "Size");
        for (_key, event) in events.iter() {
            let comm = unsafe { bytes_to_string(event.comm.as_ptr()) };
            let free_comm = unsafe { bytes_to_string(event.free_comm.as_ptr()) };

            let tid = event.tid as i32;
            let free_tid = event.free_tid as i32;

            // If trace_full_path is enabled, we show all malloc/free events.
            if !cli.trace_full_path {
                // Only show backtrace for memory region that has not been freed.
                if free_tid != -1 {
                    continue;
                }
            }

            if free_tid == -1 {
                println!("{:<4} {:<8} malloc: {:<10}({})", idx, event.size, comm, tid);
            } else {
                println!(
                    "{:<4} {:<8} malloc: {:<10}({}) free: {:<10}({})",
                    idx, event.size, comm, tid, free_comm, free_tid
                );
            }
            idx += 1;

            let ustack_sz = (event.ustack_sz / 8) as usize;
            let ustack = &event.ustack[..ustack_sz];
            match ExecMap::new(tid_to_pid(event.tid as i32).unwrap_or(event.tid as i32) as u32) {
                Ok(mut em) => {
                    println!("{:<4} Backtrace for malloc():", " ");
                    for addr in ustack {
                        let (offset, symbol, file) = em
                            .symbol(*addr)
                            .map_err(|e| {
                                jwarn!("Failed to get symbol for address {:#x}: {}", addr, e);
                                Report::new(JtraceError::SymbolAnalyzerError)
                            })
                            .unwrap_or((0, "[unknown]".to_string(), "unknown".to_string()));
                        println!("{:<4} {:x}(+{})  {} {}", " ", addr, offset, symbol, file);
                    }
                }
                Err(e) => {
                    jwarn!("Failed to get ExecMap for tid {}: {}", event.tid, e);
                    println!("    No map found.");
                }
            }
            println!();

            if free_tid != -1 {
                let free_ustack_sz = (event.free_ustack_sz / 8) as usize;
                let free_ustack = &event.free_ustack[..free_ustack_sz];
                match ExecMap::new(
                    tid_to_pid(event.free_tid as i32).unwrap_or(event.tid as i32) as u32,
                ) {
                    Ok(mut em) => {
                        println!("{:<4} Backtrace for free():", " ");
                        for addr in free_ustack {
                            let (offset, symbol, file) = em
                                .symbol(*addr)
                                .map_err(|e| {
                                    jwarn!("Failed to get symbol for address {:#x}: {}", addr, e);
                                    Report::new(JtraceError::SymbolAnalyzerError)
                                })
                                .unwrap_or((0, "[unknown]".to_string(), "unknown".to_string()));
                            println!("{:<4} {:x}(+{})  {} {}", " ", addr, offset, symbol, file);
                        }
                    }
                    Err(e) => {
                        jwarn!("Failed to get ExecMap for tid {}: {}", event.free_tid, e);
                        println!("    No map found.");
                    }
                }
                println!();
            }
        }
        return Ok(());
    }

    let malloc_records = maps.malloc_records();

    println!(
        "{:<4} {:<8} {:<8} {:<8} {:<8} {:<8} {:<10} {:<8} Comm",
        "No", "PID", "TID", "Alloc", "Free", "Real", "Real.max", "Req.max"
    );
    let mut idx = 0;
    for key in malloc_records.keys() {
        if let Some(data) = malloc_records
            .lookup(&key, MapFlags::ANY)
            .change_context(JtraceError::BPFError)?
        {
            let mut mr = MallocRecord::default();
            plain::copy_from_bytes(&mut mr, &data).expect("Corrupted event data");

            idx += 1;
            let comm = unsafe { bytes_to_string(mr.comm.as_ptr()) };

            println!(
                "{:<4} {:<8} {:<8} {:<8} {:<8} {:<8} {:<10} {:<8} {}",
                idx,
                mr.pid,
                mr.tid,
                mr.alloc_size,
                mr.free_size,
                mr.alloc_size - mr.free_size,
                mr.max_size,
                mr.max_req_size,
                comm
            );

            if cli.max_malloc_path {
                println!("    ----");
                let ustack_sz = (mr.ustack_sz / 8) as usize;
                let ustack = &mr.ustack[..ustack_sz];

                match ExecMap::new(mr.pid) {
                    Ok(mut em) => {
                        for addr in ustack {
                            let (offset, symbol, file) = em
                                .symbol(*addr)
                                .map_err(|e| {
                                    jwarn!("Failed to get symbol for address {:#x}: {}", addr, e);
                                    Report::new(JtraceError::SymbolAnalyzerError)
                                })
                                .unwrap_or((0, "[unknown]".to_string(), "unknown".to_string()));
                            println!("    {:x}(+{})  {} {}", addr, offset, symbol, file);
                        }
                    }
                    Err(e) => {
                        jwarn!("Failed to get ExecMap for pid {}: {}", mr.pid, e);
                        println!("    No map found.");
                    }
                }
                println!();
            }
        }
    }

    Ok(())
}

fn print_statistics(cli: &Cli, maps: &mut MallocFreeMaps) -> Result<(), JtraceError> {
    let stats_map = maps.stats();

    println!("\n=== Statistics ===");

    // Read statistics from all CPUs and sum them up
    let mut stats_totals = vec![0u64; 20];
    for cpu in 0..num_cpus::get() {
        for stat_idx in 0..20 {
            let key_bytes = (stat_idx as u32).to_ne_bytes();
            if let Some(data) = stats_map
                .lookup_percpu(&key_bytes, MapFlags::ANY)
                .change_context(JtraceError::BPFError)?
            {
                if let Some(cpu_data) = data.get(cpu) {
                    let mut value = 0u64;
                    let mut cursor = Cursor::new(cpu_data);
                    if cursor.read_u64::<NativeEndian>().is_ok() {
                        cursor.set_position(0);
                        value = cursor.read_u64::<NativeEndian>().unwrap_or(0);
                    }
                    stats_totals[stat_idx] += value;
                }
            }
        }
    }

    println!("  Malloc calls: {}", stats_totals[0]);
    println!("  Calloc calls: {}", stats_totals[1]);
    println!("  Realloc calls: {}", stats_totals[2]);
    println!("  Aligned_alloc calls: {}", stats_totals[3]);
    println!("  Free calls: {}", stats_totals[4]);

    let total_alloc_calls = stats_totals[0] + stats_totals[1] + stats_totals[2] + stats_totals[3];
    println!("  Total allocation calls: {}", total_alloc_calls);

    // Event drop statistics
    let total_event_drops = stats_totals[5] + stats_totals[6] + stats_totals[7] + stats_totals[8];
    println!("  Event drops: {} (total)", total_event_drops);
    if total_event_drops > 0 {
        println!("    - Map full: {}", stats_totals[5]);
        println!("    - Invalid key: {}", stats_totals[6]);
        println!("    - Out of memory: {}", stats_totals[7]);
        println!("    - Other errors: {}", stats_totals[8]);
    }

    // Record drop statistics
    let total_record_drops =
        stats_totals[9] + stats_totals[10] + stats_totals[11] + stats_totals[12];
    println!("  Record drops: {} (total)", total_record_drops);
    if total_record_drops > 0 {
        println!("    - Map full: {}", stats_totals[9]);
        println!("    - Invalid key: {}", stats_totals[10]);
        println!("    - Out of memory: {}", stats_totals[11]);
        println!("    - Other errors: {}", stats_totals[12]);
    }

    println!("  Symbol failures: {}", stats_totals[13]);
    println!("  Active events: {}", stats_totals[14]);
    println!("  Active records: {}", stats_totals[15]);

    // Calculate map utilization
    let malloc_records = maps.malloc_records();
    let mut record_count = 0;
    for _key in malloc_records.keys() {
        record_count += 1;
    }

    let malloc_event_records = maps.malloc_event_records();
    let mut event_count = 0;
    for _key in malloc_event_records.keys() {
        event_count += 1;
    }

    println!("\n=== Map Utilization ===");
    println!(
        "  Event records: {}/{} ({:.1}%)",
        event_count,
        cli.max_events,
        (event_count as f64 / cli.max_events as f64) * 100.0
    );
    println!(
        "  Process records: {}/{} ({:.1}%)",
        record_count,
        cli.max_records,
        (record_count as f64 / cli.max_records as f64) * 100.0
    );

    let total_drops = total_event_drops + total_record_drops;
    if total_drops > 0 {
        println!("\n⚠️  WARNING: {} drops detected!", total_drops);
        if stats_totals[5] > 0 || stats_totals[9] > 0 {
            println!("   - Maps are full! Consider increasing --max-events or --max-records");
        }
        if stats_totals[7] > 0 || stats_totals[11] > 0 {
            println!("   - Out of memory detected! System may be under heavy load");
        }
        if stats_totals[6] > 0 || stats_totals[10] > 0 {
            println!("   - Key conflicts detected! This may indicate internal issues");
        }
        if stats_totals[8] > 0 || stats_totals[12] > 0 {
            println!("   - Other system errors detected");
        }
    }

    Ok(())
}

fn main() -> Result<(), JtraceError> {
    let mut cli = Cli::parse();
    let max_level = match cli.verbose {
        0 => LevelFilter::INFO,
        1 => LevelFilter::DEBUG,
        2 => LevelFilter::TRACE,
        _ => LevelFilter::OFF,
    };

    JloggerBuilder::new()
        .max_level(max_level)
        .log_runtime(false)
        .build();

    bump_memlock_rlimit();
    set_print(Some((PrintLevel::Debug, print_to_log)));

    // Validate configuration parameters
    if cli.max_stack_depth > 128 {
        return Err(Report::new(JtraceError::InvalidData)
            .attach_printable("max_stack_depth cannot exceed 128"));
    }

    let skel_builder = MallocFreeSkelBuilder::default();
    let mut open_skel = skel_builder
        .open()
        .map_err(|_| Report::new(JtraceError::BPFError))
        .attach_printable("Failed to open bpf")?;

    // Configure BPF map sizes before loading
    open_skel
        .maps_mut()
        .malloc_event_records()
        .set_max_entries(cli.max_events)
        .map_err(|_| Report::new(JtraceError::BPFError))
        .attach_printable("Failed to set malloc_event_records max_entries")?;

    open_skel
        .maps_mut()
        .malloc_records()
        .set_max_entries(cli.max_records)
        .map_err(|_| Report::new(JtraceError::BPFError))
        .attach_printable("Failed to set malloc_records max_entries")?;

    open_skel
        .maps_mut()
        .ptr_sequence()
        .set_max_entries(cli.max_events)
        .map_err(|_| Report::new(JtraceError::BPFError))
        .attach_printable("Failed to set ptr_sequence max_entries")?;

    // Set BPF runtime configuration variables
    // TODO: max_stack_depth configuration not exposed in skeleton
    // open_skel.bss().max_stack_depth = cli.max_stack_depth;

    if let Some(id) = cli.pid.as_ref() {
        let pid = tid_to_pid(*id).ok_or(
            Report::new(JtraceError::InvalidData)
                .attach_printable(format!("Could not convert TID {} to PID.", id)),
        )?;

        if *id != pid {
            jinfo!("Converted TID {} to PID {}", id, pid);
        }
        open_skel.bss().target_pid = pid;
    } else {
        open_skel.bss().target_pid = -1;
    }

    if cli.trace_path || cli.trace_full_path {
        if cli.trace_full_path {
            jwarn!("Tracing full malloc/free path, this may generate a lot of data and take a lot of time.");
        }
        open_skel.bss().trace_path = true;
    }

    let mut skel = open_skel
        .load()
        .map_err(|_| Report::new(JtraceError::BPFError))
        .attach_printable("Failed to load bpf")?;

    let mut links = vec![];
    let file = if let Some(path) = cli.libpath.take() {
        path
    } else if let Some(path) = find_libc_path() {
        path
    } else {
        return Err(Report::new(JtraceError::InvalidData).attach_printable(
            "Could not find libc.so.6. Please specify the path using -l or --libpath. Common paths include /lib/x86_64-linux-gnu/libc.so.6, /usr/lib/libc.so.6, or /lib/libc.so.6.",
        ));
    };

    let elf_file = ElfFile::new(&file).change_context(JtraceError::SymbolAnalyzerError)?;
    let malloc_offset = elf_file
        .find_addr("malloc")
        .change_context(JtraceError::SymbolAnalyzerError)? as usize;

    let calloc_offset = elf_file.find_addr("calloc").ok().map(|addr| addr as usize);
    let realloc_offset = elf_file.find_addr("realloc").ok().map(|addr| addr as usize);
    let aligned_alloc_offset = elf_file
        .find_addr("aligned_alloc")
        .ok()
        .map(|addr| addr as usize);

    let free_offset = elf_file
        .find_addr("free")
        .change_context(JtraceError::SymbolAnalyzerError)? as usize;

    /*
     * Parameter
     *  pid > 0: target process to trace
     *  pid == 0 : trace self
     *  pid == -1 : trace all processes
     * See bpf_program__attach_uprobe()
     */
    // Attach malloc probes
    links.push(
        skel.progs_mut()
            .uprobe_malloc()
            .attach_uprobe(false, -1, file.clone(), malloc_offset)
            .map_err(|_| Report::new(JtraceError::BPFError))
            .attach_printable("Failed to attach uprobe_malloc.".to_string())?,
    );

    links.push(
        skel.progs_mut()
            .uretprobe_malloc()
            .attach_uprobe(true, -1, file.clone(), malloc_offset)
            .map_err(|_| Report::new(JtraceError::BPFError))
            .attach_printable("Failed to attach uretprobe_malloc.".to_string())?,
    );

    // Attach calloc probes (if available)
    if let Some(offset) = calloc_offset {
        links.push(
            skel.progs_mut()
                .uprobe_calloc()
                .attach_uprobe(false, -1, file.clone(), offset)
                .map_err(|_| Report::new(JtraceError::BPFError))
                .attach_printable("Failed to attach uprobe_calloc.".to_string())?,
        );

        links.push(
            skel.progs_mut()
                .uretprobe_calloc()
                .attach_uprobe(true, -1, file.clone(), offset)
                .map_err(|_| Report::new(JtraceError::BPFError))
                .attach_printable("Failed to attach uretprobe_calloc.".to_string())?,
        );
        jinfo!("Attached calloc probes");
    } else {
        jwarn!(
            "calloc function not found in {}, skipping calloc tracing",
            file
        );
    }

    // Attach realloc probes (if available)
    if let Some(offset) = realloc_offset {
        links.push(
            skel.progs_mut()
                .uprobe_realloc()
                .attach_uprobe(false, -1, file.clone(), offset)
                .map_err(|_| Report::new(JtraceError::BPFError))
                .attach_printable("Failed to attach uprobe_realloc.".to_string())?,
        );

        links.push(
            skel.progs_mut()
                .uretprobe_realloc()
                .attach_uprobe(true, -1, file.clone(), offset)
                .map_err(|_| Report::new(JtraceError::BPFError))
                .attach_printable("Failed to attach uretprobe_realloc.".to_string())?,
        );
        jinfo!("Attached realloc probes");
    } else {
        jwarn!(
            "realloc function not found in {}, skipping realloc tracing",
            file
        );
    }

    // Attach aligned_alloc probes (if available)
    if let Some(offset) = aligned_alloc_offset {
        links.push(
            skel.progs_mut()
                .uprobe_aligned_alloc()
                .attach_uprobe(false, -1, file.clone(), offset)
                .map_err(|_| Report::new(JtraceError::BPFError))
                .attach_printable("Failed to attach uprobe_aligned_alloc.".to_string())?,
        );

        links.push(
            skel.progs_mut()
                .uretprobe_aligned_alloc()
                .attach_uprobe(true, -1, file.clone(), offset)
                .map_err(|_| Report::new(JtraceError::BPFError))
                .attach_printable("Failed to attach uretprobe_aligned_alloc.".to_string())?,
        );
        jinfo!("Attached aligned_alloc probes");
    } else {
        jwarn!(
            "aligned_alloc function not found in {}, skipping aligned_alloc tracing",
            file
        );
    }

    // Attach free probe
    links.push(
        skel.progs_mut()
            .uprobe_free()
            .attach_uprobe(false, -1, file.clone(), free_offset)
            .map_err(|_| Report::new(JtraceError::BPFError))
            .attach_printable("Failed to attach uprobe_free.".to_string())?,
    );

    let start = Instant::now();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::Release);
    })
    .map_err(|_| Report::new(JtraceError::UnExpected))?;

    if cli.duration > 0 {
        println!(
            "Tracing malloc() in {} for {} seconds, Type Ctrl-C to stop.",
            file, cli.duration
        );
    } else {
        println!("Tracing malloc() in {}... Type Ctrl-C to stop.", file);
    }

    while running.load(Ordering::Acquire) {
        std::thread::sleep(Duration::from_millis(100));

        if cli.duration > 0 {
            let passed = start.elapsed().as_millis() as u64;
            if passed > cli.duration * 1000 {
                break;
            }
        }
    }

    for mut l in links {
        l.disconnect();
        let _ = l.detach();
    }

    println!("Tracing finished, Processing data...");
    println!();

    if cli.show_stats {
        print_statistics(&cli, &mut skel.maps())?;
        println!();
    }

    process_events(&cli, &mut skel.maps())
}
