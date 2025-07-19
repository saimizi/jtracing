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
    std::error::Error,
    std::{
        collections::HashMap,
        io::Cursor,
        mem,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    },
    tracelib::{bump_memlock_rlimit, bytes_to_string, ElfFile, ExecMap, JtraceError},
};

#[path = "bpf/malloc_free.skel.rs"]
mod malloc_free;
use malloc_free::*;

type MallocRecord = malloc_free_bss_types::malloc_record;
unsafe impl Plain for MallocRecord {}

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
}

fn process_events(cli: &Cli, maps: &mut MallocFreeMaps) -> Result<(), JtraceError> {
    let malloc_records = maps.malloc_records();

    println!(
        "{:<4} {:<8} {:<8} {:<8} {:<8} {:<10} {:<8} Comm",
        "No", "PID", "Alloc", "Free", "Real", "Real.max", "Req.max"
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
                "{:<4} {:<8} {:<8} {:<8} {:<8} {:<10} {:<8} {}",
                idx,
                mr.pid,
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

    let skel_builder = MallocFreeSkelBuilder::default();
    let mut open_skel = skel_builder
        .open()
        .map_err(|_| Report::new(JtraceError::BPFError))
        .attach_printable("Failed to open bpf")?;

    if let Some(pid) = cli.pid {
        open_skel.bss().target_pid = pid;
    } else {
        open_skel.bss().target_pid = -1;
    }

    let mut skel = open_skel
        .load()
        .map_err(|_| Report::new(JtraceError::BPFError))
        .attach_printable("Failed to load bpf")?;

    let mut links = vec![];
    let file = format!(
        "{}/libc.so.6",
        cli.libpath.take().unwrap_or("/lib".to_string())
    );

    let elf_file = ElfFile::new(&file).change_context(JtraceError::SymbolAnalyzerError)?;
    let malloc_offset = elf_file
        .find_addr("malloc")
        .change_context(JtraceError::SymbolAnalyzerError)? as usize;

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
    process_events(&cli, &mut skel.maps())
}
