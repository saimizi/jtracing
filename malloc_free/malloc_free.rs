#[allow(unused)]
use {
    byteorder::{NativeEndian, ReadBytesExt, WriteBytesExt},
    clap::Parser,
    error_stack::{IntoReport, Result, ResultExt},
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

type MallocEvent = malloc_free_bss_types::malloc_event;
unsafe impl Plain for MallocEvent {}

type MallocMax = malloc_free_bss_types::malloc_max;
unsafe impl Plain for MallocMax {}

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

    ///Show call path for max-size malloc() call.
    #[clap(short, long)]
    max_malloc_path: bool,

    ///Only trace process with specified PID.
    #[clap(short = 'p', long)]
    pid: Option<i32>,

    ///Specify ligEGL path.
    #[clap(short = 'l', long)]
    libpath: Option<String>,
}

#[derive(Default)]
struct MallocResult {
    comm: String,
    total: u32,
    max: u32,
    ustack: Vec<u64>,
    ustack_sz: usize,
}

fn process_events(cli: &Cli, maps: &mut MallocFreeMaps) -> Result<(), JtraceError> {
    let malloc_records = maps.malloc_records();
    let malloc_max = maps.malloc_max_record();
    let mut hash_result = HashMap::new();

    for key in malloc_records.keys() {
        if let Ok(Some(data)) = malloc_records.lookup(&key, MapFlags::ANY) {
            let mut me = MallocEvent::default();
            plain::copy_from_bytes(&mut me, &data).expect("Corrupted event data");

            let mut mr = hash_result.entry(me.pid).or_insert_with(|| MallocResult {
                comm: unsafe { bytes_to_string(me.comm.as_ptr()) },
                ..Default::default()
            });

            mr.total += me.size;

            let mut key = vec![];
            key.write_u32::<NativeEndian>(me.pid)
                .into_report()
                .change_context(JtraceError::InvalidData)?;
            if let Ok(Some(m)) = malloc_max.lookup(&key, MapFlags::ANY) {
                let mut m_max = MallocMax::default();
                plain::copy_from_bytes(&mut m_max, &m).expect("Corrupted event data");
                mr.max = m_max.max;

                mr.ustack_sz = (m_max.ustack_sz / 8) as usize;
                mr.ustack = m_max.ustack[..mr.ustack_sz]
                    .into_iter()
                    .map(|a| *a)
                    .collect();
            }
        }
    }

    println!("{:4} {:8} {:8} {:8} Comm", "No", "PID", "Total", "Max");
    for (idx, (pid, mr)) in hash_result.iter_mut().enumerate() {
        println!(
            "{:<4} {:<8} {:<8} {:<8} {}",
            idx + 1,
            pid,
            mr.total,
            mr.max,
            mr.comm
        );

        if cli.max_malloc_path {
            println!("    ----");
            if let Ok(mut em) = ExecMap::new(*pid) {
                for addr in &mr.ustack {
                    let (offset, symbol, file) = em.symbol(*addr).unwrap_or((
                        0,
                        "[unknown]".to_string(),
                        "unknown".to_string(),
                    ));
                    println!("    {:x}(+{})  {} {}", addr, offset, symbol, file);
                }
            } else {
                println!("    No map found.");
            }
        }

        println!();
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
        .into_report()
        .change_context(JtraceError::BPFError)
        .attach_printable("Failed to open bpf")?;

    if let Some(pid) = cli.pid {
        open_skel.bss().target_pid = pid;
    } else {
        open_skel.bss().target_pid = -1;
    }

    let mut skel = open_skel
        .load()
        .into_report()
        .change_context(JtraceError::BPFError)
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
            .into_report()
            .change_context(JtraceError::SymbolAnalyzerError)
            .attach_printable("Failed to attach eglSwapBuffers().".to_string())?,
    );

    links.push(
        skel.progs_mut()
            .uretprobe_malloc()
            .attach_uprobe(true, -1, file.clone(), malloc_offset)
            .into_report()
            .change_context(JtraceError::SymbolAnalyzerError)
            .attach_printable("Failed to attach eglSwapBuffers().".to_string())?,
    );

    links.push(
        skel.progs_mut()
            .uprobe_free()
            .attach_uprobe(false, -1, file.clone(), free_offset)
            .into_report()
            .change_context(JtraceError::SymbolAnalyzerError)
            .attach_printable("Failed to attach eglSwapBuffers().".to_string())?,
    );

    let start = Instant::now();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::Release);
    })
    .into_report()
    .change_context(JtraceError::UnExpected)?;

    if cli.duration > 0 {
        println!(
            "Tracing {} for {} seconds, Type Ctrl-C to stop.",
            file, cli.duration
        );
    } else {
        println!("Tracing {}... Type Ctrl-C to stop.", file);
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
    process_events(&cli, &mut skel.maps())
}
