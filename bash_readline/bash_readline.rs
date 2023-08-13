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
    tracelib::{bump_memlock_rlimit, bytes_to_string, ElfFile, JtraceError},
};

#[path = "bpf/bash_readline.skel.rs"]
mod bash_readline;
use std::time::Instant;

use bash_readline::*;
use error_stack::IntoReport;

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
    #[clap(short, long)]
    duration: Option<u64>,

    ///Verbose
    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,
}

type ReadLine = bash_readline_bss_types::read_line;
unsafe impl Plain for ReadLine {}

fn main() -> Result<(), JtraceError> {
    let cli = Cli::parse();
    let max_level = match cli.verbose {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    JloggerBuilder::new()
        .max_level(max_level)
        .log_runtime(false)
        .build();

    bump_memlock_rlimit();

    set_print(Some((PrintLevel::Debug, print_to_log)));

    let skel_builder = BashReadlineSkelBuilder::default();
    let open_skel = skel_builder
        .open()
        .into_report()
        .change_context(JtraceError::IOError)
        .attach_printable("Failed to open bpf.")?;

    let mut skel = open_skel
        .load()
        .into_report()
        .change_context(JtraceError::IOError)
        .attach_printable("Failed to load bpf")?;

    let handle_event = move |data: &[u8]| -> i32 {
        let mut event = ReadLine::default();
        plain::copy_from_bytes(&mut event, data).expect("Corrupted event data");
        let para = unsafe { bytes_to_string(event.para.as_ptr()) };

        let now = chrono::Local::now();
        println!(
            "{:<20} {:<8} {}",
            now.format("%Y-%m-%d %H:%M:%S"),
            event.pid,
            para
        );

        0
    };

    let mut rbuilder = RingBufferBuilder::new();
    let map = skel.maps();
    rbuilder
        .add(map.rb(), handle_event)
        .into_report()
        .change_context(JtraceError::IOError)?;
    let ringbuf = rbuilder
        .build()
        .into_report()
        .change_context(JtraceError::IOError)
        .attach_printable("Failed to create ring buffer")?;

    let elf = ElfFile::new("/bin/bash").change_context(JtraceError::SymbolAnalyzerError)?;

    let offset = elf
        .find_addr("readline")
        .change_context(JtraceError::SymbolAnalyzerError)?;

    jdebug!("addr: {:x}", offset);
    println!("{:<20} {:<8} Bash command", "Time", "PID");

    let mut link = skel
        .progs_mut()
        .uretprobe_readline()
        .attach_uprobe(true, -1, "/bin/bash", offset as usize)
        .into_report()
        .change_context(JtraceError::IOError)
        .attach_printable("Failed to attach uprobe")?;

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::Release);
    })
    .into_report()
    .change_context(JtraceError::IOError)?;

    let timeout = std::time::Duration::from_secs(cli.duration.unwrap_or(u64::MAX));
    let start = Instant::now();
    while running.load(Ordering::Acquire) {
        let _ = ringbuf.poll(std::time::Duration::from_millis(100));
        if start.elapsed() > timeout {
            break;
        }
    }

    link.disconnect();

    Ok(())
}
