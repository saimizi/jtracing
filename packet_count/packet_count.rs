#[allow(unused)]
use {
    byteorder::NativeEndian,
    clap::Parser,
    default_net::{gateway, interface},
    error_stack::{IntoReport, Report, Result, ResultExt},
    jlogger_tracing::{
        jdebug, jerror, jinfo, jtrace, jwarn, JloggerBuilder, LevelFilter, LogTimeFormat,
    },
    libbpf_rs::{
        set_print,
        skel::{OpenSkel, Skel, SkelBuilder},
        MapFlags, PrintLevel, RingBufferBuilder,
    },
    plain::Plain,
    std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        thread::{self},
        time::{Duration, Instant},
    },
    tracelib::{bump_memlock_rlimit, bytes_to_string, JtraceError},
};

#[path = "bpf/packet_count.skel.rs"]
mod packet_count;
use byteorder::ByteOrder;
use packet_count::*;

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
    #[clap(short, long)]
    duration: Option<u64>,

    ///Verbose
    #[clap(short, long, parse(from_occurrences))]
    verbose: usize,

    ///Show exit trace.
    #[clap(short, long)]
    ifname: Vec<String>,
}

type PacketInfo = packet_count_bss_types::packet_info;
unsafe impl Plain for PacketInfo {}

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

    let skel_builder = PacketCountSkelBuilder::default();
    set_print(Some((PrintLevel::Debug, print_to_log)));

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

    let mut links = vec![];
    let mut ifnames = vec![];

    for i in interface::get_interfaces() {
        if cli.ifname.iter().any(|a| a == &i.name) {
            ifnames.push(i.name);
            links.push(
                skel.progs_mut()
                    .xdp_stats_func()
                    .attach_xdp(i.index as i32)
                    .into_report()
                    .change_context(JtraceError::BPFError)
                    .attach_printable("Failed to attach xdp program")?,
            );
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::Release);
    })
    .into_report()
    .change_context(JtraceError::IOError)?;

    let timeout = Duration::from_secs(cli.duration.clone().unwrap_or(u64::MAX));
    let start = Instant::now();

    if cli.duration.is_some() {
        jinfo!(
            "Tracing {} for {} secondes...",
            ifnames.join(","),
            cli.duration.clone().unwrap()
        );
    } else {
        jinfo!("Tracing {}...", ifnames.join(","));
    }

    while running.load(Ordering::Acquire) {
        thread::sleep(Duration::from_millis(500));
        if start.elapsed() > timeout {
            break;
        }
    }

    let time = start.elapsed().as_secs();

    for link in links {
        link.detach()
            .into_report()
            .change_context(JtraceError::BPFError)?;
    }

    let binding = skel.maps();
    let maps = binding.xdp_stats_map();
    let mut no = 0;

    println!();
    println!(
        "{:8} {:9} {:8} {:8} Interface",
        "No", "Rx.packet", "Rx.bytes", "BPS"
    );
    for key in maps.keys() {
        let index = NativeEndian::read_u32(&key);
        if let Some(ifname) = interface::get_interfaces().into_iter().find_map(|i| {
            if i.index == index {
                Some(i.name)
            } else {
                None
            }
        }) {
            if let Ok(Some(data)) = maps.lookup_percpu(&key, MapFlags::ANY) {
                no += 1;
                let mut rx_packets = 0;
                let mut rx_bytes = 0;

                for d in &data {
                    let mut pi = PacketInfo::default();
                    if let Err(_) = plain::copy_from_bytes(&mut pi, d) {
                        return Err(JtraceError::InvalidData)
                            .into_report()
                            .change_context(JtraceError::InvalidData);
                    }

                    rx_packets += pi.rx_packets;
                    rx_bytes += pi.rx_bytes;
                }

                println!(
                    "{:<8} {:<9} {:<8} {:<8} {}",
                    no,
                    rx_packets,
                    rx_bytes,
                    rx_bytes / time,
                    ifname
                );
            }
        }
    }

    Ok(())
}
