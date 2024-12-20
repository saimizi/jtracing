#[allow(unused)]
use {
    byteorder::NativeEndian,
    clap::Parser,
    default_net::{gateway, interface},
    error_stack::{Report, Result, ResultExt},
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
    #[clap(short, long, action=clap::ArgAction::Count)]
    verbose: u8,

    ///Show exit trace.
    #[clap(short, long)]
    if_name: Vec<String>,
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
        .map_err(|_| Report::new(JtraceError::IOError))
        .attach_printable("Failed to open bpf.")?;

    let mut skel = open_skel
        .load()
        .map_err(|_| Report::new(JtraceError::IOError))
        .attach_printable("Failed to load bpf")?;

    let mut links = vec![];
    let mut if_names = vec![];

    for i in interface::get_interfaces() {
        if cli.if_name.is_empty() {
            if let Ok(l) = skel
                .progs_mut()
                .xdp_stats_func1()
                .attach_xdp(i.index as i32)
            {
                links.push(l);
            }
        } else if cli.if_name.iter().any(|a| a == &i.name) {
            if_names.push(i.name);
            links.push(
                skel.progs_mut()
                    .xdp_stats_func2()
                    .attach_xdp(i.index as i32)
                    .map_err(|_| Report::new(JtraceError::BPFError))
                    .attach_printable("Failed to attach xdp program")?,
            );
        }
    }

    if !cli.if_name.is_empty() && if_names.is_empty() {
        jinfo!("No valid interface found.");
        return Ok(());
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::Release);
    })
    .map_err(|_| Report::new(JtraceError::IOError))?;

    let timeout = Duration::from_secs(cli.duration.unwrap_or(u64::MAX));
    let start = Instant::now();

    if cli.duration.is_some() {
        jinfo!(
            "Tracing {} for {} secondes...",
            if_names.join(","),
            cli.duration.unwrap()
        );
    } else {
        jinfo!("Tracing {}...", if_names.join(","));
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
            .map_err(|_| Report::new(JtraceError::BPFError))?;
    }

    let binding = skel.maps();
    let maps = binding.xdp_stats_map();
    let mut no = 0;

    println!();
    if cli.if_name.is_empty() {
        println!(
            "{:8} {:9} {:8} {:8} Src.ip",
            "No", "Rx.packet", "Rx.bytes", "BPS"
        );
    } else {
        println!(
            "{:8} {:9} {:8} {:8} Interface",
            "No", "Rx.packet", "Rx.bytes", "BPS"
        );
    }

    for key in maps.keys() {
        if let Ok(Some(data)) = maps.lookup_percpu(&key, MapFlags::ANY) {
            no += 1;
            let mut rx_packets = 0;
            let mut rx_bytes = 0;

            for d in &data {
                let mut pi = PacketInfo::default();
                if plain::copy_from_bytes(&mut pi, d).is_err() {
                    return Err(Report::new(JtraceError::InvalidData));
                }

                rx_packets += pi.rx_packets;
                rx_bytes += pi.rx_bytes;
            }

            if !cli.if_name.is_empty() {
                let if_index = NativeEndian::read_u32(&key);
                let interfaces = interface::get_interfaces();
                let i = interfaces
                    .iter()
                    .find(|&i| i.index == if_index)
                    .ok_or(Report::new(JtraceError::InvalidData))?;
                println!(
                    "{:<8} {:<9} {:<8} {:<8} {}",
                    no,
                    rx_packets,
                    rx_bytes,
                    rx_bytes / time,
                    i.name,
                );
            } else {
                let ip = key
                    .iter()
                    .map(|&d| d.to_string())
                    .collect::<Vec<String>>()
                    .join(".");

                println!(
                    "{:<8} {:<9} {:<8} {:<8} {}",
                    no,
                    rx_packets,
                    rx_bytes,
                    rx_bytes / time,
                    ip
                );
            }
        }
    }

    Ok(())
}
