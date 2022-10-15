//cspell:word libbpf tracelib eglswapbuffers memlock rlimit skel libpath
//cspell:word tgid uprobe
#[allow(unused)]
use {
    anyhow::{Context, Error, Result},
    jlogger::{jdebug, jerror, jinfo, jwarn, JloggerBuilder},
    log::{debug, error, info, warn, LevelFilter},
};

use {
    clap::Parser,
    libbpf_rs::{set_print, MapFlags, PrintLevel},
    plain::Plain,
    std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    },
    tracelib::{bump_memlock_rlimit, bytes_to_string, ElfFile},
};

#[path = "bpf/eglswapbuffers.skel.rs"]
mod eglswapbuffers;

use eglswapbuffers::*;

type SwapEvent = eglswapbuffers_bss_types::swap_event;
unsafe impl Plain for SwapEvent {}

fn print_to_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => log::trace!("{}", msg.trim_matches('\n')),
        PrintLevel::Info => log::info!("{}", msg.trim_matches('\n')),
        PrintLevel::Warn => log::warn!("{}", msg.trim_matches('\n')),
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

    ///Show raw count
    #[clap(short = 'r', long)]
    raw: bool,

    ///Trace glXSwapBuffers()
    #[clap(short = 'g', long)]
    glx: bool,

    ///Only trace process with specified PID.
    #[clap(short = 'p', long)]
    pid: Option<i32>,

    ///Specify ligEGL path.
    #[clap(short = 'l', long)]
    libpath: Option<String>,
}

struct DurationCount {
    duration_ms: u32,
    count: u32,
}

fn log2_index(v: u32) -> usize {
    let fv = v as f32;
    fv.log2().floor() as usize
}

fn log2_value(i: usize) -> u32 {
    2_u32.pow(i as u32)
}

fn process_events(cli: &Cli, probe: &str, maps: &mut EglswapbuffersMaps) -> Result<()> {
    let swap_records = maps.swap_records();
    let mut hash_result = HashMap::new();

    for key in swap_records.keys() {
        if let Ok(Some(data)) = swap_records.lookup(&key, MapFlags::ANY) {
            let mut se = SwapEvent::default();
            plain::copy_from_bytes(&mut se, &key).expect("Corrupted event data");

            let mut count = 0_u32;
            plain::copy_from_bytes(&mut count, &data).expect("Corrupted event data");

            let entry = hash_result
                .entry((se.pid, se.tgid, se.comm))
                .or_insert(Vec::<DurationCount>::new());

            entry.push(DurationCount {
                duration_ms: se.duration_ms,
                count,
            });
        }
    }

    for (_, ((pid, tgid, comm_bytes), count_vec)) in hash_result.iter_mut().enumerate() {
        let comm = unsafe { bytes_to_string(comm_bytes.as_ptr()) };
        println!();
        println!("Probe: {}", probe);
        println!("TID:{} PID:{} Comm: {}", pid, tgid, comm);

        count_vec.sort_by(|a, b| a.duration_ms.partial_cmp(&b.duration_ms).unwrap());

        if cli.raw {
            let mut max_count = 0;

            for v in count_vec.iter() {
                if v.count > max_count {
                    max_count = v.count;
                }
            }

            for (_i, v) in count_vec.iter().enumerate() {
                print!("{:8}ms {:5}|", v.duration_ms, v.count);
                println!("{}", "*".repeat((v.count * 60 / max_count) as usize));
            }
        } else {
            let max = log2_index(count_vec.last().unwrap().duration_ms);
            let mut counts = vec![0; max + 1];

            let mut min_index = max;
            let mut max_count = 0;
            for v in count_vec.iter() {
                let index = log2_index(v.duration_ms);

                if index < min_index {
                    min_index = index;
                }

                counts[index] += v.count;
                if counts[index] > max_count {
                    max_count = counts[index];
                }
            }

            for (i, v) in counts.iter().enumerate() {
                if i < min_index {
                    continue;
                }

                print!(
                    "{:<20}  {:5}|",
                    format!("[{},{})", log2_value(i), log2_value(i + 1)),
                    v
                );
                println!("{}", "*".repeat((v * 60 / max_count) as usize));
            }
        }

        println!();
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let max_level = match cli.verbose {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        2 => log::LevelFilter::Trace,
        _ => log::LevelFilter::Off,
    };

    JloggerBuilder::new()
        .max_level(max_level)
        .log_time(false)
        .log_runtime(false)
        .build();

    bump_memlock_rlimit();

    let skel_builder = EglswapbuffersSkelBuilder::default();

    set_print(Some((PrintLevel::Debug, print_to_log)));

    let mut open_skel = skel_builder.open().with_context(|| "Failed to open bpf.")?;

    if let Some(pid) = cli.pid {
        open_skel.bss().target_pid = pid;
    } else {
        open_skel.bss().target_pid = -1;
    }

    let mut skel = open_skel.load().with_context(|| "Failed to load bpf.")?;

    let mut links = vec![];
    let mut dir = String::from("/usr/lib/");

    if let Some(a) = cli.libpath.as_ref() {
        dir = a.to_string();
    }

    let file;
    let probe;

    if cli.glx {
        probe = "glXSwapBuffers";
        file = format!("{}/libGL.so.1", dir);
    } else {
        probe = "eglSwapBuffers";
        file = format!("{}/libEGL.so.1", dir);
    }

    let elf_file = ElfFile::new(&file)?;
    let offset = elf_file.find_addr(probe)? as usize;
    /*
     * Parameter
     *  pid > 0: target process to trace
     *  pid == 0 : trace self
     *  pid == -1 : trace all processes
     * See bpf_program__attach_uprobe()
     */
    let link = skel
        .progs_mut()
        .swap_trace()
        .attach_uprobe(false, -1, file.clone(), offset)
        .with_context(|| "Failed to attach eglSwapBuffers().")?;

    links.push(link);

    let start = Instant::now();
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    if cli.duration > 0 {
        println!(
            "Tracing {}:{} for {} seconds, Type Ctrl-C to stop.",
            file, probe, cli.duration
        );
    } else {
        println!("Tracing {}:{} ... Type Ctrl-C to stop.", file, probe);
    }

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));

        if cli.duration > 0 {
            let passed = start.elapsed().as_millis() as u64;
            if passed > cli.duration * 1000 {
                break;
            }
        }
    }

    println!("Tracing finished, Processing data...");

    process_events(&cli, &probe, &mut skel.maps())?;
    Ok(())
}
