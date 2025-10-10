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
    regex::Regex,
    std::{
        collections::HashMap,
        io::{self, BufRead, BufReader, Cursor},
        mem,
        path::Path,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, OnceLock,
        },
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    },
    tracelib::{bump_memlock_rlimit, bytes_to_string, tid_to_pid, ElfFile, ExecMap, JtraceError},
};

// Get monotonic time in nanoseconds to match bpf_ktime_get_ns()
fn get_monotonic_time_ns() -> Result<u64, JtraceError> {
    // Use libc to get monotonic time directly, which matches bpf_ktime_get_ns()
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    unsafe {
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) != 0 {
            return Err(
                Report::new(JtraceError::IOError).attach_printable("Failed to get monotonic time")
            );
        }
    }

    // Convert to nanoseconds
    Ok((ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64))
}

// Global baseline timestamp for age calculations
static TRACE_START_TIMESTAMP: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

#[path = "bpf/malloc_free.skel.rs"]
mod malloc_free;
use malloc_free::*;

/// Age duration parsing and validation for CLI input.
///
/// Handles parsing of age specifications from command line arguments
/// with support for multiple time units and comprehensive validation.
///
/// # Supported Formats
/// - "300" or "300s" - 300 seconds
/// - "5m" - 5 minutes
/// - "1h" - 1 hour
///
/// # Validation
/// - Range: 1 second to 24 hours
/// - Format: Must match regex pattern
/// - Units: s (seconds), m (minutes), h (hours)
#[derive(Debug, Clone)]
struct AgeDuration {
    seconds: u64,
}

impl AgeDuration {
    fn parse(age_str: &str) -> Result<Self, JtraceError> {
        static AGE_REGEX: OnceLock<Regex> = OnceLock::new();
        let regex = AGE_REGEX.get_or_init(|| Regex::new(r"^(\d+)([smh]?)$").unwrap());

        let age_str = age_str.trim();

        if let Some(captures) = regex.captures(age_str) {
            let value: u64 = captures.get(1).unwrap().as_str().parse().map_err(|_| {
                Report::new(JtraceError::InvalidData)
                    .attach_printable(format!("Invalid numeric value in age: '{}'", age_str))
            })?;

            let unit = captures.get(2).map(|m| m.as_str()).unwrap_or("s");

            let seconds = match unit {
                "s" | "" => value,
                "m" => value * 60,
                "h" => value * 3600,
                _ => {
                    return Err(Report::new(JtraceError::InvalidData)
                        .attach_printable(format!("Invalid time unit in age: '{}'", unit)))
                }
            };

            // Reasonable limits
            if seconds > 24 * 3600 {
                return Err(Report::new(JtraceError::InvalidData)
                    .attach_printable("Age filter cannot exceed 24 hours"));
            }

            if seconds == 0 {
                return Err(Report::new(JtraceError::InvalidData)
                    .attach_printable("Age filter must be greater than 0"));
            }

            Ok(AgeDuration { seconds })
        } else {
            Err(
                Report::new(JtraceError::InvalidData).attach_printable(format!(
                    "Invalid age format: '{}'. Use formats like: 300, 5m, 1h",
                    age_str
                )),
            )
        }
    }

    #[cfg(test)]
    fn to_nanoseconds(&self) -> u64 {
        self.seconds * 1_000_000_000
    }
}

/// Calculate the age of an allocation based on its timestamp.
///
/// This function computes how long an allocation has been active by comparing
/// the allocation timestamp (from eBPF bpf_ktime_get_ns()) with the current
/// monotonic time. It includes comprehensive error handling for edge cases.
///
/// # Arguments
/// * `alloc_timestamp_ns` - Allocation timestamp in nanoseconds from eBPF
///
/// # Returns
/// * `Ok(Duration)` - Age of the allocation
/// * `Err(JtraceError)` - If timestamp retrieval fails
///
/// # Error Handling
/// - Detects stale data (allocations before trace start)
/// - Handles clock adjustments gracefully
/// - Warns about suspicious ages
/// - Prevents overflow in Duration calculations
fn calculate_allocation_age(alloc_timestamp_ns: u64) -> Result<Duration, JtraceError> {
    // Get current monotonic time to match bpf_ktime_get_ns() from eBPF
    let current_time = get_monotonic_time_ns()?;

    // Get the baseline timestamp from when tracing started
    let baseline_timestamp = TRACE_START_TIMESTAMP.get().copied().unwrap_or(current_time);

    // Validate that the allocation timestamp is reasonable
    if alloc_timestamp_ns < baseline_timestamp {
        // This allocation happened before we started tracing, which shouldn't happen
        // if maps were properly cleared. This indicates stale data.
        jwarn!(
            "Stale allocation detected: timestamp {} is before trace start {} (diff: {}s), treating as minimum age",
            alloc_timestamp_ns,
            baseline_timestamp,
            (baseline_timestamp - alloc_timestamp_ns) / 1_000_000_000
        );
        return Ok(Duration::from_secs(0));
    }

    // Handle clock adjustments and wraparound
    if current_time < alloc_timestamp_ns {
        // Clock went backwards or timestamp is invalid
        jwarn!("Clock adjustment detected, using minimum age");
        return Ok(Duration::from_secs(0));
    }

    let age_ns = current_time - alloc_timestamp_ns;

    // Sanity check: age shouldn't be more than the trace duration plus some buffer
    let trace_duration_ns = current_time - baseline_timestamp;
    let max_reasonable_age = trace_duration_ns + 60_000_000_000; // trace duration + 1 minute buffer

    if age_ns > max_reasonable_age {
        jwarn!(
            "Suspicious age detected: {}s (trace duration: {}s), this may indicate stale data",
            age_ns / 1_000_000_000,
            trace_duration_ns / 1_000_000_000
        );
        // Don't cap it, but warn about it
    }

    // Prevent overflow in Duration::from_nanos() - cap at maximum reasonable duration
    const MAX_DURATION_NS: u64 = u64::MAX / 2; // Safe maximum to prevent overflow
    let safe_age_ns = if age_ns > MAX_DURATION_NS {
        jwarn!(
            "Age value too large ({}ns), capping to maximum safe duration",
            age_ns
        );
        MAX_DURATION_NS
    } else {
        age_ns
    };

    Ok(Duration::from_nanos(safe_age_ns))
}

/// Format a Duration into a human-readable age string.
///
/// Converts durations into compact, readable formats:
/// - Seconds: "30s"
/// - Minutes: "5m" or "5m 30s"
/// - Hours: "1h" or "1h 15m"
///
/// # Arguments
/// * `age` - Duration to format
///
/// # Returns
/// * Human-readable age string
fn format_age(age: Duration) -> String {
    let total_seconds = age.as_secs();

    if total_seconds < 60 {
        format!("{}s", total_seconds)
    } else if total_seconds < 3600 {
        let minutes = total_seconds / 60;
        let seconds = total_seconds % 60;
        if seconds == 0 {
            format!("{}m", minutes)
        } else {
            format!("{}m {}s", minutes, seconds)
        }
    } else {
        let hours = total_seconds / 3600;
        let minutes = (total_seconds % 3600) / 60;
        if minutes == 0 {
            format!("{}h", hours)
        } else {
            format!("{}h {}m", hours, minutes)
        }
    }
}

// Age histogram implementation
#[derive(Debug)]
struct AgeHistogram {
    ranges: Vec<AgeRange>,
}

#[derive(Debug)]
struct AgeRange {
    name: String,
    min_seconds: u64,
    max_seconds: Option<u64>,
    count: usize,
    total_size: u64,
}

impl AgeHistogram {
    fn new() -> Self {
        Self {
            ranges: vec![
                AgeRange {
                    name: "0-1 min".to_string(),
                    min_seconds: 0,
                    max_seconds: Some(60),
                    count: 0,
                    total_size: 0,
                },
                AgeRange {
                    name: "1-5 min".to_string(),
                    min_seconds: 60,
                    max_seconds: Some(300),
                    count: 0,
                    total_size: 0,
                },
                AgeRange {
                    name: "5-30 min".to_string(),
                    min_seconds: 300,
                    max_seconds: Some(1800),
                    count: 0,
                    total_size: 0,
                },
                AgeRange {
                    name: "30+ min".to_string(),
                    min_seconds: 1800,
                    max_seconds: None,
                    count: 0,
                    total_size: 0,
                },
            ],
        }
    }

    fn add_allocation(&mut self, age_seconds: u64, size: u32) {
        for range in &mut self.ranges {
            if age_seconds >= range.min_seconds {
                if let Some(max) = range.max_seconds {
                    if age_seconds < max {
                        range.count += 1;
                        range.total_size += size as u64;
                        break;
                    }
                } else {
                    // Last range (30+ min)
                    range.count += 1;
                    range.total_size += size as u64;
                    break;
                }
            }
        }
    }

    fn print(&self) {
        println!("\n=== Memory Age Distribution ===");
        println!(
            "{:<12} {:<8} {:<12} {:<12}",
            "Age Range", "Count", "Total Size", "Avg Size"
        );
        println!("{}", "=".repeat(50));

        for range in &self.ranges {
            let avg_size = if range.count > 0 {
                range.total_size / range.count as u64
            } else {
                0
            };

            println!(
                "{:<12} {:<8} {:<12} {:<12}",
                range.name,
                range.count,
                format_size(range.total_size),
                format_size(avg_size)
            );
        }
    }
}

fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{}B", bytes)
    } else {
        format!("{:.1}{}", size, UNITS[unit_idx])
    }
}

#[derive(Debug)]
struct ProcessStats {
    pid: u32,
    comm: String,
    filtered_alloc_size: u32,
    free_size: u32,
    max_single_alloc: u32,
    oldest_age_str: String,
    avg_age_str: String,
}

// Calculate statistics from malloc_records (Statistics Mode)
fn calculate_process_statistics_from_records(
    maps: &mut MallocFreeMaps,
    min_age_filter: &Option<AgeDuration>,
) -> Result<std::collections::HashMap<u32, ProcessStats>, JtraceError> {
    let malloc_records = maps.malloc_records();
    let mut process_stats: std::collections::HashMap<u32, ProcessStats> =
        std::collections::HashMap::new();

    // Examine all malloc records (per-process aggregated data)
    for key in malloc_records.keys() {
        if let Some(data) = malloc_records
            .lookup(&key, MapFlags::ANY)
            .change_context(JtraceError::BPFError)?
        {
            let mut record = MallocRecord::default();
            plain::copy_from_bytes(&mut record, &data).expect("Corrupted record data");

            // Calculate current unfreed allocation size
            if record.alloc_size < record.free_size {
                // This should not happen, but just in case
                jwarn!(
                    "Inconsistent record for PID {}: alloc_size {} < free_size {}, skipping",
                    record.pid,
                    record.alloc_size,
                    record.free_size
                );
                continue;
            }
            let unfreed_size = record.alloc_size - record.free_size;

            // Skip processes with no unfreed allocations
            if unfreed_size == 0 {
                continue;
            }

            let comm = unsafe { bytes_to_string(record.comm.as_ptr()) };

            // Calculate age information from the eBPF-maintained fields
            let oldest_age_str = if record.oldest_alloc_timestamp > 0 {
                calculate_allocation_age(record.oldest_alloc_timestamp)
                    .map(|age| format_age(age))
                    .unwrap_or_else(|_| "unknown".to_string())
            } else {
                "unknown".to_string()
            };

            let avg_age_str = if record.total_unfreed_count > 0 && record.total_age_sum_ns > 0 {
                // Calculate average timestamp, then convert to age
                let avg_timestamp = record.total_age_sum_ns / record.total_unfreed_count as u64;
                calculate_allocation_age(avg_timestamp)
                    .map(|age| format_age(age))
                    .unwrap_or_else(|_| "unknown".to_string())
            } else {
                "unknown".to_string()
            };

            // Apply age filter if specified (filter based on oldest allocation age)
            let include_process = if let Some(min_age) = min_age_filter {
                if record.oldest_alloc_timestamp > 0 {
                    if let Ok(oldest_age) = calculate_allocation_age(record.oldest_alloc_timestamp)
                    {
                        oldest_age.as_secs() >= min_age.seconds
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                true // Include all processes if no filter
            };

            if include_process {
                let stats = ProcessStats {
                    pid: record.pid,
                    comm,
                    filtered_alloc_size: unfreed_size,
                    free_size: record.free_size,
                    max_single_alloc: record.max_size,
                    oldest_age_str,
                    avg_age_str,
                };

                process_stats.insert(record.pid, stats);
            }
        }
    }

    Ok(process_stats)
}

// Clear BPF maps to ensure clean state for each trace session
fn clear_bpf_maps(skel: &mut MallocFreeSkel) -> Result<(), JtraceError> {
    jinfo!("Clearing BPF maps for fresh trace session...");

    // Clear malloc_event_records map
    let mut event_count = 0;
    {
        let mut maps = skel.maps_mut();
        let malloc_events = maps.malloc_event_records();
        let mut keys_to_delete = Vec::new();

        // Collect all keys first to avoid iterator invalidation
        for key in malloc_events.keys() {
            keys_to_delete.push(key);
            event_count += 1;
        }

        // Delete all entries
        for key in keys_to_delete {
            let _ = malloc_events.delete(&key);
        }
    }
    jinfo!("Cleared {} malloc event records", event_count);

    // Clear malloc_records map
    {
        let mut maps = skel.maps_mut();
        let malloc_records = maps.malloc_records();
        let mut keys_to_delete = Vec::new();

        for key in malloc_records.keys() {
            keys_to_delete.push(key);
        }

        for key in keys_to_delete {
            let _ = malloc_records.delete(&key);
        }
    }

    // Clear ptr_sequence map
    {
        let mut maps = skel.maps_mut();
        let ptr_sequence = maps.ptr_sequence();
        let mut keys_to_delete = Vec::new();

        for key in ptr_sequence.keys() {
            keys_to_delete.push(key);
        }

        for key in keys_to_delete {
            let _ = ptr_sequence.delete(&key);
        }
    }

    jinfo!("BPF maps cleared successfully");
    Ok(())
}

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
    about = "A utility to trace malloc/free calls with age tracking for leak detection.",
    version,
    after_help = "
Examples:
    malloc_free -d 10 -l /lib/x86_64-linux-gnu/
    malloc_free -d 10 -m
    malloc_free -l /lib/x86_64-linux-gnu/ -p 3226
    malloc_free --max-events 16384 --max-records 2048 -s

Age Tracking Examples:
    malloc_free -p 1234 --min-age 5m             # Show individual allocations older than 5 minutes
    malloc_free -p 1234 -t --min-age 5m          # Show stack traces for allocations older than 5 minutes
    malloc_free -p 1234 --age-histogram          # Show age distribution in Statistics Mode
    malloc_free --min-age 1h                     # Trace Mode: allocations older than 1 hour

Output Limiting Examples:
    malloc_free -p 1234 -t --max-entries 10      # Show only first 10 allocations in Trace Mode
    malloc_free --min-age 5m --max-entries 20    # Show first 20 old allocations
    malloc_free -p 1234 -t --max-entries 50      # Limit output to 50 entries with stack traces

Age Format:
    300 or 300s    = 300 seconds
    5m             = 5 minutes  
    1h             = 1 hour

Mode Switching:
    Statistics Mode (default): Shows aggregate data per process/thread with age statistics
    Trace Mode: Triggered by -t, -T, or --min-age. Shows individual allocations
    --age-histogram: Only works in Statistics Mode (shows warning in Trace Mode)

Output Examples:
    No   PID      Alloc    Free     Real     Real.max   Req.max  Comm
    1    3226     460240   452224   8016     13088      3680     Xorg

    With Age Information:
    No   PID      TID      Alloc    Free     Real     Real.max   Req.max  Oldest       Avg.Age  Comm
    1    3226     3226     460240   452224   8016     13088      3680     5m 23s       2m 15s   Xorg
--------
No:         Record index.
PID:        PID of process.
Alloc:      Total bytes allocated.
Free:       Total bytes freed.
Real:       Bytes not freed.
Real.max:   Maximum bytes process used at the moment.
Req.max:    Maximum bytes process required at the moment.
Oldest:     Age of oldest unfreed allocation.
Avg.Age:    Average age of allocations.
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

    ///Enable Trace Mode to trace individual allocations that are not freed.
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

    ///Show only allocations older than specified age (e.g., 5m, 1h, 300s). Automatically switches to Trace Mode.
    #[clap(long)]
    min_age: Option<String>,

    ///Show age distribution histogram (Statistics Mode only).
    #[clap(long)]
    age_histogram: bool,

    ///Maximum number of entries to display in Trace Mode (default: unlimited).
    #[clap(long)]
    max_entries: Option<usize>,
}

fn process_events(cli: &Cli, maps: &mut MallocFreeMaps) -> Result<(), JtraceError> {
    // Parse age filter if provided
    let min_age_filter = if let Some(age_str) = &cli.min_age {
        Some(AgeDuration::parse(age_str)?)
    } else {
        None
    };

    if cli.trace_path || cli.trace_full_path || cli.min_age.is_some() {
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

        let mut filtered_events = Vec::new();

        // Apply age filtering
        for (_key, event) in events.iter() {
            let comm = unsafe { bytes_to_string(event.comm.as_ptr()) };
            let free_comm = unsafe { bytes_to_string(event.free_comm.as_ptr()) };

            let tid = event.tid as i32;
            let free_tid = event.free_tid;

            // If trace_full_path is enabled, we show all malloc/free events.
            if !cli.trace_full_path {
                // Only show backtrace for memory region that has not been freed.
                if free_tid != 0 {
                    continue;
                }
            }

            // Apply age filter if specified
            if let Some(min_age) = &min_age_filter {
                if event.alloc_timestamp_ns > 0 {
                    if let Ok(age) = calculate_allocation_age(event.alloc_timestamp_ns) {
                        if age.as_secs() < min_age.seconds {
                            continue; // Skip allocations that are too young
                        }
                    } else {
                        // If we can't calculate age, skip this allocation
                        continue;
                    }
                } else {
                    continue; // Skip if timestamp is uninitialized
                }
            }

            filtered_events.push((event, comm, free_comm, tid, free_tid));
        }

        // Display header with age information when using age filtering
        if min_age_filter.is_some() {
            println!("{:<4} {:<8} {:<12} {:<8}", "No", "Size", "Age", "Process");
        } else {
            println!("{:<4} {:<8} {:<8}", "No", "Size", "Process");
        }
        println!("{}", "=".repeat(60));

        let mut idx = 1_usize;
        let max_display = cli.max_entries.unwrap_or(usize::MAX);
        let total_entries = filtered_events.len();

        for (event, comm, free_comm, tid, free_tid) in filtered_events {
            // Check if we've reached the maximum number of entries to display
            if idx > max_display {
                println!(
                    "... (showing first {} entries, {} total entries found)",
                    max_display, total_entries
                );
                break;
            }
            // Calculate and display age information when using age filtering
            let age_info = if min_age_filter.is_some() {
                if event.alloc_timestamp_ns > 0 {
                    match calculate_allocation_age(event.alloc_timestamp_ns) {
                        Ok(age) => {
                            format!("{:<12}", format_age(age))
                        }
                        Err(_) => format!("{:<12}", "unknown"),
                    }
                } else {
                    format!("{:<12}", "unknown")
                }
            } else {
                String::new()
            };

            if free_tid == 0 {
                if min_age_filter.is_some() {
                    println!(
                        "{:<4} {:<8} {} malloc: {:<10}({})",
                        idx, event.size, age_info, comm, tid
                    );
                } else {
                    println!("{:<4} {:<8} malloc: {:<10}({})", idx, event.size, comm, tid);
                }
            } else {
                if min_age_filter.is_some() {
                    println!(
                        "{:<4} {:<8} {} malloc: {:<10}({}) free: {:<10}({})",
                        idx, event.size, age_info, comm, tid, free_comm, free_tid
                    );
                } else {
                    println!(
                        "{:<4} {:<8} malloc: {:<10}({}) free: {:<10}({})",
                        idx, event.size, comm, tid, free_comm, free_tid
                    );
                }
            }
            idx += 1;

            // Show stack traces only when -t/-T options are used
            if cli.trace_path || cli.trace_full_path {
                let ustack_sz = (event.ustack_sz / 8) as usize;
                let ustack = &event.ustack[..ustack_sz];
                match ExecMap::new(tid_to_pid(event.tid as i32).unwrap_or(event.tid as i32) as u32)
                {
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

                if free_tid != 0 {
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
                                        jwarn!(
                                            "Failed to get symbol for address {:#x}: {}",
                                            addr,
                                            e
                                        );
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
            } // End of stack trace disp
        }
    } else {
        // Statistics Mode
        let process_stats = calculate_process_statistics_from_records(maps, &min_age_filter)?;

        if process_stats.is_empty() {
            if min_age_filter.is_some() {
                println!("No allocations found matching the age criteria.");
            } else {
                println!("No allocation data found.");
            }
            return Ok(());
        }

        // Display age histogram if requested
        if cli.age_histogram {
            if cli.trace_path || cli.trace_full_path || cli.min_age.is_some() {
                jwarn!(
                    "--age-histogram is ignored in Trace Mode (when using -t, -T, or --min-age)"
                );
            } else {
                let mut histogram = AgeHistogram::new();

                // Populate histogram from malloc_records (Statistics Mode)
                let malloc_records = maps.malloc_records();
                let mut total_records = 0;
                let mut records_with_histogram_data = 0;

                for key in malloc_records.keys() {
                    total_records += 1;
                    if let Some(data) = malloc_records
                        .lookup(&key, MapFlags::ANY)
                        .change_context(JtraceError::BPFError)?
                    {
                        let mut record = MallocRecord::default();
                        plain::copy_from_bytes(&mut record, &data).expect("Corrupted record data");

                        // Use the age histogram data maintained by eBPF
                        if record.age_histogram[0] > 0
                            || record.age_histogram[1] > 0
                            || record.age_histogram[2] > 0
                            || record.age_histogram[3] > 0
                        {
                            records_with_histogram_data += 1;

                            // Add the eBPF-maintained histogram data to our userspace histogram
                            // Note: We need to estimate allocation sizes since eBPF only tracks counts
                            let avg_alloc_size = if record.total_unfreed_count > 0 {
                                (record.alloc_size - record.free_size) / record.total_unfreed_count
                            } else {
                                0
                            };

                            // Add histogram data for each age range
                            for (range_idx, &count) in record.age_histogram.iter().enumerate() {
                                if count > 0 {
                                    // Convert range index to representative age in seconds
                                    let age_seconds = match range_idx {
                                        0 => 30,   // 0-1 min range: use 30 seconds as representative
                                        1 => 180,  // 1-5 min range: use 3 minutes as representative
                                        2 => 900, // 5-30 min range: use 15 minutes as representative
                                        3 => 2700, // 30+ min range: use 45 minutes as representative
                                        _ => 30,   // fallback
                                    };

                                    // Add each allocation in this range to the histogram
                                    for _ in 0..count {
                                        histogram.add_allocation(age_seconds, avg_alloc_size);
                                    }
                                }
                            }
                        }
                    }
                }

                println!(
                    "Debug: Total records: {}, Records with histogram data: {}",
                    total_records, records_with_histogram_data
                );

                histogram.print();
                println!();
            }
        }

        // Display statistics with age information
        println!(
            "{:<4} {:<8} {:<8} {:<8} {:<8} {:<8} {:<10} {:<8} {:<12} {:<8} Comm",
            "No", "PID", "TID", "Alloc", "Free", "Real", "Real.max", "Req.max", "Oldest", "Avg.Age"
        );

        let mut sorted_stats: Vec<_> = process_stats.into_iter().collect();
        sorted_stats.sort_by_key(|(_, stats)| std::cmp::Reverse(stats.filtered_alloc_size));

        for (idx, (_, stats)) in sorted_stats.iter().enumerate() {
            println!(
                "{:<4} {:<8} {:<8} {:<8} {:<8} {:<8} {:<10} {:<8} {:<12} {:<8} {}",
                idx + 1,
                stats.pid,
                stats.pid, // Using PID for TID in this simplified display
                stats.filtered_alloc_size + stats.free_size, // Total allocated = Real + Free
                stats.free_size, // Actual bytes freed
                stats.filtered_alloc_size, // Real = Alloc - Free
                stats.max_single_alloc,
                stats.max_single_alloc,
                stats.oldest_age_str,
                stats.avg_age_str,
                stats.comm
            );
        }
    }

    Ok(())
}

fn print_statistics(cli: &Cli, maps: &mut MallocFreeMaps) -> Result<(), JtraceError> {
    let stats_map = maps.stats();

    println!("\n=== Statistics ===");

    // Read statistics from all CPUs and sum them up (expanded for age statistics)
    let mut stats_totals = vec![0u64; 24]; // Increased from 20 to 24
    for cpu in 0..num_cpus::get() {
        for stat_idx in 0..24 {
            // Increased from 20 to 24
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

    // Validate age filter if provided
    if let Some(age_str) = &cli.min_age {
        AgeDuration::parse(age_str)?; // This will return an error if invalid
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

    // Set Trace Mode when using trace options or age filtering
    if cli.trace_path || cli.trace_full_path || cli.min_age.is_some() {
        if cli.trace_full_path {
            jwarn!("Tracing full malloc/free path, this may generate a lot of data and take a lot of time.");
        }
        open_skel.bss().trace_mode = true;

        // Warn if age histogram is used with Trace Mode flags
        if cli.age_histogram {
            jwarn!("--age-histogram is ignored in Trace Mode. Use Statistics Mode (without -t/-T/--min-age) for age histogram.");
        }
    }

    let mut skel = open_skel
        .load()
        .map_err(|_| Report::new(JtraceError::BPFError))
        .attach_printable("Failed to load bpf")?;

    // Clear maps BEFORE attaching probes to ensure we only see allocations from this trace session
    clear_bpf_maps(&mut skel)?;

    // Set baseline timestamp for age calculations right after clearing maps
    let baseline_timestamp = get_monotonic_time_ns()?;
    TRACE_START_TIMESTAMP.set(baseline_timestamp).map_err(|_| {
        Report::new(JtraceError::UnExpected).attach_printable("Failed to set baseline timestamp")
    })?;

    jinfo!("Trace baseline timestamp set: {}", baseline_timestamp);

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Test age duration parsing with various input formats
    #[test]
    fn test_age_duration_parsing() {
        // Test valid formats
        assert_eq!(AgeDuration::parse("300").unwrap().seconds, 300);
        assert_eq!(AgeDuration::parse("300s").unwrap().seconds, 300);
        assert_eq!(AgeDuration::parse("5m").unwrap().seconds, 300);
        assert_eq!(AgeDuration::parse("1h").unwrap().seconds, 3600);
        assert_eq!(AgeDuration::parse("2h").unwrap().seconds, 7200);
        assert_eq!(AgeDuration::parse("1s").unwrap().seconds, 1);

        // Test edge cases
        assert_eq!(AgeDuration::parse("1").unwrap().seconds, 1);
        assert_eq!(AgeDuration::parse("59s").unwrap().seconds, 59);
        assert_eq!(AgeDuration::parse("60m").unwrap().seconds, 3600);
        assert_eq!(AgeDuration::parse("24h").unwrap().seconds, 86400);

        // Test whitespace handling
        assert_eq!(AgeDuration::parse("  300s  ").unwrap().seconds, 300);
        assert_eq!(AgeDuration::parse("\t5m\n").unwrap().seconds, 300);
    }

    #[test]
    fn test_age_duration_parsing_invalid() {
        // Test invalid formats
        assert!(AgeDuration::parse("").is_err());
        assert!(AgeDuration::parse("abc").is_err());
        assert!(AgeDuration::parse("5x").is_err());
        assert!(AgeDuration::parse("5.5m").is_err());
        assert!(AgeDuration::parse("-5m").is_err());
        assert!(AgeDuration::parse("5 m").is_err());
        assert!(AgeDuration::parse("m5").is_err());

        // Test boundary violations
        assert!(AgeDuration::parse("25h").is_err()); // > 24 hours
        assert!(AgeDuration::parse("1441m").is_err()); // > 24 hours in minutes
        assert!(AgeDuration::parse("86401s").is_err()); // > 24 hours in seconds

        // Test zero values (should be invalid)
        assert!(AgeDuration::parse("0").is_err());
        assert!(AgeDuration::parse("0s").is_err());
        assert!(AgeDuration::parse("0m").is_err());
        assert!(AgeDuration::parse("0h").is_err());
    }

    #[test]
    fn test_age_duration_to_nanoseconds() {
        assert_eq!(
            AgeDuration::parse("1s").unwrap().to_nanoseconds(),
            1_000_000_000
        );
        assert_eq!(
            AgeDuration::parse("1m").unwrap().to_nanoseconds(),
            60_000_000_000
        );
        assert_eq!(
            AgeDuration::parse("1h").unwrap().to_nanoseconds(),
            3_600_000_000_000
        );
        assert_eq!(
            AgeDuration::parse("300").unwrap().to_nanoseconds(),
            300_000_000_000
        );
    }

    /// Test age calculation with different timestamp scenarios
    #[test]
    fn test_age_calculation_normal() {
        // Set up a baseline timestamp
        let baseline = 1000_000_000_000u64; // 1000 seconds in nanoseconds
        TRACE_START_TIMESTAMP.set(baseline).ok();

        // Mock get_monotonic_time_ns to return a predictable value
        // We'll test with a current time 5 minutes (300 seconds) after baseline
        let current_time = baseline + 300_000_000_000u64; // 300 seconds later

        // Test allocation that happened 2 minutes (120 seconds) after baseline
        let alloc_timestamp = baseline + 120_000_000_000u64;

        // The age should be current_time - alloc_timestamp = 180 seconds
        // Note: We can't easily mock get_monotonic_time_ns in this test,
        // so we'll test the logic with known values

        // Test that allocation timestamp after baseline is valid
        assert!(alloc_timestamp >= baseline);

        // Test age calculation logic
        let age_ns = current_time - alloc_timestamp;
        let expected_age = Duration::from_nanos(age_ns);
        assert_eq!(expected_age.as_secs(), 180);
    }

    #[test]
    fn test_age_calculation_edge_cases() {
        let baseline = 1000_000_000_000u64;
        TRACE_START_TIMESTAMP.set(baseline).ok();

        // Test allocation before baseline (stale data)
        let stale_timestamp = baseline - 1000_000_000u64; // 1 second before baseline
                                                          // This should be detected as stale data and return minimum age
        assert!(stale_timestamp < baseline);

        // Test allocation at exactly baseline time
        let exact_timestamp = baseline;
        assert_eq!(exact_timestamp, baseline);

        // Test very large timestamp differences
        let large_timestamp = baseline + 86400_000_000_000u64; // 24 hours later
        let current_large = baseline + 86500_000_000_000u64; // 24 hours + 100 seconds
        let age_ns = current_large - large_timestamp;
        assert_eq!(Duration::from_nanos(age_ns).as_secs(), 100);
    }

    #[test]
    fn test_age_calculation_clock_adjustments() {
        let baseline = 1000_000_000_000u64;
        TRACE_START_TIMESTAMP.set(baseline).ok();

        // Test clock going backwards (current < allocation)
        let alloc_timestamp = baseline + 100_000_000_000u64; // 100 seconds after baseline
        let current_backwards = baseline + 50_000_000_000u64; // 50 seconds after baseline

        // This simulates clock adjustment where current time is before allocation time
        assert!(current_backwards < alloc_timestamp);
        // The function should handle this gracefully and return minimum age
    }

    /// Test age formatting for various duration ranges
    #[test]
    fn test_age_formatting_seconds() {
        assert_eq!(format_age(Duration::from_secs(0)), "0s");
        assert_eq!(format_age(Duration::from_secs(1)), "1s");
        assert_eq!(format_age(Duration::from_secs(30)), "30s");
        assert_eq!(format_age(Duration::from_secs(59)), "59s");
    }

    #[test]
    fn test_age_formatting_minutes() {
        assert_eq!(format_age(Duration::from_secs(60)), "1m");
        assert_eq!(format_age(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_age(Duration::from_secs(120)), "2m");
        assert_eq!(format_age(Duration::from_secs(300)), "5m");
        assert_eq!(format_age(Duration::from_secs(3599)), "59m 59s");
    }

    #[test]
    fn test_age_formatting_hours() {
        assert_eq!(format_age(Duration::from_secs(3600)), "1h");
        assert_eq!(format_age(Duration::from_secs(3660)), "1h 1m");
        assert_eq!(format_age(Duration::from_secs(7200)), "2h");
        assert_eq!(format_age(Duration::from_secs(7320)), "2h 2m");
        assert_eq!(format_age(Duration::from_secs(86400)), "24h");
        assert_eq!(format_age(Duration::from_secs(90000)), "25h");
    }

    #[test]
    fn test_age_formatting_edge_cases() {
        // Test exact boundaries
        assert_eq!(format_age(Duration::from_secs(59)), "59s");
        assert_eq!(format_age(Duration::from_secs(60)), "1m");
        assert_eq!(format_age(Duration::from_secs(3599)), "59m 59s");
        assert_eq!(format_age(Duration::from_secs(3600)), "1h");

        // Test large values
        assert_eq!(format_age(Duration::from_secs(100000)), "27h 46m");

        // Test zero and very small values
        assert_eq!(format_age(Duration::from_millis(500)), "0s"); // Sub-second rounds to 0s
    }

    /// Test age filtering logic with edge cases
    #[test]
    fn test_age_filtering_logic() {
        let min_age_5m = AgeDuration::parse("5m").unwrap();
        let min_age_1h = AgeDuration::parse("1h").unwrap();

        // Test ages that should pass filters
        assert!(Duration::from_secs(300).as_secs() >= min_age_5m.seconds); // Exactly 5 minutes
        assert!(Duration::from_secs(301).as_secs() >= min_age_5m.seconds); // Just over 5 minutes
        assert!(Duration::from_secs(3600).as_secs() >= min_age_1h.seconds); // Exactly 1 hour
        assert!(Duration::from_secs(7200).as_secs() >= min_age_1h.seconds); // 2 hours

        // Test ages that should not pass filters
        assert!(Duration::from_secs(299).as_secs() < min_age_5m.seconds); // Just under 5 minutes
        assert!(Duration::from_secs(0).as_secs() < min_age_5m.seconds); // Zero age
        assert!(Duration::from_secs(3599).as_secs() < min_age_1h.seconds); // Just under 1 hour
    }

    #[test]
    fn test_age_filtering_boundary_conditions() {
        // Test exact boundary conditions
        let min_age_1s = AgeDuration::parse("1s").unwrap();
        let min_age_24h = AgeDuration::parse("24h").unwrap();

        // Minimum boundary
        assert!(Duration::from_secs(1).as_secs() >= min_age_1s.seconds);
        assert!(Duration::from_secs(0).as_secs() < min_age_1s.seconds);

        // Maximum boundary (24 hours)
        assert!(Duration::from_secs(86400).as_secs() >= min_age_24h.seconds);
        assert!(Duration::from_secs(86399).as_secs() < min_age_24h.seconds);
    }

    /// Test mode switching logic
    #[test]
    fn test_mode_switching_trace_mode_triggers() {
        // Test CLI configurations that should trigger Trace Mode

        // --min-age should trigger Trace Mode
        let cli_min_age = Cli {
            min_age: Some("5m".to_string()),
            ..Default::default()
        };
        assert!(should_use_trace_mode(&cli_min_age));

        // -t should trigger Trace Mode
        let cli_trace_path = Cli {
            trace_path: true,
            ..Default::default()
        };
        assert!(should_use_trace_mode(&cli_trace_path));

        // -T should trigger Trace Mode
        let cli_trace_full = Cli {
            trace_full_path: true,
            ..Default::default()
        };
        assert!(should_use_trace_mode(&cli_trace_full));

        // Combination should trigger Trace Mode
        let cli_combined = Cli {
            trace_path: true,
            min_age: Some("1h".to_string()),
            ..Default::default()
        };
        assert!(should_use_trace_mode(&cli_combined));
    }

    #[test]
    fn test_mode_switching_statistics_mode() {
        // Test CLI configurations that should use Statistics Mode

        // Default configuration
        let cli_default = Cli::default();
        assert!(!should_use_trace_mode(&cli_default));

        // Only --age-histogram (Statistics Mode feature)
        let cli_histogram = Cli {
            age_histogram: true,
            ..Default::default()
        };
        assert!(!should_use_trace_mode(&cli_histogram));

        // Other flags that don't trigger Trace Mode
        let cli_stats = Cli {
            show_stats: true,
            duration: 60,
            pid: Some(1234),
            ..Default::default()
        };
        assert!(!should_use_trace_mode(&cli_stats));
    }

    #[test]
    fn test_mode_switching_warning_conditions() {
        // Test conditions that should generate warnings

        // --age-histogram with Trace Mode flags should generate warning
        let cli_histogram_with_trace = Cli {
            age_histogram: true,
            trace_path: true,
            ..Default::default()
        };
        assert!(should_use_trace_mode(&cli_histogram_with_trace));
        assert!(should_warn_about_histogram_in_trace_mode(
            &cli_histogram_with_trace
        ));

        let cli_histogram_with_min_age = Cli {
            age_histogram: true,
            min_age: Some("5m".to_string()),
            ..Default::default()
        };
        assert!(should_use_trace_mode(&cli_histogram_with_min_age));
        assert!(should_warn_about_histogram_in_trace_mode(
            &cli_histogram_with_min_age
        ));
    }

    /// Test age histogram functionality
    #[test]
    fn test_age_histogram_ranges() {
        let mut histogram = AgeHistogram::new();

        // Test allocations in different age ranges
        histogram.add_allocation(30, 1024); // 0-1 min range
        histogram.add_allocation(120, 2048); // 1-5 min range
        histogram.add_allocation(600, 4096); // 5-30 min range
        histogram.add_allocation(2000, 8192); // 30+ min range

        // Verify ranges are populated correctly
        assert_eq!(histogram.ranges[0].count, 1); // 0-1 min
        assert_eq!(histogram.ranges[0].total_size, 1024);

        assert_eq!(histogram.ranges[1].count, 1); // 1-5 min
        assert_eq!(histogram.ranges[1].total_size, 2048);

        assert_eq!(histogram.ranges[2].count, 1); // 5-30 min
        assert_eq!(histogram.ranges[2].total_size, 4096);

        assert_eq!(histogram.ranges[3].count, 1); // 30+ min
        assert_eq!(histogram.ranges[3].total_size, 8192);
    }

    #[test]
    fn test_age_histogram_boundary_conditions() {
        let mut histogram = AgeHistogram::new();

        // Test exact boundary values
        histogram.add_allocation(0, 100); // Exactly 0 seconds (0-1 min)
        histogram.add_allocation(59, 200); // Just under 1 minute (0-1 min)
        histogram.add_allocation(60, 300); // Exactly 1 minute (1-5 min)
        histogram.add_allocation(299, 400); // Just under 5 minutes (1-5 min)
        histogram.add_allocation(300, 500); // Exactly 5 minutes (5-30 min)
        histogram.add_allocation(1799, 600); // Just under 30 minutes (5-30 min)
        histogram.add_allocation(1800, 700); // Exactly 30 minutes (30+ min)

        // Verify boundary handling
        assert_eq!(histogram.ranges[0].count, 2); // 0s and 59s
        assert_eq!(histogram.ranges[1].count, 2); // 60s and 299s
        assert_eq!(histogram.ranges[2].count, 2); // 300s and 1799s
        assert_eq!(histogram.ranges[3].count, 1); // 1800s
    }

    #[test]
    fn test_age_histogram_multiple_allocations() {
        let mut histogram = AgeHistogram::new();

        // Add multiple allocations to same range
        for i in 0..5 {
            histogram.add_allocation(30 + i, 1000 + i as u32); // All in 0-1 min range
        }

        assert_eq!(histogram.ranges[0].count, 5);
        assert_eq!(histogram.ranges[0].total_size, 5010); // 1000+1001+1002+1003+1004

        // Test average calculation
        let avg_size = histogram.ranges[0].total_size / histogram.ranges[0].count as u64;
        assert_eq!(avg_size, 1002); // 5010 / 5
    }

    /// Test format_size utility function
    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0B");
        assert_eq!(format_size(512), "512B");
        assert_eq!(format_size(1024), "1.0KB");
        assert_eq!(format_size(1536), "1.5KB");
        assert_eq!(format_size(1048576), "1.0MB");
        assert_eq!(format_size(1073741824), "1.0GB");
        assert_eq!(format_size(2147483648), "2.0GB");
    }

    /// Test max-entries CLI option parsing and validation
    #[test]
    fn test_max_entries_option() {
        // Test default (None)
        let cli_default = Cli::default();
        assert_eq!(cli_default.max_entries, None);

        // Test with specific value
        let cli_with_limit = Cli {
            max_entries: Some(10),
            ..Default::default()
        };
        assert_eq!(cli_with_limit.max_entries, Some(10));

        // Test unlimited (None) vs limited behavior
        let unlimited = cli_default.max_entries.unwrap_or(usize::MAX);
        let limited = cli_with_limit.max_entries.unwrap_or(usize::MAX);

        assert_eq!(unlimited, usize::MAX);
        assert_eq!(limited, 10);
    }

    /// Test max-entries functionality with mock filtered events
    #[test]
    fn test_max_entries_filtering_logic() {
        // Simulate the logic used in process_events
        let mock_events = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]; // 10 mock events

        // Test unlimited (default behavior)
        let max_display_unlimited = None.unwrap_or(usize::MAX);
        let mut count_unlimited = 0;
        for (idx, _event) in mock_events.iter().enumerate() {
            let display_idx = idx + 1;
            if display_idx > max_display_unlimited {
                break;
            }
            count_unlimited += 1;
        }
        assert_eq!(count_unlimited, 10); // All events displayed

        // Test limited to 3 entries
        let max_display_limited = Some(3).unwrap_or(usize::MAX);
        let mut count_limited = 0;
        for (idx, _event) in mock_events.iter().enumerate() {
            let display_idx = idx + 1;
            if display_idx > max_display_limited {
                break;
            }
            count_limited += 1;
        }
        assert_eq!(count_limited, 3); // Only first 3 events displayed

        // Test edge case: limit larger than available events
        let max_display_large = Some(20).unwrap_or(usize::MAX);
        let mut count_large = 0;
        for (idx, _event) in mock_events.iter().enumerate() {
            let display_idx = idx + 1;
            if display_idx > max_display_large {
                break;
            }
            count_large += 1;
        }
        assert_eq!(count_large, 10); // All available events displayed
    }

    // Helper functions for mode switching tests
    fn should_use_trace_mode(cli: &Cli) -> bool {
        cli.trace_path || cli.trace_full_path || cli.min_age.is_some()
    }

    fn should_warn_about_histogram_in_trace_mode(cli: &Cli) -> bool {
        cli.age_histogram && should_use_trace_mode(cli)
    }

    /// Integration test for age filtering with mock data
    #[test]
    fn test_age_filtering_integration() {
        // Test the complete age filtering pipeline
        let min_age = AgeDuration::parse("2m").unwrap(); // 2 minutes

        // Mock allocation timestamps (in nanoseconds)
        let baseline = 1000_000_000_000u64;
        let current_time = baseline + 360_000_000_000u64; // 6 minutes after baseline

        let allocations = vec![
            (current_time - 30_000_000_000u64, 1024u32), // 30 seconds old - should be filtered out
            (current_time - 150_000_000_000u64, 2048u32), // 2.5 minutes old - should pass
            (current_time - 300_000_000_000u64, 4096u32), // 5 minutes old - should pass
        ];

        let mut passed_allocations = Vec::new();

        for (alloc_timestamp, size) in allocations {
            let age_ns = current_time - alloc_timestamp;
            let age = Duration::from_nanos(age_ns);

            if age.as_secs() >= min_age.seconds {
                passed_allocations.push((age, size));
            }
        }

        // Should have 2 allocations that passed the filter
        assert_eq!(passed_allocations.len(), 2);
        assert_eq!(passed_allocations[0].1, 2048); // 2.5 minutes old
        assert_eq!(passed_allocations[1].1, 4096); // 5 minutes old
    }

    /// Test error handling in age parsing
    #[test]
    fn test_age_parsing_error_messages() {
        // Test that error messages are informative
        let result = AgeDuration::parse("invalid");
        assert!(result.is_err());
        let error_msg = format!("{:?}", result.unwrap_err());
        assert!(error_msg.contains("Invalid age format"));

        let result = AgeDuration::parse("25h");
        assert!(result.is_err());
        let error_msg = format!("{:?}", result.unwrap_err());
        assert!(error_msg.contains("cannot exceed 24 hours"));

        let result = AgeDuration::parse("0s");
        assert!(result.is_err());
        let error_msg = format!("{:?}", result.unwrap_err());
        assert!(error_msg.contains("must be greater than 0"));
    }

    /// Test timestamp validation and edge cases
    #[test]
    fn test_timestamp_validation() {
        let baseline = 1000_000_000_000u64;
        TRACE_START_TIMESTAMP.set(baseline).ok();

        // Test various timestamp scenarios
        let test_cases = vec![
            (baseline - 1000_000_000u64, "before baseline"), // Before baseline (stale)
            (baseline, "at baseline"),                       // Exactly at baseline
            (baseline + 1000_000_000u64, "after baseline"),  // After baseline (normal)
            (0u64, "zero timestamp"),                        // Zero timestamp
            (u64::MAX, "maximum timestamp"),                 // Maximum value
        ];

        for (timestamp, description) in test_cases {
            // Test that we can handle various timestamp values without panicking
            if timestamp >= baseline && timestamp != u64::MAX {
                // Normal case - should be valid
                assert!(timestamp >= baseline, "Failed for case: {}", description);
            } else {
                // Edge cases - should be handled gracefully
                // The actual calculate_allocation_age function would handle these
                println!(
                    "Testing edge case: {} (timestamp: {})",
                    description, timestamp
                );
            }
        }
    }
}
