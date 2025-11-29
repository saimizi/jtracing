#[allow(unused)]
use {
    clap::Parser,
    error_stack::{Report, Result, ResultExt},
    jlogger_tracing::{jdebug, jerror, jinfo, jtrace, jwarn, JloggerBuilder, LevelFilter},
    libbpf_rs::{
        set_print,
        skel::{OpenSkel, Skel, SkelBuilder},
        MapFlags, PrintLevel, RingBufferBuilder,
    },
    serde::{Deserialize, Serialize},
    std::{
        collections::HashMap,
        fs::{File, OpenOptions},
        io::{BufWriter, Write},
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        time::{Duration, SystemTime, UNIX_EPOCH},
    },
    tracelib::{bump_memlock_rlimit, bytes_to_string, ExecMap, JtraceError},
};

// Custom serialization for SystemTime
mod systemtime_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn serialize<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
        let timestamp_ms = duration.as_millis() as u64;
        timestamp_ms.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let timestamp_ms = u64::deserialize(deserializer)?;
        Ok(UNIX_EPOCH + std::time::Duration::from_millis(timestamp_ms))
    }
}

// Global interruption flag for signal handling
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[path = "bpf/segfault_analyzer.skel.rs"]
mod segfault_analyzer;
use plain::Plain;
use segfault_analyzer::{SegfaultAnalyzerSkel, SegfaultAnalyzerSkelBuilder};

// Import BPF types
type SegfaultEventBpf = segfault_analyzer::segfault_analyzer_bss_types::segfault_event;
unsafe impl Plain for SegfaultEventBpf {}

/// Core data structures for segfault events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegfaultEvent {
    // Process context
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
    #[serde(with = "systemtime_serde")]
    pub timestamp: SystemTime,

    // Event classification
    pub signal_number: u32,    // SIGSEGV (11) or SIGABRT (6)
    pub event_type: EventType, // Segfault or Abort

    // Fault details
    pub fault_address: u64, // Only meaningful for SIGSEGV
    pub instruction_pointer: u64,
    pub fault_type: FaultType,

    // Optional register state
    pub registers: Option<RegisterState>,

    // Optional stack trace
    pub stack_trace: Option<Vec<u64>>,
    pub stack_trace_reliable: bool, // False if stack may be corrupted

    // Stack smashing specific
    pub vulnerable_function: Option<String>, // Function where stack smashing occurred (frame 1)

    // Memory mapping info
    pub vma_info: Option<VmaInfo>,
}

/// Event type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    Segfault,      // SIGSEGV
    StackSmashing, // SIGABRT from stack protector
    Abort,         // SIGABRT (generic)
}

impl EventType {
    fn as_str(&self) -> &'static str {
        match self {
            EventType::Segfault => "SEGFAULT",
            EventType::StackSmashing => "STACK SMASHING DETECTED",
            EventType::Abort => "ABORT",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FaultType {
    // SIGSEGV types
    MapError,    // SEGV_MAPERR - address not mapped
    AccessError, // SEGV_ACCERR - invalid permissions

    // SIGABRT types
    StackProtector, // Stack smashing detected by stack protector
    Abort,          // Generic abort signal

    Unknown(i32), // Other si_code values
}

impl FaultType {
    pub fn from_si_code(code: i32, signal: u32) -> Self {
        match signal {
            11 => {
                // SIGSEGV
                match code {
                    1 => FaultType::MapError,    // SEGV_MAPERR
                    2 => FaultType::AccessError, // SEGV_ACCERR
                    _ => FaultType::Unknown(code),
                }
            }
            6 => {
                // SIGABRT
                FaultType::Abort
            }
            _ => FaultType::Unknown(code),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            FaultType::MapError => "Address not mapped (SEGV_MAPERR)",
            FaultType::AccessError => "Access violation (SEGV_ACCERR)",
            FaultType::StackProtector => "Stack protector triggered",
            FaultType::Abort => "Abort signal",
            FaultType::Unknown(_) => "Unknown fault type",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterState {
    pub architecture: String,
    pub registers: HashMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmaInfo {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub mapping_name: Option<String>,
}

/// Output format enumeration
#[derive(Debug, Clone)]
pub enum OutputFormat {
    Text,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!(
                "Invalid output format: {}. Use 'text' or 'json'",
                s
            )),
        }
    }
}

/// Command line interface definition
#[derive(Parser, Debug)]
#[command(
    about = "A BPF-based tool to analyze and debug segmentation faults in running processes.",
    version,
    after_help = "
Examples:
    segfault_analyzer                              # Monitor all processes
    segfault_analyzer -p 1234                     # Monitor specific PID
    segfault_analyzer -n myapp                    # Monitor processes with 'myapp' in name
    segfault_analyzer -t -r                       # Show stack traces and registers
    segfault_analyzer -o crashes.log --format json # Save to file in JSON format
    segfault_analyzer -o crashes.log -a           # Append to existing file
    segfault_analyzer -d 60                       # Monitor for 60 seconds
    segfault_analyzer --stats                     # Show performance statistics

Output Format:
    Text format provides human-readable output suitable for console viewing.
    JSON format provides structured output for programmatic processing.

File Output:
    Use -o/--output to specify an output file path.
    Use -a/--append to append to existing files instead of overwriting.
    File output supports both text and JSON formats.

Filtering:
    Process filtering can be done by PID (-p) or process name (-n).
    Process name filtering supports partial matching (contains).

Performance Monitoring:
    Use --stats to display performance statistics and monitoring information.
    Use --stats-interval to control how often statistics are displayed.

Memory Management:
    Use --symbol-cache-limit to set the maximum number of cached symbols (default: 1000).
    Use --memory-limit to set the maximum memory usage in MB (default: 100).
    Note: Ring buffer size is fixed at 256KB (compile-time BPF limitation).
    
Privileges:
    This tool requires root privileges or CAP_BPF capability to load BPF programs.
"
)]
pub struct Cli {
    /// Duration to monitor in seconds (0 = infinite)
    #[clap(short, long, default_value_t = 0)]
    pub duration: u64,

    /// Filter by process ID
    #[clap(short, long)]
    pub pid: Option<i32>,

    /// Filter by process name (supports partial matching)
    #[clap(short = 'n', long)]
    pub process_name: Option<String>,

    /// Include register state in output
    #[clap(short, long)]
    pub registers: bool,

    /// Include stack trace
    #[clap(short = 't', long)]
    pub stack_trace: bool,

    /// Maximum stack depth to capture
    #[clap(long, default_value_t = 16)]
    pub max_stack_depth: u32,

    /// Output file path
    #[clap(short, long)]
    pub output: Option<PathBuf>,

    /// Output format (text, json)
    #[clap(long, default_value = "text")]
    pub format: OutputFormat,

    /// Append to output file instead of overwriting
    #[clap(short, long)]
    pub append: bool,

    /// Show performance statistics and monitoring information
    #[clap(long)]
    pub stats: bool,

    /// Statistics display interval in seconds (only with --stats)
    #[clap(long, default_value_t = 5)]
    pub stats_interval: u64,

    /// Maximum number of symbols to cache (0 = unlimited)
    #[clap(long, default_value_t = 1000)]
    pub symbol_cache_limit: usize,

    /// Maximum memory usage in MB (approximate limit)
    #[clap(long, default_value_t = 100)]
    pub memory_limit: u64,

    /// Verbose output
    #[clap(short, long)]
    pub verbose: bool,
}

/// Statistics manager for tracking performance metrics
pub struct StatisticsManager {
    userspace_stats: SegfaultStatistics,
    last_display_time: SystemTime,
    start_time: SystemTime,
}

impl Default for StatisticsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StatisticsManager {
    pub fn new() -> Self {
        let now = SystemTime::now();
        Self {
            userspace_stats: SegfaultStatistics::default(),
            last_display_time: now,
            start_time: now,
        }
    }

    /// Read statistics from BPF maps and combine with userspace stats
    pub fn collect_statistics(
        &mut self,
        skel: &SegfaultAnalyzerSkel,
    ) -> Result<SegfaultStatistics, JtraceError> {
        let mut combined_stats = self.userspace_stats.clone();

        // Read BPF statistics from per-CPU array
        let maps = skel.maps();
        let stats_map = maps.stats();

        // Statistics indices from BPF program
        const STAT_SEGFAULTS_TOTAL: u32 = 0;
        const STAT_SEGFAULTS_FILTERED: u32 = 1;
        const STAT_EVENTS_SUBMITTED: u32 = 2;
        const STAT_EVENTS_DROPPED: u32 = 3;
        const STAT_REGISTER_FAILURES: u32 = 4;
        const STAT_STACK_FAILURES: u32 = 5;
        const STAT_FAULT_INFO_CAPTURED: u32 = 6;
        const STAT_FAULT_INFO_MISSED: u32 = 7;
        const STAT_VMA_CAPTURED: u32 = 8;
        const STAT_VMA_FAILURES: u32 = 9;

        // Helper function to read per-CPU stat and sum across all CPUs
        let read_percpu_stat = |key: u32| -> Result<u64, JtraceError> {
            let key_bytes = key.to_ne_bytes();
            match stats_map.lookup_percpu(&key_bytes, MapFlags::ANY) {
                Ok(Some(values)) => {
                    let mut total = 0u64;
                    for value_bytes in values {
                        if value_bytes.len() >= 8 {
                            let value = u64::from_ne_bytes([
                                value_bytes[0],
                                value_bytes[1],
                                value_bytes[2],
                                value_bytes[3],
                                value_bytes[4],
                                value_bytes[5],
                                value_bytes[6],
                                value_bytes[7],
                            ]);
                            total += value;
                        }
                    }
                    Ok(total)
                }
                Ok(None) => Ok(0),
                Err(e) => {
                    jtrace!("Failed to read BPF stat {}: {}", key, e);
                    Ok(0) // Continue with 0 if we can't read the stat
                }
            }
        };

        // Read all BPF statistics
        combined_stats.segfaults_total = read_percpu_stat(STAT_SEGFAULTS_TOTAL)?;
        combined_stats.segfaults_filtered = read_percpu_stat(STAT_SEGFAULTS_FILTERED)?;
        combined_stats.events_submitted = read_percpu_stat(STAT_EVENTS_SUBMITTED)?;
        combined_stats.events_dropped = read_percpu_stat(STAT_EVENTS_DROPPED)?;
        combined_stats.register_failures = read_percpu_stat(STAT_REGISTER_FAILURES)?;
        combined_stats.stack_failures = read_percpu_stat(STAT_STACK_FAILURES)?;
        combined_stats.fault_info_captured = read_percpu_stat(STAT_FAULT_INFO_CAPTURED)?;
        combined_stats.fault_info_missed = read_percpu_stat(STAT_FAULT_INFO_MISSED)?;
        combined_stats.vma_captured = read_percpu_stat(STAT_VMA_CAPTURED)?;
        combined_stats.vma_failures = read_percpu_stat(STAT_VMA_FAILURES)?;

        // Estimate memory usage (rough calculation)
        combined_stats.memory_usage_bytes = self.estimate_memory_usage(skel)?;

        Ok(combined_stats)
    }

    /// Estimate current memory usage
    fn estimate_memory_usage(&self, skel: &SegfaultAnalyzerSkel) -> Result<u64, JtraceError> {
        let mut total_memory = 0u64;

        // Ring buffer size (256KB as defined in BPF - this is fixed at compile time)
        total_memory += 256 * 1024;

        // Stats map (per-CPU array with 10 entries, 8 bytes each)
        let num_cpus = num_cpus::get() as u64;
        total_memory += num_cpus * 10 * 8;

        // Fault info map (hash map with up to 1024 entries)
        // Each entry is roughly sizeof(struct fault_info) ≈ 1KB
        let _fault_info_map = skel.maps().fault_info_map();

        // Try to estimate actual entries in fault_info_map
        let mut fault_info_entries = 0u64;
        // We can't easily iterate over BPF hash maps from userspace,
        // so we'll use a conservative estimate based on recent activity
        if self.userspace_stats.fault_info_captured > 0 {
            // Assume some entries are temporarily stored
            fault_info_entries = std::cmp::min(50, self.userspace_stats.fault_info_captured / 10);
        }
        total_memory += fault_info_entries * 1024;

        // Fault info heap (per-CPU array with 1 entry per CPU)
        total_memory += num_cpus * 1024; // sizeof(struct fault_info) ≈ 1KB

        // Add userspace memory usage estimate
        let symbol_cache_entries =
            self.userspace_stats.symbol_cache_hits + self.userspace_stats.symbol_cache_misses;
        total_memory += symbol_cache_entries * 128; // Rough estimate per cached symbol (key + value)

        // Add estimated memory for exec maps and other userspace structures
        total_memory += 1024 * 1024; // 1MB estimate for misc userspace structures

        Ok(total_memory)
    }

    /// Check if memory usage is within limits
    pub fn check_memory_limit(&self, limit_bytes: u64, current_usage: u64) -> bool {
        if limit_bytes == 0 {
            return true; // No limit
        }
        current_usage <= limit_bytes
    }

    /// Get memory usage as a percentage of the limit
    pub fn memory_usage_percentage(&self, limit_bytes: u64, current_usage: u64) -> f64 {
        if limit_bytes == 0 {
            return 0.0; // No limit
        }
        (current_usage as f64 / limit_bytes as f64) * 100.0
    }

    /// Display statistics in a formatted way
    pub fn display_statistics(&mut self, stats: &SegfaultStatistics, elapsed_time: Duration) {
        let elapsed_secs = elapsed_time.as_secs_f64();

        println!("\n=== Segfault Analyzer Statistics ===");
        println!("Runtime: {:.1}s", elapsed_secs);
        println!();

        println!("Event Counts:");
        println!("  Total segfaults detected:     {}", stats.segfaults_total);
        println!(
            "  Segfaults filtered out:       {}",
            stats.segfaults_filtered
        );
        println!(
            "  Events captured:              {}",
            stats.events_captured()
        );
        println!("  Events processed:             {}", stats.events_processed);
        println!(
            "  Events submitted to userspace: {}",
            stats.events_submitted
        );
        println!("  Events dropped:               {}", stats.events_dropped);
        println!();

        println!("Performance Metrics:");
        println!("  Event drop rate:              {:.2}%", stats.drop_rate());
        println!(
            "  Fault info capture rate:      {:.2}%",
            stats.fault_info_capture_rate()
        );
        println!(
            "  Events per second:            {:.1}",
            stats.events_processed as f64 / elapsed_secs
        );
        println!();

        println!("Feature Statistics:");
        println!(
            "  Register capture failures:    {}",
            stats.register_failures
        );
        println!("  Stack trace failures:         {}", stats.stack_failures);
        println!(
            "  Fault info captured:          {}",
            stats.fault_info_captured
        );
        println!(
            "  Fault info missed:            {}",
            stats.fault_info_missed
        );
        println!("  VMA info captured:            {}", stats.vma_captured);
        println!("  VMA capture failures:         {}", stats.vma_failures);
        println!(
            "  VMA capture rate:             {:.2}%",
            stats.vma_capture_rate()
        );
        println!();

        println!("Symbol Resolution:");
        println!(
            "  Symbol cache hits:            {}",
            stats.symbol_cache_hits
        );
        println!(
            "  Symbol cache misses:          {}",
            stats.symbol_cache_misses
        );
        println!(
            "  Symbol cache hit rate:        {:.2}%",
            stats.symbol_cache_hit_rate()
        );
        println!();

        println!("Memory Usage:");
        println!(
            "  Estimated memory usage:       {:.2} MB",
            stats.memory_usage_bytes as f64 / (1024.0 * 1024.0)
        );

        // Show memory limit information if available
        if self.userspace_stats.memory_usage_bytes > 0 {
            let limit_mb = 100.0; // Default limit, could be made configurable
            let usage_pct =
                (stats.memory_usage_bytes as f64 / (limit_mb * 1024.0 * 1024.0)) * 100.0;
            println!("  Memory usage (% of limit):    {:.1}%", usage_pct);
        }

        println!("  Ring buffer size (fixed):     256 KB");
        println!(
            "  Symbol cache entries:         {}",
            stats.symbol_cache_hits + stats.symbol_cache_misses
        );
        println!();

        self.last_display_time = SystemTime::now();
    }

    /// Check if it's time to display statistics
    pub fn should_display_stats(&self, interval_secs: u64) -> bool {
        self.last_display_time
            .elapsed()
            .unwrap_or_default()
            .as_secs()
            >= interval_secs
    }

    /// Increment userspace statistics
    pub fn increment_events_processed(&mut self) {
        self.userspace_stats.events_processed += 1;
    }

    pub fn increment_symbol_cache_hit(&mut self) {
        self.userspace_stats.symbol_cache_hits += 1;
    }

    pub fn increment_symbol_cache_miss(&mut self) {
        self.userspace_stats.symbol_cache_misses += 1;
    }

    pub fn get_start_time(&self) -> SystemTime {
        self.start_time
    }
}

/// Event processor trait for handling segfault events
pub trait EventProcessor {
    fn process_event(&mut self, event: &SegfaultEvent) -> Result<(), JtraceError>;
    fn flush(&mut self) -> Result<(), JtraceError>;
}

/// Console-based event processor
pub struct ConsoleProcessor {
    exec_map: Option<ExecMap>,
    symbol_cache: HashMap<u64, Option<String>>,
    current_pid: Option<u32>,
    show_registers: bool,
    show_stack_trace: bool,
    stats_manager: Option<Arc<std::sync::Mutex<StatisticsManager>>>,
    symbol_cache_limit: usize,
    memory_limit_bytes: u64,
}

impl ConsoleProcessor {
    pub fn new(show_registers: bool, show_stack_trace: bool) -> Self {
        Self {
            exec_map: None,
            symbol_cache: HashMap::new(),
            current_pid: None,
            show_registers,
            show_stack_trace,
            stats_manager: None,
            symbol_cache_limit: 1000,
            memory_limit_bytes: 100 * 1024 * 1024, // 100MB default
        }
    }

    pub fn with_stats_manager(
        mut self,
        stats_manager: Arc<std::sync::Mutex<StatisticsManager>>,
    ) -> Self {
        self.stats_manager = Some(stats_manager);
        self
    }

    pub fn with_memory_limits(mut self, symbol_cache_limit: usize, memory_limit_mb: u64) -> Self {
        self.symbol_cache_limit = symbol_cache_limit;
        self.memory_limit_bytes = memory_limit_mb * 1024 * 1024;
        self
    }

    /// Initialize exec map for a specific process
    fn ensure_exec_map(&mut self, pid: u32) -> Result<(), JtraceError> {
        // Check if we need to reinitialize for a different PID
        if self.current_pid != Some(pid) {
            jdebug!(
                "Switching exec map from PID {:?} to PID {}",
                self.current_pid,
                pid
            );
            self.exec_map = None;
            self.symbol_cache.clear();
            self.current_pid = Some(pid);
        }

        if self.exec_map.is_none() {
            match ExecMap::new(pid) {
                Ok(exec_map) => {
                    jdebug!("Initialized exec map for PID {}", pid);
                    self.exec_map = Some(exec_map);
                }
                Err(e) => {
                    jwarn!("Failed to initialize exec map for PID {}: {}", pid, e);
                    // Continue without symbol resolution
                    return Err(Report::new(JtraceError::SymbolAnalyzerError)
                        .attach_printable(format!("Exec map initialization failed: {}", e)));
                }
            }
        }
        Ok(())
    }

    /// Resolve an address to symbol information with caching
    fn resolve_address(&mut self, pid: u32, addr: u64) -> Option<String> {
        // Check cache first
        if let Some(cached_result) = self.symbol_cache.get(&addr) {
            // Track cache hit
            if let Some(ref stats_manager) = self.stats_manager {
                if let Ok(mut stats) = stats_manager.lock() {
                    stats.increment_symbol_cache_hit();
                }
            }
            return cached_result.clone();
        }

        // Track cache miss
        if let Some(ref stats_manager) = self.stats_manager {
            if let Ok(mut stats) = stats_manager.lock() {
                stats.increment_symbol_cache_miss();
            }
        }

        // Ensure we have an exec map for this PID
        if self.ensure_exec_map(pid).is_err() {
            self.symbol_cache.insert(addr, None);
            return None;
        }

        let result = if let Some(ref mut exec_map) = self.exec_map {
            match exec_map.symbol(addr) {
                Ok((vma_offset, symbol, module)) => {
                    // Convert VMA offset to file offset for accurate symbol resolution
                    let file_offset = self.calculate_file_offset(vma_offset, &module);

                    if !symbol.is_empty() {
                        if !module.is_empty() {
                            // Extract just the filename for cleaner output
                            let filename = std::path::Path::new(&module)
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or(&module);
                            Some(format!("{}+0x{:x} ({})", symbol, file_offset, filename))
                        } else {
                            Some(format!("{}+0x{:x}", symbol, file_offset))
                        }
                    } else if !module.is_empty() {
                        // Extract just the filename for cleaner output
                        let filename = std::path::Path::new(&module)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(&module);
                        Some(format!("<{}+0x{:x}>", filename, file_offset))
                    } else {
                        None
                    }
                }
                Err(e) => {
                    jtrace!("Symbol resolution failed for 0x{:x}: {}", addr, e);
                    None
                }
            }
        } else {
            None
        };

        // Cache the result
        self.symbol_cache.insert(addr, result.clone());

        // Limit cache size to prevent memory growth
        if self.symbol_cache_limit > 0 && self.symbol_cache.len() > self.symbol_cache_limit {
            jtrace!(
                "Symbol cache size limit ({}) reached, clearing oldest entries",
                self.symbol_cache_limit
            );
            // Clear half the cache to avoid frequent clearing
            let keys_to_remove: Vec<u64> = self
                .symbol_cache
                .keys()
                .take(self.symbol_cache.len() / 2)
                .copied()
                .collect();
            for key in keys_to_remove {
                self.symbol_cache.remove(&key);
            }
        }

        result
    }

    /// Resolve address with VMA fallback when symbol resolution fails
    fn resolve_address_with_fallback(
        &mut self,
        pid: u32,
        addr: u64,
        vma_info: &Option<VmaInfo>,
    ) -> String {
        // Try normal symbol resolution first
        if let Some(symbol) = self.resolve_address(pid, addr) {
            return symbol;
        }

        // Fallback to VMA-based resolution
        if let Some(vma) = vma_info {
            return self.resolve_with_vma(addr, vma);
        }

        // Last resort: just the address
        format!("0x{:016x}", addr)
    }

    /// Calculate file offset from VMA offset using ELF parsing
    fn calculate_file_offset(&self, vma_offset: u64, binary_path: &str) -> u64 {
        // Try to get the actual text segment base address from the ELF file
        match tracelib::ElfFile::new(binary_path) {
            Ok(elf_file) => {
                match elf_file.get_text_base_address() {
                    Ok(Some(text_base)) => {
                        // Add the actual ELF text segment base address
                        vma_offset + text_base
                    }
                    Ok(None) => {
                        // No text segment found, use VMA offset as-is
                        jtrace!("No executable segment found in {}", binary_path);
                        vma_offset
                    }
                    Err(e) => {
                        // ELF parsing failed, fall back to heuristic
                        jtrace!("Failed to get text base for {}: {}", binary_path, e);
                        self.calculate_file_offset_fallback(vma_offset, binary_path)
                    }
                }
            }
            Err(e) => {
                // ELF file creation failed, fall back to heuristic
                jtrace!("Failed to open ELF file {}: {}", binary_path, e);
                self.calculate_file_offset_fallback(vma_offset, binary_path)
            }
        }
    }

    /// Fallback file offset calculation using heuristics
    fn calculate_file_offset_fallback(&self, vma_offset: u64, binary_path: &str) -> u64 {
        if binary_path.contains(".so") {
            // For shared libraries, VMA offset often matches file offset
            vma_offset
        } else {
            // For executables, use common ELF text base (0x1000) as fallback
            vma_offset + 0x1000
        }
    }

    /// Resolve address using VMA information to calculate offset in binary
    fn resolve_with_vma(&self, addr: u64, vma: &VmaInfo) -> String {
        // Validate that address is within VMA range
        if addr < vma.start || addr >= vma.end {
            return format!("0x{:016x} [addr_outside_vma]", addr);
        }

        let vma_offset = addr - vma.start;

        match &vma.mapping_name {
            Some(binary_path) => {
                // Calculate the file offset that matches objdump/addr2line
                let file_offset = self.calculate_file_offset(vma_offset, binary_path);

                // Extract just the filename for cleaner output
                let filename = std::path::Path::new(binary_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(binary_path);

                format!("0x{:016x} <{}+0x{:x}>", addr, filename, file_offset)
            }
            None => {
                // Anonymous mapping or no path available
                format!("0x{:016x} <anon_mapping+0x{:x}>", addr, vma_offset)
            }
        }
    }

    /// Find appropriate VMA info for a given address from stack trace
    /// Since BPF only captures VMA for instruction pointer, we use heuristics for stack addresses
    fn find_vma_for_stack_address<'a>(
        &self,
        addr: u64,
        event: &'a SegfaultEvent,
    ) -> Option<&'a VmaInfo> {
        // For now, we'll use the instruction pointer's VMA as a fallback
        // This works well for addresses in the same binary/library
        if let Some(ref vma) = event.vma_info {
            // Check if the stack address falls within the same VMA
            if addr >= vma.start && addr < vma.end {
                return Some(vma);
            }
        }

        // TODO: Future enhancement could capture multiple VMA entries in BPF
        // or use address range heuristics to determine likely VMA
        None
    }
}

impl EventProcessor for ConsoleProcessor {
    fn process_event(&mut self, event: &SegfaultEvent) -> Result<(), JtraceError> {
        // Track event processing
        if let Some(ref stats_manager) = self.stats_manager {
            if let Ok(mut stats) = stats_manager.lock() {
                stats.increment_events_processed();
            }
        }
        // Format timestamp
        let timestamp = event
            .timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let datetime =
            chrono::DateTime::from_timestamp(timestamp.as_secs() as i64, timestamp.subsec_nanos())
                .unwrap_or_default();

        println!(
            "[{}] {} in process {} (PID: {}, TID: {})",
            datetime.format("%Y-%m-%d %H:%M:%S%.3f"),
            event.event_type.as_str(),
            event.comm,
            event.pid,
            event.tid
        );

        // Only show fault address for segfaults (not meaningful for SIGABRT)
        if event.event_type == EventType::Segfault {
            println!("  Fault Address: 0x{:016x}", event.fault_address);
        }

        // Display instruction pointer with enhanced symbol resolution
        let ip_symbol = self.resolve_address_with_fallback(
            event.pid,
            event.instruction_pointer,
            &event.vma_info,
        );
        println!("  Instruction:   {}", ip_symbol);

        println!("  Fault Type:    {}", event.fault_type.as_str());

        // Display VMA information if available and valid
        if let Some(ref vma) = event.vma_info {
            // Validate VMA data before displaying
            if vma.start > 0 && vma.end > vma.start && vma.start < 0x800000000000 {
                println!("  \n  Memory Mapping:");
                println!("    VMA Range:   0x{:016x} - 0x{:016x}", vma.start, vma.end);
                println!("    VMA Size:    {} KB", (vma.end - vma.start) / 1024);
                println!("    Permissions: {}", vma.permissions);
                if let Some(ref path) = vma.mapping_name {
                    println!("    Module:      {}", path);
                }
                let offset = event.instruction_pointer.wrapping_sub(vma.start);
                println!("    IP Offset:   0x{:x}", offset);
            } else {
                jtrace!(
                    "Invalid VMA data: start=0x{:x}, end=0x{:x}",
                    vma.start,
                    vma.end
                );
            }
        }

        if self.show_registers {
            if let Some(ref registers) = event.registers {
                println!("  \n  Registers ({}):", registers.architecture);
                for (name, value) in &registers.registers {
                    println!("    {}: 0x{:016x}", name, value);
                }
            }
        }

        if self.show_stack_trace {
            if let Some(ref stack_trace) = event.stack_trace {
                // Add reliability warning for abort events with potentially corrupted stacks
                if event.event_type == EventType::Abort && !event.stack_trace_reliable {
                    println!(
                        "  \n  Stack Trace ({} frames) - MAY BE UNRELIABLE DUE TO CORRUPTION:",
                        stack_trace.len()
                    );
                } else {
                    println!("  \n  Stack Trace ({} frames):", stack_trace.len());
                }

                for (i, addr) in stack_trace.iter().enumerate() {
                    // Try to find appropriate VMA for this stack address
                    let vma_for_addr = self.find_vma_for_stack_address(*addr, event);
                    let vma_option = vma_for_addr.cloned().or_else(|| event.vma_info.clone());

                    let symbol = self.resolve_address_with_fallback(event.pid, *addr, &vma_option);
                    println!("    #{:<2} {}", i, symbol);
                }
            } else {
                println!("  \n  Stack Trace: Not available");
            }
        }

        println!(); // Empty line for readability
        Ok(())
    }

    fn flush(&mut self) -> Result<(), JtraceError> {
        use std::io::{self, Write};
        io::stdout().flush().map_err(|e| {
            Report::new(JtraceError::IOError)
                .attach_printable(format!("Failed to flush stdout: {}", e))
        })
    }
}

/// JSON-based event processor with symbol resolution
pub struct JsonProcessor {
    exec_map: Option<ExecMap>,
    symbol_cache: HashMap<u64, Option<String>>,
    current_pid: Option<u32>,
    include_symbols: bool,
    stats_manager: Option<Arc<std::sync::Mutex<StatisticsManager>>>,
    symbol_cache_limit: usize,
    memory_limit_bytes: u64,
}

impl JsonProcessor {
    pub fn new(include_symbols: bool) -> Self {
        Self {
            exec_map: None,
            symbol_cache: HashMap::new(),
            current_pid: None,
            include_symbols,
            stats_manager: None,
            symbol_cache_limit: 1000,
            memory_limit_bytes: 100 * 1024 * 1024, // 100MB default
        }
    }

    pub fn with_stats_manager(
        mut self,
        stats_manager: Arc<std::sync::Mutex<StatisticsManager>>,
    ) -> Self {
        self.stats_manager = Some(stats_manager);
        self
    }

    pub fn with_memory_limits(mut self, symbol_cache_limit: usize, memory_limit_mb: u64) -> Self {
        self.symbol_cache_limit = symbol_cache_limit;
        self.memory_limit_bytes = memory_limit_mb * 1024 * 1024;
        self
    }

    /// Initialize exec map for a specific process
    fn ensure_exec_map(&mut self, pid: u32) -> Result<(), JtraceError> {
        // Check if we need to reinitialize for a different PID
        if self.current_pid != Some(pid) {
            jdebug!(
                "Switching exec map from PID {:?} to PID {}",
                self.current_pid,
                pid
            );
            self.exec_map = None;
            self.symbol_cache.clear();
            self.current_pid = Some(pid);
        }

        if self.exec_map.is_none() && self.include_symbols {
            match ExecMap::new(pid) {
                Ok(exec_map) => {
                    jdebug!("Initialized exec map for PID {}", pid);
                    self.exec_map = Some(exec_map);
                }
                Err(e) => {
                    jwarn!("Failed to initialize exec map for PID {}: {}", pid, e);
                    // Continue without symbol resolution
                    return Err(Report::new(JtraceError::SymbolAnalyzerError)
                        .attach_printable(format!("Exec map initialization failed: {}", e)));
                }
            }
        }
        Ok(())
    }

    /// Resolve an address to symbol information with caching
    fn resolve_address(&mut self, pid: u32, addr: u64) -> Option<String> {
        if !self.include_symbols {
            return None;
        }

        // Check cache first
        if let Some(cached_result) = self.symbol_cache.get(&addr) {
            // Track cache hit
            if let Some(ref stats_manager) = self.stats_manager {
                if let Ok(mut stats) = stats_manager.lock() {
                    stats.increment_symbol_cache_hit();
                }
            }
            return cached_result.clone();
        }

        // Track cache miss
        if let Some(ref stats_manager) = self.stats_manager {
            if let Ok(mut stats) = stats_manager.lock() {
                stats.increment_symbol_cache_miss();
            }
        }

        // Ensure we have an exec map for this PID
        if self.ensure_exec_map(pid).is_err() {
            self.symbol_cache.insert(addr, None);
            return None;
        }

        let result = if let Some(ref mut exec_map) = self.exec_map {
            match exec_map.symbol(addr) {
                Ok((vma_offset, symbol, module)) => {
                    // Convert VMA offset to file offset for accurate symbol resolution
                    let file_offset = self.calculate_file_offset(vma_offset, &module);

                    if !symbol.is_empty() {
                        if !module.is_empty() {
                            // Extract just the filename for cleaner output
                            let filename = std::path::Path::new(&module)
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or(&module);
                            Some(format!("{}+0x{:x} ({})", symbol, file_offset, filename))
                        } else {
                            Some(format!("{}+0x{:x}", symbol, file_offset))
                        }
                    } else if !module.is_empty() {
                        // Extract just the filename for cleaner output
                        let filename = std::path::Path::new(&module)
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or(&module);
                        Some(format!("<{}+0x{:x}>", filename, file_offset))
                    } else {
                        None
                    }
                }
                Err(e) => {
                    jtrace!("Symbol resolution failed for 0x{:x}: {}", addr, e);
                    None
                }
            }
        } else {
            None
        };

        // Cache the result
        self.symbol_cache.insert(addr, result.clone());

        // Limit cache size to prevent memory growth
        if self.symbol_cache_limit > 0 && self.symbol_cache.len() > self.symbol_cache_limit {
            jtrace!(
                "Symbol cache size limit ({}) reached, clearing oldest entries",
                self.symbol_cache_limit
            );
            // Clear half the cache to avoid frequent clearing
            let keys_to_remove: Vec<u64> = self
                .symbol_cache
                .keys()
                .take(self.symbol_cache.len() / 2)
                .copied()
                .collect();
            for key in keys_to_remove {
                self.symbol_cache.remove(&key);
            }
        }

        result
    }

    /// Resolve address with VMA fallback when symbol resolution fails
    fn resolve_address_with_fallback(
        &mut self,
        pid: u32,
        addr: u64,
        vma_info: &Option<VmaInfo>,
    ) -> Option<String> {
        // Try normal symbol resolution first
        if let Some(symbol) = self.resolve_address(pid, addr) {
            return Some(symbol);
        }

        // Fallback to VMA-based resolution if symbols are enabled
        if self.include_symbols {
            if let Some(vma) = vma_info {
                return Some(self.resolve_with_vma(addr, vma));
            }
        }

        // No symbol resolution requested or no VMA info available
        None
    }

    /// Calculate file offset from VMA offset using ELF parsing
    fn calculate_file_offset(&self, vma_offset: u64, binary_path: &str) -> u64 {
        // Try to get the actual text segment base address from the ELF file
        match tracelib::ElfFile::new(binary_path) {
            Ok(elf_file) => {
                match elf_file.get_text_base_address() {
                    Ok(Some(text_base)) => {
                        // Add the actual ELF text segment base address
                        vma_offset + text_base
                    }
                    Ok(None) => {
                        // No text segment found, use VMA offset as-is
                        jtrace!("No executable segment found in {}", binary_path);
                        vma_offset
                    }
                    Err(e) => {
                        // ELF parsing failed, fall back to heuristic
                        jtrace!("Failed to get text base for {}: {}", binary_path, e);
                        self.calculate_file_offset_fallback(vma_offset, binary_path)
                    }
                }
            }
            Err(e) => {
                // ELF file creation failed, fall back to heuristic
                jtrace!("Failed to open ELF file {}: {}", binary_path, e);
                self.calculate_file_offset_fallback(vma_offset, binary_path)
            }
        }
    }

    /// Fallback file offset calculation using heuristics
    fn calculate_file_offset_fallback(&self, vma_offset: u64, binary_path: &str) -> u64 {
        if binary_path.contains(".so") {
            // For shared libraries, VMA offset often matches file offset
            vma_offset
        } else {
            // For executables, use common ELF text base (0x1000) as fallback
            vma_offset + 0x1000
        }
    }

    /// Resolve address using VMA information to calculate offset in binary
    fn resolve_with_vma(&self, addr: u64, vma: &VmaInfo) -> String {
        // Validate that address is within VMA range
        if addr < vma.start || addr >= vma.end {
            return format!("0x{:016x} [addr_outside_vma]", addr);
        }

        let vma_offset = addr - vma.start;

        match &vma.mapping_name {
            Some(binary_path) => {
                // Calculate the file offset that matches objdump/addr2line
                let file_offset = self.calculate_file_offset(vma_offset, binary_path);

                // Extract just the filename for cleaner output
                let filename = std::path::Path::new(binary_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(binary_path);

                format!("{}+0x{:x}", filename, file_offset)
            }
            None => {
                // Anonymous mapping or no path available
                format!("anon_mapping+0x{:x}", vma_offset)
            }
        }
    }

    /// Create a JSON-serializable event with optional symbol resolution
    fn create_json_event(&mut self, event: &SegfaultEvent) -> JsonSegfaultEvent {
        let timestamp_ms = event
            .timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Resolve instruction pointer symbol with VMA fallback
        let instruction_symbol = self.resolve_address_with_fallback(
            event.pid,
            event.instruction_pointer,
            &event.vma_info,
        );

        // Resolve stack trace symbols
        let stack_trace = if let Some(ref stack_addrs) = event.stack_trace {
            let frames: Vec<JsonStackFrame> = stack_addrs
                .iter()
                .enumerate()
                .map(|(i, &addr)| {
                    let symbol =
                        self.resolve_address_with_fallback(event.pid, addr, &event.vma_info);

                    JsonStackFrame {
                        frame: i,
                        address: format!("0x{:016x}", addr),
                        symbol,
                    }
                })
                .collect();
            Some(frames)
        } else {
            None
        };

        JsonSegfaultEvent {
            timestamp_ms,
            pid: event.pid,
            tid: event.tid,
            comm: event.comm.clone(),
            signal_number: event.signal_number,
            event_type: match event.event_type {
                EventType::Segfault => "segfault".to_string(),
                EventType::StackSmashing => "stack_smashing".to_string(),
                EventType::Abort => "abort".to_string(),
            },
            fault_address: format!("0x{:016x}", event.fault_address),
            instruction_pointer: format!("0x{:016x}", event.instruction_pointer),
            instruction_symbol,
            fault_type: match &event.fault_type {
                FaultType::MapError => "map_error".to_string(),
                FaultType::AccessError => "access_error".to_string(),
                FaultType::StackProtector => "stack_protector".to_string(),
                FaultType::Abort => "abort".to_string(),
                FaultType::Unknown(code) => format!("unknown_{}", code),
            },
            stack_trace_reliable: event.stack_trace_reliable,
            registers: event.registers.as_ref().map(|regs| JsonRegisterState {
                architecture: regs.architecture.clone(),
                registers: regs
                    .registers
                    .iter()
                    .map(|(name, value)| (name.clone(), format!("0x{:016x}", value)))
                    .collect(),
            }),
            stack_trace,
            vma_info: event.vma_info.as_ref().map(|vma| JsonVmaInfo {
                start: format!("0x{:016x}", vma.start),
                end: format!("0x{:016x}", vma.end),
                permissions: vma.permissions.clone(),
                mapping_name: vma.mapping_name.clone(),
            }),
        }
    }
}

impl EventProcessor for JsonProcessor {
    fn process_event(&mut self, event: &SegfaultEvent) -> Result<(), JtraceError> {
        // Track event processing
        if let Some(ref stats_manager) = self.stats_manager {
            if let Ok(mut stats) = stats_manager.lock() {
                stats.increment_events_processed();
            }
        }
        let json_event = self.create_json_event(event);

        let json_str = serde_json::to_string(&json_event).map_err(|e| {
            Report::new(JtraceError::OutputError {
                message: format!("Failed to serialize event to JSON: {}", e),
            })
        })?;

        println!("{}", json_str);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), JtraceError> {
        use std::io::{self, Write};
        io::stdout().flush().map_err(|e| {
            Report::new(JtraceError::IOError)
                .attach_printable(format!("Failed to flush stdout: {}", e))
        })
    }
}

/// Statistics tracking structure
#[derive(Debug, Clone, Default)]
pub struct SegfaultStatistics {
    pub segfaults_total: u64,
    pub segfaults_filtered: u64,
    pub events_submitted: u64,
    pub events_dropped: u64,
    pub register_failures: u64,
    pub stack_failures: u64,
    pub fault_info_captured: u64,
    pub fault_info_missed: u64,
    pub vma_captured: u64,
    pub vma_failures: u64,
    pub events_processed: u64,
    pub symbol_cache_hits: u64,
    pub symbol_cache_misses: u64,
    pub memory_usage_bytes: u64,
}

impl SegfaultStatistics {
    /// Calculate derived statistics
    pub fn events_captured(&self) -> u64 {
        self.segfaults_total - self.segfaults_filtered
    }

    pub fn drop_rate(&self) -> f64 {
        if self.events_submitted == 0 {
            0.0
        } else {
            (self.events_dropped as f64) / (self.events_submitted as f64) * 100.0
        }
    }

    pub fn symbol_cache_hit_rate(&self) -> f64 {
        let total_lookups = self.symbol_cache_hits + self.symbol_cache_misses;
        if total_lookups == 0 {
            0.0
        } else {
            (self.symbol_cache_hits as f64) / (total_lookups as f64) * 100.0
        }
    }

    pub fn fault_info_capture_rate(&self) -> f64 {
        let total_attempts = self.fault_info_captured + self.fault_info_missed;
        if total_attempts == 0 {
            0.0
        } else {
            (self.fault_info_captured as f64) / (total_attempts as f64) * 100.0
        }
    }

    pub fn vma_capture_rate(&self) -> f64 {
        let total_attempts = self.vma_captured + self.vma_failures;
        if total_attempts == 0 {
            0.0
        } else {
            (self.vma_captured as f64) / (total_attempts as f64) * 100.0
        }
    }
}

/// JSON-serializable version of SegfaultEvent with string-formatted addresses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSegfaultEvent {
    pub timestamp_ms: u64,
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
    pub signal_number: u32,
    pub event_type: String,
    pub fault_address: String,
    pub instruction_pointer: String,
    pub instruction_symbol: Option<String>,
    pub fault_type: String,
    pub stack_trace_reliable: bool,
    pub registers: Option<JsonRegisterState>,
    pub stack_trace: Option<Vec<JsonStackFrame>>,
    pub vma_info: Option<JsonVmaInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRegisterState {
    pub architecture: String,
    pub registers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonStackFrame {
    pub frame: usize,
    pub address: String,
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonVmaInfo {
    pub start: String,
    pub end: String,
    pub permissions: String,
    pub mapping_name: Option<String>,
}

/// File-based event processor that wraps another processor
pub struct FileProcessor<T: EventProcessor> {
    inner_processor: T,
    writer: BufWriter<File>,
    file_path: PathBuf,
}

impl<T: EventProcessor> FileProcessor<T> {
    pub fn new(
        inner_processor: T,
        file_path: PathBuf,
        append_mode: bool,
    ) -> Result<Self, JtraceError> {
        // Validate file path
        if let Some(parent) = file_path.parent() {
            if !parent.exists() {
                return Err(Report::new(JtraceError::FileError {
                    path: file_path.clone(),
                    operation: "create".to_string(),
                    source: "Parent directory does not exist".to_string(),
                }));
            }
        }

        // Open file with appropriate mode
        let file = if append_mode {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file_path)
        } else {
            OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&file_path)
        }
        .map_err(|e| {
            Report::new(JtraceError::FileError {
                path: file_path.clone(),
                operation: if append_mode { "append" } else { "create" }.to_string(),
                source: e.to_string(),
            })
        })?;

        let writer = BufWriter::new(file);

        jinfo!(
            "Opened output file: {} (mode: {})",
            file_path.display(),
            if append_mode { "append" } else { "overwrite" }
        );

        Ok(Self {
            inner_processor,
            writer,
            file_path,
        })
    }
}

impl<T: EventProcessor> EventProcessor for FileProcessor<T> {
    fn process_event(&mut self, event: &SegfaultEvent) -> Result<(), JtraceError> {
        // Capture the output from the inner processor
        let output = capture_processor_output(&mut self.inner_processor, event)?;

        // Write to file
        self.writer.write_all(output.as_bytes()).map_err(|e| {
            Report::new(JtraceError::FileError {
                path: self.file_path.clone(),
                operation: "write".to_string(),
                source: e.to_string(),
            })
        })?;

        // Add newline for text format if not already present
        if !output.ends_with('\n') {
            self.writer.write_all(b"\n").map_err(|e| {
                Report::new(JtraceError::FileError {
                    path: self.file_path.clone(),
                    operation: "write".to_string(),
                    source: e.to_string(),
                })
            })?;
        }

        Ok(())
    }

    fn flush(&mut self) -> Result<(), JtraceError> {
        self.writer.flush().map_err(|e| {
            Report::new(JtraceError::FileError {
                path: self.file_path.clone(),
                operation: "flush".to_string(),
                source: e.to_string(),
            })
        })
    }
}

/// Capture output from a processor by using format functions
fn capture_processor_output<T: EventProcessor>(
    _processor: &mut T,
    event: &SegfaultEvent,
) -> Result<String, JtraceError> {
    // Use type name to determine the format
    let type_name = std::any::type_name::<T>();

    if type_name.contains("ConsoleProcessor") {
        format_event_as_text(event)
    } else if type_name.contains("JsonProcessor") {
        format_event_as_json(event)
    } else {
        Err(Report::new(JtraceError::OutputError {
            message: "Unknown processor type for file output".to_string(),
        }))
    }
}

/// Format event as text for file output
fn format_event_as_text(event: &SegfaultEvent) -> Result<String, JtraceError> {
    let mut output = String::new();

    // Format timestamp
    let timestamp = event
        .timestamp
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let datetime =
        chrono::DateTime::from_timestamp(timestamp.as_secs() as i64, timestamp.subsec_nanos())
            .unwrap_or_default();

    output.push_str(&format!(
        "[{}] {} in process {} (PID: {}, TID: {})\n",
        datetime.format("%Y-%m-%d %H:%M:%S%.3f"),
        event.event_type.as_str(),
        event.comm,
        event.pid,
        event.tid
    ));

    // Only show fault address for segfaults
    if event.event_type == EventType::Segfault {
        output.push_str(&format!(
            "  Fault Address: 0x{:016x}\n",
            event.fault_address
        ));
    }
    output.push_str(&format!(
        "  Instruction:   0x{:016x}\n",
        event.instruction_pointer
    ));
    output.push_str(&format!("  Fault Type:    {}\n", event.fault_type.as_str()));

    if let Some(ref registers) = event.registers {
        output.push_str(&format!("  \n  Registers ({}):\n", registers.architecture));
        for (name, value) in &registers.registers {
            output.push_str(&format!("    {}: 0x{:016x}\n", name, value));
        }
    }

    if let Some(ref stack_trace) = event.stack_trace {
        output.push_str(&format!(
            "  \n  Stack Trace ({} frames):\n",
            stack_trace.len()
        ));
        for (i, addr) in stack_trace.iter().enumerate() {
            output.push_str(&format!("    #{:<2} 0x{:016x}\n", i, addr));
        }
    }

    output.push('\n'); // Empty line for readability
    Ok(output)
}

/// Format event as JSON for file output
fn format_event_as_json(event: &SegfaultEvent) -> Result<String, JtraceError> {
    let timestamp_ms = event
        .timestamp
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let json_event = JsonSegfaultEvent {
        timestamp_ms,
        pid: event.pid,
        tid: event.tid,
        comm: event.comm.clone(),
        signal_number: event.signal_number,
        event_type: match event.event_type {
            EventType::Segfault => "segfault".to_string(),
            EventType::StackSmashing => "stack_smashing".to_string(),
            EventType::Abort => "abort".to_string(),
        },
        fault_address: format!("0x{:016x}", event.fault_address),
        instruction_pointer: format!("0x{:016x}", event.instruction_pointer),
        instruction_symbol: None, // No symbol resolution for file output
        fault_type: match &event.fault_type {
            FaultType::MapError => "map_error".to_string(),
            FaultType::AccessError => "access_error".to_string(),
            FaultType::StackProtector => "stack_protector".to_string(),
            FaultType::Abort => "abort".to_string(),
            FaultType::Unknown(code) => format!("unknown_{}", code),
        },
        stack_trace_reliable: event.stack_trace_reliable,
        registers: event.registers.as_ref().map(|regs| JsonRegisterState {
            architecture: regs.architecture.clone(),
            registers: regs
                .registers
                .iter()
                .map(|(name, value)| (name.clone(), format!("0x{:016x}", value)))
                .collect(),
        }),
        stack_trace: event.stack_trace.as_ref().map(|stack_addrs| {
            stack_addrs
                .iter()
                .enumerate()
                .map(|(i, &addr)| JsonStackFrame {
                    frame: i,
                    address: format!("0x{:016x}", addr),
                    symbol: None, // No symbol resolution for file output
                })
                .collect()
        }),
        vma_info: event.vma_info.as_ref().map(|vma| JsonVmaInfo {
            start: format!("0x{:016x}", vma.start),
            end: format!("0x{:016x}", vma.end),
            permissions: vma.permissions.clone(),
            mapping_name: vma.mapping_name.clone(),
        }),
    };

    serde_json::to_string(&json_event).map_err(|e| {
        Report::new(JtraceError::OutputError {
            message: format!("Failed to serialize event to JSON: {}", e),
        })
    })
}

/// Parse BPF event data into Rust SegfaultEvent structure
fn parse_bpf_event(data: &[u8]) -> Result<SegfaultEvent, JtraceError> {
    // Validate input data size
    let expected_size = std::mem::size_of::<SegfaultEventBpf>();
    if data.len() < expected_size {
        return Err(
            Report::new(JtraceError::InvalidData).attach_printable(format!(
                "BPF event data too small: got {} bytes, expected at least {} bytes",
                data.len(),
                expected_size
            )),
        );
    }

    // Parse BPF event structure
    let mut bpf_event = SegfaultEventBpf::default();
    plain::copy_from_bytes(&mut bpf_event, data).map_err(|e| {
        Report::new(JtraceError::InvalidData)
            .attach_printable(format!("Failed to parse BPF event data: {:?}", e))
    })?;

    // Validate basic event fields
    if bpf_event.pid == 0 {
        return Err(
            Report::new(JtraceError::InvalidData).attach_printable("Invalid PID in BPF event")
        );
    }

    if bpf_event.timestamp_ns == 0 {
        return Err(Report::new(JtraceError::InvalidData)
            .attach_printable("Invalid timestamp in BPF event"));
    }

    // Convert BPF event to Rust event
    let comm = unsafe { bytes_to_string(bpf_event.comm.as_ptr()) };
    let timestamp = SystemTime::UNIX_EPOCH + Duration::from_nanos(bpf_event.timestamp_ns);
    let signal_number = bpf_event.signal_number;

    // Stack trace reliability flag
    let stack_trace_reliable = bpf_event.stack_reliable != 0;

    // Extract stack trace from stack map using stack_id
    let stack_trace = if bpf_event.stack_id >= 0 {
        // Get stack trace from BPF stack map
        unsafe {
            if let Some(skel_ptr) = BPF_SKEL {
                let skel = &*skel_ptr;
                let maps = skel.maps();
                let stack_traces_map = maps.stack_traces();

                // Look up stack trace using stack_id
                let stack_id_bytes = (bpf_event.stack_id as u32).to_ne_bytes();
                match stack_traces_map.lookup(&stack_id_bytes, MapFlags::ANY) {
                    Ok(Some(stack_data)) => {
                        // Stack map stores u64 addresses
                        // MAX_STACK_DEPTH is 32, so max size is 32 * 8 = 256 bytes
                        let num_frames = stack_data.len() / 8;
                        let mut frames = Vec::new();

                        for i in 0..num_frames {
                            let offset = i * 8;
                            if offset + 8 <= stack_data.len() {
                                let addr = u64::from_ne_bytes([
                                    stack_data[offset],
                                    stack_data[offset + 1],
                                    stack_data[offset + 2],
                                    stack_data[offset + 3],
                                    stack_data[offset + 4],
                                    stack_data[offset + 5],
                                    stack_data[offset + 6],
                                    stack_data[offset + 7],
                                ]);

                                // Stop at first null address (end of stack trace)
                                if addr == 0 {
                                    break;
                                }

                                // Validate address is reasonable for userspace
                                if addr > 0x1000 && addr < 0x7fffffffffff {
                                    frames.push(addr);
                                }
                            }
                        }

                        if !frames.is_empty() {
                            jtrace!(
                                "Retrieved {} stack frames from stack map (stack_id={})",
                                frames.len(),
                                bpf_event.stack_id
                            );
                            Some(frames)
                        } else {
                            jtrace!(
                                "No valid frames in stack map entry (stack_id={})",
                                bpf_event.stack_id
                            );
                            None
                        }
                    }
                    Ok(None) => {
                        jtrace!("Stack ID {} not found in stack map", bpf_event.stack_id);
                        None
                    }
                    Err(e) => {
                        jtrace!("Failed to lookup stack trace from map: {}", e);
                        None
                    }
                }
            } else {
                jtrace!("BPF skeleton not available for stack trace lookup");
                None
            }
        }
    } else if bpf_event.stack_size > 0 {
        // Fallback: use direct stack trace buffer from BPF event
        let stack_len = (bpf_event.stack_size as usize).min(bpf_event.stack_trace.len());
        let mut frames = Vec::new();

        for i in 0..stack_len {
            let addr = bpf_event.stack_trace[i];
            // Stop at first null address
            if addr == 0 {
                break;
            }
            // Validate address is reasonable for userspace
            if addr > 0x1000 && addr < 0x7fffffffffff {
                frames.push(addr);
            }
        }

        if !frames.is_empty() {
            jtrace!(
                "Retrieved {} stack frames from direct buffer (stack_size={})",
                frames.len(),
                bpf_event.stack_size
            );
            Some(frames)
        } else {
            jtrace!("No valid frames in direct stack buffer");
            None
        }
    } else {
        jtrace!(
            "No stack trace available (stack_id={}, stack_size={})",
            bpf_event.stack_id,
            bpf_event.stack_size
        );
        None
    };

    // Extract and validate register state if available
    let registers = if bpf_event.register_count > 0 {
        let mut reg_map = HashMap::new();
        let reg_count = (bpf_event.register_count as usize).min(bpf_event.registers.len());

        // Validate register count is reasonable
        if reg_count > 16 {
            jwarn!(
                "Unusually high register count: {}, capping at 16",
                reg_count
            );
        }

        // Add architecture-specific register names matching BPF capture order
        #[cfg(target_arch = "x86_64")]
        let reg_names = [
            "RIP", "RSP", "RBP", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10",
            "R11", "R12", "R13", "R14",
        ];

        #[cfg(target_arch = "aarch64")]
        let reg_names = [
            "PC", "SP", "FP", "LR", "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7", "X8", "X9",
            "X10", "X11",
        ];

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let reg_names = [
            "REG0", "REG1", "REG2", "REG3", "REG4", "REG5", "REG6", "REG7", "REG8", "REG9",
            "REG10", "REG11", "REG12", "REG13", "REG14", "REG15",
        ];

        for i in 0..reg_count.min(16) {
            if i < reg_names.len() {
                let reg_value = bpf_event.registers[i];
                // Only include non-zero register values (zero might indicate uninitialized)
                if reg_value != 0 {
                    reg_map.insert(reg_names[i].to_string(), reg_value);
                }
            }
        }

        if reg_map.is_empty() {
            jtrace!("No valid registers found in {} register entries", reg_count);
            None // No registers captured
        } else {
            jtrace!(
                "Parsed {} valid registers from {} total entries",
                reg_map.len(),
                reg_count
            );
            Some(RegisterState {
                architecture: std::env::consts::ARCH.to_string(),
                registers: reg_map,
            })
        }
    } else {
        None
    };

    // Extract VMA info if available
    let vma_info = if bpf_event.vma_start != 0 || bpf_event.vma_end != 0 {
        // Extract VMA path if present
        let vma_path = unsafe { bytes_to_string(bpf_event.vma_path.as_ptr()) };
        let mapping_name = if !vma_path.is_empty() {
            Some(vma_path)
        } else {
            None
        };

        Some(VmaInfo {
            start: bpf_event.vma_start,
            end: bpf_event.vma_end,
            permissions: format!("0x{:x}", bpf_event.vma_flags),
            mapping_name,
        })
    } else {
        None
    };

    // Classify event type and fault type based on signal
    let (event_type, fault_type) = if signal_number == 11 {
        // SIGSEGV - segfault
        (
            EventType::Segfault,
            FaultType::from_si_code(bpf_event.fault_code as i32, signal_number),
        )
    } else if signal_number == 6 {
        // SIGABRT - abort (may include stack smashing, check stack trace)
        (EventType::Abort, FaultType::Abort)
    } else {
        // Unknown signal
        (
            EventType::Segfault,
            FaultType::from_si_code(bpf_event.fault_code as i32, signal_number),
        )
    };

    // Create and validate the final event
    let event = SegfaultEvent {
        pid: bpf_event.pid,
        tid: bpf_event.tid,
        comm,
        timestamp,
        signal_number,
        event_type,
        fault_address: bpf_event.fault_addr,
        instruction_pointer: bpf_event.instruction_ptr,
        fault_type,
        registers,
        stack_trace,
        stack_trace_reliable,
        vulnerable_function: None, // Will be set by classification logic if needed
        vma_info,
    };

    // Log event summary for debugging
    jtrace!(
        "Parsed event: PID={}, TID={}, comm='{}', signal={}, type={:?}, fault_addr=0x{:x}, ip=0x{:x}, fault_type={:?}",
        event.pid,
        event.tid,
        event.comm,
        event.signal_number,
        event.event_type,
        event.fault_address,
        event.instruction_pointer,
        event.fault_type
    );

    Ok(event)
}

/// Check if the program was interrupted by signal
fn check_interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

/// Set up signal handler for graceful shutdown
fn setup_signal_handler() -> Result<(), JtraceError> {
    ctrlc::set_handler(move || {
        jinfo!("Received interrupt signal, shutting down...");
        INTERRUPTED.store(true, Ordering::Relaxed);
    })
    .map_err(|e| {
        Report::new(JtraceError::UnExpected)
            .attach_printable(format!("Failed to set signal handler: {}", e))
    })
}

/// Global event processor for ring buffer callback
static mut EVENT_PROCESSOR: Option<Box<dyn EventProcessor>> = None;

/// Global process name filter
static mut PROCESS_NAME_FILTER: Option<String> = None;

/// Global reference to BPF skeleton for stack trace lookup
static mut BPF_SKEL: Option<*const SegfaultAnalyzerSkel> = None;

/// Global event statistics
static EVENT_STATS: Mutex<EventStats> = Mutex::new(EventStats {
    events_received: 0,
    events_parsed: 0,
    events_processed: 0,
    events_filtered_name: 0,
    parse_errors: 0,
    process_errors: 0,
});

/// Event processing statistics
#[derive(Debug)]
struct EventStats {
    events_received: u64,
    events_parsed: u64,
    events_processed: u64,
    events_filtered_name: u64,
    parse_errors: u64,
    process_errors: u64,
}

fn events_received() -> u64 {
    EVENT_STATS.lock().unwrap().events_received
}

fn events_parsed() -> u64 {
    EVENT_STATS.lock().unwrap().events_parsed
}

fn events_processed() -> u64 {
    EVENT_STATS.lock().unwrap().events_processed
}

fn events_filtered_name() -> u64 {
    EVENT_STATS.lock().unwrap().events_filtered_name
}

fn events_parse_errors() -> u64 {
    EVENT_STATS.lock().unwrap().parse_errors
}

fn events_process_errors() -> u64 {
    EVENT_STATS.lock().unwrap().process_errors
}

fn increase_events_received() {
    EVENT_STATS.lock().unwrap().events_received += 1;
}

fn increase_events_parsed() {
    EVENT_STATS.lock().unwrap().events_parsed += 1;
}

fn increase_events_processed() {
    EVENT_STATS.lock().unwrap().events_processed += 1;
}

fn increase_events_filtered_name() {
    EVENT_STATS.lock().unwrap().events_filtered_name += 1;
}

fn increase_parse_errors() {
    EVENT_STATS.lock().unwrap().parse_errors += 1;
}

fn increase_process_errors() {
    EVENT_STATS.lock().unwrap().process_errors += 1;
}

/// Check if event should be filtered based on process name
fn should_filter_process_name(comm: &str) -> bool {
    unsafe {
        if let Some(ref filter) = PROCESS_NAME_FILTER {
            // Support partial name matching (contains)
            !comm.contains(filter)
        } else {
            false // No filter, don't filter out
        }
    }
}

/// Ring buffer event handler callback
fn handle_event(data: &[u8]) -> i32 {
    increase_events_received();

    match parse_bpf_event(data) {
        Ok(event) => {
            increase_events_parsed();

            // Apply process name filter if specified
            if should_filter_process_name(&event.comm) {
                increase_events_filtered_name();
                jtrace!(
                    "Filtering out event for process '{}' (doesn't match filter)",
                    event.comm
                );
                return 0; // Filtered out, but not an error
            }

            // Process the event using the global processor
            unsafe {
                if let Some(ref mut processor) = EVENT_PROCESSOR {
                    match processor.process_event(&event) {
                        Ok(()) => {
                            increase_events_processed();
                            0 // Success
                        }
                        Err(e) => {
                            increase_process_errors();

                            jerror!(
                                "Failed to process segfault event for PID {}: {}",
                                event.pid,
                                e
                            );
                            1 // Error
                        }
                    }
                } else {
                    jerror!("Event processor not initialized");
                    1 // Error
                }
            }
        }
        Err(e) => {
            increase_parse_errors();
            jerror!(
                "Failed to parse BPF event (size: {} bytes): {}",
                data.len(),
                e
            );
            1 // Error
        }
    }
}

/// Print BPF program statistics
fn print_statistics(skel: &SegfaultAnalyzerSkel) -> Result<(), JtraceError> {
    jinfo!("=== Segfault Analyzer Statistics ===");

    // Print BPF program statistics
    jinfo!("BPF Program Statistics:");
    let maps = skel.maps();
    let stats_map = maps.stats();

    // Statistics indices from BPF program
    let stat_names = [
        "Total segfaults detected",
        "Segfaults filtered (PID)",
        "Events submitted",
        "Events dropped",
        "Register capture failures",
        "Stack capture failures",
        "Fault info captured",
        "Fault info missed",
        "VMA info captured",
        "VMA capture failures",
    ];

    for (i, name) in stat_names.iter().enumerate() {
        let key = (i as u32).to_ne_bytes();
        match stats_map.lookup(&key, MapFlags::ANY) {
            Ok(Some(data)) => {
                let mut count = 0u64;
                if data.len() >= 8 {
                    count = u64::from_ne_bytes(data[0..8].try_into().unwrap_or([0; 8]));
                }
                jinfo!("  {}: {}", name, count);
            }
            Ok(None) => {
                jinfo!("  {}: 0", name);
            }
            Err(e) => {
                jwarn!("Failed to read statistic {}: {}", name, e);
            }
        }
    }

    // Print userspace event processing statistics
    jinfo!("Userspace Processing Statistics:");
    jinfo!("  Events received: {}", events_received());
    jinfo!("  Events parsed: {}", events_parsed());
    jinfo!("  Events processed: {}", events_processed());
    jinfo!("  Events filtered (name): {}", events_filtered_name());
    jinfo!("  Parse errors: {}", events_parse_errors());
    jinfo!("  Process errors: {}", events_process_errors());

    // Calculate success rates
    if events_received() > 0 {
        let parse_rate = (events_parsed() as f64 / events_received() as f64) * 100.0;
        let process_rate = (events_processed() as f64 / events_received() as f64) * 100.0;
        jinfo!("  Parse success rate: {:.1}%", parse_rate);
        jinfo!("  Process success rate: {:.1}%", process_rate);
    }

    Ok(())
}

/// Print BPF log messages
fn print_to_log(level: PrintLevel, msg: String) {
    match level {
        PrintLevel::Debug => jtrace!("{}", msg.trim_matches('\n')),
        PrintLevel::Info => jinfo!("{}", msg.trim_matches('\n')),
        PrintLevel::Warn => jwarn!("{}", msg.trim_matches('\n')),
    }
}

fn main() -> Result<(), JtraceError> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };

    JloggerBuilder::new()
        .max_level(log_level)
        .log_runtime(false)
        .build();

    jinfo!("Starting segfault analyzer...");

    // Set up signal handling
    setup_signal_handler()?;

    // Bump memory lock limit for BPF
    bump_memlock_rlimit();

    // Set BPF logging
    set_print(Some((PrintLevel::Debug, print_to_log)));

    jinfo!("Segfault analyzer initialized successfully");

    // Load and open BPF program
    let skel_builder = SegfaultAnalyzerSkelBuilder::default();
    let open_skel = skel_builder.open().map_err(|e| {
        Report::new(JtraceError::BPFError)
            .attach_printable(format!("Failed to open BPF skeleton: {}", e))
    })?;

    // Configure BPF program variables
    let mut skel = open_skel.load().map_err(|e| {
        Report::new(JtraceError::BPFError)
            .attach_printable(format!("Failed to load BPF program: {}", e))
    })?;

    // Set configuration variables
    if let Some(pid) = cli.pid {
        skel.bss().target_pid = pid;
        jinfo!("Filtering for PID: {}", pid);
    } else {
        skel.bss().target_pid = 0; // Monitor all processes
        jinfo!("Monitoring all processes");
    }

    // Set process name filter
    unsafe {
        PROCESS_NAME_FILTER = cli.process_name.clone();
        if let Some(ref name) = PROCESS_NAME_FILTER {
            jinfo!("Filtering for process name containing: '{}'", name);
        }
    }

    // Note: max_stack_depth is set as default in BPF program
    // TODO: Expose max_stack_depth in BPF skeleton for runtime configuration

    // Attach BPF programs
    skel.attach().map_err(|e| {
        Report::new(JtraceError::BPFError)
            .attach_printable(format!("Failed to attach BPF programs: {}", e))
    })?;

    jinfo!("BPF programs loaded and attached successfully");

    // Set up ring buffer for event processing
    let mut rbuilder = RingBufferBuilder::new();
    let maps = skel.maps();
    rbuilder.add(maps.events(), handle_event).map_err(|e| {
        Report::new(JtraceError::BPFError)
            .attach_printable(format!("Failed to add ring buffer: {}", e))
    })?;

    let ring_buffer = rbuilder.build().map_err(|e| {
        Report::new(JtraceError::BPFError)
            .attach_printable(format!("Failed to build ring buffer: {}", e))
    })?;

    jinfo!("Ring buffer set up successfully");

    // Create statistics manager
    let stats_manager = Arc::new(std::sync::Mutex::new(StatisticsManager::new()));
    let stats_manager_clone = Arc::clone(&stats_manager);

    // Create event processor based on output format and file options
    let processor: Box<dyn EventProcessor> = if let Some(output_path) = cli.output.clone() {
        // File output mode
        match cli.format {
            OutputFormat::Text => {
                let console_processor = ConsoleProcessor::new(cli.registers, cli.stack_trace)
                    .with_stats_manager(Arc::clone(&stats_manager))
                    .with_memory_limits(cli.symbol_cache_limit, cli.memory_limit);
                Box::new(FileProcessor::new(
                    console_processor,
                    output_path,
                    cli.append,
                )?)
            }
            OutputFormat::Json => {
                let include_symbols = cli.stack_trace || cli.registers;
                let json_processor = JsonProcessor::new(include_symbols)
                    .with_stats_manager(Arc::clone(&stats_manager))
                    .with_memory_limits(cli.symbol_cache_limit, cli.memory_limit);
                Box::new(FileProcessor::new(json_processor, output_path, cli.append)?)
            }
        }
    } else {
        // Console output mode
        match cli.format {
            OutputFormat::Text => {
                let console_processor = ConsoleProcessor::new(cli.registers, cli.stack_trace)
                    .with_stats_manager(Arc::clone(&stats_manager))
                    .with_memory_limits(cli.symbol_cache_limit, cli.memory_limit);
                Box::new(console_processor)
            }
            OutputFormat::Json => {
                let include_symbols = cli.stack_trace || cli.registers;
                let json_processor = JsonProcessor::new(include_symbols)
                    .with_stats_manager(Arc::clone(&stats_manager))
                    .with_memory_limits(cli.symbol_cache_limit, cli.memory_limit);
                Box::new(json_processor)
            }
        }
    };

    unsafe {
        EVENT_PROCESSOR = Some(processor);
        // Store skeleton reference for stack trace lookup
        BPF_SKEL = Some(&skel as *const _);
    }

    // Main event loop
    jinfo!("Starting segfault monitoring...");
    let start_time = std::time::Instant::now();

    loop {
        // Check for interruption
        if check_interrupted() {
            jinfo!("Received interrupt signal, shutting down...");
            break;
        }

        // Check duration limit
        if cli.duration > 0 && start_time.elapsed().as_secs() >= cli.duration {
            jinfo!("Duration limit reached, shutting down...");
            break;
        }

        // Display statistics if enabled and interval has passed
        if cli.stats {
            if let Ok(mut stats_mgr) = stats_manager_clone.lock() {
                if stats_mgr.should_display_stats(cli.stats_interval) {
                    match stats_mgr.collect_statistics(&skel) {
                        Ok(stats) => {
                            let elapsed = stats_mgr.get_start_time().elapsed().unwrap_or_default();
                            stats_mgr.display_statistics(&stats, elapsed);

                            // Check memory usage and warn if approaching limit
                            let memory_limit_bytes = cli.memory_limit * 1024 * 1024;
                            if !stats_mgr
                                .check_memory_limit(memory_limit_bytes, stats.memory_usage_bytes)
                            {
                                jwarn!(
                                    "Memory usage ({:.1} MB) exceeds limit ({} MB)",
                                    stats.memory_usage_bytes as f64 / (1024.0 * 1024.0),
                                    cli.memory_limit
                                );
                            } else {
                                let usage_pct = stats_mgr.memory_usage_percentage(
                                    memory_limit_bytes,
                                    stats.memory_usage_bytes,
                                );
                                if usage_pct > 80.0 {
                                    jwarn!("Memory usage is high: {:.1}% of limit", usage_pct);
                                }
                            }
                        }
                        Err(e) => {
                            jwarn!("Failed to collect statistics: {}", e);
                        }
                    }
                }
            }
        }

        // Print periodic statistics in verbose mode (legacy)
        if cli.verbose && !cli.stats && events_received() > 0 {
            let elapsed_secs = start_time.elapsed().as_secs();
            if elapsed_secs > 0 && elapsed_secs % 30 == 0 {
                jinfo!(
                    "Periodic stats: {} events received, {} processed, {} filtered (name), {}
                    errors",
                    events_received(),
                    events_processed(),
                    events_filtered_name(),
                    events_parse_errors() + events_process_errors()
                );
            }
        }

        // Poll for events with adaptive timeout based on activity
        let poll_timeout = if cli.stats {
            // Use shorter timeout when stats are enabled for more responsive display
            Duration::from_millis(50)
        } else {
            Duration::from_millis(100)
        };

        match ring_buffer.poll(poll_timeout) {
            Ok(_) => {
                // Events processed by callback
                // Flush output periodically to ensure timely display
                unsafe {
                    if let Some(ref mut processor) = EVENT_PROCESSOR {
                        if let Err(e) = processor.flush() {
                            jtrace!("Failed to flush processor output: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                jwarn!("Ring buffer poll error: {}", e);
                // Continue polling unless it's a critical error
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    // Print final statistics
    if cli.stats || cli.verbose {
        if let Ok(mut stats_mgr) = stats_manager_clone.lock() {
            match stats_mgr.collect_statistics(&skel) {
                Ok(stats) => {
                    let elapsed = stats_mgr.get_start_time().elapsed().unwrap_or_default();
                    println!("\n=== Final Statistics ===");
                    stats_mgr.display_statistics(&stats, elapsed);
                }
                Err(e) => {
                    jwarn!("Failed to collect final statistics: {}", e);
                    // Fall back to legacy statistics
                    print_statistics(&skel)?;
                }
            }
        }
    } else {
        print_statistics(&skel)?;
    }

    jinfo!("Segfault analyzer shutting down");
    Ok(())
}
