# Allocation Age Tracking Design Document - COMPLETED ✅

## Overview

**STATUS: FULLY IMPLEMENTED in v0.2.4** - This document described the design for adding allocation age tracking to the malloc_free tool. The feature has been successfully implemented and tracks how long each allocation has been unfreed, enabling users to distinguish between recent allocations (likely normal) and old allocations (likely leaked memory).

**Key Implementation Achievements:**
- ✅ Complete age tracking system for both Statistics and Trace modes
- ✅ Fixed fundamental age histogram bug (was showing incorrect data)
- ✅ Race condition prevention with thread-safe data structures
- ✅ Accurate memory size tracking with proper allocation size lookup
- ✅ Process-level aggregation for cross-thread allocation/free handling

The malloc_free tool operates in two primary modes:

1. **Statistics Mode** (default): Displays aggregate statistical information per process/thread, including memory usage totals and age-related statistics (oldest allocation age, average age)

2. **Trace Mode**: Shows individual allocation events, triggered by `--min-age` flag. Can be combined with `-t/-T` options to show stack traces for each allocation

The age tracking feature integrates with both modes, providing appropriate age information for each context.

## Architecture

### High-Level Design

The allocation age tracking feature extends the existing malloc_free architecture by:

1. **Adding timestamp fields** to existing data structures based on mode
2. **Implementing mode-aware data collection** in eBPF using `trace_mode` control
3. **Extending CLI interface** with age-related options that control eBPF mode
4. **Enhancing output formatting** to display age information per mode
5. **Eliminating race conditions** through thread-safe data passing mechanisms
6. **Ensuring accurate memory size tracking** with proper allocation size lookup
7. **Implementing process-level aggregation** for cross-thread allocation/free handling

### Critical Design Fixes

#### Race Condition Prevention

**Problem**: The original design used per-CPU arrays (`event_alloc_heap`) to pass data between uprobe and uretprobe, causing race conditions when multiple threads on the same CPU called malloc concurrently. This resulted in:
- TID corruption (wrong thread IDs in records)
- Timestamp loss (leading to "unknown" ages)
- CPU migration issues (thread moving between CPUs)

**Solution**: Replace per-CPU data passing with thread-safe hash map:

```c
// NEW: Thread-safe data passing between uprobe and uretprobe
struct inflight_alloc {
    u32 size;               // Allocation size from malloc parameter
    u64 timestamp_ns;       // Allocation timestamp from bpf_ktime_get_ns()
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);       // tid - safe because malloc is not reentrant per thread
    __type(value, struct inflight_alloc);
} inflight_allocs SEC(".maps");
```

**Per-CPU arrays are KEPT** for temporary storage to prevent BPF stack overflow (512-byte limit), but NOT used for cross-function data passing:

```c
// KEPT: Per-CPU arrays for temporary large struct storage (no race condition)
// Used ONLY within single function calls to avoid stack overflow
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct malloc_record);
} alloc_heap SEC(".maps");
```

#### Accurate Memory Size Tracking

**Problem**: Statistics Mode incorrectly tracked `free_size` as a counter (`free_size += 1`) instead of actual bytes freed.

**Solution**: Look up actual allocation size from event records:

```c
// OLD (incorrect): Just counting free operations
entry->free_size += 1;

// NEW (correct): Track actual bytes freed
struct malloc_event *event = lookup_event_by_ptr(ptr);
if (event) {
    entry->free_size += event->size;  // Actual allocation size
}
```

#### Process-Level Memory Tracking

**Problem**: Original design tracked statistics per-thread (TID), but memory can be allocated in one thread and freed in another thread of the same process.

**Solution**: Change `malloc_records` to use PID (process ID) as key instead of TID:

```c
// OLD: Per-thread tracking
struct {
    __type(key, u32);  // tid
    __type(value, struct malloc_record);
} malloc_records SEC(".maps");

// NEW: Per-process tracking
struct {
    __type(key, u32);  // pid - aggregates all threads in process
    __type(value, struct malloc_record);
} malloc_records SEC(".maps");
```

### Component Overview

```
┌─────────────────────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│         eBPF Program            │    │   Userspace      │    │   CLI Interface │
│                                 │    │   Controller     │    │                 │
│ ┌─────────────────────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │        trace_mode           │ │    │ │ Mode Control │ │    │ │ -t/-T       │ │
│ │     (bool variable)         │ │◄───┤ │ & Age Calc   │ │◄───┤ │ --min-age   │ │
│ └─────────────────────────────┘ │    │ └──────────────┘ │    │ │ --age-hist  │ │
│                                 │    │                  │    │ └─────────────┘ │
│ trace_mode = false:             │    │                  │    │                 │
│ ┌─────────────────────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │ malloc_records map          │ │    │ │ Statistics   │ │    │ │ Statistics  │ │
│ │ (aggregate per process)     │ │    │ │ Mode Output  │ │    │ │ Mode        │ │
│ └─────────────────────────────┘ │    │ └──────────────┘ │    │ └─────────────┘ │
│                                 │    │                  │    │                 │
│ trace_mode = true:              │    │                  │    │                 │
│ ┌─────────────────────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │ malloc_event_records map    │ │    │ │ Trace        │ │    │ │ Trace       │ │
│ │ (individual allocations)    │ │    │ │ Mode Output  │ │    │ │ Mode        │ │
│ └─────────────────────────────┘ │    │ └──────────────┘ │    │ └─────────────┘ │
└─────────────────────────────────┘    └──────────────────┘    └─────────────────┘
```

## Components and Interfaces

### 1. Enhanced Data Structures

#### eBPF Data Structure Changes

**Enhanced malloc_event structure:**
```c
struct malloc_event {
    // Existing fields
    u32 tid;
    char comm[TASK_COMM_LEN];
    u32 size;
    u32 free_tid;
    char free_comm[TASK_COMM_LEN];
    u64 sequence;
    s32 ustack_sz;
    u64 ustack[PERF_MAX_STACK_DEPTH];
    s32 free_ustack_sz;
    u64 free_ustack[PERF_MAX_STACK_DEPTH];
    
    // New age tracking fields
    u64 alloc_timestamp_ns;     // Allocation timestamp in nanoseconds
};
```

**Enhanced malloc_record structure:**
```c
struct malloc_record {
    // Existing fields
    u32 pid;
    u32 tid;
    char comm[TASK_COMM_LEN];
    u32 max_req_size;
    u32 max_size;
    u32 alloc_size;
    u32 free_size;
    s32 ustack_sz;
    u64 ustack[PERF_MAX_STACK_DEPTH];
    
    // New age tracking fields for Statistics Mode
    u64 oldest_alloc_timestamp; // Timestamp of oldest unfreed allocation
    u32 total_unfreed_count;    // Count of unfreed allocations for average calculation
    u64 total_age_sum_ns;       // Sum of all allocation ages for average calculation
    u32 age_histogram[4];       // Count of allocations in each age range (for --age-histogram)
};
```

#### Age Histogram Ranges

```c
// Age ranges for histogram display (Statistics Mode only)
#define AGE_RANGE_0_1MIN     0  // 0-1 minute
#define AGE_RANGE_1_5MIN     1  // 1-5 minutes  
#define AGE_RANGE_5_30MIN    2  // 5-30 minutes
#define AGE_RANGE_30MIN_PLUS 3  // 30+ minutes

// Age thresholds in nanoseconds for histogram
#define AGE_THRESHOLD_1MIN    (60ULL * 1000000000ULL)      // 1 minute
#define AGE_THRESHOLD_5MIN    (300ULL * 1000000000ULL)     // 5 minutes
#define AGE_THRESHOLD_30MIN   (1800ULL * 1000000000ULL)    // 30 minutes
```

### 2. eBPF Implementation

#### Mode Control Variable

**Global mode control variable:**
```c
// Renamed from trace_path to trace_mode for clarity
// Controls which data collection mode is active
bool trace_mode = false;  // false = Statistics Mode, true = Trace Mode
```

#### Race-Condition-Free Data Flow

**uprobe_malloc (Entry Point):**
```c
SEC("uprobe/")
int BPF_KPROBE(uprobe_malloc, int size)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;
    
    // Store allocation info in thread-safe inflight map
    struct inflight_alloc inflight = {
        .size = size,
        .timestamp_ns = bpf_ktime_get_ns()
    };
    
    bpf_map_update_elem(&inflight_allocs, &tid, &inflight, BPF_ANY);
    return 0;
}
```

**uretprobe_malloc (Return Point):**
```c
SEC("uprobe/")
int BPF_KRETPROBE(uretprobe_malloc, void *ptr)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;
    
    // Lookup inflight allocation data (thread-safe)
    struct inflight_alloc *inflight = bpf_map_lookup_elem(&inflight_allocs, &tid);
    if (!inflight || !ptr) {
        goto cleanup;
    }
    
    // Get/increment sequence number for this pointer
    u64 *seq_ptr = bpf_map_lookup_elem(&ptr_sequence, &ptr);
    u64 sequence = seq_ptr ? (*seq_ptr + 1) : 0;
    bpf_map_update_elem(&ptr_sequence, &ptr, &sequence, BPF_ANY);
    
    // Use per-CPU array for temporary storage (avoid stack overflow)
    u32 zero = 0;
    struct malloc_event *event = bpf_map_lookup_elem(&event_alloc_heap, &zero);
    if (!event) goto cleanup;
    
    // Prepare event record
    event->tid = tid;
    event->size = inflight->size;
    event->alloc_timestamp_ns = inflight->timestamp_ns;
    event->free_tid = u32::MAX;  // Not freed yet
    event->sequence = sequence;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    if (trace_mode) {
        // Trace Mode: Collect stack traces
        event->ustack_sz = bpf_get_stack(ctx, event->ustack, 
                                        sizeof(event->ustack), BPF_F_USER_STACK);
    } else {
        // Statistics Mode: No stack traces needed
        event->ustack_sz = -1;
    }
    
    // Store event record
    struct malloc_event_key key = {.ptr = ptr, .sequence = sequence};
    bpf_map_update_elem(&malloc_event_records, &key, event, BPF_ANY);
    
    // Update process-level statistics (keyed by PID, not TID)
    if (!trace_mode) {
        struct malloc_record *record = bpf_map_lookup_elem(&alloc_heap, &zero);
        if (record) {
            // Lookup existing process record or create new one
            struct malloc_record *proc_record = bpf_map_lookup_elem(&malloc_records, &pid);
            if (proc_record) {
                *record = *proc_record;  // Copy existing data
            } else {
                __builtin_memset(record, 0, sizeof(*record));
                record->pid = pid;
                record->tid = tid;
                bpf_get_current_comm(record->comm, sizeof(record->comm));
            }
            
            // Update statistics
            record->alloc_size += inflight->size;
            update_age_statistics(record, inflight->timestamp_ns);
            
            // Store updated record
            bpf_map_update_elem(&malloc_records, &pid, record, BPF_ANY);
        }
    }
    
cleanup:
    // Clean up inflight allocation
    bpf_map_delete_elem(&inflight_allocs, &tid);
    return 0;
}
```

**uprobe_free (Free Point):**
```c
SEC("uprobe/")
int BPF_KPROBE(uprobe_free, void *ptr)
{
    if (!ptr) return 0;
    
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;
    
    // Get sequence number for this pointer
    u64 *seq_ptr = bpf_map_lookup_elem(&ptr_sequence, &ptr);
    if (!seq_ptr) return 0;
    
    // Lookup the allocation event
    struct malloc_event_key key = {.ptr = ptr, .sequence = *seq_ptr};
    struct malloc_event *event = bpf_map_lookup_elem(&malloc_event_records, &key);
    if (!event) return 0;
    
    u32 actual_size = event->size;  // Get actual allocation size
    
    if (trace_mode) {
        // Trace Mode: Update event with free info, keep event
        event->free_tid = tid;
        bpf_get_current_comm(event->free_comm, sizeof(event->free_comm));
        event->free_ustack_sz = bpf_get_stack(ctx, event->free_ustack,
                                             sizeof(event->free_ustack), BPF_F_USER_STACK);
        bpf_map_update_elem(&malloc_event_records, &key, event, BPF_ANY);
    } else {
        // Statistics Mode: Update process stats, delete event to save memory
        u32 zero = 0;
        struct malloc_record *record = bpf_map_lookup_elem(&alloc_heap, &zero);
        if (record) {
            struct malloc_record *proc_record = bpf_map_lookup_elem(&malloc_records, &pid);
            if (proc_record) {
                *record = *proc_record;
                record->free_size += actual_size;  // ✅ Actual bytes, not counter!
                update_age_statistics_on_free(record, bpf_ktime_get_ns());
                bpf_map_update_elem(&malloc_records, &pid, record, BPF_ANY);
            }
        }
        
        // Delete event to save memory in Statistics Mode
        bpf_map_delete_elem(&malloc_event_records, &key);
    }
    
    return 0;
}
```

#### Statistics Mode Age Tracking

**Helper functions for Statistics Mode:**
```c
static void update_age_statistics(struct malloc_record *record, u64 alloc_timestamp_ns)
{
    // Update oldest allocation timestamp
    if (record->oldest_alloc_timestamp == 0 || 
        alloc_timestamp_ns < record->oldest_alloc_timestamp) {
        record->oldest_alloc_timestamp = alloc_timestamp_ns;
    }
    
    // Update running totals for average age calculation
    record->total_unfreed_count++;
    record->total_age_sum_ns += alloc_timestamp_ns;
    
    // Update age histogram if needed
    u32 age_range = calculate_age_histogram_range(alloc_timestamp_ns);
    record->age_histogram[age_range]++;
}

static u32 calculate_age_histogram_range(u64 alloc_timestamp_ns)
{
    u64 current_time = bpf_ktime_get_ns();
    u64 age_ns = current_time - alloc_timestamp_ns;
    
    if (age_ns < AGE_THRESHOLD_1MIN) {
        return AGE_RANGE_0_1MIN;
    } else if (age_ns < AGE_THRESHOLD_5MIN) {
        return AGE_RANGE_1_5MIN;
    } else if (age_ns < AGE_THRESHOLD_30MIN) {
        return AGE_RANGE_5_30MIN;
    } else {
        return AGE_RANGE_30MIN_PLUS;
    }
}
```

#### Mode Control from Userspace

**Setting eBPF mode from Rust:**
```rust
// In userspace (malloc_free.rs)
if cli.trace_path || cli.trace_full_path || cli.min_age.is_some() {
    // Set Trace Mode
    open_skel.bss().trace_mode = true;
} else {
    // Default to Statistics Mode  
    open_skel.bss().trace_mode = false;
}
```

### 3. Userspace Implementation

#### CLI Interface Extensions

**New command-line options:**
```rust
#[derive(Parser, Debug, Default)]
struct Cli {
    // ... existing fields ...
    
    /// Show only allocations older than specified age (e.g., 5m, 1h, 300s)
    /// Automatically switches to Trace Mode
    #[clap(long)]
    min_age: Option<String>,
    
    /// Show age distribution histogram (Statistics Mode only)
    #[clap(long)]
    age_histogram: bool,
}
```

**Mode switching behavior:**
- `--min-age` automatically sets `trace_mode = true` (Trace Mode)
- `-t/-T` options set `trace_mode = true` and enable stack trace collection
- `--age-histogram` works only when `trace_mode = false` (Statistics Mode)
- Userspace sets the eBPF `trace_mode` variable based on CLI flags

#### Age Parsing and Validation

**Age string parsing:**
```rust
#[derive(Debug, Clone)]
struct AgeDuration {
    seconds: u64,
}

impl AgeDuration {
    fn parse(age_str: &str) -> Result<Self, JtraceError> {
        let age_str = age_str.trim();
        
        // Handle different formats: "300", "300s", "5m", "1h"
        if let Some(captures) = AGE_REGEX.captures(age_str) {
            let value: u64 = captures.get(1).unwrap().as_str().parse()
                .map_err(|_| JtraceError::InvalidData)?;
            
            let unit = captures.get(2).map(|m| m.as_str()).unwrap_or("s");
            
            let seconds = match unit {
                "s" | "" => value,
                "m" => value * 60,
                "h" => value * 3600,
                _ => return Err(JtraceError::InvalidData),
            };
            
            Ok(AgeDuration { seconds })
        } else {
            Err(JtraceError::InvalidData)
        }
    }
    
    fn to_nanoseconds(&self) -> u64 {
        self.seconds * 1_000_000_000
    }
}

static AGE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(\d+)([smh]?)$").unwrap()
});
```

#### Age Calculation

**Age calculation utilities:**
```rust
fn calculate_allocation_age(alloc_timestamp_ns: u64) -> Duration {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    
    let age_ns = current_time.saturating_sub(alloc_timestamp_ns);
    Duration::from_nanos(age_ns)
}

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

fn calculate_average_age(record: &MallocRecord) -> Duration {
    // Calculate average age based on allocation timestamps
    // Implementation depends on how we track multiple allocation ages per process
    Duration::from_secs(0) // Placeholder
}
```

### 4. Output Formatting

#### Enhanced Statistics Mode Output

**Age-enhanced Statistics Mode:**
```rust
fn print_summary_with_age(records: &[MallocRecord]) {
    println!(
        "{:<4} {:<8} {:<8} {:<8} {:<8} {:<8} {:<10} {:<8} {:<12} {:<8} Comm",
        "No", "PID", "TID", "Alloc", "Free", "Real", "Real.max", "Req.max", "Oldest", "Avg.Age"
    );
    
    for (idx, record) in records.iter().enumerate() {
        let oldest_age = calculate_allocation_age(record.oldest_alloc_timestamp);
        let avg_age = calculate_average_age(record);
        
        println!(
            "{:<4} {:<8} {:<8} {:<8} {:<8} {:<8} {:<10} {:<8} {:<12} {:<8} {}",
            idx + 1,
            record.pid,
            record.tid,
            record.alloc_size,
            record.free_size,
            record.alloc_size - record.free_size,
            record.max_size,
            record.max_req_size,
            format_age(oldest_age),
            format_age(avg_age),
            unsafe { bytes_to_string(record.comm.as_ptr()) }
        );
    }
}
```

#### Trace Mode Output

**Age-enhanced trace mode display:**
```rust
fn print_trace_allocations_with_age(events: &[MallocEvent], min_age: Option<AgeDuration>, show_traces: bool) {
    println!("{:<4} {:<8} {:<12} {:<8}", "No", "Size", "Age", "Process");
    println!("{}", "=".repeat(60));
    
    let mut filtered_events = Vec::new();
    
    for event in events {
        let age = calculate_allocation_age(event.alloc_timestamp_ns);
        
        // Apply age filter if specified
        if let Some(min_age) = &min_age {
            if age.as_secs() < min_age.seconds {
                continue;
            }
        }
        
        filtered_events.push((event, age));
    }
    
    for (idx, (event, age)) in filtered_events.iter().enumerate() {
        let comm = unsafe { bytes_to_string(event.comm.as_ptr()) };
        
        println!(
            "{:<4} {:<8} {:<12} {:<8}",
            idx + 1,
            event.size,
            format_age(*age),
            format!("{}({})", comm, event.tid)
        );
        
        // Show stack trace only if -t/-T option is used
        if show_traces {
            println!("     Backtrace for malloc():");
            // ... existing stack trace logic ...
        }
    }
}
```

#### Age Histogram

**Age distribution analysis:**
```rust
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
```

## Data Models

### Enhanced Data Structures

#### Inflight Allocation Tracking (Race Condition Fix)

```c
// NEW: Thread-safe data passing between uprobe and uretprobe
struct inflight_alloc {
    u32 size;               // Allocation size from malloc parameter
    u64 timestamp_ns;       // Allocation timestamp from bpf_ktime_get_ns()
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);       // tid - unique per thread, no race condition
    __type(value, struct inflight_alloc);
} inflight_allocs SEC(".maps");
```

#### Process-Level Statistics (Cross-Thread Allocation Handling)

```c
// UPDATED: Process-level tracking (keyed by PID, not TID)
struct malloc_record {
    u32 pid;                        // Process ID (key)
    u32 tid;                        // Representative thread ID
    char comm[TASK_COMM_LEN];       // Process command name
    u32 max_req_size;               // Maximum requested size
    u32 max_size;                   // Maximum actual allocation size
    u32 alloc_size;                 // Total allocated bytes (all threads)
    u32 free_size;                  // Total freed bytes (ACTUAL size, not counter)
    s32 ustack_sz;                  // Stack trace size for largest allocation
    u64 ustack[PERF_MAX_STACK_DEPTH]; // Stack trace for largest allocation
    
    // Age tracking fields for Statistics Mode
    u64 oldest_alloc_timestamp;     // Timestamp of oldest unfreed allocation (across all threads)
    u32 total_unfreed_count;        // Count of unfreed allocations (all threads)
    u64 total_age_sum_ns;           // Sum of allocation timestamps for average calculation
    u32 age_histogram[4];           // Age distribution: [0-1min, 1-5min, 5-30min, 30min+]
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, u32);               // PID (process-level aggregation)
    __type(value, struct malloc_record);
} malloc_records SEC(".maps");
```

#### Trace Mode Events (Detailed Tracking)

```c
// UPDATED: Enhanced with accurate timestamp tracking
struct malloc_event {
    u32 tid;                        // Thread that allocated
    char comm[TASK_COMM_LEN];       // Thread command name at allocation
    u32 size;                       // Actual allocation size
    u64 alloc_timestamp_ns;         // Allocation timestamp (from inflight_allocs)
    u32 free_tid;                   // Thread that freed (u32::MAX if not freed)
    char free_comm[TASK_COMM_LEN];  // Thread command name at free
    u64 sequence;                   // Sequence number for pointer reuse handling
    s32 ustack_sz;                  // Allocation stack trace size
    u64 ustack[PERF_MAX_STACK_DEPTH]; // Allocation stack trace
    s32 free_ustack_sz;             // Free stack trace size
    u64 free_ustack[PERF_MAX_STACK_DEPTH]; // Free stack trace
};

struct malloc_event_key {
    void *ptr;                      // Allocation pointer
    u64 sequence;                   // Sequence number (handles pointer reuse)
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct malloc_event_key);
    __type(value, struct malloc_event);
} malloc_event_records SEC(".maps");
```

### Data Flow Architecture

#### Statistics Mode Data Flow
```
uprobe_malloc:
  inflight_allocs[tid] = {size, timestamp}

uretprobe_malloc:
  data = inflight_allocs[tid]                    // Thread-safe lookup
  malloc_event_records[{ptr, seq}] = event      // Temporary event (for size lookup)
  malloc_records[pid] += statistics             // Process-level aggregation
  delete inflight_allocs[tid]                   // Cleanup

uprobe_free:
  event = malloc_event_records[{ptr, seq}]      // Get actual allocation size
  malloc_records[pid].free_size += event.size  // ✅ Accurate byte tracking
  delete malloc_event_records[{ptr, seq}]      // Cleanup (temporary in Stats Mode)
```

#### Trace Mode Data Flow
```
uprobe_malloc:
  inflight_allocs[tid] = {size, timestamp}

uretprobe_malloc:
  data = inflight_allocs[tid]                    // Thread-safe lookup
  malloc_event_records[{ptr, seq}] = event      // Permanent event (with stack traces)
  delete inflight_allocs[tid]                   // Cleanup

uprobe_free:
  event = malloc_event_records[{ptr, seq}]      // Update existing event
  event.free_tid = tid                          // Mark as freed
  event.free_comm = comm                        // Free thread info
  event.free_ustack = stack                     // Free stack trace
  // Keep event for analysis (permanent in Trace Mode)
```

## Data Models

### Mode-Aware Data Collection Flow

#### Statistics Mode (trace_mode = false)
```
1. Allocation occurs in application
   ↓
2. eBPF uprobe captures allocation
   ↓
3. Record timestamp: bpf_ktime_get_ns()
   ↓
4. Update malloc_records map (aggregate per process/thread):
   - Update oldest_alloc_timestamp
   - Update total_unfreed_count and total_age_sum_ns
   - Update age_histogram[range]
   ↓
5. Userspace reads malloc_records map
   ↓
6. Display aggregate statistics with age information
```

#### Trace Mode (trace_mode = true)
```
1. Allocation occurs in application
   ↓
2. eBPF uprobe captures allocation
   ↓
3. Record timestamp: bpf_ktime_get_ns()
   ↓
4. Store in malloc_event_records map (trace mode events):
   - Store alloc_timestamp_ns per allocation
   - Store stack traces if -t/-T enabled
   ↓
5. Userspace reads malloc_event_records map
   ↓
6. Calculate current age: current_time - alloc_timestamp
   ↓
7. Apply age filters (--min-age) and display trace mode allocations
```

### Memory Layout Considerations

**Additional memory overhead per allocation:**
- `alloc_timestamp_ns`: 8 bytes per malloc_event
- **Total overhead: 8 bytes per allocation**

**Additional overhead per process (Statistics Mode):**
- `oldest_alloc_timestamp`: 8 bytes
- `total_unfreed_count`: 4 bytes  
- `total_age_sum_ns`: 8 bytes
- `age_histogram[4]`: 16 bytes
- **Total per-process overhead: 36 bytes**

**Map size calculations:**
- Default 8192 events × 8 bytes = ~64KB additional memory
- Acceptable overhead for the functionality provided

## Error Handling

### Timestamp Handling

**Clock synchronization issues:**
```rust
fn safe_calculate_age(alloc_timestamp_ns: u64) -> Result<Duration, JtraceError> {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| JtraceError::InvalidData)? the kernel level
4. **No cross-function data sharing via per-CPU arrays**: Eliminates the primary source of race conditions

**Handling concurrent allocations:**
```c
// Safe: Each thread uses its own TID as key
int uprobe_malloc(int size) {
    u32 tid = bpf_get_current_pid_tgid();
    struct inflight_alloc inflight = {.size = size, .timestamp_ns = bpf_ktime_get_ns()};
    
    // This is thread-safe because TID is unique per thread
    bpf_map_update_elem(&inflight_allocs, &tid, &inflight, BPF_ANY);
    return 0;
}
```

**CPU migration handling:**
```c
// Safe: TID-based lookup works regardless of CPU
int uretprobe_malloc(void *ptr) {
    u32 tid = bpf_get_current_pid_tgid();
    
    // This lookup works even if thread migrated to different CPU
    struct inflight_alloc *inflight = bpf_map_lookup_elem(&inflight_allocs, &tid);
    if (!inflight) return 0;  // Graceful handling of missing data
    
    // ... process allocation ...
    
    // Clean up
    bpf_map_delete_elem(&inflight_allocs, &tid);
    return 0;
}
```

### Data Integrity Assurance

**Accurate size tracking:**
```c
// Prevent size tracking errors by looking up actual allocation size
int uprobe_free(void *ptr) {
    // Get actual size from event record, not from free() parameter
    struct malloc_event *event = lookup_event_by_ptr_and_sequence(ptr);
    if (!event) {
        // Handle missing event gracefully
        jdebug("No event found for ptr %p, skipping size update", ptr);
        return 0;
    }
    
    u32 actual_size = event->size;  // ✅ Guaranteed accurate
    
    // Update statistics with correct size
    update_process_free_size(pid, actual_size);
    return 0;
}
```

**Process-level aggregation integrity:**
```rust
// Userspace: Ensure process-level statistics are read correctly
fn calculate_process_statistics_from_records(
    maps: &mut MallocFreeMaps,
) -> Result<HashMap<u32, ProcessStats>, JtraceError> {
    let malloc_records = maps.malloc_records();
    
    for key in malloc_records.keys() {
        if let Some(data) = malloc_records.lookup(&key, MapFlags::ANY)? {
            let mut record = MallocRecord::default();
            plain::copy_from_bytes(&mut record, &data)?;
            
            // Validate data integrity
            if record.alloc_size < record.free_size {
                jwarn!("Data integrity issue: free_size ({}) > alloc_size ({}) for PID {}", 
                       record.free_size, record.alloc_size, record.pid);
                continue;  // Skip corrupted records
            }
            
            // Process valid record...
        }
    }
}
```

### Timestamp Handling

**Clock synchronization issues:**
```rust
fn safe_calculate_age(alloc_timestamp_ns: u64) -> Result<Duration, JtraceError> {
    let current_time = get_monotonic_time_ns()?;  // Use monotonic time to match eBPF
    
    // Get baseline timestamp from when tracing started
    let baseline_timestamp = TRACE_START_TIMESTAMP.get().copied().unwrap_or(current_time);
    
    // Validate that allocation timestamp is reasonable
    if alloc_timestamp_ns < baseline_timestamp {
        jwarn!("Stale allocation detected: timestamp {} is before trace start {}", 
               alloc_timestamp_ns, baseline_timestamp);
        return Ok(Duration::from_secs(0));  // Treat as minimum age
    }
    
    // Handle clock adjustments and wraparound
    if current_time < alloc_timestamp_ns {
        jwarn!("Clock adjustment detected, using minimum age");
        return Ok(Duration::from_secs(0));
    }
    
    let age_ns = current_time - alloc_timestamp_ns;
    
    // Sanity check: age shouldn't be more than trace duration + buffer
    let trace_duration_ns = current_time - baseline_timestamp;
    let max_reasonable_age = trace_duration_ns + 60_000_000_000; // +1 minute buffer
    
    if age_ns > max_reasonable_age {
        jwarn!("Suspicious age detected: {}s (trace duration: {}s)", 
               age_ns / 1_000_000_000, trace_duration_ns / 1_000_000_000);
    }
    
    Ok(Duration::from_nanos(age_ns))
}
```

**"Unknown" age prevention:**
```rust
fn format_process_age_safely(record: &MallocRecord) -> (String, String) {
    let oldest_age_str = if record.oldest_alloc_timestamp > 0 {
        safe_calculate_age(record.oldest_alloc_timestamp)
            .map(|age| format_age(age))
            .unwrap_or_else(|e| {
                jwarn!("Failed to calculate oldest age: {}", e);
                "error".to_string()
            })
    } else {
        "no-data".to_string()  // Distinguish from calculation errors
    };
    
    let avg_age_str = if record.total_unfreed_count > 0 && record.total_age_sum_ns > 0 {
        let avg_timestamp = record.total_age_sum_ns / record.total_unfreed_count as u64;
        safe_calculate_age(avg_timestamp)
            .map(|age| format_age(age))
            .unwrap_or_else(|e| {
                jwarn!("Failed to calculate average age: {}", e);
                "error".to_string()
            })
    } else {
        "no-data".to_string()
    };
    
    (oldest_age_str, avg_age_str)
}
```

### Age Filter Validation

**Input validation:**
```rust
fn validate_age_filter(age_str: &str) -> Result<AgeDuration, JtraceError> {
    let age = AgeDuration::parse(age_str)
        .map_err(|_| {
            Report::new(JtraceError::InvalidData)
                .attach_printable(format!(
                    "Invalid age format: '{}'. Use formats like: 300, 5m, 1h", 
                    age_str
                ))
        })?;
    
    // Reasonable limits
    if age.seconds > 24 * 3600 {
        return Err(Report::new(JtraceError::InvalidData)
            .attach_printable("Age filter cannot exceed 24 hours"));
    }
    
    if age.seconds == 0 {
        return Err(Report::new(JtraceError::InvalidData)
            .attach_printable("Age filter must be greater than 0"));
    }
    
    Ok(age)
}
```

## Testing Strategy

### Unit Tests

**Age calculation tests:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_age_parsing() {
        assert_eq!(AgeDuration::parse("300").unwrap().seconds, 300);
        assert_eq!(AgeDuration::parse("5m").unwrap().seconds, 300);
        assert_eq!(AgeDuration::parse("1h").unwrap().seconds, 3600);
        assert!(AgeDuration::parse("invalid").is_err());
    }
    
    #[test]
    fn test_age_formatting() {
        assert_eq!(format_age(Duration::from_secs(30)), "30s");
        assert_eq!(format_age(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_age(Duration::from_secs(3660)), "1h 1m");
    }
    
    #[test]
    fn test_age_histogram_ranges() {
        // Test age histogram range calculation
        assert_eq!(calculate_age_histogram_range(Duration::from_secs(30)), AGE_RANGE_0_1MIN);
        assert_eq!(calculate_age_histogram_range(Duration::from_secs(120)), AGE_RANGE_1_5MIN);
        assert_eq!(calculate_age_histogram_range(Duration::from_secs(600)), AGE_RANGE_5_30MIN);
        assert_eq!(calculate_age_histogram_range(Duration::from_secs(2000)), AGE_RANGE_30MIN_PLUS);
    }
}
```

### Integration Tests

**End-to-end age tracking tests:**
```rust
#[test]
fn test_age_filtering_integration() {
    // Create test application with known allocation pattern
    let mut test_app = TestApplication::new();
    
    // Allocate memory and wait
    test_app.allocate(1024);
    std::thread::sleep(Duration::from_secs(2));
    
    // Test age filtering
    let output = run_malloc_free(&["--min-age", "1s", "-p", &test_app.pid().to_string()]);
    assert!(output.contains("1024"));
    
    let output = run_malloc_free(&["--min-age", "5s", "-p", &test_app.pid().to_string()]);
    assert!(!output.contains("1024"));
}
```

### Performance Tests

**Overhead measurement:**
```rust
#[test]
fn test_age_tracking_overhead() {
    let baseline = measure_malloc_free_performance(false); // Without age tracking
    let with_age = measure_malloc_free_performance(true);  // With age tracking
    
    let overhead = (with_age - baseline) / baseline;
    assert!(overhead < 0.05, "Age tracking overhead should be < 5%");
}
```

This design provides a comprehensive foundation for implementing allocation age tracking while maintaining performance and usability. The feature integrates seamlessly with existing functionality and provides powerful new capabilities for distinguishing true memory leaks from normal allocations.
#
# Architecture Benefits

### 1. Race Condition Elimination ✅

**Before (Problematic):**
```c
// Per-CPU array caused race conditions
per_cpu_event[cpu_id] = {tid, size, timestamp};  // ❌ Overwritten by concurrent threads
```

**After (Safe):**
```c
// TID-keyed hash map is thread-safe
inflight_allocs[tid] = {size, timestamp};  // ✅ Each thread has unique TID
```

**Benefits:**
- No more TID corruption in records
- No more timestamp loss leading to "unknown" ages
- CPU migration safe (TID lookup works on any CPU)
- Concurrent malloc calls on same CPU handled correctly

### 2. Accurate Memory Size Tracking ✅

**Before (Incorrect):**
```c
entry->free_size += 1;  // ❌ Just counting operations, not bytes
```

**After (Correct):**
```c
struct malloc_event *event = lookup_event(ptr);
entry->free_size += event->size;  // ✅ Actual bytes freed
```

**Benefits:**
- "Free" column shows actual bytes freed, not operation count
- "Real" memory calculation is accurate: Real = Alloc - Free
- Memory leak detection is precise at byte level
- Statistics reflect true memory usage patterns

### 3. Process-Level Memory Aggregation ✅

**Before (Limited):**
```c
malloc_records[tid] = {...};  // ❌ Per-thread, misses cross-thread alloc/free
```

**After (Comprehensive):**
```c
malloc_records[pid] = {...};  // ✅ Per-process, handles cross-thread operations
```

**Benefits:**
- Memory allocated in one thread, freed in another is correctly tracked
- Process-wide memory usage view for multi-threaded applications
- Age statistics aggregate across all threads in a process
- More accurate leak detection for complex applications

### 4. Memory Efficiency ✅

**Statistics Mode:**
- Events are temporary (created on malloc, deleted on free)
- Only active allocations consume memory
- Minimal overhead for production monitoring

**Trace Mode:**
- Events are permanent (kept for detailed analysis)
- Complete allocation history available
- Suitable for debugging and leak investigation

### 5. Data Integrity Assurance ✅

**Timestamp Integrity:**
- No more corrupted timestamps from race conditions
- Monotonic time matching between eBPF and userspace
- Graceful handling of clock adjustments and edge cases

**Size Integrity:**
- Actual allocation sizes tracked, not estimates
- Cross-validation between event records and statistics
- Error detection for data corruption

## Validation and Testing

### Expected Behavior Changes

**Before Refactoring (Issues):**
```
No   PID      TID      Alloc    Free     Real     Oldest       Avg.Age  Comm
1    1234     1234     1000000  500      999500   unknown      unknown  myapp
```

**After Refactoring (Fixed):**
```
No   PID      TID      Alloc    Free     Real     Oldest       Avg.Age  Comm
1    1234     1234     1000000  500000   500000   5m 23s       2m 15s   myapp
```

**Key Improvements:**
- ✅ "Free" shows actual bytes (500000) instead of operation count (500)
- ✅ "Real" calculation is accurate (500000) instead of wrong (999500)
- ✅ Ages show actual values ("5m 23s", "2m 15s") instead of "unknown"
- ✅ Process-level aggregation works correctly

### Test Scenarios

#### 1. Race Condition Testing
```bash
# High-concurrency test
stress-ng --malloc 100 --malloc-bytes 1M --timeout 30s &
sudo ./target/release/malloc_free -p $! --age-histogram -d 30

# Expected: No "unknown" ages, consistent statistics
```

#### 2. Cross-Thread Allocation Testing
```c
// Test program: allocate in thread A, free in thread B
void *ptr = malloc(1000);  // Thread A
// Pass ptr to Thread B
free(ptr);                 // Thread B

// Expected: Process statistics correctly aggregate both operations
```

#### 3. Memory Size Accuracy Testing
```bash
# Allocate known amounts, verify statistics
./test_program_allocates_exactly_1MB &
sudo ./target/release/malloc_free -p $! -d 10

# Expected: "Alloc" column shows ~1MB, "Free" shows actual freed bytes
```

#### 4. Age Histogram Testing
```bash
# Long-running allocations
./continuous_alloc &  # Allocates every 2 seconds, keeps allocations
sudo ./target/release/malloc_free -p $! --age-histogram -d 60

# Expected: Age histogram shows distribution across time ranges
```

### Performance Validation

**Memory Overhead:**
- Statistics Mode: O(processes) memory usage
- Trace Mode: O(allocations) memory usage
- Inflight map: O(concurrent_allocations) - typically small

**CPU Overhead:**
- Hash map lookups: O(1) average case
- No per-CPU array contention
- Reduced lock contention from race condition elimination

**Scalability:**
- Handles high-concurrency workloads without data corruption
- Scales with number of processes, not threads
- Memory usage bounded by configuration limits

## Implementation Status

✅ **COMPLETED** - All architectural improvements implemented:

1. ✅ **Race condition elimination** - TID-keyed inflight map replaces per-CPU data passing
2. ✅ **Accurate size tracking** - Event lookup for actual allocation sizes
3. ✅ **Process-level aggregation** - PID-keyed statistics instead of TID-keyed
4. ✅ **Data integrity** - Comprehensive error handling and validation
5. ✅ **Memory efficiency** - Mode-specific event lifecycle management
6. ✅ **Comprehensive testing** - Unit tests covering all age tracking functionality

The refactored design eliminates the fundamental issues that caused "unknown" ages and inaccurate memory tracking, providing a robust foundation for reliable memory leak detection and analysis.