# malloc_free Design Document

## Overview

The `malloc_free` tool is a sophisticated memory allocation tracer that uses eBPF to monitor dynamic memory allocation and deallocation in userspace applications. It provides comprehensive statistics, memory leak detection, and detailed stack trace analysis for debugging memory-related issues.

## Architecture

### Two-Component System

1. **eBPF Kernel Program** (`malloc_free.bpf.c`)
   - Runs in kernel space with minimal overhead
   - Attaches to libc memory allocation functions via uprobes
   - Collects allocation/deallocation events and statistics

2. **Userspace Controller** (`malloc_free.rs`)
   - Manages eBPF program lifecycle
   - Processes collected data from eBPF maps
   - Provides symbol resolution and formatted output

## Core Data Structures

### malloc_event
Tracks individual allocation/deallocation events:

```c
struct malloc_event {
    u32 tid;                    // Thread ID that performed allocation
    char comm[TASK_COMM_LEN];   // Process name at allocation time
    u32 size;                   // Requested allocation size
    u32 free_tid;               // Thread ID that freed memory (-1 if not freed)
    char free_comm[TASK_COMM_LEN]; // Process name at free time
    u64 sequence;               // Sequence number for pointer reuse handling
    s32 ustack_sz;              // Size of allocation stack trace
    u64 ustack[128];            // User stack trace at allocation
    s32 free_ustack_sz;         // Size of free stack trace
    u64 free_ustack[128];       // User stack trace at free
    
    // Age tracking fields (added in v0.2.4)
    u64 alloc_timestamp_ns;     // Timestamp when allocation occurred
};
```

### malloc_record
Aggregated per-process memory statistics:

```c
struct malloc_record {
    u32 pid, tid;               // Process and thread identifiers
    char comm[TASK_COMM_LEN];   // Process name
    u32 max_req_size;           // Largest single allocation request
    u32 max_size;               // Peak total memory usage
    u32 alloc_size;             // Cumulative bytes allocated
    u32 free_size;              // Cumulative bytes freed
    s32 ustack_sz;              // Stack trace size for max allocation
    u64 ustack[128];            // Stack trace for largest allocation
    
    // Age tracking fields (added in v0.2.4)
    u64 oldest_alloc_timestamp; // Timestamp of oldest unfreed allocation
    u32 total_unfreed_count;    // Count of currently unfreed allocations
    u64 total_age_sum_ns;       // Sum of allocation timestamps for average age
    u32 age_histogram[4];       // Age distribution histogram buckets
};
```

### malloc_event_key
Compound key for handling pointer reuse:

```c
struct malloc_event_key {
    void *ptr;                  // Memory pointer
    u64 sequence;               // Sequence number for this pointer
};
```

## Function Coverage

The tool monitors all major libc memory allocation functions:

- **malloc()** - Standard memory allocation
- **calloc()** - Zero-initialized allocation
- **realloc()** - Memory reallocation/resizing
- **aligned_alloc()** - Aligned memory allocation
- **free()** - Memory deallocation

## Key Technical Features

### 1. Pointer Reuse Handling

**Problem**: Memory pointers can be reused after free(), leading to tracking conflicts.

**Solution**: Compound key system using `{pointer, sequence_number}`:
```c
// Increment sequence on each allocation
u64 sequence = seq ? (*seq + 1) : 1;
bpf_map_update_elem(&ptr_sequence, &ptr, &sequence, BPF_ANY);

struct malloc_event_key key = {
    .ptr = ptr,
    .sequence = sequence
};
```

### 2. Per-CPU Optimization

**Problem**: High contention on shared data structures in multi-CPU systems.

**Solution**: Per-CPU temporary storage maps:
```c
// Per-CPU heaps reduce lock contention
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct malloc_record);
} alloc_heap SEC(".maps");
```

### 3. Comprehensive Statistics

Tracks 24 different operational metrics (expanded in v0.2.4):

| Statistic | Purpose |
|-----------|---------|
| STAT_MALLOC_CALLS | Count of malloc() calls |
| STAT_CALLOC_CALLS | Count of calloc() calls |
| STAT_REALLOC_CALLS | Count of realloc() calls |
| STAT_ALIGNED_ALLOC_CALLS | Count of aligned_alloc() calls |
| STAT_FREE_CALLS | Count of free() calls |
| STAT_EVENT_DROPS_* | Various drop reasons for debugging |
| STAT_ACTIVE_EVENTS | Current active allocations |
| STAT_ACTIVE_RECORDS | Current tracked processes |

### 4. Dynamic Library Integration

**Automatic libc Detection**:
```rust
fn find_libc_path_from_proc_maps() -> Option<String> {
    // Scans /proc/self/maps for libc.so.6
    // Falls back to common system paths
}
```

**Symbol Resolution**:
```rust
let elf_file = ElfFile::new(&file)?;
let malloc_offset = elf_file.find_addr("malloc")? as usize;
```

## Age Tracking and Histogram Feature (v0.2.4)

### Age Histogram Implementation

The age histogram feature tracks allocation lifetime patterns to help distinguish between normal memory usage and potential leaks.

#### Key Design Principles

1. **Lifetime Tracking**: Histogram is populated at **free time** when actual allocation lifetime can be calculated
2. **Conservative Estimation**: Unfreed allocations are counted in the longest age bucket (30+ minutes)
3. **Statistics Mode Compatibility**: Works efficiently without requiring individual event preservation

#### Histogram Buckets

| Bucket | Age Range | Semantic Meaning |
|--------|-----------|------------------|
| 0 | 0-1 minute | Short-lived allocations (freed quickly) |
| 1 | 1-5 minutes | Medium-lived allocations |
| 2 | 5-30 minutes | Long-lived allocations |
| 3 | 30+ minutes | Very long-lived allocations + all unfreed allocations |

#### Implementation Details

**eBPF Side (malloc_free.bpf.c)**:
- Histogram updated in `uprobe_free()` when allocation lifetime is known
- Uses `calculate_age_histogram_range(alloc_timestamp)` to determine bucket
- Removed incorrect histogram updates at allocation time

**Userspace Side (malloc_free.rs)**:
- Adds `total_unfreed_count` to the 30+ minute bucket for conservative estimation
- Provides age distribution analysis alongside existing statistics

#### Sample Output

```
=== Memory Age Distribution ===
Age Range    Count    Total Size   Avg Size    
==================================================
0-1 min      1000     2.1MB        2.1KB       
1-5 min      50       5.2MB        104KB       
5-30 min     10       15.6MB       1.56MB      
30+ min      25       45.2MB       1.81MB      

Note: 30+ min bucket includes 20 currently unfreed allocations
```

#### Benefits

- **Leak Detection**: Large counts in 30+ minute bucket indicate potential leaks
- **Usage Patterns**: Shows whether application uses mostly short-lived or long-lived allocations
- **Performance Insights**: Helps identify memory usage efficiency
- **Complementary Data**: Works alongside existing `oldest_age` and `avg_age` metrics

## Operation Modes

### 1. Summary Mode (Default)
Provides aggregated statistics per process with age information:
```
No   PID      TID      Alloc    Free     Real     Real.max   Req.max  Oldest       Avg.Age  Comm
1    3226     3226     460240   452224   8016     13088      3680     29m 59s      2m 15s   Xorg
```

### 2. Trace Path Mode (`-t`)
Shows stack traces for unfreed allocations:
```
1    8192     malloc: bash      (1234)
     Backtrace for malloc():
     7f8b2c0a1234(+0)  malloc /lib/x86_64-linux-gnu/libc.so.6
     55a8f2b3c567(+12) main /usr/bin/bash
```

### 3. Full Trace Mode (`-T`)
Shows stack traces for all allocations and frees (high overhead).

### 4. Max Malloc Path Mode (`-m`)
Shows stack trace for the largest allocation per process.

## Performance Considerations

### Strengths
- **Per-CPU maps** reduce contention
- **Configurable map sizes** balance memory vs completeness
- **Efficient uprobe attachment** to specific function offsets
- **Minimal kernel-userspace data transfer**

### Overhead Sources
- **Stack trace collection**: 128 frames × 8 bytes per event
- **Hash map operations**: Lookup/update for every allocation/free
- **Symbol resolution**: ELF parsing and address translation

### Scalability Limits
- **Map size constraints**: Configurable but finite
- **Memory usage**: Large stack traces consume significant memory
- **CPU overhead**: Increases with allocation frequency

## Error Handling and Monitoring

### Drop Statistics
The tool tracks various failure modes:
```rust
match ret {
    -E2BIG => increment_stat(STAT_EVENT_DROPS_MAP_FULL),
    -EEXIST | -ENOENT => increment_stat(STAT_EVENT_DROPS_INVALID_KEY),
    -ENOMEM => increment_stat(STAT_EVENT_DROPS_NOMEM),
    _ => increment_stat(STAT_EVENT_DROPS_OTHERS),
}
```

### Graceful Degradation
- Missing functions (calloc, realloc, aligned_alloc) are skipped with warnings
- Symbol resolution failures don't crash the tool
- Map full conditions are reported but don't stop tracing

## Configuration Options

### Runtime Parameters
```bash
malloc_free [OPTIONS]

Options:
  -d, --duration <SECONDS>     Trace duration (0 = unlimited)
  -p, --pid <PID>             Target specific process
  -l, --libpath <PATH>        Specify libc.so.6 path
  -t, --trace-path            Show stack traces for unfreed memory
  -T, --trace-full-path       Show all allocation/free stack traces
  -m, --max-malloc-path       Show stack trace for largest allocation
  -s, --show-stats            Display statistics and map utilization
  --max-events <COUNT>        Maximum events to track (default: 8192)
  --max-records <COUNT>       Maximum process records (default: 1024)
  --max-stack-depth <DEPTH>   Maximum stack frames (default: 128)
  
  # Age tracking and output options (v0.2.4)
  --min-age <AGE>             Show only allocations older than specified age (e.g., 5m, 1h)
  --age-histogram             Display age distribution histogram (Statistics Mode only)
  --max-entries <COUNT>       Maximum entries to display in Trace Mode
  --output-file <FILE>        Save results to file instead of stdout
```

### eBPF Map Configuration
Maps are dynamically sized based on command-line parameters:
```rust
open_skel.maps_mut().malloc_event_records()
    .set_max_entries(cli.max_events)?;
open_skel.maps_mut().malloc_records()
    .set_max_entries(cli.max_records)?;
```

## Use Cases

### 1. Memory Leak Detection
Identify allocations without corresponding frees:
```bash
malloc_free -t -d 60  # Trace unfreed allocations for 60 seconds
```

### 2. Memory Usage Profiling
Analyze peak memory usage patterns:
```bash
malloc_free -m -p 1234  # Show max allocation path for process 1234
```

### 3. System-wide Monitoring
Monitor allocation patterns across all processes:
```bash
malloc_free -s -d 300  # System-wide stats for 5 minutes
```

### 4. Performance Analysis
Identify allocation hotspots:
```bash
malloc_free -T -d 10  # Full trace mode for detailed analysis
```

## Recent Improvements (v0.2.4)

### Age Histogram Fix
**Problem**: The age histogram was showing incorrect data due to fundamental design flaws:
- Histogram populated at allocation time (when age ≈ 0)
- All new allocations incorrectly placed in "0-1 min" bucket
- Histogram never decremented on free operations

**Solution Implemented**:
- **eBPF Changes**: Moved histogram updates from allocation time to free time
- **Lifetime Calculation**: Histogram now reflects actual allocation lifetimes
- **Conservative Estimation**: Unfreed allocations added to 30+ minute bucket
- **Consistency**: Histogram data now aligns with `oldest_age` and `avg_age` statistics

### Output File Support
**New Feature**: Added `--output-file` option for saving results to files
- **Comprehensive Error Handling**: Detailed error messages for file operations
- **Periodic Flushing**: Automatic flushing during long-running operations
- **Performance Optimization**: Reduces I/O overhead through intelligent buffering

### Enhanced Error Handling
- **Centralized Error Management**: Consistent error reporting across all output operations
- **Context-Aware Messages**: Different error messages for file vs stdout operations
- **Graceful Degradation**: Periodic flush errors don't terminate analysis

## Implementation Quality

### Strengths
- **Robust error handling** with detailed error categorization
- **Flexible operation modes** for different debugging scenarios
- **Comprehensive statistics** for operational monitoring
- **Automatic library detection** reduces configuration burden
- **Cross-architecture support** (x86_64, ARM64)
- **Accurate age tracking** with fixed histogram implementation
- **File output support** with comprehensive error handling

### Areas for Enhancement
1. **Memory efficiency**: Large stack traces consume significant memory
2. **Filtering granularity**: Could support more specific filtering options
3. **Real-time monitoring**: Live dashboard capabilities
4. **Integration**: Hooks for external monitoring systems

## Security Considerations

- **Privilege requirements**: Requires CAP_BPF and CAP_PERFMON capabilities
- **System impact**: Minimal kernel footprint with bounded resource usage
- **Data exposure**: Only exposes allocation patterns, not memory contents
- **Process isolation**: Respects process boundaries and permissions

## Conclusion

The malloc_free tool represents a sophisticated approach to memory allocation tracing, combining advanced eBPF techniques with practical debugging capabilities. Its design demonstrates deep understanding of both kernel-userspace interaction and memory management patterns, making it a valuable tool for system administrators, developers, and performance engineers.

The implementation successfully balances functionality with performance, providing comprehensive memory tracking while maintaining reasonable system overhead. The modular design and extensive configuration options make it adaptable to various debugging and monitoring scenarios.