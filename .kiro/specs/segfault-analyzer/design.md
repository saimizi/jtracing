# Design Document

## Overview

The segfault analyzer will be a BPF-based tool that monitors segmentation faults (SIGSEGV) across all processes on the system. It leverages kernel tracepoints to capture detailed information about segfaults including memory access patterns, stack traces, register states, and process context.

The tool follows the established patterns in the codebase, using libbpf-rs for BPF program management and implementing both real-time monitoring and file output capabilities.

## Architecture

### Core Components

1. **BPF Kernel Program** (`segfault_analyzer.bpf.c`)
   - Attaches to `signal_deliver` tracepoint to capture SIGSEGV events
   - Captures process context, memory access information, and register state
   - Stores events in BPF maps for userspace consumption

2. **Userspace Application** (`segfault_analyzer.rs`)
   - Loads and manages BPF programs
   - Processes events from BPF maps
   - Handles symbol resolution for stack traces
   - Provides filtering and output formatting

3. **Event Processing Pipeline**
   - Real-time event consumption from ring buffer
   - Symbol resolution using existing ElfFile infrastructure
   - Filtering by PID/process name
   - Output formatting (console/file)

### BPF Program Design

#### Tracepoint Attachment
- **Primary**: `signal:signal_deliver` tracepoint
  - Captures when SIGSEGV (signal 11) is delivered to a process
  - Provides access to `siginfo_t` structure with fault address and context
  - Available on all kernel versions with tracepoint support

#### Data Structures

```c
struct segfault_event {
    // Process information
    u32 pid;
    u32 tid;
    char comm[TASK_COMM_LEN];
    u64 timestamp_ns;
    
    // Fault information
    u64 fault_addr;        // Address that caused the fault
    u64 instruction_ptr;   // RIP/PC at time of fault
    u32 fault_code;        // si_code from siginfo (SEGV_MAPERR, SEGV_ACCERR)
    
    // Register state (architecture-specific)
    u64 registers[16];     // Key CPU registers
    u32 register_count;    // Number of valid registers
    
    // Stack trace
    u64 stack_trace[PERF_MAX_STACK_DEPTH];
    s32 stack_size;        // Number of stack frames captured
    
    // Memory mapping context
    u64 vma_start;         // Start of VMA containing fault address
    u64 vma_end;           // End of VMA containing fault address
    u32 vma_flags;         // VMA protection flags
};
```

#### Maps Configuration

```c
// Event storage for userspace consumption
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} events SEC(".maps");

// Statistics tracking
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 8);
    __type(key, u32);
    __type(value, u64);
} stats SEC(".maps");
```

### Signal Information Extraction

The `signal_deliver` tracepoint provides access to:
- `int sig` - Signal number (we filter for SIGSEGV = 11)
- `struct kernel_siginfo *info` - Contains fault address and error code
- `struct k_sigaction *ka` - Signal handler information

Key siginfo fields for segfaults:
- `si_addr` - Faulting memory address
- `si_code` - Fault type (SEGV_MAPERR, SEGV_ACCERR, etc.)

### Register State Capture

Architecture-specific register capture using BPF helpers:
- **x86_64**: RIP, RSP, RBP, RAX, RBX, RCX, RDX, RSI, RDI, R8-R15
- **ARM64**: PC, SP, X0-X30, LR
- **Other**: Graceful degradation with available registers

Implementation uses `bpf_probe_read_user()` to safely read register context from the signal frame.

## Components and Interfaces

### Command Line Interface

```rust
#[derive(Parser)]
struct Cli {
    /// Duration to monitor (0 = infinite)
    #[clap(short, default_value_t = 0)]
    duration: u64,
    
    /// Filter by process ID
    #[clap(short, long)]
    pid: Option<i32>,
    
    /// Filter by process name (supports partial matching)
    #[clap(short = 'n', long)]
    process_name: Option<String>,
    
    /// Include register state in output
    #[clap(short, long)]
    registers: bool,
    
    /// Include stack trace
    #[clap(short = 't', long)]
    stack_trace: bool,
    
    /// Maximum stack depth to capture
    #[clap(long, default_value_t = 16)]
    max_stack_depth: u32,
    
    /// Output file path
    #[clap(short, long)]
    output: Option<PathBuf>,
    
    /// Output format (text, json)
    #[clap(long, default_value = "text")]
    format: String,
    
    /// Verbose output
    #[clap(short, long)]
    verbose: bool,
}
```

### Event Processing Interface

```rust
trait EventProcessor {
    fn process_event(&mut self, event: &SegfaultEvent) -> Result<(), JtraceError>;
    fn flush(&mut self) -> Result<(), JtraceError>;
}

struct ConsoleProcessor {
    symbol_analyzer: SymbolAnalyzer,
    show_registers: bool,
    show_stack_trace: bool,
}

struct FileProcessor {
    writer: BufWriter<File>,
    format: OutputFormat,
    symbol_analyzer: SymbolAnalyzer,
}
```

### Symbol Resolution Integration

Leverages existing `SymbolAnalyzer` infrastructure:
- Resolves instruction pointer and stack addresses to function names
- Handles both user and kernel symbols
- Caches symbol information for performance
- Graceful degradation when symbols unavailable

## Data Models

### Core Event Structure

```rust
#[derive(Debug, Clone)]
struct SegfaultEvent {
    // Process context
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
    pub timestamp: SystemTime,
    
    // Fault details
    pub fault_address: u64,
    pub instruction_pointer: u64,
    pub fault_type: FaultType,
    
    // Optional register state
    pub registers: Option<RegisterState>,
    
    // Optional stack trace
    pub stack_trace: Option<Vec<u64>>,
    
    // Memory mapping info
    pub vma_info: Option<VmaInfo>,
}

#[derive(Debug, Clone)]
enum FaultType {
    MapError,      // SEGV_MAPERR - address not mapped
    AccessError,   // SEGV_ACCERR - invalid permissions
    Unknown(i32),  // Other si_code values
}

#[derive(Debug, Clone)]
struct RegisterState {
    pub architecture: String,
    pub registers: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
struct VmaInfo {
    pub start: u64,
    pub end: u64,
    pub permissions: String,
    pub mapping_name: Option<String>,
}
```

### Output Formats

#### Text Format
```
[2024-02-15 10:30:45] SEGFAULT in process myapp (PID: 1234, TID: 1234)
  Fault Address: 0x7f8b4c000000
  Instruction:   0x555555554000 (main+0x10)
  Fault Type:    Access violation (SEGV_ACCERR)
  
  Registers:
    RIP: 0x555555554000    RSP: 0x7ffe12345678
    RAX: 0x0000000000000000    RBX: 0x7f8b4c000000
    
  Stack Trace:
    #0  0x555555554000 main+0x10 (/path/to/myapp)
    #1  0x7f8b4b123456 __libc_start_main+0x123 (/lib/libc.so.6)
    #2  0x555555553000 _start+0x20 (/path/to/myapp)
```

#### JSON Format
```json
{
  "timestamp": "2024-02-15T10:30:45.123Z",
  "pid": 1234,
  "tid": 1234,
  "comm": "myapp",
  "fault_address": "0x7f8b4c000000",
  "instruction_pointer": "0x555555554000",
  "fault_type": "access_error",
  "registers": {
    "rip": "0x555555554000",
    "rsp": "0x7ffe12345678",
    "rax": "0x0000000000000000"
  },
  "stack_trace": [
    {
      "address": "0x555555554000",
      "symbol": "main+0x10",
      "module": "/path/to/myapp"
    }
  ]
}
```

## Error Handling

### BPF Program Error Handling
- Graceful handling of missing siginfo data
- Safe memory access using `bpf_probe_read_*` helpers
- Statistics tracking for dropped events and errors
- Fallback behavior when register/stack capture fails

### Userspace Error Handling
- Robust event parsing with validation
- Symbol resolution error recovery
- File I/O error handling with user feedback
- Process filtering error handling

### Error Categories
```rust
enum SegfaultAnalyzerError {
    BpfLoadError(String),
    EventParsingError(String),
    SymbolResolutionError(String),
    FilterError(String),
    OutputError(String),
}
```

## Testing Strategy

### Unit Tests
- Event structure serialization/deserialization
- Symbol resolution with mock data
- Process filtering logic
- Output formatting for different formats

### Integration Tests
- BPF program loading and attachment
- End-to-end event capture with test programs
- File output validation
- Performance testing with high event rates

### Test Programs
Create simple test programs that trigger segfaults:
```c
// test_segfault.c - triggers various segfault types
int main() {
    // Null pointer dereference
    int *p = NULL;
    *p = 42;  // SEGV_MAPERR
    
    // Access violation
    char *readonly = "test";
    readonly[0] = 'x';  // SEGV_ACCERR
    
    return 0;
}
```

### Performance Considerations
- Ring buffer sizing for high-frequency events
- Symbol cache optimization
- Minimal overhead BPF program design
- Efficient filtering to reduce userspace processing

## Security Considerations

### Privilege Requirements
- Requires CAP_BPF or root privileges for BPF program loading
- Requires access to /proc filesystem for symbol resolution
- May need CAP_SYS_ADMIN for certain kernel versions

### Data Privacy
- Process names and command lines are captured
- Memory addresses are logged (potential ASLR bypass concern)
- Stack traces may reveal sensitive function names
- Consider data sanitization options for production use

### Resource Limits
- BPF map size limits to prevent memory exhaustion
- Event rate limiting to prevent DoS
- Automatic cleanup on program termination