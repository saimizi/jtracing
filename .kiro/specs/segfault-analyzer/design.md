# Design Document

## Overview

The segfault analyzer will be a BPF-based tool that monitors both segmentation faults (SIGSEGV) and abort signals (SIGABRT) across all processes on the system. It leverages kernel tracepoints to capture detailed information about crashes including memory access patterns, stack traces, register states, and process context.

The tool follows the established patterns in the codebase, using libbpf-rs for BPF program management and implementing both real-time monitoring and file output capabilities.

### Abort Signal Monitoring

The tool monitors SIGABRT signals which can be triggered by various conditions including:
- Stack smashing detection (when compiled with `-fstack-protector-strong`)
- Explicit abort() calls
- Failed assertions
- Other runtime errors

When SIGABRT is captured, the tool provides complete diagnostic information including stack traces, allowing users to identify the cause. Stack smashing can be identified by the presence of `__stack_chk_fail()` or related functions in the stack trace.

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
  - Captures when SIGSEGV (signal 11) or SIGABRT (signal 6) is delivered to a process
  - Provides access to `siginfo_t` structure with fault address and context
  - Available on all kernel versions with tracepoint support
  
#### Signal Filtering Strategy
- **SIGSEGV (11)**: Captured as segmentation faults
- **SIGABRT (6)**: Captured as abort signals
  - All SIGABRT signals are treated uniformly
  - Stack trace reveals the abort cause (e.g., `__stack_chk_fail` for stack smashing)
  - Users can identify stack smashing by examining the stack trace

#### Data Structures

```c
struct segfault_event {
    // Process information
    u32 pid;
    u32 tid;
    char comm[TASK_COMM_LEN];
    u64 timestamp_ns;
    
    // Event classification
    u32 signal_number;     // SIGSEGV (11) or SIGABRT (6)
    u32 event_type;        // 0=segfault, 1=abort
    
    // Fault information
    u64 fault_addr;        // Address that caused the fault (SIGSEGV only)
    u64 instruction_ptr;   // RIP/PC at time of fault
    u32 fault_code;        // si_code from siginfo
    
    // Register state (architecture-specific)
    u64 registers[16];     // Key CPU registers
    u32 register_count;    // Number of valid registers
    
    // Stack trace
    u64 stack_trace[PERF_MAX_STACK_DEPTH];
    s32 stack_size;        // Number of stack frames captured
    u8 stack_reliable;     // 0=unreliable (corrupted), 1=reliable
    
    // Memory mapping context
    u64 vma_start;         // Start of VMA containing instruction pointer
    u64 vma_end;           // End of VMA containing instruction pointer
    u32 vma_flags;         // VMA protection flags
    char vma_path[256];    // Binary/library path
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
- `int sig` - Signal number (we filter for SIGSEGV = 11 and SIGABRT = 6)
- `struct kernel_siginfo *info` - Contains fault address and error code
- `struct k_sigaction *ka` - Signal handler information

Key siginfo fields:
- **For segfaults (SIGSEGV)**:
  - `si_addr` - Faulting memory address
  - `si_code` - Fault type (SEGV_MAPERR, SEGV_ACCERR, etc.)
- **For aborts (SIGABRT)**:
  - `si_code` - Abort reason
  - Stack trace - Shows the abort cause (e.g., `__stack_chk_fail` for stack smashing)

### Register State Capture

Architecture-specific register capture using BPF helpers:
- **x86_64**: RIP, RSP, RBP, RAX, RBX, RCX, RDX, RSI, RDI, R8-R15
- **ARM64**: PC, SP, X0-X30, LR
- **Other**: Graceful degradation with available registers

Implementation uses `bpf_probe_read_user()` to safely read register context from the signal frame.

### Stack Smashing Detection Implementation

#### Detection Strategy

1. **Signal Filtering**: Monitor both SIGSEGV (11) and SIGABRT (6) signals
2. **Origin Identification**: For SIGABRT signals, determine if they originated from stack protector
3. **Symbol-Based Detection**: Check if instruction pointer resolves to known stack protector functions:
   - `__stack_chk_fail` - GCC/Clang stack protector
   - `__stack_chk_fail_local` - Local variant
   - `__fortify_fail` - FORTIFY_SOURCE detection
4. **Fallback Detection**: If symbol resolution fails, use heuristics based on stack trace patterns

#### Stack Trace Reliability

When stack smashing is detected, the stack may be corrupted:
- **Attempt stack unwinding**: Use `bpf_get_stack()` to capture user stack
- **Mark reliability**: Set `stack_trace_reliable = false` for stack smashing events
- **Provide fallback**: Always capture instruction pointer and registers as minimum diagnostic info
- **Best-effort approach**: Display whatever stack information is available, with warnings

#### Finding the Vulnerable Function

The instruction pointer at SIGABRT will point to `__stack_chk_fail()`, which is not useful. To find the actual vulnerable function:

1. **Stack Trace Method (preferred)**:
   - Capture stack trace using `bpf_get_stack()`
   - Frame 0: `__stack_chk_fail()` (not useful)
   - Frame 1: **Vulnerable function** (this is what we want!)
   - Frame 2+: Call chain leading to vulnerable function

2. **Return Address Method (fallback)**:
   - If stack trace fails, read return address from stack
   - Use RSP (stack pointer) register to locate return address
   - Return address points to instruction after the call to `__stack_chk_fail()`
   - This gives us the location in the vulnerable function

3. **Register-Based Heuristic (last resort)**:
   - Examine RBP (frame pointer) to walk stack manually
   - Read saved return address from previous stack frame
   - May fail if stack is heavily corrupted

#### Diagnostic Information Priority

For stack smashing events, provide information in order of reliability:
1. **Stack Trace Frame 1** (most useful) - The vulnerable function that called `__stack_chk_fail`
2. **Return Address from Stack** (fallback) - If stack trace partially works
3. **Register State** (always available) - RSP, RBP can help locate return address
4. **Full Stack Trace** (potentially unreliable) - May be corrupted, marked accordingly
5. **Instruction Pointer** (least useful) - Will show `__stack_chk_fail`, not the vulnerable function

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
    
    // Event classification
    pub signal_number: u32,      // SIGSEGV (11) or SIGABRT (6)
    pub event_type: EventType,   // Segfault or Abort
    
    // Fault details
    pub fault_address: u64,        // Only meaningful for SIGSEGV
    pub instruction_pointer: u64,
    pub fault_type: FaultType,
    
    // Optional register state
    pub registers: Option<RegisterState>,
    
    // Optional stack trace
    pub stack_trace: Option<Vec<u64>>,
    pub stack_trace_reliable: bool,  // False if stack may be corrupted
    
    // Memory mapping info
    pub vma_info: Option<VmaInfo>,
}

#[derive(Debug, Clone)]
enum EventType {
    Segfault,      // SIGSEGV
    Abort,         // SIGABRT (includes stack smashing)
}

#[derive(Debug, Clone)]
enum FaultType {
    // SIGSEGV types
    MapError,      // SEGV_MAPERR - address not mapped
    AccessError,   // SEGV_ACCERR - invalid permissions
    
    // SIGABRT type
    Abort,         // Abort signal (may include stack smashing)
    
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

**Segmentation Fault Example:**
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

**Abort Signal Example (Stack Smashing):**
```
[2024-02-15 10:30:45] ABORT in process myapp (PID: 1234, TID: 1234)
  Instruction:   0x7f8b4b234567 (__stack_chk_fail+0x10)
  Fault Type:    Abort signal
  
  Memory Mapping:
    VMA Range:   0x00007f8b4b200000 - 0x00007f8b4b400000
    Module:      libc.so.6
  
  Registers:
    RIP: 0x7f8b4b234567    RSP: 0x7ffe12345678
    RAX: 0x0000000000000000    RBX: 0x7f8b4c000000
    
  Stack Trace (7 frames) - MAY BE UNRELIABLE DUE TO CORRUPTION:
    #0  0x7f8b4b234567 __stack_chk_fail+0x10 (/lib/libc.so.6)
    #1  0x555555554abc vulnerable_function+0x42 (/usr/bin/myapp)
    #2  0x555555554000 main+0x10 (/usr/bin/myapp)
    #3  0x7f8b4b123456 __libc_start_main+0x123 (/lib/libc.so.6)
```

#### JSON Format

**Segmentation Fault Example:**
```json
{
  "timestamp": "2024-02-15T10:30:45.123Z",
  "event_type": "segfault",
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
  ],
  "stack_trace_reliable": true
}
```

**Abort Signal Example (Stack Smashing):**
```json
{
  "timestamp": "2024-02-15T10:30:45.123Z",
  "signal_number": 6,
  "event_type": "abort",
  "pid": 1234,
  "tid": 1234,
  "comm": "myapp",
  "instruction_pointer": "0x7f8b4b234567",
  "fault_type": "abort",
  "registers": {
    "rip": "0x7f8b4b234567",
    "rsp": "0x7ffe12345678",
    "rax": "0x0000000000000000"
  },
  "stack_trace": [
    {
      "address": "0x7f8b4b234567",
      "symbol": "__stack_chk_fail+0x10",
      "module": "/lib/libc.so.6"
    },
    {
      "address": "0x555555554abc",
      "symbol": "vulnerable_function+0x42",
      "module": "/usr/bin/myapp"
    }
  ],
  "stack_trace_reliable": false
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

Create test programs that trigger both segfaults and stack smashing:

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

```c
// test_stack_smashing.c - triggers stack protector
// Compile with: gcc -fstack-protector-strong test_stack_smashing.c -o test_stack_smashing

#include <string.h>

void vulnerable_function(const char *input) {
    char buffer[16];
    // This will overflow the buffer and corrupt the stack canary
    strcpy(buffer, input);
}

int main() {
    // Create a string longer than the buffer to trigger overflow
    char large_input[100];
    memset(large_input, 'A', sizeof(large_input) - 1);
    large_input[sizeof(large_input) - 1] = '\0';
    
    vulnerable_function(large_input);
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