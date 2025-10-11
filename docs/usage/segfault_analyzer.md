# Segfault Analyzer Documentation

## Overview

The segfault analyzer is a BPF-based tool that monitors and analyzes segmentation faults (SIGSEGV) in real-time across all processes on the system. It captures detailed information about segfault events including memory access patterns, stack traces, register states, and process context to help developers identify the root cause of crashes.

## Features

- **Real-time monitoring**: Captures segfaults as they occur across all system processes
- **Detailed fault information**: Records fault address, instruction pointer, and fault type
- **Stack trace capture**: Provides call stack with symbol resolution when available
- **Register state**: Captures CPU register values at the time of fault (optional)
- **Process filtering**: Filter by PID or process name for focused debugging
- **Multiple output formats**: Human-readable text or structured JSON output
- **File output**: Save results to files for later analysis
- **Performance monitoring**: Built-in statistics and performance metrics
- **Memory management**: Configurable limits to prevent resource exhaustion

## Installation and Requirements

### Prerequisites

- Linux kernel with BPF support (kernel 4.15+ recommended)
- Root privileges or CAP_BPF capability
- libbpf library (included in build dependencies)

### Building

The segfault analyzer is built as part of the jtracing project:

```bash
# Build the entire project
cargo build --release

# Build only the segfault analyzer
cargo build --release --bin segfault_analyzer

# Check compilation without building
cargo check --bin segfault_analyzer
```

## Command Line Interface

### Basic Usage

```bash
# Monitor all processes (requires root)
sudo ./target/release/segfault_analyzer

# Monitor for a specific duration (60 seconds)
sudo ./target/release/segfault_analyzer -d 60

# Monitor with verbose output
sudo ./target/release/segfault_analyzer -v
```

### Process Filtering

```bash
# Monitor specific process by PID
sudo ./target/release/segfault_analyzer -p 1234

# Monitor processes by name (partial matching)
sudo ./target/release/segfault_analyzer -n myapp

# Monitor processes with "test" in the name
sudo ./target/release/segfault_analyzer -n test
```

### Enhanced Information Capture

```bash
# Include register state in output
sudo ./target/release/segfault_analyzer -r

# Include stack traces
sudo ./target/release/segfault_analyzer -t

# Include both registers and stack traces
sudo ./target/release/segfault_analyzer -r -t

# Limit stack trace depth
sudo ./target/release/segfault_analyzer -t --max-stack-depth 8
```

### Output Options

```bash
# Save to file (text format)
sudo ./target/release/segfault_analyzer -o crashes.log

# Save in JSON format
sudo ./target/release/segfault_analyzer -o crashes.json --format json

# Append to existing file instead of overwriting
sudo ./target/release/segfault_analyzer -o crashes.log -a

# JSON output with symbols for programmatic analysis
sudo ./target/release/segfault_analyzer --format json -t -o analysis.json
```

### Performance Monitoring

```bash
# Show performance statistics
sudo ./target/release/segfault_analyzer --stats

# Show statistics every 10 seconds
sudo ./target/release/segfault_analyzer --stats --stats-interval 10

# Configure memory limits
sudo ./target/release/segfault_analyzer --symbol-cache-limit 2000 --memory-limit 200
```

## Complete Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--duration` | `-d` | Duration to monitor in seconds (0 = infinite) | 0 |
| `--pid` | `-p` | Filter by process ID | None |
| `--process-name` | `-n` | Filter by process name (partial matching) | None |
| `--registers` | `-r` | Include register state in output | false |
| `--stack-trace` | `-t` | Include stack trace | false |
| `--max-stack-depth` | | Maximum stack depth to capture | 16 |
| `--output` | `-o` | Output file path | None (stdout) |
| `--format` | | Output format (text, json) | text |
| `--append` | `-a` | Append to output file instead of overwriting | false |
| `--stats` | | Show performance statistics | false |
| `--stats-interval` | | Statistics display interval in seconds | 5 |
| `--symbol-cache-limit` | | Maximum number of symbols to cache | 1000 |
| `--memory-limit` | | Maximum memory usage in MB | 100 |
| `--verbose` | `-v` | Verbose output | false |
| `--help` | `-h` | Show help message | |
| `--version` | `-V` | Show version information | |

## Usage Examples

### Example 1: Basic Monitoring

Monitor all segfaults on the system with basic information:

```bash
sudo ./target/release/segfault_analyzer
```

**Sample Output:**
```
[2024-02-15 10:30:45.123] SEGFAULT in process myapp (PID: 1234, TID: 1234)
  Fault Address: 0x7f8b4c000000
  Instruction:   0x555555554000 (main+0x10)
  Fault Type:    Access violation (SEGV_ACCERR)

[2024-02-15 10:30:47.456] SEGFAULT in process test_program (PID: 5678, TID: 5678)
  Fault Address: 0x0000000000000000
  Instruction:   0x555555554020
  Fault Type:    Address not mapped (SEGV_MAPERR)
```

### Example 2: Debugging Specific Application

Monitor a specific application with detailed information:

```bash
# Start your application in one terminal
./my_buggy_app

# In another terminal, monitor it specifically
sudo ./target/release/segfault_analyzer -n my_buggy_app -r -t
```

**Sample Output:**
```
[2024-02-15 10:35:12.789] SEGFAULT in process my_buggy_app (PID: 9876, TID: 9876)
  Fault Address: 0x0000000000000008
  Instruction:   0x555555554567 (process_data+0x23 (/path/to/my_buggy_app))
  Fault Type:    Address not mapped (SEGV_MAPERR)
  
  Registers (x86_64):
    RIP: 0x555555554567    RSP: 0x7ffe12345678
    RAX: 0x0000000000000000    RBX: 0x0000000000000008
    RCX: 0x00007f8b4c123456    RDX: 0x0000000000000010
    
  Stack Trace (4 frames):
    #0  0x555555554567 process_data+0x23 (/path/to/my_buggy_app)
    #1  0x555555554123 handle_request+0x45 (/path/to/my_buggy_app)
    #2  0x555555553000 main+0x67 (/path/to/my_buggy_app)
    #3  0x7f8b4b123456 __libc_start_main+0x123 (/lib/libc.so.6)
```

### Example 3: JSON Output for Automated Analysis

Capture segfaults in JSON format for automated processing:

```bash
sudo ./target/release/segfault_analyzer --format json -t -o segfaults.json
```

**Sample JSON Output:**
```json
{
  "timestamp": 1708000245123,
  "pid": 1234,
  "tid": 1234,
  "comm": "my_buggy_app",
  "fault_address": "0x0000000000000008",
  "instruction_pointer": "0x555555554567",
  "instruction_symbol": "process_data+0x23 (/path/to/my_buggy_app)",
  "fault_type": "map_error",
  "stack_trace": [
    {
      "address": "0x555555554567",
      "symbol": "process_data+0x23 (/path/to/my_buggy_app)"
    },
    {
      "address": "0x555555554123", 
      "symbol": "handle_request+0x45 (/path/to/my_buggy_app)"
    }
  ]
}
```

### Example 4: Performance Monitoring

Monitor system-wide segfaults with performance statistics:

```bash
sudo ./target/release/segfault_analyzer --stats --stats-interval 10
```

**Sample Statistics Output:**
```
=== Segfault Analyzer Statistics ===
Runtime: 45.2s

Event Counts:
  Total segfaults detected:     23
  Segfaults filtered out:       5
  Events captured:              18
  Events processed:             18
  Events submitted to userspace: 18
  Events dropped:               0

Performance Metrics:
  Event drop rate:              0.00%
  Fault info capture rate:      95.65%
  Events per second:            0.4

Feature Statistics:
  Register capture failures:    2
  Stack trace failures:         1
  Fault info captured:          22
  Fault info missed:            1

Symbol Resolution:
  Symbol cache hits:            156
  Symbol cache misses:          34
  Symbol cache hit rate:        82.11%

Memory Usage:
  Estimated memory usage:       12.45 MB
  Memory usage (% of limit):    12.5%
  Ring buffer size (fixed):     256 KB
  Symbol cache entries:         190
```

### Example 5: Long-term Monitoring

Set up continuous monitoring with file rotation:

```bash
# Monitor for 1 hour, saving to timestamped file
sudo ./target/release/segfault_analyzer -d 3600 -o "segfaults_$(date +%Y%m%d_%H%M%S).log" --format json -t

# Or use a script for continuous monitoring with rotation
#!/bin/bash
while true; do
    timestamp=$(date +%Y%m%d_%H%M%S)
    sudo ./target/release/segfault_analyzer -d 3600 -o "segfaults_${timestamp}.log" --format json -t
    sleep 60  # Brief pause between sessions
done
```

## Output Formats

### Text Format

The text format provides human-readable output suitable for console viewing and log files. Each segfault event is displayed with:

- Timestamp with millisecond precision
- Process information (name, PID, TID)
- Fault address and instruction pointer
- Fault type description
- Optional register state (with `-r` flag)
- Optional stack trace with symbol resolution (with `-t` flag)

### JSON Format

The JSON format provides structured output for programmatic processing. Each event is a JSON object with the following fields:

- `timestamp`: Unix timestamp in milliseconds
- `pid`: Process ID
- `tid`: Thread ID  
- `comm`: Process command name
- `fault_address`: Memory address that caused the fault (hex string)
- `instruction_pointer`: Instruction pointer at fault time (hex string)
- `instruction_symbol`: Symbol information for instruction pointer (if available)
- `fault_type`: Fault type ("map_error", "access_error", or "unknown")
- `registers`: Object with register names and values (if `-r` flag used)
- `stack_trace`: Array of stack frame objects with address and symbol (if `-t` flag used)

## Troubleshooting

### Common Issues and Solutions

#### 1. Permission Denied

**Problem:** `Error: Permission denied when loading BPF program`

**Solution:**
- Run with `sudo` or as root user
- Ensure your user has CAP_BPF capability
- Check that BPF is enabled in kernel config

```bash
# Check BPF support
zcat /proc/config.gz | grep BPF

# Run with sudo
sudo ./target/release/segfault_analyzer
```

#### 2. BPF Program Load Failure

**Problem:** `Failed to load BPF program: Invalid argument`

**Solutions:**
- Verify kernel version (4.15+ recommended, 5.8+ for best compatibility)
- Check kernel BPF features:

```bash
# Check kernel version
uname -r

# Check available BPF program types
ls /sys/fs/bpf/

# Verify tracepoint availability
ls /sys/kernel/debug/tracing/events/signal/
```

#### 3. No Events Captured

**Problem:** Tool runs but no segfaults are detected

**Debugging steps:**
1. Verify the tool is working by creating a test segfault:

```bash
# Terminal 1: Start monitoring
sudo ./target/release/segfault_analyzer -v

# Terminal 2: Create a test segfault
echo 'int main() { int *p = 0; *p = 42; }' > test.c
gcc test.c -o test
./test
```

2. Check if events are being filtered:
```bash
# Monitor all processes without filters
sudo ./target/release/segfault_analyzer --stats
```

3. Verify tracepoint attachment:
```bash
# Check if tracepoint exists
cat /sys/kernel/debug/tracing/events/signal/signal_deliver/enable
```

#### 4. Symbol Resolution Issues

**Problem:** Stack traces show only addresses, no function names

**Solutions:**
- Install debug symbols for your application
- Ensure the binary has symbol information:

```bash
# Check if binary has symbols
file /path/to/your/binary
nm /path/to/your/binary | head

# Compile with debug info
gcc -g -O0 your_program.c -o your_program

# Install debug packages (Ubuntu/Debian)
sudo apt install libc6-dbg
```

#### 5. High Memory Usage

**Problem:** Tool consumes excessive memory

**Solutions:**
- Reduce symbol cache limit:
```bash
sudo ./target/release/segfault_analyzer --symbol-cache-limit 500
```

- Set memory limit:
```bash
sudo ./target/release/segfault_analyzer --memory-limit 50
```

- Monitor memory usage:
```bash
sudo ./target/release/segfault_analyzer --stats --stats-interval 5
```

#### 6. Events Being Dropped

**Problem:** Statistics show high event drop rate

**Solutions:**
- Process events faster by reducing symbol resolution:
```bash
# Disable stack traces to reduce processing time
sudo ./target/release/segfault_analyzer -r  # registers only, no stack traces
```

- Filter to specific processes:
```bash
sudo ./target/release/segfault_analyzer -p 1234  # specific PID only
```

- Use JSON format for faster processing:
```bash
sudo ./target/release/segfault_analyzer --format json -o output.json
```

#### 7. Build Issues

**Problem:** Compilation fails with BPF-related errors

**Solutions:**
- Ensure libbpf development packages are installed:

```bash
# Ubuntu/Debian
sudo apt install libbpf-dev clang llvm

# RHEL/CentOS/Fedora  
sudo dnf install libbpf-devel clang llvm
```

- Check Rust toolchain:
```bash
rustc --version  # Should be 1.70+
cargo --version
```

- Clean and rebuild:
```bash
cargo clean
cargo build --release --bin segfault_analyzer
```

### Performance Considerations

#### Memory Usage

- **Ring Buffer**: Fixed 256KB (compile-time BPF limitation)
- **Symbol Cache**: Configurable, default 1000 entries (~128KB)
- **BPF Maps**: ~1MB for statistics and temporary storage
- **Userspace**: Variable based on symbol resolution and caching

#### CPU Overhead

- **BPF Program**: Minimal overhead, runs only on segfault events
- **Symbol Resolution**: Main CPU cost, can be disabled for performance
- **Event Processing**: Scales with segfault frequency

#### Optimization Tips

1. **Use process filtering** to reduce event volume
2. **Disable symbol resolution** for high-frequency scenarios
3. **Use JSON format** for better processing performance
4. **Adjust cache limits** based on available memory
5. **Monitor statistics** to identify bottlenecks

### Debugging the Tool Itself

If you suspect issues with the segfault analyzer itself:

1. **Enable verbose logging:**
```bash
sudo ./target/release/segfault_analyzer -v
```

2. **Check BPF program status:**
```bash
# List loaded BPF programs
sudo bpftool prog list | grep segfault

# Show BPF map contents
sudo bpftool map list | grep segfault
```

3. **Monitor system logs:**
```bash
# Check kernel messages
sudo dmesg | grep -i bpf

# Check system logs
journalctl -f | grep segfault_analyzer
```

4. **Test with known segfault:**
```bash
# Create reproducible segfault
cat > test_segfault.c << 'EOF'
#include <stdio.h>
int main() {
    printf("About to segfault...\n");
    int *p = (int*)0x1;  // Invalid address
    *p = 42;             // This will segfault
    return 0;
}
EOF

gcc test_segfault.c -o test_segfault
sudo ./target/release/segfault_analyzer -v &
./test_segfault
```

## Integration Examples

### Automated Crash Reporting

```bash
#!/bin/bash
# crash_monitor.sh - Automated crash reporting script

LOG_DIR="/var/log/segfaults"
ALERT_EMAIL="admin@company.com"

mkdir -p "$LOG_DIR"

# Start monitoring in background
sudo ./target/release/segfault_analyzer \
    --format json \
    --output "$LOG_DIR/segfaults_$(date +%Y%m%d).json" \
    --append \
    --stack-trace &

MONITOR_PID=$!

# Set up signal handler for cleanup
trap "kill $MONITOR_PID 2>/dev/null" EXIT

# Monitor for new crashes and send alerts
tail -f "$LOG_DIR/segfaults_$(date +%Y%m%d).json" | while read line; do
    if echo "$line" | jq -e '.fault_type == "access_error"' >/dev/null; then
        # Send alert for access violations
        echo "Critical segfault detected: $line" | mail -s "Segfault Alert" "$ALERT_EMAIL"
    fi
done
```

### Integration with Monitoring Systems

```python
#!/usr/bin/env python3
# segfault_metrics.py - Export metrics to monitoring system

import json
import subprocess
import time
from prometheus_client import Counter, Histogram, start_http_server

# Prometheus metrics
segfault_counter = Counter('segfaults_total', 'Total segfaults detected', ['process', 'fault_type'])
segfault_histogram = Histogram('segfault_processing_time', 'Time to process segfault events')

def process_segfault_line(line):
    try:
        event = json.loads(line)
        segfault_counter.labels(
            process=event['comm'], 
            fault_type=event['fault_type']
        ).inc()
    except json.JSONDecodeError:
        pass

def main():
    # Start Prometheus metrics server
    start_http_server(8000)
    
    # Start segfault analyzer
    proc = subprocess.Popen([
        'sudo', './target/release/segfault_analyzer',
        '--format', 'json'
    ], stdout=subprocess.PIPE, text=True)
    
    # Process events
    for line in proc.stdout:
        with segfault_histogram.time():
            process_segfault_line(line.strip())

if __name__ == '__main__':
    main()
```

## Best Practices

1. **Start with basic monitoring** before adding detailed capture options
2. **Use process filtering** to focus on specific applications during debugging
3. **Enable stack traces and registers** only when needed for detailed analysis
4. **Use JSON format** for automated processing and integration
5. **Monitor performance statistics** to ensure the tool isn't impacting system performance
6. **Set appropriate memory limits** based on your system resources
7. **Rotate log files** for long-term monitoring to prevent disk space issues
8. **Test with known segfaults** to verify the tool is working correctly

## See Also

- [Memory Leak Detection Guide](memory_leak_detection.md)
- [BPF Programming Documentation](../design/malloc_free.md)
- [Project README](../../README.md)