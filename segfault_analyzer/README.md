# Segfault Analyzer

A BPF-based tool for real-time monitoring and analysis of segmentation faults in Linux processes.

## Quick Start

```bash
# Build the tool
cargo build --release --bin segfault_analyzer

# Basic monitoring (requires root)
sudo ./target/release/segfault_analyzer

# Monitor specific process with full details
sudo ./target/release/segfault_analyzer -n myapp -r -t

# Save results to JSON file
sudo ./target/release/segfault_analyzer --format json -o crashes.json -t
```

## Features

- **Real-time segfault detection** across all system processes
- **Detailed fault information** including memory addresses and fault types
- **Stack trace capture** with symbol resolution
- **CPU register state** capture at fault time
- **Process filtering** by PID or name
- **Multiple output formats** (human-readable text or JSON)
- **Performance monitoring** with built-in statistics
- **Memory management** with configurable limits

## Documentation

- **[Complete Documentation](../docs/usage/segfault_analyzer.md)** - Comprehensive guide with examples
- **[Quick Reference](../docs/usage/segfault_analyzer_quick_reference.md)** - Command cheat sheet
- **[Design Document](../.kiro/specs/segfault-analyzer/design.md)** - Technical architecture details

## Testing

### Build Test Examples

```bash
cd testfiles
make
```

### Run Tests

```bash
# Automated test suite (requires root)
sudo docs/usage/test_segfault_analyzer.sh

# Interactive demo
sudo docs/usage/test_segfault_analyzer.sh demo

# Quick basic test
sudo docs/usage/test_segfault_analyzer.sh basic
```

### Manual Testing

```bash
# Terminal 1: Start monitoring
sudo ./target/release/segfault_analyzer -t -r

# Terminal 2: Trigger test segfault
./testfiles/segfault_examples null
```

## Common Usage Patterns

### Development Debugging
```bash
# Monitor your application during development
sudo ./target/release/segfault_analyzer -n myapp -t -r -o debug.log
```

### Production Monitoring
```bash
# Lightweight monitoring with JSON output
sudo ./target/release/segfault_analyzer --format json -o /var/log/segfaults.json
```

### Performance Analysis
```bash
# Monitor with statistics for performance impact assessment
sudo ./target/release/segfault_analyzer --stats --stats-interval 30
```

## Requirements

- Linux kernel 4.15+ (5.8+ recommended)
- Root privileges or CAP_BPF capability
- BPF support enabled in kernel

## Troubleshooting

### Permission Issues
```bash
# Ensure you're running as root
sudo ./target/release/segfault_analyzer

# Or check BPF capabilities
sudo setcap cap_bpf+ep ./target/release/segfault_analyzer
```

### No Events Detected
```bash
# Test with known segfault
echo 'int main(){int*p=0;*p=1;}' > test.c && gcc test.c && ./a.out

# Check verbose output
sudo ./target/release/segfault_analyzer -v
```

### Symbol Resolution Issues
```bash
# Compile with debug symbols
gcc -g -O0 your_program.c -o your_program

# Install debug packages (Ubuntu/Debian)
sudo apt install libc6-dbg
```

## Architecture

The segfault analyzer consists of:

1. **BPF Kernel Program** (`segfault_analyzer.bpf.c`)
   - Attaches to `signal_deliver` tracepoint
   - Captures SIGSEGV events with detailed context
   - Stores events in ring buffer for userspace processing

2. **Userspace Application** (`segfault_analyzer.rs`)
   - Loads and manages BPF programs
   - Processes events with symbol resolution
   - Provides filtering and output formatting

3. **Symbol Resolution**
   - Integrates with existing `SymbolAnalyzer` infrastructure
   - Resolves addresses to function names and modules
   - Caches symbols for performance

## Output Examples

### Text Format
```
[2024-02-15 10:30:45.123] SEGFAULT in process myapp (PID: 1234, TID: 1234)
  Fault Address: 0x0000000000000000
  Instruction:   0x555555554000 (main+0x10)
  Fault Type:    Address not mapped (SEGV_MAPERR)
  
  Registers (x86_64):
    RIP: 0x555555554000    RSP: 0x7ffe12345678
    RAX: 0x0000000000000000    RBX: 0x0000000000000008
    
  Stack Trace (3 frames):
    #0  0x555555554000 main+0x10 (/path/to/myapp)
    #1  0x7f8b4b123456 __libc_start_main+0x123 (/lib/libc.so.6)
    #2  0x555555553000 _start+0x20 (/path/to/myapp)
```

### JSON Format
```json
{
  "timestamp": 1708000245123,
  "pid": 1234,
  "tid": 1234,
  "comm": "myapp",
  "fault_address": "0x0000000000000000",
  "instruction_pointer": "0x555555554000",
  "instruction_symbol": "main+0x10 (/path/to/myapp)",
  "fault_type": "map_error",
  "registers": {
    "rip": "0x555555554000",
    "rsp": "0x7ffe12345678",
    "rax": "0x0000000000000000"
  },
  "stack_trace": [
    {
      "address": "0x555555554000",
      "symbol": "main+0x10 (/path/to/myapp)"
    }
  ]
}
```

## Performance Considerations

- **BPF overhead**: Minimal, only activates on segfault events
- **Symbol resolution**: Main performance cost, can be disabled
- **Memory usage**: Configurable limits (default 100MB)
- **Event processing**: Scales with segfault frequency

## Integration

The segfault analyzer integrates with:
- Existing jtracing project build system
- Symbol resolution infrastructure (`SymbolAnalyzer`)
- Standard logging and error handling patterns
- BPF program compilation pipeline

## Contributing

When modifying the segfault analyzer:

1. Update BPF program in `bpf/segfault_analyzer.bpf.c`
2. Modify userspace code in `segfault_analyzer.rs`
3. Update tests in `testfiles/` and documentation
4. Run test suite: `sudo docs/usage/test_segfault_analyzer.sh`
5. Update this README and main documentation

## License

This tool is part of the jtracing project and follows the same GPL-2.0 license.