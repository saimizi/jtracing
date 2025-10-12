# Segfault Analyzer Quick Reference

## Quick Start

```bash
# Basic monitoring (requires root)
sudo ./target/release/segfault_analyzer

# Monitor specific process with full details
sudo ./target/release/segfault_analyzer -n myapp -r -t

# Save to JSON file for analysis
sudo ./target/release/segfault_analyzer --format json -o crashes.json -t
```

## Common Commands

| Use Case | Command |
|----------|---------|
| Monitor all processes | `sudo ./target/release/segfault_analyzer` |
| Monitor specific PID | `sudo ./target/release/segfault_analyzer -p 1234` |
| Monitor by process name | `sudo ./target/release/segfault_analyzer -n firefox` |
| Include registers | `sudo ./target/release/segfault_analyzer -r` |
| Include stack traces | `sudo ./target/release/segfault_analyzer -t` |
| JSON output | `sudo ./target/release/segfault_analyzer --format json` |
| Save to file | `sudo ./target/release/segfault_analyzer -o crashes.log` |
| Show statistics | `sudo ./target/release/segfault_analyzer --stats` |
| Monitor for 60 seconds | `sudo ./target/release/segfault_analyzer -d 60` |

## Key Options

- `-p, --pid <PID>` - Filter by process ID
- `-n, --process-name <NAME>` - Filter by process name (partial match)
- `-r, --registers` - Show CPU registers
- `-t, --stack-trace` - Show stack trace with symbols
- `-o, --output <FILE>` - Save to file
- `--format <FORMAT>` - Output format (text/json)
- `-a, --append` - Append to file instead of overwrite
- `--stats` - Show performance statistics
- `-d, --duration <SECS>` - Monitor duration (0=infinite)
- `-v, --verbose` - Verbose output

## Troubleshooting Quick Fixes

| Problem | Solution |
|---------|----------|
| Permission denied | Run with `sudo` |
| No events captured | Test with: `echo 'int main(){int*p=0;*p=1;}' > t.c && gcc t.c && ./a.out` |
| No symbols in stack trace | Compile with `-g` flag, install debug packages |
| High memory usage | Use `--symbol-cache-limit 500 --memory-limit 50` |
| Events being dropped | Use process filtering: `-p PID` or `-n name` |

## Output Examples

### Text Format
```
[2024-02-15 10:30:45.123] SEGFAULT in process myapp (PID: 1234, TID: 1234)
  Fault Address: 0x0000000000000000
  Instruction:   0x555555554000 (main+0x10)
  Fault Type:    Address not mapped (SEGV_MAPERR)
```

### JSON Format
```json
{
  "timestamp": 1708000245123,
  "pid": 1234,
  "comm": "myapp", 
  "fault_address": "0x0000000000000000",
  "instruction_pointer": "0x555555554000",
  "fault_type": "map_error"
}
```

## Performance Tips

- Use process filtering to reduce overhead
- Disable stack traces (`-t`) for high-frequency monitoring
- Use JSON format for better performance
- Set memory limits: `--memory-limit 50`
- Monitor stats: `--stats --stats-interval 10`