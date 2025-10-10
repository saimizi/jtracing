# Output File Option Design Document

## Overview

This document describes the design for adding an --output-file option to the malloc_free tool. This feature will redirect all output from stdout to a specified file, enabling persistent storage of memory analysis results for later review, automated processing, or integration with other tools.

The design focuses on:
1. **Seamless integration** with all existing malloc_free modes and features
2. **Robust error handling** for file operations and edge cases
3. **Minimal performance impact** on the target application being analyzed
4. **Consistent output formatting** matching current stdout behavior
5. **Proper resource management** including signal handling and cleanup

## Architecture

### High-Level Design

The output file feature extends the existing malloc_free architecture by:

1. **Adding CLI option parsing** for --output-file parameter
2. **Implementing output redirection** at the application level (not shell level)
3. **Creating file management utilities** for creation, writing, and cleanup
4. **Enhancing error handling** for file-related operations
5. **Adding signal handlers** for proper file cleanup on interruption

### Component Overview

```
┌─────────────────────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│         CLI Interface           │    │   File Manager   │    │   Output Writer │
│                                 │    │                  │    │                 │
│ ┌─────────────────────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │      --output-file          │ │    │ │ File Creation│ │    │ │ Buffered    │ │
│ │    (file path string)       │ │◄───┤ │ & Validation │ │◄───┤ │ Writer      │ │
│ └─────────────────────────────┘ │    │ └──────────────┘ │    │ └─────────────┘ │
│                                 │    │                  │    │                 │
│ ┌─────────────────────────────┐ │    │ ┌──────────────┐ │    │ ┌─────────────┐ │
│ │    Existing CLI Options     │ │    │ │ Error        │ │    │ │ Format      │ │
│ │   (-t, -p, --min-age, etc)  │ │    │ │ Handling     │ │    │ │ Preservation│ │
│ └─────────────────────────────┘ │    │ └──────────────┘ │    │ └─────────────┘ │
└─────────────────────────────────┘    └──────────────────┘    └─────────────────┘
                                                │
                                                ▼
                                       ┌──────────────────┐
                                       │  Signal Handler  │
                                       │                  │
                                       │ ┌──────────────┐ │
                                       │ │ SIGINT/TERM  │ │
                                       │ │ File Cleanup │ │
                                       │ └──────────────┘ │
                                       └──────────────────┘
```

## Components and Interfaces

### 1. CLI Interface Extension

#### Enhanced Cli Structure

```rust
#[derive(Parser, Debug, Default)]
struct Cli {
    // ... existing fields ...
    
    /// Output file path to save results instead of printing to stdout
    #[clap(long, value_name = "FILE")]
    output_file: Option<PathBuf>,
}
```

#### CLI Validation

```rust
impl Cli {
    fn validate(&self) -> Result<(), JtraceError> {
        // Validate output file path if provided
        if let Some(output_path) = &self.output_file {
            // Check if parent directory exists or can be created
            if let Some(parent) = output_path.parent() {
                if !parent.exists() {
                    // Attempt to create parent directories
                    std::fs::create_dir_all(parent)
                        .map_err(|e| JtraceError::InvalidData(
                            format!("Cannot create output directory '{}': {}", 
                                   parent.display(), e)
                        ))?;
                }
            }
            
            // Check write permissions by attempting to create/open the file
            validate_output_file_access(output_path)?;
        }
        
        Ok(())
    }
}

fn validate_output_file_access(path: &PathBuf) -> Result<(), JtraceError> {
    // Test file creation/write access
    match std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path) 
    {
        Ok(_) => Ok(()),
        Err(e) => Err(JtraceError::InvalidData(
            format!("Cannot write to output file '{}': {}", path.display(), e)
        )),
    }
}
```

### 2. Output Management System

#### Output Writer Abstraction

```rust
trait OutputWriter {
    fn write_line(&mut self, line: &str) -> Result<(), JtraceError>;
    fn write_formatted(&mut self, args: std::fmt::Arguments) -> Result<(), JtraceError>;
    fn flush(&mut self) -> Result<(), JtraceError>;
}

struct StdoutWriter;

impl OutputWriter for StdoutWriter {
    fn write_line(&mut self, line: &str) -> Result<(), JtraceError> {
        println!("{}", line);
        Ok(())
    }
    
    fn write_formatted(&mut self, args: std::fmt::Arguments) -> Result<(), JtraceError> {
        print!("{}", args);
        Ok(())
    }
    
    fn flush(&mut self) -> Result<(), JtraceError> {
        use std::io::Write;
        std::io::stdout().flush()
            .map_err(|e| JtraceError::InvalidData(format!("Failed to flush stdout: {}", e)))
    }
}

struct FileWriter {
    file: BufWriter<File>,
    path: PathBuf,
}

impl FileWriter {
    fn new(path: PathBuf) -> Result<Self, JtraceError> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| JtraceError::InvalidData(
                format!("Failed to create output file '{}': {}", path.display(), e)
            ))?;
            
        Ok(Self {
            file: BufWriter::new(file),
            path,
        })
    }
}

impl OutputWriter for FileWriter {
    fn write_line(&mut self, line: &str) -> Result<(), JtraceError> {
        writeln!(self.file, "{}", line)
            .map_err(|e| JtraceError::InvalidData(
                format!("Failed to write to file '{}': {}", self.path.display(), e)
            ))
    }
    
    fn write_formatted(&mut self, args: std::fmt::Arguments) -> Result<(), JtraceError> {
        write!(self.file, "{}", args)
            .map_err(|e| JtraceError::InvalidData(
                format!("Failed to write to file '{}': {}", self.path.display(), e)
            ))
    }
    
    fn flush(&mut self) -> Result<(), JtraceError> {
        self.file.flush()
            .map_err(|e| JtraceError::InvalidData(
                format!("Failed to flush file '{}': {}", self.path.display(), e)
            ))
    }
}

impl Drop for FileWriter {
    fn drop(&mut self) {
        // Ensure data is flushed when FileWriter is dropped
        let _ = self.flush();
    }
}
```

#### Output Manager

```rust
struct OutputManager {
    writer: Box<dyn OutputWriter>,
}

impl OutputManager {
    fn new(output_file: Option<PathBuf>) -> Result<Self, JtraceError> {
        let writer: Box<dyn OutputWriter> = match output_file {
            Some(path) => Box::new(FileWriter::new(path)?),
            None => Box::new(StdoutWriter),
        };
        
        Ok(Self { writer })
    }
    
    fn write_line(&mut self, line: &str) -> Result<(), JtraceError> {
        self.writer.write_line(line)
    }
    
    fn write_formatted(&mut self, args: std::fmt::Arguments) -> Result<(), JtraceError> {
        self.writer.write_formatted(args)
    }
    
    fn flush(&mut self) -> Result<(), JtraceError> {
        self.writer.flush()
    }
}

// Convenience macro for formatted writing
macro_rules! output_writeln {
    ($output:expr, $($arg:tt)*) => {
        $output.write_formatted(format_args!("{}\n", format_args!($($arg)*)))
    };
}

macro_rules! output_write {
    ($output:expr, $($arg:tt)*) => {
        $output.write_formatted(format_args!($($arg)*))
    };
}
```

### 3. Integration with Existing Output Functions

#### Modified Output Functions

All existing output functions need to be modified to accept an `OutputManager` instead of writing directly to stdout:

```rust
// Before: Direct stdout printing
fn print_summary(records: &[MallocRecord]) {
    println!("{:<4} {:<8} {:<8} {:<8} {:<8} {:<8} {:<10} {:<8} Comm",
             "No", "PID", "TID", "Alloc", "Free", "Real", "Real.max", "Req.max");
    
    for (idx, record) in records.iter().enumerate() {
        println!("{:<4} {:<8} {:<8} {:<8} {:<8} {:<8} {:<10} {:<8} {}",
                 idx + 1, record.pid, record.tid, record.alloc_size,
                 record.free_size, record.alloc_size - record.free_size,
                 record.max_size, record.max_req_size,
                 unsafe { bytes_to_string(record.comm.as_ptr()) });
    }
}

// After: OutputManager integration
fn print_summary(records: &[MallocRecord], output: &mut OutputManager) -> Result<(), JtraceError> {
    output_writeln!(output, "{:<4} {:<8} {:<8} {:<8} {:<8} {:<8} {:<10} {:<8} Comm",
                   "No", "PID", "TID", "Alloc", "Free", "Real", "Real.max", "Req.max")?;
    
    for (idx, record) in records.iter().enumerate() {
        output_writeln!(output, "{:<4} {:<8} {:<8} {:<8} {:<8} {:<8} {:<10} {:<8} {}",
                       idx + 1, record.pid, record.tid, record.alloc_size,
                       record.free_size, record.alloc_size - record.free_size,
                       record.max_size, record.max_req_size,
                       unsafe { bytes_to_string(record.comm.as_ptr()) })?;
    }
    
    Ok(())
}

// Similar modifications for:
// - print_trace_allocations()
// - print_age_histogram()
// - print_stack_trace()
// - All other output functions
```

#### Error Handling Strategy

```rust
// Centralized error handling for output operations
fn handle_output_error(error: JtraceError, output_file: Option<&PathBuf>) {
    match output_file {
        Some(path) => {
            eprintln!("Error writing to output file '{}': {}", path.display(), error);
            eprintln!("Results may be incomplete or corrupted.");
        }
        None => {
            eprintln!("Error writing to stdout: {}", error);
        }
    }
}
```

### 4. Signal Handling and Cleanup

#### Signal Handler Implementation

```rust
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

fn setup_signal_handlers() -> Result<(), JtraceError> {
    // Handle SIGINT (Ctrl+C)
    ctrlc::set_handler(move || {
        INTERRUPTED.store(true, Ordering::SeqCst);
        eprintln!("\nReceived interrupt signal. Cleaning up...");
    })
    .map_err(|e| JtraceError::InvalidData(format!("Failed to set signal handler: {}", e)))
}

fn check_interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

// Modified main processing loop
fn process_events_with_interruption(
    output: &mut OutputManager,
    // ... other parameters
) -> Result<(), JtraceError> {
    loop {
        // Check for interruption periodically
        if check_interrupted() {
            output_writeln!(output, "\n=== INTERRUPTED - PARTIAL RESULTS ===")?;
            output.flush()?;
            break;
        }
        
        // Process events...
        // ... existing event processing logic ...
        
        // Flush output periodically to ensure data is written
        if should_flush() {
            output.flush()?;
        }
    }
    
    Ok(())
}
```

#### Graceful Shutdown

```rust
struct GracefulShutdown {
    output_manager: OutputManager,
}

impl GracefulShutdown {
    fn new(output_file: Option<PathBuf>) -> Result<Self, JtraceError> {
        Ok(Self {
            output_manager: OutputManager::new(output_file)?,
        })
    }
    
    fn shutdown(mut self) -> Result<(), JtraceError> {
        // Ensure all data is flushed before shutdown
        self.output_manager.flush()?;
        
        // FileWriter's Drop implementation will handle final cleanup
        Ok(())
    }
}
```

### 5. Main Application Integration

#### Modified Main Function

```rust
fn main() -> Result<(), JtraceError> {
    let cli = Cli::parse();
    
    // Validate CLI arguments including output file
    cli.validate()?;
    
    // Setup signal handlers
    setup_signal_handlers()?;
    
    // Create output manager
    let mut output_manager = OutputManager::new(cli.output_file.clone())?;
    
    // Suppress stdout for informational messages when writing to file
    let show_progress = cli.output_file.is_none();
    
    if show_progress {
        println!("Starting malloc_free analysis...");
    }
    
    // ... existing eBPF setup code ...
    
    // Process events with output redirection
    let result = match cli.trace_path || cli.trace_full_path || cli.min_age.is_some() {
        true => process_trace_mode(&cli, &mut output_manager),
        false => process_statistics_mode(&cli, &mut output_manager),
    };
    
    // Handle any output errors
    if let Err(ref error) = result {
        handle_output_error(error.clone(), cli.output_file.as_ref());
    }
    
    // Ensure final flush
    output_manager.flush()?;
    
    if show_progress {
        match &cli.output_file {
            Some(path) => println!("Results saved to: {}", path.display()),
            None => {}, // Already printed to stdout
        }
    }
    
    result
}

fn process_statistics_mode(cli: &Cli, output: &mut OutputManager) -> Result<(), JtraceError> {
    // ... existing statistics processing ...
    
    // Modified to use output manager instead of direct printing
    print_summary(&records, output)?;
    
    if cli.age_histogram {
        print_age_histogram(&histogram, output)?;
    }
    
    Ok(())
}

fn process_trace_mode(cli: &Cli, output: &mut OutputManager) -> Result<(), JtraceError> {
    // ... existing trace processing ...
    
    // Modified to use output manager instead of direct printing
    print_trace_allocations(&events, &cli, output)?;
    
    Ok(())
}
```

## Data Models

### File Management Data Structures

#### Output Configuration

```rust
#[derive(Debug, Clone)]
struct OutputConfig {
    file_path: Option<PathBuf>,
    buffer_size: usize,
    flush_interval: Duration,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            file_path: None,
            buffer_size: 8192, // 8KB buffer
            flush_interval: Duration::from_secs(5), // Flush every 5 seconds
        }
    }
}
```

#### File Statistics

```rust
#[derive(Debug, Default)]
struct FileStats {
    bytes_written: u64,
    lines_written: u64,
    flush_count: u64,
    last_flush: Option<Instant>,
}

impl FileStats {
    fn record_write(&mut self, bytes: usize) {
        self.bytes_written += bytes as u64;
        self.lines_written += 1;
    }
    
    fn record_flush(&mut self) {
        self.flush_count += 1;
        self.last_flush = Some(Instant::now());
    }
}
```

### Error Types Extension

```rust
#[derive(Debug, Clone)]
pub enum JtraceError {
    // ... existing variants ...
    
    FileError {
        path: PathBuf,
        operation: String,
        source: String,
    },
    
    OutputError {
        message: String,
    },
}

impl std::fmt::Display for JtraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // ... existing variants ...
            
            JtraceError::FileError { path, operation, source } => {
                write!(f, "File operation '{}' failed for '{}': {}", 
                       operation, path.display(), source)
            }
            
            JtraceError::OutputError { message } => {
                write!(f, "Output error: {}", message)
            }
        }
    }
}
```

## Error Handling

### File Operation Error Handling

#### Comprehensive Error Coverage

```rust
fn handle_file_operation<T, F>(
    operation: &str,
    path: &PathBuf,
    f: F,
) -> Result<T, JtraceError>
where
    F: FnOnce() -> std::io::Result<T>,
{
    f().map_err(|e| {
        let error_msg = match e.kind() {
            std::io::ErrorKind::NotFound => {
                format!("File or directory not found")
            }
            std::io::ErrorKind::PermissionDenied => {
                format!("Permission denied")
            }
            std::io::ErrorKind::AlreadyExists => {
                format!("File already exists")
            }
            std::io::ErrorKind::InvalidInput => {
                format!("Invalid file path or name")
            }
            std::io::ErrorKind::WriteZero => {
                format!("Failed to write data (disk full?)")
            }
            std::io::ErrorKind::Interrupted => {
                format!("Operation was interrupted")
            }
            _ => format!("I/O error: {}", e),
        };
        
        JtraceError::FileError {
            path: path.clone(),
            operation: operation.to_string(),
            source: error_msg,
        }
    })
}
```

#### Recovery Strategies

```rust
impl FileWriter {
    fn write_with_retry(&mut self, data: &str, max_retries: usize) -> Result<(), JtraceError> {
        let mut attempts = 0;
        
        loop {
            match self.write_line(data) {
                Ok(()) => return Ok(()),
                Err(e) if attempts < max_retries => {
                    attempts += 1;
                    eprintln!("Write attempt {} failed, retrying: {}", attempts, e);
                    
                    // Brief delay before retry
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
    
    fn handle_disk_full(&mut self) -> Result<(), JtraceError> {
        // Attempt to flush and close cleanly
        let _ = self.flush();
        
        Err(JtraceError::OutputError {
            message: format!(
                "Disk full or write error for file '{}'. Partial results may be saved.",
                self.path.display()
            ),
        })
    }
}
```

### Interruption Handling

#### Clean Shutdown Process

```rust
fn cleanup_on_interruption(output: &mut OutputManager) -> Result<(), JtraceError> {
    // Write interruption marker
    output.write_line("\n=== ANALYSIS INTERRUPTED ===")?;
    output.write_line(&format!("Timestamp: {}", 
                              chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")))?;
    output.write_line("Results above are partial and may be incomplete.")?;
    
    // Ensure data is flushed
    output.flush()?;
    
    Ok(())
}
```

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_file_writer_creation() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        
        let writer = FileWriter::new(path.clone());
        assert!(writer.is_ok());
    }
    
    #[test]
    fn test_file_writer_write_and_read() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        
        {
            let mut writer = FileWriter::new(path.clone()).unwrap();
            writer.write_line("Test line 1").unwrap();
            writer.write_line("Test line 2").unwrap();
            writer.flush().unwrap();
        }
        
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content, "Test line 1\nTest line 2\n");
    }
    
    #[test]
    fn test_invalid_file_path() {
        let invalid_path = PathBuf::from("/invalid/path/that/does/not/exist/file.txt");
        let result = FileWriter::new(invalid_path);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_output_manager_stdout() {
        let manager = OutputManager::new(None).unwrap();
        // Test that stdout writer is created
        // (This is harder to test directly, but we can verify no panics)
    }
    
    #[test]
    fn test_output_manager_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        
        let manager = OutputManager::new(Some(path));
        assert!(manager.is_ok());
    }
}
```

### Integration Tests

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::process::Command;
    use tempfile::TempDir;
    
    #[test]
    fn test_output_file_with_statistics_mode() {
        let temp_dir = TempDir::new().unwrap();
        let output_file = temp_dir.path().join("stats_output.txt");
        
        // Run malloc_free with output file (would need test binary)
        let output = Command::new("./target/debug/malloc_free")
            .args(&["--output-file", output_file.to_str().unwrap()])
            .output()
            .expect("Failed to execute malloc_free");
        
        assert!(output.status.success());
        assert!(output_file.exists());
        
        let content = std::fs::read_to_string(&output_file).unwrap();
        assert!(!content.is_empty());
        assert!(content.contains("PID")); // Should contain statistics headers
    }
    
    #[test]
    fn test_output_file_with_trace_mode() {
        let temp_dir = TempDir::new().unwrap();
        let output_file = temp_dir.path().join("trace_output.txt");
        
        let output = Command::new("./target/debug/malloc_free")
            .args(&["-t", "--output-file", output_file.to_str().unwrap()])
            .output()
            .expect("Failed to execute malloc_free");
        
        assert!(output.status.success());
        assert!(output_file.exists());
    }
}
```

This design provides a comprehensive solution for adding file output capability to malloc_free while maintaining compatibility with all existing features and ensuring robust error handling.