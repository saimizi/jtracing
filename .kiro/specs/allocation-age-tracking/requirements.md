# Requirements Document

## Introduction

This document specifies the requirements for adding allocation age tracking to the malloc_free tool. The allocation age tracking feature will help distinguish between true memory leaks (old unfreed allocations) and normal memory usage (recent allocations that may be freed soon). This addresses the core challenge of determining whether unfreed memory represents a leak or legitimate temporary allocation.

The malloc_free tool supports two primary tracing modes:

1. **Statistics Mode** (default): Collects and displays aggregate statistical information about memory allocation patterns per process/thread, including total allocated memory, freed memory, current usage, and allocation counts. This mode provides a high-level overview of memory usage patterns.

2. **Trace Mode** (`-t` flag): Captures and displays individual malloc()/free() calls with their complete stack traces, showing detailed execution flow for each allocation event. This mode is used for detailed analysis of specific allocation patterns and leak investigation.

The allocation age tracking feature must integrate seamlessly with both modes, providing age-related statistics in Statistics Mode and per-allocation age information in Trace Mode.

## Requirements

### Requirement 1: Timestamp Tracking for Trace Mode

**User Story:** As a developer debugging memory leaks in Trace Mode, I want to know how long each individual allocation has been unfreed, so that I can distinguish between recent allocations (likely normal) and old allocations (likely leaked).

#### Acceptance Criteria

1. WHEN an allocation occurs in Trace Mode THEN the system SHALL record the current timestamp for that allocation
2. WHEN displaying individual allocation information in Trace Mode THEN the system SHALL show the age of each unfreed allocation
3. WHEN an allocation is freed in Trace Mode THEN the system SHALL remove the timestamp tracking for that allocation
4. IF the system clock changes THEN the system SHALL handle timestamp calculations gracefully without crashes

### Requirement 2: Timestamp Tracking for Statistics Mode

**User Story:** As a developer analyzing memory usage patterns in Statistics Mode, I want to see age-related statistics per process/thread, so that I can identify processes with potentially leaked memory based on allocation age patterns.

#### Acceptance Criteria

1. WHEN collecting statistics per process/thread THEN the system SHALL track the timestamp of the oldest unfreed allocation
2. WHEN displaying statistics THEN the system SHALL show the age of the oldest allocation per process/thread
3. WHEN calculating statistics THEN the system SHALL compute the average age of all unfreed allocations per process/thread
4. WHEN an allocation is freed THEN the system SHALL update the oldest allocation timestamp if necessary
5. IF no unfreed allocations remain for a process THEN the system SHALL reset age tracking for that process

### Requirement 3: Age-Based Filtering for Trace Mode

**User Story:** As a developer analyzing memory usage in Trace Mode, I want to filter individual allocations by age, so that I can focus on old allocations that are likely to be leaks while ignoring recent normal allocations.

#### Acceptance Criteria

1. WHEN using the --min-age flag THEN the system SHALL automatically switch to Trace Mode to enable individual allocation filtering
2. WHEN using the --min-age flag in Trace Mode THEN the system SHALL only display individual allocations older than the specified threshold
3. WHEN age thresholds are specified THEN the system SHALL accept time units: seconds (s), minutes (m), hours (h)
4. WHEN age thresholds are specified THEN the system SHALL default to seconds if no unit is provided
5. WHEN invalid age values are provided THEN the system SHALL display clear error messages

### Requirement 4: Race Condition Prevention and Data Integrity

**User Story:** As a developer using malloc_free in high-concurrency environments, I want accurate and consistent allocation tracking without race conditions, so that I can trust the age and size data for memory leak analysis.

#### Acceptance Criteria

1. WHEN multiple threads allocate memory concurrently on the same CPU THEN the system SHALL NOT corrupt timestamp or TID data
2. WHEN a thread migrates between CPUs during allocation THEN the system SHALL maintain correct allocation tracking
3. WHEN displaying age information THEN the system SHALL NOT show "unknown" ages due to data corruption
4. WHEN tracking allocation sizes THEN the system SHALL use thread-safe mechanisms to prevent data races
5. IF concurrent allocations occur THEN each allocation SHALL maintain its correct timestamp and thread association

### Requirement 5: Accurate Memory Size Tracking

**User Story:** As a developer analyzing memory usage patterns, I want accurate byte-level tracking of allocated and freed memory, so that I can identify the true memory footprint and detect leaks precisely.

#### Acceptance Criteria

1. WHEN memory is freed THEN the system SHALL track the actual number of bytes freed, not just increment a counter
2. WHEN displaying statistics THEN the "Free" column SHALL show the total bytes freed, not the number of free operations
3. WHEN calculating "Real" memory usage THEN the system SHALL use accurate allocation and free sizes (Real = Alloc - Free)
4. WHEN memory is allocated in one thread and freed in another THEN the system SHALL correctly attribute both operations to the same process
5. IF allocation size lookup fails THEN the system SHALL handle the error gracefully without corrupting statistics

### Requirement 6: Process-Level Memory Tracking

**User Story:** As a developer analyzing multi-threaded applications, I want memory statistics aggregated at the process level, so that I can see the complete memory usage picture regardless of which threads perform allocations and frees.

#### Acceptance Criteria

1. WHEN memory is allocated in one thread and freed in another thread of the same process THEN both operations SHALL be correctly aggregated in process statistics
2. WHEN displaying Statistics Mode output THEN memory usage SHALL be shown per-process, not per-thread
3. WHEN calculating age statistics THEN the system SHALL track the oldest allocation across all threads in a process
4. WHEN computing average allocation age THEN the system SHALL include allocations from all threads in the process
5. IF a process has multiple threads THEN the age histogram SHALL aggregate data from all threads
6. WHEN no allocations match the age criteria in Trace Mode THEN the system SHALL display an appropriate message
7. WHEN using --min-age together with -t/-T option THEN the system SHALL show stack traces only for allocations older than the threshold

**Examples:**
- `--min-age 300` or `--min-age 300s` = show allocations older than 5 minutes
- `--min-age 5m` = show allocations older than 5 minutes  
- `--min-age 1h` = show allocations older than 1 hour

**Note:** The --max-age flag is removed as it's not useful for leak detection. Focus is on old allocations (potential leaks), not recent ones.

### Requirement 4: Age Distribution Analysis for Statistics Mode

**User Story:** As a developer investigating memory patterns in Statistics Mode, I want to see the distribution of allocation ages across processes, so that I can understand the overall memory usage patterns and identify potential leak hotspots through aggregate analysis.

#### Acceptance Criteria

1. WHEN using the --age-histogram flag in Statistics Mode THEN the system SHALL display allocations grouped by age ranges
2. WHEN displaying age histogram THEN the system SHALL show count, total size, and average size for each age range
3. WHEN displaying age histogram THEN the system SHALL use meaningful age ranges (0-1min, 1-5min, 5-30min, 30min+)
4. WHEN displaying age histogram THEN the system SHALL calculate and display leak confidence based on age distribution
5. WHEN using --age-histogram together with -t/-T or --min-age flags THEN the system SHALL display a warning that --age-histogram is ignored in Trace Mode

### Requirement 5: Enhanced Output Formats

**User Story:** As a developer analyzing memory leaks, I want age information integrated into existing output formats, so that I can see age data alongside existing allocation information.

#### Acceptance Criteria

1. WHEN using trace mode THEN the system SHALL display age for each unfreed allocation in human-readable format
2. WHEN using trace mode with --min-age THEN the system SHALL show stack traces only for allocations older than the threshold
3. WHEN using statistics mode THEN the system SHALL display the age information described in Requirement 2
4. WHEN displaying stack traces THEN the system SHALL show allocation age alongside the trace

**Example trace output with age:**
```
1    8192     malloc: myapp (1234) [Age: 5m 23s]
     Backtrace for malloc():
     7f8b2c0a1234(+0)  malloc /lib/x86_64-linux-gnu/libc.so.6
     55a8f2b3c567(+12) leak_function /home/user/myapp
```

### Requirement 6: Performance and Memory Efficiency

**User Story:** As a system administrator monitoring production systems, I want age tracking to have minimal performance impact, so that I can use it in production environments without affecting application performance.

#### Acceptance Criteria

1. WHEN age tracking is enabled THEN the memory overhead per allocation SHALL be less than 16 bytes
2. WHEN age tracking is enabled THEN the CPU overhead SHALL be less than 5% compared to baseline
3. WHEN the system is under memory pressure THEN age tracking SHALL not cause allocation failures
4. WHEN age tracking maps become full THEN the system SHALL handle gracefully with appropriate warnings

### Requirement 7: Time Precision and Accuracy

**User Story:** As a developer debugging timing-sensitive memory issues, I want accurate age measurements, so that I can correlate memory allocations with specific application events.

#### Acceptance Criteria

1. WHEN recording timestamps THEN the system SHALL use nanosecond precision
2. WHEN calculating ages THEN the system SHALL handle timestamp wraparound correctly
3. WHEN system time changes THEN the system SHALL detect and handle clock adjustments
4. WHEN displaying ages THEN the system SHALL use human-readable formats (e.g., "2m 30s", "1h 15m")

### Requirement 8: Integration with Existing Features

**User Story:** As a developer using multiple malloc_free features, I want age tracking to work seamlessly with existing functionality, so that I can combine age filtering with other analysis options.

#### Acceptance Criteria

1. WHEN using --min-age with trace path options (-t/-T) THEN the system SHALL show stack traces only for allocations older than the threshold
2. WHEN using --min-age without trace path options (-t/-T) THEN the system SHALL show individual allocations (without stack traces) filtered by age
3. WHEN using --min-age with PID filtering (-p) THEN both filters SHALL work together correctly
4. WHEN using age tracking with statistics mode (-s) THEN age-based statistics SHALL be included
5. WHEN using age tracking with duration limits (-d) THEN both time constraints SHALL be respected

**Example usage combinations:**
```bash
# Show stack traces for allocations older than 5 minutes in process 1234
sudo ./malloc_free -p 1234 -t --min-age 5m

# Show summary of allocations older than 1 hour across all processes  
sudo ./malloc_free --min-age 1h -d 60

# Show statistics including age distribution for specific process
sudo ./malloc_free -p 1234 -s --age-histogram
```

### Requirement 9: Error Handling and Edge Cases

**User Story:** As a developer using malloc_free in various environments, I want robust error handling for age tracking, so that the tool remains reliable even in edge cases.

#### Acceptance Criteria

1. WHEN timestamp storage fails THEN the system SHALL continue operation without age tracking for that allocation
2. WHEN clock resolution is insufficient THEN the system SHALL use the best available precision
3. WHEN memory maps are corrupted THEN the system SHALL detect and report the issue clearly
4. WHEN age calculations overflow THEN the system SHALL handle gracefully and report maximum age