# Implementation Plan

- [ ] 1. Rename trace_path to trace_mode for clarity
  - Rename `trace_path` variable to `trace_mode` in eBPF C program
  - Update userspace code to set `trace_mode` instead of `trace_path`
  - Update all references and comments to use the new naming
  - _Requirements: 1.1, 2.1_

- [ ] 2. Enhance eBPF data structures with mode-aware timestamp fields
  - Add `alloc_timestamp_ns` field to `malloc_event` structure (Individual Mode)
  - Add age-related fields to `malloc_record` structure (Statistics Mode)
  - Define age histogram range constants and thresholds
  - _Requirements: 1.1, 2.1, 7.1_

- [ ] 3. Implement mode-aware timestamp recording in eBPF allocation handlers
  - [ ] 3.1 Add mode-aware timestamp recording to `handle_alloc_entry()` function
    - Use `bpf_ktime_get_ns()` to capture allocation timestamp
    - When `trace_mode = true`: Store timestamp in `malloc_event` structure
    - When `trace_mode = false`: Update age statistics in `malloc_record` structure
    - _Requirements: 1.1, 2.1, 7.1_

  - [ ] 3.2 Create age statistics helper functions for Statistics Mode
    - Implement `update_age_statistics()` function in eBPF
    - Update oldest allocation timestamp per process/thread
    - Update running totals for average age calculation
    - Update age histogram ranges when `--age-histogram` is used
    - _Requirements: 2.2, 2.3, 4.2, 4.3_

- [ ] 4. Extend CLI interface with age-related options
  - [ ] 4.1 Add new command-line arguments to Cli structure
    - Add `--min-age` option with string parsing (switches to Individual Mode)
    - Add `--age-histogram` boolean flag (Statistics Mode only)
    - Remove `--show-age` flag (simplified design)
    - _Requirements: 3.1, 4.1_

  - [ ] 4.2 Implement age duration parsing and validation
    - Create `AgeDuration` struct for time representation
    - Implement parsing for formats: "300", "5m", "1h", "300s"
    - Add input validation with clear error messages
    - Handle edge cases and invalid inputs gracefully
    - _Requirements: 3.2, 3.4, 9.1_

  - [ ] 4.3 Update mode control logic
    - Set `trace_mode = true` when `--min-age`, `-t`, or `-T` is used
    - Show warning when `--age-histogram` is used with Individual Mode flags
    - Ensure proper mode switching based on CLI flags
    - _Requirements: 3.1, 4.5_

- [ ] 5. Implement userspace age calculation and utilities
  - [ ] 5.1 Create age calculation functions
    - Implement `calculate_allocation_age()` for current age calculation
    - Add `format_age()` for human-readable age display
    - Remove confidence scoring functionality (simplified design)
    - Handle timestamp wraparound and clock adjustments
    - _Requirements: 7.2, 7.3, 9.2, 9.3_

  - [ ] 5.2 Implement age-based filtering logic for Individual Mode
    - Create filtering functions for minimum age thresholds
    - Apply age filters to malloc events in Individual Mode
    - Integrate filtering with existing PID and duration filters
    - _Requirements: 3.1, 3.2, 8.1, 8.3_

- [ ] 6. Enhance output formatting with age information
  - [ ] 6.1 Update Statistics Mode output with age statistics
    - Add "Oldest" and "Avg.Age" columns to statistics table
    - Calculate and display oldest allocation age per process/thread
    - Show average age of unfreed allocations per process/thread
    - _Requirements: 2.2, 2.3, 5.3_

  - [ ] 6.2 Enhance Individual Mode output with age display
    - Add age information to each individual allocation display
    - Remove confidence level display (simplified design)
    - Apply age filtering to allocation display
    - Format age in human-readable format (e.g., "5m 23s")
    - Show stack traces only when `-t/-T` options are used
    - _Requirements: 1.2, 5.1, 5.4, 8.2_

  - [ ] 6.3 Implement age histogram functionality for Statistics Mode
    - Create `AgeHistogram` struct for age distribution analysis
    - Define age ranges: 0-1min, 1-5min, 5-30min, 30+min
    - Calculate count, total size, and average size per range
    - Remove confidence assessment (simplified design)
    - _Requirements: 4.2, 4.3, 4.4_

- [ ] 7. Integrate age tracking with existing features
  - [ ] 7.1 Update event processing to handle age-filtered Individual Mode
    - Modify `process_events()` to apply age filters in Individual Mode
    - Ensure age filtering works with trace path options (`-t/-T`)
    - Combine age filtering with PID filtering (`-p`)
    - _Requirements: 8.1, 8.2, 8.3_

  - [ ] 7.2 Enhance Statistics Mode with age-based metrics
    - Add age information to statistics output as described in Requirement 2
    - Include age histogram when `--age-histogram` flag is used
    - Ensure Statistics Mode works with existing duration limits (`-d`)
    - _Requirements: 8.4, 8.5_

- [ ] 8. Add comprehensive error handling and edge case management
  - [ ] 8.1 Implement robust timestamp handling
    - Add clock adjustment detection and handling
    - Implement maximum age limits to prevent overflow
    - Handle timestamp corruption gracefully
    - Add appropriate warning messages for edge cases
    - _Requirements: 7.2, 7.3, 9.2, 9.3_

  - [ ] 8.2 Add age filter validation and error reporting
    - Validate age format and range limits
    - Provide clear error messages for invalid inputs
    - Handle memory allocation failures gracefully
    - _Requirements: 3.4, 9.1_

- [x] 9. Write comprehensive unit tests for age tracking functionality
  - Test age duration parsing with various input formats
  - Test age calculation with different timestamp scenarios
  - Test age formatting for various duration ranges
  - Test age filtering logic with edge cases
  - Test mode switching logic
  - _Requirements: All requirements validation_

- [ ]* 10. Write integration tests for end-to-end age tracking
  - Test age filtering with real allocation patterns in Individual Mode
  - Test age histogram generation with sample data in Statistics Mode
  - Test integration with existing CLI options
  - Test mode switching behavior
  - _Requirements: 6.1, 6.2, 6.3_

- [ ]* 11. Add performance benchmarks and overhead measurement
  - Measure memory overhead of additional timestamp fields per mode
  - Benchmark CPU overhead of age calculation
  - Test scalability with large numbers of allocations
  - Compare performance between Statistics Mode and Individual Mode
  - _Requirements: 6.1, 6.2, 6.3_

- [ ] 12. Update documentation and help text
  - [ ] 12.1 Update CLI help text with new age-related options
    - Add descriptions for `--min-age`, `--age-histogram`
    - Remove `--show-age` references (simplified design)
    - Provide usage examples for age filtering
    - Document age format specifications and mode switching behavior
    - _Requirements: 3.3_

  - [ ] 12.2 Update existing documentation with age tracking examples
    - Add age tracking examples for both Statistics and Individual modes
    - Update design documentation with implementation details
    - Create usage examples for different age tracking scenarios
    - Document the `trace_mode` variable and mode control
    - _Requirements: All requirements_

- [ ] 13. Fix timestamp synchronization issues
  - [ ] 13.1 Implement proper timestamp baseline synchronization
    - Capture baseline monotonic time before attaching eBPF program
    - Store baseline timestamp for age calculations
    - Ensure maps are cleared before any allocations are captured
    - _Requirements: 7.1, 7.2, 7.3_

  - [ ] 13.2 Improve age calculation accuracy
    - Use clock_gettime(CLOCK_MONOTONIC) instead of /proc/uptime for better precision
    - Add timestamp validation to detect clock adjustments
    - Implement proper handling of timestamp wraparound scenarios
    - _Requirements: 9.2, 9.3_

  - [ ] 13.3 Add debugging and validation for timestamp issues
    - Add debug logging for timestamp synchronization
    - Implement sanity checks for allocation ages
    - Add warnings for suspicious age calculations
    - _Requirements: 9.4_