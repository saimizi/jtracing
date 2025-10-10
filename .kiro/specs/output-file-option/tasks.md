# Implementation Plan

- [x] 1. Add CLI option for output file
  - Add `output_file: Option<PathBuf>` field to Cli struct
  - Add clap annotation with appropriate help text and value name
  - Import PathBuf from std::path in the CLI module
  - _Requirements: 6.1, 6.4_

- [x] 2. Implement output writer abstraction
  - [x] 2.1 Create OutputWriter trait with write_line, write_formatted, and flush methods
    - Define trait with error handling using JtraceError return types
    - Add documentation for each trait method
    - _Requirements: 1.1, 3.1_

  - [x] 2.2 Implement StdoutWriter for console output
    - Create struct implementing OutputWriter trait for stdout
    - Use println! and print! macros for output
    - Implement flush using std::io::Write::flush on stdout
    - _Requirements: 1.1, 3.1_

  - [x] 2.3 Implement FileWriter for file output
    - Create struct with BufWriter<File> and PathBuf fields
    - Implement new() method with file creation and error handling
    - Implement OutputWriter trait methods with file I/O operations
    - Add Drop implementation to ensure file is flushed on cleanup
    - _Requirements: 1.1, 1.2, 1.3, 5.4_

- [ ] 3. Create output manager system
  - [x] 3.1 Implement OutputManager struct
    - Create struct containing Box<dyn OutputWriter>
    - Implement new() method that creates appropriate writer based on CLI option
    - Add convenience methods for writing lines and formatted output
    - _Requirements: 2.1, 2.2, 2.3_

  - [x] 3.2 Create output macros for convenient formatting
    - Define output_writeln! macro for line-based output with formatting
    - Define output_write! macro for inline output with formatting
    - Ensure macros handle error propagation properly
    - _Requirements: 3.1, 3.2_

- [ ] 4. Add file validation and error handling
  - [ ] 4.1 Implement CLI validation for output file paths
    - Add validate() method to Cli struct
    - Check parent directory existence and create if needed
    - Test file write access before main processing
    - _Requirements: 1.4, 4.1, 4.2_

  - [ ] 4.2 Create comprehensive file error handling
    - Implement handle_file_operation helper function
    - Map std::io::ErrorKind to user-friendly error messages
    - Add JtraceError variants for file operations
    - _Requirements: 4.1, 4.2, 4.3, 4.4_

  - [ ] 4.3 Add retry logic for transient file errors
    - Implement write_with_retry method in FileWriter
    - Handle disk full scenarios with appropriate error messages
    - Add brief delays between retry attempts
    - _Requirements: 4.3, 5.3_

- [x] 5. Integrate output manager with existing functions
  - [x] 5.1 Modify print_summary function to use OutputManager
    - Change function signature to accept &mut OutputManager parameter
    - Replace println! calls with output_writeln! macro calls
    - Add error handling and propagation
    - _Requirements: 2.1, 3.1, 3.2_

  - [x] 5.2 Modify trace mode output functions to use OutputManager
    - Update print_trace_allocations function signature and implementation
    - Update print_stack_trace function for file output
    - Ensure stack trace indentation is preserved in file output
    - _Requirements: 2.2, 3.3_

  - [x] 5.3 Modify age tracking output functions to use OutputManager
    - Update print_age_histogram function for file output
    - Update age-related output formatting functions
    - Ensure age information formatting is preserved
    - _Requirements: 2.3, 3.4_

- [x] 6. Implement signal handling and cleanup
  - [ ] 6.1 Add signal handler setup
    - Use ctrlc crate to handle SIGINT (Ctrl+C)
    - Create atomic boolean for interruption tracking
    - Add setup_signal_handlers function in main
    - _Requirements: 8.1, 8.2_

  - [x] 6.2 Implement graceful shutdown logic
    - Add check_interrupted function for periodic interruption checks
    - Modify main processing loops to check for interruption
    - Write interruption markers to output when interrupted
    - Ensure output is flushed before exit
    - _Requirements: 8.1, 8.3, 8.4, 8.5_

  - [x] 6.3 Add cleanup on drop for FileWriter
    - Ensure Drop implementation flushes remaining data
    - Handle cleanup errors gracefully without panicking
    - _Requirements: 5.4, 8.4_

- [x] 7. Update main application flow
  - [x] 7.1 Modify main function to use OutputManager
    - Create OutputManager instance based on CLI options
    - Pass OutputManager to processing functions
    - Add progress messages only when outputting to stdout
    - _Requirements: 2.1, 6.3_

  - [x] 7.2 Update statistics mode processing
    - Modify process_statistics_mode to accept OutputManager
    - Update all output calls to use OutputManager methods
    - Add error handling for output operations
    - _Requirements: 2.1, 3.1_

  - [x] 7.3 Update trace mode processing
    - Modify process_trace_mode to accept OutputManager
    - Update all trace output to use OutputManager methods
    - Ensure stack traces are properly formatted in files
    - _Requirements: 2.2, 3.3_

- [x] 8. Add comprehensive error handling
  - [x] 8.1 Implement centralized output error handling
    - Create handle_output_error function for consistent error reporting
    - Differentiate between stdout and file error messages
    - Add context about partial results when errors occur
    - _Requirements: 4.1, 4.2, 4.3, 4.4_

  - [x] 8.2 Add periodic flushing for long-running operations
    - Implement should_flush logic based on time intervals
    - Add flush calls during long processing loops
    - Handle flush errors without terminating analysis
    - _Requirements: 5.1, 5.2_

- [x] 9. Add dependencies and imports
  - [x] 9.1 Add required dependencies to Cargo.toml
    - Add ctrlc crate for signal handling
    - Add chrono crate for timestamp formatting in interruption messages
    - Ensure std::io::BufWriter and related imports are available
    - _Requirements: 8.1, 8.5_

  - [x] 9.2 Update module imports
    - Add PathBuf import to CLI module
    - Add BufWriter, File, and Write imports to output module
    - Add signal handling imports to main module
    - _Requirements: 1.1, 5.4, 8.1_

- [ ]* 10. Write unit tests for output functionality
  - Test FileWriter creation with valid and invalid paths
  - Test OutputManager creation for both stdout and file modes
  - Test output formatting preservation in file mode
  - Test error handling for various file operation failures
  - _Requirements: All requirements validation_

- [ ]* 11. Write integration tests for end-to-end functionality
  - Test complete malloc_free execution with --output-file option
  - Test output file content matches expected format
  - Test integration with existing CLI options (-t, -p, --min-age, etc.)
  - Test signal handling and cleanup behavior
  - _Requirements: 2.1, 2.2, 2.3, 8.1, 8.2_

- [x] 12. Update help text and documentation
  - [x] 12.1 Add help text for --output-file option
    - Add clear description of the option's purpose
    - Include examples of usage with different modes
    - Document file path format requirements
    - _Requirements: 6.4_

  - [x] 12.2 Update existing documentation with output file examples
    - Add examples showing --output-file with statistics mode
    - Add examples showing --output-file with trace mode
    - Add examples showing --output-file with age tracking options
    - Document behavior when file already exists (overwrite)
    - _Requirements: 6.1, 6.2, 6.3_