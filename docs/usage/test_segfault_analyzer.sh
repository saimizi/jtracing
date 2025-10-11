#!/bin/bash
#
# Segfault Analyzer Test Script
#
# This script demonstrates various usage scenarios for the segfault analyzer
# and provides automated testing capabilities.
#

set -e

# Configuration
ANALYZER_PATH="../target/release/segfault_analyzer"
TEST_PROGRAM_PATH="../testfiles/segfault_examples"
OUTPUT_DIR="/tmp/segfault_analyzer_tests"
LOG_FILE="$OUTPUT_DIR/test_results.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (for BPF program loading)"
        log_info "Please run: sudo $0"
        exit 1
    fi
    
    # Check if analyzer exists
    if [[ ! -f "$ANALYZER_PATH" ]]; then
        log_error "Segfault analyzer not found at: $ANALYZER_PATH"
        log_info "Please build it first: cargo build --release --bin segfault_analyzer"
        exit 1
    fi
    
    # Check if test program exists
    if [[ ! -f "$TEST_PROGRAM_PATH" ]]; then
        log_warning "Test program not found, building it..."
        (cd "$(dirname "$TEST_PROGRAM_PATH")" && make)
        if [[ ! -f "$TEST_PROGRAM_PATH" ]]; then
            log_error "Failed to build test program"
            exit 1
        fi
    fi
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    log_success "Prerequisites check passed"
}

# Test basic functionality
test_basic_functionality() {
    log_info "Testing basic functionality..."
    
    local output_file="$OUTPUT_DIR/basic_test.log"
    
    # Start analyzer in background
    timeout 10s "$ANALYZER_PATH" -v > "$output_file" 2>&1 &
    local analyzer_pid=$!
    
    # Give analyzer time to start
    sleep 2
    
    # Trigger a segfault
    log_info "Triggering null pointer dereference..."
    "$TEST_PROGRAM_PATH" null >/dev/null 2>&1 || true
    
    # Wait a bit for event processing
    sleep 2
    
    # Stop analyzer
    kill $analyzer_pid 2>/dev/null || true
    wait $analyzer_pid 2>/dev/null || true
    
    # Check if segfault was captured
    if grep -q "SEGFAULT" "$output_file"; then
        log_success "Basic functionality test passed - segfault detected"
    else
        log_error "Basic functionality test failed - no segfault detected"
        log_info "Analyzer output:"
        cat "$output_file"
        return 1
    fi
}

# Test process filtering
test_process_filtering() {
    log_info "Testing process filtering..."
    
    local output_file="$OUTPUT_DIR/filter_test.log"
    
    # Start analyzer with process name filter
    timeout 10s "$ANALYZER_PATH" -n segfault_examples -v > "$output_file" 2>&1 &
    local analyzer_pid=$!
    
    sleep 2
    
    # Trigger segfault in target process
    log_info "Triggering segfault in filtered process..."
    "$TEST_PROGRAM_PATH" wild >/dev/null 2>&1 || true
    
    sleep 2
    
    # Stop analyzer
    kill $analyzer_pid 2>/dev/null || true
    wait $analyzer_pid 2>/dev/null || true
    
    # Check results
    if grep -q "segfault_examples" "$output_file"; then
        log_success "Process filtering test passed"
    else
        log_error "Process filtering test failed"
        return 1
    fi
}

# Test stack trace capture
test_stack_trace() {
    log_info "Testing stack trace capture..."
    
    local output_file="$OUTPUT_DIR/stacktrace_test.log"
    
    # Start analyzer with stack trace enabled
    timeout 10s "$ANALYZER_PATH" -t -v > "$output_file" 2>&1 &
    local analyzer_pid=$!
    
    sleep 2
    
    # Trigger segfault with nested function calls
    log_info "Triggering segfault in nested function..."
    "$TEST_PROGRAM_PATH" nested >/dev/null 2>&1 || true
    
    sleep 2
    
    # Stop analyzer
    kill $analyzer_pid 2>/dev/null || true
    wait $analyzer_pid 2>/dev/null || true
    
    # Check for stack trace
    if grep -q "Stack Trace" "$output_file"; then
        log_success "Stack trace test passed"
    else
        log_warning "Stack trace test failed - no stack trace found"
        return 1
    fi
}

# Test register capture
test_register_capture() {
    log_info "Testing register capture..."
    
    local output_file="$OUTPUT_DIR/register_test.log"
    
    # Start analyzer with register capture enabled
    timeout 10s "$ANALYZER_PATH" -r -v > "$output_file" 2>&1 &
    local analyzer_pid=$!
    
    sleep 2
    
    # Trigger segfault
    log_info "Triggering segfault for register capture..."
    "$TEST_PROGRAM_PATH" readonly >/dev/null 2>&1 || true
    
    sleep 2
    
    # Stop analyzer
    kill $analyzer_pid 2>/dev/null || true
    wait $analyzer_pid 2>/dev/null || true
    
    # Check for register information
    if grep -q "Registers" "$output_file"; then
        log_success "Register capture test passed"
    else
        log_warning "Register capture test failed - no register info found"
        return 1
    fi
}

# Test JSON output
test_json_output() {
    log_info "Testing JSON output format..."
    
    local output_file="$OUTPUT_DIR/json_test.json"
    
    # Start analyzer with JSON output
    timeout 10s "$ANALYZER_PATH" --format json -t > "$output_file" 2>&1 &
    local analyzer_pid=$!
    
    sleep 2
    
    # Trigger segfault
    log_info "Triggering segfault for JSON output..."
    "$TEST_PROGRAM_PATH" funcptr >/dev/null 2>&1 || true
    
    sleep 2
    
    # Stop analyzer
    kill $analyzer_pid 2>/dev/null || true
    wait $analyzer_pid 2>/dev/null || true
    
    # Validate JSON output
    if command -v jq >/dev/null 2>&1; then
        if jq empty "$output_file" 2>/dev/null; then
            log_success "JSON output test passed - valid JSON generated"
        else
            log_error "JSON output test failed - invalid JSON"
            return 1
        fi
    else
        # Basic JSON validation without jq
        if grep -q '"timestamp"' "$output_file" && grep -q '"pid"' "$output_file"; then
            log_success "JSON output test passed - JSON structure detected"
        else
            log_error "JSON output test failed - no JSON structure found"
            return 1
        fi
    fi
}

# Test file output
test_file_output() {
    log_info "Testing file output..."
    
    local output_file="$OUTPUT_DIR/file_output_test.log"
    
    # Start analyzer with file output
    timeout 10s "$ANALYZER_PATH" -o "$output_file" -v &
    local analyzer_pid=$!
    
    sleep 2
    
    # Trigger segfault
    log_info "Triggering segfault for file output..."
    "$TEST_PROGRAM_PATH" string >/dev/null 2>&1 || true
    
    sleep 2
    
    # Stop analyzer
    kill $analyzer_pid 2>/dev/null || true
    wait $analyzer_pid 2>/dev/null || true
    
    # Check if file was created and contains segfault info
    if [[ -f "$output_file" ]] && grep -q "SEGFAULT" "$output_file"; then
        log_success "File output test passed"
    else
        log_error "File output test failed"
        return 1
    fi
}

# Test statistics
test_statistics() {
    log_info "Testing statistics display..."
    
    local output_file="$OUTPUT_DIR/stats_test.log"
    
    # Start analyzer with statistics
    timeout 15s "$ANALYZER_PATH" --stats --stats-interval 5 -v > "$output_file" 2>&1 &
    local analyzer_pid=$!
    
    sleep 2
    
    # Trigger multiple segfaults
    log_info "Triggering multiple segfaults for statistics..."
    for test_type in null wild bounds; do
        "$TEST_PROGRAM_PATH" "$test_type" >/dev/null 2>&1 || true
        sleep 1
    done
    
    # Wait for statistics display
    sleep 8
    
    # Stop analyzer
    kill $analyzer_pid 2>/dev/null || true
    wait $analyzer_pid 2>/dev/null || true
    
    # Check for statistics output
    if grep -q "Segfault Analyzer Statistics" "$output_file"; then
        log_success "Statistics test passed"
    else
        log_error "Statistics test failed - no statistics found"
        return 1
    fi
}

# Performance test
test_performance() {
    log_info "Testing performance with multiple segfaults..."
    
    local output_file="$OUTPUT_DIR/performance_test.log"
    
    # Start analyzer with statistics
    timeout 30s "$ANALYZER_PATH" --stats --stats-interval 10 > "$output_file" 2>&1 &
    local analyzer_pid=$!
    
    sleep 2
    
    # Generate multiple segfaults rapidly
    log_info "Generating rapid segfaults..."
    for i in {1..10}; do
        "$TEST_PROGRAM_PATH" null >/dev/null 2>&1 || true &
        "$TEST_PROGRAM_PATH" wild >/dev/null 2>&1 || true &
        sleep 0.5
    done
    
    # Wait for processing
    sleep 15
    
    # Stop analyzer
    kill $analyzer_pid 2>/dev/null || true
    wait $analyzer_pid 2>/dev/null || true
    
    # Check for performance metrics
    if grep -q "Events per second" "$output_file"; then
        log_success "Performance test completed"
        # Extract and display key metrics
        grep -E "(Events per second|Event drop rate|Memory usage)" "$output_file" | head -3
    else
        log_warning "Performance test completed but no metrics found"
    fi
}

# Run comprehensive test suite
run_comprehensive_tests() {
    log_info "Starting comprehensive test suite..."
    
    local tests=(
        "test_basic_functionality"
        "test_process_filtering" 
        "test_stack_trace"
        "test_register_capture"
        "test_json_output"
        "test_file_output"
        "test_statistics"
        "test_performance"
    )
    
    local passed=0
    local failed=0
    
    for test in "${tests[@]}"; do
        log_info "Running $test..."
        if $test; then
            ((passed++))
        else
            ((failed++))
        fi
        echo "----------------------------------------" >> "$LOG_FILE"
    done
    
    log_info "Test suite completed"
    log_info "Results: $passed passed, $failed failed"
    
    if [[ $failed -eq 0 ]]; then
        log_success "All tests passed!"
        return 0
    else
        log_error "Some tests failed. Check $LOG_FILE for details."
        return 1
    fi
}

# Interactive demo
run_interactive_demo() {
    log_info "Starting interactive demo..."
    
    echo "This demo will show various segfault analyzer features."
    echo "Press Enter to continue between steps, or Ctrl+C to exit."
    
    read -p "Press Enter to start basic monitoring demo..."
    
    echo "Starting segfault analyzer in background..."
    "$ANALYZER_PATH" -v &
    local analyzer_pid=$!
    
    sleep 2
    
    echo "Triggering a null pointer dereference..."
    "$TEST_PROGRAM_PATH" null >/dev/null 2>&1 || true
    
    sleep 2
    
    read -p "Press Enter to test stack trace capture..."
    
    echo "Restarting analyzer with stack trace enabled..."
    kill $analyzer_pid 2>/dev/null || true
    wait $analyzer_pid 2>/dev/null || true
    
    "$ANALYZER_PATH" -t -v &
    analyzer_pid=$!
    
    sleep 2
    
    echo "Triggering segfault in nested function..."
    "$TEST_PROGRAM_PATH" nested >/dev/null 2>&1 || true
    
    sleep 2
    
    read -p "Press Enter to test JSON output..."
    
    echo "Restarting analyzer with JSON output..."
    kill $analyzer_pid 2>/dev/null || true
    wait $analyzer_pid 2>/dev/null || true
    
    "$ANALYZER_PATH" --format json -t &
    analyzer_pid=$!
    
    sleep 2
    
    echo "Triggering segfault for JSON capture..."
    "$TEST_PROGRAM_PATH" readonly >/dev/null 2>&1 || true
    
    sleep 2
    
    echo "Stopping analyzer..."
    kill $analyzer_pid 2>/dev/null || true
    wait $analyzer_pid 2>/dev/null || true
    
    log_success "Interactive demo completed!"
}

# Show usage
show_usage() {
    echo "Segfault Analyzer Test Script"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  test        - Run comprehensive test suite (default)"
    echo "  demo        - Run interactive demo"
    echo "  basic       - Run basic functionality test only"
    echo "  performance - Run performance test only"
    echo "  help        - Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0              # Run full test suite"
    echo "  sudo $0 demo         # Interactive demonstration"
    echo "  sudo $0 basic        # Quick basic test"
    echo ""
    echo "Output files will be saved to: $OUTPUT_DIR"
    echo "Test log will be saved to: $LOG_FILE"
}

# Main function
main() {
    local command="${1:-test}"
    
    case "$command" in
        "test")
            check_prerequisites
            run_comprehensive_tests
            ;;
        "demo")
            check_prerequisites
            run_interactive_demo
            ;;
        "basic")
            check_prerequisites
            test_basic_functionality
            ;;
        "performance")
            check_prerequisites
            test_performance
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Initialize log file
echo "Segfault Analyzer Test Session - $(date)" > "$LOG_FILE"
echo "=========================================" >> "$LOG_FILE"

# Run main function
main "$@"