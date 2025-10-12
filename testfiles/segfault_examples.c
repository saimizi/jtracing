/*
 * Segfault Test Examples
 * 
 * This file contains various types of segmentation faults that can be used
 * to test the segfault_analyzer tool. Each function demonstrates a different
 * type of memory access violation.
 * 
 * Compile with: gcc -g -O0 segfault_examples.c -o segfault_examples
 * 
 * Usage examples:
 *   ./segfault_examples null        # Null pointer dereference
 *   ./segfault_examples wild        # Wild pointer access
 *   ./segfault_examples stack       # Stack overflow
 *   ./segfault_examples readonly    # Write to read-only memory
 *   ./segfault_examples freed       # Use after free
 *   ./segfault_examples bounds      # Array bounds violation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

void test_null_pointer() {
    printf("Testing null pointer dereference...\n");
    int *p = NULL;
    *p = 42;  // SEGV_MAPERR - address not mapped
}

void test_wild_pointer() {
    printf("Testing wild pointer access...\n");
    int *p = (int*)0x12345678;  // Random invalid address
    *p = 42;  // SEGV_MAPERR - address not mapped
}

void recursive_function(int depth) {
    char buffer[1024];  // Consume stack space
    printf("Recursion depth: %d\n", depth);
    if (depth < 10000) {
        recursive_function(depth + 1);
    }
}

void test_stack_overflow() {
    printf("Testing stack overflow...\n");
    recursive_function(0);  // Eventually causes stack overflow
}

void test_readonly_write() {
    printf("Testing write to read-only memory...\n");
    
    // Create read-only memory mapping
    void *addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap failed");
        return;
    }
    
    // Try to write to read-only memory
    *(int*)addr = 42;  // SEGV_ACCERR - access violation
}

void test_use_after_free() {
    printf("Testing use after free...\n");
    int *p = malloc(sizeof(int));
    *p = 42;
    printf("Allocated and set value: %d\n", *p);
    
    free(p);
    
    // Access freed memory (may or may not segfault depending on allocator)
    printf("Trying to access freed memory...\n");
    *p = 123;  // Undefined behavior, may cause segfault
}

void test_array_bounds() {
    printf("Testing array bounds violation...\n");
    int arr[10];
    
    // Access way beyond array bounds
    // This may or may not segfault depending on memory layout
    for (int i = 0; i < 1000000; i++) {
        arr[i] = i;  // Eventually hits unmapped memory
    }
}

void test_function_pointer() {
    printf("Testing invalid function pointer...\n");
    void (*func_ptr)() = (void(*)())0x12345678;  // Invalid function address
    func_ptr();  // SEGV_MAPERR - trying to execute unmapped memory
}

void test_string_operations() {
    printf("Testing string operation on invalid memory...\n");
    char *str = (char*)0x1000;  // Invalid address
    strcpy(str, "Hello World");  // SEGV_MAPERR - writing to unmapped memory
}

void nested_function_call() {
    printf("In nested function, about to segfault...\n");
    test_null_pointer();
}

void test_nested_segfault() {
    printf("Testing segfault in nested function call...\n");
    nested_function_call();
}

void print_usage(const char *program_name) {
    printf("Usage: %s <test_type>\n", program_name);
    printf("Available test types:\n");
    printf("  null      - Null pointer dereference (SEGV_MAPERR)\n");
    printf("  wild      - Wild pointer access (SEGV_MAPERR)\n");
    printf("  stack     - Stack overflow\n");
    printf("  readonly  - Write to read-only memory (SEGV_ACCERR)\n");
    printf("  freed     - Use after free (may not always segfault)\n");
    printf("  bounds    - Array bounds violation\n");
    printf("  funcptr   - Invalid function pointer call\n");
    printf("  string    - String operation on invalid memory\n");
    printf("  nested    - Segfault in nested function (for stack trace testing)\n");
    printf("\nExample usage with segfault_analyzer:\n");
    printf("  # Terminal 1: Start monitoring\n");
    printf("  sudo ./target/release/segfault_analyzer -t -r\n");
    printf("  \n");
    printf("  # Terminal 2: Trigger segfault\n");
    printf("  ./%s null\n", program_name);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *test_type = argv[1];
    
    printf("Segfault Test Program\n");
    printf("PID: %d\n", getpid());
    printf("Test type: %s\n", test_type);
    printf("Sleeping for 2 seconds to allow monitoring setup...\n");
    sleep(2);
    
    if (strcmp(test_type, "null") == 0) {
        test_null_pointer();
    } else if (strcmp(test_type, "wild") == 0) {
        test_wild_pointer();
    } else if (strcmp(test_type, "stack") == 0) {
        test_stack_overflow();
    } else if (strcmp(test_type, "readonly") == 0) {
        test_readonly_write();
    } else if (strcmp(test_type, "freed") == 0) {
        test_use_after_free();
    } else if (strcmp(test_type, "bounds") == 0) {
        test_array_bounds();
    } else if (strcmp(test_type, "funcptr") == 0) {
        test_function_pointer();
    } else if (strcmp(test_type, "string") == 0) {
        test_string_operations();
    } else if (strcmp(test_type, "nested") == 0) {
        test_nested_segfault();
    } else {
        printf("Unknown test type: %s\n", test_type);
        print_usage(argv[0]);
        return 1;
    }
    
    printf("Test completed (this should not be reached if segfault occurred)\n");
    return 0;
}