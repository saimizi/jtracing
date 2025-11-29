// Test program to trigger stack smashing detection
// Compile with: gcc -fstack-protector-strong test_stack_smashing.c -o test_stack_smashing

#include <string.h>
#include <stdio.h>

void vulnerable_function(const char *input) {
    char buffer[16];
    // This will overflow the buffer and corrupt the stack canary
    strcpy(buffer, input);
    printf("Buffer content: %s\n", buffer);
}

int main() {
    printf("Testing stack smashing detection...\n");
    
    // Create a string longer than the buffer to trigger overflow
    char large_input[100];
    memset(large_input, 'A', sizeof(large_input) - 1);
    large_input[sizeof(large_input) - 1] = '\0';
    
    printf("Calling vulnerable_function with %zu byte input...\n", strlen(large_input));
    vulnerable_function(large_input);
    
    printf("This line should not be reached\n");
    return 0;
}
