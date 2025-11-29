# Makefile for segfault test examples

CC = gcc
#CFLAGS = -g -O0 -Wall -Wextra -no-pie
CFLAGS = -g -O0 -Wall -Wextra
STACK_PROTECTOR_FLAGS = -fstack-protector-strong

TARGET = segfault_examples
SOURCE = segfault_examples.c

STACK_SMASHING_TARGET = test_stack_smashing
STACK_SMASHING_SOURCE = test_stack_smashing.c

.PHONY: all clean test help

all: $(TARGET) $(STACK_SMASHING_TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

$(STACK_SMASHING_TARGET): $(STACK_SMASHING_SOURCE)
	$(CC) $(CFLAGS) $(STACK_PROTECTOR_FLAGS) -o $(STACK_SMASHING_TARGET) $(STACK_SMASHING_SOURCE)

clean:
	rm -f $(TARGET) $(STACK_SMASHING_TARGET)

test: $(TARGET) $(STACK_SMASHING_TARGET)
	@echo "Building test programs..."
	@echo "Test programs built successfully!"
	@echo ""
	@echo "To test the segfault analyzer:"
	@echo "1. In one terminal, start the analyzer:"
	@echo "   sudo ../target/release/segfault_analyzer -t -r"
	@echo ""
	@echo "2. In another terminal, run a test:"
	@echo "   ./$(TARGET) null              # Test segmentation fault"
	@echo "   ./$(STACK_SMASHING_TARGET)    # Test stack smashing (SIGABRT)"
	@echo ""
	@echo "Available segfault test types:"
	@./$(TARGET) 2>&1 | grep -A 20 "Available test types:" || true

help:
	@echo "Segfault Test Examples Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build all test programs (default)"
	@echo "  clean   - Remove built files"
	@echo "  test    - Build and show usage instructions"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Test Programs:"
	@echo "  $(TARGET)              - Various segfault test cases"
	@echo "  $(STACK_SMASHING_TARGET) - Stack smashing detection test (SIGABRT)"
	@echo ""
	@echo "Usage:"
	@echo "  make          # Build all test programs"
	@echo "  make test     # Build and show test instructions"
	@echo "  make clean    # Clean up"
