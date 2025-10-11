# Makefile for segfault test examples

CC = gcc
#CFLAGS = -g -O0 -Wall -Wextra -no-pie
CFLAGS = -g -O0 -Wall -Wextra
TARGET = segfault_examples
SOURCE = segfault_examples.c

.PHONY: all clean test help

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

test: $(TARGET)
	@echo "Building test program..."
	@echo "Test program built successfully!"
	@echo ""
	@echo "To test the segfault analyzer:"
	@echo "1. In one terminal, start the analyzer:"
	@echo "   sudo ../target/release/segfault_analyzer -t -r"
	@echo ""
	@echo "2. In another terminal, run a test:"
	@echo "   ./$(TARGET) null"
	@echo ""
	@echo "Available test types:"
	@./$(TARGET) 2>&1 | grep -A 20 "Available test types:" || true

help:
	@echo "Segfault Test Examples Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all     - Build the test program (default)"
	@echo "  clean   - Remove built files"
	@echo "  test    - Build and show usage instructions"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make          # Build test program"
	@echo "  make test     # Build and show test instructions"
	@echo "  make clean    # Clean up"
