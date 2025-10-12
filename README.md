# jtracing

This repository contains a collection of eBPF-based tracing utilities for Linux, written in Rust. It is inspired by the tools from [bcc](https://github.com/iovisor/bcc).

## Description

`jtracing` provides a suite of command-line tools to trace and analyze various system and application events, such as file opens, process executions, function calls, and more. It leverages the power of eBPF (extended Berkeley Packet Filter) to safely and efficiently collect this data from the Linux kernel.

## Available Tools

The following tracing tools are included:

*   **`opensnoop`**: Trace `open()` syscalls.
*   **`execsnoop`**: Trace `exec()` syscalls, showing process executions. Two versions are provided (`execsnoop_pb` using perf buffer and `execsnoop_rb` using a ring buffer).
*   **`funccount`**: Count calls to specified kernel or user-space functions.
*   **`eglswapbuffers`**: Trace `eglSwapBuffers` calls, useful for graphics performance analysis.
*   **`profile`**: A simple CPU profiler.
*   **`bash_readline`**: Trace commands executed in `bash`.
*   **`malloc_free`**: Trace `malloc()` and `free()` calls to debug memory usage.
*   **`packet_count`**: Count network packets on a specified interface.
*   **`segfault_analyzer`**: Monitor and analyze segmentation faults with detailed fault information, stack traces, and register states.

## Prerequisites

*   Rust (latest stable version recommended)
*   `libbpf` and its dependencies (`libelf`, `zlib`). The project is configured to build `libbpf` from source via a git submodule.
*   Linux kernel with eBPF support.

## Building

To build all the tracing tools, you can use Cargo:

```bash
cargo build --release
```

The compiled binaries will be located in the `target/release/` directory.

## Usage

Each tool is a standalone executable. You typically need to run them with `sudo` to grant the necessary eBPF permissions.

For example, to trace file open calls:

```bash
sudo ./target/release/opensnoop
```

Each tool may have its own set of command-line arguments. Use the `--help` flag to see the available options for a specific tool.

```bash
./target/release/opensnoop --help
```

## License

This project is licensed under the GPL-2.0 License. See the [LICENSE](LICENSE) file for details.
