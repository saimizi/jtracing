// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2024 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 128
#endif

// Segfault signal number
#define SIGSEGV 11

// si_code values for SIGSEGV
#define SEGV_MAPERR 1  // Address not mapped to object
#define SEGV_ACCERR 2  // Invalid permissions for mapped object

// Max path length for VMA file path
#ifndef VMA_PATH_MAX
#define VMA_PATH_MAX 256
#endif

// Structure to store segfault event data
struct segfault_event {
    // Process information
    u32 pid;
    u32 tid;
    char comm[TASK_COMM_LEN];
    u64 timestamp_ns;

    // Fault information
    u64 fault_addr;        // Address that caused the fault
    u64 instruction_ptr;   // RIP/PC at time of fault
    u32 fault_code;        // si_code from siginfo (SEGV_MAPERR, SEGV_ACCERR)

    // Register state (architecture-specific)
    u64 registers[16];     // Key CPU registers
    u32 register_count;    // Number of valid registers

    // Stack trace
    u64 stack_trace[PERF_MAX_STACK_DEPTH];
    s32 stack_size;        // Number of stack frames captured

    // Memory mapping context for instruction pointer
    u64 vma_start;         // Start of VMA containing instruction pointer
    u64 vma_end;           // End of VMA containing instruction pointer
    u32 vma_flags;         // VMA protection flags
    char vma_path[VMA_PATH_MAX]; // File path of the VMA (executable/library)
};

// Global variables for type export to userspace
struct segfault_event _segfault_event = {};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Configuration variables set from userspace
u32 max_stack_depth = 16;
int target_pid = 0;

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} events SEC(".maps");

// Statistics tracking
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 12); // Increased from 10 to 12 for VMA stats
    __type(key, u32);
    __type(value, u64);
} stats SEC(".maps");

// Temporary storage for fault information
struct segfault_fault_info {
    u64 fault_addr;
    u64 instruction_ptr;
    u32 pid;
    u64 timestamp_ns;
    // Register state (architecture-specific)
    u64 registers[16];
    u32 register_count;
    // Stack trace
    u64 stack_trace[PERF_MAX_STACK_DEPTH];
    s32 stack_size;
    // VMA information for instruction pointer
    u64 vma_start;
    u64 vma_end;
    u32 vma_flags;
    char vma_path[VMA_PATH_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32); // PID
    __type(value, struct segfault_fault_info);
} fault_info_map SEC(".maps");

// Per-CPU array to store fault_info temporarily (avoid stack overflow)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct segfault_fault_info);
} fault_info_heap SEC(".maps");

// Statistics indices
#define STAT_SEGFAULTS_TOTAL 0
#define STAT_SEGFAULTS_FILTERED 1
#define STAT_EVENTS_SUBMITTED 2
#define STAT_EVENTS_DROPPED 3
#define STAT_REGISTER_FAILURES 4
#define STAT_STACK_FAILURES 5
#define STAT_FAULT_INFO_CAPTURED 6
#define STAT_FAULT_INFO_MISSED 7
#define STAT_VMA_CAPTURED 8
#define STAT_VMA_FAILURES 9

static void increment_stat(u32 stat_key)
{
    u64 *count = bpf_map_lookup_elem(&stats, &stat_key);
    if (count)
        __sync_fetch_and_add(count, 1);
}

// Helper function to capture register state from pt_regs
static u32 capture_registers(struct pt_regs *ctx, u64 *registers)
{
    u32 count = 0;
    
    if (!ctx || !registers) {
        return 0;
    }
    
    // Architecture-specific register capture with safe access
    #ifdef __TARGET_ARCH_x86
    // x86_64 registers - use BPF helper macros for safe access
    if (count < 16) {
        u64 reg_val = PT_REGS_IP(ctx);
        registers[count++] = reg_val;  // RIP
    }
    if (count < 16) {
        u64 reg_val = PT_REGS_SP(ctx);
        registers[count++] = reg_val;  // RSP
    }
    if (count < 16) {
        u64 reg_val = PT_REGS_FP(ctx);
        registers[count++] = reg_val;  // RBP
    }
    if (count < 16) {
        u64 reg_val = PT_REGS_RC(ctx);
        registers[count++] = reg_val;  // RAX
    }
    // Use bpf_probe_read_kernel for other registers to ensure safety
    if (count < 16) {
        u64 reg_val = 0;
        bpf_probe_read_kernel(&reg_val, sizeof(reg_val), &ctx->bx);
        registers[count++] = reg_val;  // RBX
    }
    if (count < 16) {
        u64 reg_val = 0;
        bpf_probe_read_kernel(&reg_val, sizeof(reg_val), &ctx->cx);
        registers[count++] = reg_val;  // RCX
    }
    if (count < 16) {
        u64 reg_val = 0;
        bpf_probe_read_kernel(&reg_val, sizeof(reg_val), &ctx->dx);
        registers[count++] = reg_val;  // RDX
    }
    if (count < 16) {
        u64 reg_val = 0;
        bpf_probe_read_kernel(&reg_val, sizeof(reg_val), &ctx->si);
        registers[count++] = reg_val;  // RSI
    }
    if (count < 16) {
        u64 reg_val = 0;
        bpf_probe_read_kernel(&reg_val, sizeof(reg_val), &ctx->di);
        registers[count++] = reg_val;  // RDI
    }
    if (count < 16) {
        u64 reg_val = 0;
        bpf_probe_read_kernel(&reg_val, sizeof(reg_val), &ctx->r8);
        registers[count++] = reg_val;  // R8
    }
    if (count < 16) {
        u64 reg_val = 0;
        bpf_probe_read_kernel(&reg_val, sizeof(reg_val), &ctx->r9);
        registers[count++] = reg_val;  // R9
    }
    if (count < 16) {
        u64 reg_val = 0;
        bpf_probe_read_kernel(&reg_val, sizeof(reg_val), &ctx->r10);
        registers[count++] = reg_val;  // R10
    }
    if (count < 16) {
        u64 reg_val = 0;
        bpf_probe_read_kernel(&reg_val, sizeof(reg_val), &ctx->r11);
        registers[count++] = reg_val;  // R11
    }
    if (count < 16) {
        u64 reg_val = 0;
        bpf_probe_read_kernel(&reg_val, sizeof(reg_val), &ctx->r12);
        registers[count++] = reg_val;  // R12
    }
    if (count < 16) {
        u64 reg_val = 0;
        bpf_probe_read_kernel(&reg_val, sizeof(reg_val), &ctx->r13);
        registers[count++] = reg_val;  // R13
    }
    if (count < 16) {
        u64 reg_val = 0;
        bpf_probe_read_kernel(&reg_val, sizeof(reg_val), &ctx->r14);
        registers[count++] = reg_val;  // R14
    }
    #endif
    
    #ifdef __TARGET_ARCH_arm64
    // ARM64 registers - use safe access methods
    if (count < 16) {
        u64 reg_val = PT_REGS_IP(ctx);
        registers[count++] = reg_val;  // PC
    }
    if (count < 16) {
        u64 reg_val = PT_REGS_SP(ctx);
        registers[count++] = reg_val;  // SP
    }
    if (count < 16) {
        u64 reg_val = PT_REGS_FP(ctx);
        registers[count++] = reg_val;  // X29 (FP)
    }
    // Use bpf_probe_read_kernel for array access
    for (int i = 0; i < 13 && count < 16; i++) {
        u64 reg_val = 0;
        int reg_idx = (i == 0) ? 30 : (i - 1); // X30 (LR), then X0-X11
        bpf_probe_read_kernel(&reg_val, sizeof(reg_val), &ctx->regs[reg_idx]);
        registers[count++] = reg_val;
    }
    #endif
    
    return count;
}

// Helper function to capture user stack trace
static s32 capture_stack_trace(void *ctx, u64 *stack_trace, u32 max_depth)
{
    if (!ctx || !stack_trace || max_depth == 0) {
        return 0;
    }

    // Limit max_depth to prevent excessive overhead
    if (max_depth > PERF_MAX_STACK_DEPTH) {
        max_depth = PERF_MAX_STACK_DEPTH;
    }

    // Capture user-space stack trace
    s32 stack_size = bpf_get_stack(ctx, stack_trace, max_depth * sizeof(u64), BPF_F_USER_STACK);

    if (stack_size < 0) {
        // Stack capture failed
        return 0;
    }

    // Convert byte size to number of stack frames
    return stack_size / sizeof(u64);
}

// Callback data structure for bpf_find_vma
struct vma_callback_data {
    u64 vma_start;
    u64 vma_end;
    u32 vma_flags;
    char vma_path[VMA_PATH_MAX];
    int found;
};

// Per-CPU map to store VMA callback results (workaround for read-only callback context)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct vma_callback_data);
} vma_callback_data_heap SEC(".maps");

// Callback function for bpf_find_vma
// Signature: long (*callback_fn)(struct task_struct *task, struct vm_area_struct *vma, void *callback_ctx)
static long vma_callback(struct task_struct *task, struct vm_area_struct *vma, void *data)
{
    u32 zero = 0;
    struct vma_callback_data *cb_data;

    // Suppress unused parameter warning
    (void)task;
    (void)data;

    if (!vma) {
        return 1; // Stop iteration on error
    }

    // Get callback data from per-CPU map (allows write access)
    cb_data = bpf_map_lookup_elem(&vma_callback_data_heap, &zero);
    if (!cb_data) {
        return 1; // Stop iteration on error
    }

    // Store VMA information - use direct field access (vma is trusted pointer from bpf_find_vma)
    cb_data->vma_start = vma->vm_start;
    cb_data->vma_end = vma->vm_end;
    cb_data->vma_flags = vma->vm_flags;

    // Try to read the file path if this VMA is file-backed
    // We need to use bpf_probe_read_kernel for pointer chain access
    struct file *vm_file;
    bpf_probe_read_kernel(&vm_file, sizeof(vm_file), &vma->vm_file);
    if (vm_file) {
        struct dentry *dentry;
        bpf_probe_read_kernel(&dentry, sizeof(dentry), &vm_file->f_path.dentry);
        if (dentry) {
            struct qstr d_name;
            bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);
            if (d_name.name) {
                bpf_probe_read_kernel_str(cb_data->vma_path, VMA_PATH_MAX, d_name.name);
            }
        }
    }

    cb_data->found = 1;
    return 1; // Return 1 to stop iteration after finding VMA
}

// Helper function to capture VMA information for a given address
// Returns 0 on success, -1 on failure
static int capture_vma_info(u64 addr, u64 *vma_start, u64 *vma_end, u32 *vma_flags, char *vma_path, u32 path_len)
{
    struct task_struct *task;
    struct vma_callback_data *cb_data;
    u32 zero = 0;
    int ret;

    if (!vma_start || !vma_end || !vma_flags || !vma_path || path_len == 0) {
        return -1;
    }

    // Initialize output values
    *vma_start = 0;
    *vma_end = 0;
    *vma_flags = 0;
    for (u32 i = 0; i < path_len && i < VMA_PATH_MAX; i++) {
        vma_path[i] = 0;
    }

    // Get callback data storage from per-CPU map
    cb_data = bpf_map_lookup_elem(&vma_callback_data_heap, &zero);
    if (!cb_data) {
        return -1;
    }

    // Initialize callback data
    cb_data->found = 0;
    cb_data->vma_start = 0;
    cb_data->vma_end = 0;
    cb_data->vma_flags = 0;
    for (u32 i = 0; i < VMA_PATH_MAX; i++) {
        cb_data->vma_path[i] = 0;
    }

    // Get current task with BTF (required for bpf_find_vma)
    task = bpf_get_current_task_btf();
    if (!task) {
        return -1;
    }

    // Use bpf_find_vma to find the VMA containing the address (kernel 5.17+)
    // Pass NULL as callback data since we use the per-CPU map instead
    ret = bpf_find_vma(task, addr, vma_callback, NULL, 0);

    // Retrieve results from callback data
    cb_data = bpf_map_lookup_elem(&vma_callback_data_heap, &zero);
    if (!cb_data) {
        return -1;
    }

    if (ret == 0 && cb_data->found) {
        *vma_start = cb_data->vma_start;
        *vma_end = cb_data->vma_end;
        *vma_flags = cb_data->vma_flags;

        // Copy the path
        for (u32 i = 0; i < VMA_PATH_MAX; i++) {
            vma_path[i] = cb_data->vma_path[i];
            if (cb_data->vma_path[i] == 0) {
                break;
            }
        }

        return 0;
    }

    return -1;
}

// Kprobe to capture fault information from force_sig_fault
SEC("kprobe/force_sig_fault")
int kprobe_force_sig_fault(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    
    // Apply PID filter if specified
    if (target_pid > 0 && target_pid != pid) {
        return 0;
    }
    
    // Extract arguments from force_sig_fault function
    // force_sig_fault(int sig, int code, void __user *addr)
    int sig = (int)PT_REGS_PARM1(ctx);
    int code = (int)PT_REGS_PARM2(ctx);
    void *addr = (void *)PT_REGS_PARM3(ctx);
    
    // Only process SIGSEGV
    if (sig != SIGSEGV) {
        return 0;
    }
    
    // Use per-CPU array to avoid stack overflow
    u32 zero = 0;
    struct segfault_fault_info *info = bpf_map_lookup_elem(&fault_info_heap, &zero);
    if (!info) {
        return 0;
    }
    
    // Initialize fault_info structure manually (BPF doesn't support {} initialization)
    info->fault_addr = (u64)addr;
    info->instruction_ptr = 0; // Will be set from stack trace
    info->pid = pid;
    info->timestamp_ns = bpf_ktime_get_ns();
    info->register_count = 0;
    info->stack_size = 0;
    info->vma_start = 0;
    info->vma_end = 0;
    info->vma_flags = 0;

    // Initialize vma_path
    for (int i = 0; i < VMA_PATH_MAX; i++) {
        info->vma_path[i] = 0;
    }

    // Capture register state
    info->register_count = capture_registers(ctx, info->registers);
    if (info->register_count == 0) {
        increment_stat(STAT_REGISTER_FAILURES);
    }

    // Capture stack trace first
    info->stack_size = capture_stack_trace(ctx, info->stack_trace, max_stack_depth);
    if (info->stack_size == 0) {
        increment_stat(STAT_STACK_FAILURES);
    }

    // Use the first stack frame as the instruction pointer (most accurate for userspace)
    if (info->stack_size > 0) {
        info->instruction_ptr = info->stack_trace[0];
    }

    // Capture VMA information for the instruction pointer
    if (info->instruction_ptr != 0) {
        if (capture_vma_info(info->instruction_ptr, &info->vma_start, &info->vma_end,
                             &info->vma_flags, info->vma_path, VMA_PATH_MAX) == 0) {
            increment_stat(STAT_VMA_CAPTURED);
        } else {
            increment_stat(STAT_VMA_FAILURES);
        }
    } else {
        increment_stat(STAT_VMA_FAILURES);
    }

    bpf_map_update_elem(&fault_info_map, &pid, info, BPF_ANY);

    return 0;
}

// Tracepoint to capture signal delivery
SEC("tp/signal/signal_deliver")
int trace_signal_deliver(struct trace_event_raw_signal_deliver *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;
    
    // Only process SIGSEGV signals
    if (ctx->sig != SIGSEGV) {
        return 0;
    }
    
    increment_stat(STAT_SEGFAULTS_TOTAL);
    
    // Apply PID filter if specified
    if (target_pid > 0 && target_pid != pid) {
        increment_stat(STAT_SEGFAULTS_FILTERED);
        return 0;
    }
    
    // Reserve space in ring buffer
    struct segfault_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        increment_stat(STAT_EVENTS_DROPPED);
        return 0;
    }
    
    // Initialize event structure (manual initialization for BPF compatibility)
    event->pid = 0;
    event->tid = 0;
    event->timestamp_ns = 0;
    event->fault_addr = 0;
    event->instruction_ptr = 0;
    event->fault_code = 0;
    event->register_count = 0;
    event->stack_size = 0;
    event->vma_start = 0;
    event->vma_end = 0;
    event->vma_flags = 0;

    // Initialize comm array
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        event->comm[i] = 0;
    }

    // Initialize vma_path
    for (int i = 0; i < VMA_PATH_MAX; i++) {
        event->vma_path[i] = 0;
    }
    
    // Fill basic process information
    event->pid = pid;
    event->tid = tid;
    event->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Extract fault information from signal_deliver tracepoint
    event->fault_code = ctx->code; // si_code from siginfo (SEGV_MAPERR, SEGV_ACCERR, etc.)
    
    // Try to get fault address and instruction pointer from stored fault info
    struct segfault_fault_info *fault_info = bpf_map_lookup_elem(&fault_info_map, &pid);
    if (fault_info) {
        // Check if this fault info is recent (within 1 second)
        u64 time_diff = event->timestamp_ns - fault_info->timestamp_ns;
        if (time_diff < 1000000000ULL) { // 1 second in nanoseconds
            event->fault_addr = fault_info->fault_addr;
            event->instruction_ptr = fault_info->instruction_ptr;

            // Copy register state
            event->register_count = fault_info->register_count;
            for (int i = 0; i < 16 && i < fault_info->register_count; i++) {
                event->registers[i] = fault_info->registers[i];
            }

            // Copy stack trace
            event->stack_size = fault_info->stack_size;
            for (int i = 0; i < PERF_MAX_STACK_DEPTH && i < fault_info->stack_size; i++) {
                event->stack_trace[i] = fault_info->stack_trace[i];
            }

            // Copy VMA information
            event->vma_start = fault_info->vma_start;
            event->vma_end = fault_info->vma_end;
            event->vma_flags = fault_info->vma_flags;
            for (int i = 0; i < VMA_PATH_MAX; i++) {
                event->vma_path[i] = fault_info->vma_path[i];
            }

            increment_stat(STAT_FAULT_INFO_CAPTURED);
        } else {
            increment_stat(STAT_FAULT_INFO_MISSED);
        }

        // Clean up the fault info entry
        bpf_map_delete_elem(&fault_info_map, &pid);
    } else {
        increment_stat(STAT_FAULT_INFO_MISSED);
    }
    
    // Stack trace and VMA info are now captured and copied above

    // Submit event to userspace
    bpf_ringbuf_submit(event, 0);
    increment_stat(STAT_EVENTS_SUBMITTED);
    
    return 0;
}