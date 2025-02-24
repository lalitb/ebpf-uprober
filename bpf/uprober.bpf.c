#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

s// Define the span information structure
struct span_info {
    __u64 start_time;
    __u64 end_time;
    char function_name[64];  // Adding space for function name
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);          // pid_tid as key
    __type(value, struct span_info);
} span_map SEC(".maps");


SEC("uprobe/test_function")
int uprobe_test_function(struct pt_regs *ctx) {
    bpf_printk("Uprobe hit: test_function()\n");
    __u64 pid_tid = bpf_get_current_pid_tgid();
    struct span_info span = {};
    span.start_time = bpf_ktime_get_ns();
    bpf_probe_read_kernel_str(span.function_name, sizeof(span.function_name), "test_function");

    bpf_map_update_elem(&span_map, &pid_tid, &span, BPF_ANY);

    bpf_printk("Uprobe hit: %s started at %llu\n", 
        span.function_name, 
        span.start_time);
    return 0;
}

SEC("uretprobe/test_function")
int uretprobe_test_function(struct pt_regs *ctx) {
    __u64 pid_tid = bpf_get_current_pid_tgid();
    struct span_info *span;
    span = bpf_map_lookup_elem(&span_map, &pid_tid);
    if (span) {
        span->end_time = bpf_ktime_get_ns();
        bpf_printk("Uretprobe hit: %s ended at %llu\n", 
            span->function_name, 
            span->end_time,
            span->end_time - span->start_time);
        bpf_map_delete_elem(&span_map, &pid_tid);
    }

    bpf_printk("Uretprobe hit: Returning from test_function()\n");
    return 0;
}

char _license[] SEC("license") = "GPL";