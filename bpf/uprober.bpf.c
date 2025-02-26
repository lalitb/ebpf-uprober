#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

// Define the span information structure
struct span_info {
    __u64 start_time;
    __u64 end_time;
    //char function_name[64];  // Adding space for function name
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} start_times SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); // 64 KB buffer
} span_events SEC(".maps");

SEC("uprobe/test_function")
int uprobe_test_function(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 start_time = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_times, &pid_tgid, &start_time, BPF_ANY);
    bpf_printk("Uprobe: %llu started at %llu\n", pid_tgid, start_time);
    return 0;
}

SEC("uretprobe/test_function")
int uretprobe_test_function(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 end_time = bpf_ktime_get_ns();
    // Look up the start time
    u64 *start_time_ptr = bpf_map_lookup_elem(&start_times, &pid_tgid);
    if (!start_time_ptr) {
        return 0; // No start time found
    }
    // Create a complete span event
    struct span_info *span = bpf_ringbuf_reserve(&span_events, sizeof(struct span_info), 0);
    if (!span) {
        return 0; // Drop if ring buffer is full
    }

    span->start_time = *start_time_ptr;
    span->end_time = end_time;
    
    // Submit the complete event
    bpf_ringbuf_submit(span, 0);
    
    // Remove the start time from the hash map
    bpf_map_delete_elem(&start_times, &pid_tgid);
    
    return 0;
}

char _license[] SEC("license") = "GPL";