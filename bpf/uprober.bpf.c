#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

// Define the span information structure
struct span_info {
    __u64 start_time;
    __u64 end_time;
    //char function_name[64];  // Adding space for function name
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); // 64 KB buffer
} span_events SEC(".maps");

SEC("uprobe/test_function")
int uprobe_test_function(struct pt_regs *ctx) {
    struct span_info *span;
    
    // Reserve space in the ring buffer
    span = bpf_ringbuf_reserve(&span_events, sizeof(struct span_info), 0);
    if (!span) {
        return 0; // Drop if ring buffer is full
    }

    __builtin_memset(span, 0, sizeof(struct span_info));

    span->start_time = bpf_ktime_get_ns();
   // if (bpf_probe_read_kernel_str(span->function_name, sizeof(span->function_name), "test_function") < 0) {
    //    bpf_ringbuf_discard(span, 0);  // Discard if copy fails
   //     return 0;
   // }
    // Submit the event
    bpf_ringbuf_submit(span, 0);

    //bpf_printk("Uprobe: %s started at %llu\n", span->function_name, span->start_time);
    return 0;
}

SEC("uretprobe/test_function")
int uretprobe_test_function(struct pt_regs *ctx) {
    struct span_info *span;

    // Reserve space in the ring buffer
    span = bpf_ringbuf_reserve(&span_events, sizeof(struct span_info), 0);
    if (!span) {
        return 0; // Drop if ring buffer is full
    }

    span->end_time = bpf_ktime_get_ns();
    //bpf_probe_read_kernel_str(span->function_name, sizeof(span->function_name), "test_function");

    //bpf_printk("Uretprobe: %s ended at %llu\n", span->function_name, span->end_time);

    // Submit the event
    bpf_ringbuf_submit(span, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";