#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

// Define the span information structure
struct span_info {
    __u64 start_time;
    __u64 end_time;
    __u64 method_id;
    char method_name[64];
};


// Structure to store start time and method information
struct start_data {
    __u64 start_time;
    __u64 method_id;
};

struct start_key {
    __u64 pid_tgid;
    __u64 method_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct start_key);
    __type(value, struct start_data);
} start_times SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16); // 64 KB buffer
} span_events SEC(".maps");

// Map to store method names (populated from userspace)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);  // Support up to 256 different methods
    __type(key, u32);
    __type(value, char[64]);  // 64 bytes for method name
} method_names SEC(".maps");

SEC("uprobe")
int uprobe_test_function(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 start_time = bpf_ktime_get_ns();

    // Get the cookie value (set by userspace when attaching)
    u64 method_id = bpf_get_attach_cookie(ctx);

    // Store the start time and method ID in the hash map
    struct start_data data = {
        .start_time = start_time,
        .method_id = method_id
    };
    struct start_key key = { 
        .pid_tgid = pid_tgid, 
        .method_id = method_id 
    };

    bpf_map_update_elem(&start_times, &key, &data, BPF_ANY);
    bpf_printk("Uprobe: method_id=%llu, pid_tgid=%llu started at %llu\n", 
               method_id, pid_tgid, start_time);    return 0;
}

SEC("uretprobe")
int uretprobe_test_function(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 end_time = bpf_ktime_get_ns();
    u64 method_id = bpf_get_attach_cookie(ctx);


    // Look up the start time
    struct start_key key = { .pid_tgid = pid_tgid, .method_id = method_id };
    struct start_data *start_data_ptr = bpf_map_lookup_elem(&start_times, &key);
    if (!start_data_ptr) {
        return 0; // No start time found
    }
    // Create a complete span event
    struct span_info *span = bpf_ringbuf_reserve(&span_events, sizeof(struct span_info), 0);
    if (!span) {
        return 0; // Drop if ring buffer is full
    }

    span->start_time = start_data_ptr->start_time;
    span->end_time = end_time;
    span->method_id = start_data_ptr->method_id;

    // Look up the method name from the method ID
    u32 method_id_32 = (u32)start_data_ptr->method_id;
    char (*name_ptr)[64] = bpf_map_lookup_elem(&method_names, &method_id_32);
    if (name_ptr) {
        // Copy the method name into the span info
        bpf_probe_read_kernel(&span->method_name, sizeof(span->method_name), *name_ptr);
    } else {
        // Default name if not found
        char default_name[8] = "unknown";
        bpf_probe_read_kernel(&span->method_name, sizeof(default_name), default_name);
    }
    
    // Submit the complete event
    bpf_ringbuf_submit(span, 0);
    
    // Remove the start time from the hash map
    bpf_map_delete_elem(&start_times, &key);
    
    return 0;
}

char _license[] SEC("license") = "GPL";