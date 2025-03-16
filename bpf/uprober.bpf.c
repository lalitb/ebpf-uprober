#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Structure to store per-thread tracing context
struct trace_context {
    __u64 trace_id;
    __u64 span_id;
};

// BPF map to store trace context per process/thread
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct trace_context);
} context_map SEC(".maps");

struct span_info {
    __u64 trace_id;
    __u64 span_id;
    __u64 parent_span_id;
    __u64 start_time;
    __u64 end_time;
    __u64 method_id;
    char method_name[64];
};

struct start_data {
    __u64 trace_id;
    __u64 span_id;
    __u64 parent_span_id;
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
    __uint(max_entries, 1 << 16);
} span_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, char[64]);
} method_names SEC(".maps");

SEC("uprobe")
int uprobe_test_function(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 start_time = bpf_ktime_get_ns();
    u64 method_id = bpf_get_attach_cookie(ctx);

    bpf_printk("[UPROBE] Function called: method_id=%llu, pid_tgid=%llu", method_id, pid_tgid);

    struct trace_context *parent_ctx = bpf_map_lookup_elem(&context_map, &pid_tgid);
    struct trace_context new_ctx;

    struct start_key key = { .pid_tgid = pid_tgid, .method_id = method_id };
    struct start_data data = { .start_time = start_time, .method_id = method_id };

    if (parent_ctx) {
        // ✅ Inherit trace_id and correct parent_span_id from the existing context
        data.trace_id = parent_ctx->trace_id;
        data.parent_span_id = parent_ctx->span_id;
        new_ctx.trace_id = parent_ctx->trace_id;
    } else {
        // ✅ Root function (monitor_system) starts a new trace
        data.trace_id = ((__u64)bpf_get_prandom_u32()) << 32 | bpf_get_prandom_u32();
        data.parent_span_id = 0;
        new_ctx.trace_id = data.trace_id;
    }

    // ✅ Always assign a new span_id
    data.span_id = ((__u64)bpf_get_prandom_u32()) << 32 | bpf_get_prandom_u32();
    new_ctx.span_id = data.span_id;

    bpf_printk("[UPROBE] Created span: trace_id=%llu, span_id=%llu, parent_span_id=%llu",
               data.trace_id, data.span_id, data.parent_span_id);

    // ✅ Store execution context but preserve root function's trace context separately
    bpf_map_update_elem(&start_times, &key, &data, BPF_ANY);

    // ✅ Store in `context_map` only if it's a **root function** (monitor_system)
    if (data.parent_span_id == 0) {
        bpf_map_update_elem(&context_map, &pid_tgid, &new_ctx, BPF_ANY);
        bpf_printk("[UPROBE] Stored root function context: trace_id=%llu, span_id=%llu",
                   new_ctx.trace_id, new_ctx.span_id);
    }

    return 0;
}

SEC("uretprobe")
int uretprobe_test_function(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 end_time = bpf_ktime_get_ns();
    u64 method_id = bpf_get_attach_cookie(ctx);

    struct start_key key = { .pid_tgid = pid_tgid, .method_id = method_id };
    struct start_data *start_data_ptr = bpf_map_lookup_elem(&start_times, &key);
    if (!start_data_ptr) {
        return 0;
    }

    struct span_info *span = bpf_ringbuf_reserve(&span_events, sizeof(struct span_info), 0);
    if (!span) {
        return 0;
    }

    span->trace_id = start_data_ptr->trace_id;
    span->span_id = start_data_ptr->span_id;
    span->parent_span_id = start_data_ptr->parent_span_id;
    span->start_time = start_data_ptr->start_time;
    span->end_time = end_time;
    span->method_id = start_data_ptr->method_id;

    u32 method_id_32 = (u32)start_data_ptr->method_id;
    char (*name_ptr)[64] = bpf_map_lookup_elem(&method_names, &method_id_32);
    if (name_ptr) {
        bpf_probe_read_kernel(&span->method_name, sizeof(span->method_name), *name_ptr);
    }

    // ✅ Submit the span event
    bpf_ringbuf_submit(span, 0);

    // ✅ Only remove context if it's NOT monitor_system
    struct trace_context *current_ctx = bpf_map_lookup_elem(&context_map, &pid_tgid);
    if (current_ctx && current_ctx->span_id == start_data_ptr->span_id) {
        if (method_id != 4) { // 4 = monitor_system method_id
            bpf_map_delete_elem(&context_map, &pid_tgid);
        }
    }

    // ✅ Always delete from `start_times`
    bpf_map_delete_elem(&start_times, &key);

    return 0;
}

char _license[] SEC("license") = "GPL";