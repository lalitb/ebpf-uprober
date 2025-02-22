#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

SEC("uprobe/test_function")
int uprobe_test_function(struct pt_regs *ctx) {
    bpf_printk("Uprobe hit: test_function()\n");
    return 0;
}

SEC("uretprobe/test_function")
int uretprobe_test_function(struct pt_regs *ctx) {
    bpf_printk("Uretprobe hit: Returning from test_function()\n");
    return 0;
}

char _license[] SEC("license") = "GPL";