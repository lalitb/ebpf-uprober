#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

SEC("uprobe/test_function")
int uprobe_readline(struct pt_regs *ctx) {
    bpf_printk("Uprobe hit: test_function()\n");
    return 0;
}

char _license[] SEC("license") = "GPL";