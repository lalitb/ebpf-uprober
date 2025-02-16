#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("uprobe/bash_readline")
int uprobe_readline(struct pt_regs *ctx) {
    bpf_printk("Uprobe hit: readline() in bash\n");
    return 0;
}

char _license[] SEC("license") = "GPL";