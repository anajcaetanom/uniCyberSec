#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))

SEC("tracepoint/syscalls/sys_enter_clone")
int tracepoint_teste(void *ctx) {
    /* Retorna 0 para não interferir no fluxo normal do kernel */
    return 0;
}

char _license[] SEC("license") = "GPL";