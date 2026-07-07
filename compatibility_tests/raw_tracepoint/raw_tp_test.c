#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))

SEC("raw_tracepoint/sys_enter")
int raw_tp_teste(void *ctx) {
    return 0;
}

char _license[] SEC("license") = "GPL";