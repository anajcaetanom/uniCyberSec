#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))

SEC("fentry/__x64_sys_clone")
int tracing_teste(unsigned long *ctx) {
    return 0;
}

char _license[] SEC("license") = "GPL";