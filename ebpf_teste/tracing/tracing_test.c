#include <linux/bpf.h>

/* Definição manual da macro SEC */
#define SEC(name) __attribute__((section(name), used))

SEC("fentry/__x64_sys_clone")
int tracing_teste(unsigned long *ctx) {
    /* Retorna 0 indicando execução com sucesso */
    return 0;
}

char _license[] SEC("license") = "GPL";