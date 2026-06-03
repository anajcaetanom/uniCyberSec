#include <linux/bpf.h>

/* Definição manual para contornar a ausência do bpf_helpers.h */
#define SEC(name) __attribute__((section(name), used))

SEC("kprobe/__x64_sys_clone")
int kprobe_teste(void *ctx) {
    /* Retorna 0 indicando execução com sucesso sem alterar o fluxo */
    return 0;
}

char _license[] SEC("license") = "GPL";