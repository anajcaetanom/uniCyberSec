#include <linux/bpf.h>

// não lembro se o robô tem bpf_helpers.h ou não

/* Definição manual para contornar a ausência do bpf_helpers.h */
#define SEC(name) __attribute__((section(name), used))

SEC("kprobe/__x64_sys_clone")
int kprobe_teste(void *ctx) {
    /* Retorna 0 indicando execução com sucesso sem alterar o fluxo */
    return 0;
}

char _license[] SEC("license") = "GPL";