#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;

    /* 1. Carrega o objeto (Valida a syscall bpf e o Verificador) */
    obj = bpf_object__open_file("kprobe_test.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "Falha: O kernel rejeitou o carregamento do programa.\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "kprobe_teste");
    if (!prog) {
        fprintf(stderr, "Falha: Programa kprobe_teste nao encontrado no ELF.\n");
        return 1;
    }

    /* 2. Tenta realizar o acoplamento do kprobe (Valida o subsistema de tracing) */
    link = bpf_program__attach_kprobe(prog, false, "__x64_sys_clone");
    if (!link || libbpf_get_error(link)) {
        fprintf(stderr, "Falha Crítica: Kprobe nao suportado. O subsistema perf_event/tracefs esta inacessivel.\n");
        return 1;
    }

    printf("Sucesso: Kprobe atrelado corretamente.\n");
    bpf_link__destroy(link);
    return 0;
}