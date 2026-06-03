#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;

    /* 1. OPEN */
    obj = bpf_object__open_file("tracing_test.o", NULL);
    if (!obj) {
        fprintf(stderr, "Falha: Erro ao abrir o arquivo tracing_test.o.\n");
        return 1;
    }

    /* 2. LOAD */
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Falha Crítica: O kernel rejeitou o carregamento do programa TRACING. Possível ausência de BTF no kernel (vmlinux).\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "tracing_teste");
    if (!prog) {
        fprintf(stderr, "Falha: Programa tracing_teste não encontrado.\n");
        return 1;
    }

    /* 3. ATTACH */
    link = bpf_program__attach_trace(prog);
    if (!link || libbpf_get_error(link)) {
        fprintf(stderr, "Falha: Não foi possível realizar o attach do tipo fentry.\n");
        return 1;
    }

    printf("Sucesso: Programa TRACING atrelado corretamente.\n");
    bpf_link__destroy(link);
    return 0;
}