#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;

    obj = bpf_object__open_file("raw_tp_test.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "Falha: Erro ao carregar o bytecode raw_tracepoint no kernel.\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "raw_tp_teste");
    if (!prog) {
        fprintf(stderr, "Falha: Programa raw_tp_teste não encontrado.\n");
        return 1;
    }

    link = bpf_program__attach_raw_tracepoint(prog, "sys_enter");
    if (!link || libbpf_get_error(link)) {
        fprintf(stderr, "Falha Crítica: O kernel recusou o attach do Raw Tracepoint.\n");
        return 1;
    }

    printf("Sucesso: Raw Tracepoint atrelado corretamente.\n");
    bpf_link__destroy(link);
    return 0;
}