#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;

    /* 1. Validação da Syscall e do Verificador (Carregamento) */
    obj = bpf_object__open_file("tracepoint_test.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "Falha: O kernel rejeitou o carregamento do bytecode.\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "tracepoint_teste");
    if (!prog) {
        fprintf(stderr, "Falha: Programa não encontrado no objeto compilado.\n");
        return 1;
    }

    /* 2. Validação do Subsistema de Tracepoints (Acoplamento) */
    link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_clone");
    if (!link || libbpf_get_error(link)) {
        fprintf(stderr, "Falha Crítica: Tracepoint inacessível. O subsistema não expõe os eventos.\n");
        return 1;
    }

    printf("Sucesso: Tracepoint atrelado corretamente.\n");
    bpf_link__destroy(link);
    return 0;
}