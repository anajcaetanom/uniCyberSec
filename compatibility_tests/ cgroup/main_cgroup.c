#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Função auxiliar para tentar o attach de forma limpa */
void attach_and_check(int prog_fd, int cg_fd, enum bpf_attach_type type, const char *nome_teste) {
    if (bpf_prog_attach(prog_fd, cg_fd, type, 0) < 0) {
        fprintf(stderr, "[ FALHA ] %s rejeitado.\n", nome_teste);
    } else {
        printf("[  OK  ] %s atrelado com sucesso!\n", nome_teste);
        bpf_prog_detach(cg_fd, type); /* Limpeza imediata */
    }
}

int main() {
    struct bpf_object *obj;
    int cg_fd;

    /* 1. Abre o diretório do Cgroup v2 */
    cg_fd = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY);
    if (cg_fd < 0) {
        fprintf(stderr, "Falha: Cgroup v2 inacessível.\n");
        return 1;
    }

    /* 2. Carrega TODOS os programas de uma vez só no Kernel */
    obj = bpf_object__open_file("cgroup_test.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "Falha Crítica: Verificador rejeitou o arquivo unificado.\n");
        close(cg_fd);
        return 1;
    }
    printf("Arquivo cgroup_all.o carregado! Validando ganchos...\n\n");

    /* 3. Extrai os FDs (File Descriptors) de cada programa isoladamente */
    int fd_dev         = bpf_program__fd(bpf_object__find_program_by_name(obj, "test_cg_dev"));
    int fd_sock_create = bpf_program__fd(bpf_object__find_program_by_name(obj, "test_cg_sock_create"));
    int fd_sock        = bpf_program__fd(bpf_object__find_program_by_name(obj, "test_cg_sock"));
    int fd_bind        = bpf_program__fd(bpf_object__find_program_by_name(obj, "test_cg_bind"));
    int fd_skb         = bpf_program__fd(bpf_object__find_program_by_name(obj, "test_cg_skb"));
    int fd_sock_ops    = bpf_program__fd(bpf_object__find_program_by_name(obj, "test_sock_ops"));

    /* 4. Acopla cada FD ao seu evento respectivo no Cgroup */
    attach_and_check(fd_dev, cg_fd, BPF_CGROUP_DEVICE, "Cgroup Device");
    attach_and_check(fd_sock_create, cg_fd, BPF_CGROUP_INET_SOCK_CREATE, "Cgroup Sock Create");
    attach_and_check(fd_sock, cg_fd, BPF_CGROUP_INET_SOCK_RELEASE, "Cgroup Sock Release");
    attach_and_check(fd_bind, cg_fd, BPF_CGROUP_INET4_BIND, "Cgroup Bind IPv4");
    
    /* O mesmo programa SKB é testado tanto na entrada quanto na saída da rede */
    attach_and_check(fd_skb, cg_fd, BPF_CGROUP_INET_INGRESS, "Cgroup SKB (Ingress/Entrada)");
    attach_and_check(fd_skb, cg_fd, BPF_CGROUP_INET_EGRESS, "Cgroup SKB (Egress/Saída)");
    
    attach_and_check(fd_sock_ops, cg_fd, BPF_CGROUP_SOCK_OPS, "Cgroup Sock Ops (TCP State)");

    close(cg_fd);
    return 0;
}