#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))

/* 1. Controle de Dispositivos (/dev) */
SEC("cgroup/dev")
int test_cg_dev(void *ctx) {
    return 1; /* 1 = Allow */
}

/* 2. Criação de Sockets (Chamada socket()) */
SEC("cgroup/sock_create")
int test_cg_sock_create(void *ctx) {
    return 1;
}

/* 3. Operações em Sockets (Pós-criação) */
SEC("cgroup/sock")
int test_cg_sock(void *ctx) {
    return 1;
}

/* 4. Interceptação de Endereço IPv4 (Chamada bind()) */
SEC("cgroup/bind4")
int test_cg_bind(void *ctx) {
    return 1;
}

/* 5. Inspeção de Buffer de Tráfego (Firewall para pacotes) */
SEC("cgroup/skb")
int test_cg_skb(struct __sk_buff *skb) {
    return 1; /* 1 = PASS (Deixar o tráfego fluir) */
}

/* 6. Operações de Estado TCP (SYN, ESTABLISHED, etc.) */
SEC("cgroup/sock_ops")
int test_sock_ops(struct bpf_sock_ops *skops) {
    return 0; /* ATENÇÃO: Para SOCK_OPS, 0 significa Sucesso/Permitir */
}

char _license[] SEC("license") = "GPL";