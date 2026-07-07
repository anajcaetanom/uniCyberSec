#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Estrutura que servirá como Chave do nosso mapa */
struct ip_pair {
    __u32 src_ip;
    __u32 dst_ip;
};

/* Estrutura que servirá como Valor do nosso mapa */
struct traffic_stat {
    __u64 packets;
    __u64 bytes;
};

/* Mapa Hash para armazenar estatísticas dinâmicas de várias conexões */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ip_pair);
    __type(value, struct traffic_stat);
    __uint(max_entries, 1024); // Rastreia até 1024 pares de IP simultâneos
} ip_traffic_stats SEC(".maps");

SEC("socket")
int count_socket_traffic(struct __sk_buff *skb) {
    struct ethhdr eth;
    struct iphdr ip;

    // 1. Lê o cabeçalho Ethernet de forma segura a partir do sk_buff
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
        // Retornar skb->len permite que o pacote passe para a aplicação normalmente
        return skb->len; 
    }

    // Só estamos interessados em pacotes IPv4
    if (eth.h_proto != bpf_htons(ETH_P_IP)) {
        return skb->len;
    }

    // 2. Lê o cabeçalho IP logo após o Ethernet
    if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip)) < 0) {
        return skb->len;
    }

    // 3. Prepara a chave com os IPs de origem e destino
    struct ip_pair key = {};
    key.src_ip = ip.saddr;
    key.dst_ip = ip.daddr;

    // 4. Atualiza as estatísticas no mapa
    struct traffic_stat *stat = bpf_map_lookup_elem(&ip_traffic_stats, &key);
    if (stat) {
        // Se a entrada já existe, incrementa
        __sync_fetch_and_add(&stat->packets, 1);
        __sync_fetch_and_add(&stat->bytes, skb->len);
    } else {
        // Se for uma conexão nova, cria o registro inicial
        struct traffic_stat initial_stat = {
            .packets = 1,
            .bytes = skb->len
        };
        bpf_map_update_elem(&ip_traffic_stats, &key, &initial_stat, BPF_ANY);
    }

    return skb->len;
}

char _license[] SEC("license") = "GPL";