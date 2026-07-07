typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;

typedef signed char        __s8;
typedef signed short       __s16;
typedef signed int         __s32;
typedef signed long long   __s64;


#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#define ETH_P_IP 0x0800

struct ethhdr {
    __u8  h_dest[6];
    __u8  h_source[6];
    __u16 h_proto;
};

struct iphdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8 ihl:4;
    __u8 version:4;
#else
    __u8 version:4;
    __u8 ihl:4;
#endif

    __u8  tos;
    __u16 tot_len;
    __u16 id;
    __u16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
};

struct ip_pair {
    __u32 src_ip;
    __u32 dst_ip;
};

struct traffic_stat {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ip_pair);
    __type(value, struct traffic_stat);
    __uint(max_entries, 1024); // Rastreia ate 1024 pares de IP simultaneos
} ip_traffic_stats SEC(".maps");

SEC("socket")
int count_socket_traffic(struct __sk_buff *skb)
{
    struct ethhdr eth;
    struct iphdr ip;

    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
        return skb->len;
    }

    if (eth.h_proto != bpf_htons(ETH_P_IP)) {
        return skb->len;
    }

    if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip)) < 0) {
        return skb->len;
    }

    // 3. Prepara a chave com os IPs de origem e destino
    struct ip_pair key = {};
    key.src_ip = ip.saddr;
    key.dst_ip = ip.daddr;

    // 4. Atualiza as estatisticas no mapa
    struct traffic_stat *stat = bpf_map_lookup_elem(&ip_traffic_stats, &key);
    if (stat) {
        // Se a entrada ja existe, incrementa
        __sync_fetch_and_add(&stat->packets, 1);
        __sync_fetch_and_add(&stat->bytes, skb->len);
    } else {
        // Se for uma conexao nova, cria o registro inicial
        struct traffic_stat initial_stat = {
            .packets = 1,
            .bytes = skb->len
        };
        bpf_map_update_elem(&ip_traffic_stats, &key, &initial_stat, BPF_ANY);
    }

    return skb->len;
}

char _license[] SEC("license") = "GPL";