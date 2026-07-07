#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Porta MQTT específica usada pela telemetria do Unitree G1
#define UNITREE_MQTT_PORT 17883

// Macro para montar IPs IPv4 no formato de rede (Little Endian para sistemas padrão)
#define IP4(a, b, c, d) ((a) | ((b) << 8) | ((c) << 16) | ((d) << 24))

/* Mapa eBPF para categorizar a telemetria do robô */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 3); // 0 = Outros, 1 = Servidor Primário, 2 = Servidor Secundário
} unitree_telemetry_count SEC(".maps");

SEC("xdp")
int monitor_robot_telemetry(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Parse Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    // 2. Parse IPv4
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    // 3. Parse TCP
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    // 4. Identificação do tráfego do Unitree G1
    if (tcp->source == bpf_htons(UNITREE_MQTT_PORT) || tcp->dest == bpf_htons(UNITREE_MQTT_PORT)) {
        
        __u32 key = 0; // Chave 0: Tráfego na porta 17883, mas para outros IPs
        
        // IPs de telemetria maliciosa/não autorizada documentados
        __u32 target_ip1 = IP4(43, 175, 228, 18);
        __u32 target_ip2 = IP4(43, 175, 229, 18);

        // Verifica se a origem ou destino bate com os servidores de exfiltração
        if (ip->daddr == target_ip1 || ip->saddr == target_ip1) {
            key = 1; 
        } else if (ip->daddr == target_ip2 || ip->saddr == target_ip2) {
            key = 2; 
        }

        // Incrementa o contador apropriado
        __u64 *value = bpf_map_lookup_elem(&unitree_telemetry_count, &key);
        if (value) {
            __sync_fetch_and_add(value, 1);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";