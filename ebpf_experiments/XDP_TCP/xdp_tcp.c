#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Porta MQTT da telemetria do Unitree G1 documentada
#define UNITREE_MQTT_PORT 17883

/* Mapa eBPF para categorizar os pacotes por Flag TCP
 * Índice 0: SYN (Tentativas de conexão)
 * Índice 1: RST (Conexões recusadas/quebradas)
 * Índice 2: FIN (Fechamento normal de conexão)
 * Índice 3: PSH (Envio de dados reais / Exfiltração)
 * Índice 4: Outros (ACKs de controle, keep-alive vazio)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 5);
} tcp_flags_count SEC(".maps");

SEC("xdp")
int analyze_unitree_tcp(struct xdp_md *ctx) {
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
    // O tamanho do cabeçalho IP varia, calculamos dinamicamente (ip->ihl * 4)
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    // 4. Identificação do tráfego do Unitree G1 (porta 17883)
    if (tcp->source == bpf_htons(UNITREE_MQTT_PORT) || tcp->dest == bpf_htons(UNITREE_MQTT_PORT)) {
        
        __u32 key = 4; // Categoria padrão: Outros (ex: ACKs puros)

        // Verifica o estado da conexão através das flags
        if (tcp->syn) {
            key = 0; // SYN: Iniciando conexão
        } else if (tcp->rst) {
            key = 1; // RST: Conexão resetada
        } else if (tcp->fin) {
            key = 2; // FIN: Finalizando conexão
        } else if (tcp->psh) {
            key = 3; // PSH: Pacote com payload (dados sendo enviados para a rede)
        }

        // Incrementa o contador da flag correspondente
        __u64 *value = bpf_map_lookup_elem(&tcp_flags_count, &key);
        if (value) {
            __sync_fetch_and_add(value, 1);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";