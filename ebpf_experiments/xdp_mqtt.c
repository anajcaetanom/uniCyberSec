
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


#define ETH_P_IP          0x0800
#define IPPROTO_TCP       6
#define UNITREE_MQTT_PORT 17883

#define IP4(a,b,c,d) \
    ((__u32)(a) | ((__u32)(b)<<8) | ((__u32)(c)<<16) | ((__u32)(d)<<24))


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

struct tcphdr {
    __u16 source;
    __u16 dest;
    __u32 seq;
    __u32 ack_seq;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u16 res1:4,
          doff:4,
          fin:1,
          syn:1,
          rst:1,
          psh:1,
          ack:1,
          urg:1,
          ece:1,
          cwr:1;
#else
    __u16 doff:4,
          res1:4,
          cwr:1,
          ece:1,
          urg:1,
          ack:1,
          psh:1,
          rst:1,
          syn:1,
          fin:1;
#endif

    __u16 window;
    __u16 check;
    __u16 urg_ptr;
};

#define XDP_ABORTED 0
#define XDP_DROP    1
#define XDP_PASS    2
#define XDP_TX      3
#define XDP_REDIRECT 4

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 3);
} unitree_telemetry_count SEC(".maps");


SEC("xdp")
int monitor_robot_telemetry(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp->source == bpf_htons(UNITREE_MQTT_PORT) ||
        tcp->dest   == bpf_htons(UNITREE_MQTT_PORT)) {

        __u32 key = 0;

        __u32 target_ip1 = IP4(43,175,228,18);
        __u32 target_ip2 = IP4(43,175,229,18);

        if (ip->daddr == target_ip1 || ip->saddr == target_ip1)
            key = 1;
        else if (ip->daddr == target_ip2 || ip->saddr == target_ip2)
            key = 2;

        __u64 *value = bpf_map_lookup_elem(&unitree_telemetry_count, &key);
        if (value)
            __sync_fetch_and_add(value, 1);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";