#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

int main() {
    const char *ifname = "nome_da_interface";

    int ifindex = if_nametoindex(ifname);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    struct bpf_object *obj = bpf_object__open_file("socket_filter.o", NULL);
    if (libbpf_get_error(obj)) { fprintf(stderr, "open failed\n"); return 1; }

    if (bpf_object__load(obj)) { fprintf(stderr, "load failed\n"); return 1; }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "count_socket_traffic");
    if (!prog) { fprintf(stderr, "program not found\n"); return 1; }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) { fprintf(stderr, "invalid prog fd\n"); return 1; }

    // Cria um raw socket AF_PACKET para receber todos os frames da interface
    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0) { perror("socket"); return 1; }

    struct sockaddr_ll sll = {0};
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        return 1;
    }

    // Anexa o programa BPF ao socket
    if (setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
        perror("setsockopt(SO_ATTACH_BPF)");
        return 1;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "ip_traffic_stats");
    if (!map) { fprintf(stderr, "map not found\n"); return 1; }

    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    bpf_obj_get_info_by_fd(bpf_map__fd(map), &info, &len);

    printf("attached (sem pin). map_id=%u name=%s\n", info.id, info.name);

    while (1) sleep(60);
}