#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

struct ip_pair {
    __u32 src_ip;
    __u32 dst_ip;
};

struct traffic_stat {
    __u64 packets;
    __u64 bytes;
};

static void print_ip(__u32 ip_be) {
    struct in_addr addr;
    addr.s_addr = ip_be;
    printf("%s", inet_ntoa(addr));
}

int main() {
    __u32 id = 0;
    int map_fd = -1;

    while (bpf_map_get_next_id(id, &id) == 0) {
        int fd = bpf_map_get_fd_by_id(id);
        if (fd < 0) continue;

        struct bpf_map_info info = {};
        __u32 len = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd, &info, &len) == 0) {
            if (strcmp(info.name, "ip_traffic_stats") == 0) {
                map_fd = fd;
                printf("mapa encontrado: id=%u name=%s\n", info.id, info.name);
                break;
            }
        }
        close(fd);
    }

    if (map_fd < 0) {
        fprintf(stderr, "mapa nao encontrado\n");
        return 1;
    }

    struct ip_pair key = {}, next_key;
    int has_key = 0;

    while (bpf_map_get_next_key(map_fd, has_key ? &key : NULL, &next_key) == 0) {
        struct traffic_stat stat = {};
        int ret = bpf_map_lookup_elem(map_fd, &next_key, &stat);
        if (ret == 0) {
            printf("src=");
            print_ip(next_key.src_ip);
            printf(" dst=");
            print_ip(next_key.dst_ip);
            printf(" packets=%llu bytes=%llu\n", stat.packets, stat.bytes);
        } else {
            printf("lookup falhou (errno=%d, %s)\n", errno, strerror(errno));
        }

        key = next_key;
        has_key = 1;
    }

    return 0;
}