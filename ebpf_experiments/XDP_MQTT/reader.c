#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int main() {
    __u32 id = 0;
    int map_fd = -1;

    while (bpf_map_get_next_id(id, &id) == 0) {
        int fd = bpf_map_get_fd_by_id(id);
        if (fd < 0) continue;

        struct bpf_map_info info = {};
        __u32 len = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd, &info, &len) == 0) {
            if (strcmp(info.name, "unitree_telemet") == 0) {
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

    for (__u32 key = 0; key < 3; key++) {
        __u64 value = 0;
        int ret = bpf_map_lookup_elem(map_fd, &key, &value);
        if (ret == 0)
            printf("key %u = %llu\n", key, value);
        else
            printf("key %u: lookup falhou (errno=%d, %s)\n", key, errno, strerror(errno));
    }

    return 0;
}