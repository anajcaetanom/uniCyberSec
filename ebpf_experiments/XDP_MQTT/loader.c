#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    int ifindex = if_nametoindex("nome_da_interface");
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    struct bpf_object *obj = bpf_object__open_file("xdp_mqtt.o", NULL);
    if (libbpf_get_error(obj)) { fprintf(stderr, "open failed\n"); return 1; }

    if (bpf_object__load(obj)) { fprintf(stderr, "load failed\n"); return 1; }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "monitor_robot_telemetry");
    bpf_xdp_attach(ifindex, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE, NULL);

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "unitree_telemetry_count");
    int map_id = bpf_map__fd(map) >= 0 ? 0 : -1;
    (void)map_id;

    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    bpf_obj_get_info_by_fd(bpf_map__fd(map), &info, &len);

    printf("attached (sem pin). map_id=%u name=%s\n", info.id, info.name);

    while (1) sleep(60);
}