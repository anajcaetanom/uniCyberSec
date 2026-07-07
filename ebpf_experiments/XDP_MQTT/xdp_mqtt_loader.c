// loader.c
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <stdio.h>

int main() {
    int ifindex = if_nametoindex("wlp0s20f3");

    struct bpf_object *obj = bpf_object__open_file("xdp_mqtt.o", NULL);
    bpf_object__load(obj);

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "monitor_robot_telemetry");
    bpf_xdp_attach(ifindex, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE, NULL);

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "unitree_telemetry_count");
    bpf_obj_pin(bpf_map__fd(map), "/sys/fs/bpf/unitree_telemetry_count");

    printf("attached + pinned\n");
    while (1) sleep(60);
}