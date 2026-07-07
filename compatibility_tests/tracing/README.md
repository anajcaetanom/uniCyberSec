ver qual o nome da função sys_clone:

```bash
sudo grep -E '(__x64_sys_clone|sys_clone|clone3|kernel_clone|do_fork|_do_fork)' /sys/kernel/tracing/available_filter_functions
```

compilar programa eBPF:

```bash
clang -O2 -target bpf -I/usr/include/$(uname -m)-linux-gnu -c tracing_test.c -o tracing_test.o
```

compilar main:

```bash
gcc main_tracing.c -lbpf -o verificar_tracing
```

rodar:

```bash
sudo ./verificar_tracing
```
