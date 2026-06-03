ver se existe o diretório e qual o nome da função:

```bash
ls /sys/kernel/tracing/events/syscalls/ | grep clone
```

compilar programa eBPF:

```bash
clang -O2 -target bpf -I/usr/include/$(uname -m)-linux-gnu -c tracepoint_test.c -o tracepoint_test.o
```

compilar main:

```bash
gcc main_tp.c -lbpf -o verificar_tp
```

rodar:

```bash
sudo ./verificar_tp
```
