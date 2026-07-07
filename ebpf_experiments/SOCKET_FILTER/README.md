# Socket Filter IP Traffic Monitor

Implementação sem pinning de mapas, considerando a possível ausência do diretório `/sys/fs/bpf` no robô. O programa BPF é carregado e anexado a um raw socket normalmente, mantendo o mapa em memória enquanto o processo permanece ativo. A leitura dos dados é feita via syscall `bpf()`, sem depender de bpffs, tracing ou `bpftool`.


## 1. Compilar o programa socket filter

```bash
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c socket_filter.c -o socket_filter.o
```

## 2. Compilar o loader (attach)

Edita a interface de rede dentro de `loader.c` (`const char *ifname = "nome_da_interface";`) .

```bash
gcc loader.c -o loader $(pkg-config --cflags --libs libbpf) -lbpf
```

## 3. Rodar o loader (anexa no socket raw da interface)

```bash
sudo ./loader
```

Deixa rodando em background/terminal separado. Se ele for encerrado, o programa se desanexa do socket.

## 4. Compilar o reader (lê o mapa)

```bash
gcc reader.c -o reader $(pkg-config --cflags --libs libbpf) -lbpf
```

## 5. Rodar o reader (lê os contadores por par de IP)

```bash
sudo ./reader
```

Pode rodar quantas vezes quiser, enquanto o `loader` estiver ativo.