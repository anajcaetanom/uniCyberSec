# XDP MQTT Monitor

A implementação sem pinning de mapas, considerando a possível ausência do diretório `/sys/fs/bpf` no robô. O programa XDP é carregado e anexado normalmente, mantendo o mapa em memória enquanto o processo permanece ativo. A leitura dos dados é feita via syscall `bpf()`, sem depender de bpffs, tracing ou `bpftool`.


## 1. Compilar o programa XDP

```bash
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c xdp_mqtt.c -o xdp_mqtt.o
```

## 2. Compilar o loader (attach + pin)

Edita a interface de rede dentro de `loader.c` (`if_nametoindex("nome_da_interface")`) .

```bash
gcc loader.c -o loader $(pkg-config --cflags --libs libbpf) -lbpf
```

## 3. Rodar o loader (anexa na interface e pina o mapa)

```bash
sudo ./loader
```

Deixa rodando em background/terminal separado. Se ele for encerrado, o programa se desanexa da interface.

## 4. Compilar o reader (lê o mapa)

```bash
gcc reader.c -o reader $(pkg-config --cflags --libs libbpf) -lbpf
```

## 5. Rodar o reader (lê os contadores)

```bash
sudo ./reader
```

Pode rodar quantas vezes quiser, enquanto o `loader` estiver ativo.