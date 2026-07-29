# Socket Filter IP Traffic Monitor

## Visão Geral

Este projeto implementa um monitor de tráfego de rede capaz de contabilizar, em tempo real, a quantidade de pacotes e _bytes_ trocados entre pares de endereços IP (origem e destino) em uma interface de rede.

A solução é composta por três componentes principais:

| Componente | Arquivo | Função |
|---|---|---|
| Programa eBPF | `socket_filter.c` | Executa no _kernel_ e coleta as estatísticas de tráfego |
| Loader | `loader.c` | Carrega o programa eBPF e o anexa a um _socket raw_ |
| Reader | `reader.c` | Lê e exibe os dados coletados no mapa eBPF |

### Por que sem *pinning* de mapas?

Em condições normais, um mapa eBPF pode ser "fixado" (*pinned*) no sistema de arquivos virtual `bpffs` (geralmente montado em `/sys/fs/bpf`), permitindo que processos independentes o acessem mesmo após o encerramento do programa que o criou.

Neste projeto, optou-se por **não utilizar _pinning_**, pois o ambiente de destino (o robô) pode não ter o `bpffs` disponível. Como consequência:

- O mapa `ip_traffic_stats` permanece **em memória**, associado ao processo `loader`, enquanto este estiver em execução.
- O processo `reader` localiza o mapa dinamicamente, percorrendo os mapas ativos no sistema via chamadas de sistema (`syscall bpf()`), sem depender de `bpftool` ou de arquivos montados em `bpffs`.
- Se o `loader` for encerrado, o programa BPF é automaticamente desanexado do _socket_ e o mapa deixa de existir.

---

## Pré-requisitos

- Compilador **Clang/LLVM** com suporte ao alvo `bpf` (para compilar o programa eBPF).
- Compilador **GCC** (para compilar `loader.c` e `reader.c`).
- Biblioteca **libbpf**.
- Permissões de **superusuário (root)**, necessárias para anexar programas eBPF a _sockets_ e para consultar mapas eBPF do _kernel_.
- Uma interface de rede válida, cujo nome será usado na configuração do `loader`.

---

## Passo a Passo

### 1. Compilar o programa eBPF (`socket_filter.c`)

Este é o código que será carregado no _kernel_. Ele é compilado para o alvo especial `bpf`, e não para a arquitetura nativa da máquina:

```bash
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c socket_filter.c -o socket_filter.o
```

**O que este comando faz:**
- `-target bpf`: instrui o Clang a gerar bytecode BPF, e não código de máquina x86/ARM comum.
- `-I/usr/include/$(uname -m)-linux-gnu`: inclui os cabeçalhos específicos da arquitetura, necessários para identificar tipos e macros do sistema.
- `-c ... -o socket_filter.o`: gera o arquivo-objeto `socket_filter.o`, que será carregado posteriormente pelo `loader`.

---

### 2. Configurar e compilar o loader (`loader.c`)

O `loader` é responsável por carregar o programa eBPF compilado e anexá-lo a um _socket raw_ da interface de rede escolhida.

**Antes de compilar**, edite o arquivo `loader.c` e defina o nome da interface de rede desejada:

```c
const char *ifname = "nome_da_interface";
```

Substitua `"nome_da_interface"` pelo nome real da interface (por exemplo, `"eth0"` ou `"wlan0"`). Você pode listar as interfaces disponíveis com o comando `ip link show`.

Em seguida, compile o loader:

```bash
gcc loader.c -o loader $(pkg-config --cflags --libs libbpf) -lbpf
```

---

### 3. Executar o loader

Com o binário `loader` gerado, execute-o com privilégios de root:

```bash
sudo ./loader
```

**Importante:**
- O `loader` deve permanecer em execução (em segundo plano ou em um terminal dedicado), pois é ele quem mantém o programa eBPF anexado ao _socket_ e o mapa vivo na memória do _kernel_.
- Caso o processo seja encerrado (por exemplo, com `Ctrl+C` ou `kill`), o programa eBPF é automaticamente desanexado e as estatísticas coletadas são perdidas.

---

### 4. Compilar o reader (`reader.c`)

O `reader` é um programa auxiliar, independente do `loader`, que consulta o mapa eBPF em execução e exibe os contadores de tráfego.

```bash
gcc reader.c -o reader $(pkg-config --cflags --libs libbpf) -lbpf
```

---

### 5. Executar o reader

Com o `loader` ativo, execute o `reader` (também como _root_, pois a leitura de mapas eBPF exige privilégios elevados):

```bash
sudo ./reader
```

A saída exibirá, para cada par de IPs observado, o número de pacotes e o total de _bytes_ trafegados, no seguinte formato:

```
src=192.168.0.10 dst=192.168.0.1 packets=42 bytes=13580
```

O `reader` pode ser executado **quantas vezes forem necessárias**, a qualquer momento, desde que o `loader` continue em execução. O `reader` apenas consulta o estado atual do mapa, sem interferir na coleta.

---