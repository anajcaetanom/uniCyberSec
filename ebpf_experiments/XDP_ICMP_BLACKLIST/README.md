# XDP ICMP Blacklist

Este código foi desenvolvido com base em: [Proteção DDoS com XDP (eBPF)](https://github.com/adudacoelho/xdp-ddos-protect)

## Visão Geral

Implementa um mecanismo de proteção de tráfego baseado em **XDP** (*eXpress Data Path*) e *eBPF*, destinado à detecção e ao bloqueio de tráfego ICMP excessivo.

O programa monitora requisições ICMP Echo (*ping*) recebidas pela interface de rede, mantém a contagem de pacotes por endereço IP de origem e adiciona automaticamente à *blacklist* os endereços que ultrapassam o limite configurado.

A solução é composta por três componentes principais:

| Componente | Arquivo | Função |
|---|---|---|
| Programa XDP | `xdp_ddos_protection.c` | Executa no *kernel*, contabiliza os pacotes e realiza o bloqueio |
| Programa de *pinning* | `pin.c` | Localiza os mapas criados pelo XDP e os fixa em `/sys/fs/bpf` |
| Monitor | `monitor.c` | Lê e exibe as informações armazenadas nos mapas *eBPF* |

---

## O que o programa XDP faz

O programa `xdp_prog`, definido em `xdp_ddos_protection.c`, é anexado à interface de rede e inspeciona os pacotes recebidos, seguindo esta lógica:

1. Verifica se o pacote é **IPv4** (*Ethertype* `0x0800`); caso contrário, retorna `XDP_PASS`.
2. Verifica se o protocolo IP é **ICMP**; caso contrário, retorna `XDP_PASS`.
3. Verifica se o pacote é uma requisição ICMP Echo (*ping request*); caso contrário, retorna `XDP_PASS`.
4. Obtém o endereço IP de origem do pacote.
5. Consulta o mapa `blacklist_map` para verificar se o endereço já está bloqueado.
6. Caso esteja na *blacklist*, o pacote é descartado com `XDP_DROP`.
7. Consulta o mapa `rate_limit_map` e incrementa o contador associado ao endereço IP.
8. Quando o número de pacotes ultrapassa o limite definido por `RATE_LIMIT`, o endereço IP é inserido em `blacklist_map` e o pacote é descartado.

---

## Compatibilidade com o ambiente do Unitree Go2

O ambiente do robô utiliza uma versão antiga do `iproute2` e apresenta limitações relacionadas a BTF.

Por esse motivo, os mapas são declarados utilizando o formato legado compatível com o *loader* interno do `iproute2`, por meio de `struct bpf_elf_map` e da seção:

```c
SEC("maps")
```

Além disso, os mapas criados pelo *loader* não apresentam seus nomes em `bpf_map_info.name`.

Dessa forma, o programa `pin.c` identifica os mapas pelas suas características.

Após identificá-los, os mapas são fixados nos seguintes caminhos:

```text
/sys/fs/bpf/rate_limit_map
/sys/fs/bpf/blacklist_map
```

---

## Pré-requisitos

- Compilador **Clang/LLVM** com suporte ao alvo `bpf`.
- Compilador **GCC**.
- Biblioteca **libbpf**.
- Utilitário `ip` com suporte a XDP.
- Sistema de arquivos `bpffs` montado em `/sys/fs/bpf`.
- Permissões de superusuário (*root*) para carregar programas XDP, enumerar mapas *eBPF* e realizar *pinning*.

---

## Passo a Passo

### 1. Compilar o programa XDP

Compile `xdp_ddos_protection.c` com:

```bash
clang -O2 -target bpf \
    -I/usr/include/$(uname -m)-linux-gnu \
    -c xdp_ddos_protection.c \
    -o xdp_ddos_protection.o
```

**O que este comando faz:**

- `-O2`: habilita otimizações do compilador.
- `-target bpf`: gera *bytecode eBPF*.
- `-I/usr/include/$(uname -m)-linux-gnu`: adiciona os cabeçalhos específicos da arquitetura.
- Gera o arquivo `xdp_ddos_protection.o`.

A opção `-g` não é utilizada devido às limitações de BTF encontradas no ambiente do robô.

---

### 2. Anexar o programa XDP

Para carregar o programa em modo XDP genérico:

```bash
sudo ip link set dev wlan0 xdpgeneric obj xdp_ddos_protection.o sec xdp
```

Substitua `wlan0` pela interface desejada, se necessário.

É possível verificar o estado da interface com:

```bash
ip link show wlan0
```

---

### 3. Compilar o programa de *pinning*

Compile `pin.c`:

```bash
gcc pin.c -o pin -lbpf
```

---

### 4. Fixar os mapas em `bpffs`

Com o XDP já carregado, execute:

```bash
sudo ./pin
```

O programa localiza os mapas criados pelo XDP e os fixa em:

```text
/sys/fs/bpf/rate_limit_map
/sys/fs/bpf/blacklist_map
```

---

### 5. Compilar o monitor

Compile `monitor.c`:

```bash
gcc monitor.c -o monitor -lbpf
```

---

### 6. Executar o monitor

Execute como *root*:

```bash
sudo ./monitor
```

O monitor consulta continuamente o `rate_limit_map` e apresenta as alterações observadas.

Uma execução pode apresentar mensagens semelhantes a:

```text
Mapas abertos com sucesso!
PING de 192.168.122.1 -> 1 pacotes
PING de 192.168.122.1 -> 2 pacotes
PING de 192.168.122.1 -> 3 pacotes
PING de 192.168.122.1 -> 4 pacotes. [STRIKE] limite excedido
192.168.122.1 [BLACKLISTED]
```

O monitor atua somente na visualização das informações. A decisão de inserir o endereço na *blacklist* e o descarte dos pacotes são realizados diretamente pelo programa XDP.

---

## Remover o programa XDP

Para desanexar o programa da interface:

```bash
sudo ip link set dev wlan0 xdpgeneric off
```

Os *pins* podem ser removidos com:

```bash
sudo rm -f /sys/fs/bpf/rate_limit_map
sudo rm -f /sys/fs/bpf/blacklist_map
```

---
