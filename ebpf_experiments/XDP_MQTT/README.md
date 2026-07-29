# XDP MQTT Monitor

## Visão Geral

Implementa um monitor de tráfego de rede baseado em **XDP** (*eXpress Data Path*), uma tecnologia *eBPF* que processa pacotes no nível mais baixo possível da pilha de rede do Linux. O objetivo é contabilizar pacotes MQTT, associados a endereços IP específicos, sem interferir no fluxo normal da rede.

A solução é composta por três componentes principais:

| Componente | Arquivo | Função |
|---|---|---|
| Programa XDP | `xdp_mqtt.c` | Executa no *kernel* e contabiliza os pacotes de interesse |
| *Loader* | `loader.c` | Carrega o programa XDP e o anexa à interface de rede |
| *Reader* | `reader.c` | Lê e exibe os contadores acumulados no mapa *eBPF* |

### Por que sem *pinning* de mapas?

Assim como em outros monitores deste conjunto de ferramentas, optou-se por não utilizar *pinning* de mapas *eBPF*, pois o ambiente de destino (o robô) pode não ter o diretório `bpffs` (normalmente `/sys/fs/bpf`) disponível.

---

## O que o programa XDP faz

O programa `monitor_robot_telemetry`, definido em `xdp_mqtt.c`, é anexado à interface de rede e inspeciona todo pacote recebido, seguindo esta lógica:

1. Verifica se o pacote é **IPv4** (*Ethertype* `0x0800`); caso contrário, deixa passar sem contabilizar.
2. Verifica se o protocolo IP é **TCP**; caso contrário, deixa passar.
3. Verifica se a porta de origem ou destino é `17883` (porta configurada como `UNITREE_MQTT_PORT`, usada pelo serviço de telemetria MQTT do robô).
4. Se o pacote corresponder, compara o IP de origem/destino com dois endereços específicos, previamente conhecidos como destinos da telemetria (`43.175.228.18` e `43.175.229.18`), e incrementa o contador correspondente no mapa.

Em nenhum momento o programa descarta, redireciona ou modifica pacotes — a função sempre retorna `XDP_PASS`. Trata-se de um monitor estritamente passivo.

### Estrutura do mapa de contagem

O mapa `unitree_telemetry_count` é do tipo `BPF_MAP_TYPE_ARRAY`, com 3 posições fixas (chaves `0`, `1` e `2`):

| Chave | Significado |
|---|---|
| `0` | Pacotes MQTT que não correspondem a nenhum dos dois IPs monitorados |
| `1` | Pacotes MQTT trocados com o endereço `43.175.228.18` |
| `2` | Pacotes MQTT trocados com o endereço `43.175.229.18` |

---

## Pré-requisitos

- Compilador **Clang/LLVM** com suporte ao alvo `bpf`.
- Compilador **GCC**.
- Biblioteca **libbpf**.
- Permissões de superusuário (*root*), necessárias para anexar programas XDP a interfaces e consultar mapas *eBPF* do *kernel*.
- Uma interface de rede válida, cujo nome será usado na configuração do `loader`.

---

## Passo a Passo

### 1. Compilar o programa XDP (`xdp_mqtt.c`)

```bash
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c xdp_mqtt.c -o xdp_mqtt.o
```

**O que este comando faz:**
- `-target bpf`: gera *bytecode* *eBPF*, e não código de máquina nativo.
- `-I/usr/include/$(uname -m)-linux-gnu`: inclui os cabeçalhos específicos da arquitetura da máquina, necessários para resolver tipos do sistema.
- Resulta no arquivo-objeto `xdp_mqtt.o`, que será carregado pelo *loader*.

---

### 2. Configurar e compilar o *loader* (`loader.c`)

O *loader* carrega o programa XDP compilado e o anexa à interface de rede escolhida, em **modo SKB** (`XDP_FLAGS_SKB_MODE`) (modo genérico, compatível com praticamente qualquer *driver* de rede).

Antes de compilar, edite `loader.c` e defina a interface de rede desejada:

```c
int ifindex = if_nametoindex("nome_da_interface");
```

Substitua `"nome_da_interface"` pelo nome real da interface (por exemplo, `"eth0"` ou `"wlan0"`). É possível listar as interfaces disponíveis com `ip link show`.

Em seguida, compile:

```bash
gcc loader.c -o loader $(pkg-config --cflags --libs libbpf) -lbpf
```

---

### 3. Executar o *loader*

```bash
sudo ./loader
```

**Importante:**
- O *loader* deve permanecer em execução (em *background* ou terminal dedicado) — é ele quem mantém o programa XDP anexado à interface e o mapa vivo na memória do *kernel*.
- Se o processo for encerrado, o programa XDP é automaticamente desanexado da interface e as estatísticas coletadas são perdidas.

---

### 4. Compilar o *reader* (`reader.c`)

```bash
gcc reader.c -o reader $(pkg-config --cflags --libs libbpf) -lbpf
```

---

### 5. Executar o *reader*

Com o *loader* ativo, execute o *reader* como *root*:

```bash
sudo ./reader
```

A saída exibe os três contadores acumulados:

```
key 0 = 12
key 1 = 340
key 2 = 87
```

O *reader* pode ser executado quantas vezes forem necessárias, a qualquer momento, desde que o *loader* continue ativo — ele apenas consulta o estado atual do mapa, sem interferir na coleta.

---
