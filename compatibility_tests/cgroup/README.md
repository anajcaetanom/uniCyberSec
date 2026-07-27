# cgroup

Testa a compatibilidade de programas eBPF do tipo _cgroup_ no robô Unitree Go2, verificando se cada gancho (*hook*) consegue ser carregado e atrelado (*attach*). 
Programas do tipo _cgroup_ permitem anexar programas eBPF a um _cgroup_ para interceptar e controlar recursos de processos dentro dele, como acesso a dispositivos, criação/liberação de _sockets_, `bind()` e tráfego de rede (entrada/saída). É muito usado para políticas de segurança e isolamento de containers.

## Arquivos

- **`cgroup_test.c`** — programas eBPF, um para cada tipo de _hook_ testado.
- **`main_cgroup.c`** — espaço de usuário: carrega o objeto compilado, extrai cada programa e tenta o _attach_ no _cgroup_, reportando sucesso ou falha.

## Ganchos testados

| Programa | Seção | Evento | O que intercepta |
|---|---|---|---|
| `test_cg_dev` | `cgroup/dev` | `BPF_CGROUP_DEVICE` | Acesso a dispositivos (`/dev`) |
| `test_cg_sock_create` | `cgroup/sock_create` | `BPF_CGROUP_INET_SOCK_CREATE` | Criação de socket (`socket()`) |
| `test_cg_sock` | `cgroup/sock` | `BPF_CGROUP_INET_SOCK_RELEASE` | Liberação/pós-criação de socket |
| `test_cg_bind` | `cgroup/bind4` | `BPF_CGROUP_INET4_BIND` | Chamada `bind()` em IPv4 |
| `test_cg_skb` | `cgroup/skb` | `BPF_CGROUP_INET_INGRESS` / `BPF_CGROUP_INET_EGRESS` | Tráfego de rede (entrada e saída) |
| `test_sock_ops` | `sockops` | `BPF_CGROUP_SOCK_OPS` | Mudanças de estado da conexão TCP |

Todos os programas retornam apenas `1` (ou `0`, no caso de `sock_ops`) para permitir a ação. O objetivo aqui não é bloquear nada, e sim confirmar que o _hook_ é suportado pelo _kernel_.

## Como rodar

```bash
clang -O2 -target bpf -c cgroup_test.c -o cgroup_test.o
gcc main_cgroup.c -lbpf -o main_cgroup
sudo ./main_cgroup
```

O binário abre `/sys/fs/cgroup`, carrega `cgroup_test.o` e tenta atrelar cada programa ao seu evento correspondente, imprimindo `[ OK ]` ou `[ FALHA ]` para cada um. Cada _attach_ bem-sucedido é desfeito (`detach`) logo em seguida.

## Tratamento de erros

O erro é reportado conforme a etapa:

- Abertura do _cgroup_ e carregamento do `.o` no _kernel_ são falhas fatais. O programa imprime a causa e aborta com `return 1`.
- _Attach_ de cada gancho é isolado: uma falha só imprime `[ FALHA ] <nome> rejeitado.` e segue para o próximo, sem interromper os demais testes.
