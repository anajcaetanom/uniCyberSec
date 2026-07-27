# tracepoint

Testa a compatibilidade de programas eBPF do tipo _tracepoint_ no robô Unitree Go2, verificando se o gancho (*hook*) consegue ser carregado e atrelado (*attach*).
Programas desse tipo permitem anexar programas eBPF a pontos de instrumentação já definidos e estáveis dentro do _kernel_ (como entradas/saídas de _syscalls_). É mais seguro e previsível do que _kprobes_, pois esses pontos fazem parte da ABI estável do _kernel_.

## Arquivos

- **`tracepoint_test.c`** — programa eBPF do tipo _tracepoint_.
- **`main_tp.c`** — espaço de usuário: carrega o objeto compilado, extrai o programa e tenta o _attach_ no _tracepoint_, reportando sucesso ou falha.

## Gancho testado

| Programa | Seção | Evento | O que intercepta |
|---|---|---|---|
| `tracepoint_teste` | `tracepoint/syscalls/sys_enter_clone` | `sys_enter_clone` | Entrada na chamada de sistema `clone()` |

O programa apenas retorna `0`. O objetivo aqui não é interferir em nada, e sim confirmar que o _hook_ é suportado pelo _kernel_.

## Como rodar

Verificar se o evento existe no _kernel_:

```bash
ls /sys/kernel/tracing/events/syscalls/ | grep clone
```

Compilar e executar:

```bash
clang -O2 -target bpf -I/usr/include/$(uname -m)-linux-gnu -c tracepoint_test.c -o tracepoint_test.o
```
```bash
gcc main_tp.c -lbpf -o main_tp
sudo ./main_tp
```

O binário carrega `tracepoint_test.o` no _kernel_ e tenta atrelar o programa ao _tracepoint_ `syscalls/sys_enter_clone`, imprimindo uma mensagem de sucesso ou falha.

## Tratamento de erros

O erro é reportado conforme a etapa:

- Carregamento do `.o` no _kernel_ ou programa não encontrado no objeto são falhas fatais. O programa imprime a causa e aborta com `return 1`.
- Falha no _attach_ do _tracepoint_ também é fatal: imprime `Falha Crítica: Tracepoint inacessível. O subsistema não expõe os eventos.` e aborta com `return 1`.
