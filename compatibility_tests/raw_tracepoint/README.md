# raw_tracepoint

Testa a compatibilidade de programas eBPF do tipo _raw_tracepoint_ no robô Unitree Go2, verificando se o gancho (*hook*) consegue ser carregado e atrelado (*attach*). 
Programas eBPF do tipo _raw tracepoint_ são uma versão de baixo nível dos _tracepoints_, dando acesso direto aos parâmetros brutos do evento sem a camada de formatação do _tracepoint_ tradicional. Tem menor _overhead_ e é usado quando se precisa de mais performance ou de dados que o _tracepoint_ normal não expõe.

## Arquivos

- **`raw_tp_test.c`** — programa eBPF do tipo _raw_tracepoint_.
- **`main_raw_tp.c`** — espaço de usuário: carrega o objeto compilado, extrai o programa e tenta o _attach_ no _raw tracepoint_, reportando sucesso ou falha.

## Gancho testado

| Programa | Seção | Evento | O que intercepta |
|---|---|---|---|
| `raw_tp_teste` | `raw_tracepoint/sys_enter` | `sys_enter` | Entrada em chamadas de sistema (_syscalls_) |

O programa apenas retorna `0`. O objetivo aqui não é interferir em nada, e sim confirmar que o _hook_ é suportado pelo _kernel_.

## Como executar

```bash
clang -O2 -target bpf -c raw_tp_test.c -o raw_tp_test.o
gcc main_raw_tp.c -lbpf -o main_raw_tp
sudo ./main_raw_tp
```

O binário carrega `raw_tp_test.o` no _kernel_ e tenta atrelar o programa ao _raw tracepoint_ `sys_enter`, imprimindo uma mensagem de sucesso ou falha.

## Tratamento de erros

O erro é reportado conforme a etapa:

- Carregamento do `.o` no _kernel_ ou programa não encontrado no objeto são falhas fatais. O programa imprime a causa e aborta com `return 1`.
- Falha no _attach_ do _raw tracepoint_ também é fatal: imprime `Falha Crítica: O kernel recusou o attach do Raw Tracepoint.` e aborta com `return 1`.
