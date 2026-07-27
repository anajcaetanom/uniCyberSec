# tracing

Testa a compatibilidade de programas eBPF do tipo _tracing_ (fentry) no robô Unitree Go2, verificando se o gancho (*hook*) consegue ser carregado e atrelado (*attach*). Programas do tipo _tracing_ usam BTF (_BPF Type Format_) para anexar o programa diretamente à entrada (_fentry_) ou saída (_fexit_) de qualquer função do _kernel_, com acesso tipado aos argumentos e menor _overhead_ que _kprobes_. É a forma moderna e mais eficiente de fazer _tracing_, mas exige suporte a `BTF/vmlinux` no _kernel_.

## Arquivos

- **`tracing_test.c`** — programa eBPF do tipo _tracing_ (fentry).
- **`main_tracing.c`** — espaço de usuário: carrega o objeto compilado, extrai o programa e tenta o _attach_ no evento de _tracing_, reportando sucesso ou falha.

## Gancho testado

| Programa | Seção | Evento | O que intercepta |
|---|---|---|---|
| `tracing_teste` | `fentry/__x64_sys_clone` | `__x64_sys_clone` | Entrada na função de kernel da chamada de sistema `clone()` |

O programa apenas retorna `0`. O objetivo aqui não é interferir em nada, e sim confirmar que o _hook_ é suportado pelo _kernel_.

## Como rodar

Verificar o nome correto da função no kernel:

```bash
sudo grep -E '(__x64_sys_clone|sys_clone|clone3|kernel_clone|do_fork|_do_fork)' /sys/kernel/tracing/available_filter_functions
```

Compilar e executar:

```bash
clang -O2 -target bpf -I/usr/include/$(uname -m)-linux-gnu -c tracing_test.c -o tracing_test.o
```
```bash
gcc main_tracing.c -lbpf -o main_tracing
sudo ./main_tracing
```

O binário carrega `tracing_test.o` no _kernel_ e tenta atrelar o programa via _fentry_ à função `__x64_sys_clone`, imprimindo uma mensagem de sucesso ou falha.

## Tratamento de erros

O erro é reportado conforme a etapa:

- Abertura do arquivo `.o`, carregamento no _kernel_ (possível ausência de `BTF/vmlinux`) e programa não encontrado no objeto são falhas fatais. O programa imprime a causa e aborta com `return 1`.
- Falha no _attach_ do tipo _fentry_ também é fatal: imprime `Falha: Não foi possível realizar o attach do tipo fentry.` e aborta com `return 1`.
