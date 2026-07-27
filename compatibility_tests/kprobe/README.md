# kprobe

Testa a compatibilidade de programas eBPF do tipo _kprobe_ no robô Unitree Go2, verificando se é possível instrumentar dinamicamente uma função do kernel via `perf_event`/`tracefs`.
Programas _kprobe_ permitem instrumentar dinamicamente quase qualquer função do _kernel_, disparando o programa eBPF sempre que ela é chamada (_kprobe_) ou retorna (_kretprobe_). É a ferramenta mais flexível para depuração e observabilidade, mas também a menos estável, já que depende de símbolos internos do _kernel_ que podem mudar entre versões.

## Arquivos

- **`kprobe_test.c`** — programa eBPF atrelado à entrada da função `__x64_sys_clone`.
- **`main_kprobe.c`** — userspace: carrega o objeto compilado e tenta o _attach_ via _kprobe_.

## Gancho testado

| Programa | Seção | Função-alvo | O que intercepta |
|---|---|---|---|
| `kprobe_teste` | `kprobe/__x64_sys_clone` | `__x64_sys_clone` | Entrada da _syscall_ responsável pela criação de processos/threads |

O programa apenas retorna `0`, sem alterar o fluxo de execução. O objetivo é apenas confirmar que o _kernel_ do robô suporta a instrumentação via _kprobe_.

## Como rodar

Verificar se o _tracefs_ está disponível:

```bash
ls -ld /sys/kernel/debug/tracing /sys/kernel/tracing 2>/dev/null
```

Confirmar o nome real da função de clone no _kernel_ do robô (pode variar por arquitetura/versão):

```bash
sudo grep -E '(__x64_sys_clone|sys_clone|clone3|kernel_clone|do_fork|_do_fork)' /sys/kernel/tracing/available_filter_functions
```

Compilar o programa eBPF e o binário _userspace_, e executar:

```bash
clang -O2 -target bpf -I/usr/include/$(uname -m)-linux-gnu -c kprobe_test.c -o kprobe_test.o
gcc main_kprobe.c -lbpf -o verificar_kprobe
sudo ./verificar_kprobe
```

## Tratamento de erros

- **Carregamento do `.o`** e **programa não encontrado no ELF** são falhas fatais de compilação/kernel — abortam com mensagem específica para cada causa.
- **Attach via kprobe** falha separadamente, com mensagem própria indicando que o subsistema `perf_event`/`tracefs` está inacessível.
