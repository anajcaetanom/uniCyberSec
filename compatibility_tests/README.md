# compatibility_tests

Testes de compatibilidade que verificam quais tipos de programas eBPF conseguem ser carregados e executados no ambiente do robô Unitree Go2. É a etapa exploratória do repositório: define o que funciona antes de qualquer aprofundamento.

## Estrutura

- **`cgroup/`** — programas eBPF anexados a _cgroups_, usados para interceptar eventos no escopo de um _control group_.
- **`kprobe/`** — programas do tipo _kprobe/kretprobe_, para instrumentação dinâmica de funções do _kernel_.
- **`raw_tracepoint/`** — programas do tipo _raw tracepoint_, conectados diretamente aos pontos de rastreamento do _kernel_, com menor _overhead_ que os _tracepoints_ convencionais.
- **`tracepoint/`** — programas do tipo _tracepoint_, associados a pontos estáticos de instrumentação do _kernel_.
- **`tracing/`** — programas do tipo _tracing_ (_fentry/fexit_), com acesso direto aos argumentos das funções instrumentadas.

Os recursos validados aqui servem de base para os experimentos em [`ebpf_experiments`](../ebpf_experiments).