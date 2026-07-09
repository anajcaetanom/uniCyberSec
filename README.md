# uniCyberSec

Repositório de pesquisa dedicado à avaliação e experimentação de programas eBPF (_extended Berkeley Packet Filter_) executados sobre o robô quadrúpede Unitree Go2. O trabalho está organizado em duas etapas metodológicas complementares: (i) um levantamento de compatibilidade dos recursos eBPF disponíveis na plataforma e (ii) o aprofundamento experimental sobre os recursos previamente validados.

## Estrutura do repositório

```
uniCyberSec/
├── compatibility_tests/
└── ebpf_experiments/
```

### `compatibility_tests/`
Contém os testes de compatibilidade, cujo objetivo é determinar quais funcionalidades e programas eBPF são suportados pelo ambiente de execução do robô Go2. 

### `ebpf_experiments/`
A partir dos recursos eBPF identificados como compatíveis, esta etapa propõe investigações mais aprofundadas, avaliando comportamento, desempenho e aplicabilidade desses recursos em contextos mais elaborados.

## Sobre o projeto

- **Linguagem principal:** C
- **Plataforma-alvo:** Robô Unitree Go2
- **Área de estudo:** Cibersegurança aplicada a sistemas robóticos com locomoção por pernas, com foco na tecnologia eBPF.
