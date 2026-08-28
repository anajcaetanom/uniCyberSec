# Experiments

Após a realização dos testes de compatibilidade de diferentes tipos de programas eBPF no robô Unitree Go2, que confirmaram a possibilidade de utilização de XDP e Socket Filter, os testes seguintes tiveram como objetivo avaliar aplicações mais práticas desses programas. Os testes compreenderam o monitoramento de tráfego MQTT por meio de XDP, com contabilização de pacotes associados a endereços IP específicos; o monitoramento, utilizando Socket Filter, da quantidade de pacotes e bytes trocados entre pares de endereços IP; e a implementação de um mecanismo de blacklist capaz de bloquear tráfego ICMP.

## Estrutura

```
ebpf_experiments/
├── SOCKET_FILTER/
├── XDP_ICMP_BLACKLIST/
└── XDP_MQTT/
```

### `SOCKET_FILTER/`
Programa do tipo Socket Filter para monitorar o tráfego de rede em tempo real. Nesse caso, o programa contabiliza a quantidade de pacotes e de bytes trocados entre pares de endereços IP de origem e destino. 

### `XDP_ICMP_BLACKLIST/`
Realiza o acompanhamento dos pacotes ICMP recebidos e, após a identificação de três pacotes associados ao mesmo endereço IP, adiciona esse endereço a uma blacklist. A partir desse momento, os pacotes ICMP provenientes do endereço bloqueado deixam de ser aceitos pelo programa.

### `XDP_MQTT/`
Execução de um programa XDP destinado ao monitoramento de tráfego MQTT. O programa realiza a contabilização de pacotes associados a endereços IP específicos, permitindo observar a ocorrência desse tipo de tráfego diretamente na interface de rede. O processamento é realizado sem bloquear ou modificar os pacotes, de modo que o fluxo normal da comunicação seja mantido.





