# rawpkt

Sniffer de pacotes de rede escrito em Python. O rawpkt captura em tempo real os frames que passam pela placa de rede, decodifica cada camada de protocolo (Ethernet, IP, TCP, UDP e ICMP), mostra os campos dos headers e valida os checksums.

A proposta é tornar observável o tráfego de rede, que normalmente é invisível, e servir de ponte entre a teoria de Redes de Computadores e a programação de baixo nível.

> **Estado do projeto:** em desenvolvimento. Hoje só o módulo de checksum está implementado. Veja o [roadmap](#roadmap).

## Por que não usar o Wireshark?

Ferramentas prontas mostram o resultado, mas escondem como ele foi obtido. Construir um sniffer do zero obriga a entender na prática:

- como os bytes estão organizados em cada header;
- a ordem de bytes da rede (big-endian);
- o encapsulamento de uma camada dentro da outra;
- como funciona a detecção de erros por checksum.

## Objetivos

- Capturar pacotes em tempo real na interface de rede.
- Decodificar manualmente os headers de cada camada com o módulo `struct`.
- Recalcular e validar os checksums do IPv4, TCP, UDP e ICMP.
- Entregar os pacotes analisados a uma interface de terminal ou desktop.
- Servir de base para estudos e extensões futuras.

## Arquitetura

O projeto tem duas partes:

1. **A biblioteca `rawpkt`**, que cuida de captura, parsing e validação e não depende de nenhuma interface.
2. **As aplicações** que consomem a biblioteca: uma TUI ([Textual](https://textual.textualize.io/)) e/ou uma GUI desktop ([PySide](https://doc.qt.io/qtforpython/)).

### Camadas

| # | Camada | Módulo | Responsabilidade |
|---|--------|--------|------------------|
| 1 | Captura | `capture` | Obtém os bytes crus de cada frame a partir de um backend que pode ser trocado. |
| 2 | Dissecação | `dissector` + `layers` | Transforma os bytes em objetos de camada encadeados. Usa o EtherType e o campo de protocolo do IP para decidir o próximo parser. |
| 3 | Validação | `checksum` | Recalcula os checksums e compara com os valores recebidos. |
| 4 | Distribuição | `events` | Publica cada pacote analisado num barramento de eventos. |
| 5 | Apresentação | `apps` | A TUI ou a GUI se inscrevem nos eventos e exibem os dados. |

### Estrutura de módulos (planejada)

```
rawpkt/
  capture/
    base.py        # Backend (ABC)
    linux_raw.py   # LinuxRawSocket (AF_PACKET)
    pcap.py        # PcapReader
  layers/
    base.py        # Layer (ABC)
    ethernet.py
    ipv4.py
    ipv6.py
    tcp.py
    udp.py
    icmp.py
  checksum.py      # internet_checksum, pseudo-headers
  dissector.py     # Dissector, registro de protocolos
  packet.py        # Packet (pilha de camadas + metadados)
  events.py        # EventBus / fila
  sniffer.py       # Sniffer (orquestra tudo)
tests/
  fixtures/*.pcap
apps/
  tui/
  gui/
```

### Diagrama de classes

![Diagrama de classes do rawpkt](docs/diagrams/classes.png)

Fonte editável: [`docs/diagrams/classes.mmd`](docs/diagrams/classes.mmd)

### Fluxo de captura de um pacote

![Diagrama de sequência da captura de um pacote](docs/diagrams/sequencia.png)

Fonte editável: [`docs/diagrams/sequencia.mmd`](docs/diagrams/sequencia.mmd)

### Decisões de projeto

- **Biblioteca separada da interface.** As apps só consomem o `EventBus`. Isso facilita os testes e permite trocar a interface sem reescrever o núcleo.
- **Parsing manual, Scapy só nos testes.** Usar o [Scapy](https://scapy.net/) no núcleo esconderia exatamente o que se quer aprender. Por isso o parsing é escrito à mão com `struct`, e o Scapy serve só de referência para conferir os resultados nos testes.
- **Captura atrás de uma abstração.** A ABC `Backend` isola a origem dos frames. O primeiro backend é o raw socket do Linux (`AF_PACKET`), e o `PcapReader` permite testar com tráfego gravado, sem rede ao vivo.
- **Checksum offload não é erro.** Pacotes de saída com checksum divergente são marcados como `offload_suspected` em vez de acusados como corrompidos.

## O checksum da internet

O checksum usado pelo IPv4, TCP, UDP e ICMP ([RFC 1071](https://www.rfc-editor.org/rfc/rfc1071)) é a soma em complemento de um de todas as palavras de 16 bits, invertida no final. Quem recebe o pacote recalcula essa soma. Se o valor não bater, o pacote foi corrompido no caminho. No TCP e no UDP, o cálculo também inclui um **pseudo-header** com os endereços IP de origem e destino, o protocolo e o tamanho do segmento.

Dois casos especiais que o rawpkt trata:

- **Checksum offload:** placas de rede modernas calculam o checksum no hardware, depois que o pacote já foi capturado. Por isso, pacotes de saída costumam aparecer no sniffer com checksum "errado". O rawpkt identifica esse caso (`offload_suspected=True`) em vez de acusar erro.
- **UDP sobre IPv4:** o checksum é opcional, e o valor zero significa "não calculado". Nesse caso o resultado vem com `skipped=True` e é considerado válido.

### Uso do módulo `checksum`

```python
from checksum import verify, pseudo_header_v4, OFFSET_IPV4, OFFSET_UDP, PROTO_UDP

# Header IPv4
r = verify("ipv4", ipv4_header, OFFSET_IPV4)
print(r.valid, hex(r.expected), hex(r.computed))

# Segmento UDP, com pseudo-header
ph = pseudo_header_v4(src_ip, dst_ip, PROTO_UDP, len(udp_segment))
r = verify("udp", udp_segment, OFFSET_UDP, ph, outgoing=True)
print(r.valid, r.offload_suspected, r.skipped)
```

Para ver os casos (header válido, header corrompido, UDP com checksum zero e offload) em ação:

```bash
python demo_checksum.py
```

## Requisitos

- Python 3.10 ou mais recente (o código usa `dataclass(slots=True)` e a sintaxe de tipos `X | Y`).
- Linux, para a captura ao vivo com `AF_PACKET`. A leitura de arquivos pcap não depende de sistema operacional.
- Privilégios de administrador (ou a capability `CAP_NET_RAW`) para abrir raw sockets.

## Roadmap

A ordem de implementação definida é:

- [x] `checksum`: checksum da internet, pseudo-headers e detecção de offload
- [ ] `layers`: Ethernet, IPv4, IPv6, TCP, UDP, ICMP
- [ ] `dissector`
- [ ] `PcapReader`
- [ ] `LinuxRawSocket`
- [ ] `events` / `Sniffer`
- [ ] apps (TUI e/ou GUI)

## Temas para estudo

- Como o modelo TCP/IP se reflete na estrutura de bytes de um pacote real?
- Quais as diferenças entre os headers do IPv4 e do IPv6, e por que o IPv6 removeu o checksum do header IP?
- Por que raw sockets exigem privilégios de administrador?
- Quais os limites de desempenho do Python para captura em alta velocidade, e como contorná-los?
- Como estender o projeto para protocolos de aplicação, como DNS ou HTTP?

## Aspectos éticos e legais

Capturar tráfego de rede só é aceitável em redes próprias ou com autorização explícita. Interceptar comunicações de terceiros sem consentimento pode ser crime. Em ambiente acadêmico, prefira máquinas virtuais, redes de laboratório ou arquivos pcap públicos.

## Licença

Distribuído sob a [GNU General Public License v3.0](LICENSE).
