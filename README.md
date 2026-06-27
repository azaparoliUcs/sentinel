# Sentinel

Sentinel e um analisador de seguranca de rede em **Java 17**, com **Pcap4J** para captura de pacotes e **JavaFX** para interface grafica.

## Visao geral

O projeto captura trafego em tempo real ou a partir de arquivos `.pcap`, interpreta os cabecalhos dos pacotes e aplica regras de deteccao para identificar:

- `port scan` com limiar fixo de 20 portas em 60 segundos;
- fragmentacao IPv4 suspeita, incluindo fragmentos pequenos e sobrepostos.

Os resultados sao exibidos na interface, enviados para o console e gravados em `alerts.log`.

## Requisitos

- Java 17 ou superior
- Maven 3.8+
- `libpcap` no Linux e macOS
- `Npcap` no Windows
- permissao para captura de pacotes:
  - Linux e macOS: normalmente `root`
  - Windows: executar como Administrador

## Instalacao de dependencias nativas

### Linux

```bash
sudo apt update
sudo apt install libpcap-dev
```

### macOS

```bash
brew install libpcap
```

### Windows

Instale o `Npcap` em: <https://npcap.com>

## Como executar

### Interface grafica

```bash
mvn javafx:run
```

## Arquivos de exemplo

O diretorio `samples/` contem arquivos para teste manual:

- `fragmentacao_suspeita.pcap` - cenário com fragmentacao IPv4 suspeita;
- `port_scan_ate_20_portas.pcap` - cenário com ate 20 portas distintas para validar o `WARN`.

## O que o projeto faz

- captura pacotes a partir de uma interface de rede ou de um arquivo PCAP;
- detecta padroes de `port scan` e fragmentacao suspeita;
- exibe pacotes e alertas na interface;
- registra saida em console e em log;
- mantem uma janela de detalhes com pacotes relacionados ao alerta.

## Estrutura principal

- `src/main/java/br/com/sentinel/SentinelApp.java` - ponto de entrada da aplicacao JavaFX;
- `src/main/java/br/com/sentinel/capture/` - captura e controle do fluxo de pacotes;
- `src/main/java/br/com/sentinel/analysis/` - regras de analise e deteccao;
- `src/main/java/br/com/sentinel/model/` - modelos de dados usados no fluxo;
- `src/main/java/br/com/sentinel/parse/` - conversao de pacotes brutos para DTO;
- `src/main/java/br/com/sentinel/ui/` - interface grafica e componentes visuais;
- `src/main/java/br/com/sentinel/output/` - saida em console, log e listeners;
- `src/main/java/br/com/sentinel/format/` - formatacao de pacotes e alertas.

## Dica de validacao

Para testar rapidamente:

1. execute `mvn javafx:run`;
2. selecione a interface de rede ou um arquivo `.pcap`;
3. use os arquivos da pasta `samples/` para validar a deteccao;
4. observe a tabela de pacotes, os alertas e o arquivo `alerts.log`.
