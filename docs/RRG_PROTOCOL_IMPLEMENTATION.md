# Implementação RRG / Iceman no Utamo RF Lab

## Base consultada

- Repositório `RfidResearchGroup/proxmark3`.
- Documento público de comandos do Proxmark3/Iceman.
- Changelog público do projeto para recursos recentes.

## Decisão técnica

Foi criado um catálogo local em `app/rf/protocol_catalog.py`, em vez de acoplar o sistema diretamente ao repositório externo. Isso evita dependência de internet, preserva estabilidade e permite controlar quais comandos a interface pode executar.

## Implementado

- 25 perfis de protocolos.
- 40 comandos read-only homologados.
- Endpoint de listagem de protocolos.
- Endpoint de classificação de comando.
- Endpoint de sugestão de protocolo por saída colada.
- Endpoint para executar perfil seguro.
- UI com cards de protocolos, risco, comandos permitidos e comandos bloqueados.
- Parser Proxmark expandido para HF/LF:
  - ISO14443-A
  - ISO14443-B
  - ISO15693
  - MIFARE Classic
  - MFU/NTAG
  - DESFire
  - NTAG424
  - FeliCa
  - Topaz
  - ST25TA
  - Seos
  - EM410x
  - HID Prox/Wiegand
  - AWID
  - Indala
  - ioProx
  - FDX-B
  - Hitag
  - T55xx

## Mantido bloqueado

- Ataques MIFARE Classic: autopwn, nested, hardnested, darkside.
- Recuperação/brute force: brute, crack, chk, fchk.
- Escrita/alteração: write, wrbl, wipe, restore, setuid, setkey, changekey.
- Clonagem/emulação/replay: clone, sim, simulate, spoof, replay, relay.
- Sniffing/raw/tearoff: sniff, raw, tearoff.

## Resultado

O Utamo RF Lab agora serve como ferramenta defensiva de inventário e análise RFID/Proxmark3, com base no ecossistema Iceman, sem abrir botões perigosos na interface.
