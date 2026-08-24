# Leitura inteligente do cartão

A versão 3.1 adiciona um orquestrador read-only para transformar a saída do Proxmark3 em análise estruturada.

## Fluxo

```text
hf search
  → extração de UID/ATQA/SAK/ATS
  → classificação conservadora da família
  → refinamento ISO14443-A quando necessário
  → plano de comandos read-only específico
  → verificação de que o mesmo UID permanece presente
  → coleta de arquivos gerados pelo cliente
  → importação pelo motor normalizado
  → relatório, evidência bruta e auditoria
```

Cada leitura é registrada nas tabelas `smart_scan_jobs` e `smart_scan_steps`. A saída original do cliente é preservada localmente e o resultado estruturado aparece em **Proxmark3 → Leituras**.

## Planos por família

| Família | Aquisição automática |
|---|---|
| MIFARE Classic | `hf mf info`, NDEF opcional e tentativa de `hf mf dump` com chaves já disponíveis |
| MIFARE Ultralight/NTAG | `hf mfu info`, NDEF e `hf mfu dump` |
| MIFARE Plus | `hf mfp info`, ACL, MAD, NDEF e tentativa de dump |
| DESFire | informações, versão, UID quando permitido, memória livre, AIDs e estrutura pública |
| NTAG 424 DNA | informações públicas do chip |
| ISO14443-A/B | identificação e tentativa NDEF compatível |
| ISO15693 | identificação pública |
| FeliCa | informações e códigos de sistema públicos |
| Topaz | informações públicas |

Falhas opcionais não interrompem o restante da coleta. Falhas obrigatórias, troca de cartão, timeout total ou cancelamento encerram o fluxo de forma controlada.

## Limite de segurança

O orquestrador possui allowlist própria, separada do modo manual. Ele não executa:

- recuperação ou brute force de chaves;
- `autopwn`, nested, hardnested ou darkside;
- escrita, restauração, formatação ou alteração de chave;
- simulação, emulação, replay ou sniffing;
- APDUs arbitrários;
- caminhos de saída escolhidos pelo navegador.

Argumentos de arquivo aceitam somente nomes simples dentro de `runtime/smart_scans/scan-XXXXXX`. O subprocesso continua com `shell=False`.

## MIFARE Classic

Um dump completo depende das chaves já conhecidas. Configure opcionalmente um arquivo de chaves local em **Configuração local do cliente**. O arquivo é copiado para o diretório isolado da leitura e não é exposto pela API.

A leitura inteligente não tenta descobrir chaves ausentes. Quando o dump não pode ser produzido, o trabalho termina como `metadata_only` ou `partial`, mantendo as informações de identificação obtidas.

## Consistência do cartão

Por padrão, o fluxo aborta quando um UID diferente aparece em uma etapa posterior. Isso reduz o risco de unir dados de dois cartões. Para cartões com UID aleatório explicitamente informado pelo cliente, a comparação rígida é relaxada e o relatório registra essa condição.

## Limites operacionais

Variáveis disponíveis:

```text
UTAMO_SMART_SCAN_DIR
UTAMO_SMART_SCAN_MAX_COMMANDS
UTAMO_SMART_SCAN_TOTAL_TIMEOUT
UTAMO_SMART_AUTO_DUMP
UTAMO_SMART_READ_NDEF
```

O cancelamento é verificado durante a execução e entre etapas. O runner encerra o processo do cliente; no Windows, também tenta finalizar a árvore do wrapper/processo pelo PID.

## Validação física

Os testes automatizados usam um executor simulado e dumps sanitizados. Valide em hardware real:

1. cartão Classic conhecido e arquivo de chaves correspondente;
2. Ultralight/NTAG sem senha;
3. cartão protegido para confirmar resultado parcial;
4. remoção/troca do cartão durante a leitura;
5. cancelamento durante um comando;
6. cliente e firmware Iceman do mesmo commit ou release.
