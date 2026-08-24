# Utamo RF Lab - RFID Card Dump Analyzer

## Implementado
- Parser `.eml`
- Parser `.bin` / `.dump`
- Parser `.json`
- Análise MIFARE Classic setor/bloco
- Detecção de trailer block
- Extração Key A / Key B
- Extração Access Bits
- Heurística MAD/AID
- Extração UID/SAK/ATQA quando presente no metadata ou inferível
- Comparação entre dumps
- Clone detection por similaridade estrutural
- Análise de setores/blocos vazios
- Detecção de chaves padrão/teste
- Relatório forense JSON
- Importação de dump pela interface
- Endpoint `/api/rf/card-dump/analyze`
- Endpoint `/api/rf/card-dump/compare`
- Endpoint `/api/rf/card-dump/list`

## Tela
- `/rf/card-dumps`

## Observações
- O analisador é estático/forense e não executa cracking, brute force, replay, emulação ou clonagem.
- Access bits são extraídos e destacados; validação completa bit-a-bit pode ser aprofundada em etapa posterior.
- UID/SAK/ATQA nem sempre aparecem em dumps brutos de setor; quando ausentes, o sistema tenta inferir UID do bloco 0.

## Teste rápido API
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/rf/card-dump/analyze" -Method POST -ContentType "application/json" -Body '{"name":"teste.eml","content":"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n000000000000FF078069FFFFFFFFFFFF"}'
