# Relatório de validação — versão 3.2

Data: 2026-08-15

## Verificações automatizadas

- suíte Pytest: **40 testes aprovados**;
- Ruff com regras de corretude, segurança e modernização: **aprovado**;
- auditoria de arquivos rastreados e padrões de segredo: **aprovada**;
- verificação de dependências instaladas: **aprovada**;
- parsing de Python/Jinja, sintaxe JavaScript e integridade estrutural do CSS: **aprovados**.

A cobertura inclui parsing MFU/Classic/Plus, UID/BCC, MAD, Value Blocks, mascaramento, política de comandos, autenticação, CSRF, Bearer token, rate limit, CSP estrita, configuração de produção, fluxo inteligente, cancelamento e rejeição de caminhos/comandos inseguros.

## Mudanças estruturais verificadas

- módulos RF/SDR experimentais não registrados foram removidos;
- caches, bancos, dumps, capturas e relatórios operacionais deixaram de ser rastreados;
- arquivos físicos locais foram preservados e permanecem ignorados;
- documentação histórica conflitante foi removida;
- CI cobre Python 3.11, 3.12, 3.13 e 3.14;
- interface ativa não contém estilos, scripts ou handlers inline.

## Limitações da validação

Não havia hardware Proxmark3 conectado. Política, runner, parser e fronteira de subprocesso foram validados, mas comunicação USB/serial e compatibilidade do binário/firmware instalado devem ser testadas no equipamento alvo.

Arquivos operacionais removidos do índice ainda podem existir no histórico Git anterior. Antes de publicar um repositório que já contenha esse histórico, faça uma revisão separada e, se necessário, reescreva-o com uma ferramenta apropriada; essa operação destrutiva não faz parte desta limpeza.
