# Arquitetura

```text
Navegador/API
  └─ autenticação + CSRF/Bearer + rate limit
      ├─ importação → parser normalizado → evidências/risco → relatório + SQLite
      ├─ comando PM3 → política → validação → subprocess(shell=False) → parser + auditoria
      └─ leitura inteligente → classificação → plano read-only → workspace → analisador normalizado
```

## Limites dos componentes

- `app/__init__.py` cria a aplicação, valida a configuração, registra as rotas e aplica cabeçalhos de segurança.
- `app/security.py` concentra autenticação, autorização, CSRF e limitação de login.
- `app/rf/` contém domínio, análise e orquestração; não depende da interface HTML.
- `app/rf_engine/proxmark3.py` é a única fronteira de execução do cliente externo.
- `app/database/db.py` mantém o schema SQLite, configurações e auditoria.
- `runtime/` é a fronteira de dados locais e não pertence ao código-fonte.

## Pipeline de dumps

1. Detecta formato por conteúdo e extensão.
2. Normaliza páginas de 4 bytes, blocos de 16 bytes ou metadados lógicos.
3. Infere a família somente quando estrutura ou metadados sustentam a conclusão.
4. Extrai identidade e valida BCC quando disponível.
5. Decodifica trailers, Access Bits, Value Blocks, MAD e NDEF aplicáveis.
6. Separa achados, risco e evidência estática.
7. Persiste evidência bruta localmente e mascara dados sensíveis na exportação padrão.

## Fronteira do dispositivo

O parser não depende do Proxmark3. Importações manuais e a leitura inteligente alimentam o mesmo modelo. O runner valida executável, raízes permitidas, porta, comando, caracteres, timeout, diretório de trabalho e confirmação antes de criar um subprocesso sem shell.

## Concorrência e implantação

O fluxo inteligente grava jobs/etapas no SQLite e serializa a porta com locks em memória. Por isso, a topologia suportada é uma única instância e um único processo. Escala horizontal ou múltiplos workers exigiriam fila/lock distribuído e banco servidor, o que não faz parte desta versão.
