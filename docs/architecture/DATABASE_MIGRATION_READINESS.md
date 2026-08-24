# RFLAB DATABASE MIGRATION READINESS — Preparação para banco maior

Estado atual: **SQLite** (`runtime/utamo_rfid_lab.db`), WAL, `busy_timeout=30s`, `synchronous=NORMAL`, `foreign_keys=ON`, schema versionado (tabela `schema_migrations`, versão 6; arquivos de referência em `migrations/*.sql`).

Decisão do briefing: **não migrar agora**. Este documento mapeia acoplamentos e o caminho seguro para uma migração futura.

## 1. Camada de acesso atual

* Ponto único: `app/database/db.py`
  * `get_connection()` / `get_conn()` (alias de compatibilidade) — fábrica única de conexão.
  * `transaction()` — contextmanager `BEGIN IMMEDIATE` + commit/rollback.
  * `init_db()` — criação idempotente de schema + registro de migrations.
* Todas as consultas são **parametrizadas** (`?`) — nenhuma concatenação SQL dinâmica encontrada (duas ocorrências de colunas fixas por literal comentadas com `noqa: S608`; valores sempre parametrizados).
* Timestamps: strings locais `YYYY-MM-DD HH:MM:SS` via `now_str()` — portável textualmente, porém não TZ-aware.

## 2. Acoplamentos identificados

| Acoplamento | Risco pós-migração | Preparação recomendada |
|---|---|---|
| SQLite específico: `PRAGMA journal_mode=WAL`, `BEGIN IMMEDIATE`, `AUTOINCREMENT`, `INSERT OR IGNORE/CONFLICT` | Médio — sintaxe suportada por Postgres com ajustes | Concentrar PRAGMAs atrás de flag de engine em `get_connection()` |
| Conexões abertas/fechadas por operação (sem pool) | Baixo no SQLite; alto sem pool em servidor remoto | Introduzir pool/factory configurável por `DATABASE_URL` |
| Locks em memória por porta (`_port_lock`) e threads de job | Exige single-process | Manter contrato single-process ou externalizar jobs |
| `get_setting/set_setting` como KV genérico | Baixo | Já é boundary natural (repository-like) |
| Datas como TEXT | Médio para ordenação cross-TZ | Migração futura: converter para UTC ISO-8601 |

## 3. Itens já prontos

* Fábrica central de conexão (um único ponto a alterar).
* Consultas parametrizadas em 100% do código.
* Paginação/limites presentes nos listadores (`LIMIT ?` com clamp).
* Índices cobrindo os acessos principais (`created_at`, `uid`, `dump_id`, `status+updated_at`, etc.).
* Schema versionado com tabela de migrations própria (mecanismo independente de ORM).
* Backup: copiar arquivo do banco com app parado (documentado no README; WAL permite snapshot quente com `VACUUM INTO`).

## 4. Estratégia recomendada quando houver necessidade real

1. Introduzir `DATABASE_URL` em `Config` mantendo SQLite como default.
2. Extrair repositórios mínimos (settings, dumps, sessions, smart scans) mantendo SQL atual.
3. Converter timestamps para ISO-8601 UTC na escrita (leitura tolerante ao formato antigo).
4. Criar migration idempotente de dados (ETL via `tools/migrate_legacy_db.py` estendido).
5. Só então avaliar ORM — não introduzido por estética nesta fase.

## Conclusão

DB MIGRATION READINESS: **PASS (preparado, sem migração executada)**. Nenhuma alteração de schema foi feita nesta auditoria.
