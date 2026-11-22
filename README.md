# tgkeyhunt

Оборонительный аудит утекших токенов Telegram Bot API в локальных файлах.
Ищет строку вида `<id>:<secret>`, считает энтропию секрета, определяет уверенность
и делает отчёт. Полные секреты в результат не пишутся.

Проект не обращается к Telegram, не проверяет ключи, не подбирает токены и не
обходил авторизацию. Все строки в примерах фейковые и содержат `FAKE`.

## Что умеет

- искать кандидатов по формату `123456789:...`;
- считать энтропию Шеннона секрета;
- делить находки на `high`, `medium` и `low`;
- пропускать бинарники, большие файлы и служебные каталоги;
- маскировать секреты — в отчёте только `bot_id`, длина и энтропия;
- строить Markdown-отчёт с рекомендациями.

## Части проекта

- `rust/` — ядро: детект, энтропия, обход каталога, C ABI и CLI `tgkeyhunt`.
- `go/` — параллельный сканер, CLI `tgkeyscan`.
- `python/` — Markdown-отчёт.
- `examples/fixtures/` — тестовые файлы с фейковыми токенами.

## Быстрый старт

```bash
make test
make demo
```

Демо создаёт `examples/findings.json` и `examples/report.md`.

## CLI

```bash
cargo run --manifest-path Cargo.toml --bin tgkeyhunt -- scan examples/fixtures

(cd go && go run ./cmd/tgkeyscan \
  --dir ../examples/fixtures --out ../examples/findings.json)

(cd python && PYTHONPATH=. python3 -m tgkeyhunt.report \
  examples/findings.json examples/report.md)
```

## C ABI

Заголовок: `include/tgkeyhunt.h`.

```c
int th_scan_text(const char *text, const char *file,
                 char **out_json, int *out_len);
void th_free(char *ptr);
```

Подробный контракт всех модулей лежит в `SPEC.md`.
