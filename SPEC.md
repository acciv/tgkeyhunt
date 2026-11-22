# tgkeyhunt — общий формат и контракт модулей

## Назначение

tgkeyhunt ищет утекшие токены Telegram Bot API в локальных файлах. Это оборонительный
аудит: энтропия, формат, маскирование и отчёт.

Запрещено и не реализовано: запросы к Telegram, проверка ключей, подбор, обход
авторизации. Все строки в примерах заведомо фейковые и содержат `FAKE`.

## Что считается кандидатом

Строка вида `<id>:<secret>`:

- `id` — от 6 до 12 цифр;
- `secret` — от 30 до 50 символов из набора `A-Z a-z 0-9 _ -`;
- границы: перед `id` и после `secret` не должно быть символов из этого же набора
  или цифры.

Настоящие токены обычно имеют секрет длиной ровно 35 символов, но детектор намеренно
ищет шире, чтобы ловить варианты.

## Метрики

`entropy(secret)` — энтропия Шеннона по символам, битов на символ, округлённая до 2 знаков.

`confidence`:

- `high` — длина секрета ровно 35 и энтропия >= 4.0;
- `medium` — длина 30..50 и энтропия >= 3.5;
- `low` — всё остальное.

`reason`:

- `exact length and high entropy`
- `token-like length and entropy`
- `weak entropy or unusual length`

## Выходной формат findings.json

```json
{
  "scanned_files": 2,
  "skipped_files": 0,
  "findings": [
    {
      "file": "examples/fixtures/app.log",
      "line": 1,
      "column": 1,
      "bot_id": "123456789",
      "secret_length": 35,
      "entropy": 4.21,
      "confidence": "high",
      "reason": "exact length and high entropy"
    }
  ]
}
```

Правила:

- массивы сортируются по `file`, затем `line`, затем `column`;
- полный секрет никогда не попадает в выходной файл: в нём есть только `bot_id`,
  длина и энтропия;
- `skipped_files` — число файлов, пропущенных из-за размера > 1 МБ или бинарного
  содержимого;
- пропускаются каталоги `.git`, `target`, `node_modules`, `__pycache__`.

## Контракт Rust-ядра

Публичные функции `tgkeyhunt_core`:

- `entropy(value: &str) -> f64`
- `scan_text(text: &str, file: &str) -> Vec<Finding>`
- `scan_dir(path: &Path) -> Result<Report, String>`
- `report_json(report: &Report) -> String`

C ABI в `include/tgkeyhunt.h`:

- `int th_scan_text(const char *text, const char *file, char **out_json, int *out_len)`
  — 0 при успехе, 1 при ошибке;
- `void th_free(char *ptr)`.

CLI `tgkeyhunt`:

```
tgkeyhunt scan <path>
```

Печатает findings.json в stdout. При ошибке — stderr и код 1.

Без внешних crates. Минимум 5 тестов в `src/lib.rs`.

## Контракт Go-сканера

Пакет `internal/scan`:

- `ScanFile(path string) ([]Finding, error)`
- `ScanDir(root string) (Report, error)` — параллельный обход через горутины,
  детерминированный результат.
- `WriteReport(path string, report Report) error` — JSON с отступами 2 пробела.

Правила детекта,entropy, confidence и reason полностью совпадают со спецификацией.
Секрет в результат не пишется.

CLI `go/cmd/tgkeyscan/main.go`:

```
tgkeyscan --dir examples/fixtures --out examples/findings.json
```

Минимум 3 теста в `internal/scan/scan_test.go`.

## Контракт Python-отчёта

`python/tgkeyhunt/report.py`:

- `load_report(path: str) -> dict`
- `render_markdown(report: dict) -> str`
- CLI: `python -m tgkeyhunt.report findings.json report.md`

Markdown обязан содержать:

- заголовок `# tgkeyhunt report`;
- таблицу Summary со счётчиками;
- таблицу Findings с колонками File | Line | Confidence | Bot ID | Entropy | Reason;
- раздел Recommendations;
- явную пометку, что все ключи в примерах фейковые.

В отчёте не должно быть ни одного полного секретного значения. Тест обязан это проверять.

Минимум 6 тестов через `unittest`.

## Тесты и демо

- Rust: `cargo test --manifest-path Cargo.toml`
- Go: `cd go && go test ./...`
- Python: `cd python && python3 -m unittest discover -s tests -v`
- `examples/demo.sh`: Go-сканер → Python-отчёт → печать отчёта.

## Важно

- Не использовать сеть в коде и тестах.
- Не писать реальные токены. Только строки с `FAKE`.
- Не делать git commit/push — это делает основной агент.
