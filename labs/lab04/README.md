# Лабораторна робота №4: Інтеграція із зовнішніми Web API та автоматизоване тестування Python-коду

## Номер варіанта та правило відбору
- **Варіант:** `9` (зчитується з `shared/student.py`)
- **Напрям відбору:** Локальний вектор атаки
- **Умова правила:** `score >= 5.0` та `cvssData.attackVector == "LOCAL"` у межах вибраної оцінки CVSS v3.1

**Пояснення метрики:** поле `attackVector` у CVSS v3.1 визначає спосіб доступу для експлуатації вразливості (`NETWORK`, `ADJACENT_NETWORK`, `LOCAL`, `PHYSICAL`). Значення `LOCAL` означає, що атака не виконується віддалено через мережу — зловмисник повинен мати локальний доступ до цільової системи (локальний термінал або вже запущений процес). Якщо оцінка `>= 5.0` і вектор дорівнює `LOCAL`, запис отримує стан `review`, інакше — `other`.

## Встановлення залежностей
Усі команди виконуються з кореня репозиторію в активованому віртуальному середовищі (Python 3.12+):

```bash
pip install -r requirements.txt
```

Використані пакети: `requests`, `pytest`, `ruff`.

## Команди запуску в обох режимах

### 1. Локальний режим (без мережевих запитів, читання з JSON-файла)
```bash
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```

### 2. Мережевий режим (запит до NVD CVE API 2.0)
```bash
python -m labs.lab04.main --cve CVE-2021-44228
```
За потреби ключ доступу передається через змінну середовища `NVD_API_KEY` (клієнт додає його в HTTP-заголовок `apiKey`; без змінної запит виконується публічно).

## Формат звіту
На успішному завершенні (код виходу `0`) утиліта виводить у `stdout` один JSON-об'єкт (помилки виводяться у `stderr` з кодами `1` або `2`).

Приклад вихідного JSON-звіту для синтетичного запису `CVE-2099-10001` (варіант 9):
```json
{
  "cve_id": "CVE-2099-10001",
  "variant": 9,
  "description": "Synthetic vulnerability for offline API testing.",
  "vuln_status": "Analyzed",
  "cvss_version": "3.1",
  "score": 9.8,
  "score_source": "nvd@nist.gov",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "rule": {
    "threshold": 5.0,
    "field": "attackVector",
    "expected": "LOCAL"
  },
  "observed": "NETWORK",
  "decision": "other"
}
```

### Опис полів звіту
- `cve_id` — запитаний ідентифікатор CVE;
- `variant` — номер варіанта (`9`);
- `description` — перший непорожній англійський опис вразливості або `null`;
- `vuln_status` — статус запису в NVD (`Analyzed`, `Rejected` тощо) або `null`;
- `cvss_version` — версія метрики (`"3.1"`) або `null`;
- `score` — базова оцінка `baseScore` вибраної метрики CVSS v3.1 (`Primary`, за відсутності — першої у списку) або `null`;
- `score_source` — джерело вибраної оцінки або `null`;
- `vector` — рядок вектора CVSS v3.1 або `null`;
- `rule` — параметри правила варіанта (`threshold`, `field`, `expected`);
- `observed` — фактичне значення `attackVector` у вибраній оцінці або `null`;
- `decision` — підсумкове рішення за пріоритетом перевірок:
  - `not_found` — запис за вказаним CVE не знайдено;
  - `rejected` — запис має статус `Rejected`;
  - `insufficient_data` — відсутній статус, оцінка CVSS v3.1 або поле `attackVector`;
  - `review` — дані повні, `score >= 5.0` і `attackVector == "LOCAL"`;
  - `other` — дані повні, але умова правила не виконується.

## Команди перевірки

### Запуск автоматизованих тестів (pytest)
Тести працюють повністю локально без мережевих запитів (блокування налаштовано у `labs/lab04/tests/conftest.py`):
```bash
python -m pytest labs/lab04/tests -q
```

### Перевірка стилю та форматування коду (Ruff)
```bash
ruff check labs/lab04
ruff format --check labs/lab04
```

### Сценарії тестування для захисту (`labs/lab04/tests/test_lab04.py`)
- **Успішний сценарій:** `test_variant9_threshold_and_feature` перевіряє правило нижче порога (`4.9` -> `other`), рівно на порозі (`5.0` + `LOCAL` -> `review`), вище порога (`8.5` + `LOCAL` -> `review`) та за високої оцінки з іншим вектором (`9.8` + `NETWORK` -> `other`). Тест `test_cli_local_input_success` перевіряє локальний запуск CLI на `nvd_sample.json` із кодом завершення `0`.
- **Помилковий сценарій:** `test_invalid_base_score_raises_value_error` та `test_invalid_variant_field_raises_value_error` перевіряють виклик `ValueError` при некоректних типах/значеннях (`bool`, рядок замість числа, `NaN`, невідомий вектор), а `test_cli_invalid_json_returns_code_1` підтверджує код виходу `1` і виведення помилки у `stderr` для пошкодженого JSON-файла.
