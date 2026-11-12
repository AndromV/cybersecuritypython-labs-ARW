# Лабораторна робота №3: Прикладні бібліотеки Python для побудови вебзастосунків

## Загальна інформація
- **Студент:** Романюк Андрій Володимирович
- **Група:** КБ-208
- **Варіант:** №9
- **Предметна область:** «Облік часу опрацювання повідомлень»
- **Одиниця вимірювання (`unit`):** хвилини (`minutes`)
- **Поріг реагування (`threshold`):** 15.0 хв.
- **Фіксовані категорії:** `siem` (id: 1), `helpdesk` (id: 2), `monitoring` (id: 3)
- **Мета роботи:** Опанувати розробку Web API за допомогою FastAPI, роботу з реляційною базою даних SQLite через параметризовані SQL-запити, механізм транзакцій, валідацію вхідних даних із Pydantic 2, структурування коду за архітектурним патерном розділення відповідальності та перевірку коду лінтером Ruff.

---

## 1. Структура проєкту

```text
cybersecurity-python-labs/
├── .gitignore
├── requirements.txt
├── shared/
│   ├── __init__.py
│   └── student.py              # Відомості про студента (Романюк А. В., КБ-208, вар. 9)
└── labs/
    ├── __init__.py
    ├── lab01/
    ├── lab02/
    └── lab03/
        ├── __init__.py
        ├── README.md           # Документація запуску
        ├── config.py           # Константи предметної області, обмеження та одиниці виміру
        ├── schema.sql          # Готова реляційна схема таблиць categories та records
        ├── database.py         # Керування з'єднанням SQLite та PRAGMA foreign_keys = ON
        ├── schemas.py          # Pydantic-моделі валідації запитів та відповідей
        ├── repository.py       # Шар доступу до даних (DAL) з параметризованими SQL-запитами
        ├── seed.py             # Скрипт первинного заповнення бази з JSON
        ├── main.py             # FastAPI-застосунок, lifespan та системні маршрути
        ├── routers/
        │   ├── __init__.py
        │   ├── categories.py   # Ендпоінти для керування категоріями
        │   └── records.py      # Ендпоінти CRUD, фільтрації та пакетного додавання (bulk)
        └── data/
            ├── seed.json       # Навчальний набір початкових даних (3 категорії, 8 записів)
            └── lab3.sqlite3    # Робочий файл бази SQLite (додано до .gitignore)
```

---

## 2. Налаштування середовища та конфігураційні файли

### 2.1. `requirements.txt` (у корені репозиторію)
```text
fastapi
uvicorn
pydantic
ruff
```

### 2.2. `.gitignore` (доповнення в корені репозиторію)
```gitignore
labs/lab03/data/*.sqlite3
labs/lab03/data/*.sqlite3-*
labs/lab03/data/*.db
labs/lab03/data/*.db-*
```

## 3. Інструкція із запуску програми

Усі команди виконуються в терміналі з **кореня репозиторію** в середовищі Python 3.10+:

### 3.1. Встановлення залежностей
```powershell
pip install -r requirements.txt
```

### 3.2. Створення та ініціалізація бази даних
```powershell
# Створення схеми таблиць за готовим SQL
python -m labs.lab03.database

# Заповнення початковими даними Варіанта 9 (3 категорії, 8 записів)
python -m labs.lab03.seed
```

### 3.3. Запуск вебсервера розробки (Uvicorn)
```powershell
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```
Після старту вебсервісу:
- **Swagger UI:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 4. Документація API та приклади перевірки всіх 14 сценаріїв (cURL)

Нижче наведено команди для перевірки обов'язкових сценаріїв лабораторної роботи (розділ «Завдання 3», виконано у Git Bash):

### Сценарій 1: Повторне заповнення бази
```powershell
python -m labs.lab03.seed
# Очікувано: Повідомлення про наявність даних у базі, дублікати не створюються.
```

### Сценарій 2: Перевірка службових маршрутів та списку категорій
```powershell
curl -i "http://127.0.0.1:8000/ping"
# Очікувано: 200 OK, {"status": "ok"}

curl -i "http://127.0.0.1:8000/student"
# Очікувано: 200 OK, {"student_name": "Романюк Андрій Володимирович", "group_name": "КБ-208", "variant_number": 9}

curl -i "http://127.0.0.1:8000/categories"
# Очікувано: 200 OK, список 3 категорій (siem, helpdesk, monitoring)
```

### Сценарій 3: Повний цикл CRUD окремого запису
```powershell
# Create (POST)
curl -i -X POST "http://127.0.0.1:8000/records" `
  -H "Content-Type: application/json" `
  -d '{"code": "V09-CRUD", "title": "Нове тестове вимірювання", "category_id": 1, "value": 11.2, "status": "new"}'
# Очікувано: 201 Created (id=9)

# Read (GET)
curl -i "http://127.0.0.1:8000/records/9"
# Очікувано: 200 OK

# Update (PUT)
curl -i -X PUT "http://127.0.0.1:8000/records/9" `
  -H "Content-Type: application/json" `
  -d '{"code": "V09-CRUD", "title": "Оновлене тестове вимірювання", "category_id": 1, "value": 13.0, "status": "done"}'
# Очікувано: 200 OK

# Delete (DELETE)
curl -i -X DELETE "http://127.0.0.1:8000/records/9"
# Очікувано: 204 No Content
```

### Сценарій 4: Фільтри вибірки та пагінація
```powershell
curl -i "http://127.0.0.1:8000/records?category_id=1&status=new&min_value=5.0&limit=5&offset=0"
# Очікувано: 200 OK, відфільтровані результати за зростанням id
```

### Сценарій 5: Валідація некоректних полів
```powershell
curl -i -X POST "http://127.0.0.1:8000/records" `
  -H "Content-Type: application/json" `
  -d '{"code": "V09-ERR", "title": "   ", "category_id": 1, "value": -2.0, "status": "invalid_status"}'
# Очікувано: 422 Unprocessable Entity, база залишається без змін
```

### Сценарій 6: Валідація некоректного типу або нескінченності
```powershell
curl -i -X POST "http://127.0.0.1:8000/records" `
  -H "Content-Type: application/json" `
  -d '{"code": "V09-NAN", "title": "Некоректне значення", "category_id": 1, "value": "не_число", "status": "new"}'
# Очікувано: 422 Unprocessable Entity
```

### Сценарій 7: Запит неіснуючого ресурсу
```powershell
curl -i "http://127.0.0.1:8000/records/999"
# Очікувано: 404 Not Found

curl -i -X POST "http://127.0.0.1:8000/records" `
  -H "Content-Type: application/json" `
  -d '{"code": "V09-NOCAT", "title": "Неіснуюча категорія", "category_id": 999, "value": 10.0, "status": "new"}'
# Очікувано: 404 Not Found
```

### Сценарій 8: Порушення унікальності коду та назви категорії
```powershell
curl -i -X POST "http://127.0.0.1:8000/records" `
  -H "Content-Type: application/json" `
  -d '{"code": "V09-01", "title": "Спроба дублювання", "category_id": 1, "value": 10.0, "status": "new"}'
# Очікувано: 409 Conflict

curl -i -X POST "http://127.0.0.1:8000/categories" `
  -H "Content-Type: application/json" `
  -d '{"name": "siem"}'
# Очікувано: 409 Conflict
```

### Сценарій 9: Видалення непорожньої та порожньої категорії
```powershell
# Спроба видалити категорію siem (містить записи)
curl -i -X DELETE "http://127.0.0.1:8000/categories/1"
# Очікувано: 409 Conflict (ON DELETE RESTRICT)

# Створення та видалення порожньої категорії
curl -i -X POST "http://127.0.0.1:8000/categories" `
  -H "Content-Type: application/json" `
  -d '{"name": "temporary"}'
# Очікувано: 201 Created (наприклад id=4)

curl -i -X DELETE "http://127.0.0.1:8000/categories/4"
# Очікувано: 204 No Content
```

### Сценарій 10: Успішний атомарний пакет
```powershell
curl -i -X POST "http://127.0.0.1:8000/records/bulk" `
  -H "Content-Type: application/json" `
  -d '[
    {"code": "V09-BULK-01", "title": "Пакетне вимірювання 1", "category_id": 1, "value": 8.0, "status": "new"},
    {"code": "V09-BULK-02", "title": "Пакетне вимірювання 2", "category_id": 2, "value": 14.0, "status": "new"}
  ]'
# Очікувано: 201 Created, обидва записи додано
```

### Сценарій 11: Скасування пакета при конфлікті коду (Rollback)
```powershell
curl -i -X POST "http://127.0.0.1:8000/records/bulk" `
  -H "Content-Type: application/json" `
  -d '[
    {"code": "V09-ROLLBACK", "title": "Перший запис", "category_id": 1, "value": 10.0, "status": "new"},
    {"code": "V09-01", "title": "Дублікат із бази", "category_id": 2, "value": 12.0, "status": "new"}
  ]'
# Очікувано: 409 Conflict. Запис V09-ROLLBACK НЕ додається до бази (транзакцію скасовано).
```

### Сценарій 12: Скасування пакета при неіснуючій категорії
```powershell
curl -i -X POST "http://127.0.0.1:8000/records/bulk" `
  -H "Content-Type: application/json" `
  -d '[
    {"code": "V09-NOT-SAVED", "title": "Не має зберегтися", "category_id": 1, "value": 5.0, "status": "new"},
    {"code": "V09-NEW-02", "title": "Погана категорія", "category_id": 9999, "value": 5.0, "status": "new"}
  ]'
# Очікувано: 404 Not Found. Жоден запис не зберігається.
```

### Сценарій 13: Захист від SQL-ін'єкцій при пошуку
```powershell
curl -i "http://127.0.0.1:8000/records?q=%27%20OR%201=1--"
# Очікувано: 200 OK, повертає порожній масив або безпечний збіг підрядка; SQL-ін'єкція нейтралізована через параметризацію instr(title, ?).
```

### Сценарій 14: Збереження стану після перезапуску сервера
```powershell
# 1. Зупинити сервер (Ctrl+C).
# 2. Запустити uvicorn повторно:
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000

# 3. Перевірити збережені дані:
curl -i "http://127.0.0.1:8000/records/1"
# Очікувано: 200 OK, дані успішно завантажено з файлу data/lab3.sqlite3
```

---

## 5. Контроль якості та стилю коду (Ruff)

Усі файли повністю відповідають вимогам стандарту PEP 8:

```powershell
# Перевірка на помилки та дотримання правил лінтера
ruff check labs/lab03/

# Перевірка форматування коду
ruff format --check labs/lab03/

# Автоматичне виправлення та переформатування (за потреби)
ruff check --fix labs/lab03/
ruff format labs/lab03/
```
