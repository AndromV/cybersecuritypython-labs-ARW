import json
import logging
import sqlite3
from contextlib import closing
from pathlib import Path

from pydantic import ValidationError

from labs.lab03.database import get_connection, initialize_database
from labs.lab03.schemas import RecordCreate

BASE_DIR = Path(__file__).resolve().parent
SEED_DATA_PATH = BASE_DIR / "data" / "seed.json"

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("seed")


def seed_database() -> None:
    initialize_database()

    if not SEED_DATA_PATH.exists():
        logger.error("Файл початкових даних не знайдено: %s", SEED_DATA_PATH)
        return

    try:
        content = SEED_DATA_PATH.read_text(encoding="utf-8")
        data = json.loads(content)
    except (OSError, json.JSONDecodeError) as err:
        logger.error("Помилка парсингу seed.json: %s", err)
        return

    categories = data.get("categories", [])
    records = data.get("records", [])

    if len(categories) != 3 or len(records) != 8:
        logger.error(
            "Некоректна кількість початкових даних: очікується 3 категорії та 8 записів."
        )
        return

    try:
        for rec in records:
            RecordCreate(**rec)
    except ValidationError as err:
        logger.error("Помилка валідації початкових записів через Pydantic: %s", err)
        return

    with closing(get_connection()) as conn:
        cat_count = conn.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
        rec_count = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]

        if cat_count > 0 or rec_count > 0:
            print("База даних уже містить дані. Початкове заповнення пропущено.")
            return

        try:
            with conn:
                for cat in categories:
                    conn.execute(
                        "INSERT INTO categories (id, name) VALUES (?, ?)",
                        (cat["id"], cat["name"]),
                    )
                for rec in records:
                    conn.execute(
                        """
                        INSERT INTO records (code, title, category_id, value, status)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            rec["code"],
                            rec["title"],
                            rec["category_id"],
                            rec["value"],
                            rec["status"],
                        ),
                    )
            print("Початкові дані успішно завантажено (3 категорії, 8 записів).")
        except sqlite3.Error as err:
            logger.error("Помилка транзакції при заповненні бази: %s", err)
            raise


if __name__ == "__main__":
    seed_database()
