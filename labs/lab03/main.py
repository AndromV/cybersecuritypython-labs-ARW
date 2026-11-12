"""Точка входу FastAPI-застосунку для Варіанта 9."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from labs.lab03.config import DOMAIN_DESCRIPTION, DOMAIN_TITLE, THRESHOLD, UNIT
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from labs.lab03.schemas import StudentRead
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("lab03")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Життєвий цикл сервісу: автоматичне створення структури таблиць під час старту."""
    logger.info("Перевірка та ініціалізація структури бази SQLite...")
    initialize_database()
    logger.info("Базу даних успішно ініціалізовано.")
    yield


app = FastAPI(
    title=f"Варіант {VARIANT_NUMBER}: {DOMAIN_TITLE}",
    description=(
        f"{DOMAIN_DESCRIPTION}\n\n"
        f"**Одиниця вимірювання:** `{UNIT}`\n\n"
        f"**Поріг реагування:** `{THRESHOLD}` хв."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(categories.router, prefix="/categories", tags=["Категорії"])
app.include_router(records.router, prefix="/records", tags=["Записи"])


@app.get("/ping", tags=["Системні"], summary="Перевірка доступності сервісу")
def ping() -> dict[str, str]:
    """Перевірка працездатності Web API."""
    return {"status": "ok"}


@app.get(
    "/student",
    response_model=StudentRead,
    tags=["Системні"],
    summary="Відомості про автора роботи",
)
def get_student() -> StudentRead:
    """Отримати дані студента з shared/student.py."""
    return StudentRead(
        student_name=STUDENT_NAME,
        group_name=GROUP_NAME,
        variant_number=VARIANT_NUMBER,
    )
