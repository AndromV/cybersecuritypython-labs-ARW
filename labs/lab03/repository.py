import sqlite3
from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection
from labs.lab03.schemas import RecordCreate, RecordReplace


class RepositoryError(Exception):
    """Базовий виняток шару репозиторію."""


class NotFoundError(RepositoryError):
    """Ресурс не знайдено (HTTP 404)."""


class ConflictError(RepositoryError):
    """Конфлікт унікальності або обмежень цілісності (HTTP 409)."""


class CategoryNotFoundError(NotFoundError):
    """Категорію не знайдено (HTTP 404)."""


class CategoryNotEmptyError(ConflictError):
    """Категорія містить пов'язані записи (HTTP 409)."""


def create_category(name: str) -> dict[str, Any]:
    with closing(get_connection()) as conn:
        try:
            with conn:
                cursor = conn.execute(
                    "INSERT INTO categories (name) VALUES (?)",
                    (name,),
                )
                category_id = cursor.lastrowid
            return {"id": category_id, "name": name}
        except sqlite3.IntegrityError as err:
            raise ConflictError(f"Категорія з назвою '{name}' вже існує.") from err


def get_categories() -> list[dict[str, Any]]:
    with closing(get_connection()) as conn:
        rows = conn.execute(
            "SELECT id, name FROM categories ORDER BY id ASC"
        ).fetchall()
        return [{"id": row[0], "name": row[1]} for row in rows]


def get_category_by_id(category_id: int) -> dict[str, Any]:
    with closing(get_connection()) as conn:
        row = conn.execute(
            "SELECT id, name FROM categories WHERE id = ?",
            (category_id,),
        ).fetchone()
        if not row:
            raise NotFoundError(f"Категорію з id={category_id} не знайдено.")
        return {"id": row[0], "name": row[1]}


def delete_category(category_id: int) -> None:
    with closing(get_connection()) as conn:
        row = conn.execute(
            "SELECT id FROM categories WHERE id = ?",
            (category_id,),
        ).fetchone()
        if not row:
            raise NotFoundError(f"Категорію з id={category_id} не знайдено.")

        count = conn.execute(
            "SELECT COUNT(*) FROM records WHERE category_id = ?",
            (category_id,),
        ).fetchone()[0]
        if count > 0:
            raise CategoryNotEmptyError(
                f"Неможливо видалити категорію з id={category_id}, оскільки вона містить {count} запис(ів)."
            )

        with conn:
            conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))


def create_record(record_data: RecordCreate) -> dict[str, Any]:
    with closing(get_connection()) as conn:
        cat = conn.execute(
            "SELECT name FROM categories WHERE id = ?",
            (record_data.category_id,),
        ).fetchone()
        if not cat:
            raise CategoryNotFoundError(
                f"Категорію з id={record_data.category_id} не знайдено."
            )

        try:
            with conn:
                cursor = conn.execute(
                    """
                    INSERT INTO records (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        record_data.code,
                        record_data.title,
                        record_data.category_id,
                        record_data.value,
                        record_data.status,
                    ),
                )
                rec_id = cursor.lastrowid
            return {
                "id": rec_id,
                "code": record_data.code,
                "title": record_data.title,
                "category_id": record_data.category_id,
                "value": record_data.value,
                "status": record_data.status,
                "category_name": cat[0],
            }
        except sqlite3.IntegrityError as err:
            raise ConflictError(
                f"Запис із кодом '{record_data.code}' вже існує."
            ) from err


def get_record_by_id(record_id: int) -> dict[str, Any]:
    with closing(get_connection()) as conn:
        row = conn.execute(
            """
            SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name
            FROM records r
            JOIN categories c ON r.category_id = c.id
            WHERE r.id = ?
            """,
            (record_id,),
        ).fetchone()
        if not row:
            raise NotFoundError(f"Запис із id={record_id} не знайдено.")
        return {
            "id": row[0],
            "code": row[1],
            "title": row[2],
            "category_id": row[3],
            "value": row[4],
            "status": row[5],
            "category_name": row[6],
        }


def list_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    with closing(get_connection()) as conn:
        conditions: list[str] = []
        params: list[Any] = []

        if category_id is not None:
            conditions.append("r.category_id = ?")
            params.append(category_id)
        if status is not None:
            conditions.append("r.status = ?")
            params.append(status)
        if min_value is not None:
            conditions.append("r.value >= ?")
            params.append(min_value)
        if q is not None and len(q) > 0:
            conditions.append("instr(r.title, ?) > 0")
            params.append(q)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        sql = f"""
            SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name
            FROM records r
            JOIN categories c ON r.category_id = c.id
            {where_clause}
            ORDER BY r.id ASC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        rows = conn.execute(sql, tuple(params)).fetchall()
        return [
            {
                "id": row[0],
                "code": row[1],
                "title": row[2],
                "category_id": row[3],
                "value": row[4],
                "status": row[5],
                "category_name": row[6],
            }
            for row in rows
        ]


def update_record(
    record_id: int,
    record_data: RecordReplace,
) -> dict[str, Any]:
    with closing(get_connection()) as conn:
        rec = conn.execute(
            "SELECT id FROM records WHERE id = ?",
            (record_id,),
        ).fetchone()
        if not rec:
            raise NotFoundError(f"Запис із id={record_id} не знайдено.")

        cat = conn.execute(
            "SELECT name FROM categories WHERE id = ?",
            (record_data.category_id,),
        ).fetchone()
        if not cat:
            raise CategoryNotFoundError(
                f"Категорію з id={record_data.category_id} не знайдено."
            )

        try:
            with conn:
                conn.execute(
                    """
                    UPDATE records
                    SET code = ?, title = ?, category_id = ?, value = ?, status = ?
                    WHERE id = ?
                    """,
                    (
                        record_data.code,
                        record_data.title,
                        record_data.category_id,
                        record_data.value,
                        record_data.status,
                        record_id,
                    ),
                )
            return {
                "id": record_id,
                "code": record_data.code,
                "title": record_data.title,
                "category_id": record_data.category_id,
                "value": record_data.value,
                "status": record_data.status,
                "category_name": cat[0],
            }
        except sqlite3.IntegrityError as err:
            raise ConflictError(
                f"Запис із кодом '{record_data.code}' вже існує."
            ) from err


def delete_record(record_id: int) -> None:
    with closing(get_connection()) as conn:
        rec = conn.execute(
            "SELECT id FROM records WHERE id = ?",
            (record_id,),
        ).fetchone()
        if not rec:
            raise NotFoundError(f"Запис із id={record_id} не знайдено.")

        with conn:
            conn.execute("DELETE FROM records WHERE id = ?", (record_id,))


def bulk_create_records(records_data: list[RecordCreate]) -> list[dict[str, Any]]:
    codes = [item.code for item in records_data]
    if len(codes) != len(set(codes)):
        raise ConflictError(
            "Пакет містить дубльовані коди записів всередині тіла запиту."
        )

    with closing(get_connection()) as conn:
        category_ids = {item.category_id for item in records_data}
        placeholders = ",".join("?" for _ in category_ids)
        existing_categories = {
            row[0]
            for row in conn.execute(
                f"SELECT id FROM categories WHERE id IN ({placeholders})",
                tuple(category_ids),
            ).fetchall()
        }
        missing_categories = category_ids - existing_categories
        if missing_categories:
            missing_str = ", ".join(str(cid) for cid in sorted(missing_categories))
            raise CategoryNotFoundError(f"Категорії з id [{missing_str}] не знайдено.")

        try:
            with conn:
                cat_map = {
                    row[0]: row[1]
                    for row in conn.execute(
                        "SELECT id, name FROM categories"
                    ).fetchall()
                }
                created_records: list[dict[str, Any]] = []
                for item in records_data:
                    cursor = conn.execute(
                        """
                        INSERT INTO records (code, title, category_id, value, status)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            item.code,
                            item.title,
                            item.category_id,
                            item.value,
                            item.status,
                        ),
                    )
                    created_records.append(
                        {
                            "id": cursor.lastrowid,
                            "code": item.code,
                            "title": item.title,
                            "category_id": item.category_id,
                            "value": item.value,
                            "status": item.status,
                            "category_name": cat_map[item.category_id],
                        }
                    )
                return created_records
        except sqlite3.IntegrityError as err:
            raise ConflictError(
                "Дублікат коду або порушення обмежень цілісності у базі даних."
            ) from err
