from typing import Annotated, Literal

from fastapi import APIRouter, Body, HTTPException, Path, Query, status

from labs.lab03 import repository
from labs.lab03.schemas import RecordCreate, RecordRead, RecordReplace

router = APIRouter()


@router.get(
    "",
    response_model=list[RecordRead],
    summary="Список записів із фільтрами та пагінацією",
)
def list_records_endpoint(
    category_id: Annotated[
        int | None,
        Query(gt=0, description="Фільтр за id категорії"),
    ] = None,
    status_filter: Annotated[
        Literal["new", "in_progress", "done"] | None,
        Query(alias="status", description="Фільтр за статусом"),
    ] = None,
    min_value: Annotated[
        float | None,
        Query(ge=0.0, description="Мінімальне значення тривалості (хв)"),
    ] = None,
    q: Annotated[
        str | None,
        Query(min_length=1, max_length=120, description="Підрядок для пошуку в назві"),
    ] = None,
    limit: Annotated[
        int,
        Query(ge=1, le=100, description="Кількість записів"),
    ] = 20,
    offset: Annotated[
        int,
        Query(ge=0, description="Зсув вибірки"),
    ] = 0,
) -> list[dict]:
    return repository.list_records(
        category_id=category_id,
        status=status_filter,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримання окремого запису",
    responses={404: {"description": "Запис не знайдено"}},
)
def get_record_endpoint(
    record_id: Annotated[int, Path(gt=0, description="Ідентифікатор запису")],
) -> dict:
    try:
        return repository.get_record_by_id(record_id)
    except repository.NotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(err)
        ) from err


@router.post(
    "",
    response_model=RecordRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створення окремого запису",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Запис із таким кодом вже існує"},
    },
)
def create_record_endpoint(payload: RecordCreate) -> dict:
    try:
        return repository.create_record(payload)
    except repository.CategoryNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(err)
        ) from err
    except repository.ConflictError as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(err)
        ) from err


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повна заміна змінюваних полів запису",
    responses={
        404: {"description": "Запис або категорію не знайдено"},
        409: {"description": "Конфлікт дублікату коду"},
    },
)
def update_record_endpoint(
    payload: RecordReplace,
    record_id: Annotated[int, Path(gt=0, description="Ідентифікатор запису")],
) -> dict:
    try:
        return repository.update_record(record_id, payload)
    except repository.CategoryNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(err)
        ) from err
    except repository.NotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(err)
        ) from err
    except repository.ConflictError as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(err)
        ) from err


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалення запису",
    responses={404: {"description": "Запис не знайдено"}},
)
def delete_record_endpoint(
    record_id: Annotated[int, Path(gt=0, description="Ідентифікатор запису")],
) -> None:
    try:
        repository.delete_record(record_id)
    except repository.NotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(err)
        ) from err


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
    summary="Пакетне створення записів в одній транзакції",
    responses={
        404: {"description": "Одну з категорій не знайдено"},
        409: {"description": "Дублікат коду в базі чи пакеті"},
    },
)
def bulk_create_records_endpoint(
    payload: Annotated[
        list[RecordCreate],
        Body(
            min_length=1,
            max_length=100,
            description="JSON-масив об'єктів для додавання (від 1 до 100)",
        ),
    ],
) -> list[dict]:
    try:
        return repository.bulk_create_records(payload)
    except repository.CategoryNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(err)
        ) from err
    except repository.ConflictError as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(err)
        ) from err
