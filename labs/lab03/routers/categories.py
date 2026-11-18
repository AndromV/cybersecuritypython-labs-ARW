from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, status

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead

router = APIRouter()


@router.get(
    "",
    response_model=list[CategoryRead],
    summary="Список категорій",
)
def get_categories_endpoint() -> list[dict]:
    return repository.get_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створення категорії",
    responses={409: {"description": "Категорія з такою назвою вже існує"}},
)
def create_category_endpoint(payload: CategoryCreate) -> dict:
    try:
        return repository.create_category(payload.name)
    except repository.ConflictError as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(err)
        ) from err


@router.delete(
    "/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалення порожньої категорії",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія містить пов'язані записи"},
    },
)
def delete_category_endpoint(
    category_id: Annotated[int, Path(gt=0, description="Ідентифікатор категорії")],
) -> None:
    try:
        repository.delete_category(category_id)
    except repository.CategoryNotEmptyError as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(err)
        ) from err
    except repository.NotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(err)
        ) from err
