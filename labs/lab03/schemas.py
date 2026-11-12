from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class CategoryCreate(BaseModel):

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(
        ...,
        min_length=2,
        max_length=40,
        description="Унікальна назва категорії джерела повідомлення",
    )


class CategoryRead(CategoryCreate):

    id: int = Field(..., gt=0, description="Унікальний ідентифікатор категорії")


class RecordCreate(BaseModel):

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    code: str = Field(
        ...,
        min_length=3,
        max_length=40,
        description="Унікальний код вимірювання (наприклад, V09-01)",
    )
    title: str = Field(
        ...,
        min_length=3,
        max_length=120,
        description="Назва вимірювання",
    )
    category_id: int = Field(
        ...,
        gt=0,
        description="Ідентифікатор пов'язаної категорії",
    )
    value: float = Field(
        ...,
        ge=0.0,
        allow_inf_nan=False,
        description="Тривалість у хвилинах (>= 0)",
    )
    status: Literal["new", "in_progress", "done"] = Field(
        ...,
        description="Стан перевірки вимірювання",
    )


class RecordReplace(RecordCreate):
    """Модель повної заміни полів наявного запису (PUT)."""


class RecordRead(RecordCreate):

    id: int = Field(..., gt=0, description="Унікальний ідентифікатор запису")
    category_name: str = Field(..., description="Назва категорії, отримана через JOIN")


class StudentRead(BaseModel):

    student_name: str
    group_name: str
    variant_number: int
