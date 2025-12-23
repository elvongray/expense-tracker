from pydantic import BaseModel, Field


class CategoryBase(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    color: str | None = Field(default=None, max_length=20)


class CategoryCreate(CategoryBase):
    pass


class CategoryUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    color: str | None = Field(default=None, max_length=20)


class CategoryOut(BaseModel):
    id: str
    name: str
    color: str | None
    is_deleted: bool | None = False

    model_config = {"from_attributes": True}


class CategoryListResponse(BaseModel):
    system: list[CategoryOut]
    custom: list[CategoryOut]
