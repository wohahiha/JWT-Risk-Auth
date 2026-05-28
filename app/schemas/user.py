from pydantic import BaseModel, EmailStr, Field


class UserCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    surname: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8)
    confirm_password: str = Field(min_length=8)


class UserRead(BaseModel):
    id: int
    name: str
    surname: str
    email: EmailStr

    model_config = {"from_attributes": True}
