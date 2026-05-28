from decimal import Decimal

from pydantic import BaseModel, Field


class TransactionCreate(BaseModel):
    amount: Decimal = Field(gt=0)
    description: str | None = Field(default=None, max_length=500)


class TransactionRead(BaseModel):
    id: int
    user_id: int
    amount: Decimal
    points: int
    status: str
    description: str | None = None

    model_config = {"from_attributes": True}
