from fastapi import APIRouter, status

from app.schemas.transaction import TransactionCreate, TransactionRead

router = APIRouter()


@router.post("", response_model=TransactionRead, status_code=status.HTTP_201_CREATED)
def create_transaction(payload: TransactionCreate) -> TransactionRead:
    points = int(payload.amount)
    return TransactionRead(
        id=0,
        user_id=0,
        amount=payload.amount,
        points=points,
        status="created",
        description=payload.description,
    )


@router.get("", response_model=list[TransactionRead])
def list_transactions() -> list[TransactionRead]:
    return []


@router.get("/{transaction_id}", response_model=TransactionRead)
def get_transaction(transaction_id: int) -> TransactionRead:
    return TransactionRead(
        id=transaction_id,
        user_id=0,
        amount=0,
        points=0,
        status="created",
        description=None,
    )


@router.delete("/{transaction_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_transaction(transaction_id: int) -> None:
    return None
