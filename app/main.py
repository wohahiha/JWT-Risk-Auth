from fastapi import FastAPI

from app.api.v1 import auth, transactions, users

app = FastAPI(
    title="JWT Risk-Aware Authentication",
    version="0.1.0",
    description="Reproduction and extension project for behavior-aware JWT authentication.",
)


@app.get("/health", tags=["system"])
def health_check() -> dict[str, str]:
    return {"status": "ok", "service": "jwt-risk-auth"}


app.include_router(users.router, prefix="/api/v1/users", tags=["users"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(transactions.router, prefix="/api/v1/transactions", tags=["transactions"])
