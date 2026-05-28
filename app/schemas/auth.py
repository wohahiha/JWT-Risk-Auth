from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    id: int
    authorization_token: str
    token_type: str = "bearer"
    risk_level: str = "low"


class ChallengeOptions(BaseModel):
    user_id: int
    number1: int
    number2: int
    number3: int
    debug_correct_value: int | None = None


class ChallengeVerifyRequest(BaseModel):
    user_id: int
    mailed_value: int = Field(ge=100000, le=999999)


class LoginResponse(BaseModel):
    jwt_token: TokenResponse | None = None
    user_challenge_numbers: ChallengeOptions | None = None
    decision: str
