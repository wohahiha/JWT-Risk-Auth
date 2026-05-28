from datetime import datetime, timedelta, timezone
from uuid import uuid4

import jwt

from app.core.config import Settings, get_settings


class JwtService:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def create_access_token(self, subject: str, risk_level: str = "low", challenge_token: bool = False) -> str:
        now = datetime.now(timezone.utc)
        minutes = (
            self.settings.challenge_token_expire_minutes
            if challenge_token
            else self.settings.access_token_expire_minutes
        )
        payload = {
            "sub": subject,
            "jti": uuid4().hex,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=minutes),
            "iss": self.settings.jwt_issuer,
            "aud": self.settings.jwt_audience,
            "risk_level": risk_level,
        }
        return jwt.encode(payload, self.settings.jwt_secret_key, algorithm=self.settings.jwt_algorithm)

    def decode_token(self, token: str) -> dict:
        return jwt.decode(
            token,
            self.settings.jwt_secret_key,
            algorithms=[self.settings.jwt_algorithm],
            issuer=self.settings.jwt_issuer,
            audience=self.settings.jwt_audience,
        )
