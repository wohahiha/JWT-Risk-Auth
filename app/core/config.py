from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    app_name: str = "jwt-risk-auth"
    environment: str = "local"

    database_url: str = Field(
        default="postgresql+psycopg://jwt_user:jwt_password@localhost:5432/jwt_risk_auth"
    )

    jwt_secret_key: str = Field(default="change-me-in-production")
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "jwt-risk-auth"
    jwt_audience: str = "jwt-risk-auth-users"
    access_token_expire_minutes: int = 30
    challenge_token_expire_minutes: int = 5
    refresh_token_expire_days: int = 7

    original_point_threshold: float = 3.5
    original_percentage_threshold: float = 80.0
    auth_decision_mode: Literal["original", "improved"] = "original"

    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None
    smtp_use_tls: bool = True
    mail_debug_fallback_enabled: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
