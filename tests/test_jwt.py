from app.core.config import Settings
from app.services.jwt_service import JwtService


def test_jwt_round_trip() -> None:
    service = JwtService(
        Settings(
            jwt_secret_key="test-secret",
            jwt_issuer="test-issuer",
            jwt_audience="test-audience",
            access_token_expire_minutes=10,
        )
    )

    token = service.create_access_token(subject="user@example.com", risk_level="low")
    payload = service.decode_token(token)

    assert payload["sub"] == "user@example.com"
    assert payload["risk_level"] == "low"
    assert payload["iss"] == "test-issuer"
    assert payload["aud"] == "test-audience"
    assert "jti" in payload
