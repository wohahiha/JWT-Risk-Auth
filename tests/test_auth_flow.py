from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.security import verify_password
from app.main import app
from app.models.auth import AuthChallenge, AuthProfile, JwtSession, LoginEvent
from app.models.user import User
from app.services.jwt_service import JwtService


def _register(client: TestClient, email: str = "user@example.com") -> dict:
    response = client.post(
        "/api/v1/users/register",
        json={
            "name": "Ada",
            "surname": "Lovelace",
            "email": email,
            "password": "strong-password",
            "confirm_password": "strong-password",
        },
    )
    assert response.status_code == 201
    return response.json()


def _login(
    client: TestClient,
    email: str = "user@example.com",
    password: str = "strong-password",
    ip_address: str = "10.0.0.10",
    user_agent: str = "pytest-agent",
):
    return client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
        headers={"X-Forwarded-For": ip_address, "User-Agent": user_agent},
    )


def _use_improved_mode() -> None:
    app.dependency_overrides[get_settings] = lambda: Settings(auth_decision_mode="improved")


def test_register_creates_user_and_auth_profile(client: TestClient, db_session: Session) -> None:
    body = _register(client)

    user = db_session.scalar(select(User).where(User.id == body["id"]))
    assert user is not None
    assert user.email == "user@example.com"
    assert verify_password("strong-password", user.hashed_password)

    profile = db_session.scalar(select(AuthProfile).where(AuthProfile.user_id == user.id))
    assert profile is not None
    assert profile.original_points == 0.0
    assert profile.failed_attempts == 0


def test_register_rejects_duplicate_email(client: TestClient) -> None:
    _register(client)

    response = client.post(
        "/api/v1/users/register",
        json={
            "name": "Ada",
            "surname": "Lovelace",
            "email": "user@example.com",
            "password": "strong-password",
            "confirm_password": "strong-password",
        },
    )

    assert response.status_code == 409


def test_register_rejects_password_mismatch(client: TestClient) -> None:
    response = client.post(
        "/api/v1/users/register",
        json={
            "name": "Ada",
            "surname": "Lovelace",
            "email": "user@example.com",
            "password": "strong-password",
            "confirm_password": "different-password",
        },
    )

    assert response.status_code == 400


def test_invalid_password_increments_failed_attempts_and_logs_event(client: TestClient, db_session: Session) -> None:
    body = _register(client)

    response = _login(client, password="wrong-password")

    assert response.status_code == 401
    db_session.expire_all()
    profile = db_session.scalar(select(AuthProfile).where(AuthProfile.user_id == body["id"]))
    assert profile is not None
    assert profile.failed_attempts == 1

    event = db_session.scalar(select(LoginEvent).where(LoginEvent.user_id == body["id"]))
    assert event is not None
    assert event.success is False
    assert event.decision == "deny"


def test_trusted_login_returns_jwt_and_records_session(client: TestClient, db_session: Session) -> None:
    body = _register(client)
    profile = db_session.scalar(select(AuthProfile).where(AuthProfile.user_id == body["id"]))
    assert profile is not None
    profile.last_ip_address = "10.0.0.10"
    profile.last_user_agent = "pytest-agent"
    db_session.commit()

    response = _login(client)

    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "allow"
    assert data["jwt_token"]["id"] == body["id"]
    assert data["user_challenge_numbers"] is None
    payload = JwtService().decode_token(data["jwt_token"]["authorization_token"])
    assert payload["sub"] == str(body["id"])
    assert payload["risk_level"] == "low"

    session = db_session.scalar(select(JwtSession).where(JwtSession.user_id == body["id"]))
    assert session is not None
    assert session.risk_level == "low"


def test_low_trust_login_generates_challenge_with_debug_fallback(client: TestClient, db_session: Session) -> None:
    body = _register(client)

    response = _login(client)

    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "challenge"
    assert data["jwt_token"] is None
    challenge_body = data["user_challenge_numbers"]
    assert challenge_body["user_id"] == body["id"]
    assert challenge_body["debug_correct_value"] is not None

    challenge = db_session.scalar(select(AuthChallenge).where(AuthChallenge.user_id == body["id"]))
    assert challenge is not None
    assert challenge.correct_value == challenge_body["debug_correct_value"]


def test_challenge_verify_accepts_correct_value_and_marks_used(client: TestClient, db_session: Session) -> None:
    body = _register(client)
    login_response = _login(client).json()
    correct_value = login_response["user_challenge_numbers"]["debug_correct_value"]

    response = client.post(
        "/api/v1/auth/challenge/verify",
        json={"user_id": body["id"], "mailed_value": correct_value},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == body["id"]
    assert data["risk_level"] == "medium"
    payload = JwtService().decode_token(data["authorization_token"])
    assert payload["sub"] == str(body["id"])

    db_session.expire_all()
    challenge = db_session.scalar(select(AuthChallenge).where(AuthChallenge.user_id == body["id"]))
    assert challenge is not None
    assert challenge.used_at is not None
    session = db_session.scalar(select(JwtSession).where(JwtSession.user_id == body["id"]))
    assert session is not None
    assert session.risk_level == "medium"


def test_challenge_verify_rejects_wrong_value(client: TestClient) -> None:
    body = _register(client)
    login_response = _login(client).json()
    correct_value = login_response["user_challenge_numbers"]["debug_correct_value"]

    response = client.post(
        "/api/v1/auth/challenge/verify",
        json={"user_id": body["id"], "mailed_value": correct_value + 1},
    )

    assert response.status_code == 400


def test_challenge_verify_rejects_expired_value(client: TestClient, db_session: Session) -> None:
    body = _register(client)
    login_response = _login(client).json()
    correct_value = login_response["user_challenge_numbers"]["debug_correct_value"]
    challenge = db_session.scalar(select(AuthChallenge).where(AuthChallenge.user_id == body["id"]))
    assert challenge is not None
    challenge.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()

    response = client.post(
        "/api/v1/auth/challenge/verify",
        json={"user_id": body["id"], "mailed_value": correct_value},
    )

    assert response.status_code == 410


def test_challenge_verify_rejects_reuse(client: TestClient) -> None:
    body = _register(client)
    login_response = _login(client).json()
    correct_value = login_response["user_challenge_numbers"]["debug_correct_value"]

    first_response = client.post(
        "/api/v1/auth/challenge/verify",
        json={"user_id": body["id"], "mailed_value": correct_value},
    )
    second_response = client.post(
        "/api/v1/auth/challenge/verify",
        json={"user_id": body["id"], "mailed_value": correct_value},
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 410


def test_improved_mode_allows_low_risk_first_login(client: TestClient, db_session: Session) -> None:
    _use_improved_mode()
    body = _register(client)

    response = _login(client)

    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "allow"
    assert data["jwt_token"]["id"] == body["id"]
    assert data["jwt_token"]["risk_level"] == "low"

    db_session.expire_all()
    profile = db_session.scalar(select(AuthProfile).where(AuthProfile.user_id == body["id"]))
    assert profile is not None
    assert 0 < profile.risk_score <= 30

    event = db_session.scalar(select(LoginEvent).where(LoginEvent.user_id == body["id"]))
    assert event is not None
    assert event.decision == "allow"
    assert event.reason == "improved_low_risk_allowed"
    assert event.risk_score == profile.risk_score


def test_improved_mode_challenges_medium_risk_login_after_failures(
    client: TestClient, db_session: Session
) -> None:
    _use_improved_mode()
    body = _register(client)
    assert _login(client, password="wrong-password").status_code == 401
    assert _login(client, password="wrong-password").status_code == 401

    response = _login(client, ip_address="203.0.113.10", user_agent="UnknownBrowser/1.0")

    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "challenge"
    assert data["jwt_token"] is None
    assert data["user_challenge_numbers"]["debug_correct_value"] is not None

    db_session.expire_all()
    profile = db_session.scalar(select(AuthProfile).where(AuthProfile.user_id == body["id"]))
    assert profile is not None
    assert 30 < profile.risk_score <= 70
    event = db_session.scalars(
        select(LoginEvent).where(LoginEvent.user_id == body["id"]).order_by(LoginEvent.id.desc())
    ).first()
    assert event is not None
    assert event.decision == "challenge"
    assert event.reason == "improved_medium_risk_challenge"
    assert event.risk_score == profile.risk_score


def test_improved_mode_denies_high_risk_login_without_jwt(
    client: TestClient, db_session: Session, monkeypatch
) -> None:
    _use_improved_mode()
    body = _register(client)
    profile = db_session.scalar(select(AuthProfile).where(AuthProfile.user_id == body["id"]))
    assert profile is not None
    profile.failed_attempts = 3
    profile.previous_ip_address = "10.0.0.10"
    profile.last_ip_address = "10.0.1.10"
    profile.last_user_agent = "Chrome/120 Windows"
    db_session.add(
        LoginEvent(
            user_id=body["id"],
            email="user@example.com",
            success=False,
            decision="deny",
            reason="previous_abnormal_event",
        )
    )
    db_session.commit()
    monkeypatch.setattr("app.api.v1.auth._current_time", lambda: datetime(2026, 1, 1, 2, 0, tzinfo=timezone.utc))

    response = _login(client, ip_address="10.0.2.10", user_agent="UnknownBot/1.0")

    assert response.status_code == 403
    assert response.json()["detail"] == "High risk login denied"

    db_session.expire_all()
    profile = db_session.scalar(select(AuthProfile).where(AuthProfile.user_id == body["id"]))
    assert profile is not None
    assert profile.risk_score > 70
    session = db_session.scalar(select(JwtSession).where(JwtSession.user_id == body["id"]))
    assert session is None
    event = db_session.scalars(
        select(LoginEvent).where(LoginEvent.user_id == body["id"]).order_by(LoginEvent.id.desc())
    ).first()
    assert event is not None
    assert event.decision == "deny"
    assert event.reason == "improved_high_risk_denied"
    assert event.risk_score == profile.risk_score


def test_improved_mode_recent_abnormal_rate_raises_risk_score(
    client: TestClient, db_session: Session
) -> None:
    _use_improved_mode()
    body = _register(client)
    assert _login(client, password="wrong-password").status_code == 401
    assert _login(client, password="wrong-password").status_code == 401

    response = _login(client, ip_address="203.0.113.11", user_agent="UnknownBrowser/2.0")

    assert response.status_code == 200
    db_session.expire_all()
    profile = db_session.scalar(select(AuthProfile).where(AuthProfile.user_id == body["id"]))
    assert profile is not None
    # 15 failed-attempt points + 12 new-IP points + 10.5 new-device points would
    # remain below challenge threshold without recent abnormal history.
    assert profile.risk_score > 37.5
