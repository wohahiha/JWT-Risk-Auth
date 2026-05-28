from datetime import datetime, timezone
from ipaddress import ip_address

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.security import verify_password
from app.db.session import get_db
from app.models.auth import AuthChallenge, AuthProfile, JwtSession, LoginDecision, LoginEvent
from app.models.user import User
from app.schemas.auth import ChallengeOptions, ChallengeVerifyRequest, LoginRequest, LoginResponse, TokenResponse
from app.services.challenge_service import ChallengeService
from app.services.jwt_service import JwtService
from app.services.mail_service import MailService, get_mail_service
from app.services.original_credibility_service import OriginalCredibilityService, OriginalLoginContext
from app.services.risk_score_service import LoginRiskContext, RiskScoreResult, RiskScoreService

router = APIRouter()


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    mail_service: MailService = Depends(get_mail_service),
    settings: Settings = Depends(get_settings),
) -> LoginResponse:
    email = str(payload.email).lower()
    user = db.scalar(select(User).where(User.email == email))
    ip_address = _client_ip(request)
    user_agent = request.headers.get("user-agent")

    if user is None or not verify_password(payload.password, user.hashed_password):
        if user is not None:
            profile = _get_or_create_profile(db, user)
            profile.failed_attempts += 1
            user_id = user.id
        else:
            user_id = None

        db.add(
            LoginEvent(
                user_id=user_id,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=False,
                decision=LoginDecision.DENY.value,
                reason="invalid_credentials",
            )
        )
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    profile = _get_or_create_profile(db, user)
    failed_attempts_for_login = profile.failed_attempts
    same_ip = bool(ip_address and profile.last_ip_address == ip_address)
    same_user_agent = bool(user_agent and profile.last_user_agent == user_agent)
    two_last_ips_differed = bool(
        ip_address
        and profile.last_ip_address
        and profile.previous_ip_address
        and ip_address != profile.last_ip_address
        and profile.previous_ip_address != profile.last_ip_address
    )
    credibility = OriginalCredibilityService().calculate(
        OriginalLoginContext(
            failed_attempts=failed_attempts_for_login,
            same_ip_as_last_login=same_ip,
            two_last_logins_had_different_ip=two_last_ips_differed,
            same_user_agent_as_last_login=same_user_agent,
        ),
        current_points=profile.original_points,
    )
    risk_result: RiskScoreResult | None = None
    if settings.auth_decision_mode == "improved":
        risk_result = RiskScoreService().calculate(
            _build_login_risk_context(
                db=db,
                user_id=user.id,
                profile=profile,
                failed_attempts=failed_attempts_for_login,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        )
        profile.risk_score = risk_result.score

    profile.original_points = 0.0 if credibility.should_reset else profile.original_points + credibility.points_delta
    profile.original_percentage = credibility.percentage
    profile.failed_attempts = 0
    should_update_behavior_profile = not (
        settings.auth_decision_mode == "improved"
        and risk_result is not None
        and risk_result.decision == LoginDecision.DENY.value
    )
    if should_update_behavior_profile and ip_address:
        if profile.last_ip_address != ip_address:
            profile.previous_ip_address = profile.last_ip_address
        profile.last_ip_address = ip_address
    if should_update_behavior_profile and user_agent:
        profile.last_user_agent = user_agent

    if settings.auth_decision_mode == "improved":
        if risk_result is None:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Risk score unavailable")
        if risk_result.decision == LoginDecision.DENY.value:
            db.add(
                LoginEvent(
                    user_id=user.id,
                    email=email,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=False,
                    decision=LoginDecision.DENY.value,
                    risk_score=risk_result.score,
                    reason="improved_high_risk_denied",
                )
            )
            db.commit()
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="High risk login denied")
        if risk_result.decision == LoginDecision.ALLOW.value:
            token = JwtService().create_access_token(subject=str(user.id), risk_level=risk_result.risk_level)
            _add_jwt_session(db, user.id, token)
            db.add(
                LoginEvent(
                    user_id=user.id,
                    email=email,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    success=True,
                    decision=LoginDecision.ALLOW.value,
                    risk_score=risk_result.score,
                    reason="improved_low_risk_allowed",
                )
            )
            db.commit()
            return LoginResponse(
                jwt_token=TokenResponse(id=user.id, authorization_token=token, risk_level=risk_result.risk_level),
                decision=LoginDecision.ALLOW.value,
            )

        return _create_challenge_response(
            db=db,
            user=user,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            mail_service=mail_service,
            risk_score=risk_result.score,
            reason="improved_medium_risk_challenge",
        )

    if credibility.percentage_method_allows:
        token = JwtService().create_access_token(subject=str(user.id), risk_level="low")
        _add_jwt_session(db, user.id, token)
        db.add(
            LoginEvent(
                user_id=user.id,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                success=True,
                decision=LoginDecision.ALLOW.value,
                risk_score=0.0,
                reason="original_percentage_allowed",
            )
        )
        db.commit()
        return LoginResponse(
            jwt_token=TokenResponse(id=user.id, authorization_token=token, risk_level="low"),
            decision=LoginDecision.ALLOW.value,
        )

    return _create_challenge_response(
        db=db,
        user=user,
        email=email,
        ip_address=ip_address,
        user_agent=user_agent,
        mail_service=mail_service,
        risk_score=0.0,
        reason="original_percentage_below_threshold",
    )


def _create_challenge_response(
    db: Session,
    user: User,
    email: str,
    ip_address: str | None,
    user_agent: str | None,
    mail_service: MailService,
    risk_score: float,
    reason: str,
) -> LoginResponse:
    challenge = ChallengeService().generate(user_id=user.id)
    db.add(
        AuthChallenge(
            user_id=user.id,
            correct_value=challenge.correct_value,
            option_1=challenge.options[0],
            option_2=challenge.options[1],
            option_3=challenge.options[2],
            expires_at=challenge.expires_at,
        )
    )
    mail_result = mail_service.send_challenge_email(user.email, challenge.correct_value)
    if not mail_result.sent and not mail_result.used_debug_fallback:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Unable to deliver challenge")

    db.add(
        LoginEvent(
            user_id=user.id,
            email=email,
            ip_address=ip_address,
            user_agent=user_agent,
            success=True,
            decision=LoginDecision.CHALLENGE.value,
            risk_score=risk_score,
            reason=reason,
        )
    )
    db.commit()
    return LoginResponse(
        user_challenge_numbers=ChallengeOptions(
            user_id=user.id,
            number1=challenge.options[0],
            number2=challenge.options[1],
            number3=challenge.options[2],
            debug_correct_value=challenge.correct_value if mail_result.used_debug_fallback else None,
        ),
        decision=LoginDecision.CHALLENGE.value,
    )


@router.post("/challenge/verify", response_model=TokenResponse)
def verify_challenge(payload: ChallengeVerifyRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = db.get(User, payload.user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    challenge = db.scalar(
        select(AuthChallenge)
        .where(AuthChallenge.user_id == payload.user_id)
        .order_by(AuthChallenge.id.desc())
    )
    if challenge is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Challenge not found")
    if challenge.used_at is not None:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Challenge already used")
    if _as_utc(challenge.expires_at) <= _current_time():
        raise HTTPException(status_code=status.HTTP_410_GONE, detail="Challenge expired")
    if payload.mailed_value != challenge.correct_value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid challenge value")

    challenge.used_at = _current_time()
    token = JwtService().create_access_token(subject=str(user.id), risk_level="medium", challenge_token=True)
    _add_jwt_session(db, user.id, token)
    db.commit()
    return TokenResponse(id=user.id, authorization_token=token, risk_level="medium")


@router.get("/challenge/example", response_model=ChallengeOptions)
def challenge_example() -> ChallengeOptions:
    challenge = ChallengeService().generate(user_id=0)
    return ChallengeOptions(
        user_id=challenge.user_id,
        number1=challenge.options[0],
        number2=challenge.options[1],
        number3=challenge.options[2],
    )


def _get_or_create_profile(db: Session, user: User) -> AuthProfile:
    if user.auth_profile is not None:
        return user.auth_profile

    profile = AuthProfile(user_id=user.id)
    db.add(profile)
    db.flush()
    return profile


def _client_ip(request: Request) -> str | None:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",", maxsplit=1)[0].strip()
    if request.client is None:
        return None
    return request.client.host


def _build_login_risk_context(
    db: Session,
    user_id: int,
    profile: AuthProfile,
    failed_attempts: int,
    ip_address: str | None,
    user_agent: str | None,
) -> LoginRiskContext:
    return LoginRiskContext(
        failed_attempts=failed_attempts,
        ip_relation=_ip_relation(ip_address, profile.last_ip_address, profile.previous_ip_address),
        device_relation=_device_relation(user_agent, profile.last_user_agent),
        time_relation=_time_relation(db, user_id),
        token_event="normal",
        recent_abnormal_rate=_recent_abnormal_rate(db, user_id),
    )


def _ip_relation(current_ip: str | None, last_ip: str | None, previous_ip: str | None) -> str:
    if current_ip and last_ip and current_ip == last_ip:
        return "same"
    if current_ip and last_ip and _same_ipv4_subnet(current_ip, last_ip):
        return "same_subnet"
    if current_ip and last_ip and previous_ip and current_ip != last_ip and previous_ip != last_ip:
        return "rapid_change"
    return "new"


def _same_ipv4_subnet(first_ip: str, second_ip: str) -> bool:
    try:
        first = ip_address(first_ip)
        second = ip_address(second_ip)
    except ValueError:
        return False
    if first.version != 4 or second.version != 4:
        return False
    return int(first) >> 8 == int(second) >> 8


def _device_relation(current_user_agent: str | None, last_user_agent: str | None) -> str:
    if current_user_agent and last_user_agent and current_user_agent == last_user_agent:
        return "same"

    current_family = _browser_family(current_user_agent)
    last_family = _browser_family(last_user_agent)
    if current_family and last_family and current_family == last_family:
        return "browser_update"
    return "new_device"


def _browser_family(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    lowered = user_agent.lower()
    for family in ("edg", "edge", "chrome", "firefox", "safari"):
        if family in lowered:
            return "edge" if family == "edg" else family
    return None


def _time_relation(db: Session, user_id: int) -> str:
    now = _current_time()
    if not 0 <= now.hour <= 5:
        return "usual"

    previous_events = list(
        db.scalars(
            select(LoginEvent)
            .where(LoginEvent.user_id == user_id)
            .order_by(LoginEvent.id.desc())
            .limit(100)
        )
    )
    had_late_login = any(0 <= _as_utc(event.created_at).hour <= 5 for event in previous_events)
    return "unusual" if had_late_login else "first_late_night"


def _recent_abnormal_rate(db: Session, user_id: int) -> float:
    events = list(
        db.scalars(
            select(LoginEvent)
            .where(LoginEvent.user_id == user_id)
            .order_by(LoginEvent.id.desc())
            .limit(10)
        )
    )
    if not events:
        return 0.0

    abnormal = sum(
        1
        for event in events
        if not event.success or event.decision in {LoginDecision.CHALLENGE.value, LoginDecision.DENY.value}
    )
    return abnormal / len(events)


def _add_jwt_session(db: Session, user_id: int, token: str) -> None:
    payload = JwtService().decode_token(token)
    expires_at = datetime.fromtimestamp(payload["exp"], timezone.utc)
    db.add(
        JwtSession(
            user_id=user_id,
            jti=payload["jti"],
            risk_level=payload["risk_level"],
            expires_at=expires_at,
        )
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _current_time() -> datetime:
    return datetime.now(timezone.utc)
