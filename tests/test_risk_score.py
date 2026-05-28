from app.services.risk_score_service import LoginRiskContext, RiskScoreService


def test_low_risk_login_is_allowed() -> None:
    result = RiskScoreService().calculate(
        LoginRiskContext(
            failed_attempts=0,
            ip_relation="same",
            device_relation="same",
            time_relation="usual",
            token_event="normal",
            recent_abnormal_rate=0.0,
        )
    )

    assert result.score == 0.0
    assert result.risk_level == "low"
    assert result.decision == "allow"


def test_medium_risk_login_requires_challenge() -> None:
    result = RiskScoreService().calculate(
        LoginRiskContext(
            failed_attempts=1,
            ip_relation="new",
            device_relation="browser_update",
            time_relation="unusual",
            token_event="normal",
            recent_abnormal_rate=0.2,
        )
    )

    assert 30 < result.score <= 70
    assert result.risk_level == "medium"
    assert result.decision == "challenge"


def test_high_risk_login_is_denied() -> None:
    result = RiskScoreService().calculate(
        LoginRiskContext(
            failed_attempts=4,
            ip_relation="rapid_change",
            device_relation="new_device",
            time_relation="first_late_night",
            token_event="revoked_or_reused",
            recent_abnormal_rate=0.9,
        )
    )

    assert result.score > 70
    assert result.risk_level == "high"
    assert result.decision == "deny"
