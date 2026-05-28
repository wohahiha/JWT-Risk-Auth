from app.services.original_credibility_service import OriginalCredibilityService, OriginalLoginContext


def test_percentage_method_allows_ideal_login() -> None:
    result = OriginalCredibilityService().calculate(
        OriginalLoginContext(
            failed_attempts=0,
            same_ip_as_last_login=True,
            two_last_logins_had_different_ip=False,
            same_user_agent_as_last_login=True,
        )
    )

    assert result.percentage == 100.0
    assert result.percentage_method_allows is True
    assert result.should_reset is False


def test_point_method_allows_after_accumulated_trust() -> None:
    result = OriginalCredibilityService().calculate(
        OriginalLoginContext(
            failed_attempts=0,
            same_ip_as_last_login=True,
            two_last_logins_had_different_ip=False,
            same_user_agent_as_last_login=True,
        ),
        current_points=2.4,
    )

    assert result.points_delta == 1.1
    assert result.point_method_allows is True


def test_original_method_resets_after_three_failed_attempts() -> None:
    result = OriginalCredibilityService().calculate(
        OriginalLoginContext(
            failed_attempts=3,
            same_ip_as_last_login=True,
            two_last_logins_had_different_ip=False,
            same_user_agent_as_last_login=True,
        ),
        current_points=5.0,
    )

    assert result.should_reset is True
    assert result.percentage == 0.0
    assert result.point_method_allows is False
