from dataclasses import dataclass


@dataclass(frozen=True)
class OriginalLoginContext:
    failed_attempts: int
    same_ip_as_last_login: bool
    two_last_logins_had_different_ip: bool
    same_user_agent_as_last_login: bool


@dataclass(frozen=True)
class OriginalCredibilityResult:
    points_delta: float
    percentage: float
    should_reset: bool
    point_method_allows: bool
    percentage_method_allows: bool


class OriginalCredibilityService:
    point_threshold = 3.5
    percentage_threshold = 80.0

    def calculate(self, context: OriginalLoginContext, current_points: float = 0.0) -> OriginalCredibilityResult:
        should_reset = context.failed_attempts >= 3 or context.two_last_logins_had_different_ip

        if context.failed_attempts >= 3:
            retry_points = 0.0
            retry_percentage = 0.0
        elif context.failed_attempts == 0:
            retry_points = 0.7
            retry_percentage = 70.0
        elif context.failed_attempts == 1:
            retry_points = 0.4
            retry_percentage = 40.0
        else:
            retry_points = 0.2
            retry_percentage = 20.0

        if context.two_last_logins_had_different_ip:
            ip_points = -0.5
            ip_percentage = 0.0
        elif context.same_ip_as_last_login:
            ip_points = 0.2
            ip_percentage = 20.0
        else:
            ip_points = 0.0
            ip_percentage = 0.0

        user_agent_points = 0.2 if context.same_user_agent_as_last_login else 0.0
        user_agent_percentage = 10.0 if context.same_user_agent_as_last_login else 0.0

        points_delta = round(retry_points + ip_points + user_agent_points, 2)
        effective_points = 0.0 if should_reset else current_points + points_delta
        percentage = 0.0 if should_reset else retry_percentage + ip_percentage + user_agent_percentage

        return OriginalCredibilityResult(
            points_delta=points_delta,
            percentage=percentage,
            should_reset=should_reset,
            point_method_allows=effective_points >= self.point_threshold,
            percentage_method_allows=percentage > self.percentage_threshold,
        )
