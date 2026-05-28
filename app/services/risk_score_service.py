from dataclasses import dataclass


@dataclass(frozen=True)
class LoginRiskContext:
    failed_attempts: int
    ip_relation: str
    device_relation: str
    time_relation: str
    token_event: str
    recent_abnormal_rate: float


@dataclass(frozen=True)
class RiskScoreResult:
    score: float
    risk_level: str
    decision: str


class RiskScoreService:
    weights = {
        "failed_attempts": 0.25,
        "ip": 0.20,
        "device": 0.15,
        "time": 0.15,
        "token": 0.10,
        "history": 0.15,
    }

    def calculate(self, context: LoginRiskContext) -> RiskScoreResult:
        failed_score = self._failed_attempt_score(context.failed_attempts)
        ip_score = {"same": 0, "same_subnet": 25, "new": 60, "rapid_change": 100}.get(context.ip_relation, 60)
        device_score = {"same": 0, "browser_update": 30, "new_device": 70}.get(context.device_relation, 70)
        time_score = {"usual": 0, "unusual": 50, "first_late_night": 70}.get(context.time_relation, 50)
        token_score = {"normal": 0, "expired": 40, "revoked_or_reused": 100}.get(context.token_event, 40)
        history_score = min(max(context.recent_abnormal_rate, 0.0), 1.0) * 100

        score = (
            failed_score * self.weights["failed_attempts"]
            + ip_score * self.weights["ip"]
            + device_score * self.weights["device"]
            + time_score * self.weights["time"]
            + token_score * self.weights["token"]
            + history_score * self.weights["history"]
        )
        score = round(score, 2)

        if score <= 30:
            return RiskScoreResult(score=score, risk_level="low", decision="allow")
        if score <= 70:
            return RiskScoreResult(score=score, risk_level="medium", decision="challenge")
        return RiskScoreResult(score=score, risk_level="high", decision="deny")

    @staticmethod
    def _failed_attempt_score(failed_attempts: int) -> int:
        if failed_attempts <= 0:
            return 0
        if failed_attempts == 1:
            return 30
        if failed_attempts == 2:
            return 60
        return 100
