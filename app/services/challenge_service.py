from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from random import SystemRandom


@dataclass(frozen=True)
class ChallengePayload:
    user_id: int
    correct_value: int
    options: tuple[int, int, int]
    expires_at: datetime


class ChallengeService:
    def __init__(self) -> None:
        self._random = SystemRandom()

    def generate(self, user_id: int, ttl_minutes: int = 5) -> ChallengePayload:
        correct_value = self._random.randint(100000, 999999)
        options = {correct_value}
        while len(options) < 3:
            options.add(self._random.randint(100000, 999999))

        shuffled = list(options)
        self._random.shuffle(shuffled)
        return ChallengePayload(
            user_id=user_id,
            correct_value=correct_value,
            options=(shuffled[0], shuffled[1], shuffled[2]),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes),
        )
