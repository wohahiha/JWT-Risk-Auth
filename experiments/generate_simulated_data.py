from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta
from pathlib import Path
from random import Random

SCENARIOS = ["normal", "network_change", "password_attack", "new_device", "token_replay"]
SCENARIO_WEIGHTS = {
    "normal": 65,
    "network_change": 15,
    "password_attack": 8,
    "new_device": 8,
    "token_replay": 4,
}


def generate_rows(users: int, days: int, seed: int) -> list[dict[str, str | int | float]]:
    rng = Random(seed)
    start = datetime(2026, 1, 1, 9, 0, 0)
    rows: list[dict[str, str | int | float]] = []
    scenario_pool = _scenario_pool(users)
    rng.shuffle(scenario_pool)

    for user_id in range(1, users + 1):
        scenario = scenario_pool[user_id - 1]
        base_ip = f"10.0.{user_id % 255}.{rng.randint(2, 254)}"

        for day in range(days):
            login_time = start + timedelta(days=day, hours=rng.choice([0, 1, 2, 8, 14]))
            failed_attempts = 0
            ip_relation = "same"
            device_relation = "same"
            time_relation = "usual"
            token_event = "normal"
            recent_abnormal_rate = round(rng.uniform(0.0, 0.08), 2)
            user_agent = "Chrome/120 Windows"

            if scenario == "network_change" and day % 7 == 0:
                ip_relation = "new"
                recent_abnormal_rate = round(rng.uniform(0.12, 0.28), 2)
            elif scenario == "password_attack" and day % 3 == 0:
                failed_attempts = rng.randint(3, 5)
                ip_relation = "rapid_change"
                device_relation = "new_device"
                time_relation = "first_late_night"
                recent_abnormal_rate = round(rng.uniform(0.85, 1.0), 2)
                user_agent = "UnknownBot/1.0"
            elif scenario == "new_device" and day % 10 == 0:
                device_relation = rng.choice(["browser_update", "new_device"])
                recent_abnormal_rate = round(rng.uniform(0.15, 0.35), 2)
                user_agent = "Chrome/121 Windows" if device_relation == "browser_update" else "Firefox/122 Windows"
            elif scenario == "token_replay" and day % 2 == 0:
                token_event = "revoked_or_reused"
                time_relation = "first_late_night"
                recent_abnormal_rate = round(rng.uniform(0.85, 1.0), 2)

            rows.append(
                {
                    "user_id": user_id,
                    "scenario": scenario,
                    "login_at": login_time.isoformat(),
                    "ip_address": base_ip,
                    "user_agent": user_agent,
                    "failed_attempts": failed_attempts,
                    "ip_relation": ip_relation,
                    "device_relation": device_relation,
                    "time_relation": time_relation,
                    "token_event": token_event,
                    "recent_abnormal_rate": recent_abnormal_rate,
                    "is_attack": int(scenario in {"password_attack", "token_replay"}),
                }
            )

    return rows


def _scenario_pool(users: int) -> list[str]:
    if users < len(SCENARIOS):
        raise ValueError(f"users must be at least {len(SCENARIOS)}")

    total_weight = sum(SCENARIO_WEIGHTS.values())
    counts = {scenario: max(1, users * weight // total_weight) for scenario, weight in SCENARIO_WEIGHTS.items()}
    while sum(counts.values()) < users:
        for scenario in SCENARIOS:
            counts[scenario] += 1
            if sum(counts.values()) == users:
                break
    while sum(counts.values()) > users:
        for scenario in reversed(SCENARIOS):
            if counts[scenario] > 1:
                counts[scenario] -= 1
                if sum(counts.values()) == users:
                    break

    return [scenario for scenario in SCENARIOS for _ in range(counts[scenario])]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate simulated login behavior data.")
    parser.add_argument("--users", type=int, default=500)
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=Path("experiments/simulated_login_events.csv"))
    args = parser.parse_args()

    rows = generate_rows(users=args.users, days=args.days, seed=args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {args.output}")


if __name__ == "__main__":
    main()
