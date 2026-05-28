from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.original_credibility_service import OriginalCredibilityService, OriginalLoginContext
from app.services.risk_score_service import LoginRiskContext, RiskScoreService


def run(input_path: Path, output_path: Path, metrics_path: Path, scenario_metrics_path: Path) -> None:
    data = pd.read_csv(input_path)
    original = OriginalCredibilityService()
    improved = RiskScoreService()

    results = []
    for row in data.to_dict(orient="records"):
        original_result = original.calculate(
            OriginalLoginContext(
                failed_attempts=int(row["failed_attempts"]),
                same_ip_as_last_login=row["ip_relation"] == "same",
                two_last_logins_had_different_ip=row["ip_relation"] == "rapid_change",
                same_user_agent_as_last_login=row["device_relation"] == "same",
            )
        )
        improved_result = improved.calculate(
            LoginRiskContext(
                failed_attempts=int(row["failed_attempts"]),
                ip_relation=str(row["ip_relation"]),
                device_relation=str(row["device_relation"]),
                time_relation=str(row["time_relation"]),
                token_event=str(row["token_event"]),
                recent_abnormal_rate=float(row["recent_abnormal_rate"]),
            )
        )
        results.append(
            {
                **row,
                "original_percentage": original_result.percentage,
                "original_percentage_decision": "allow" if original_result.percentage_method_allows else "challenge",
                "improved_score": improved_result.score,
                "improved_decision": improved_result.decision,
            }
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    results_data = pd.DataFrame(results)
    results_data.to_csv(output_path, index=False)
    build_metrics_summary(results_data).to_csv(metrics_path, index=False)
    build_scenario_metrics(results_data).to_csv(scenario_metrics_path, index=False)
    print(f"Wrote comparison results to {output_path}")
    print(f"Wrote metrics summary to {metrics_path}")
    print(f"Wrote scenario metrics to {scenario_metrics_path}")


def build_metrics_summary(data: pd.DataFrame) -> pd.DataFrame:
    attack_rows = data["is_attack"] == 1
    normal_rows = data["scenario"] == "normal"
    return pd.DataFrame(
        [
            {
                "metric": "allow_rate",
                "original": _rate(data["original_percentage_decision"] == "allow"),
                "improved": _rate(data["improved_decision"] == "allow"),
            },
            {
                "metric": "challenge_rate",
                "original": _rate(data["original_percentage_decision"] == "challenge"),
                "improved": _rate(data["improved_decision"] == "challenge"),
            },
            {
                "metric": "deny_rate",
                "original": 0.0,
                "improved": _rate(data["improved_decision"] == "deny"),
            },
            {
                "metric": "attack_intercept_rate",
                "original": _rate(data.loc[attack_rows, "original_percentage_decision"] != "allow"),
                "improved": _rate(data.loc[attack_rows, "improved_decision"] != "allow"),
            },
            {
                "metric": "normal_false_challenge_rate",
                "original": _rate(data.loc[normal_rows, "original_percentage_decision"] == "challenge"),
                "improved": _rate(data.loc[normal_rows, "improved_decision"] == "challenge"),
            },
            {
                "metric": "normal_allow_rate",
                "original": _rate(data.loc[normal_rows, "original_percentage_decision"] == "allow"),
                "improved": _rate(data.loc[normal_rows, "improved_decision"] == "allow"),
            },
        ]
    )


def build_scenario_metrics(data: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for scenario, scenario_data in data.groupby("scenario", sort=True):
        rows.append(
            {
                "scenario": scenario,
                "samples": len(scenario_data),
                "original_allow_rate": _rate(scenario_data["original_percentage_decision"] == "allow"),
                "original_challenge_rate": _rate(scenario_data["original_percentage_decision"] == "challenge"),
                "original_deny_rate": 0.0,
                "improved_allow_rate": _rate(scenario_data["improved_decision"] == "allow"),
                "improved_challenge_rate": _rate(scenario_data["improved_decision"] == "challenge"),
                "improved_deny_rate": _rate(scenario_data["improved_decision"] == "deny"),
            }
        )
    return pd.DataFrame(rows)


def _rate(mask: pd.Series) -> float:
    if len(mask) == 0:
        return 0.0
    return round(float(mask.mean()), 4)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare original and improved authentication methods.")
    parser.add_argument("--input", type=Path, default=Path("experiments/simulated_login_events.csv"))
    parser.add_argument("--output", type=Path, default=Path("experiments/comparison_results.csv"))
    parser.add_argument("--metrics-output", type=Path, default=Path("experiments/metrics_summary.csv"))
    parser.add_argument("--scenario-output", type=Path, default=Path("experiments/scenario_metrics.csv"))
    args = parser.parse_args()
    run(args.input, args.output, args.metrics_output, args.scenario_output)


if __name__ == "__main__":
    main()
