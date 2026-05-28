from __future__ import annotations

import argparse
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

plt.switch_backend("Agg")


def main() -> None:
    parser = argparse.ArgumentParser(description="Plot comparison metrics.")
    parser.add_argument("--input", type=Path, default=Path("experiments/comparison_results.csv"))
    parser.add_argument("--metrics-input", type=Path, default=Path("experiments/metrics_summary.csv"))
    parser.add_argument("--scenario-input", type=Path, default=Path("experiments/scenario_metrics.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("experiments"))
    args = parser.parse_args()

    data = pd.read_csv(args.input)
    metrics = pd.read_csv(args.metrics_input)
    scenario_metrics = pd.read_csv(args.scenario_input)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    plot_decision_comparison(data, args.output_dir / "decision_comparison.png")
    plot_scenario_distribution(scenario_metrics, args.output_dir / "scenario_decision_distribution.png")
    plot_metric(metrics, "attack_intercept_rate", "Attack Intercept Rate", args.output_dir / "attack_intercept_comparison.png")
    plot_metric(
        metrics,
        "normal_false_challenge_rate",
        "Normal User False Challenge Rate",
        args.output_dir / "normal_false_challenge_comparison.png",
    )
    print(f"Wrote charts to {args.output_dir}")


def plot_decision_comparison(data: pd.DataFrame, output_path: Path) -> None:
    summary = pd.DataFrame(
        {
            "allow": [
                (data["original_percentage_decision"] == "allow").mean(),
                (data["improved_decision"] == "allow").mean(),
            ],
            "challenge": [
                (data["original_percentage_decision"] == "challenge").mean(),
                (data["improved_decision"] == "challenge").mean(),
            ],
            "deny": [
                0.0,
                (data["improved_decision"] == "deny").mean(),
            ],
        },
        index=["original", "improved"],
    )
    ax = summary.plot(kind="bar", ylim=(0, 1), title="Overall Authentication Decision Rates")
    ax.set_ylabel("rate")
    ax.set_xlabel("method")
    ax.legend(title="decision")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def plot_scenario_distribution(scenario_metrics: pd.DataFrame, output_path: Path) -> None:
    scenarios = scenario_metrics["scenario"].tolist()
    labels = [f"{scenario}\noriginal" for scenario in scenarios] + [f"{scenario}\nimproved" for scenario in scenarios]
    plot_data = pd.DataFrame(
        {
            "allow": scenario_metrics["original_allow_rate"].tolist()
            + scenario_metrics["improved_allow_rate"].tolist(),
            "challenge": scenario_metrics["original_challenge_rate"].tolist()
            + scenario_metrics["improved_challenge_rate"].tolist(),
            "deny": scenario_metrics["original_deny_rate"].tolist() + scenario_metrics["improved_deny_rate"].tolist(),
        },
        index=labels,
    )
    ax = plot_data.plot(kind="bar", stacked=True, ylim=(0, 1), title="Decision Distribution by Scenario")
    ax.set_ylabel("rate")
    ax.set_xlabel("scenario and method")
    ax.legend(title="decision", loc="upper right")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def plot_metric(metrics: pd.DataFrame, metric: str, title: str, output_path: Path) -> None:
    row = metrics.loc[metrics["metric"] == metric].iloc[0]
    values = pd.Series({"original": row["original"], "improved": row["improved"]})
    ax = values.plot(kind="bar", ylim=(0, 1), title=title)
    ax.set_ylabel("rate")
    ax.set_xlabel("method")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


if __name__ == "__main__":
    main()
