import csv
from pathlib import Path

import pandas as pd

from experiments.generate_simulated_data import SCENARIOS, generate_rows
from experiments.plot_results import main as plot_main
from experiments.run_comparison import run


def _write_rows(path: Path, rows: list[dict[str, str | int | float]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def test_simulated_data_is_reproducible_and_covers_all_scenarios() -> None:
    first = generate_rows(users=50, days=7, seed=123)
    second = generate_rows(users=50, days=7, seed=123)

    assert first == second
    assert {row["scenario"] for row in first} == set(SCENARIOS)


def test_comparison_outputs_metrics_and_intercepts_improved_attack_cases(tmp_path: Path) -> None:
    input_path = tmp_path / "simulated_login_events.csv"
    output_path = tmp_path / "comparison_results.csv"
    metrics_path = tmp_path / "metrics_summary.csv"
    scenario_metrics_path = tmp_path / "scenario_metrics.csv"
    _write_rows(input_path, generate_rows(users=100, days=12, seed=42))

    run(input_path, output_path, metrics_path, scenario_metrics_path)

    assert output_path.exists()
    assert metrics_path.exists()
    assert scenario_metrics_path.exists()

    results = pd.read_csv(output_path)
    metrics = pd.read_csv(metrics_path).set_index("metric")
    scenario_metrics = pd.read_csv(scenario_metrics_path).set_index("scenario")

    assert metrics.loc["attack_intercept_rate", "improved"] > metrics.loc["attack_intercept_rate", "original"]
    assert metrics.loc["normal_false_challenge_rate", "improved"] < metrics.loc["attack_intercept_rate", "improved"]
    assert scenario_metrics.loc["password_attack", "improved_deny_rate"] > 0
    assert scenario_metrics.loc["token_replay", "improved_challenge_rate"] > 0
    assert (results.loc[results["scenario"] == "token_replay", "improved_decision"] != "allow").any()


def test_plot_results_generates_all_expected_charts(tmp_path: Path, monkeypatch) -> None:
    input_path = tmp_path / "simulated_login_events.csv"
    output_path = tmp_path / "comparison_results.csv"
    metrics_path = tmp_path / "metrics_summary.csv"
    scenario_metrics_path = tmp_path / "scenario_metrics.csv"
    charts_dir = tmp_path / "charts"
    _write_rows(input_path, generate_rows(users=100, days=12, seed=42))
    run(input_path, output_path, metrics_path, scenario_metrics_path)

    monkeypatch.setattr(
        "sys.argv",
        [
            "plot_results.py",
            "--input",
            str(output_path),
            "--metrics-input",
            str(metrics_path),
            "--scenario-input",
            str(scenario_metrics_path),
            "--output-dir",
            str(charts_dir),
        ],
    )
    plot_main()

    assert (charts_dir / "decision_comparison.png").exists()
    assert (charts_dir / "scenario_decision_distribution.png").exists()
    assert (charts_dir / "attack_intercept_comparison.png").exists()
    assert (charts_dir / "normal_false_challenge_comparison.png").exists()
