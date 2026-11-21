"""Automated Precision/Recall regression test across all synthetic baselines, attack scenarios, and Sigma rules."""

from pathlib import Path

from artex_defense.eval_harness import run_evaluation

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "sigma"


def test_eval_harness_achieves_perfect_precision_and_recall_on_synthetic_suite() -> None:
    report = run_evaluation(rules_dir=RULES_DIR, with_gemma4=False)
    metrics = report["metrics"]

    assert metrics["tp"] == 18, f"Expected all 18 synthetic scenarios detected: {report['scenarios']}"
    assert metrics["fp"] == 0, f"Unexpected false positives on benign baselines: {report['scenarios']}"
    assert metrics["tn"] == 16
    assert metrics["fn"] == 0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0

    for scenario in report["scenarios"]:
        assert not scenario["missing_expected_reasons"], (
            f"{scenario['dataset']} missing expected reasons: {scenario['missing_expected_reasons']} "
            f"(observed: {scenario['observed_reasons']})"
        )
        assert scenario["kill_chain_ok"] is True, f"{scenario['dataset']} failed kill-chain correlation"

    # Every Sigma rule must be syntactically valid, hit >=1 synthetic attack, and have 0 baseline FPs
    assert len(report["sigma_rules"]) >= 19
    for rule in report["sigma_rules"]:
        assert rule["valid"] is True, f"Invalid Sigma YAML {rule['file']}: {rule['errors']}"
        assert rule["synthetic_attack_hits"] >= 1, (
            f"Sigma rule {rule['file']} did not match any synthetic attack scenario"
        )
        assert rule["synthetic_baseline_fp_hits"] == 0, (
            f"Sigma rule {rule['file']} fired {rule['synthetic_baseline_fp_hits']} FP hits on benign baselines"
        )
