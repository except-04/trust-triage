"""Offline checks for the inline MLflow setup, without importing training scripts.

Some scripts load models or export files at import time. Execute only their
actual tracking setup AST against a mock, never MLflow or training/data I/O.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
from unittest.mock import Mock, call

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = [
    ("models/tune_lightgbm.py", "trust-triage-baseline"),
    ("models/train_xgboost_500.py", "TRUST-Triage-XGBoost-500"),
    ("models/compare_baseline_models.py", "TRUST-Triage-Baseline-Feature-Count"),
    ("models/export_baseline_pkl.py", "trust-triage-baseline"),
    ("models/export_mlflow_result.py", "trust-triage-baseline"),
    ("models/check_gain_vs_split.py", "trust-triage-baseline"),
    ("jrr/train_calibrator.py", "JRR_Calibration"),
    ("jrr/risk_signals.py", "JRR_Calibration"),
    ("jrr/evaluate_jrr.py", "JRR_Evaluation_and_KillTest"),
]


def tracking_setup(relative_path):
    tree = ast.parse((ROOT / "src" / relative_path).read_text(encoding="utf-8"))
    os_import = next(
        node for node in tree.body
        if isinstance(node, ast.Import)
        and any(alias.name == "os" and alias.asname is None for alias in node.names)
    )
    matches = []
    for scope in ast.walk(tree):
        if not isinstance(scope, (ast.Module, ast.FunctionDef)):
            continue
        for index, statement in enumerate(scope.body):
            if (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Call)
                and ast.unparse(statement.value.func) == "mlflow.set_experiment"
            ):
                assert index > 0
                guard = scope.body[index - 1]
                assert isinstance(guard, ast.If)
                assert ast.unparse(guard.test) == "'MLFLOW_TRACKING_URI' in os.environ"
                matches.append([os_import, guard, statement])
    assert len(matches) == 1
    return compile(
        ast.Module(body=matches[0], type_ignores=[]),
        str(ROOT / "src" / relative_path),
        "exec",
    )


@pytest.mark.parametrize("relative_path,experiment", SCRIPTS)
@pytest.mark.parametrize(
    "uri",
    [
        None,
        "",
        "http://127.0.0.1:5000",
        # Placeholder only, deliberately not a real AWS account/server.
        "arn:aws:sagemaker:REGION:ACCOUNT:mlflow-tracking-server/offline-test",
    ],
    ids=["unset", "empty", "local-server", "managed-server"],
)
def test_tracking_uri_is_optional_and_set_before_experiment(
    monkeypatch, relative_path, experiment, uri
):
    if uri is None:
        monkeypatch.delenv("MLFLOW_TRACKING_URI", raising=False)
    else:
        monkeypatch.setenv("MLFLOW_TRACKING_URI", uri)

    mlflow = Mock()
    exec(tracking_setup(relative_path), {"mlflow": mlflow})
    expected = [] if uri is None else [call.set_tracking_uri(uri)]
    assert mlflow.mock_calls == expected + [call.set_experiment(experiment)]
    # In particular, the unset case must not reset the existing/default URI.
    if uri is None:
        mlflow.set_tracking_uri.assert_not_called()


@pytest.mark.parametrize("relative_path,experiment", SCRIPTS)
def test_tracking_setup_errors_do_not_silently_fall_back(
    monkeypatch, relative_path, experiment
):
    monkeypatch.setenv("MLFLOW_TRACKING_URI", "unsupported://offline-test")
    mlflow = Mock()
    mlflow.set_tracking_uri.side_effect = RuntimeError("tracking setup failed")
    with pytest.raises(RuntimeError, match="tracking setup failed"):
        exec(tracking_setup(relative_path), {"mlflow": mlflow})
    mlflow.set_experiment.assert_not_called()


def test_all_existing_mlflow_call_sites_are_covered():
    active_scripts = set()
    for directory in ("models", "jrr"):
        for path in (ROOT / "src" / directory).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            if any(
                isinstance(node, ast.Call)
                and ast.unparse(node.func).startswith("mlflow.")
                for node in ast.walk(tree)
            ):
                active_scripts.add(path.relative_to(ROOT / "src").as_posix())
    assert active_scripts == {path for path, _ in SCRIPTS}

