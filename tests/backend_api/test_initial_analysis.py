"""No PE bytes, deserialized models, external APIs, or real ML inference are used."""

from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from jrr import JointRiskRouter
from trust_triage.backend_api import initial_analysis as module
from trust_triage.backend_api.errors import BackendError
from trust_triage.backend_api.initial_analysis import (
    InitialAnalysisConfig,
    InitialAnalysisService,
)
from trust_triage.backend_api.model_bundle import ModelBundle, ModelBundleConfig
from trust_triage.backend_api.schemas import InitialResult
from trust_triage.feature_extraction import (
    ExtractionStatus,
    FeatureExtractionResult,
    FeatureSchema,
    FeatureSelector,
)

SHA256 = "b" * 64


class ProbabilityDouble:
    def __init__(self, probability):
        self.probability = probability
        self.inputs = []

    def predict_proba(self, matrix):
        self.inputs.append(matrix.copy())
        return np.array([[1 - self.probability, self.probability]])


class CalibratorDouble:
    def __init__(self, probability):
        self.probability = probability
        self.inputs = []

    def predict(self, values):
        self.inputs.append(values.copy())
        return np.array([self.probability])


@pytest.fixture
def components():
    schema = FeatureSchema(
        "synthetic-v1",
        ("f[0]", "f[1]", "f[2]", "pefilewarnings[0]", "pefilewarnings[1]"),
    )
    selector = FeatureSelector.from_feature_names(
        schema, ("f[0]", "f[2]", "pefilewarnings[0]", "pefilewarnings[1]")
    )
    result = FeatureExtractionResult.success(
        schema=schema, sha256=SHA256, file_type="PE32", values=[3, 7, 11, 0, 0]
    )
    bundle = ModelBundle(
        lgbm=ProbabilityDouble(0.6100023),
        xgb=ProbabilityDouble(0.62),
        calibrator=CalibratorDouble(0.60),
        ood_model=SimpleNamespace(decision_function=lambda values: [0.12345678]),
        difficulty_indices=(2, 3),
        selector=selector,
        router=JointRiskRouter(),
        artifact_sha256={"lgbm_path": "a" * 64, "xgb_path": "c" * 64},
        paths={
            "selection_manifest_path": Path("manifest.json"),
            "top_indices_path": Path("indices.npy"),
        },
    )
    return result, bundle


@pytest.mark.parametrize(
    ("probability", "verdict", "route"),
    [
        (0.60, "AUTO_BENIGN", "FINAL"),
        (0.983645, "AUTO_MALICIOUS", "FINAL"),
        (0.6000001, "HIGH_RISK_UNCERTAIN", "DEEP_ANALYSIS"),
    ],
)
def test_initial_analysis_uses_existing_jrr_without_rounding_inputs(
    components, probability, verdict, route
):
    result, bundle = components
    bundle.calibrator.probability = probability
    output, vector = module._predict_initial(result, bundle, SHA256)
    assert output["initial_verdict"] == verdict
    assert output["route"] == route
    assert output["prediction"]["calibrated_probability"] == probability
    assert output["prediction"]["lgbm_raw_probability"] == 0.6100023
    assert output["risk_signals"]["ood_score"] == 0.12345678
    np.testing.assert_array_equal(vector, [3, 11, 0, 0])
    for model in (bundle.lgbm, bundle.xgb):
        assert model.inputs[0].dtype == np.float32
        assert model.inputs[0].shape == (1, 4)
    np.testing.assert_array_equal(bundle.calibrator.inputs[0], [0.6100023])
    metadata = output["feature_metadata"]
    assert metadata["source_schema_version"] == "synthetic-v1"
    assert metadata["output_schema_version"] == bundle.selector.output_schema.version
    assert metadata["model_version"]["lgbm"] == "sha256:" + "a" * 64
    assert metadata["jrr_thresholds"]["tau_high"] == 0.983645


def test_difficulty_uses_model_positions_and_can_override_confident_probability(
    components,
):
    result, bundle = components
    result.features = [3, 999, 11, 2, 3]
    output, _ = module._predict_initial(result, bundle, SHA256)
    assert output["risk_signals"]["difficulty_score"] == 5
    assert output["initial_verdict"] == "HIGH_RISK_UNCERTAIN"
    assert output["reason"].startswith("High Analysis Difficulty")


@pytest.mark.parametrize("value", [np.nan, np.inf, -np.inf])
def test_nonfinite_features_fail_explicitly_without_imputation_or_prediction(
    components, value
):
    result, bundle = components
    result.features[0] = value
    with pytest.raises(BackendError) as error:
        module._predict_initial(result, bundle, SHA256)
    assert error.value.code == "FEATURE_NONFINITE"
    assert bundle.lgbm.inputs == []
    assert not np.isfinite(result.features[0])


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("sha256", "c" * 64, "SAMPLE_HASH_MISMATCH"),
        ("schema_version", "wrong-v1", "FEATURE_SCHEMA_MISMATCH"),
        ("feature_count", 99, "FEATURE_SCHEMA_MISMATCH"),
        ("feature_names", ["incorrect"] * 5, "FEATURE_SCHEMA_MISMATCH"),
        ("status", ExtractionStatus.PARSE_ERROR, "FEATURE_EXTRACTION_FAILED"),
        ("status", ExtractionStatus.TIMEOUT, "FEATURE_EXTRACTION_TIMEOUT"),
    ],
)
def test_extraction_contract_failures_prevent_model_calls(
    components, field, value, code
):
    result, bundle = components
    setattr(result, field, value)
    with pytest.raises(BackendError) as error:
        module._predict_initial(result, bundle, SHA256)
    assert error.value.code == code
    assert bundle.lgbm.inputs == []


@pytest.mark.parametrize(
    "prediction", [[[0.2, np.nan]], [[-0.1, 1.1]], [[0.2, 0.2]], [0.2, 0.8], [[0.5]]]
)
def test_invalid_model_probabilities_are_not_routed(components, prediction):
    result, bundle = components
    bundle = replace(
        bundle, lgbm=SimpleNamespace(predict_proba=lambda matrix: prediction)
    )
    with pytest.raises(BackendError) as error:
        module._predict_initial(result, bundle, SHA256)
    assert error.value.code == "MODEL_OUTPUT_INVALID"


@pytest.mark.parametrize("probability", [np.nan, np.inf, -0.1, 1.1])
def test_invalid_calibration_output_is_explicit(components, probability):
    result, bundle = components
    bundle.calibrator.probability = probability
    with pytest.raises(BackendError) as error:
        module._predict_initial(result, bundle, SHA256)
    assert error.value.code == "CALIBRATION_OUTPUT_INVALID"


def test_component_exception_is_sanitized_and_has_stage(components):
    result, bundle = components

    def fail(matrix):
        raise ValueError("sensitive internal path or artifact contents")

    bundle = replace(bundle, ood_model=SimpleNamespace(decision_function=fail))
    with pytest.raises(BackendError) as error:
        module._predict_initial(result, bundle, SHA256)
    assert error.value.code == "RISK_SIGNALS_FAILED"
    assert "sensitive" not in error.value.message


def test_shap_maps_the_selected_model_position_to_value(components, monkeypatch):
    _, bundle = components
    calls = {}

    class ExplainerDouble:
        def __init__(self, *args, **kwargs):
            calls["constructor"] = (args, kwargs)
            self.feature_names = bundle.selector.selected_feature_names
            self.source_indices = bundle.selector.source_indices

        def explain(self, vector, *, top_k):
            calls["top_k"] = top_k
            return [
                SimpleNamespace(
                    name="f[2]",
                    contribution=-0.4,
                    direction="BENIGN",
                    model_input_index=1,
                    source_index=2,
                )
            ]

    monkeypatch.setitem(
        sys.modules,
        "trust_triage.explanation",
        SimpleNamespace(LightGBMShapExplainer=ExplainerDouble),
    )
    bundle = replace(
        bundle,
        artifact_sha256={
            "selection_manifest_path": "d" * 64,
            "top_indices_path": "d" * 64,
        },
    )
    monkeypatch.setattr(module, "_file_sha256", lambda path: "d" * 64)
    values = module._explain(bundle, np.array([3, 11, 0, 0], dtype=np.float32), 5)
    assert values == [
        {
            "feature_name": "f[2]",
            "feature_value": 11,
            "shap_value": -0.4,
            "direction": "BENIGN",
        }
    ]
    assert calls["constructor"][0][0] is bundle.lgbm
    assert calls["constructor"][1]["expected_source_schema_version"] == "synthetic-v1"


@pytest.mark.parametrize("mismatch", ["names", "indices", "hash"])
def test_shap_cannot_relabel_existing_input_after_artifact_replacement(
    components, monkeypatch, mismatch
):
    _, bundle = components
    bundle = replace(
        bundle,
        artifact_sha256={
            "selection_manifest_path": "d" * 64,
            "top_indices_path": "d" * 64,
        },
    )

    class ExplainerDouble:
        def __init__(self, *args, **kwargs):
            self.feature_names = (
                ("changed[0]",)
                if mismatch == "names"
                else bundle.selector.selected_feature_names
            )
            self.source_indices = (
                (99,) if mismatch == "indices" else bundle.selector.source_indices
            )

        def explain(self, *args, **kwargs):
            raise AssertionError(
                "mismatched artifacts must fail before SHAP computation"
            )

    monkeypatch.setitem(
        sys.modules,
        "trust_triage.explanation",
        SimpleNamespace(LightGBMShapExplainer=ExplainerDouble),
    )
    monkeypatch.setattr(
        module, "_file_sha256", lambda path: ("e" if mismatch == "hash" else "d") * 64
    )
    with pytest.raises(BackendError) as error:
        module._explain(bundle, np.array([3, 11, 0, 0], dtype=np.float32), 5)
    assert error.value.code == "XAI_SCHEMA_MISMATCH"


class SenderDouble:
    def __init__(self):
        self.messages = []
        self.closed = False

    def send(self, message):
        self.messages.append(message)

    def close(self):
        self.closed = True


def test_worker_emits_jrr_before_shap_and_preserves_it_on_failure(
    components, monkeypatch
):
    import trust_triage.feature_extraction as extraction

    result, bundle = components
    extractor = SimpleNamespace(
        schema=bundle.selector.source_schema, extract=lambda path: result
    )
    monkeypatch.setattr(extraction, "EmberV3Extractor", lambda **kwargs: extractor)
    monkeypatch.setattr(ModelBundle, "load", lambda *args: bundle)

    def fail(*args):
        raise RuntimeError("private SHAP details")

    monkeypatch.setattr(module, "_explain", fail)
    sender = SenderDouble()
    module._worker_entry(
        InitialAnalysisConfig(), Path("never-read-upload.bin"), SHA256, sender
    )
    assert [kind for kind, _ in sender.messages] == ["phase", "phase", "initial", "xai"]
    assert sender.messages[2][1]["initial_verdict"] == "AUTO_BENIGN"
    assert sender.messages[3][1]["xai_status"] == "FAILED"
    assert sender.messages[3][1]["xai_error"]["code"] == "XAI_FAILED"
    assert "private" not in str(sender.messages)
    assert sender.closed


class ReceiverDouble:
    def __init__(self, messages):
        self.messages = list(messages)
        self.closed = False

    def poll(self, timeout):
        return bool(self.messages)

    def recv(self):
        return self.messages.pop(0)

    def close(self):
        self.closed = True


class ProcessDouble:
    def __init__(self, *, alive=True, ignores_terminate=False):
        self.alive = alive
        self.ignores_terminate = ignores_terminate
        self.terminated = self.killed = self.closed = self.started = False

    def start(self):
        self.started = True

    def is_alive(self):
        return self.alive

    def terminate(self):
        self.terminated = True
        if not self.ignores_terminate:
            self.alive = False

    def kill(self):
        self.killed = True
        self.alive = False

    def join(self, timeout):
        pass

    def close(self):
        self.closed = True


def _service(monkeypatch, messages=(), *, alive=True, ignores_terminate=False):
    monkeypatch.setattr(ModelBundleConfig, "validated_paths", lambda self: {})
    receiver, sender = ReceiverDouble(messages), SenderDouble()
    process = ProcessDouble(alive=alive, ignores_terminate=ignores_terminate)
    context = SimpleNamespace(
        Pipe=lambda **kwargs: (receiver, sender), Process=lambda **kwargs: process
    )
    ticks = iter(index * 0.2 for index in range(100))
    service = InitialAnalysisService(
        InitialAnalysisConfig(
            extraction_timeout_seconds=1,
            inference_timeout_seconds=1,
            xai_timeout_seconds=0.5,
        ),
        process_context=context,
        clock=lambda: next(ticks),
    )
    return service, process, receiver


def test_missing_artifacts_returns_clear_unavailable_error_without_starting_child():
    service = InitialAnalysisService()
    with pytest.raises(BackendError) as error:
        service.analyze(Path("never-read-upload.bin"), sha256=SHA256)
    assert error.value.code == "MODEL_NOT_CONFIGURED"
    assert error.value.http_status == 503


def test_model_timeout_terminates_the_process(monkeypatch):
    service, process, receiver = _service(monkeypatch, ignores_terminate=True)
    with pytest.raises(BackendError) as error:
        service.analyze(Path("never-read-upload.bin"), sha256=SHA256)
    assert error.value.code == "INITIAL_ANALYSIS_TIMEOUT"
    assert process.terminated and process.killed and process.closed
    assert receiver.closed


def test_extraction_timeout_has_distinct_stage(monkeypatch):
    service, process, _ = _service(monkeypatch, [("phase", "FEATURE_EXTRACTION")])
    with pytest.raises(BackendError) as error:
        service.analyze(Path("never-read-upload.bin"), sha256=SHA256)
    assert error.value.code == "FEATURE_EXTRACTION_TIMEOUT"
    assert error.value.stage == "FEATURE_EXTRACTION"
    assert process.terminated


@pytest.mark.parametrize("alive", [True, False])
def test_shap_timeout_or_process_exit_preserves_initial_jrr(
    components, monkeypatch, alive
):
    initial, _ = module._predict_initial(*components, SHA256)
    service, process, _ = _service(monkeypatch, [("initial", initial)], alive=alive)
    output = service.analyze(Path("never-read-upload.bin"), sha256=SHA256)
    assert output["prediction"] == initial["prediction"]
    assert output["risk_signals"] == initial["risk_signals"]
    assert output["initial_verdict"] == "AUTO_BENIGN"
    assert output["route"] == "FINAL"
    assert output["top_features"] == []
    assert output["xai_status"] == "FAILED"
    assert output["xai_error"]["code"] == (
        "XAI_TIMEOUT" if alive else "XAI_PROCESS_EXITED"
    )
    assert process.closed


def test_complete_explanation_is_returned_with_initial_result(components, monkeypatch):
    initial, _ = module._predict_initial(*components, SHA256)
    xai = {
        "top_features": [
            {
                "feature_name": "f[0]",
                "feature_value": 3,
                "shap_value": 0.1,
                "direction": "MALICIOUS",
            }
        ],
        "xai_status": "SUCCESS",
        "xai_error": None,
    }
    service, process, _ = _service(monkeypatch, [("initial", initial), ("xai", xai)])
    output = service.analyze(Path("never-read-upload.bin"), sha256=SHA256)
    assert output == {**initial, **xai}
    assert InitialResult.model_validate(output).initial_verdict.value == "AUTO_BENIGN"
    assert process.closed


def test_lease_cancellation_interrupts_work_and_stops_child(monkeypatch):
    service, process, _ = _service(monkeypatch)
    count = 0

    def check():
        nonlocal count
        count += 1
        if count == 3:
            raise BackendError("LEASE_LOST", "Lease lost.")

    with pytest.raises(BackendError) as error:
        service.analyze(Path("never-read-upload.bin"), sha256=SHA256, check=check)
    assert error.value.code == "LEASE_LOST"
    assert process.terminated and process.closed


def test_worker_error_remains_structured(monkeypatch):
    payload = {
        "code": "MODEL_SCHEMA_MISMATCH",
        "message": "Artifact mismatch.",
        "stage": "MODEL_LOADING",
        "http_status": 503,
        "retryable": False,
    }
    service, process, _ = _service(monkeypatch, [("error", payload)])
    with pytest.raises(BackendError) as error:
        service.analyze(Path("never-read-upload.bin"), sha256=SHA256)
    assert error.value.code == "MODEL_SCHEMA_MISMATCH"
    assert error.value.http_status == 503
    assert process.closed


def test_child_exit_after_poll_does_not_discard_buffered_messages(
    components, monkeypatch
):
    initial, _ = module._predict_initial(*components, SHA256)
    xai = {"top_features": [], "xai_status": "SUCCESS", "xai_error": None}
    service, _, receiver = _service(
        monkeypatch, [("initial", initial), ("xai", xai)], alive=False
    )
    first_poll = True

    def poll(timeout):
        nonlocal first_poll
        if first_poll:
            first_poll = False
            return False
        return bool(receiver.messages)

    receiver.poll = poll
    assert service.analyze(Path("never-read-upload.bin"), sha256=SHA256) == {
        **initial,
        **xai,
    }


def test_process_start_failure_is_sanitized_and_cleans_up(monkeypatch):
    service, process, receiver = _service(monkeypatch)

    def fail():
        raise OSError("internal process detail")

    process.start = fail
    with pytest.raises(BackendError) as error:
        service.analyze(Path("never-read-upload.bin"), sha256=SHA256)
    assert error.value.code == "INITIAL_ANALYSIS_START_FAILED"
    assert "internal" not in error.value.message
    assert process.closed and receiver.closed
