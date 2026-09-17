"""Cache lifetime, actual spawn/IPC and recovery, using only inert feature doubles."""

from __future__ import annotations

import json
import multiprocessing
import os
import threading
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from jrr import JointRiskRouter
from trust_triage.backend_api import initial_worker as module
from trust_triage.backend_api.errors import BackendError
from trust_triage.backend_api.initial_analysis import (
    InitialAnalysisConfig,
    InitialAnalysisService,
)
from trust_triage.backend_api.model_bundle import ModelBundle, ModelBundleConfig
from trust_triage.backend_api.schemas import InitialResult
from trust_triage.feature_extraction import (
    FeatureExtractionResult,
    FeatureSchema,
    FeatureSelector,
)

from .test_initial_analysis import CalibratorDouble, ProbabilityDouble

SHA256 = "b" * 64


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
        ProbabilityDouble(0.61),
        ProbabilityDouble(0.62),
        CalibratorDouble(0.60),
        SimpleNamespace(decision_function=lambda values: [0.123]),
        (2, 3),
        selector,
        JointRiskRouter(),
        {"lgbm_path": "a" * 64},
        {},
    )
    return result, bundle


class ExplainerDouble:
    def explain(self, vector, *, top_k):
        if vector[0] == 13:
            time.sleep(5)
        if vector[0] == 14:
            raise RuntimeError("SECRET private native details")
        return [
            SimpleNamespace(
                name="f[0]",
                model_input_index=0,
                contribution=0.1,
                direction="MALICIOUS",
            )
        ]


class WireDouble:
    def __init__(self, messages):
        self.incoming = list(messages)
        self.outgoing = []
        self.closed = False

    def recv_bytes(self, limit):
        if not self.incoming:
            raise EOFError
        return json.dumps(self.incoming.pop(0)).encode()

    def send_bytes(self, data):
        self.outgoing.append(json.loads(data))

    def close(self):
        self.closed = True


def test_model_worker_loads_bundle_and_builds_shap_only_once(monkeypatch):
    import trust_triage.feature_extraction as extraction

    result, bundle = components()
    calls = []
    monkeypatch.setattr(
        extraction,
        "EmberV3Extractor",
        lambda **kwargs: SimpleNamespace(schema=bundle.selector.source_schema),
    )
    monkeypatch.setattr(
        ModelBundle, "load", lambda *args: calls.append("model_load") or bundle
    )
    monkeypatch.setattr(
        module,
        "_build_explainer",
        lambda _: calls.append("shap_init") or ExplainerDouble(),
    )
    wire = WireDouble(
        [
            {
                "kind": "analyze",
                "job_id": job_id,
                "payload": {"features": result.to_dict(), "sha256": SHA256},
            }
            for job_id in ("job-1", "job-2")
        ]
    )
    module._model_entry(InitialAnalysisConfig(), wire)
    assert calls == ["model_load", "shap_init"]
    assert [message["kind"] for message in wire.outgoing] == [
        "ready",
        "initial",
        "xai",
        "initial",
        "xai",
    ]
    assert wire.outgoing[1]["payload"] == wire.outgoing[3]["payload"]
    assert wire.outgoing[2]["payload"] == wire.outgoing[4]["payload"]
    assert wire.closed


def test_extractor_sends_only_features_not_pe_or_unused_metadata(monkeypatch):
    import trust_triage.feature_extraction as extraction

    result, _ = components()
    result.metadata = {"unused": "private extraction implementation"}
    calls = []
    extractor = SimpleNamespace(extract=lambda path: calls.append(path) or result)
    monkeypatch.setattr(extraction, "EmberV3Extractor", lambda **kwargs: extractor)
    wire = WireDouble([])
    module._extract_entry(1024, Path("never-read-PE.bin"), "job-1", wire)
    assert calls == [Path("never-read-PE.bin")]
    assert wire.outgoing[0]["kind"] == "features"
    assert wire.outgoing[0]["payload"]["metadata"] == {}
    assert wire.outgoing[0]["payload"]["api_groups"] is None
    assert "never-read-PE" not in json.dumps(wire.outgoing)
    assert "private" not in json.dumps(wire.outgoing)
    assert wire.closed


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_extractor_rejects_nonfinite_features_before_transport(monkeypatch, value):
    import trust_triage.feature_extraction as extraction

    result, _ = components()
    result.features[0] = value
    monkeypatch.setattr(
        extraction,
        "EmberV3Extractor",
        lambda **kwargs: SimpleNamespace(extract=lambda path: result),
    )
    wire = WireDouble([])
    module._extract_entry(1024, Path("never-read-PE.bin"), "job-1", wire)
    assert wire.outgoing[0]["payload"]["code"] == "FEATURE_NONFINITE"


def harmless_model_target(config, connection):
    """Run the production model loop after replacing only the ML components."""
    import trust_triage.feature_extraction as extraction

    _, bundle = components()
    counts = {"loads": 0, "shap": 0}
    original_predict = module._predict_initial

    def load(*args):
        counts["loads"] += 1
        return bundle

    def build(_bundle):
        counts["shap"] += 1
        return ExplainerDouble()

    def predict(result, current_bundle, sha256):
        if "hang_inference" in result.warnings:
            time.sleep(5)
        if "crash_inference" in result.warnings:
            raise RuntimeError("SECRET native prediction failure")
        initial, vector = original_predict(result, current_bundle, sha256)
        initial["feature_metadata"]["test_model_loads"] = counts["loads"]
        initial["feature_metadata"]["test_model_pid"] = os.getpid()
        return initial, vector

    def explain(current_bundle, vector, top_k, *, explainer=None):
        from trust_triage.backend_api.initial_analysis import _explain

        answer = _explain(current_bundle, vector, top_k, explainer=explainer)
        # Observe the actual cached explainer without changing production output.
        answer[0]["feature_name"] = f"shap_init_count={counts['shap']}"
        return answer

    extraction.EmberV3Extractor = lambda **kwargs: SimpleNamespace(
        schema=bundle.selector.source_schema
    )
    ModelBundle.load = load
    module._build_explainer, module._predict_initial, module._explain = (
        build,
        predict,
        explain,
    )
    module._model_entry(config, connection)


def harmless_extraction_target(max_file_size, path, job_id, connection):
    try:
        if path.name == "hang_extraction":
            time.sleep(5)
        result, _ = components()
        result.warnings = [f"extractor_pid={os.getpid()}"]
        if path.name in {"hang_inference", "crash_inference"}:
            result.warnings.append(path.name)
        if path.name == "hang_xai":
            result.features[0] = 13
        if path.name == "fail_xai":
            result.features[0] = 14
        if path.name == "wrong_sha":
            result.sha256 = "c" * 64
        if path.name == "large_result":
            result.warnings.append("x" * (256 * 1024))
        module._send(connection, "features", job_id, result.to_dict())
    finally:
        connection.close()


@pytest.fixture
def reusable(tmp_path):
    paths = {}
    for name in ModelBundleConfig.__dataclass_fields__:
        path = tmp_path / name
        path.write_text("inert test artifact; never deserialized", encoding="utf-8")
        paths[name] = path
    config = InitialAnalysisConfig(
        artifacts=ModelBundleConfig(**paths),
        inference_timeout_seconds=15,
        extraction_timeout_seconds=10,
        xai_timeout_seconds=5,
    )
    service = InitialAnalysisService(config)
    session = module.ReusableInitialAnalysis(
        config,
        multiprocessing.get_context("spawn"),
        time.monotonic,
        model_target=harmless_model_target,
        extraction_target=harmless_extraction_target,
    )
    service._reusable = session
    try:
        yield service, session
    finally:
        service.close()


def analyze(service, name="normal"):
    return service.analyze(Path(name), sha256=SHA256)


def test_actual_spawn_reuses_models_and_shap_with_fresh_extraction(reusable, caplog):
    service, session = reusable
    with caplog.at_level("INFO", logger=module.__name__):
        first, second = analyze(service), analyze(service)
    assert first["feature_metadata"]["test_model_loads"] == 1
    assert second["feature_metadata"]["test_model_loads"] == 1
    assert (
        first["feature_metadata"]["test_model_pid"]
        == second["feature_metadata"]["test_model_pid"]
    )
    assert (
        first["feature_metadata"]["warnings"] != second["feature_metadata"]["warnings"]
    )
    assert first["prediction"] == second["prediction"]
    assert first["risk_signals"] == second["risk_signals"]
    assert first["top_features"] == second["top_features"]
    assert first["top_features"][0]["feature_name"] == "shap_init_count=1"
    assert session.jobs == 2 and session.process.is_alive()
    assert InitialResult.model_validate(second).initial_verdict.value == "AUTO_BENIGN"
    assert "model_reused=False" in caplog.text and "model_reused=True" in caplog.text
    for stage in ("MODEL_LOADING", "FEATURE_EXTRACTION", "MODEL_INFERENCE", "XAI"):
        assert f"stage={stage}" in caplog.text


def test_model_artifact_replacement_restarts_cache(reusable):
    service, session = reusable
    first = analyze(service)
    Path(session.config.artifacts.lgbm_path).write_text(
        "new inert model version", encoding="utf-8"
    )
    second = analyze(service)
    assert (
        first["feature_metadata"]["test_model_pid"]
        != second["feature_metadata"]["test_model_pid"]
    )
    assert second["feature_metadata"]["test_model_loads"] == 1
    assert session.jobs == 1


def test_worker_recycles_after_configured_job_count(reusable):
    service, session = reusable
    session.config = replace(session.config, model_worker_max_jobs=2)
    first, second = analyze(service), analyze(service)
    assert (
        first["feature_metadata"]["test_model_pid"]
        == second["feature_metadata"]["test_model_pid"]
    )
    assert session.process is None and session.channel is None
    third = analyze(service)
    assert (
        first["feature_metadata"]["test_model_pid"]
        != third["feature_metadata"]["test_model_pid"]
    )


@pytest.mark.parametrize("case", ["hang_inference", "crash_inference", "wrong_sha"])
def test_prediction_failure_discards_worker_and_next_job_recovers(reusable, case):
    service, session = reusable
    first = analyze(service)
    session.config = replace(session.config, inference_timeout_seconds=0.3)
    with pytest.raises(BackendError) as caught:
        analyze(service, case)
    assert (
        caught.value.code
        == {
            "hang_inference": "INITIAL_ANALYSIS_TIMEOUT",
            "crash_inference": "INITIAL_ANALYSIS_FAILED",
            "wrong_sha": "SAMPLE_HASH_MISMATCH",
        }[case]
    )
    assert "SECRET" not in str(caught.value)
    assert session.process is None and session.channel is None
    session.config = replace(session.config, inference_timeout_seconds=15)
    recovered = analyze(service)
    assert (
        recovered["feature_metadata"]["test_model_pid"]
        != first["feature_metadata"]["test_model_pid"]
    )


@pytest.mark.parametrize(
    "case,code", [("hang_xai", "XAI_TIMEOUT"), ("fail_xai", "XAI_FAILED")]
)
def test_shap_failure_preserves_jrr_and_replaces_worker(reusable, case, code):
    service, session = reusable
    first = analyze(service)
    session.config = replace(session.config, xai_timeout_seconds=0.3)
    result = analyze(service, case)
    assert result["prediction"] == first["prediction"]
    assert result["initial_verdict"] == "AUTO_BENIGN" and result["route"] == "FINAL"
    assert result["xai_status"] == "FAILED" and result["xai_error"]["code"] == code
    assert "SECRET" not in str(result)
    assert session.process is None
    assert analyze(service)["xai_status"] == "SUCCESS"


def test_extraction_timeout_keeps_idle_models_and_stops_extractor(reusable):
    service, session = reusable
    first = analyze(service)
    session.config = replace(session.config, extraction_timeout_seconds=0.3)
    with pytest.raises(BackendError) as caught:
        analyze(service, "hang_extraction")
    assert caught.value.code == "FEATURE_EXTRACTION_TIMEOUT"
    assert session.process is not None and session.process.is_alive()
    session.config = replace(session.config, extraction_timeout_seconds=10)
    second = analyze(service)
    assert (
        first["feature_metadata"]["test_model_pid"]
        == second["feature_metadata"]["test_model_pid"]
    )


def test_lease_cancellation_discards_pending_prediction(reusable):
    service, session = reusable
    analyze(service)
    previous_writer = session.channel.writer

    def check():
        if session.channel.writer is not previous_writer:
            raise BackendError("LEASE_LOST", "Analysis ownership expired.")

    with pytest.raises(BackendError, match="Analysis ownership"):
        service.analyze(Path("normal"), sha256=SHA256, check=check)
    assert session.process is None
    assert analyze(service)["xai_status"] == "SUCCESS"


def test_large_feature_result_does_not_block_pipe_deadlines(reusable):
    service, _ = reusable
    result = analyze(service, "large_result")
    assert len(result["feature_metadata"]["warnings"][-1]) == 256 * 1024
    assert result["xai_status"] == "SUCCESS"


def test_close_releases_native_worker_and_ipc_threads(reusable):
    service, session = reusable
    analyze(service)
    child, channel = session.process, session.channel
    pid = child.pid
    service.close()
    service.close()
    assert session.process is None and session.channel is None
    assert not channel.reader.is_alive()
    assert channel.writer is None or not channel.writer.is_alive()
    assert pid not in {process.pid for process in multiprocessing.active_children()}


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "unknown", "job_id": "job-1", "payload": {}},
        {"kind": "error", "job_id": "job-1", "payload": {"code": "E"}},
    ],
)
def test_malformed_model_worker_response_is_sanitized(payload):
    session = module.ReusableInitialAnalysis(
        InitialAnalysisConfig(), None, time.monotonic
    )
    channel = module._Channel(WireDouble([payload]))
    try:
        with pytest.raises(BackendError) as caught:
            session._next(
                channel, "job-1", time.monotonic() + 1, "MODEL_INFERENCE", None
            )
        assert caught.value.code == "INITIAL_ANALYSIS_PROTOCOL_ERROR"
        assert "invalid" in caught.value.message
    finally:
        channel.close()


class BlockingConnection:
    def __init__(self):
        self.closed = threading.Event()

    def recv_bytes(self, maximum):
        self.closed.wait(5)
        raise EOFError

    def send_bytes(self, data):
        self.closed.wait(5)
        raise OSError("SECRET pipe details")

    def close(self):
        self.closed.set()


@pytest.mark.parametrize("direction", ["read", "write"])
def test_blocking_ipc_cannot_block_supervisor_timeout(direction):
    session = module.ReusableInitialAnalysis(
        InitialAnalysisConfig(), None, time.monotonic
    )
    channel = module._Channel(BlockingConnection())
    deadline = time.monotonic() + 0.1
    try:
        with pytest.raises(BackendError) as caught:
            if direction == "read":
                session._next(channel, "job-1", deadline, "MODEL_INFERENCE", None)
            else:
                channel.send(
                    "analyze",
                    "job-1",
                    {},
                    lambda: session._check(deadline, "MODEL_INFERENCE", None),
                )
        assert caught.value.code == "INITIAL_ANALYSIS_TIMEOUT"
        assert time.monotonic() < deadline + 1
    finally:
        channel.close()
    assert not channel.reader.is_alive()
    assert channel.writer is None or not channel.writer.is_alive()


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, 10001])
def test_recycle_limit_is_bounded(limit):
    with pytest.raises(ValueError, match="model_worker_max_jobs"):
        InitialAnalysisConfig(model_worker_max_jobs=limit)


@pytest.mark.parametrize("value", ["true", 1, None])
def test_reuse_switch_must_be_boolean(value):
    with pytest.raises(TypeError, match="reuse_models"):
        InitialAnalysisConfig(reuse_models=value)
