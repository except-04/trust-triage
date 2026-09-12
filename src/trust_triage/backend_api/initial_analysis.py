"""Bounded PE feature/model/JRR analysis with an independently optional SHAP step."""

from __future__ import annotations

import math
import multiprocessing
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter, ValidationError

from .errors import BackendError
from .model_bundle import ModelBundle, ModelBundleConfig, _file_sha256
from .schemas import TriggeredSignals

_TRIGGERED_SIGNALS = TypeAdapter(TriggeredSignals)


@dataclass(frozen=True)
class InitialAnalysisConfig:
    artifacts: ModelBundleConfig = field(default_factory=ModelBundleConfig)
    extraction_timeout_seconds: float = 30.0
    inference_timeout_seconds: float = 120.0
    xai_timeout_seconds: float = 30.0
    shap_top_k: int = 5
    max_file_size_bytes: int = 50 * 1024 * 1024

    def __post_init__(self) -> None:
        for value in (
            self.extraction_timeout_seconds,
            self.inference_timeout_seconds,
            self.xai_timeout_seconds,
        ):
            if isinstance(value, bool) or not math.isfinite(value) or value <= 0:
                raise ValueError(
                    "Initial-analysis timeouts must be finite and positive."
                )
        if (
            isinstance(self.shap_top_k, bool)
            or not isinstance(self.shap_top_k, int)
            or not 1 <= self.shap_top_k <= 50
        ):
            raise ValueError("shap_top_k must be an integer between 1 and 50.")
        if (
            isinstance(self.max_file_size_bytes, bool)
            or not isinstance(self.max_file_size_bytes, int)
            or self.max_file_size_bytes <= 0
        ):
            raise ValueError("max_file_size_bytes must be a positive integer.")


def _failure(
    code: str, message: str, stage: str, *, http_status: int = 500
) -> BackendError:
    return BackendError(code, message, stage=stage, http_status=http_status)


def _model_input(result: Any, bundle: ModelBundle, sha256: str) -> Any:
    import numpy as np

    status = getattr(result.status, "value", result.status)
    if status != "SUCCESS":
        code = (
            "FEATURE_EXTRACTION_TIMEOUT"
            if status == "TIMEOUT"
            else "FEATURE_EXTRACTION_FAILED"
        )
        raise _failure(
            code,
            f"Feature extraction ended with status {status}.",
            "FEATURE_EXTRACTION",
        )
    if result.sha256 != sha256:
        raise _failure(
            "SAMPLE_HASH_MISMATCH",
            "The extracted sample hash does not match the stored upload.",
            "FEATURE_EXTRACTION",
        )
    selector = bundle.selector
    if result.feature_count != selector.source_schema.feature_count:
        raise _failure(
            "FEATURE_SCHEMA_MISMATCH",
            "The extracted feature count does not match the source schema.",
            "FEATURE_EXTRACTION",
        )
    try:
        values = np.asarray(result.features, dtype=np.float32)
        if not np.all(np.isfinite(values)):
            # The existing FeatureSelector requires finite vectors. Do not
            # replace missing values with zero or claim inference succeeded.
            raise _failure(
                "FEATURE_NONFINITE",
                "The current feature/model contract rejects NaN or infinite inputs; no values were imputed.",
                "FEATURE_EXTRACTION",
            )
        vector = result.to_model_input(selector)
        if vector.dtype != np.dtype("float32") or vector.shape != (
            selector.feature_count,
        ):
            raise ValueError("Invalid model vector schema")
        return vector
    except BackendError:
        raise
    except (TypeError, ValueError, OverflowError) as exc:
        raise _failure(
            "FEATURE_SCHEMA_MISMATCH",
            "The extracted feature names, order, version, or dtype do not match the model selection.",
            "FEATURE_EXTRACTION",
        ) from exc


def _probability(model: Any, matrix: Any, label: str) -> float:
    import numpy as np

    values = np.asarray(model.predict_proba(matrix), dtype=float)
    if (
        values.shape != (1, 2)
        or not np.all(np.isfinite(values))
        or np.any(values < 0)
        or np.any(values > 1)
        or not np.isclose(values.sum(), 1.0, rtol=0, atol=1e-6)
    ):
        raise _failure(
            "MODEL_OUTPUT_INVALID",
            f"{label} returned an invalid binary probability.",
            "MODEL_INFERENCE",
        )
    return float(values[0, 1])


def _single_number(
    value: Any, code: str, stage: str, *, probability: bool = False
) -> float:
    import numpy as np

    values = np.asarray(value, dtype=float)
    if values.shape != (1,) or not np.isfinite(values[0]):
        raise _failure(
            code,
            "An analysis component returned an invalid single-sample score.",
            stage,
        )
    number = float(values[0])
    if probability and not 0 <= number <= 1:
        raise _failure(code, "The calibrated probability is outside [0, 1].", stage)
    return number


def _predict_initial(
    result: Any, bundle: ModelBundle, sha256: str
) -> tuple[dict[str, Any], Any]:
    """Pure adapter seam used by fake-component tests; performs no file IO."""
    import numpy as np

    vector = _model_input(result, bundle, sha256)
    matrix = vector.reshape(1, -1)
    stage = "MODEL_INFERENCE"
    try:
        p_lgbm = _probability(bundle.lgbm, matrix, "LightGBM")
        p_xgb = _probability(bundle.xgb, matrix, "XGBoost")
        stage = "CALIBRATION"
        p_calibrated = _single_number(
            bundle.calibrator.predict(np.asarray([p_lgbm])),
            "CALIBRATION_OUTPUT_INVALID",
            stage,
            probability=True,
        )
        stage = "RISK_SIGNALS"
        disagreement = float(bundle.router.compute_disagreement(p_lgbm, p_xgb))
        ood = _single_number(
            bundle.ood_model.decision_function(matrix), "RISK_OUTPUT_INVALID", stage
        )
        difficulty = float(np.sum(matrix[:, bundle.difficulty_indices], axis=1)[0])
        if (
            not math.isfinite(disagreement)
            or not 0 <= disagreement <= 1
            or not math.isfinite(difficulty)
            or difficulty < 0
        ):
            raise _failure(
                "RISK_OUTPUT_INVALID",
                "Risk signals are outside their valid ranges.",
                stage,
            )
        stage = "INITIAL_JRR"
        routed = bundle.router.route_sample(p_calibrated, disagreement, ood, difficulty)
        expected_routes = {
            "AUTO_BENIGN": "FINAL",
            "AUTO_MALICIOUS": "FINAL",
            "HIGH_RISK_UNCERTAIN": "DEEP_ANALYSIS",
        }
        verdict = routed.get("initial_verdict")
        if (
            verdict not in expected_routes
            or routed.get("route") != expected_routes[verdict]
            or not isinstance(routed.get("reason"), str)
        ):
            raise _failure(
                "JRR_OUTPUT_INVALID",
                "The initial JRR returned an invalid route.",
                stage,
            )
        try:
            # New executions must follow the current JRR contract. Only stored
            # legacy results may omit this field; never infer it from reason.
            signals = _TRIGGERED_SIGNALS.validate_python(
                routed.get("triggered_signals")
            )
        except ValidationError as exc:
            raise _failure(
                "JRR_OUTPUT_INVALID",
                "The initial JRR returned invalid or missing triggered signals.",
                stage,
            ) from exc
        if verdict != "HIGH_RISK_UNCERTAIN" and signals:
            raise _failure(
                "JRR_OUTPUT_INVALID",
                "An automatic JRR verdict cannot contain triggered risk signals.",
                stage,
            )
    except BackendError:
        raise
    except Exception as exc:
        raise _failure(
            f"{stage}_FAILED", "An initial-analysis component failed.", stage
        ) from exc
    selector = bundle.selector
    metadata = {
        "source_schema_version": selector.source_schema.version,
        "output_schema_version": selector.output_schema.version,
        "source_feature_count": selector.source_schema.feature_count,
        "model_feature_count": selector.feature_count,
        "dtype": selector.dtype,
        "selection_id": selector.selection_id,
        "model_version": {
            name.removesuffix("_path"): f"sha256:{digest}"
            for name, digest in bundle.artifact_sha256.items()
            if name in {"lgbm_path", "xgb_path", "calibrator_path", "risk_signals_path"}
        },
        "artifact_sha256": dict(bundle.artifact_sha256),
        "file_type": result.file_type,
        "is_dotnet": result.is_dotnet,
        "missing_features": list(result.missing_features),
        "warnings": list(result.warnings),
        "jrr_thresholds": {
            name: getattr(bundle.router, name)
            for name in (
                "tau_low",
                "tau_high",
                "tau_disagree",
                "tau_ood",
                "tau_difficulty",
            )
        },
    }
    return {
        "prediction": {
            "lgbm_raw_probability": p_lgbm,
            "xgb_raw_probability": p_xgb,
            "calibrated_probability": p_calibrated,
        },
        "risk_signals": {
            "disagreement": disagreement,
            "ood_score": ood,
            "difficulty_score": difficulty,
        },
        "initial_verdict": verdict,
        "route": routed["route"],
        "reason": routed["reason"],
        "triggered_signals": signals,
        "top_features": [],
        "feature_metadata": metadata,
        "xai_status": "PENDING",
        "xai_error": None,
    }, vector


def _explain(bundle: ModelBundle, vector: Any, top_k: int) -> list[dict[str, Any]]:
    import numpy as np

    from trust_triage.explanation import LightGBMShapExplainer

    explainer = LightGBMShapExplainer(
        bundle.lgbm,
        bundle.paths["selection_manifest_path"],
        bundle.paths["top_indices_path"],
        expected_source_schema_version=bundle.selector.source_schema.version,
    )
    # The explainer reads these files again. Refuse an artifact replacement
    # between inference and explanation, including a new internally valid pair.
    if (
        tuple(explainer.feature_names) != bundle.selector.selected_feature_names
        or not np.array_equal(explainer.source_indices, bundle.selector.source_indices)
        or any(
            _file_sha256(bundle.paths[name]) != bundle.artifact_sha256[name]
            for name in ("selection_manifest_path", "top_indices_path")
        )
    ):
        raise _failure(
            "XAI_SCHEMA_MISMATCH",
            "SHAP artifacts changed after initial model input validation.",
            "XAI",
        )
    return [
        {
            "feature_name": item.name,
            "feature_value": float(vector[item.model_input_index]),
            "shap_value": float(item.contribution),
            "direction": item.direction,
        }
        for item in explainer.explain(vector, top_k=top_k)
    ]


def _worker_entry(
    config: InitialAnalysisConfig, path: Path, sha256: str, sender: Any
) -> None:
    """Each upload gets a spawned process; no native model/parser call can hang the API."""
    stage = "MODEL_LOADING"
    try:
        from trust_triage.feature_extraction import EmberV3Extractor

        extractor = EmberV3Extractor(
            max_file_size_bytes=config.max_file_size_bytes, verify_source=True
        )
        bundle = ModelBundle.load(config.artifacts, extractor.schema)
        stage = "FEATURE_EXTRACTION"
        sender.send(("phase", stage))
        # This entire process is already bounded by the parent. Using extract()
        # here avoids creating an orphanable nested extraction subprocess.
        result = extractor.extract(path)
        stage = "MODEL_INFERENCE"
        sender.send(("phase", stage))
        initial, vector = _predict_initial(result, bundle, sha256)
        sender.send(("initial", initial))
        try:
            features = _explain(bundle, vector, config.shap_top_k)
            sender.send(
                (
                    "xai",
                    {
                        "top_features": features,
                        "xai_status": "SUCCESS",
                        "xai_error": None,
                    },
                )
            )
        except BackendError as exc:
            sender.send(
                (
                    "xai",
                    {
                        "top_features": [],
                        "xai_status": "FAILED",
                        "xai_error": exc.to_dict(),
                    },
                )
            )
        except ImportError:
            sender.send(
                (
                    "xai",
                    _xai_failure(
                        "XAI_DEPENDENCY_MISSING",
                        "SHAP dependencies are unavailable; the initial model/JRR decision is preserved.",
                    ),
                )
            )
        except Exception:  # noqa: BLE001 - isolate optional tool failure at the worker boundary.
            sender.send(
                (
                    "xai",
                    _xai_failure(
                        "XAI_FAILED",
                        "SHAP explanation failed; the initial model/JRR decision is preserved.",
                    ),
                )
            )
    except BackendError as exc:
        sender.send(("error", {**exc.to_dict(), "http_status": exc.http_status}))
    except ImportError:
        sender.send(
            (
                "error",
                {
                    "code": "MODEL_DEPENDENCY_MISSING",
                    "message": "Initial-analysis dependencies are unavailable.",
                    "stage": stage,
                    "http_status": 503,
                    "retryable": False,
                },
            )
        )
    except Exception:  # noqa: BLE001 - return a sanitized structured failure across the process boundary.
        sender.send(
            (
                "error",
                {
                    "code": "INITIAL_ANALYSIS_FAILED",
                    "message": "Initial analysis failed.",
                    "stage": stage,
                    "http_status": 500,
                    "retryable": False,
                },
            )
        )
    finally:
        sender.close()


def _xai_failure(code: str, message: str) -> dict[str, Any]:
    return {
        "top_features": [],
        "xai_status": "FAILED",
        "xai_error": _failure(code, message, "XAI").to_dict(),
    }


def _stop_process(process: Any) -> None:
    if process.is_alive():
        process.terminate()
        process.join(timeout=1.0)
    if process.is_alive():
        process.kill()
        process.join(timeout=1.0)
    if not process.is_alive():
        process.join(timeout=0)
        process.close()


class InitialAnalysisService:
    def __init__(
        self,
        config: InitialAnalysisConfig | None = None,
        *,
        process_context: Any = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config or InitialAnalysisConfig()
        self._context = process_context or multiprocessing.get_context("spawn")
        self._clock = clock

    def analyze(
        self, path: Path, *, sha256: str, check: Callable[[], None] | None = None
    ) -> dict[str, Any]:
        if check is not None:
            check()
        # Booting the API requires no model dependencies or local model files.
        # A submitted analysis receives a clear 503 if artifacts are unavailable.
        self.config.artifacts.validated_paths()
        receiver, sender = self._context.Pipe(duplex=False)
        process = self._context.Process(
            target=_worker_entry, args=(self.config, path, sha256, sender)
        )
        phase = "MODEL_LOADING"
        deadline = self._clock() + self.config.inference_timeout_seconds
        initial: dict[str, Any] | None = None
        started = False
        try:
            try:
                process.start()
            except (OSError, RuntimeError) as exc:
                raise _failure(
                    "INITIAL_ANALYSIS_START_FAILED",
                    "The initial-analysis worker could not start.",
                    phase,
                ) from exc
            started = True
            sender.close()
            while True:
                if check is not None:
                    check()
                if self._clock() >= deadline:
                    if initial is not None:
                        return {
                            **initial,
                            **_xai_failure(
                                "XAI_TIMEOUT",
                                "SHAP explanation timed out; the initial model/JRR decision is preserved.",
                            ),
                        }
                    code = (
                        "FEATURE_EXTRACTION_TIMEOUT"
                        if phase == "FEATURE_EXTRACTION"
                        else "INITIAL_ANALYSIS_TIMEOUT"
                    )
                    raise _failure(
                        code,
                        "Initial analysis exceeded its stage time limit.",
                        phase,
                        http_status=504,
                    )
                if receiver.poll(0.1):
                    try:
                        kind, payload = receiver.recv()
                    except EOFError:
                        break
                    if kind == "phase":
                        phase = payload
                        timeout = (
                            self.config.extraction_timeout_seconds
                            if phase == "FEATURE_EXTRACTION"
                            else self.config.inference_timeout_seconds
                        )
                        deadline = self._clock() + timeout
                    elif kind == "initial":
                        initial = payload
                        phase = "XAI"
                        deadline = self._clock() + self.config.xai_timeout_seconds
                    elif kind == "xai" and initial is not None:
                        return {**initial, **payload}
                    elif kind == "error":
                        raise BackendError(
                            payload["code"],
                            payload["message"],
                            stage=payload.get("stage"),
                            http_status=payload.get("http_status", 500),
                            retryable=payload.get("retryable", False),
                        )
                elif not process.is_alive():
                    # The child may have sent its final result after the timed
                    # poll returned False but before is_alive() observed exit.
                    if not receiver.poll(0):
                        break
            if initial is not None:
                return {
                    **initial,
                    **_xai_failure(
                        "XAI_PROCESS_EXITED",
                        "SHAP ended without an explanation; the initial model/JRR decision is preserved.",
                    ),
                }
            raise _failure(
                "INITIAL_ANALYSIS_PROCESS_EXITED",
                "Initial analysis ended without a result.",
                phase,
            )
        finally:
            sender.close()
            receiver.close()
            if started:
                _stop_process(process)
            else:
                process.close()
