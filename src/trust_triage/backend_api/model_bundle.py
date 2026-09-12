"""Load explicitly configured, trusted local artifacts and check their contracts.

Pickle/joblib files are executable serialization. Paths come from server-side
configuration only; an upload or a request must never choose them. Heavy imports
and artifact loading happen in the bounded initial-analysis child process.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, fields
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import BackendError

if TYPE_CHECKING:
    from trust_triage.feature_extraction import FeatureSchema, FeatureSelector


def _schema_error(message: str) -> BackendError:
    return BackendError(
        "MODEL_SCHEMA_MISMATCH", message, http_status=503, stage="MODEL_LOADING"
    )


@dataclass(frozen=True)
class ModelBundleConfig:
    lgbm_path: Path | str | None = None
    xgb_path: Path | str | None = None
    calibrator_path: Path | str | None = None
    risk_signals_path: Path | str | None = None
    top_indices_path: Path | str | None = None
    selection_manifest_path: Path | str | None = None

    def validated_paths(self) -> dict[str, Path]:
        paths: dict[str, Path] = {}
        for field in fields(self):
            value = getattr(self, field.name)
            if value is None or not str(value).strip():
                raise BackendError(
                    "MODEL_NOT_CONFIGURED",
                    "Initial-analysis artifacts are not configured.",
                    http_status=503,
                    stage="MODEL_LOADING",
                )
            path = Path(value).expanduser()
            if not path.is_file():
                raise BackendError(
                    "MODEL_ARTIFACT_MISSING",
                    "A configured initial-analysis artifact is missing.",
                    http_status=503,
                    stage="MODEL_LOADING",
                )
            paths[field.name] = path.resolve()
        return paths


def validate_selection(
    source_schema: FeatureSchema,
    manifest: dict[str, Any],
    indices: Any,
    *,
    indices_sha256: str,
) -> FeatureSelector:
    import numpy as np

    from trust_triage.feature_extraction import FeatureSelector

    required = {"dtype", "feature_count", "source_indices", "feature_names"}
    if not isinstance(manifest, dict) or not required.issubset(manifest):
        raise _schema_error("The selection manifest is missing required schema fields.")
    if source_schema.dtype != "float32" or manifest["dtype"] != "float32":
        raise _schema_error("The source and model input dtype must be float32.")
    if manifest.get("selection_order") != "ascending_source_index":
        raise _schema_error(
            "The selection order must match ascending training indices."
        )
    if manifest.get("feature_count") != 500:
        raise _schema_error("The configured models require exactly 500 input features.")
    declared = manifest["source_indices"]
    if not isinstance(declared, list) or any(
        isinstance(index, bool) or not isinstance(index, int) for index in declared
    ):
        raise _schema_error("Selection source indices must be integers.")
    indices = np.asarray(indices)
    if indices.shape != (500,) or not np.issubdtype(indices.dtype, np.integer):
        raise _schema_error(
            "The top-feature artifact must contain 500 integer indices."
        )
    if not np.all(indices[:-1] < indices[1:]) or not np.array_equal(indices, declared):
        raise _schema_error(
            "The manifest and training indices must match in ascending order."
        )
    expected_hash = manifest.get("source_artifact_sha256")
    if (
        not isinstance(expected_hash, str)
        or expected_hash.casefold() != indices_sha256.casefold()
    ):
        raise _schema_error(
            "The top-feature artifact hash does not match the manifest."
        )
    try:
        return FeatureSelector.from_manifest(source_schema, manifest)
    except (TypeError, ValueError) as exc:
        raise _schema_error(
            "The selected feature schema does not match the extractor."
        ) from exc


def _validate_feature_count(model: Any, count: int, label: str) -> None:
    import numpy as np

    actual = getattr(model, "n_features_in_", None)
    if (
        isinstance(actual, (bool, np.bool_))
        or not isinstance(actual, (int, np.integer))
        or actual != count
    ):
        raise _schema_error(
            f"{label} input feature count does not match the selection."
        )


def validate_model(model: Any, feature_count: int, label: str) -> None:
    import numpy as np

    _validate_feature_count(model, feature_count, label)
    if not np.array_equal(np.asarray(getattr(model, "classes_", [])), [0, 1]):
        raise _schema_error(f"{label} classes must be [0, 1], with class 1 malicious.")
    if not callable(getattr(model, "predict_proba", None)):
        raise _schema_error(f"{label} does not provide predict_proba.")


def validate_calibrator(payload: Any, *, threshold: float) -> Any:
    import numpy as np

    if not isinstance(payload, dict) or not {"model", "threshold"}.issubset(payload):
        raise _schema_error(
            "The calibration artifact must contain model and threshold."
        )
    stored = payload["threshold"]
    if (
        isinstance(stored, (bool, np.bool_))
        or not isinstance(stored, (int, float, np.integer, np.floating))
        or not math.isfinite(float(stored))
        or not 0 <= float(stored) <= 1
        # Router policy is recorded to six decimal places. Accept only rounding
        # error at that precision, never replace its policy with an artifact value.
        or not math.isclose(float(stored), threshold, rel_tol=0, abs_tol=5e-7)
    ):
        raise _schema_error(
            "The calibration threshold does not match the current JRR policy."
        )
    model = payload["model"]
    if not callable(getattr(model, "predict", None)):
        raise _schema_error("The calibration model does not provide predict.")
    return model


def validate_risk_artifact(
    payload: Any, selector: FeatureSelector
) -> tuple[Any, tuple[int, ...]]:
    import numpy as np

    if not isinstance(payload, dict) or not {
        "ood_model",
        "difficulty_indices",
    }.issubset(payload):
        raise _schema_error(
            "The risk artifact must contain OOD and difficulty components."
        )
    model = payload["ood_model"]
    _validate_feature_count(model, selector.feature_count, "OOD")
    if not callable(getattr(model, "decision_function", None)):
        raise _schema_error("The OOD model does not provide decision_function.")
    actual = np.asarray(payload["difficulty_indices"])
    expected = tuple(
        position
        for position, name in enumerate(selector.selected_feature_names)
        if name.startswith("pefilewarnings[")
    )
    if (
        actual.ndim != 1
        or not np.issubdtype(actual.dtype, np.integer)
        or tuple(actual.tolist()) != expected
        or not expected
    ):
        raise _schema_error(
            "Difficulty indices must select the warning positions in model input."
        )
    return model, expected


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_runtime_model_types(
    lgbm: Any, xgb: Any, calibrator: Any, ood_model: Any
) -> None:
    from lightgbm import LGBMClassifier
    from sklearn.ensemble import IsolationForest
    from sklearn.isotonic import IsotonicRegression
    from xgboost import XGBClassifier

    # Dimensions alone cannot detect swapped LightGBM/XGBoost paths: that would
    # apply the LightGBM-trained calibrator to the wrong probability stream.
    for model, expected, label in (
        (lgbm, LGBMClassifier, "LightGBM"),
        (xgb, XGBClassifier, "XGBoost"),
        (calibrator, IsotonicRegression, "Calibration"),
        (ood_model, IsolationForest, "OOD"),
    ):
        if not isinstance(model, expected):
            raise _schema_error(
                f"{label} artifact type does not match the current training pipeline."
            )


@dataclass(frozen=True)
class ModelBundle:
    lgbm: Any
    xgb: Any
    calibrator: Any
    ood_model: Any
    difficulty_indices: tuple[int, ...]
    selector: FeatureSelector
    router: Any
    artifact_sha256: dict[str, str]
    paths: dict[str, Path]

    @classmethod
    def load(
        cls, config: ModelBundleConfig, source_schema: FeatureSchema
    ) -> ModelBundle:
        paths = config.validated_paths()
        try:
            import joblib
            import numpy as np

            from jrr import JointRiskRouter

            hashes = {name: _file_sha256(path) for name, path in paths.items()}
            manifest = json.loads(
                paths["selection_manifest_path"].read_text(encoding="utf-8")
            )
            indices = np.load(paths["top_indices_path"], allow_pickle=False)
            selector = validate_selection(
                source_schema,
                manifest,
                indices,
                indices_sha256=hashes["top_indices_path"],
            )
            # Only server-approved paths reach this loader; never load user PE
            # bytes or any request-supplied pickle/model content.
            lgbm = joblib.load(paths["lgbm_path"])
            xgb = joblib.load(paths["xgb_path"])
            validate_model(lgbm, selector.feature_count, "LightGBM")
            validate_model(xgb, selector.feature_count, "XGBoost")
            router = JointRiskRouter()
            calibrator = validate_calibrator(
                joblib.load(paths["calibrator_path"]), threshold=router.tau_high
            )
            ood_model, difficulty_indices = validate_risk_artifact(
                joblib.load(paths["risk_signals_path"]), selector
            )
            _validate_runtime_model_types(lgbm, xgb, calibrator, ood_model)
            if any(_file_sha256(path) != hashes[name] for name, path in paths.items()):
                raise _schema_error(
                    "An initial-analysis artifact changed while it was loading."
                )
            return cls(
                lgbm,
                xgb,
                calibrator,
                ood_model,
                difficulty_indices,
                selector,
                router,
                hashes,
                paths,
            )
        except BackendError:
            raise
        except ImportError as exc:
            raise BackendError(
                "MODEL_DEPENDENCY_MISSING",
                "Initial-analysis dependencies are unavailable.",
                http_status=503,
                stage="MODEL_LOADING",
            ) from exc
        except Exception as exc:
            raise BackendError(
                "MODEL_LOAD_FAILED",
                "Initial-analysis artifacts could not be loaded.",
                http_status=503,
                stage="MODEL_LOADING",
            ) from exc
