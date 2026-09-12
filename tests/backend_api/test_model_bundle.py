"""Bundle validation uses only synthetic metadata and inert model doubles."""

from __future__ import annotations

import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType, SimpleNamespace

import numpy as np
import pytest

from trust_triage.backend_api.errors import BackendError
from trust_triage.backend_api.model_bundle import (
    ModelBundleConfig,
    _validate_runtime_model_types,
    validate_calibrator,
    validate_model,
    validate_risk_artifact,
    validate_selection,
)
from trust_triage.feature_extraction import FeatureSchema, FeatureSelector

THRESHOLD = 0.983645
INDICES_SHA256 = "a" * 64
PATH_FIELDS = (
    "lgbm_path",
    "xgb_path",
    "calibrator_path",
    "risk_signals_path",
    "top_indices_path",
    "selection_manifest_path",
)


def _unused_prediction(*args, **kwargs):
    raise AssertionError("metadata validation must not run model inference")


def _classifier(**overrides):
    properties = {
        "n_features_in_": 500,
        "classes_": np.array([0, 1]),
        "predict_proba": _unused_prediction,
    }
    properties.update(overrides)
    return SimpleNamespace(**properties)


def _ood_model(**overrides):
    properties = {
        "n_features_in_": 500,
        "decision_function": _unused_prediction,
    }
    properties.update(overrides)
    return SimpleNamespace(**properties)


@pytest.fixture
def selection_contract():
    names = tuple(f"f[{index}]" for index in range(498)) + tuple(
        f"pefilewarnings[{index}]" for index in range(4)
    )
    schema = FeatureSchema("synthetic-source-v1", names)
    selector = FeatureSelector.from_feature_names(
        schema, names[:500], selection_id="synthetic-top500"
    )
    manifest = selector.to_dict()
    manifest.update(
        selection_order="ascending_source_index",
        source_artifact="synthetic-indices.npy",
        source_artifact_sha256=INDICES_SHA256,
    )
    return schema, selector, manifest, np.arange(500, dtype=np.int64)


@pytest.fixture
def artifact_paths(tmp_path):
    paths = {}
    for field in PATH_FIELDS:
        path = tmp_path / f"{field}.placeholder"
        path.write_text("inert path fixture; never deserialize", encoding="utf-8")
        paths[field] = path
    return paths


def _validate_selection(
    contract, *, manifest=None, indices=None, digest=INDICES_SHA256
):
    schema, _, original_manifest, original_indices = contract
    return validate_selection(
        schema,
        original_manifest if manifest is None else manifest,
        original_indices if indices is None else indices,
        indices_sha256=digest,
    )


def test_bundle_config_requires_explicit_model_artifacts():
    with pytest.raises(BackendError) as error:
        ModelBundleConfig().validated_paths()
    assert error.value.code == "MODEL_NOT_CONFIGURED"


@pytest.mark.parametrize("field", PATH_FIELDS)
def test_bundle_config_rejects_partially_configured_bundle(artifact_paths, field):
    artifact_paths[field] = None
    with pytest.raises(BackendError) as error:
        ModelBundleConfig(**artifact_paths).validated_paths()
    assert error.value.code == "MODEL_NOT_CONFIGURED"


def test_bundle_config_resolves_paths_without_deserializing_them(artifact_paths):
    config = ModelBundleConfig(
        **{name: str(path) for name, path in artifact_paths.items()}
    )
    resolved = config.validated_paths()
    assert resolved == {name: path.resolve() for name, path in artifact_paths.items()}
    assert all(isinstance(path, Path) for path in resolved.values())


@pytest.mark.parametrize("field", PATH_FIELDS)
def test_bundle_config_rejects_missing_artifact(artifact_paths, tmp_path, field):
    artifact_paths[field] = tmp_path / f"missing-{field}"
    with pytest.raises(BackendError) as error:
        ModelBundleConfig(**artifact_paths).validated_paths()
    assert error.value.code == "MODEL_ARTIFACT_MISSING"


def test_bundle_config_rejects_directory_instead_of_artifact(artifact_paths, tmp_path):
    artifact_paths["lgbm_path"] = tmp_path
    with pytest.raises(BackendError) as error:
        ModelBundleConfig(**artifact_paths).validated_paths()
    assert error.value.code == "MODEL_ARTIFACT_MISSING"


def test_selection_preserves_validated_names_order_and_dtype(selection_contract):
    schema, expected, _, _ = selection_contract
    actual = _validate_selection(selection_contract)
    assert isinstance(actual, FeatureSelector)
    assert actual.selected_feature_names == expected.selected_feature_names
    assert actual.source_indices == expected.source_indices
    assert actual.output_schema.version == expected.output_schema.version
    vector = actual.select_vector(np.arange(schema.feature_count, dtype=np.float64))
    assert vector.shape == (500,)
    assert vector.dtype == np.dtype("float32")
    np.testing.assert_array_equal(vector, np.arange(500, dtype=np.float32))


def test_selection_generates_output_schema_when_manifest_omits_it(selection_contract):
    _, expected, original, _ = selection_contract
    manifest = deepcopy(original)
    manifest.pop("output_schema_version")
    actual = _validate_selection(selection_contract, manifest=manifest)
    assert actual.output_schema.version == expected.output_schema.version


@pytest.mark.parametrize(
    "field",
    [
        "source_schema_version",
        "feature_names",
        "feature_count",
        "dtype",
        "source_indices",
        "selection_order",
        "source_artifact_sha256",
    ],
)
def test_selection_requires_explicit_input_contract(selection_contract, field):
    manifest = deepcopy(selection_contract[2])
    manifest.pop(field)
    with pytest.raises(BackendError) as error:
        _validate_selection(selection_contract, manifest=manifest)
    assert error.value.code == "MODEL_SCHEMA_MISMATCH"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_schema_version", "unrelated-schema-v2"),
        ("output_schema_version", "unrelated-output-v2"),
        ("dtype", "float64"),
        ("feature_count", 499),
        ("feature_count", True),
        ("selection_order", "importance_rank"),
        ("source_artifact_sha256", "b" * 64),
    ],
)
def test_selection_rejects_inconsistent_manifest(selection_contract, field, value):
    manifest = deepcopy(selection_contract[2])
    manifest[field] = value
    with pytest.raises(BackendError) as error:
        _validate_selection(selection_contract, manifest=manifest)
    assert error.value.code == "MODEL_SCHEMA_MISMATCH"


@pytest.mark.parametrize(
    "indices",
    [
        np.arange(500, dtype=np.int64)[::-1],
        np.arange(499, dtype=np.int64),
        np.arange(500, dtype=np.int64).reshape(1, 500),
        np.arange(500, dtype=np.float64),
        np.zeros(500, dtype=np.int64),
        np.full(500, np.nan),
        np.full(500, np.inf),
    ],
    ids=["reordered", "short", "matrix", "floating", "duplicates", "nan", "infinite"],
)
def test_selection_rejects_invalid_index_artifact(selection_contract, indices):
    with pytest.raises(BackendError) as error:
        _validate_selection(selection_contract, indices=indices)
    assert error.value.code == "MODEL_SCHEMA_MISMATCH"


def test_selection_rejects_manifest_names_with_swapped_feature_meanings(
    selection_contract,
):
    manifest = deepcopy(selection_contract[2])
    manifest["feature_names"][0], manifest["feature_names"][1] = (
        manifest["feature_names"][1],
        manifest["feature_names"][0],
    )
    with pytest.raises(BackendError) as error:
        _validate_selection(selection_contract, manifest=manifest)
    assert error.value.code == "MODEL_SCHEMA_MISMATCH"


def test_selection_rejects_consistently_declared_non_top500_dimension(
    selection_contract,
):
    schema = selection_contract[0]
    selector = FeatureSelector.from_feature_names(
        schema, schema.feature_names[:499], selection_id="wrong-count"
    )
    manifest = selector.to_dict()
    manifest.update(
        selection_order="ascending_source_index",
        source_artifact_sha256=INDICES_SHA256,
    )
    with pytest.raises(BackendError) as error:
        _validate_selection(
            selection_contract,
            manifest=manifest,
            indices=np.arange(499, dtype=np.int64),
        )
    assert error.value.code == "MODEL_SCHEMA_MISMATCH"


def test_classifier_accepts_binary_positive_class_contract_without_inference():
    assert validate_model(_classifier(), 500, "LightGBM") is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"n_features_in_": 499},
        {"n_features_in_": np.nan},
        {"classes_": np.array([1, 0])},
        {"classes_": np.array([0, 1, 2])},
        {"classes_": np.array([0, np.nan])},
        {"classes_": np.array(["BENIGN", "MALICIOUS"])},
        {"predict_proba": None},
    ],
    ids=[
        "dimension",
        "nan-dimension",
        "class-order",
        "multiclass",
        "nan-class",
        "labels",
        "method",
    ],
)
def test_classifier_rejects_incompatible_contract(overrides):
    with pytest.raises(BackendError) as error:
        validate_model(_classifier(**overrides), 500, "LightGBM")
    assert error.value.code == "MODEL_SCHEMA_MISMATCH"


@pytest.mark.parametrize("delta", [0.0, -4.9e-7, 4.9e-7])
def test_calibrator_accepts_numpy_scalar_threshold_within_tolerance(delta):
    model = SimpleNamespace(predict=_unused_prediction)
    payload = {"model": model, "threshold": np.float64(THRESHOLD + delta)}
    assert validate_calibrator(payload, threshold=THRESHOLD) is model


@pytest.mark.parametrize(
    "value",
    [np.nan, np.inf, -np.inf, True, "0.983645", THRESHOLD - 5.1e-7, THRESHOLD + 5.1e-7],
    ids=["nan", "positive-inf", "negative-inf", "bool", "text", "below", "above"],
)
def test_calibrator_rejects_invalid_or_different_threshold(value):
    payload = {"model": SimpleNamespace(predict=_unused_prediction), "threshold": value}
    with pytest.raises(BackendError) as error:
        validate_calibrator(payload, threshold=THRESHOLD)
    assert error.value.code == "MODEL_SCHEMA_MISMATCH"


@pytest.mark.parametrize(
    "payload",
    [None, {}, {"threshold": THRESHOLD}, {"model": None, "threshold": THRESHOLD}],
)
def test_calibrator_requires_usable_model_and_explicit_threshold(payload):
    with pytest.raises(BackendError) as error:
        validate_calibrator(payload, threshold=THRESHOLD)
    assert error.value.code == "MODEL_SCHEMA_MISMATCH"


def test_risk_artifact_accepts_warning_positions_in_selected_vector(selection_contract):
    selector = selection_contract[1]
    model = _ood_model()
    actual_model, difficulty_indices = validate_risk_artifact(
        {
            "ood_model": model,
            "difficulty_indices": np.array([498, 499], dtype=np.int64),
        },
        selector,
    )
    assert actual_model is model
    assert difficulty_indices == (498, 499)


@pytest.mark.parametrize(
    "indices",
    [
        [],
        [0, 1],
        [498],
        [499, 498],
        [498, 498],
        [498, 500],
        [-1, 498],
        [498.0, 499.0],
        [np.nan, 499],
        [np.inf, 499],
        [[498, 499]],
    ],
    ids=[
        "empty",
        "wrong-group",
        "missing",
        "order",
        "duplicate",
        "outside",
        "negative",
        "float",
        "nan",
        "inf",
        "matrix",
    ],
)
def test_risk_artifact_rejects_invalid_warning_positions(selection_contract, indices):
    with pytest.raises(BackendError) as error:
        validate_risk_artifact(
            {"ood_model": _ood_model(), "difficulty_indices": np.asarray(indices)},
            selection_contract[1],
        )
    assert error.value.code == "MODEL_SCHEMA_MISMATCH"


@pytest.mark.parametrize(
    "model", [_ood_model(n_features_in_=499), _ood_model(decision_function=None), None]
)
def test_risk_artifact_requires_compatible_ood_model(selection_contract, model):
    with pytest.raises(BackendError) as error:
        validate_risk_artifact(
            {"ood_model": model, "difficulty_indices": np.array([498, 499])},
            selection_contract[1],
        )
    assert error.value.code == "MODEL_SCHEMA_MISMATCH"


@pytest.mark.parametrize("payload", [None, {}, {"ood_model": _ood_model()}])
def test_risk_artifact_requires_explicit_components(selection_contract, payload):
    with pytest.raises(BackendError) as error:
        validate_risk_artifact(payload, selection_contract[1])
    assert error.value.code == "MODEL_SCHEMA_MISMATCH"


@pytest.fixture
def runtime_models(monkeypatch):
    """Inject distinct inert types without importing the real ML libraries."""
    modules = {}
    instances = []
    for module_name, class_name in (
        ("lightgbm", "LGBMClassifier"),
        ("xgboost", "XGBClassifier"),
        ("sklearn.isotonic", "IsotonicRegression"),
        ("sklearn.ensemble", "IsolationForest"),
    ):
        module = ModuleType(module_name)
        inert_class = type(class_name, (), {})
        setattr(module, class_name, inert_class)
        modules[module_name] = module
        instances.append(inert_class())

    sklearn = ModuleType("sklearn")
    sklearn.__path__ = []
    sklearn.isotonic = modules["sklearn.isotonic"]
    sklearn.ensemble = modules["sklearn.ensemble"]
    modules["sklearn"] = sklearn
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    return instances


def test_runtime_model_types_accept_matching_pipeline_components(runtime_models):
    assert _validate_runtime_model_types(*runtime_models) is None


def test_runtime_model_types_reject_swapped_probability_models(runtime_models):
    lgbm, xgb, calibrator, ood_model = runtime_models
    with pytest.raises(BackendError) as error:
        _validate_runtime_model_types(xgb, lgbm, calibrator, ood_model)
    assert error.value.code == "MODEL_SCHEMA_MISMATCH"
    assert error.value.stage == "MODEL_LOADING"
    assert error.value.http_status == 503


@pytest.mark.parametrize(
    ("position", "label"),
    [(0, "LightGBM"), (1, "XGBoost"), (2, "Calibration"), (3, "OOD")],
)
def test_runtime_model_types_reject_wrong_component_family(
    runtime_models, position, label
):
    models = list(runtime_models)
    models[position] = models[(position + 1) % len(models)]
    with pytest.raises(BackendError) as error:
        _validate_runtime_model_types(*models)
    assert error.value.code == "MODEL_SCHEMA_MISMATCH"
    assert label in error.value.message
