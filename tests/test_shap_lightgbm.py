from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import lightgbm as lgb
import numpy as np
import pytest
import shap

from trust_triage.explanation import (
    FeatureOrderingError,
    LightGBMShapExplainer,
    ShapExplanationError,
)


TEST_SCHEMA_VERSION = "ember2024-v3-pe-test0000000"


def _write_artifacts(tmp_path: Path) -> tuple[Path, Path]:
    indices = np.arange(500, dtype=np.int64)
    indices_path = tmp_path / "top_feature_indices_500.npy"
    np.save(indices_path, indices)
    manifest = {
        "feature_count": 500,
        "selection_order": "ascending_source_index",
        "source_schema_version": TEST_SCHEMA_VERSION,
        "feature_names": [f"group[{index}]" for index in range(500)],
        "source_indices": indices.tolist(),
        "source_artifact_sha256": hashlib.sha256(indices_path.read_bytes()).hexdigest(),
    }
    manifest_path = tmp_path / "selection.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path, indices_path


def _fake_model() -> SimpleNamespace:
    return SimpleNamespace(
        n_features_in_=500,
        classes_=np.array([0, 1]),
        get_params=lambda: {"objective": "binary"},
    )


def _build_without_init(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    contributions: np.ndarray,
    *,
    values_shape: tuple[int, ...] = (1, 500),
    base_shape: tuple[int, ...] = (1,),
) -> LightGBMShapExplainer:
    manifest_path, indices_path = _write_artifacts(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    names, source_indices, groups, schema_version = (
        LightGBMShapExplainer._validate_ordering(manifest, indices_path)
    )
    instance = object.__new__(LightGBMShapExplainer)
    instance.source_schema_version = schema_version
    instance.feature_names = names
    instance.source_indices = source_indices
    instance.feature_groups = groups
    instance.model = SimpleNamespace(
        predict=lambda values, raw_score=True: np.array([contributions.sum()])
    )

    class FakeExplainer:
        def __call__(self, values, check_additivity=True):
            shaped_values = np.asarray(contributions).reshape(values_shape)
            return shap.Explanation(
                values=shaped_values,
                base_values=np.zeros(base_shape),
                data=values,
            )

    instance._explainer = FakeExplainer()
    return instance


def test_ordering_accepts_matching_manifest_and_npy(tmp_path: Path) -> None:
    manifest_path, indices_path = _write_artifacts(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    names, indices, groups, schema_version = LightGBMShapExplainer._validate_ordering(
        manifest, indices_path
    )

    assert names[17] == "group[17]"
    assert indices[17] == 17
    assert groups[17] == "group"
    assert schema_version == TEST_SCHEMA_VERSION


def test_ordering_rejects_missing_source_schema_version(tmp_path: Path) -> None:
    manifest_path, indices_path = _write_artifacts(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["source_schema_version"]

    with pytest.raises(FeatureOrderingError, match="source_schema_version"):
        LightGBMShapExplainer._validate_ordering(manifest, indices_path)


def test_ordering_accepts_matching_expected_source_schema_version(
    tmp_path: Path,
) -> None:
    manifest_path, indices_path = _write_artifacts(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    _, _, _, schema_version = LightGBMShapExplainer._validate_ordering(
        manifest,
        indices_path,
        expected_source_schema_version=TEST_SCHEMA_VERSION,
    )

    assert schema_version == TEST_SCHEMA_VERSION


def test_ordering_rejects_mismatched_expected_source_schema_version(
    tmp_path: Path,
) -> None:
    manifest_path, indices_path = _write_artifacts(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    with pytest.raises(FeatureOrderingError, match="does not match the live"):
        LightGBMShapExplainer._validate_ordering(
            manifest,
            indices_path,
            expected_source_schema_version="ember2024-v3-pe-someothercommit",
        )


def test_ordering_rejects_same_values_in_different_order(tmp_path: Path) -> None:
    manifest_path, indices_path = _write_artifacts(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["source_indices"][10], manifest["source_indices"][11] = (
        manifest["source_indices"][11],
        manifest["source_indices"][10],
    )

    with pytest.raises(FeatureOrderingError, match="strictly ascending"):
        LightGBMShapExplainer._validate_ordering(manifest, indices_path)


def test_ordering_rejects_npy_value_mismatch(tmp_path: Path) -> None:
    manifest_path, indices_path = _write_artifacts(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    indices = np.load(indices_path)
    indices[10] = 1000
    np.save(indices_path, indices)

    with pytest.raises(FeatureOrderingError, match="differ at model input index 10"):
        LightGBMShapExplainer._validate_ordering(manifest, indices_path)


def test_ordering_rejects_sha256_mismatch(tmp_path: Path) -> None:
    manifest_path, indices_path = _write_artifacts(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["source_artifact_sha256"] = "0" * 64

    with pytest.raises(FeatureOrderingError, match="SHA-256"):
        LightGBMShapExplainer._validate_ordering(manifest, indices_path)


def test_validate_model_requires_lightgbm_binary_class_one() -> None:
    with pytest.raises(ShapExplanationError, match="LGBMClassifier"):
        LightGBMShapExplainer._validate_model(_fake_model())


def _lgbm_classifier(
    *,
    objective: str = "binary",
    n_features_in_: int = 500,
    classes_: np.ndarray | None = None,
) -> lgb.LGBMClassifier:
    """학습된 것처럼 속성을 설정한 실제 미학습 LGBMClassifier를 만든다.

    _validate_model의 isinstance() 검증에는 실제 LGBMClassifier가 필요하다.
    SimpleNamespace로는 그 분기만 테스트할 수 있기 때문에 사용하는 helper다.
    """

    model = lgb.LGBMClassifier(objective=objective)
    model.n_features_in_ = n_features_in_
    # classes_는 _classes와 fitted_를 사용하는 읽기 전용 property다
    # (lightgbm.sklearn.LGBMModel.__sklearn_is_fitted__ 참고). 이 모델은 실제로
    # fit()하지 않으므로 두 값을 직접 설정한다.
    model.fitted_ = True
    model._classes = np.array([0, 1]) if classes_ is None else classes_
    return model


def test_validate_model_rejects_wrong_feature_count() -> None:
    model = _lgbm_classifier(n_features_in_=499)
    with pytest.raises(ShapExplanationError, match="500 features"):
        LightGBMShapExplainer._validate_model(model)


def test_validate_model_rejects_non_binary_classes() -> None:
    model = _lgbm_classifier(classes_=np.array([0, 1, 2]))
    with pytest.raises(ShapExplanationError, match="classes_"):
        LightGBMShapExplainer._validate_model(model)


def test_validate_model_rejects_non_binary_objective() -> None:
    model = _lgbm_classifier(objective="multiclass")
    with pytest.raises(ShapExplanationError, match="objective"):
        LightGBMShapExplainer._validate_model(model)


@pytest.mark.parametrize("shape", [(499,), (501,), (2, 500)])
def test_input_rejects_wrong_shapes(shape: tuple[int, ...]) -> None:
    with pytest.raises(ShapExplanationError, match="shape"):
        LightGBMShapExplainer._validate_input(np.zeros(shape))


def test_input_rejects_non_finite_values() -> None:
    values = np.zeros(500)
    values[3] = np.nan
    with pytest.raises(ShapExplanationError, match="NaN"):
        LightGBMShapExplainer._validate_input(values)


def test_explain_returns_stable_top_five_with_all_directions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contributions = np.zeros(500)
    contributions[[1, 2, 3, 4]] = [9.0, -8.0, 7.0, -6.0]
    explainer = _build_without_init(tmp_path, monkeypatch, contributions)

    result = explainer.explain(np.zeros(500, dtype=np.float32))

    assert [item.model_input_index for item in result] == [1, 2, 3, 4, 0]
    assert [item.direction for item in result] == [
        "MALICIOUS",
        "BENIGN",
        "MALICIOUS",
        "BENIGN",
        "NEUTRAL",
    ]
    assert result[0].to_dict() == {
        "name": "group[1]",
        "contribution": 9.0,
        "direction": "MALICIOUS",
        "group": "group",
        "model_input_index": 1,
        "source_index": 1,
    }


@pytest.mark.parametrize("top_k", [0, -1, 501, True, 5.0])
def test_explain_rejects_invalid_top_k(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    top_k: object,
) -> None:
    explainer = _build_without_init(tmp_path, monkeypatch, np.zeros(500))

    with pytest.raises(ShapExplanationError, match="top_k"):
        explainer.explain(np.zeros(500, dtype=np.float32), top_k=top_k)


def test_explain_breaks_magnitude_ties_by_ascending_model_input_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contributions = np.zeros(500)
    contributions[[50, 10, 30]] = [2.0, -2.0, 2.0]
    explainer = _build_without_init(tmp_path, monkeypatch, contributions)

    result = explainer.explain(np.zeros(500, dtype=np.float32), top_k=3)

    assert [item.model_input_index for item in result] == [10, 30, 50]


@pytest.mark.parametrize(
    ("values_shape", "base_shape", "message"),
    [
        ((500,), (1,), "SHAP values shape"),
        ((1, 500, 1), (1,), "SHAP values shape"),
        ((1, 500), (1, 1), "base_values shape"),
    ],
)
def test_explain_rejects_unverified_shap_shapes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    values_shape: tuple[int, ...],
    base_shape: tuple[int, ...],
    message: str,
) -> None:
    explainer = _build_without_init(
        tmp_path,
        monkeypatch,
        np.zeros(500),
        values_shape=values_shape,
        base_shape=base_shape,
    )

    with pytest.raises(ShapExplanationError, match=message):
        explainer.explain(np.zeros(500))


_OFFICIAL_MODEL_PATH = (
    Path(__file__).resolve().parents[1] / "baseline_model_lightgbm_tuned_500_v4_9120.pkl"
)
_OFFICIAL_MANIFEST_PATH = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "feature-extraction"
    / "feature-selection-ember-v3-top500.json"
)
_OFFICIAL_INDICES_PATH = (
    Path(__file__).resolve().parents[1] / "top_feature_indices_500.npy"
)


def test_official_artifacts_have_expected_order_and_model_contract() -> None:
    if not _OFFICIAL_MODEL_PATH.exists():
        pytest.skip("official LightGBM artifact is not available")

    model = __import__("joblib").load(_OFFICIAL_MODEL_PATH)
    manifest = json.loads(_OFFICIAL_MANIFEST_PATH.read_text(encoding="utf-8"))
    names, indices, _, schema_version = LightGBMShapExplainer._validate_ordering(
        manifest, _OFFICIAL_INDICES_PATH
    )
    LightGBMShapExplainer._validate_model(model)

    assert len(names) == 500
    assert np.array_equal(indices, np.load(_OFFICIAL_INDICES_PATH))
    assert schema_version == manifest["source_schema_version"]


def test_official_explain_returns_top5_and_additivity_holds() -> None:
    """실제 모델, manifest, npy를 함께 사용하는 통합 테스트다.

    ordering과 모델 계약만 확인하는
    test_official_artifacts_have_expected_order_and_model_contract와 달리,
    production artifact에 대해 explain()과 shap.TreeExplainer를 실제로 실행한다.
    설치된 SHAP/LightGBM 버전에서도 _validate_shap_result에 기록한
    Explanation shape `(1, 500)`/`(1,)`가 유효한지 확인하고 additivity도
    독립적으로 다시 검증한다.
    """

    if not _OFFICIAL_MODEL_PATH.exists():
        pytest.skip("official LightGBM artifact is not available")

    explainer = LightGBMShapExplainer.from_files(
        _OFFICIAL_MODEL_PATH, _OFFICIAL_MANIFEST_PATH, _OFFICIAL_INDICES_PATH
    )

    zeros = np.zeros(500, dtype=np.float32)
    result = explainer.explain(zeros, top_k=5)

    assert len(result) == 5
    assert all(isinstance(item.contribution, float) for item in result)
    assert all(item.direction in ("MALICIOUS", "BENIGN", "NEUTRAL") for item in result)
    # 기여도가 큰 feature부터 |contribution| 내림차순이어야 한다.
    magnitudes = [abs(item.contribution) for item in result]
    assert magnitudes == sorted(magnitudes, reverse=True)

    values = explainer._validate_input(zeros)
    explanation = explainer._explainer(values, check_additivity=True)
    contributions, base_value = explainer._validate_shap_result(explanation)
    raw_score = explainer.model.predict(values, raw_score=True)[0]

    assert np.isclose(
        base_value + float(contributions.sum()), raw_score, rtol=1e-5, atol=1e-6
    )
