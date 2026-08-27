"""공식 Top-500 LightGBM 모델의 SHAP 설명을 제공한다.

이 모듈은 Calibration 또는 JRR 단계에서 만든 확률이 아니라 LightGBM raw score를
설명한다. Top-500 manifest를 모델 입력 feature 이름의 source of truth로 사용하고,
NumPy artifact로 학습 당시의 원본 index 순서를 독립적으로 검증한다.

모델 입력 순서(중요: artifact 자체에는 기록되지 않음)
-------------------------------------------------------
학습된 ``.pkl``(예: ``baseline_model_lightgbm_tuned_500_v4_9120.pkl``)에는
feature 이름이나 원본 index metadata가 없다. LightGBM sklearn wrapper가 booster에
자동 생성한 열 이름(``Column_0`` .. ``Column_499``)만 저장하므로, 모델 파일만으로는
각 열이 원본 500개 index 중 어디에 해당하는지 증명할 수 없다.

따라서 정확성은 학습 코드의 열 선택 규칙에 의존한다. ``src/models/tune_lightgbm.py``
(및 ``train_xgboost_500.py``)는
``np.sort(np.load("top_feature_indices_500.npy"))``로 열을 선택하므로 모델 입력은
**원본 index 오름차순**이다. ``_validate_ordering``은 체크인된 ``.npy``와 selection
manifest의 ``source_indices``가 일치하고, manifest의 ``selection_order``가
``ascending_source_index``인지 확인한다. 이를 통해 explainer의 index → 이름 매핑이
학습 규칙과 일관되도록 한다. 향후 다른 열 순서로 모델을 학습하더라도 ``.pkl``만으로는
그 불일치를 탐지할 수 없다. 이는 이 모듈만으로 해소할 수 없는 artifact의 구조적 한계다.

이 모듈이 ``trust_triage.feature_extraction``을 import하지 않는 이유
-------------------------------------------------------------------
``FeatureSelector``/``FeatureSchema``(``feature_extraction/selection.py``,
``schema.py``)는 selection manifest를 실제 ``source_schema_version``과 검증할 수 있다.
하지만 ``trust_triage.feature_extraction``의 하위 모듈을 import하면 package의
``__init__.py``가 실행되면서 ``ember_v3.py``와 ``pefile``까지 불러온다. 실제 schema
version을 얻으려면 ``EmberV3Extractor()``를 생성해야 하며, 이 과정은 고정된 commit을
기준으로 ``thrember``/``signify``를 지연 import하고 VCS 검증도 수행한다.

이 SHAP 모듈은 이미 추출된 500차원 벡터만 설명하고 PE bytes는 다루지 않는다.
따라서 version 문자열 하나를 비교하기 위해 PE parsing stack 전체에 의존하면, 추출
stack 없이 explainer만 사용하는 구성(예: 저장된 벡터를 읽는 검토 dashboard)에
불필요하게 무거운 의존성이 생긴다.

대신 호출자가 이미 알고 있는 schema version(일반적으로 500차원 ``model_input``을
만든 시점의 ``EmberV3Extractor().schema.version``)을
``expected_source_schema_version``으로 주입할 수 있다. 이를 생략하면 manifest의
``source_schema_version``이 존재하고 형식이 올바른지만 확인하며, 실제 schema와의
일치 여부는 호출자가 책임진다.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Literal

import joblib
import lightgbm as lgb
import numpy as np
import shap


Direction = Literal["BENIGN", "MALICIOUS", "NEUTRAL"]
_FEATURE_NAME = re.compile(r"^(?P<group>[^\[\]]+)\[(?P<index>\d+)\]$")


class ShapExplanationError(ValueError):
    """모델, 입력, manifest 또는 SHAP 결과가 계약을 위반했음을 나타낸다."""


class FeatureOrderingError(ShapExplanationError):
    """체크인된 Top-500 ordering artifact가 서로 일치하지 않음을 나타낸다."""


@dataclass(frozen=True)
class ShapContribution:
    """한 모델 입력 feature가 악성 raw score에 미친 기여도."""

    name: str
    contribution: float
    direction: Direction
    group: str
    model_input_index: int
    source_index: int

    def to_dict(self) -> dict[str, str | float | int]:
        """JSON으로 직렬화할 수 있는 dict를 반환한다."""

        return asdict(self)


class LightGBMShapExplainer:
    """공식 binary LightGBM 모델로 단일 Top-500 입력을 설명한다."""

    FEATURE_COUNT = 500
    SOURCE_FEATURE_COUNT = 2568

    def __init__(
        self,
        model: lgb.LGBMClassifier,
        manifest_path: str | Path,
        top_indices_path: str | Path,
        *,
        expected_source_schema_version: str | None = None,
    ) -> None:
        """하나의 manifest/index 배열 쌍에 연결된 explainer를 생성한다.

        ``expected_source_schema_version``은 선택적인 dependency injection 값이다.
        ``model_input``을 만든 호출자(일반적으로 extraction/inference 계층)가 실제
        ``EmberV3Extractor().schema.version``을 전달하면 manifest와 현재 사용 중인
        schema가 일치하는지 확인한다. 이 모듈은 그 값을 직접 계산하지 않는다.
        ``trust_triage.feature_extraction``을 import하지 않는 이유는 모듈 docstring을
        참고한다. 값을 생략하면 manifest 자체의 ``source_schema_version``이 존재하고
        형식이 올바른지만 확인하며, 실제 schema와 비교하지 않는다.
        """

        self.model = model
        self.manifest_path = Path(manifest_path)
        self.top_indices_path = Path(top_indices_path)

        manifest = self._load_manifest(self.manifest_path)
        (
            self.feature_names,
            self.source_indices,
            self.feature_groups,
            self.source_schema_version,
        ) = self._validate_ordering(
            manifest,
            self.top_indices_path,
            expected_source_schema_version=expected_source_schema_version,
        )
        self._validate_model(model)
        self._explainer = shap.TreeExplainer(model, model_output="raw")

    @classmethod
    def from_files(
        cls,
        model_path: str | Path,
        manifest_path: str | Path,
        top_indices_path: str | Path,
        *,
        expected_source_schema_version: str | None = None,
    ) -> "LightGBMShapExplainer":
        """신뢰할 수 있는 로컬 artifact를 로드해 explainer를 생성한다."""

        model = joblib.load(Path(model_path))
        return cls(
            model,
            manifest_path,
            top_indices_path,
            expected_source_schema_version=expected_source_schema_version,
        )

    def explain(
        self,
        model_input: np.ndarray,
        *,
        top_k: int = 5,
    ) -> list[ShapContribution]:
        """악성 raw score에 가장 크게 기여한 feature를 반환한다."""

        if isinstance(top_k, bool) or not isinstance(top_k, int):
            raise ShapExplanationError("top_k must be an integer")
        if not 1 <= top_k <= self.FEATURE_COUNT:
            raise ShapExplanationError(
                f"top_k must be between 1 and {self.FEATURE_COUNT}"
            )

        values = self._validate_input(model_input)
        explanation = self._explainer(values, check_additivity=True)
        contributions, base_value = self._validate_shap_result(explanation)
        self._validate_raw_score_additivity(values, contributions, base_value)

        ranked = np.argsort(-np.abs(contributions), kind="stable")[:top_k]
        return [self._build_contribution(int(index), contributions) for index in ranked]

    @staticmethod
    def _load_manifest(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ShapExplanationError(f"cannot load selection manifest: {path}") from exc
        if not isinstance(value, dict):
            raise ShapExplanationError("selection manifest must be a JSON object")
        return value

    @classmethod
    def _validate_ordering(
        cls,
        manifest: dict[str, Any],
        top_indices_path: Path,
        *,
        expected_source_schema_version: str | None = None,
    ) -> tuple[tuple[str, ...], np.ndarray, tuple[str, ...], str]:
        if manifest.get("feature_count") != cls.FEATURE_COUNT:
            raise FeatureOrderingError("manifest feature_count must be 500")
        if manifest.get("selection_order") != "ascending_source_index":
            raise FeatureOrderingError(
                "manifest selection_order must be 'ascending_source_index'"
            )

        source_schema_version = manifest.get("source_schema_version")
        if not isinstance(source_schema_version, str) or not source_schema_version:
            raise FeatureOrderingError(
                "manifest source_schema_version must be a non-empty string"
            )
        if (
            expected_source_schema_version is not None
            and source_schema_version != expected_source_schema_version
        ):
            raise FeatureOrderingError(
                "manifest source_schema_version does not match the live feature "
                f"schema: manifest={source_schema_version!r}, "
                f"expected={expected_source_schema_version!r}"
            )

        names_value = manifest.get("feature_names")
        indices_value = manifest.get("source_indices")
        if not isinstance(names_value, list) or len(names_value) != cls.FEATURE_COUNT:
            raise FeatureOrderingError("manifest feature_names must contain 500 items")
        if not isinstance(indices_value, list) or len(indices_value) != cls.FEATURE_COUNT:
            raise FeatureOrderingError("manifest source_indices must contain 500 items")
        if any(not isinstance(name, str) or not name for name in names_value):
            raise FeatureOrderingError("manifest feature names must be non-empty strings")
        if len(set(names_value)) != cls.FEATURE_COUNT:
            raise FeatureOrderingError("manifest feature names must be unique")
        if any(isinstance(index, bool) or not isinstance(index, int) for index in indices_value):
            raise FeatureOrderingError("manifest source indices must be integers")

        source_indices = np.asarray(indices_value, dtype=np.int64)
        if np.any(source_indices < 0) or np.any(source_indices >= cls.SOURCE_FEATURE_COUNT):
            raise FeatureOrderingError("manifest source index is outside [0, 2568)")
        if len(np.unique(source_indices)) != cls.FEATURE_COUNT:
            raise FeatureOrderingError("manifest source indices must be unique")
        if not np.all(source_indices[:-1] < source_indices[1:]):
            raise FeatureOrderingError("manifest source indices must be strictly ascending")

        groups: list[str] = []
        for name in names_value:
            match = _FEATURE_NAME.fullmatch(name)
            if match is None:
                raise FeatureOrderingError(
                    f"manifest feature name does not match group[index]: {name!r}"
                )
            groups.append(match.group("group"))

        try:
            top_indices = np.load(top_indices_path, allow_pickle=False)
        except (OSError, ValueError) as exc:
            raise FeatureOrderingError(
                f"cannot load top-feature indices: {top_indices_path}"
            ) from exc
        if top_indices.shape != (cls.FEATURE_COUNT,):
            raise FeatureOrderingError("top-feature index array must have shape (500,)")
        if not np.issubdtype(top_indices.dtype, np.integer):
            raise FeatureOrderingError("top-feature index array must have an integer dtype")
        top_indices = top_indices.astype(np.int64, copy=False)

        if not np.array_equal(source_indices, top_indices):
            differing = np.flatnonzero(source_indices != top_indices)
            position = int(differing[0])
            raise FeatureOrderingError(
                "manifest source_indices and top-feature array differ at model input "
                f"index {position}: manifest={source_indices[position]}, "
                f"npy={top_indices[position]}"
            )

        expected_hash = manifest.get("source_artifact_sha256")
        if not isinstance(expected_hash, str) or not expected_hash:
            raise FeatureOrderingError("manifest source_artifact_sha256 is required")
        actual_hash = hashlib.sha256(top_indices_path.read_bytes()).hexdigest()
        if actual_hash.casefold() != expected_hash.casefold():
            raise FeatureOrderingError(
                "top-feature array SHA-256 does not match the selection manifest"
            )

        return tuple(names_value), source_indices, tuple(groups), source_schema_version

    @classmethod
    def _validate_model(cls, model: Any) -> None:
        if not isinstance(model, lgb.LGBMClassifier):
            raise ShapExplanationError("model must be a LightGBM LGBMClassifier")
        if getattr(model, "n_features_in_", None) != cls.FEATURE_COUNT:
            raise ShapExplanationError("LightGBM model must expect exactly 500 features")
        classes = np.asarray(getattr(model, "classes_", []))
        if classes.shape != (2,) or not np.array_equal(classes, np.array([0, 1])):
            raise ShapExplanationError(
                "LightGBM classes_ must be [0, 1] so class 1 is malicious"
            )
        if model.get_params().get("objective") != "binary":
            raise ShapExplanationError("LightGBM model objective must be 'binary'")

    @classmethod
    def _validate_input(cls, model_input: np.ndarray) -> np.ndarray:
        values = np.asarray(model_input)
        if values.shape == (cls.FEATURE_COUNT,):
            values = values.reshape(1, cls.FEATURE_COUNT)
        elif values.shape != (1, cls.FEATURE_COUNT):
            raise ShapExplanationError(
                "model input must have shape (500,) or (1, 500)"
            )
        try:
            values = values.astype(np.float32, copy=False)
        except (TypeError, ValueError) as exc:
            raise ShapExplanationError("model input must be numeric") from exc
        if not np.all(np.isfinite(values)):
            raise ShapExplanationError("model input contains NaN or infinite values")
        return values

    @classmethod
    def _validate_shap_result(
        cls,
        explanation: Any,
    ) -> tuple[np.ndarray, float]:
        # 공식 모델과 SHAP 0.52.0, LightGBM 4.7.0 환경에서 확인한 형태다.
        # Explanation.values는 (1, 500), base_values는 (1,)이다.
        # 확인되지 않은 class 또는 axis 구조는 추측하지 않고 거부한다.
        if not isinstance(explanation, shap.Explanation):
            raise ShapExplanationError("TreeExplainer must return shap.Explanation")
        values = np.asarray(explanation.values)
        base_values = np.asarray(explanation.base_values)
        if values.shape != (1, cls.FEATURE_COUNT):
            raise ShapExplanationError(
                "unexpected SHAP values shape: "
                f"{values.shape}; expected (1, {cls.FEATURE_COUNT})"
            )
        if base_values.shape != (1,):
            raise ShapExplanationError(
                f"unexpected SHAP base_values shape: {base_values.shape}; expected (1,)"
            )
        contributions = values[0].astype(np.float64, copy=False)
        base_value = float(base_values[0])
        if not np.all(np.isfinite(contributions)) or not np.isfinite(base_value):
            raise ShapExplanationError("SHAP result contains NaN or infinite values")
        return contributions, base_value

    def _validate_raw_score_additivity(
        self,
        model_input: np.ndarray,
        contributions: np.ndarray,
        base_value: float,
    ) -> None:
        # 위 SHAP 호출에 전달한 check_additivity=True와 의도적으로 검증이 중복된다.
        # 해당 검증은 SHAP 내부 tree traversal 구현과 자체 허용 오차로 수행된다.
        # 여기서는 LightGBM booster의 predict() 경로로 raw score를 별도로 계산한다.
        # 잘못된 class나 axis의 SHAP 결과는 분석가에게 MALICIOUS/BENIGN 방향을 반대로
        # 보여줄 수 있으므로, LightGBM 예측 한 번의 비용을 감수하고 두 구현의 결과가
        # 일치하는지 독립적으로 확인한다.
        raw_score = np.asarray(self.model.predict(model_input, raw_score=True))
        if raw_score.shape != (1,) or not np.isfinite(raw_score[0]):
            raise ShapExplanationError(
                "LightGBM raw-score prediction must be one finite value"
            )
        reconstructed = base_value + float(np.sum(contributions))
        if not np.isclose(reconstructed, raw_score[0], rtol=1e-5, atol=1e-6):
            raise ShapExplanationError(
                "SHAP contributions do not add up to the LightGBM raw score"
            )

    def _build_contribution(
        self,
        index: int,
        contributions: np.ndarray,
    ) -> ShapContribution:
        contribution = float(contributions[index])
        if contribution > 0:
            direction: Direction = "MALICIOUS"
        elif contribution < 0:
            direction = "BENIGN"
        else:
            direction = "NEUTRAL"
        return ShapContribution(
            name=self.feature_names[index],
            contribution=contribution,
            direction=direction,
            group=self.feature_groups[index],
            model_input_index=index,
            source_index=int(self.source_indices[index]),
        )
