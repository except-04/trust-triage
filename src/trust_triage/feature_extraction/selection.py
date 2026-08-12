"""모델 학습·추론에 사용할 Feature 부분집합을 고정하고 검증한다."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from .schema import FeatureSchema


FEATURE_SELECTION_SCHEMA_VERSION = "feature-selection-v1"


class FeatureSelectionError(ValueError):
    """Feature 선택 manifest 또는 선택 입력이 유효하지 않을 때 발생한다."""


def _normalize_feature_names(feature_names: Sequence[str]) -> tuple[str, ...]:
    """입력 이름 목록을 불변 tuple로 바꾸고 기본 형식을 확인한다."""

    if isinstance(feature_names, (str, bytes)):
        raise FeatureSelectionError("feature names must be a sequence, not a string")

    try:
        normalized = tuple(feature_names)
    except TypeError as exc:
        raise FeatureSelectionError("feature names must be a sequence") from exc

    if not normalized:
        raise FeatureSelectionError("selected feature names must not be empty")
    if any(not isinstance(name, str) or not name for name in normalized):
        raise FeatureSelectionError("selected feature names must be non-empty strings")
    if len(set(normalized)) != len(normalized):
        raise FeatureSelectionError("selected feature names must be unique")
    return normalized


def _validate_model_dtype(dtype: str) -> str:
    """모델 입력 자료형을 float32로 고정한다."""

    try:
        normalized = np.dtype(dtype)
    except (TypeError, ValueError) as exc:
        raise FeatureSelectionError(f"unsupported selection dtype: {dtype!r}") from exc

    if normalized != np.dtype("float32"):
        raise FeatureSelectionError(
            "model input selection dtype must be float32, "
            f"got {normalized}"
        )
    return "float32"


@dataclass(frozen=True)
class FeatureSelector:
    """원본 Schema에서 모델 입력 Feature를 명시적으로 선택하는 객체.

    ``selected_feature_names``의 순서는 모델 입력 순서다. 따라서 이름을
    알파벳순으로 정렬하거나 원본 Schema 순서로 몰래 바꾸지 않는다.
    """

    source_schema: FeatureSchema
    selected_feature_names: tuple[str, ...]
    selection_id: str = "custom"
    dtype: str = "float32"
    source_indices: tuple[int, ...] = field(init=False)
    output_schema: FeatureSchema = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.selection_id, str) or not self.selection_id.strip():
            raise FeatureSelectionError("selection_id must be a non-empty string")

        normalized_names = _normalize_feature_names(self.selected_feature_names)
        model_dtype = _validate_model_dtype(self.dtype)

        if self.source_schema.feature_count == 0:
            raise FeatureSelectionError("source schema must contain at least one feature")

        source_positions = {
            name: index
            for index, name in enumerate(self.source_schema.feature_names)
        }
        unknown_names = [
            name for name in normalized_names if name not in source_positions
        ]
        if unknown_names:
            raise FeatureSelectionError(
                "selected feature names are not present in the source schema: "
                + ", ".join(repr(name) for name in unknown_names[:5])
            )

        source_indices = tuple(source_positions[name] for name in normalized_names)
        output_version = self._build_output_schema_version(
            source_schema=self.source_schema,
            selection_id=self.selection_id,
            feature_names=normalized_names,
            dtype=model_dtype,
        )
        output_schema = FeatureSchema(
            version=output_version,
            feature_names=normalized_names,
            dtype=model_dtype,
        )

        object.__setattr__(self, "selected_feature_names", normalized_names)
        object.__setattr__(self, "dtype", model_dtype)
        object.__setattr__(self, "source_indices", source_indices)
        object.__setattr__(self, "output_schema", output_schema)

    @classmethod
    def all(
        cls,
        source_schema: FeatureSchema,
        *,
        selection_id: str = "all",
    ) -> "FeatureSelector":
        """원본 Schema의 모든 Feature를 같은 순서로 선택한다."""

        return cls(
            source_schema=source_schema,
            selected_feature_names=source_schema.feature_names,
            selection_id=selection_id,
        )

    @classmethod
    def from_feature_names(
        cls,
        source_schema: FeatureSchema,
        feature_names: Sequence[str],
        *,
        selection_id: str = "custom",
        dtype: str = "float32",
    ) -> "FeatureSelector":
        """모델 manifest에 적은 순서 그대로 Feature 부분집합을 만든다."""

        return cls(
            source_schema=source_schema,
            selected_feature_names=tuple(feature_names),
            selection_id=selection_id,
            dtype=dtype,
        )

    @classmethod
    def from_manifest(
        cls,
        source_schema: FeatureSchema,
        manifest: Mapping[str, Any],
    ) -> "FeatureSelector":
        """JSON manifest 내용을 검사한 뒤 FeatureSelector를 만든다."""

        if not isinstance(manifest, Mapping):
            raise FeatureSelectionError("selection manifest must be a JSON object")

        manifest_version = manifest.get("selection_schema_version")
        if manifest_version != FEATURE_SELECTION_SCHEMA_VERSION:
            raise FeatureSelectionError(
                "unsupported selection manifest version: "
                f"{manifest_version!r}; expected {FEATURE_SELECTION_SCHEMA_VERSION!r}"
            )

        source_version = manifest.get("source_schema_version")
        if source_version != source_schema.version:
            raise FeatureSelectionError(
                "source schema version mismatch: "
                f"manifest={source_version!r}, runtime={source_schema.version!r}"
            )

        selection_id = manifest.get("selection_id")
        if not isinstance(selection_id, str) or not selection_id.strip():
            raise FeatureSelectionError(
                "selection manifest must contain a non-empty selection_id"
            )

        mode = manifest.get("mode")
        if mode not in {"all", "subset"}:
            raise FeatureSelectionError(
                "selection manifest mode must be either 'all' or 'subset'"
            )

        dtype = manifest.get("dtype", "float32")
        allow_nan = manifest.get("allow_nan", True)
        allow_infinity = manifest.get("allow_infinity", False)
        if allow_nan is not True:
            raise FeatureSelectionError(
                "selection manifest must preserve NaN model inputs"
            )
        if allow_infinity is not False:
            raise FeatureSelectionError(
                "selection manifest must reject infinite model inputs"
            )
        feature_names_value = manifest.get("feature_names")

        if mode == "all":
            if feature_names_value in (None, []):
                selected_names = source_schema.feature_names
            else:
                selected_names = _normalize_manifest_names(feature_names_value)
                if selected_names != source_schema.feature_names:
                    raise FeatureSelectionError(
                        "mode='all' must use the complete source feature list "
                        "in the original order"
                    )
        else:
            selected_names = _normalize_manifest_names(feature_names_value)
            if (
                len(selected_names) == source_schema.feature_count
                and set(selected_names) == set(source_schema.feature_names)
            ):
                raise FeatureSelectionError(
                    "mode='subset' must select fewer than all source features"
                )

        selector = cls.from_feature_names(
            source_schema,
            selected_names,
            selection_id=selection_id,
            dtype=dtype,
        )

        declared_output_version = manifest.get("output_schema_version")
        if (
            declared_output_version is not None
            and declared_output_version != selector.output_schema.version
        ):
            raise FeatureSelectionError(
                "output schema version does not match the selected feature list: "
                f"manifest={declared_output_version!r}, "
                f"computed={selector.output_schema.version!r}"
            )

        declared_feature_count = manifest.get("feature_count")
        if declared_feature_count is not None:
            if (
                isinstance(declared_feature_count, bool)
                or not isinstance(declared_feature_count, int)
                or declared_feature_count != selector.feature_count
            ):
                raise FeatureSelectionError(
                    "manifest feature_count does not match the selected feature list"
                )

        declared_source_indices = manifest.get("source_indices")
        if declared_source_indices is not None:
            if not isinstance(declared_source_indices, (list, tuple)):
                raise FeatureSelectionError(
                    "manifest source_indices must be a JSON array"
                )
            try:
                normalized_indices = tuple(declared_source_indices)
            except TypeError as exc:
                raise FeatureSelectionError(
                    "manifest source_indices must be a JSON array"
                ) from exc
            if normalized_indices != selector.source_indices:
                raise FeatureSelectionError(
                    "manifest source_indices do not match the selected feature list"
                )

        return selector

    @classmethod
    def from_json_file(
        cls,
        source_schema: FeatureSchema,
        path: str | Path,
    ) -> "FeatureSelector":
        """UTF-8 JSON manifest 파일에서 Feature 선택을 읽는다."""

        manifest_path = Path(path)
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise FileNotFoundError(
                f"selection manifest does not exist: {manifest_path}"
            ) from None
        except json.JSONDecodeError as exc:
            raise FeatureSelectionError(
                f"invalid selection manifest JSON: {manifest_path}: {exc}"
            ) from exc
        except OSError as exc:
            raise FeatureSelectionError(
                f"could not read selection manifest: {manifest_path}: {exc}"
            ) from exc

        return cls.from_manifest(source_schema, manifest)

    @property
    def feature_count(self) -> int:
        """선택된 모델 입력 차원."""

        return len(self.selected_feature_names)

    @property
    def is_all(self) -> bool:
        """원본 Schema의 모든 Feature를 선택했는지 반환한다."""

        return self.selected_feature_names == self.source_schema.feature_names

    def validate_source_metadata(
        self,
        schema_version: str,
        feature_names: Sequence[str] | None = None,
    ) -> None:
        """선택 대상 벡터의 원본 Schema 메타데이터를 검증한다."""

        if schema_version != self.source_schema.version:
            raise FeatureSelectionError(
                "source schema version mismatch: "
                f"input={schema_version!r}, expected={self.source_schema.version!r}"
            )

        if feature_names is not None:
            try:
                self.source_schema.validate_feature_names(feature_names)
            except ValueError as exc:
                raise FeatureSelectionError(
                    f"source feature names/order do not match {self.source_schema.version}: "
                    f"{exc}"
                ) from exc

    def select_vector(
        self,
        values: Sequence[float] | np.ndarray,
        *,
        schema_version: str | None = None,
        feature_names: Sequence[str] | None = None,
    ) -> np.ndarray:
        """원본 1차원 벡터에서 선택된 Feature만 float32로 반환한다."""

        if schema_version is not None:
            self.validate_source_metadata(schema_version, feature_names)
        elif feature_names is not None:
            try:
                self.source_schema.validate_feature_names(feature_names)
            except ValueError as exc:
                raise FeatureSelectionError(
                    f"source feature names/order do not match {self.source_schema.version}: "
                    f"{exc}"
                ) from exc

        source_vector = self.source_schema.validate_vector(values)
        selected_vector = source_vector[list(self.source_indices)].astype(
            np.float32,
            copy=False,
        )
        return self.output_schema.validate_vector(selected_vector)

    def select_matrix(
        self,
        values: Sequence[Sequence[float]] | np.ndarray,
        *,
        schema_version: str | None = None,
        feature_names: Sequence[str] | None = None,
    ) -> np.ndarray:
        """여러 샘플의 원본 행렬에서 선택된 열만 float32로 반환한다."""

        if schema_version is not None:
            self.validate_source_metadata(schema_version, feature_names)
        elif feature_names is not None:
            try:
                self.source_schema.validate_feature_names(feature_names)
            except ValueError as exc:
                raise FeatureSelectionError(
                    f"source feature names/order do not match {self.source_schema.version}: "
                    f"{exc}"
                ) from exc

        source_matrix = self.source_schema.validate_matrix(values)
        selected_matrix = source_matrix[:, list(self.source_indices)].astype(
            np.float32,
            copy=False,
        )
        return self.output_schema.validate_matrix(selected_matrix)

    def to_dict(self) -> dict[str, Any]:
        """선택 규칙과 모델 입력 Schema를 재현할 수 있는 manifest를 반환한다."""

        return {
            "selection_schema_version": FEATURE_SELECTION_SCHEMA_VERSION,
            "source_schema_version": self.source_schema.version,
            "output_schema_version": self.output_schema.version,
            "selection_id": self.selection_id,
            "mode": "all" if self.is_all else "subset",
            "dtype": self.dtype,
            "allow_nan": True,
            "allow_infinity": False,
            "feature_count": self.feature_count,
            "feature_names": list(self.selected_feature_names),
            "source_indices": list(self.source_indices),
        }

    @staticmethod
    def _build_output_schema_version(
        *,
        source_schema: FeatureSchema,
        selection_id: str,
        feature_names: tuple[str, ...],
        dtype: str,
    ) -> str:
        """선택 규칙으로부터 충돌 가능성이 낮은 출력 Schema 버전을 만든다."""

        payload = {
            "source_schema_version": source_schema.version,
            "selection_id": selection_id,
            "dtype": dtype,
            "feature_names": list(feature_names),
        }
        serialized = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        fingerprint = hashlib.sha256(serialized).hexdigest()[:12]
        return f"{source_schema.version}-selection-{fingerprint}"


def _normalize_manifest_names(value: Any) -> tuple[str, ...]:
    """manifest의 feature_names 필드를 목록으로 엄격하게 검사한다."""

    if not isinstance(value, (list, tuple)):
        raise FeatureSelectionError("feature_names in a manifest must be a JSON array")
    return _normalize_feature_names(value)
