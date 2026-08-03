"""모델 입력 벡터의 버전과 순서를 검증하는 공통 Schema."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np


@dataclass(frozen=True)
class FeatureGroup:
    """Feature 벡터 안에서 하나의 그룹이 차지하는 범위를 표현한다."""

    name: str
    start_index: int
    dimension: int

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("feature group name must not be empty")
        if self.start_index < 0:
            raise ValueError("feature group start index must not be negative")
        if self.dimension <= 0:
            raise ValueError("feature group dimension must be positive")

    @property
    def end_index_exclusive(self) -> int:
        """그룹 범위의 끝 인덱스다. 끝 인덱스는 포함하지 않는다."""

        return self.start_index + self.dimension

    def to_dict(self) -> dict[str, object]:
        """문서와 JSON 출력에 사용할 그룹 정보로 변환한다."""

        return {
            "name": self.name,
            "start_index": self.start_index,
            "end_index_exclusive": self.end_index_exclusive,
            "dimension": self.dimension,
            "feature_names": [
                f"{self.name}[{index}]" for index in range(self.dimension)
            ],
        }


@dataclass(frozen=True)
class FeatureSchema:
    """Feature 벡터의 버전, 이름, 자료형을 설명하는 불변 객체."""

    version: str
    feature_names: tuple[str, ...]
    dtype: str = "float32"
    groups: tuple[FeatureGroup, ...] = ()

    def __post_init__(self) -> None:
        """모델 입력 순서를 망가뜨릴 수 있는 잘못된 Schema를 즉시 거부한다."""

        if not self.version:
            raise ValueError("schema version must not be empty")
        if any(not name for name in self.feature_names):
            raise ValueError("feature names must not be empty")
        if len(set(self.feature_names)) != len(self.feature_names):
            raise ValueError("feature names must be unique")
        if self.groups:
            expected_start = 0
            seen_group_names: set[str] = set()
            for group in self.groups:
                if group.name in seen_group_names:
                    raise ValueError("feature group names must be unique")
                if group.start_index != expected_start:
                    raise ValueError("feature groups must cover the vector in order")
                if group.end_index_exclusive > len(self.feature_names):
                    raise ValueError("feature group exceeds the schema feature count")
                seen_group_names.add(group.name)
                expected_start = group.end_index_exclusive
            if expected_start != len(self.feature_names):
                raise ValueError("feature groups must cover all schema features")
        try:
            dtype = np.dtype(self.dtype)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unsupported schema dtype: {self.dtype}") from exc
        if not np.issubdtype(dtype, np.floating):
            raise ValueError("schema dtype must be a floating-point type")

    @property
    def feature_count(self) -> int:
        return len(self.feature_names)

    def to_dict(self) -> dict[str, object]:
        """모델팀이 사용할 수 있는 Schema manifest로 변환한다."""

        return {
            "schema_version": self.version,
            "dtype": str(np.dtype(self.dtype)),
            "feature_count": self.feature_count,
            "feature_name_pattern": "{group}[{index}]",
            "groups": [group.to_dict() for group in self.groups],
            "feature_names": list(self.feature_names),
        }

    def validate_vector(self, values: Sequence[float] | np.ndarray) -> np.ndarray:
        """1차원이고 개수와 값이 올바른 Schema 자료형 벡터를 반환한다."""

        vector = np.asarray(values, dtype=np.dtype(self.dtype))
        if vector.ndim != 1:
            raise ValueError("feature vector must be one-dimensional")
        if vector.shape[0] != self.feature_count:
            raise ValueError(
                f"expected {self.feature_count} features for {self.version}, "
                f"got {vector.shape[0]}"
            )
        if not np.all(np.isfinite(vector)):
            raise ValueError("feature vector contains NaN or infinite values")
        return vector
