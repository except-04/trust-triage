"""모델 입력 벡터의 버전과 순서를 검증하는 공통 Schema."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np


@dataclass(frozen=True)
class FeatureSchema:
    """Feature 벡터의 버전, 이름, 자료형을 설명하는 불변 객체."""

    version: str
    feature_names: tuple[str, ...]
    dtype: str = "float32"

    def __post_init__(self) -> None:
        """모델 입력 순서를 망가뜨릴 수 있는 잘못된 Schema를 즉시 거부한다."""

        if not self.version:
            raise ValueError("schema version must not be empty")
        if any(not name for name in self.feature_names):
            raise ValueError("feature names must not be empty")
        if len(set(self.feature_names)) != len(self.feature_names):
            raise ValueError("feature names must be unique")
        try:
            dtype = np.dtype(self.dtype)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"unsupported schema dtype: {self.dtype}") from exc
        if not np.issubdtype(dtype, np.floating):
            raise ValueError("schema dtype must be a floating-point type")

    @property
    def feature_count(self) -> int:
        return len(self.feature_names)

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
