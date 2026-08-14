"""모든 Feature 추출기가 공통으로 반환하는 결과 모델."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

import numpy as np

from .api_groups import ApiGroupReport
from .schema import FeatureSchema
from .selection import FeatureSelector


class ExtractionStatus(str, Enum):
    """다른 분석 모듈과 공유하는 안정적인 처리 상태."""

    SUCCESS = "SUCCESS"
    INVALID_PE = "INVALID_PE"
    PARSE_ERROR = "PARSE_ERROR"
    UNSUPPORTED = "UNSUPPORTED"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    TIMEOUT = "TIMEOUT"
    TOOL_ERROR = "TOOL_ERROR"


@dataclass
class FeatureExtractionResult:
    """모든 Extractor가 반환하는 JSON 변환 가능한 결과."""

    schema_version: str
    sha256: str
    file_type: str
    status: ExtractionStatus
    feature_count: int
    feature_names: list[str] = field(default_factory=list)
    features: list[float] = field(default_factory=list)
    missing_features: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    api_groups: ApiGroupReport | None = None
    is_dotnet: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def success(
        cls,
        *,
        schema: FeatureSchema,
        sha256: str,
        file_type: str,
        values: Sequence[float] | np.ndarray,
        missing_features: list[str] | None = None,
        warnings: list[str] | None = None,
        api_groups: ApiGroupReport | None = None,
        is_dotnet: bool = False,
        metadata: Mapping[str, Any] | None = None,
    ) -> "FeatureExtractionResult":
        vector = schema.validate_vector(values)
        return cls(
            schema_version=schema.version,
            sha256=sha256,
            file_type=file_type,
            status=ExtractionStatus.SUCCESS,
            feature_count=schema.feature_count,
            feature_names=list(schema.feature_names),
            features=[float(value) for value in vector],
            missing_features=list(missing_features or []),
            warnings=list(warnings or []),
            api_groups=api_groups,
            is_dotnet=is_dotnet,
            metadata=dict(metadata or {}),
        )

    @classmethod
    def failure(
        cls,
        *,
        schema_version: str,
        status: ExtractionStatus,
        sha256: str = "",
        file_type: str = "UNKNOWN",
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> "FeatureExtractionResult":
        return cls(
            schema_version=schema_version,
            sha256=sha256,
            file_type=file_type,
            status=status,
            feature_count=0,
            warnings=list(warnings or []),
            errors=list(errors or []),
            metadata=dict(metadata or {}),
        )

    def to_float32(self, schema: FeatureSchema | None = None) -> np.ndarray:
        """성공한 결과를 고정된 모델 입력용 float32 벡터로 변환한다."""

        if self.status is not ExtractionStatus.SUCCESS:
            raise ValueError(f"cannot convert unsuccessful result: {self.status}")
        if schema is None:
            raise ValueError("schema is required when converting a result")
        if schema.version != self.schema_version:
            raise ValueError(
                f"schema mismatch: result={self.schema_version}, "
                f"requested={schema.version}"
            )
        return schema.validate_vector(self.features)

    def to_model_input(self, selector: FeatureSelector) -> np.ndarray:
        """선택 규칙을 검증한 뒤 모델에 전달할 Feature 벡터를 반환한다.

        추출 결과의 Feature 개수만 확인하지 않고, 원본 Schema 버전과
        Feature 이름·순서도 함께 확인한다. 이를 통해 다른 버전의 벡터나
        열 순서가 바뀐 데이터를 실수로 모델에 전달하는 것을 막는다.
        """

        if self.status is not ExtractionStatus.SUCCESS:
            raise ValueError(f"cannot convert unsuccessful result: {self.status}")

        selector.validate_source_metadata(self.schema_version, self.feature_names)
        return selector.select_vector(self.features)

    def to_dict(self) -> dict[str, Any]:
        """JSON으로 직렬화할 수 있는 공통 딕셔너리를 반환한다."""

        return {
            "schema_version": self.schema_version,
            "sha256": self.sha256,
            "file_type": self.file_type,
            "is_dotnet": self.is_dotnet,
            "status": self.status.value,
            "feature_count": self.feature_count,
            "feature_names": list(self.feature_names),
            "features": [float(value) for value in self.features],
            "missing_features": list(self.missing_features),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "metadata": dict(self.metadata),
            "api_groups": (
                self.api_groups.to_dict() if self.api_groups is not None else None
            ),
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        """NumPy 전용 자료형 없이 결과를 JSON 문자열로 직렬화한다."""

        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            indent=indent,
            allow_nan=False,
        )
