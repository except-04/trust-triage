"""버전과 순서가 고정된 Feature Schema.

이 모듈의 Feature 이름과 순서가 모델 입력 벡터의 유일한 기준이다.
기존 벡터를 조용히 바꾸지 말고, Feature 구성이 달라지면 새 Schema 버전을
만들어 모델 입력 호환성을 보존한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np


@dataclass(frozen=True)
class FeatureSchema:
    """모델 입력 벡터를 설명하는 변경 불가능한 Schema."""

    version: str
    feature_names: tuple[str, ...]
    dtype: str = "float32"

    @property
    def feature_count(self) -> int:
        return len(self.feature_names)

    def validate_vector(self, values: Sequence[float] | np.ndarray) -> np.ndarray:
        """검증된 1차원 NumPy 벡터를 반환한다.

        잘못된 벡터를 0으로 채우거나 자르지 않는다. 그렇게 하면 Feature
        개수나 순서가 달라도 모델 호환이 깨진 사실을 숨기게 된다.
        """

        vector = np.asarray(values, dtype=np.float32)
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


PE_STATIC_SCHEMA_VERSION = "pe-static-mvp-v1"

# 이 튜플의 순서는 모델 입력 벡터의 순서와 정확히 같아야 한다.
# SHA-256과 파일 형식은 메타데이터이므로 숫자 Feature 벡터에는 넣지 않는다.
PE_STATIC_FEATURE_NAMES = (
    # 파일 전체에서 계산하는 값.
    "file_size",
    "file_entropy",
    # COFF Header와 Optional Header 값.
    "machine",
    "number_of_sections",
    "timestamp",
    "pe_characteristics",
    "optional_header_magic",
    "major_linker_version",
    "minor_linker_version",
    "size_of_code",
    "size_of_initialized_data",
    "size_of_uninitialized_data",
    "address_of_entry_point",
    "base_of_code",
    "image_base",
    "section_alignment",
    "file_alignment",
    "size_of_image",
    "size_of_headers",
    "subsystem",
    "dll_characteristics",
    "number_of_rva_and_sizes",
    # 여러 Section의 값을 합산·평균·최대값 등으로 요약한 값.
    "section_raw_size_sum",
    "section_raw_size_mean",
    "section_raw_size_max",
    "section_virtual_size_sum",
    "section_virtual_size_mean",
    "section_virtual_size_max",
    "section_entropy_min",
    "section_entropy_mean",
    "section_entropy_max",
    "executable_section_count",
    "writable_section_count",
    "readable_section_count",
    "zero_raw_size_section_count",
    "overlay_size",
    # Import와 Export 관련 값.
    "import_dll_count",
    "import_function_count",
    "ordinal_import_count",
    "export_count",
    "export_named_count",
    # 출력 가능한 ASCII·UTF-16 문자열 통계.
    "ascii_string_count",
    "ascii_string_total_length",
    "ascii_string_max_length",
    "ascii_string_mean_length",
    "unicode_string_count",
    "unicode_string_total_length",
    "unicode_string_max_length",
    "unicode_string_mean_length",
    # 파일 형식과 보안 관련 표시 값.
    "has_security_directory",
    "is_dotnet",
    "is_dll",
)


PE_STATIC_FEATURE_SCHEMA = FeatureSchema(
    version=PE_STATIC_SCHEMA_VERSION,
    feature_names=PE_STATIC_FEATURE_NAMES,
)
