"""PE 파일 정적 Feature 추출.

이 모듈은 파일 바이트와 PE 메타데이터만 읽는다. 입력 파일을 실행하거나
DLL을 로드하지 않으며, 파일 안에 있는 명령도 호출하지 않는다.
"""

from __future__ import annotations

import hashlib
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar, Sequence

import numpy as np
import pefile

from .result import ExtractionStatus, FeatureExtractionResult
from .schema import FeatureSchema, PE_STATIC_FEATURE_SCHEMA


DEFAULT_MAX_FILE_SIZE_BYTES = 200 * 1024 * 1024
# 문자열 통계에 포함할 최소 문자열 길이.
MIN_STRING_LENGTH = 4

_MIN_STRING_LENGTH_TEXT = str(MIN_STRING_LENGTH).encode("ascii")
_ASCII_STRING_PATTERN = re.compile(
    rb"[\x20-\x7e]{" + _MIN_STRING_LENGTH_TEXT + rb",}"
)
_UNICODE_STRING_PATTERN = re.compile(
    rb"(?:[\x20-\x7e]\x00){" + _MIN_STRING_LENGTH_TEXT + rb",}"
)

# IMAGE_SECTION_HEADER.Characteristics에 정의된 Section 권한 Flag.
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_READ = 0x40000000
_IMAGE_SCN_MEM_WRITE = 0x80000000

# PE Data Directory 배열의 표준 인덱스.
_IMAGE_DIRECTORY_ENTRY_SECURITY = 4
_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14

# IMAGE_FILE_HEADER.Characteristics의 DLL 여부 Flag.
_IMAGE_FILE_DLL = 0x2000


class BaseExtractor(ABC):
    """PE, ELF, Mach-O 등 형식별 Extractor가 구현할 공통 인터페이스."""

    format_name: ClassVar[str]
    schema: ClassVar[FeatureSchema]

    @classmethod
    @abstractmethod
    def can_handle(cls, header: bytes) -> bool:
        """파일 시그니처가 이 Extractor가 처리할 형식인지 반환한다."""

    @abstractmethod
    def extract(self, path: str | Path) -> FeatureExtractionResult:
        """파일을 실행하지 않고 고정 Schema 결과를 추출한다."""


def _file_entropy(data: bytes) -> float:
    """바이트별 출현 확률로 Shannon Entropy를 계산한다.

    Entropy는 데이터가 얼마나 균등하게 분포하는지 나타내며, 일반적인
    8비트 바이트 데이터에서는 0부터 8 사이의 값을 갖는다. 압축·암호화·
    패킹된 영역은 높은 Entropy를 보일 수 있지만, 이것만으로 악성 여부를
    확정할 수는 없다.
    """

    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = counts[counts > 0] / len(data)
    return float(-(probabilities * np.log2(probabilities)).sum())


def _summary(values: Sequence[float]) -> tuple[float, float, float]:
    """값의 합·평균·최대값을 반환하며, 빈 목록은 0으로 처리한다."""

    if not values:
        return 0.0, 0.0, 0.0
    return float(sum(values)), float(sum(values) / len(values)), float(max(values))


def _min_mean_max(values: Sequence[float]) -> tuple[float, float, float]:
    """값의 최소·평균·최대값을 반환하며, 빈 목록은 0으로 처리한다."""

    if not values:
        return 0.0, 0.0, 0.0
    return float(min(values)), float(sum(values) / len(values)), float(max(values))


def _string_lengths(data: bytes, pattern: re.Pattern[bytes], divisor: int = 1) -> list[int]:
    """정규식으로 찾은 문자열 길이를 반환한다.

    UTF-16LE 문자열은 한 문자가 2바이트이므로 divisor를 2로 전달한다.
    문자열 원문은 저장하지 않고 개수와 길이 통계만 Feature로 사용한다.
    """

    return [len(match.group(0)) // divisor for match in pattern.finditer(data)]


def _string_summary(lengths: Sequence[int]) -> tuple[float, float, float, float]:
    """문자열 개수·총 길이·최대 길이·평균 길이를 반환한다."""

    if not lengths:
        return 0.0, 0.0, 0.0, 0.0
    return (
        float(len(lengths)),
        float(sum(lengths)),
        float(max(lengths)),
        float(sum(lengths) / len(lengths)),
    )


def _append_once(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _read_numeric(
    obj: object,
    attribute: str,
    feature_name: str,
    values: dict[str, float],
    missing_features: list[str],
) -> None:
    raw_value = getattr(obj, attribute, None)
    if raw_value is None:
        values[feature_name] = 0.0
        _append_once(missing_features, feature_name)
        return
    try:
        values[feature_name] = float(raw_value)
    except (TypeError, ValueError, OverflowError):
        values[feature_name] = 0.0
        _append_once(missing_features, feature_name)


def _directory_present(pe: pefile.PE, directory_index: int) -> bool:
    """지정한 PE Data Directory가 존재하는지 확인한다.

    이 함수는 디렉터리의 주소나 크기가 기록되어 있는지만 확인한다.
    예를 들어 Security Directory가 있어도 인증서의 유효성까지 검증하지는
    않는다.
    """

    directories = getattr(getattr(pe, "OPTIONAL_HEADER", None), "DATA_DIRECTORY", ())
    if len(directories) <= directory_index:
        return False
    directory = directories[directory_index]
    size = int(getattr(directory, "Size", 0) or 0)
    virtual_address = int(getattr(directory, "VirtualAddress", 0) or 0)
    return size > 0 or virtual_address > 0


def _hash_and_read(path: Path, max_file_size_bytes: int) -> tuple[bytes | None, str, str | None]:
    """파일을 읽고 SHA-256을 계산한다.

    PE를 메모리에서 파싱해야 하므로 먼저 파일 크기 제한을 적용한다.
    제한을 넘거나 읽기에 실패하면 바이트와 해시를 반환하지 않는다.
    """

    try:
        if not path.is_file():
            return None, "", "input path is not a regular file"
        file_size = path.stat().st_size
    except OSError as exc:
        return None, "", f"unable to inspect input file: {type(exc).__name__}: {exc}"

    if file_size > max_file_size_bytes:
        return None, "", f"file size {file_size} exceeds limit {max_file_size_bytes}"

    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, "", f"unable to read input file: {type(exc).__name__}: {exc}"

    if len(data) > max_file_size_bytes:
        return None, "", f"file size {len(data)} exceeds limit {max_file_size_bytes}"
    return data, hashlib.sha256(data).hexdigest(), None


class PEExtractor(BaseExtractor):
    """PE32와 PE32+ 파일에서 재현 가능한 정적 Feature를 추출한다."""

    format_name = "PE"
    schema = PE_STATIC_FEATURE_SCHEMA

    def __init__(self, max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES) -> None:
        if max_file_size_bytes <= 0:
            raise ValueError("max_file_size_bytes must be positive")
        self.max_file_size_bytes = max_file_size_bytes

    @classmethod
    def can_handle(cls, header: bytes) -> bool:
        return header[:2] == b"MZ"

    def extract(self, path: str | Path) -> FeatureExtractionResult:
        input_path = Path(path)
        data, sha256, read_error = _hash_and_read(
            input_path, self.max_file_size_bytes
        )
        if read_error is not None:
            status = (
                ExtractionStatus.FILE_TOO_LARGE
                if "exceeds limit" in read_error
                else ExtractionStatus.PARSE_ERROR
            )
            return FeatureExtractionResult.failure(
                schema_version=self.schema.version,
                status=status,
                errors=[read_error],
            )
        assert data is not None

        if not self.can_handle(data[:2]):
            return FeatureExtractionResult.failure(
                schema_version=self.schema.version,
                status=ExtractionStatus.INVALID_PE,
                sha256=sha256,
                errors=["missing DOS MZ signature"],
            )

        try:
            pe = pefile.PE(data=data, fast_load=False)
        except pefile.PEFormatError as exc:
            return FeatureExtractionResult.failure(
                schema_version=self.schema.version,
                status=ExtractionStatus.INVALID_PE,
                sha256=sha256,
                errors=[f"pefile rejected the input: {exc}"],
            )
        except Exception as exc:  # 예상하지 못한 파서 오류도 숨기지 않고 기록한다.
            return FeatureExtractionResult.failure(
                schema_version=self.schema.version,
                status=ExtractionStatus.PARSE_ERROR,
                sha256=sha256,
                errors=[f"PE parsing failed: {type(exc).__name__}: {exc}"],
            )

        try:
            return self._extract_parsed(pe, data, sha256)
        except Exception as exc:  # 내부 오류를 SUCCESS로 바꾸지 않고 실패로 반환한다.
            return FeatureExtractionResult.failure(
                schema_version=self.schema.version,
                status=ExtractionStatus.PARSE_ERROR,
                sha256=sha256,
                errors=[f"feature extraction failed: {type(exc).__name__}: {exc}"],
            )
        finally:
            pe.close()

    def _extract_parsed(
        self, pe: pefile.PE, data: bytes, sha256: str
    ) -> FeatureExtractionResult:
        values: dict[str, float] = {
            "file_size": float(len(data)),
            "file_entropy": _file_entropy(data),
        }
        missing_features: list[str] = []
        warnings: list[str] = []

        optional_header = getattr(pe, "OPTIONAL_HEADER", None)
        file_header = getattr(pe, "FILE_HEADER", None)
        if optional_header is None or file_header is None:
            return FeatureExtractionResult.failure(
                schema_version=self.schema.version,
                status=ExtractionStatus.PARSE_ERROR,
                sha256=sha256,
                errors=["PE headers are incomplete"],
            )

        optional_header_magic = int(getattr(optional_header, "Magic", 0) or 0)
        if optional_header_magic not in (0x10B, 0x20B):
            return FeatureExtractionResult.failure(
                schema_version=self.schema.version,
                status=ExtractionStatus.UNSUPPORTED,
                sha256=sha256,
                errors=[f"unsupported optional-header magic: {optional_header_magic:#x}"],
            )

        header_fields = (
            (file_header, "Machine", "machine"),
            (file_header, "NumberOfSections", "number_of_sections"),
            (file_header, "TimeDateStamp", "timestamp"),
            (file_header, "Characteristics", "pe_characteristics"),
            (optional_header, "Magic", "optional_header_magic"),
            (optional_header, "MajorLinkerVersion", "major_linker_version"),
            (optional_header, "MinorLinkerVersion", "minor_linker_version"),
            (optional_header, "SizeOfCode", "size_of_code"),
            (
                optional_header,
                "SizeOfInitializedData",
                "size_of_initialized_data",
            ),
            (
                optional_header,
                "SizeOfUninitializedData",
                "size_of_uninitialized_data",
            ),
            (optional_header, "AddressOfEntryPoint", "address_of_entry_point"),
            (optional_header, "BaseOfCode", "base_of_code"),
            (optional_header, "ImageBase", "image_base"),
            (optional_header, "SectionAlignment", "section_alignment"),
            (optional_header, "FileAlignment", "file_alignment"),
            (optional_header, "SizeOfImage", "size_of_image"),
            (optional_header, "SizeOfHeaders", "size_of_headers"),
            (optional_header, "Subsystem", "subsystem"),
            (optional_header, "DllCharacteristics", "dll_characteristics"),
            (optional_header, "NumberOfRvaAndSizes", "number_of_rva_and_sizes"),
        )
        for obj, attribute, feature_name in header_fields:
            _read_numeric(obj, attribute, feature_name, values, missing_features)

        characteristics = int(getattr(file_header, "Characteristics", 0) or 0)
        # Security Directory는 존재 여부만 보며, 서명 검증은 담당하지 않는다.
        values["has_security_directory"] = float(
            _directory_present(pe, _IMAGE_DIRECTORY_ENTRY_SECURITY)
        )
        # COM Descriptor가 있으면 .NET 가능성을 표시한다. 심층 .NET 분석은
        # 별도 모듈의 책임이며, 여기서는 PE 수준의 표시 값만 제공한다.
        values["is_dotnet"] = float(
            _directory_present(pe, _IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        )
        values["is_dll"] = float(bool(characteristics & _IMAGE_FILE_DLL))

        sections = list(getattr(pe, "sections", ()) or ())
        raw_sizes: list[float] = []
        virtual_sizes: list[float] = []
        section_entropies: list[float] = []
        executable_count = 0
        writable_count = 0
        readable_count = 0
        zero_raw_size_count = 0

        for section in sections:
            raw_size = getattr(section, "SizeOfRawData", 0)
            virtual_size = getattr(section, "Misc_VirtualSize", 0)
            raw_size = float(raw_size or 0)
            virtual_size = float(virtual_size or 0)
            raw_sizes.append(raw_size)
            virtual_sizes.append(virtual_size)
            if raw_size == 0:
                zero_raw_size_count += 1

            characteristics_value = int(getattr(section, "Characteristics", 0) or 0)
            executable_count += bool(characteristics_value & _IMAGE_SCN_MEM_EXECUTE)
            writable_count += bool(characteristics_value & _IMAGE_SCN_MEM_WRITE)
            readable_count += bool(characteristics_value & _IMAGE_SCN_MEM_READ)

            try:
                section_entropies.append(float(section.get_entropy()))
            except Exception as exc:
                _append_once(missing_features, "section_entropy")
                warnings.append(
                    f"section entropy unavailable: {type(exc).__name__}: {exc}"
                )

        raw_sum, raw_mean, raw_max = _summary(raw_sizes)
        virtual_sum, virtual_mean, virtual_max = _summary(virtual_sizes)
        entropy_min, entropy_mean, entropy_max = _min_mean_max(section_entropies)
        values.update(
            {
                "section_raw_size_sum": raw_sum,
                "section_raw_size_mean": raw_mean,
                "section_raw_size_max": raw_max,
                "section_virtual_size_sum": virtual_sum,
                "section_virtual_size_mean": virtual_mean,
                "section_virtual_size_max": virtual_max,
                "section_entropy_min": entropy_min,
                "section_entropy_mean": entropy_mean,
                "section_entropy_max": entropy_max,
                "executable_section_count": float(executable_count),
                "writable_section_count": float(writable_count),
                "readable_section_count": float(readable_count),
                "zero_raw_size_section_count": float(zero_raw_size_count),
            }
        )

        try:
            overlay_start = pe.get_overlay_data_start_offset()
            values["overlay_size"] = float(
                max(0, len(data) - overlay_start) if overlay_start is not None else 0
            )
        except Exception as exc:
            values["overlay_size"] = 0.0
            _append_once(missing_features, "overlay_size")
            warnings.append(f"overlay size unavailable: {type(exc).__name__}: {exc}")

        import_dll_count = 0
        import_function_count = 0
        ordinal_import_count = 0
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()) or ():
            import_dll_count += 1
            for imported in getattr(entry, "imports", ()) or ():
                import_function_count += 1
                ordinal_import_count += bool(
                    getattr(imported, "import_by_ordinal", False)
                )
        values.update(
            {
                "import_dll_count": float(import_dll_count),
                "import_function_count": float(import_function_count),
                "ordinal_import_count": float(ordinal_import_count),
            }
        )

        export_symbols = getattr(
            getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", ()
        ) or ()
        export_count = len(export_symbols)
        export_named_count = sum(
            getattr(symbol, "name", None) is not None for symbol in export_symbols
        )
        values.update(
            {
                "export_count": float(export_count),
                "export_named_count": float(export_named_count),
            }
        )

        ascii_lengths = _string_lengths(data, _ASCII_STRING_PATTERN)
        unicode_lengths = _string_lengths(data, _UNICODE_STRING_PATTERN, divisor=2)
        (
            ascii_count,
            ascii_total,
            ascii_max,
            ascii_mean,
        ) = _string_summary(ascii_lengths)
        (
            unicode_count,
            unicode_total,
            unicode_max,
            unicode_mean,
        ) = _string_summary(unicode_lengths)
        values.update(
            {
                "ascii_string_count": ascii_count,
                "ascii_string_total_length": ascii_total,
                "ascii_string_max_length": ascii_max,
                "ascii_string_mean_length": ascii_mean,
                "unicode_string_count": unicode_count,
                "unicode_string_total_length": unicode_total,
                "unicode_string_max_length": unicode_max,
                "unicode_string_mean_length": unicode_mean,
            }
        )

        for feature_name in self.schema.feature_names:
            if feature_name not in values:
                values[feature_name] = 0.0
                _append_once(missing_features, feature_name)

        vector = [values[feature_name] for feature_name in self.schema.feature_names]
        return FeatureExtractionResult.success(
            schema=self.schema,
            sha256=sha256,
            file_type=self._file_type(pe),
            values=vector,
            missing_features=missing_features,
            warnings=warnings,
        )

    @staticmethod
    def _file_type(pe: pefile.PE) -> str:
        magic = int(getattr(getattr(pe, "OPTIONAL_HEADER", None), "Magic", 0) or 0)
        if magic == 0x10B:
            return "PE32"
        if magic == 0x20B:
            return "PE32+"
        return "UNKNOWN"


def _unsupported_result(
    path: Path,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
) -> FeatureExtractionResult:
    data, sha256, read_error = _hash_and_read(path, max_file_size_bytes)
    if read_error is not None:
        status = (
            ExtractionStatus.FILE_TOO_LARGE
            if "exceeds limit" in read_error
            else ExtractionStatus.PARSE_ERROR
        )
        return FeatureExtractionResult.failure(
            schema_version="unsupported-v1",
            status=status,
            errors=[read_error],
        )
    assert data is not None
    return FeatureExtractionResult.failure(
        schema_version="unsupported-v1",
        status=ExtractionStatus.UNSUPPORTED,
        sha256=sha256,
        errors=["no registered extractor recognizes the file signature"],
    )


def extract_file(
    path: str | Path,
    extractors: Sequence[BaseExtractor] | None = None,
) -> FeatureExtractionResult:
    """파일 시그니처에 맞는 첫 번째 Extractor로 분석을 전달한다.

    앞으로 ELF나 Mach-O를 지원할 때도 BaseExtractor를 구현해 전달하면
    되며, 결과 JSON과 상태 계약은 그대로 유지한다.
    """

    input_path = Path(path)
    try:
        with input_path.open("rb") as file_handle:
            header = file_handle.read(4)
    except OSError as exc:
        return FeatureExtractionResult.failure(
            schema_version="unsupported-v1",
            status=ExtractionStatus.PARSE_ERROR,
            errors=[f"unable to read input file: {type(exc).__name__}: {exc}"],
        )

    registered_extractors = tuple(
        (PEExtractor(),) if extractors is None else extractors
    )
    for extractor in registered_extractors:
        if extractor.can_handle(header):
            return extractor.extract(input_path)
    return _unsupported_result(input_path)
