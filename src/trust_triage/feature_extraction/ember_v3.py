"""공식 EMBER2024 Feature Version 3 추출기.

공식 EMBER2024 저장소의 ``thrember`` 구현을 사용해 Feature 그룹과 벡터
순서를 그대로 적용한다. 프로젝트에는 이 추출기만 등록되어 있으며,
입력 PE는 실행하지 않고 바이트를 정적으로 읽기만 한다.
"""

from __future__ import annotations

import hashlib
import json
import math
import multiprocessing
import queue
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from time import perf_counter
from typing import Any, Final, Protocol, Sequence

import numpy as np
import pefile

from .api_groups import classify_imports
from .result import ExtractionStatus, FeatureExtractionResult
from .schema import FeatureGroup, FeatureSchema


DEFAULT_MAX_FILE_SIZE_BYTES: Final[int] = 200 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0
EMBER_V3_SCHEMA_PREFIX: Final[str] = "ember2024-v3-pe"
EMBER_V3_SOURCE_PACKAGE: Final[str] = "thrember"
EMBER_V3_SOURCE_REPOSITORY: Final[str] = (
    "https://github.com/FutureComputing4AI/EMBER2024"
)
EMBER_V3_SOURCE_COMMIT: Final[str] = (
    "0ef753e81d98bf209f71b03cd331dfc190b5b54d"
)


class _FeatureGroup(Protocol):
    """공식 thrember Feature 그룹에서 사용하는 최소 인터페이스."""

    name: str
    dim: int


class _ThremberExtractor(Protocol):
    """프로젝트가 공식 thrember 추출기에 사용하는 최소 인터페이스."""

    features: Sequence[_FeatureGroup]

    def feature_vector(self, bytez: bytes) -> np.ndarray:
        """PE 바이트를 고정 길이 벡터로 변환한다."""


def _normalize_repository_url(value: str) -> str:
    """저장소 URL의 마지막 슬래시와 .git 차이를 제거한다."""

    return value.rstrip("/").removesuffix(".git").casefold()


def _load_thrember_source_metadata(*, verify_source: bool) -> dict[str, object]:
    """설치된 thrember의 VCS 출처를 읽고 고정 커밋과 비교한다.

    requirements.txt는 EMBER2024 저장소 커밋을 고정한다. 설치된 패키지가
    다른 커밋인데도 같은 그룹 차원만 우연히 유지하면 모델 입력 계약이
    깨질 수 있으므로, PEP 610의 direct_url.json을 이용해 출처를 확인한다.
    """

    try:
        package_distribution = distribution(EMBER_V3_SOURCE_PACKAGE)
    except PackageNotFoundError as exc:
        raise RuntimeError(
            "설치된 thrember 배포판의 출처를 확인할 수 없습니다. "
            "requirements.txt를 다시 설치하세요."
        ) from exc

    observed_repository = ""
    observed_commit = ""
    source_error = ""
    try:
        direct_url_text = package_distribution.read_text("direct_url.json")
    except (OSError, UnicodeError) as exc:
        direct_url_text = None
        source_error = (
            "could not read direct_url.json: "
            f"{type(exc).__name__}: {exc}"
        )

    if direct_url_text and not source_error:
        try:
            direct_url = json.loads(direct_url_text)
            if not isinstance(direct_url, dict):
                raise TypeError("direct_url.json must contain a JSON object")

            observed_repository = str(direct_url.get("url", ""))
            vcs_info = direct_url.get("vcs_info", {})
            if not isinstance(vcs_info, dict):
                raise TypeError("direct_url.json vcs_info must be an object")
            observed_commit = str(vcs_info.get("commit_id", ""))
        except (json.JSONDecodeError, TypeError) as exc:
            source_error = f"invalid direct_url.json: {type(exc).__name__}: {exc}"
    elif not source_error:
        source_error = "direct_url.json is missing"

    verified = (
        not source_error
        and _normalize_repository_url(observed_repository)
        == _normalize_repository_url(EMBER_V3_SOURCE_REPOSITORY)
        and observed_commit == EMBER_V3_SOURCE_COMMIT
    )
    if verify_source and not verified:
        raise RuntimeError(
            "thrember 출처 검증에 실패했습니다. "
            f"expected={EMBER_V3_SOURCE_REPOSITORY}@{EMBER_V3_SOURCE_COMMIT}, "
            f"observed={observed_repository or 'unknown'}@{observed_commit or 'unknown'}"
            + (f" ({source_error})" if source_error else "")
        )

    return {
        "package": EMBER_V3_SOURCE_PACKAGE,
        "version": package_distribution.version,
        "repository": observed_repository or None,
        "commit": observed_commit or None,
        "expected_repository": EMBER_V3_SOURCE_REPOSITORY,
        "expected_commit": EMBER_V3_SOURCE_COMMIT,
        "source_verified": verified,
        "source_verification_error": source_error or None,
    }


@dataclass(frozen=True)
class _FileReadResult:
    """파일 읽기 단계의 데이터와 실패 상태를 함께 보관한다."""

    data: bytes | None
    sha256: str
    error: str | None
    status: ExtractionStatus | None


def _read_file(path: Path, max_file_size_bytes: int) -> _FileReadResult:
    """파일을 읽고 SHA-256을 계산한다.

    파일 크기를 먼저 확인해 불필요하게 큰 파일을 메모리에 올리지 않는다.
    이 함수는 파일을 실행하거나 DLL로 로드하지 않는다.
    """

    try:
        if not path.is_file():
            return _FileReadResult(
                data=None,
                sha256="",
                error="input path is not a regular file",
                status=ExtractionStatus.PARSE_ERROR,
            )
        file_size = path.stat().st_size
    except OSError as exc:
        return _FileReadResult(
            data=None,
            sha256="",
            error=f"unable to inspect input file: {type(exc).__name__}: {exc}",
            status=ExtractionStatus.PARSE_ERROR,
        )

    if file_size > max_file_size_bytes:
        return _FileReadResult(
            data=None,
            sha256="",
            error=f"file size {file_size} exceeds limit {max_file_size_bytes}",
            status=ExtractionStatus.FILE_TOO_LARGE,
        )

    try:
        data = path.read_bytes()
    except OSError as exc:
        return _FileReadResult(
            data=None,
            sha256="",
            error=f"unable to read input file: {type(exc).__name__}: {exc}",
            status=ExtractionStatus.PARSE_ERROR,
        )

    if len(data) > max_file_size_bytes:
        return _FileReadResult(
            data=None,
            sha256="",
            error=f"file size {len(data)} exceeds limit {max_file_size_bytes}",
            status=ExtractionStatus.FILE_TOO_LARGE,
        )

    return _FileReadResult(
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        error=None,
        status=None,
    )


def _read_failure(
    *,
    schema_version: str,
    read_result: _FileReadResult,
    metadata: dict[str, object] | None = None,
) -> FeatureExtractionResult:
    """파일 읽기 실패를 공통 결과 객체로 변환한다."""

    if read_result.error is None or read_result.status is None:
        raise ValueError("a failed file-read result must contain error and status")
    return FeatureExtractionResult.failure(
        schema_version=schema_version,
        status=read_result.status,
        errors=[read_result.error],
        metadata=metadata,
    )


def _run_extraction_worker(
    sample_path: str,
    max_file_size_bytes: int,
    features_file: str | None,
    verify_source: bool,
    result_queue: Any,
) -> None:
    """별도 프로세스에서 Feature 추출을 실행하고 결과를 전달한다."""

    try:
        extractor = EmberV3Extractor(
            max_file_size_bytes=max_file_size_bytes,
            features_file=features_file,
            verify_source=verify_source,
        )
        result_queue.put(extractor.extract(sample_path))
    except Exception as exc:
        result_queue.put(
            {
                "error": f"{type(exc).__name__}: {exc}",
            }
        )


def _stop_process(process: multiprocessing.Process) -> None:
    """분석 프로세스를 terminate 후 필요하면 kill한다."""

    if not process.is_alive():
        return
    process.terminate()
    process.join(2)
    if process.is_alive():
        process.kill()
        process.join(2)


def _load_thrember_extractor(
    features_file: Path | None = None,
) -> _ThremberExtractor:
    """공식 ``thrember`` 추출기를 생성한다.

    thrember를 모듈 import 시점이 아니라 객체 생성 시점에 불러온다. 그러면
    프로젝트의 다른 모듈이 import 오류로 즉시 종료되지 않고, 실행 시점에
    설치 문제를 이해하기 쉬운 메시지로 확인할 수 있다.
    """

    try:
        from thrember.features import PEFeatureExtractor
    except ImportError as exc:
        raise RuntimeError(
            "EMBER2024 Feature를 사용하려면 requirements.txt의 공식 "
            "thrember 의존성을 설치해야 합니다. 설치된 thrember와 "
            "signify 버전이 requirements.txt와 같은지도 확인하세요."
        ) from exc

    return PEFeatureExtractor(features_file=features_file)


def _build_schema(thrember_extractor: _ThremberExtractor) -> FeatureSchema:
    """공식 추출기의 Feature 그룹에서 프로젝트 Schema를 만든다.

    thrember는 개별 벡터 원소의 이름 목록을 따로 제공하지 않는다. 따라서
    ``그룹명[원소번호]`` 형식으로 이름을 만들고, 실제 그룹 순서와 차원은
    설치된 공식 추출기에서 읽는다. 이 정보는 코드에 중복해서 적지 않는다.
    """

    feature_names: list[str] = []
    group_signature: list[str] = []
    feature_groups: list[FeatureGroup] = []
    seen_group_names: set[str] = set()
    start_index = 0

    for feature_group in thrember_extractor.features:
        group_name = str(feature_group.name)
        dimension = int(feature_group.dim)
        if not group_name or group_name in seen_group_names:
            raise ValueError(f"invalid or duplicated EMBER Feature group: {group_name!r}")
        if dimension <= 0:
            raise ValueError(
                f"EMBER Feature group {group_name!r} has invalid dimension: {dimension}"
            )

        seen_group_names.add(group_name)
        group_signature.append(f"{group_name}:{dimension}")
        feature_names.extend(
            f"{group_name}[{index}]" for index in range(dimension)
        )
        feature_groups.append(
            FeatureGroup(
                name=group_name,
                start_index=start_index,
                dimension=dimension,
            )
        )
        start_index += dimension

    if not feature_names:
        raise ValueError("the EMBER Feature configuration contains no Feature groups")

    # 그룹의 이름·순서·차원을 지문으로 만들어 설정이 달라지면 Schema 버전도
    # 달라지게 한다. 모델이 다른 Feature 구성의 벡터를 받는 실수를 막기 위한
    # 장치다.
    signature = "|".join(group_signature).encode("utf-8")
    fingerprint = hashlib.sha256(signature).hexdigest()[:12]
    return FeatureSchema(
        version=f"{EMBER_V3_SCHEMA_PREFIX}-{fingerprint}",
        feature_names=tuple(feature_names),
        groups=tuple(feature_groups),
    )


class EmberV3Extractor:
    """공식 EMBER2024 Feature Version 3 PE 벡터를 추출한다."""

    def __init__(
        self,
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
        features_file: str | Path | None = None,
        verify_source: bool = True,
    ) -> None:
        if max_file_size_bytes <= 0:
            raise ValueError("max_file_size_bytes must be positive")

        config_path = Path(features_file) if features_file is not None else None
        if config_path is not None and not config_path.is_file():
            raise FileNotFoundError(
                f"EMBER Feature configuration does not exist: {config_path}"
            )

        self.max_file_size_bytes = max_file_size_bytes
        self.features_file = config_path
        self.verify_source = verify_source
        self._thrember = _load_thrember_extractor(config_path)
        self.source_metadata = _load_thrember_source_metadata(
            verify_source=verify_source
        )
        self.schema = _build_schema(self._thrember)

    @staticmethod
    def can_handle(header: bytes) -> bool:
        """파일 시작 부분이 PE의 DOS MZ 서명인지 확인한다."""

        return header[:2] == b"MZ"

    def extract(self, path: str | Path) -> FeatureExtractionResult:
        """PE 파일을 읽어 공식 EMBER v3 벡터로 변환한다."""

        read_result = _read_file(Path(path), self.max_file_size_bytes)
        if read_result.error is not None:
            return _read_failure(
                schema_version=self.schema.version,
                read_result=read_result,
                metadata=self.source_metadata,
            )
        assert read_result.data is not None
        return self._extract_bytes(read_result.data, read_result.sha256)

    def _extract_bytes(
        self,
        data: bytes,
        sha256: str,
    ) -> FeatureExtractionResult:
        """이미 읽은 PE 바이트를 파싱하고 Feature 벡터로 변환한다."""

        if not self.can_handle(data[:2]):
            return FeatureExtractionResult.failure(
                schema_version=self.schema.version,
                status=ExtractionStatus.UNSUPPORTED,
                sha256=sha256,
                errors=["only PE files with a DOS MZ signature are supported"],
                metadata=self.source_metadata,
            )

        try:
            pe = pefile.PE(data=data, fast_load=False)
        except pefile.PEFormatError as exc:
            return FeatureExtractionResult.failure(
                schema_version=self.schema.version,
                status=ExtractionStatus.INVALID_PE,
                sha256=sha256,
                errors=[f"pefile rejected the input: {exc}"],
                metadata=self.source_metadata,
            )
        except Exception as exc:
            return FeatureExtractionResult.failure(
                schema_version=self.schema.version,
                status=ExtractionStatus.PARSE_ERROR,
                sha256=sha256,
                errors=[f"PE parsing failed: {type(exc).__name__}: {exc}"],
                metadata=self.source_metadata,
            )

        try:
            vector = np.asarray(
                self._thrember.feature_vector(data),
                dtype=np.float32,
            )
            api_groups = None
            warnings: list[str] = []
            try:
                api_groups = classify_imports(pe)
            except Exception as exc:
                # API 그룹 분석 실패가 EMBER 모델용 Feature 추출 실패를 의미하지는 않는다.
                warnings.append(
                    "API group classification failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            return FeatureExtractionResult.success(
                schema=self.schema,
                sha256=sha256,
                file_type=self._file_type(pe),
                values=vector,
                warnings=warnings,
                api_groups=api_groups,
                is_dotnet=self._is_dotnet(pe),
                metadata=self.source_metadata,
            )
        except Exception as exc:
            return FeatureExtractionResult.failure(
                schema_version=self.schema.version,
                status=ExtractionStatus.PARSE_ERROR,
                sha256=sha256,
                errors=[
                    f"EMBER Feature extraction failed: {type(exc).__name__}: {exc}"
                ],
                metadata=self.source_metadata,
            )
        finally:
            pe.close()

    @staticmethod
    def _file_type(pe: pefile.PE) -> str:
        """Optional Header의 Magic 값으로 PE32 계열을 구분한다."""

        magic = int(getattr(getattr(pe, "OPTIONAL_HEADER", None), "Magic", 0) or 0)
        if magic == 0x10B:
            return "PE32"
        if magic == 0x20B:
            return "PE32+"
        return "UNKNOWN"

    @staticmethod
    def _is_dotnet(pe: pefile.PE) -> bool:
        """CLR Runtime Header 디렉터리가 있는지 확인해 .NET 여부를 판별한다."""

        try:
            directory_index = pefile.DIRECTORY_ENTRY[
                "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"
            ]
            directories = getattr(
                getattr(pe, "OPTIONAL_HEADER", None),
                "DATA_DIRECTORY",
                [],
            )
            if len(directories) <= directory_index:
                return False

            clr_directory = directories[directory_index]
            return bool(
                int(getattr(clr_directory, "VirtualAddress", 0) or 0)
                and int(getattr(clr_directory, "Size", 0) or 0)
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            return False

    def extract_with_timeout(
        self,
        path: str | Path,
        timeout_seconds: float,
    ) -> FeatureExtractionResult:
        """별도 프로세스에서 추출하고 제한 시간을 넘기면 종료한다.

        일반 ``extract``는 데이터 처리 파이프라인에서 반복 호출하기 쉽도록
        현재 프로세스에서 실행한다. 외부 파일을 받는 CLI·API는 이 메서드나
        ``extract_file(..., timeout_seconds=...)``를 사용해야 한다.
        """

        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        return _extract_with_timeout(self, Path(path), timeout_seconds)


def _close_result_queue(result_queue: Any) -> None:
    """별도 프로세스 결과 Queue를 안전하게 닫는다."""

    try:
        result_queue.close()
    finally:
        result_queue.join_thread()


def _extract_with_timeout(
    extractor: EmberV3Extractor,
    path: Path,
    timeout_seconds: float,
) -> FeatureExtractionResult:
    """추출 작업을 별도 프로세스에서 실행하고 결과를 회수한다."""

    read_result = _read_file(path, extractor.max_file_size_bytes)
    if read_result.error is not None:
        return _read_failure(
            schema_version=extractor.schema.version,
            read_result=read_result,
            metadata={
                **extractor.source_metadata,
                "execution_mode": "separate_process",
                "timeout_seconds": timeout_seconds,
            },
        )

    # 부모 프로세스에서는 사전 검증과 SHA-256 확인만 수행한다. 전체 바이트를
    # 계속 들고 있지 않아 자식 프로세스와 메모리를 불필요하게 중복하지 않는다.
    expected_sha256 = read_result.sha256
    del read_result

    metadata = {
        **extractor.source_metadata,
        "execution_mode": "separate_process",
        "timeout_seconds": timeout_seconds,
    }
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue(maxsize=1)
    process = context.Process(
        target=_run_extraction_worker,
        args=(
            str(path),
            extractor.max_file_size_bytes,
            str(extractor.features_file) if extractor.features_file else None,
            extractor.verify_source,
            result_queue,
        ),
    )
    started = perf_counter()

    try:
        process.start()
    except Exception as exc:
        _close_result_queue(result_queue)
        return FeatureExtractionResult.failure(
            schema_version=extractor.schema.version,
            sha256=expected_sha256,
            status=ExtractionStatus.TOOL_ERROR,
            errors=[f"timed extraction process failed to start: {exc}"],
            metadata=metadata,
        )

    payload: object | None = None
    received = False
    while not received:
        remaining = timeout_seconds - (perf_counter() - started)
        if remaining <= 0:
            break
        try:
            payload = result_queue.get(timeout=min(0.1, remaining))
            received = True
        except queue.Empty:
            if not process.is_alive():
                break

    elapsed_ms = int((perf_counter() - started) * 1000)
    if not received:
        process_was_alive = process.is_alive()
        if process_was_alive:
            _stop_process(process)
            status = ExtractionStatus.TIMEOUT
            summary = "정적 Feature 추출이 제한 시간 안에 끝나지 않았습니다."
            error = (
                f"timeout_seconds={timeout_seconds}, "
                f"process_exit_code={process.exitcode}"
            )
        else:
            process.join(1)
            status = ExtractionStatus.TOOL_ERROR
            summary = "정적 Feature 추출 프로세스가 결과를 반환하지 않았습니다."
            error = f"process_exit_code={process.exitcode}"
        _close_result_queue(result_queue)
        return FeatureExtractionResult.failure(
            schema_version=extractor.schema.version,
            sha256=expected_sha256,
            status=status,
            errors=[error],
            warnings=[summary],
            metadata={
                **metadata,
                "analysis_time_ms": elapsed_ms,
            },
        )

    # Queue에서 결과를 받았지만 자식 프로세스가 정리되지 않는 경우도
    # 부모가 계속 기다리지 않도록 종료한다.
    if process.is_alive():
        _stop_process(process)
    else:
        process.join(1)
    _close_result_queue(result_queue)

    if not isinstance(payload, FeatureExtractionResult):
        error = (
            payload.get("error", "unknown worker error")
            if isinstance(payload, dict)
            else "worker returned an invalid result"
        )
        return FeatureExtractionResult.failure(
            schema_version=extractor.schema.version,
            sha256=expected_sha256,
            status=ExtractionStatus.TOOL_ERROR,
            errors=[str(error)],
            metadata={
                **metadata,
                "analysis_time_ms": elapsed_ms,
            },
        )

    if payload.sha256 != expected_sha256:
        return FeatureExtractionResult.failure(
            schema_version=extractor.schema.version,
            sha256=expected_sha256,
            status=ExtractionStatus.PARSE_ERROR,
            errors=["input file changed while timed extraction was running"],
            metadata={
                **metadata,
                "analysis_time_ms": elapsed_ms,
            },
        )

    payload.metadata = {
        **payload.metadata,
        "execution_mode": "separate_process",
        "timeout_seconds": timeout_seconds,
        "analysis_time_ms": elapsed_ms,
    }
    return payload


def extract_file(
    path: str | Path,
    *,
    features_file: str | Path | None = None,
    timeout_seconds: float | None = None,
    verify_source: bool = True,
) -> FeatureExtractionResult:
    """프로젝트의 유일한 추출기인 EMBER v3 방식으로 파일을 처리한다.

    ``timeout_seconds``를 지정하면 추출 작업 전체를 별도 프로세스에서
    실행한다. 지정하지 않으면 반복적인 데이터 처리에 적합한 현재 프로세스
    실행 경로를 사용한다.
    """

    extractor = EmberV3Extractor(
        features_file=features_file,
        verify_source=verify_source,
    )
    if timeout_seconds is None:
        return extractor.extract(path)
    return extractor.extract_with_timeout(path, timeout_seconds)
