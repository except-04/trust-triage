"""Speakeasy를 제한된 별도 프로세스에서 실행하고 Evidence로 변환한다."""

from __future__ import annotations

import hashlib
import json
import multiprocessing
import queue
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Mapping

from .models import DynamicAnalysisResult, DynamicAnalysisStatus


DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_INSTRUCTIONS = 1_000_000
DEFAULT_MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_API_COUNT = 10_000
MAX_EVENTS_PER_CATEGORY = 100
MAX_EVENT_VALUE_LENGTH = 4_096

_EVENT_FIELDS = {
    "network_events": "network",
    "file_access": "file_access",
    "registry_access": "registry_access",
    "process_events": "process_events",
    "dynamic_code_segments": "dynamic_code",
    "dropped_files": "dropped_files",
    "handled_exceptions": "handled_exceptions",
}


@dataclass(frozen=True)
class ReportSummary:
    """대형 원본 report에서 후속 모듈에 전달할 요약만 보관한다."""

    observed_apis: tuple[str, ...]
    api_call_counts: Mapping[str, int]
    behaviors: tuple[str, ...]
    events: Mapping[str, tuple[Mapping[str, Any], ...]]
    warnings: tuple[str, ...]


def _new_evidence_id() -> str:
    """분석 실행마다 충돌하지 않는 Evidence ID를 만든다."""

    return f"speakeasy-{uuid.uuid4().hex}"


def _utc_now() -> str:
    """사람이 읽기 쉬운 UTC ISO-8601 시각을 반환한다."""

    return datetime.now(timezone.utc).isoformat()


def _speakeasy_version() -> str:
    """현재 환경에 설치된 Speakeasy 버전을 가져온다."""

    # import 모듈명은 speakeasy지만 PyPI 배포명은 환경에 따라 다를 수 있다.
    for distribution_name in ("speakeasy-emulator", "speakeasy"):
        try:
            return version(distribution_name)
        except PackageNotFoundError:
            continue
    return "unknown"


def _sha256(path: Path) -> str:
    """파일 전체를 한 번에 메모리에 올리지 않고 SHA-256을 계산한다."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _put_worker_message(result_queue: Any, payload: Mapping[str, Any]) -> None:
    """자식 프로세스에서 작고 JSON으로 직렬화 가능한 결과만 전달한다."""

    result_queue.put(json.dumps(dict(payload), ensure_ascii=False, default=str))


def _classify_speakeasy_error(message: str) -> str:
    """Speakeasy 예외 메시지를 공통 상태로 분류한다."""

    lowered = message.casefold()
    if "api" in lowered and ("unsupported" in lowered or "not supported" in lowered):
        return "UNSUPPORTED_API"
    if (
        "not supported" in lowered
        or "not currently supported" in lowered
        or "unsupported" in lowered
    ):
        return "UNSUPPORTED_TARGET"
    if "not a pe" in lowered:
        return "UNSUPPORTED_TARGET"
    return "TOOL_ERROR"


def _json_safe(value: Any, *, depth: int = 0) -> Any:
    """이벤트 세부 정보가 큐 직렬화를 방해하지 않도록 제한적으로 정규화한다."""

    if depth >= 4:
        return str(value)[:MAX_EVENT_VALUE_LENGTH]
    if isinstance(value, Mapping):
        return {
            str(key): _json_safe(item, depth=depth + 1)
            for key, item in list(value.items())[:MAX_EVENTS_PER_CATEGORY]
        }
    if isinstance(value, (list, tuple)):
        return [
            _json_safe(item, depth=depth + 1)
            for item in list(value)[:MAX_EVENTS_PER_CATEGORY]
        ]
    if isinstance(value, str):
        return value[:MAX_EVENT_VALUE_LENGTH]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:MAX_EVENT_VALUE_LENGTH]


def _as_items(value: Any) -> tuple[Any, ...]:
    """report 필드가 단일 객체여도 이벤트 목록처럼 처리한다."""

    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return (value,)


def _append_event(
    events: dict[str, list[Mapping[str, Any]]],
    category: str,
    value: Any,
    entry_point_index: int,
) -> None:
    """이벤트를 카테고리별로 제한된 개수만 저장한다."""

    category_events = events.setdefault(category, [])
    if len(category_events) >= MAX_EVENTS_PER_CATEGORY:
        return

    safe_value = _json_safe(value)
    if isinstance(safe_value, Mapping):
        event = dict(safe_value)
        event["entry_point"] = entry_point_index
    else:
        event = {"entry_point": entry_point_index, "value": safe_value}
    category_events.append(event)


def _run_speakeasy_worker(
    sample_path: str,
    engine_timeout_seconds: int,
    max_instructions: int,
    max_api_count: int,
    emulate_children: bool,
    raw_report_path: str | None,
    result_queue: Any,
) -> None:
    """별도 프로세스에서 Speakeasy를 실행하고 요약 결과만 부모에게 보낸다.

    원본 PE를 개발 프로세스에서 직접 실행하지 않고, Speakeasy의 에뮬레이션만
    제한된 자식 프로세스에서 수행한다. 원본 report가 필요하면 큐로 보내지 않고
    무시된 artifact 경로에 저장하여 결과 큐가 커지는 것을 막는다.
    """

    try:
        from speakeasy import Speakeasy
    except Exception as exc:  # pragma: no cover - 설치 환경에 따라 결정된다.
        _put_worker_message(
            result_queue,
            {"kind": "error", "status": "TOOL_ERROR", "message": str(exc)},
        )
        return

    try:
        emulator = Speakeasy()
        # 엔진 자체 제한을 먼저 적용한다. 부모 프로세스 제한은 이보다 짧게 둔다.
        emulator.config["timeout"] = engine_timeout_seconds
        emulator.config["max_instructions"] = max_instructions
        emulator.config["max_api_count"] = max_api_count

        module = emulator.load_module(path=sample_path)
        emulator.run_module(module, emulate_children=emulate_children)
        report = emulator.get_report() or {}
        summary = _summarize_report(report)
        message: dict[str, Any] = {
            "kind": "summary",
            "observed_apis": list(summary.observed_apis),
            "api_call_counts": dict(summary.api_call_counts),
            "behaviors": list(summary.behaviors),
            "events": {
                category: list(category_events)
                for category, category_events in summary.events.items()
            },
            "warnings": list(summary.warnings),
        }

        if raw_report_path:
            try:
                report_path = Path(raw_report_path)
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(
                    json.dumps(report, ensure_ascii=False, indent=2, default=str),
                    encoding="utf-8",
                )
                message["raw_reference"] = str(report_path)
            except OSError as exc:
                # 분석 자체는 끝났지만 결과 보관에 실패한 경우도 숨기지 않는다.
                message["warnings"] = [
                    *summary.warnings,
                    f"raw_report_error: {exc}",
                ]

        _put_worker_message(result_queue, message)
    except Exception as exc:
        message = str(exc) or exc.__class__.__name__
        _put_worker_message(
            result_queue,
            {
                "kind": "error",
                "status": _classify_speakeasy_error(message),
                "message": message,
            },
        )


def _summarize_report(report: Mapping[str, Any]) -> ReportSummary:
    """Speakeasy 원본 report에서 API·행동·이벤트·경고를 추출한다."""

    api_call_counts: dict[str, int] = {}
    observed_apis: set[str] = set()
    behaviors: set[str] = set()
    events: dict[str, list[Mapping[str, Any]]] = {}
    warnings: list[str] = []

    for entry_point_index, entry_point in enumerate(
        _as_items(report.get("entry_points", []))
    ):
        if not isinstance(entry_point, Mapping):
            continue

        for api_call in _as_items(entry_point.get("apis", [])):
            if not isinstance(api_call, Mapping):
                continue
            api_name = api_call.get("api_name")
            if api_name:
                name = str(api_name)
                observed_apis.add(name)
                api_call_counts[name] = api_call_counts.get(name, 0) + 1
            _append_event(events, "api_calls", api_call, entry_point_index)

        for report_field, behavior_name in _EVENT_FIELDS.items():
            field_items = _as_items(entry_point.get(report_field))
            if not field_items:
                continue
            behaviors.add(behavior_name)
            for event in field_items:
                _append_event(events, report_field, event, entry_point_index)

        if entry_point.get("error"):
            warnings.append(_format_report_error(entry_point["error"]))

    for error in _as_items(report.get("errors", [])):
        warnings.append(_format_report_error(error))

    return ReportSummary(
        observed_apis=tuple(sorted(observed_apis)),
        api_call_counts=dict(sorted(api_call_counts.items())),
        behaviors=tuple(sorted(behaviors)),
        events={
            category: tuple(category_events)
            for category, category_events in sorted(events.items())
        },
        warnings=tuple(warnings),
    )


def _format_report_error(error: Any) -> str:
    """Speakeasy 오류를 레지스터 덤프가 없는 짧은 문자열로 정리한다."""

    if isinstance(error, Mapping):
        error_type = str(error.get("type", "unknown_error"))
        api_name = error.get("api_name")
        return f"{error_type}: {api_name}" if api_name else error_type
    return str(error)


def _status_from_report_warnings(
    warnings: tuple[str, ...],
) -> DynamicAnalysisStatus:
    """report 경고를 분석 상태로 변환한다."""

    joined = "\n".join(warnings).casefold()
    if "unsupported_api" in joined or "unsupported api" in joined:
        return DynamicAnalysisStatus.UNSUPPORTED_API
    if "timeout" in joined:
        return DynamicAnalysisStatus.TIMEOUT
    if warnings:
        # 원인을 알 수 없는 경고를 성공으로 숨기면 후속 라우터가 잘못 판단한다.
        return DynamicAnalysisStatus.TOOL_ERROR
    return DynamicAnalysisStatus.SUCCESS


def _close_queue(result_queue: Any) -> None:
    """multiprocessing Queue를 예외 상황에서도 정리한다."""

    try:
        result_queue.close()
    finally:
        result_queue.join_thread()


class SpeakeasyAnalyzer:
    """PE 파일을 Speakeasy로 분석하고 공통 Evidence 결과를 반환한다."""

    source = "SPEAKEASY"
    category = "DYNAMIC_ANALYSIS"

    def __init__(
        self,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
        max_api_count: int = DEFAULT_MAX_API_COUNT,
        emulate_children: bool = False,
        include_raw_report: bool = False,
        raw_report_directory: str | Path = "artifacts/speakeasy",
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_instructions <= 0:
            raise ValueError("max_instructions must be positive")
        if max_file_size_bytes <= 0:
            raise ValueError("max_file_size_bytes must be positive")
        if max_api_count <= 0:
            raise ValueError("max_api_count must be positive")

        self.timeout_seconds = timeout_seconds
        self.max_instructions = max_instructions
        self.max_file_size_bytes = max_file_size_bytes
        self.max_api_count = max_api_count
        self.emulate_children = emulate_children
        self.include_raw_report = include_raw_report
        self.raw_report_directory = Path(raw_report_directory)
        self.tool_version = _speakeasy_version()

    def analyze(self, sample_path: str | Path) -> DynamicAnalysisResult:
        """PE 파일을 분석하고 성공·부분 결과·실패 상태를 구분해 반환한다."""

        path = Path(sample_path)
        evidence_id = _new_evidence_id()

        if not path.is_file():
            return self._failure(
                evidence_id=evidence_id,
                status=DynamicAnalysisStatus.INVALID_INPUT,
                summary="분석 대상 파일을 찾을 수 없습니다.",
                errors=(str(path),),
            )

        try:
            file_size = path.stat().st_size
        except OSError as exc:
            return self._failure(
                evidence_id=evidence_id,
                status=DynamicAnalysisStatus.INVALID_INPUT,
                summary="분석 대상 파일 정보를 읽을 수 없습니다.",
                errors=(str(exc),),
            )

        if file_size > self.max_file_size_bytes:
            return self._failure(
                evidence_id=evidence_id,
                status=DynamicAnalysisStatus.FILE_TOO_LARGE,
                summary="분석 대상 파일이 허용 크기를 초과했습니다.",
                errors=(f"size={file_size}, limit={self.max_file_size_bytes}",),
            )

        try:
            with path.open("rb") as stream:
                magic = stream.read(2)
            if magic != b"MZ":
                return self._failure(
                    evidence_id=evidence_id,
                    status=DynamicAnalysisStatus.UNSUPPORTED_TARGET,
                    summary="PE 파일이 아니므로 Speakeasy 분석을 수행하지 않았습니다.",
                )
            sha256 = _sha256(path)
        except OSError as exc:
            return self._failure(
                evidence_id=evidence_id,
                status=DynamicAnalysisStatus.INVALID_INPUT,
                summary="분석 대상 파일을 읽을 수 없습니다.",
                errors=(str(exc),),
            )

        started_at = _utc_now()
        start = time.perf_counter()
        engine_timeout_seconds = max(1, int(self.timeout_seconds) - 1)
        metadata = {
            "file_size_bytes": file_size,
            "timeout_seconds": self.timeout_seconds,
            "engine_timeout_seconds": engine_timeout_seconds,
            "max_instructions": self.max_instructions,
            "max_api_count": self.max_api_count,
            "max_file_size_bytes": self.max_file_size_bytes,
            "emulate_children": self.emulate_children,
        }
        raw_report_path = (
            str(self.raw_report_directory / f"{sha256}.json")
            if self.include_raw_report
            else None
        )

        context = multiprocessing.get_context("spawn")
        result_queue = context.Queue(maxsize=1)
        process = context.Process(
            target=_run_speakeasy_worker,
            args=(
                str(path),
                engine_timeout_seconds,
                self.max_instructions,
                self.max_api_count,
                self.emulate_children,
                raw_report_path,
                result_queue,
            ),
        )

        try:
            process.start()
        except Exception as exc:
            _close_queue(result_queue)
            return self._failure(
                evidence_id=evidence_id,
                sha256=sha256,
                status=DynamicAnalysisStatus.TOOL_ERROR,
                summary="Speakeasy 프로세스를 시작하지 못했습니다.",
                analysis_time_ms=int((time.perf_counter() - start) * 1000),
                errors=(str(exc),),
                metadata=metadata,
                tool_version=self.tool_version,
                started_at=started_at,
                completed_at=_utc_now(),
            )

        process.join(self.timeout_seconds)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        if process.is_alive():
            process.terminate()
            process.join(2)
            if process.is_alive():
                # terminate()이 Windows에서 즉시 끝내지 못하는 경우의 마지막 안전장치다.
                process.kill()
                process.join(2)
            _close_queue(result_queue)
            return self._failure(
                evidence_id=evidence_id,
                sha256=sha256,
                status=DynamicAnalysisStatus.TIMEOUT,
                summary="Speakeasy 분석이 제한 시간 안에 끝나지 않았습니다.",
                analysis_time_ms=elapsed_ms,
                metadata=metadata,
                tool_version=self.tool_version,
                started_at=started_at,
                completed_at=_utc_now(),
            )

        try:
            raw_message = result_queue.get(timeout=2)
        except queue.Empty:
            return self._failure(
                evidence_id=evidence_id,
                sha256=sha256,
                status=DynamicAnalysisStatus.TOOL_ERROR,
                summary="Speakeasy 프로세스가 결과를 반환하지 않았습니다.",
                analysis_time_ms=elapsed_ms,
                errors=(f"process_exit_code={process.exitcode}",),
                metadata=metadata,
                tool_version=self.tool_version,
                started_at=started_at,
                completed_at=_utc_now(),
            )
        finally:
            _close_queue(result_queue)

        try:
            message = json.loads(raw_message)
        except (TypeError, json.JSONDecodeError) as exc:
            return self._failure(
                evidence_id=evidence_id,
                sha256=sha256,
                status=DynamicAnalysisStatus.TOOL_ERROR,
                summary="Speakeasy 결과를 JSON으로 해석하지 못했습니다.",
                analysis_time_ms=elapsed_ms,
                errors=(str(exc),),
                metadata=metadata,
                tool_version=self.tool_version,
                started_at=started_at,
                completed_at=_utc_now(),
            )

        if message.get("kind") == "error":
            status_name = message.get("status", DynamicAnalysisStatus.TOOL_ERROR.value)
            try:
                status = DynamicAnalysisStatus(status_name)
            except ValueError:
                status = DynamicAnalysisStatus.TOOL_ERROR
            return self._failure(
                evidence_id=evidence_id,
                sha256=sha256,
                status=status,
                summary="Speakeasy 분석을 완료하지 못했습니다.",
                analysis_time_ms=elapsed_ms,
                errors=(str(message.get("message", "알 수 없는 오류")),),
                metadata=metadata,
                tool_version=self.tool_version,
                started_at=started_at,
                completed_at=_utc_now(),
            )

        if message.get("kind") != "summary":
            return self._failure(
                evidence_id=evidence_id,
                sha256=sha256,
                status=DynamicAnalysisStatus.TOOL_ERROR,
                summary="Speakeasy 결과 형식이 올바르지 않습니다.",
                analysis_time_ms=elapsed_ms,
                metadata=metadata,
                tool_version=self.tool_version,
                started_at=started_at,
                completed_at=_utc_now(),
            )

        observed_apis = tuple(str(value) for value in message.get("observed_apis", []))
        api_call_counts = {
            str(name): int(count)
            for name, count in (message.get("api_call_counts") or {}).items()
        }
        behaviors = tuple(str(value) for value in message.get("behaviors", []))
        events = {
            str(category): tuple(
                dict(event) for event in category_events if isinstance(event, Mapping)
            )
            for category, category_events in (message.get("events") or {}).items()
            if isinstance(category_events, list)
        }
        warnings = tuple(str(value) for value in message.get("warnings", []))
        status = _status_from_report_warnings(warnings)
        if status is DynamicAnalysisStatus.TIMEOUT:
            summary = (
                "Speakeasy 분석 제한에 도달했지만 부분 결과를 반환했습니다: "
                f"API {len(observed_apis)}종, 행동 그룹 {len(behaviors)}개"
            )
        elif status is DynamicAnalysisStatus.UNSUPPORTED_API:
            summary = (
                "지원되지 않는 API에서 분석이 중단됐지만 부분 결과를 반환했습니다: "
                f"API {len(observed_apis)}종, 행동 그룹 {len(behaviors)}개"
            )
        elif status is DynamicAnalysisStatus.TOOL_ERROR:
            summary = (
                "Speakeasy report에 처리 오류가 포함되어 부분 결과를 반환했습니다: "
                f"API {len(observed_apis)}종, 행동 그룹 {len(behaviors)}개"
            )
        else:
            summary = (
                f"Speakeasy 분석 완료: API {len(observed_apis)}종, "
                f"행동 그룹 {len(behaviors)}개"
            )

        return DynamicAnalysisResult(
            evidence_id=evidence_id,
            sha256=sha256,
            source=self.source,
            category=self.category,
            status=status,
            summary=summary,
            raw_reference=(
                str(message["raw_reference"])
                if message.get("raw_reference")
                else None
            ),
            observed_apis=observed_apis,
            api_call_counts=api_call_counts,
            behaviors=behaviors,
            events=events,
            analysis_time_ms=elapsed_ms,
            warnings=warnings,
            tool_version=self.tool_version,
            started_at=started_at,
            completed_at=_utc_now(),
            metadata=metadata,
        )

    def _failure(
        self,
        *,
        evidence_id: str,
        status: DynamicAnalysisStatus,
        summary: str,
        sha256: str = "",
        analysis_time_ms: int | None = None,
        errors: tuple[str, ...] = (),
        metadata: Mapping[str, Any] | None = None,
        tool_version: str | None = None,
        started_at: str | None = None,
        completed_at: str | None = None,
    ) -> DynamicAnalysisResult:
        """실패 원인과 구분 상태를 보존하는 결과 객체를 만든다."""

        return DynamicAnalysisResult(
            evidence_id=evidence_id,
            sha256=sha256,
            source=self.source,
            category=self.category,
            status=status,
            summary=summary,
            analysis_time_ms=analysis_time_ms,
            errors=errors,
            tool_version=tool_version,
            started_at=started_at,
            completed_at=completed_at,
            metadata=dict(metadata or {}),
        )
