"""Worker 결과 봉투를 검증하고 기존 Speakeasy 정규화 입력으로 변환한다."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..dynamic_analysis.models import (
    DYNAMIC_ANALYSIS_SCHEMA_VERSION,
    DynamicAnalysisStatus,
)
from ..speakeasy_worker.models import RESULT_SCHEMA_VERSION, JobRecord
from ..storage import ArtifactReference
from .checkpoints import json_snapshot
from .service_models import DeepAnalysisRequest


def validate_worker_record(
    request: DeepAnalysisRequest, record: JobRecord
) -> dict[str, Any]:
    if not record.job.same_input(request.worker_job) or not record.status.terminal:
        raise ValueError("Worker job does not match the pending deep-analysis request")
    if record.result is None or record.result.get("status") != record.status.value:
        raise ValueError("Worker status and saved result do not match")
    payload = json_snapshot(dict(record.result))
    analysis_from_worker(request, payload)
    return payload


def analysis_from_worker(
    request: DeepAnalysisRequest, value: Mapping[str, Any]
) -> dict[str, Any]:
    """상세 도구 상태와 부분 결과를 보존하되 실패를 성공 증거로 바꾸지 않는다."""

    payload = json_snapshot(dict(value))
    if (
        payload.get("schema_version") != RESULT_SCHEMA_VERSION
        or payload.get("analysis_id") != request.analysis_id
        or payload.get("sha256") != request.sha256
        or payload.get("tool") != "SPEAKEASY"
        or payload.get("status") not in {"COMPLETED", "FAILED"}
    ):
        raise ValueError("Worker result identity, schema or status is invalid")
    _validate_artifact(request, payload)
    behavior = payload.get("behavior")
    categories = {"processes", "api_calls", "files", "registry", "network"}
    if not isinstance(behavior, dict) or set(behavior) != categories:
        raise ValueError("Worker result has invalid behavior categories")
    if any(
        not isinstance(events, list)
        or any(not isinstance(event, dict) for event in events)
        for events in behavior.values()
    ):
        raise ValueError("Worker behavior categories must contain arrays of objects")
    success = payload["status"] == "COMPLETED"
    error = payload.get("error")
    if success:
        if error is not None:
            raise ValueError("Completed Worker result cannot contain an error")
    elif (
        not isinstance(error, dict)
        or not isinstance(error.get("code"), str)
        or not error["code"]
        or not isinstance(error.get("message"), str)
    ):
        raise ValueError("Failed Worker result must contain an explicit error")

    inner = payload.get("analysis")
    if inner is None:
        if success or payload.get("tool_status") is not None or any(behavior.values()):
            raise ValueError(
                "Worker result without analysis cannot contain successful observations"
            )
        return {
            "sha256": request.sha256,
            "status": "TOOL_ERROR",
            "errors": [f"{error['code']}: {error['message']}"],
        }
    if not isinstance(inner, dict):
        raise ValueError("Worker analysis must be an object or null")  # noqa: TRY004 - invalid serialized contract
    status = inner.get("status")
    if (
        inner.get("schema_version") != DYNAMIC_ANALYSIS_SCHEMA_VERSION
        or inner.get("source") != "SPEAKEASY"
        or status not in {item.value for item in DynamicAnalysisStatus}
        or payload.get("tool_status") != status
        or (inner.get("sha256") and inner["sha256"] != request.sha256)
        or (status == "SUCCESS" and inner.get("sha256") != request.sha256)
        or inner.get("raw_report") is not None
    ):
        raise ValueError("Nested Speakeasy analysis does not match the Worker result")
    if success and status != "SUCCESS":
        raise ValueError("Completed Worker result requires successful tool analysis")
    if not success and status == "SUCCESS" and error["code"] != "JOB_TIMEOUT":
        raise ValueError("Failed Worker result contradicts successful tool analysis")
    for name in ("observed_apis", "behaviors", "warnings", "errors"):
        values = inner.get(name)
        if not isinstance(values, list) or any(
            not isinstance(item, str) for item in values
        ):
            raise ValueError(f"Speakeasy {name} must be a string array")
    events = inner.get("events")
    if not isinstance(events, dict) or any(
        not isinstance(items, list) or any(not isinstance(item, dict) for item in items)
        for items in events.values()
    ):
        raise ValueError("Speakeasy events must contain arrays of event objects")
    if not success:
        # JOB_TIMEOUT은 엔진 SUCCESS 직후 Worker 전체 기한이 지난 경우에도 생긴다.
        # 원래 봉투는 DB에 보존하고, 후속 정규화에는 성공으로 전달하지 않는다.
        if status == "SUCCESS":
            inner["status"] = "TIMEOUT"
        inner["errors"] = [*inner["errors"], f"{error['code']}: {error['message']}"]
    return inner


def _validate_artifact(
    request: DeepAnalysisRequest, payload: Mapping[str, Any]
) -> None:
    """A Worker report remains attached to the same sample, request and execution."""
    value, error = payload.get("artifact"), payload.get("artifact_error")
    if error is not None and (
        not isinstance(error, dict)
        or not isinstance(error.get("code"), str)
        or not error["code"]
        or not isinstance(error.get("message"), str)
    ):
        raise ValueError("Worker artifact error must contain a code and message")
    if value is None:
        return  # Older results or a failed supplementary report archive.
    if not isinstance(value, dict) or error is not None:
        raise ValueError("Worker artifact reference conflicts with its archive status")
    try:
        reference = ArtifactReference(**value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Worker artifact reference is invalid") from exc
    if (
        reference.analysis_id != request.analysis_id
        or reference.sha256 != request.sha256
        or reference.tool != "SPEAKEASY"
        or reference.tool_run_id != payload.get("tool_run_id")
    ):
        raise ValueError("Worker artifact belongs to another analysis or execution")
