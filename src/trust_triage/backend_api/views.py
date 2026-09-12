"""DB/도구 결과에서 외부에 보여줄 필드만 선택한다. 내부 저장 위치는 반환하지 않는다."""

from __future__ import annotations

from typing import Any

from .repository import AnalysisRecord
from .schemas import (
    AnalysisAccepted,
    AnalysisProgress,
    AnalysisResponse,
    DeepAnalysisResponse,
    FinalAssessment,
    InitialResult,
    ReviewResponse,
    TriageResponse,
    XAIResponse,
)

_NO_DEEP = {
    "capa": "NOT_REQUIRED",
    "floss": "NOT_REQUIRED",
    "speakeasy": "NOT_REQUIRED",
    "cape": "NOT_REQUIRED",
}


def identity(record: AnalysisRecord) -> dict[str, Any]:
    return {
        key: getattr(record, key)
        for key in ("analysis_id", "batch_id", "sha256", "created_at")
    }


def _error(value: Any) -> dict[str, Any] | None:
    if not value:
        return None
    # retry_count/next_retry_at는 내부 스케줄 정보이며 공개 오류는 안정된 네 필드만 쓴다.
    return {
        "code": value.get("code", "ANALYSIS_ERROR"),
        "message": value.get("message", "분석에 실패했습니다."),
        "stage": value.get("stage"),
        "retryable": bool(value.get("retryable", False)),
    }


def accepted(record: AnalysisRecord) -> AnalysisAccepted:
    return AnalysisAccepted(
        **identity(record), status=record.status, duplicate_of=record.duplicate_of
    )


def progress(record: AnalysisRecord) -> AnalysisProgress:
    return AnalysisProgress(
        **identity(record),
        status=record.status,
        current_stage=record.current_stage,
        updated_at=record.updated_at,
        completed_at=record.completed_at,
        error=_error(record.error),
    )


def triage(record: AnalysisRecord) -> TriageResponse:
    value = (
        InitialResult.model_validate(record.initial_result)
        if record.initial_result
        else None
    )
    return TriageResponse(
        **identity(record),
        status="COMPLETED" if value else "FAILED" if record.terminal else record.status,
        **(
            {
                key: getattr(value, key)
                for key in (
                    "prediction",
                    "risk_signals",
                    "initial_verdict",
                    "route",
                    "reason",
                    "triggered_signals",
                    "feature_metadata",
                )
            }
            if value
            else {}
        ),
    )


def xai(record: AnalysisRecord) -> XAIResponse:
    value = (
        InitialResult.model_validate(record.initial_result).model_dump(mode="json")
        if record.initial_result
        else {}
    )
    status = {
        "SUCCESS": "COMPLETED",
        "FAILED": "FAILED",
        "NOT_REQUIRED": "NOT_REQUIRED",
    }.get(value.get("xai_status"), "FAILED" if record.terminal else record.status)
    return XAIResponse(
        **identity(record),
        status=status,
        top_features=value.get("top_features", []),
        error=_error(value.get("xai_error")),
    )


def _tool_status(value: Any) -> str:
    if value in {"SUCCESS", "COMPLETE", "COMPLETED"}:
        return "COMPLETED"
    if value in {"QUEUED", "RUNNING", "NOT_REQUIRED"}:
        return value
    return "FAILED"


def _floss_strings(value: Any) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {
        key: [] for key in ("static", "stack", "tight", "decoded")
    }
    if isinstance(value, list):
        for row in value:
            if not isinstance(row, dict):
                continue
            kind = str(row.get("string_type", "")).lower().removesuffix("_strings")
            if kind in grouped and isinstance(row.get("string"), str):
                grouped[kind].append(row["string"])
    elif isinstance(value, dict):
        # Also accept a grouped tool report, projecting only string values so
        # raw metadata/provenance fields cannot enter the public result.
        for kind, collected in grouped.items():
            strings = value.get(kind, value.get(f"{kind}_strings", []))
            if not isinstance(strings, list):
                continue
            for item in strings:
                text = item.get("string") if isinstance(item, dict) else item
                if isinstance(text, str):
                    collected.append(text)
    return grouped


def _evidence_items(snapshot: dict[str, Any]) -> tuple[list[dict], list[dict]]:
    grouped: dict[str, dict[str, Any]] = {}
    details = []
    for item in snapshot.get("evidence", []):
        detail = {
            key: item[key]
            for key in (
                "evidence_id",
                "sha256",
                "source",
                "category",
                "severity",
                "reliability",
                "summary",
                "status",
                "attack_techniques",
            )
            if key in item
        }
        details.append(detail)
        for technique in item.get("attack_techniques", []):
            technique_id = technique.get("technique_id")
            if not technique_id:
                continue
            entry = grouped.setdefault(
                technique_id,
                {
                    "technique_id": technique_id,
                    "technique_name": technique.get("technique_name", technique_id),
                    "sources": [],
                    "summary": "",
                    "evidence_ids": [],
                },
            )
            if item["source"] not in entry["sources"]:
                entry["sources"].append(item["source"])
            if item["evidence_id"] not in entry["evidence_ids"]:
                entry["evidence_ids"].append(item["evidence_id"])
                entry["summary"] = (
                    entry["summary"] + " " + item.get("summary", "")
                ).strip()[:2000]
    return list(grouped.values()), details


def deep_analysis(record: AnalysisRecord) -> DeepAnalysisResponse:
    snapshot = dict(record.deep_result or {})
    initial = record.initial_result or {}
    needed = initial.get("initial_verdict") == "HIGH_RISK_UNCERTAIN"
    states = dict(_NO_DEEP)
    if not initial and not record.terminal:
        states = {key: "QUEUED" for key in ("capa", "floss", "speakeasy")} | {
            "cape": "NOT_REQUIRED"
        }
    elif needed:
        states.update(capa="QUEUED", floss="QUEUED", speakeasy="QUEUED")
    for tool, status in snapshot.get("tool_statuses", {}).items():
        if tool.lower() in states:
            states[tool.lower()] = _tool_status(status)
    if snapshot.get("status") in {"COMPLETED", "FAILED"}:
        for tool in ("capa", "floss", "speakeasy"):
            if tool.upper() not in snapshot.get("tool_statuses", {}):
                states[tool] = "NOT_REQUIRED"
    interrupted = (
        record.status == "FAILED"
        and needed
        and snapshot.get("status") not in {"COMPLETED", "FAILED"}
    )
    if interrupted:
        observed_tools = {name.lower() for name in snapshot.get("tool_statuses", {})}
        for tool, state in states.items():
            # The linked worker may still run after the backend stops waiting.
            # Keep explicitly observed tool states; only remove placeholders
            # for tools that were never observed or selected before termination.
            if tool not in observed_tools and state == "QUEUED":
                states[tool] = "NOT_REQUIRED"
    static = snapshot.get("static_results", {})
    capa_raw, floss_raw = static.get("CAPA"), static.get("FLOSS")
    capa = None
    if capa_raw:
        capa = {
            "analysis_id": record.analysis_id,
            "tool": "CAPA",
            "status": states["capa"],
            "capabilities": [
                {
                    "name": row.get("rule_name", ""),
                    "namespace": row.get("namespace", ""),
                }
                for row in capa_raw.get("capabilities", [])
            ],
            "raw_result_location": None,
        }
    floss = None
    if floss_raw:
        strings = _floss_strings(floss_raw.get("strings", []))
        floss = {
            "analysis_id": record.analysis_id,
            "tool": "FLOSS",
            "status": states["floss"],
            "strings": strings,
        }
    worker = snapshot.get("speakeasy_result")
    speakeasy = None
    if worker:
        speakeasy = {
            "analysis_id": record.analysis_id,
            "tool": "SPEAKEASY",
            "status": states["speakeasy"],
            "tool_status": worker.get("tool_status"),
            "behavior": worker.get("behavior"),
            "error": (
                {
                    "code": worker["error"].get("code", "SPEAKEASY_FAILED"),
                    "message": "Speakeasy 단계가 실패했습니다. 상세 도구 상태를 확인해주세요.",
                }
                if worker.get("error")
                else None
            ),
        }
    evidence, evidence_details = _evidence_items(snapshot)
    result = snapshot.get("result") or {}
    llm = result.get("llm_interpretation") or {}
    summary = None
    if llm.get("status") == "SUCCESS":
        supporting = set(llm.get("supporting_evidence_ids", []))
        summary = {
            "summary": llm.get("summary", ""),
            "suspicious_behaviors": [
                item.get("summary", "")
                for item in snapshot.get("evidence", [])
                if item.get("evidence_id") in supporting
            ],
            "analyst_notes": "LLM 해석은 참고 자료이며 최종 판정은 전문가가 검토합니다.",
        }
    status = snapshot.get("status") or (
        "NOT_REQUIRED"
        if initial and not needed
        else "FAILED"
        if record.terminal
        else "QUEUED"
    )
    if interrupted:
        status = "FAILED"
    elif status == "QUEUED" and record.phase == "WAITING_DEEP" and record.claimed:
        status = "RUNNING"
    detail = {}
    for tool, state in snapshot.get("tool_statuses", {}).items():
        raw = static.get(tool, {})
        detail[tool.lower()] = {
            "tool_status": state,
            "version": raw.get("capa_version", raw.get("floss_version")),
            "elapsed_ms": raw.get("elapsed_ms"),
        }
        if tool.upper() == "SPEAKEASY" and worker:
            analysis = worker.get("analysis") or {}
            detail[tool.lower()].update(
                version=analysis.get("tool_version"),
                elapsed_ms=analysis.get("analysis_time_ms"),
            )
    return DeepAnalysisResponse(
        **identity(record),
        status=status,
        deep_analysis_status=states,
        tool_details=detail,
        capa=capa,
        floss=floss,
        speakeasy=speakeasy,
        evidence=evidence,
        evidence_details=evidence_details,
        llm_summary=summary,
        llm_status=llm.get("status"),
        error=_error(record.error) if status == "FAILED" else None,
    )


def analysis(record: AnalysisRecord) -> AnalysisResponse:
    initial, deep, status = triage(record), deep_analysis(record), progress(record)
    final = (
        FinalAssessment.model_validate(record.final_assessment)
        if record.final_assessment
        else None
    )
    approval = "PENDING"
    if record.analyst_final_verdict:
        approval = (
            "APPROVED"
            if final and record.analyst_final_verdict == final.final_verdict
            else "MODIFIED"
        )
    elif final and not final.requires_human_review and record.review_revision == 0:
        approval = "AUTO_POLICY"
    return AnalysisResponse(
        **status.model_dump(),
        filename=record.filename,
        size_bytes=record.size_bytes,
        duplicate_of=record.duplicate_of,
        prediction=initial.prediction,
        risk_signals=initial.risk_signals,
        initial_verdict=initial.initial_verdict,
        route=initial.route,
        reason=initial.reason,
        triggered_signals=initial.triggered_signals,
        top_features=xai(record).top_features,
        deep_analysis_status=deep.deep_analysis_status,
        evidence=deep.evidence,
        llm_summary=deep.llm_summary,
        final_verdict=final.final_verdict if final else None,
        final_assessment=final,
        analyst_final_verdict=record.analyst_final_verdict,
        approval_status=approval,
        review_revision=record.review_revision,
    )


def review(value: dict[str, Any]) -> ReviewResponse:
    return ReviewResponse(**{key: value[key] for key in ReviewResponse.model_fields})
