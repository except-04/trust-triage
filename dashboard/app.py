import inspect
import re
import time
from collections import Counter
from datetime import datetime
from html import escape

import api_client
import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
from api_client import ApiError

# 진행 상황 패널의 자동 갱신 주기. 전체 app rerun이 아니라 fragment만 다시 돈다.
POLL_INTERVAL_SECONDS = 2
# 백엔드가 응답은 하지만 상태가 끝나지 않는 경우까지 대비한 상한. 무한 폴링 방지용.
POLL_TIMEOUT_SECONDS = 600
# 더 이상 조회할 필요가 없는 상태.
TERMINAL_STATUSES = ("COMPLETED", "FAILED")
# 업로드 항목을 전송 경로로 나누는 기준. 내용 검증은 백엔드가 한다.
PE_EXTENSIONS = (".exe", ".dll")
ARCHIVE_EXTENSIONS = (".zip",)
# /batches 한 번에 보낼 수 있는 PE 개수. 백엔드 기본값(BACKEND_MAX_BATCH_FILES)을
# 반영한 사전 안내용이며, 최종 판단은 백엔드가 한다.
MAX_BATCH_FILES = 10
# 해시 검색 입력 검증. 백엔드 GET /analyses 의 sha256 필터와 같은 정규식이라
# 형식이 어긋난 입력은 422를 받기 전에 프론트에서 막는다.
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
# 한 번에 가져올 이력 건수. 백엔드 limit 상한은 100이다.
HASH_SEARCH_LIMIT = 20
# 상세 화면이 서식 문자열에서 직접 인덱싱하는 값들. 하나라도 비어 있으면
# 렌더 도중 TypeError가 나므로 상세 전환 전에 존재를 확인한다.
DETAIL_REQUIRED_FIELDS = (
    "route",
    "raw_probability",
    "calibrated_probability",
    "disagreement",
    "ood_score",
    "difficulty_score",
)
# 검색이 쓰는 session_state 키. 접수/폴링 키와 겹치지 않게 한곳에 모아 둔다.
HASH_SEARCH_KEYS = ("hash_search", "hash_search_error", "hash_search_selector")
DETAIL_COLUMN_GAP = "medium"
DETAIL_CARD_GAP = "small"
SPEAKEASY_PREVIEW_LIMIT = 10
# Deep Analysis 검색에서 일치한 칸의 색. 다크 모드에서는 표 전체에 색 반전 필터
# (invert + hue-rotate)가 걸리므로, 반전된 뒤 남색 배경(#21458f 근처)과 밝은 파란
# 글자(#dbeaff)가 되도록 고른 원래 색이다. 라이트 모드에서는 연한 파랑으로 보인다.
DEEP_SEARCH_HIGHLIGHT = "background-color: #9cc0ff; color: #000f63; font-weight: 600"
# 분석가가 판정을 옮길 수 있는 그룹과, 그룹별로 백엔드에 저장하는 analyst_final_verdict.
# 백엔드에는 "검토 필요" 값이 없으므로 Needs Review는 보류(null)로 저장한다.
REVIEW_GROUPS = ("needs_review", "auto_malicious", "auto_benign")
REVIEW_VERDICT_BY_GROUP = {
    "needs_review": None,
    "auto_malicious": "MALICIOUS",
    "auto_benign": "BENIGN",
}
REVIEW_GROUP_BY_VERDICT = {
    verdict: group for group, verdict in REVIEW_VERDICT_BY_GROUP.items()
}
# 백엔드 ReviewRequest 와 같은 제한. 어긋나면 422를 받기 전에 프론트에서 막는다.
REVIEWER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
REVIEW_NOTES_MAX = 4000
# 세 그룹 표에 공통으로 붙는 수정 여부 열 이름.
REVIEW_COLUMN = "Analyst Review"


def reset_analysis_result():
    """Clear stale batch results whenever the selected uploads change."""
    st.session_state.analysis_result = None
    st.session_state.pop("batch_data", None)
    st.session_state.pop("batch_results", None)
    st.session_state.pop("batch_id", None)
    st.session_state.pop("batch_ids", None)
    st.session_state.pop("selected_analysis_id", None)
    st.session_state.pop("batch_group", None)
    st.session_state.pop("group_analysis_selector", None)
    st.session_state.pop("poll_started_at", None)
    st.session_state.pop("poll_timed_out", None)
    st.session_state.pop("intake_receipt", None)
    st.session_state.pop("batch_filter_query", None)
    st.session_state.pop("deep_filter_query", None)
    st.session_state.pop("pending_batch_group", None)


def reset_analysis_session():
    """Return the console to its upload state for a new batch."""
    reset_analysis_result()
    st.session_state.pop("batch_file_uploader", None)


def select_analysis_result(widget_key="selected_analysis_id"):
    """Bind the selected batch row to the existing detail view."""
    selected_id = st.session_state.get(widget_key)
    selected = find_batch_analysis(selected_id)
    if selected is not None:
        st.session_state.selected_analysis_id = selected_id
        st.session_state.analysis_result = selected


def verdict_badge_markup(verdict):
    labels = {
        "MALICIOUS": "악성 (Malicious)",
        "BENIGN": "정상 (Benign)",
        "UNCERTAIN": "판정 보류 (Uncertain)",
        "AUTO_MALICIOUS": "AUTO MALICIOUS",
        "AUTO_BENIGN": "AUTO BENIGN",
        "HIGH_RISK_UNCERTAIN": "HIGH-RISK UNCERTAIN",
        "Malicious": "악성 (Malicious)",
        "Benign": "정상 (Benign)",
        "Analyst Review": "분석가 검토 (Analyst Review)",
        "High-Risk Uncertain": "HIGH-RISK UNCERTAIN",
        "Pending": "분석 진행 중 (Pending)",
    }
    label = labels.get(verdict, verdict)

    if verdict in {"MALICIOUS", "AUTO_MALICIOUS", "Malicious"}:
        badge_class = "badge-danger"
    elif verdict in {"BENIGN", "AUTO_BENIGN", "Benign"}:
        badge_class = "badge-success"
    elif verdict in {
        "UNCERTAIN",
        "HIGH_RISK_UNCERTAIN",
        "Analyst Review",
        "High-Risk Uncertain",
    }:
        badge_class = "badge-warning"
    else:
        badge_class = "badge-neutral"

    return f'<span class="status-badge {badge_class}">{escape(label)}</span>'


def route_display_name(route):
    labels = {
        "DEEP_ANALYSIS": "Deep Analysis",
        "FINAL": "Final",
    }
    return labels.get(route, route)


def route_badge_markup(route):
    label = route_display_name(route)

    if route in {"DEEP_ANALYSIS", "Deep Analysis"}:
        badge_class = "badge-info"
    elif route == "Analyst Review":
        badge_class = "badge-warning"
    else:
        badge_class = "badge-neutral"

    return f'<span class="status-badge {badge_class}">{escape(label)}</span>'


def pipeline_state_markup(status):
    if status in {"COMPLETED", "Completed"}:
        label = "✓ 완료"
        status_class = "pipeline-complete"
    elif status in {"NOT_REQUIRED", "Not Required"}:
        label = "○ 미실행"
        status_class = "pipeline-skipped"
    elif status == "FAILED":
        label = "실패"
        status_class = "pipeline-failed"
    elif status == "RUNNING":
        label = "진행 중"
        status_class = "pipeline-running"
    elif status == "QUEUED":
        label = "대기"
        status_class = "pipeline-skipped"
    else:
        label = escape(status)
        status_class = "badge-info"

    return f'<span class="pipeline-state {status_class}">{label}</span>'


def truncate_hash(value, prefix=12, suffix=8):
    if "..." in value or len(value) <= prefix + suffix + 3:
        return value
    return f"{value[:prefix]}...{value[-suffix:]}"


def format_file_size(size_bytes):
    if size_bytes >= 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / 1024:.1f} KB"


def file_kind(filename):
    """업로드 항목을 전송 경로로 분류한다.

    확장자만 본다. ZIP 해제와 PE 유효성은 백엔드가 판정하므로 프론트는
    어느 엔드포인트로 보낼지만 결정한다.
    """
    lowered = (filename or "").lower()
    if lowered.endswith(ARCHIVE_EXTENSIONS):
        return "ZIP"
    if lowered.endswith(PE_EXTENSIONS):
        return "PE"
    return "OTHER"


def uploaded_descriptors(uploaded_files):
    """Normalize Streamlit uploads before handing them to the transport layer."""
    return [
        {
            "filename": uploaded_file.name,
            "size": uploaded_file.size,
            "content": uploaded_file.getvalue(),
            "kind": file_kind(uploaded_file.name),
        }
        for uploaded_file in (uploaded_files or [])
    ]


def is_ood_detected(result):
    if result.get("ood_score") is not None:
        return result["ood_score"] < 0
    return bool(result.get("ood", False))


def difficulty_label(score):
    if score is None:
        return "Unknown"
    if score <= 3:
        return "Low"
    if score <= 6:
        return "Medium"
    return "High"


def deep_analysis_status_markup(statuses):
    tools = (
        ("CAPA", "capa"),
        ("FLOSS", "floss"),
        ("Speakeasy", "speakeasy"),
    )
    # 알약들을 한 묶음으로 감싸야 어디에 놓이든 사이 간격(gap)이 생긴다.
    items = "".join(
        (
            '<span class="deep-status-item">'
            f"<strong>{tool_name}</strong> · {escape(statuses.get(key, 'NOT_REQUIRED'))}"
            "</span>"
        )
        for tool_name, key in tools
    )
    return f'<span class="deep-status-list">{items}</span>'


def shap_feature_label(feature):
    """차트 y축 라벨. 백엔드가 준 표시용 이름을 우선 쓰고 없으면 raw 이름을 쓴다.

    display_name은 선택 필드라 이 필드가 생기기 전 기록이나 목업에는 없다.
    feature_name은 식별자이므로 그대로 두고 라벨만 바꾼다.
    """
    return feature.get("display_name") or feature.get(
        "feature_name",
        feature.get("feature", feature.get("SHAP 특성", "Unknown")),
    )


def render_shap_chart(target, features):
    chart_features = features[:5]
    names = [shap_feature_label(feature) for feature in chart_features]
    values = [
        float(
            feature.get(
                "shap_value",
                feature.get("value", feature.get("영향도", 0)),
            )
        )
        for feature in chart_features
    ]
    theme = DARK_THEME if st.session_state.get("dark_mode") else LIGHT_THEME
    colors = [
        theme["chart-malicious"] if value >= 0 else theme["chart-benign"]
        for value in values
    ]
    limit = max((abs(value) for value in values), default=0.1) * 1.22

    # 설명 가능성 칸(약 70%)에서 옆 분석 파이프라인 카드와 높이가 비슷해지는 비율.
    figure, axis = plt.subplots(figsize=(6.2, 1.6))
    positions = list(range(len(names)))
    axis.barh(positions, values, color=colors, height=0.55)
    axis.axvline(0, color=theme["text-muted"], linewidth=1.1, zorder=0)
    axis.set_xlim(-limit, limit)
    axis.set_yticks(positions, labels=names)
    axis.invert_yaxis()
    axis.xaxis.grid(True, color=theme["border"], linewidth=0.7)
    axis.set_axisbelow(True)
    axis.tick_params(axis="both", labelsize=6.5, colors=theme["text-3"], pad=1)

    for position, value in zip(positions, values):
        offset = limit * 0.025
        axis.text(
            value + (offset if value >= 0 else -offset),
            position,
            f"{value:+.2f}",
            va="center",
            ha="left" if value >= 0 else "right",
            fontsize=6.5,
            color=theme["text-2"],
        )

    axis.text(
        0.01,
        1.04,
        "← Benign contribution",
        transform=axis.transAxes,
        color=theme["chart-benign"],
        fontsize=6.5,
        fontweight="bold",
    )
    axis.text(
        0.99,
        1.04,
        "Malicious contribution →",
        transform=axis.transAxes,
        color=theme["chart-malicious"],
        fontsize=6.5,
        fontweight="bold",
        ha="right",
    )

    for spine in axis.spines.values():
        spine.set_visible(False)

    axis.set_xlabel("SHAP value", fontsize=6.5, color=theme["text-muted"], labelpad=1)
    figure.patch.set_alpha(0)
    axis.set_facecolor("none")
    figure.tight_layout(pad=0.35)
    target.pyplot(figure, width="stretch")
    plt.close(figure)


def derive_batch_summary(analyses):
    """Derive mutually exclusive analyst-facing counts from analysis records."""
    summary = {
        "total": len(analyses),
        "high_risk_uncertain": 0,
        "auto_malicious": 0,
        "auto_benign": 0,
        "failed": 0,
    }
    # 분석가가 판정을 수정한 건은 수정된 그룹으로 센다. 그룹 타일과 같은 기준이다.
    summary_key = {
        "failed": "failed",
        "needs_review": "high_risk_uncertain",
        "auto_malicious": "auto_malicious",
        "auto_benign": "auto_benign",
    }
    for analysis in analyses:
        key = summary_key.get(triage_group_key(analysis))
        if key is not None:
            summary[key] += 1
    return summary


def entry_view(entry, status):
    """접수 응답의 entries 항목 하나를 대시보드 뷰 모델로 옮긴다.

    filename/sha256/size_bytes는 이 응답만이 알고 있다. ZIP 내부 PE는 프론트에
    바이트가 없어서 로컬 해시로는 복원할 수 없기 때문에 entries가 유일한 근거다.
    """
    return {
        "analysis_id": entry.get("analysis_id"),
        "sha256": entry.get("sha256") or "",
        "status": status,
        "filename": entry.get("filename") or "(이름 없음)",
        "file_size": entry.get("size_bytes") or 0,
        "initial_verdict": None,
        "route": None,
        "reason": None,
        "final_verdict": None,
        "calibrated_probability": None,
        "raw_probability": None,
        "disagreement": None,
        "ood_score": None,
        "difficulty_score": None,
        "triggered_signals": None,
        "top_features": [],
        "deep_analysis_status": {},
        "deep_status": None,
        "current_stage": None,
        "evidence": [],
        "evidence_details": [],
        "llm_summary": None,
        "llm_status": None,
        "final_assessment": None,
        "capa": None,
        "floss": None,
        "speakeasy": None,
        "tool_details": {},
        "deep_error": None,
        "error": None,
        "analyst_final_verdict": None,
        "approval_status": None,
        "review_revision": 0,
    }


def receipt_views(receipt, source):
    """접수 응답을 (분석 뷰 모델, 제외 항목) 으로 나눈다.

    source는 ZIP 접수일 때 그 ZIP 파일명, 직접 업로드면 None이다. 백엔드 응답에는
    ZIP 파일명이 담기지 않으므로 화면 표기는 프론트가 알고 있는 이름을 쓴다.
    """
    accepted_status = {
        item["analysis_id"]: item.get("status", "QUEUED")
        for item in receipt.get("analyses", [])
        if item.get("analysis_id")
    }

    analyses, skipped = [], []
    for entry in receipt.get("entries", []):
        analysis_id = entry.get("analysis_id")
        if entry.get("status") == "ACCEPTED" and analysis_id:
            analyses.append(
                entry_view(entry, accepted_status.get(analysis_id, "QUEUED"))
            )
        elif entry.get("status") == "SKIPPED":
            skipped.append(
                {
                    "filename": entry.get("filename") or "(이름 없음)",
                    "size_bytes": entry.get("size_bytes"),
                    "reason_code": entry.get("reason_code") or "-",
                    "reason": entry.get("reason") or "사유가 제공되지 않았습니다.",
                    "source": source,
                }
            )
    return analyses, skipped


def submit_batch(file_descriptors, on_progress=None):
    """업로드를 백엔드에 접수하고, 결과가 아직 비어 있는 batch_data를 만든다.

    PE/DLL은 /batches 한 번으로, ZIP은 파일당 /batches/zip 한 번으로 보낸다.
    백엔드가 요청마다 batch_id를 새로 발급하므로 한 화면이 여러 배치를 갖는다.
    한 요청이 실패해도 나머지 접수 결과는 버리지 않고 errors에 모아 알린다.

    on_progress는 요청 하나가 끝날 때마다(성공/실패 모두) 그 시점까지 누적된
    receipt로 호출된다. 여러 ZIP을 순차 접수하는 도중 뒤 요청이 실패하거나
    화면이 다시 그려져도, 이미 백엔드가 받아 준 batch_id를 잃지 않기 위해서다.
    batch_id를 잃으면 그 배치는 접수만 되고 폴링할 방법이 없어진다.
    """
    pe_files = [d for d in file_descriptors if d["kind"] == "PE"]
    zip_files = [d for d in file_descriptors if d["kind"] == "ZIP"]

    # 누적 대상은 이 dict 하나다. on_progress에 넘기는 것도 같은 객체이므로
    # 중간 저장 시점마다 "그때까지 확보한 전부"가 그대로 전달된다.
    receipt = {"batch_ids": [], "analyses": [], "skipped": [], "errors": []}
    batch_ids = receipt["batch_ids"]
    analyses = receipt["analyses"]
    skipped = receipt["skipped"]
    errors = receipt["errors"]

    def commit():
        if on_progress is not None:
            on_progress(receipt)

    # 백엔드가 받지 않는 확장자는 요청을 보내지 않고 화면에서만 알린다
    for descriptor in file_descriptors:
        if descriptor["kind"] == "OTHER":
            skipped.append(
                {
                    "filename": descriptor["filename"],
                    "size_bytes": descriptor["size"],
                    "reason_code": "UNSUPPORTED_FILE_TYPE",
                    "reason": ".exe·.dll·.zip 파일만 접수합니다.",
                    "source": None,
                }
            )

    def collect(call, source, label):
        try:
            response = call()
        except ApiError as e:
            errors.append({"filename": label, "code": e.code, "message": e.message})
            # 실패 사유도 즉시 남긴다. 앞서 성공한 접수는 이미 저장되어 있다.
            commit()
            return
        batch_ids.append(response["batch_id"])
        accepted, dropped = receipt_views(response, source)
        analyses.extend(accepted)
        skipped.extend(dropped)
        # 접수 성공 직후 저장한다. 다음 요청이 무엇을 하든 이 결과는 남는다.
        commit()

    if pe_files:
        payload = [(d["filename"], d["content"]) for d in pe_files]
        collect(
            lambda: api_client.upload_batch(payload),
            None,
            f"PE/DLL {len(pe_files)}건",
        )

    for descriptor in zip_files:
        collect(
            lambda d=descriptor: api_client.upload_zip(d["filename"], d["content"]),
            descriptor["filename"],
            descriptor["filename"],
        )

    # 보낼 요청이 하나도 없었던 경우(전건 OTHER)에도 제외 사유는 저장한다
    if not pe_files and not zip_files:
        commit()

    return receipt


def refresh_pending(batch_data):
    """끝나지 않은 분석들의 상태를 백엔드에 다시 묻고 갱신한다.

    반환: 아직 진행 중인 건이 하나라도 있으면 True
    """
    still_running = False

    for index, analysis in enumerate(batch_data["analyses"]):
        # 이미 끝난 건 다시 묻지 않는다
        if analysis.get("status") in ("COMPLETED", "FAILED"):
            continue

        try:
            progress = api_client.get_status(analysis["analysis_id"])
        except ApiError as e:
            analysis["status"] = "FAILED"
            analysis["error"] = {
                "code": e.code,
                "message": e.message,
                "stage": e.stage,
            }
            continue

        analysis["status"] = progress.get("status", "QUEUED")
        analysis["current_stage"] = progress.get("current_stage")
        analysis["error"] = progress.get("error")

        # Batch 조회를 쓸 수 없는 fallback에서도 누적 종합 결과를 읽는다.
        # Initial Analysis가 저장되는 즉시 뷰에 반영하며, 별도 polling loop는
        # 만들지 않고 기존 status polling의 같은 주기 안에서만 수행한다.
        try:
            full = api_client.get_result(analysis["analysis_id"])
            updated = to_view(full, analysis)
            if deep_result_ready(updated):
                updated = load_deep_result_once(updated)
            batch_data["analyses"][index] = updated
            analysis = updated
        except ApiError as e:
            analysis["error"] = {
                "code": e.code,
                "message": e.message,
                "stage": e.stage,
            }

        if analysis.get("status") not in TERMINAL_STATUSES:
            still_running = True

    return still_running


def to_view(full, previous):
    """API 응답을 대시보드가 읽는 평면 키로 옮긴다."""
    prediction = full.get("prediction") or {}
    signals = full.get("risk_signals") or {}

    return {
        **previous,
        "status": full.get("status") or previous.get("status"),
        "current_stage": full.get("current_stage", previous.get("current_stage")),
        "initial_verdict": full.get("initial_verdict"),
        "route": full.get("route"),
        "reason": full.get("reason"),
        "triggered_signals": full.get("triggered_signals"),
        "final_verdict": full.get("final_verdict"),
        "final_assessment": full.get("final_assessment"),
        "raw_probability": prediction.get("lgbm_raw_probability"),
        "calibrated_probability": prediction.get("calibrated_probability"),
        "disagreement": signals.get("disagreement"),
        "ood_score": signals.get("ood_score"),
        "difficulty_score": signals.get("difficulty_score"),
        "top_features": full.get("top_features", []),
        "deep_analysis_status": full.get("deep_analysis_status", {}),
        "evidence": full.get("evidence", []),
        "llm_summary": full.get("llm_summary"),
        "error": full.get("error"),
        **review_fields(full),
    }


def review_fields(full):
    """종합 결과 중 분석가 판정 관련 값. 저장 직후 이 값만 따로 갱신할 때도 쓴다."""
    return {
        "analyst_final_verdict": full.get("analyst_final_verdict"),
        "approval_status": full.get("approval_status"),
        "review_revision": full.get("review_revision") or 0,
    }


def merge_deep_result(analysis, deep):
    """Deep Analysis endpoint 응답을 기존 평면 뷰에 안전하게 합친다."""
    return {
        **analysis,
        "deep_status": deep.get("status"),
        "deep_analysis_status": deep.get("deep_analysis_status") or {},
        "tool_details": deep.get("tool_details") or {},
        "capa": deep.get("capa"),
        "floss": deep.get("floss"),
        "speakeasy": deep.get("speakeasy"),
        "evidence": deep.get("evidence") or analysis.get("evidence") or [],
        "evidence_details": deep.get("evidence_details") or [],
        "llm_summary": deep.get("llm_summary") or analysis.get("llm_summary"),
        "llm_status": deep.get("llm_status"),
        "deep_error": deep.get("error"),
        "deep_detail_loaded": True,
    }


def deep_result_ready(analysis):
    """Deep이 끝났거나 전체 분석이 종료되어 상세 조회가 필요한지 확인한다."""
    if analysis.get("initial_verdict") != "HIGH_RISK_UNCERTAIN":
        return False
    if analysis.get("status") in TERMINAL_STATUSES:
        return True
    statuses = analysis.get("deep_analysis_status") or {}
    return all(
        statuses.get(tool) in {"COMPLETED", "FAILED", "NOT_REQUIRED"}
        for tool in ("capa", "floss", "speakeasy")
    )


def load_deep_result_once(analysis):
    """HIGH_RISK_UNCERTAIN의 완료된 Deep 상세를 한 번만 보강한다."""
    if analysis.get("initial_verdict") != "HIGH_RISK_UNCERTAIN" or analysis.get(
        "deep_detail_loaded"
    ):
        return analysis
    try:
        deep = api_client.get_deep_analysis(analysis["analysis_id"])
    except ApiError as e:
        return {
            **analysis,
            "deep_error": {
                "code": e.code,
                "message": e.message,
                "stage": e.stage,
            },
            "deep_detail_loaded": True,
        }
    return merge_deep_result(analysis, deep)


def pending_analyses(batch_data):
    """아직 종료되지 않은 분석만 고른다."""
    return [
        analysis
        for analysis in batch_data.get("analyses", [])
        if analysis.get("status") not in TERMINAL_STATUSES
    ]


def poll_status_counts(analyses):
    """진행 상황 패널용 상태별 건수.

    완료 화면의 derive_batch_summary()는 판정 그룹(분석가 수정 반영)을 세고, 이쪽은
    작업 상태를 센다.
    서로 다른 집계이므로 합치지 않는다.
    """
    counts = {"QUEUED": 0, "RUNNING": 0, "COMPLETED": 0, "FAILED": 0}
    for analysis in analyses:
        status = analysis.get("status") or "QUEUED"
        counts[status] = counts.get(status, 0) + 1
    return counts


def sync_selected_analysis(batch_data):
    """갱신된 batch_data를 session_state에 다시 연결한다.

    refresh_batch()/refresh_pending()은 완료된 건의 리스트 요소를 새 dict로
    교체한다. 이 재연결을 빼먹으면 상세 화면이 접수 직후의 빈 dict를 계속 본다.
    """
    st.session_state.batch_data = batch_data
    st.session_state.batch_results = batch_data["analyses"]
    selected_id = st.session_state.get("selected_analysis_id")
    for analysis in batch_data["analyses"]:
        if analysis["analysis_id"] == selected_id:
            st.session_state.analysis_result = analysis
            break


def batch_id_list(batch_data):
    """이 화면이 조회해야 하는 배치 번호들.

    PE는 /batches 한 번, ZIP은 파일당 /batches/zip 한 번으로 접수되므로 배치가
    여러 개일 수 있다. 단일 배치만 있던 이전 세션도 같은 형태로 다룬다.
    """
    ids = [value for value in (batch_data.get("batch_ids") or []) if value]
    if ids:
        return ids
    single = batch_data.get("batch_id")
    return [single] if single else []


def batch_id_label(batch_data):
    """화면 머리말에 쓸 배치 번호 표기."""
    ids = batch_id_list(batch_data)
    if not ids:
        return "-"
    if len(ids) == 1:
        return ids[0]
    return f"{ids[0]} 외 {len(ids) - 1}건"


def refresh_batch(batch_data):
    """등록된 배치들의 상태를 배치 단위로 갱신한다.

    GET /batches/{batch_id}의 analyses는 GET /analyses/{id}와 같은 종합 결과라서
    파일별 status/result 반복 조회를 대신할 수 있다. 조회 대상이 없거나 모든 배치
    조회가 실패하면 기존 파일별 폴링(refresh_pending)으로 물러난다.

    반환: 아직 진행 중인 건이 하나라도 있으면 True
    """
    batch_ids = batch_id_list(batch_data)
    if not batch_ids:
        return refresh_pending(batch_data)

    by_id, failed = {}, 0
    for batch_id in batch_ids:
        try:
            batch = api_client.get_batch(batch_id)
        except ApiError:
            # 한 배치만 실패했다면 그 배치의 건들은 아래에서 진행 중으로 남는다
            failed += 1
            continue
        for item in batch.get("analyses", []):
            if item.get("analysis_id"):
                by_id[item["analysis_id"]] = item

    if failed == len(batch_ids):
        return refresh_pending(batch_data)

    still_running = False
    for index, analysis in enumerate(batch_data["analyses"]):
        # 이미 끝난 건은 다시 반영하지 않는다
        if analysis.get("status") in TERMINAL_STATUSES:
            continue

        full = by_id.get(analysis["analysis_id"])
        if full is None:
            # 배치 응답에 없는 건은 상태를 추측하지 않고 진행 중으로 둔다
            still_running = True
            continue

        # batch 응답은 진행 중에도 GET /analyses/{id}와 같은 누적 결과를 준다.
        # 따라서 terminal 전에도 Initial/JRR/SHAP/deep status를 뷰에 반영한다.
        updated = to_view(full, analysis)
        status = updated.get("status") or "QUEUED"
        if deep_result_ready(updated):
            updated = load_deep_result_once(updated)
        if status not in TERMINAL_STATUSES:
            still_running = True
        batch_data["analyses"][index] = updated

    return still_running


def poll_started_at():
    """폴링 시작 시각. 세션이 이어진 경우를 대비해 없으면 지금으로 채운다."""
    if "poll_started_at" not in st.session_state:
        st.session_state.poll_started_at = time.monotonic()
    return st.session_state.poll_started_at


def resume_polling():
    """시간 초과 뒤 수동 재조회. 경과 시간을 다시 센다."""
    st.session_state.poll_timed_out = False
    st.session_state.poll_started_at = time.monotonic()


def find_batch_analysis(analysis_id, batch_data=None):
    """현재 세션에 저장된 배치 결과에서 특정 분석(analysis_id) 항목을 찾아 반환합니다."""
    batch = batch_data or st.session_state.get("batch_data", {})
    for analysis in batch.get("analyses", []):
        if analysis["analysis_id"] == analysis_id:
            return analysis
    return None


def filter_batch_analyses(analyses, query):
    """현재 배치 결과에서 파일명 또는 SHA-256으로 찾는다. 백엔드는 부르지 않는다.

    파일명은 대소문자를 무시한 부분 일치, SHA-256도 부분 일치다. 화면 머리말이
    해시를 앞 12자리...뒤 8자리로 잘라 보여주므로, 어느 쪽을 복사해 붙여도
    맞도록 앞부분만이 아니라 부분 문자열로 비교한다. 빈 검색어는 전부 돌려준다.
    """
    needle = (query or "").strip().lower()
    if not needle:
        return analyses
    return [
        analysis
        for analysis in analyses
        if needle in (analysis.get("filename") or "").lower()
        or needle in (analysis.get("sha256") or "").lower()
    ]


BATCH_GROUP_LABELS = {
    "total": "Total",
    "needs_review": "Needs Review",
    "auto_malicious": "Auto Malicious",
    "auto_benign": "Auto Benign",
    "failed": "Failed",
}


def is_reviewed(analysis):
    """분석가가 한 번이라도 판정을 저장했는지. 보류(null) 저장도 포함한다."""
    return (analysis.get("review_revision") or 0) > 0


def initial_group_key(analysis):
    """시스템 초기 판정 기준 그룹. 분석가 수정과 무관한 '원래' 그룹이다."""
    return {
        "HIGH_RISK_UNCERTAIN": "needs_review",
        "AUTO_MALICIOUS": "auto_malicious",
        "AUTO_BENIGN": "auto_benign",
    }.get(analysis.get("initial_verdict"))


def triage_group_key(analysis):
    """분석 한 건이 속한 그룹 키. 아직 판정 전이면 None.

    분석가가 판정을 저장한 건은 그 판정을 따른다. 백엔드는 initial_verdict를
    바꾸지 않으므로 그룹 이동은 프론트가 analyst_final_verdict로 정한다.
    보류(null)로 저장한 건은 Needs Review로 간다.
    """
    if analysis["status"] == "FAILED":
        return "failed"
    if is_reviewed(analysis):
        return REVIEW_GROUP_BY_VERDICT.get(
            analysis.get("analyst_final_verdict"), "needs_review"
        )
    return initial_group_key(analysis)


def review_mark(analysis):
    """세 그룹 표의 수정 여부 열 글자."""
    if not is_reviewed(analysis):
        return "-"
    original = initial_group_key(analysis)
    if original is not None and original != triage_group_key(analysis):
        return f"수정됨 · 원래 {BATCH_GROUP_LABELS[original].upper()}"
    # 저장은 했지만 원래 그룹과 같다(시스템 판정을 확인했거나 되돌린 경우)
    return "확인됨"


def triage_group_label(analysis):
    """Total 표의 Group 열 글자. 판정 전 항목은 PENDING."""
    key = triage_group_key(analysis)
    return BATCH_GROUP_LABELS[key].upper() if key else "PENDING"


def group_batch_analyses(analyses):
    """Partition results by analyst workflow priority."""
    groups = {
        "needs_review": [],
        "auto_malicious": [],
        "auto_benign": [],
        "failed": [],
    }
    for analysis in analyses:
        key = triage_group_key(analysis)
        if key is not None:
            groups[key].append(analysis)
    return groups


def deep_analysis_status_text(analysis):
    """Summarize tool states for the Needs Review result table."""
    # 자동 판정에서 분석가가 옮겨 온 건은 심층 분석을 거치지 않았다
    if analysis.get("initial_verdict") != "HIGH_RISK_UNCERTAIN":
        return "NOT RUN"
    statuses = analysis.get("deep_analysis_status") or {}
    for tool_name, key in (
        ("Speakeasy", "speakeasy"),
        ("FLOSS", "floss"),
        ("CAPA", "capa"),
    ):
        if statuses.get(key) in {"RUNNING", "QUEUED", "FAILED"}:
            return f"{tool_name} {statuses[key]}"
    if all(
        statuses.get(key) in {"COMPLETED", "NOT_REQUIRED"}
        for key in ("capa", "floss", "speakeasy")
    ):
        return "COMPLETED"
    return "QUEUED"


def initial_detail_available(analysis):
    """Initial Analysis 상세를 안전하게 그릴 수 있을 만큼 저장되었는지 확인한다."""
    return bool(analysis.get("initial_verdict") and analysis.get("route")) and all(
        analysis.get(key) is not None for key in DETAIL_REQUIRED_FIELDS
    )


def is_progressive_result(analysis):
    return (
        analysis.get("initial_verdict") == "HIGH_RISK_UNCERTAIN"
        and analysis.get("route") == "DEEP_ANALYSIS"
        and initial_detail_available(analysis)
    )


def evidence_visible(analysis):
    """MITRE/위협 근거를 보여줄 시점.

    백엔드는 심층 분석이 진행 중인 스냅샷에도 evidence를 실어 보낼 수 있다
    (progressive 계약). 표시 시점은 프론트가 정한다: 완료면 항상, 실패면
    확보된 부분 근거가 있을 때만, 대기·진행·불필요면 보여주지 않는다.
    """
    state = deep_analysis_state(analysis)
    if state == "COMPLETED":
        return True
    if state == "FAILED":
        return bool(analysis.get("evidence"))
    return False


def evidence_card_markup(evidence, capa_behaviors):
    """위협 근거 카드 HTML. 줄바꿈 없이 한 줄로 만든다.

    st.markdown은 본문을 dedent한 뒤 CommonMark로 파싱한다. 여러 줄 템플릿에서
    항목이 비어 단독 줄이 빈 줄이 되면 <div> HTML 블록이 거기서 끝나고, 뒤따르는
    들여쓴 줄은 코드 블록으로 렌더돼 '</div>' 같은 조각이 화면에 그대로 찍혔다.
    줄바꿈 자체를 없애면 블록이 쪼개질 수 없다. 값은 전부 escape한다.
    """
    mitre_items = "".join(
        '<div class="evidence-item"><span class="technique-id">'
        f"{escape(technique.get('technique_id', technique.get('id', '')))}"
        "</span> "
        f"{escape(technique.get('technique_name', technique.get('name', '')))}"
        " · "
        f"{escape(technique.get('tactic', ', '.join(technique.get('sources', []))))}"
        "</div>"
        for technique in evidence
    )
    capa_items = "".join(
        f'<div class="evidence-item">· {escape(behavior)}</div>'
        for behavior in capa_behaviors
    )

    def section(title, items, empty_text):
        body = items or f'<div class="evidence-item">{escape(empty_text)}</div>'
        return (
            '<div class="evidence-section">'
            f'<div class="evidence-title">{title}</div>{body}</div>'
        )

    return (
        '<div class="evidence-grid">'
        + section(
            "MITRE ATT&amp;CK", mitre_items, "표시할 MITRE ATT&CK 근거가 없습니다."
        )
        + section("CAPA Behavior", capa_items, "표시할 CAPA 행위가 없습니다.")
        + "</div>"
    )


def evidence_layout(target, result):
    """완료 화면의 근거/SHAP 영역 배치. SHAP을 그릴 컨테이너를 돌려준다.

    심층 분석이 불필요한 자동 판정(AUTO_*)이나 아직 끝나지 않은 경우에는 위협
    근거 카드를 그리지 않고 SHAP이 전체 폭을 쓴다.
    """
    if not evidence_visible(result):
        return target.container()
    evidence_col, explainability_col = target.columns(2, gap="medium")
    render_evidence_card(evidence_col, result)
    return explainability_col


def render_evidence_card(target, result):
    """완료 화면의 '위협 근거' 카드. 표시 여부는 호출자가 evidence_visible로 정한다."""
    target.subheader("위협 근거")
    card = target.container(
        border=True,
        key="evidence-card",
        height="stretch",
        vertical_alignment="center",
    )
    card.markdown(
        evidence_card_markup(
            result.get("evidence") or result.get("mitre_attack") or [],
            result.get("capa_behaviors") or [],
        ),
        unsafe_allow_html=True,
    )


def deep_analysis_state(analysis):
    """종합 Deep 상태가 없는 batch 응답에서도 표시 상태를 안전하게 계산한다."""
    if analysis.get("route") == "FINAL":
        return "NOT_REQUIRED"
    explicit = analysis.get("deep_status")
    if explicit in {"QUEUED", "RUNNING", "COMPLETED", "FAILED", "NOT_REQUIRED"}:
        return explicit
    if analysis.get("initial_verdict") != "HIGH_RISK_UNCERTAIN":
        return "NOT_REQUIRED"
    if analysis.get("status") == "FAILED":
        return "FAILED"

    statuses = analysis.get("deep_analysis_status") or {}
    selected = [
        statuses.get(key)
        for key in ("capa", "floss", "speakeasy")
        if statuses.get(key) != "NOT_REQUIRED"
    ]
    if "RUNNING" in selected:
        return "RUNNING"
    if "QUEUED" in selected:
        has_finished_tool = any(value in {"COMPLETED", "FAILED"} for value in selected)
        return "RUNNING" if has_finished_tool else "QUEUED"
    if selected and all(value in {"COMPLETED", "FAILED"} for value in selected):
        return "FAILED" if "FAILED" in selected else "COMPLETED"
    if analysis.get("status") == "COMPLETED":
        return "COMPLETED"
    return "QUEUED"


def _metric_text(value, pattern):
    if value is None:
        return "-"
    try:
        return pattern.format(float(value))
    except (TypeError, ValueError):
        return str(value)


def tooltip_attr(text):
    """설명 문구를 data-tip 속성값으로 바꾼다. 줄바꿈(\n)은 &#10; 으로 넣어야
    마크다운 처리를 거쳐도 살아남고, CSS white-space: pre-line 이 줄을 바꾼다."""
    return escape(text).replace("\n", "&#10;")


def result_detail_state(analysis):
    """Batch 상태가 아닌 현재 파일의 확보된 결과로 표시 여부를 결정한다."""
    return {
        "available": initial_detail_available(analysis),
        "deep": deep_analysis_state(analysis),
        "tools": {
            tool: "NOT_REQUIRED"
            if analysis.get("route") == "FINAL"
            else (analysis.get("deep_analysis_status") or {}).get(tool)
            or ("NOT_REQUIRED" if tool == "cape" else "QUEUED")
            for tool in ("capa", "floss", "speakeasy", "cape")
        },
    }


def detail_section(target, title, key):
    """모든 route에서 같은 제목 간격, 카드 폭, 기본 padding을 사용한다."""
    section = target.container(
        key=f"detail_{key}_section", height="stretch", gap=DETAIL_CARD_GAP
    )
    section.subheader(title)
    return section.container(
        border=True, key=f"detail_{key}_card", height="stretch", gap=DETAIL_CARD_GAP
    )


def final_verdict_cell(analysis):
    """분석 요약의 Final Verdict 칸 (라벨, 배지).

    분석가가 판정을 저장했으면 시스템 판정 대신 분석가 판정을 보여 주고,
    라벨에 수정/승인/보류 여부를 붙인다. 시스템 판정은 백엔드에 그대로 남아 있다.
    """
    if not is_reviewed(analysis):
        return "Final Verdict", verdict_badge_markup(
            analysis.get("final_verdict") or "Pending"
        )
    verdict = analysis.get("analyst_final_verdict")
    if verdict is None:
        return "Final Verdict · 분석가 보류", verdict_badge_markup("UNCERTAIN")
    note = "분석가 승인" if analysis.get("approval_status") == "APPROVED" else "수정됨"
    return f"Final Verdict · {note}", verdict_badge_markup(verdict)


def review_blocker(analysis):
    """판정 수정 버튼을 막는 이유. 수정할 수 있으면 None."""
    if analysis.get("status") != "COMPLETED":
        return "분석이 완료된 파일만 판정을 수정할 수 있습니다."
    if triage_group_key(analysis) not in REVIEW_GROUPS:
        return "Needs Review / Auto Malicious / Auto Benign 판정만 수정할 수 있습니다."
    batch_data = st.session_state.get("batch_data")
    if batch_data and pending_analyses(batch_data):
        # 진행 화면은 2초마다 다시 그려져서 열어 둔 팝업이 닫힌다
        return "배치의 모든 분석이 끝난 뒤 수정할 수 있습니다."
    return None


def render_summary_section(target, analysis):
    """'분석 요약' 제목 줄 맨 오른쪽에 판정 수정 버튼을 둔 카드. 카드 컨테이너를 돌려준다."""
    section = target.container(
        key="detail_summary_section", height="stretch", gap=DETAIL_CARD_GAP
    )
    title, action = section.columns([6, 1], vertical_alignment="bottom")
    title.subheader("분석 요약")
    blocker = review_blocker(analysis)
    if action.button(
        "판정 수정",
        key="open_review_dialog",
        width="stretch",
        disabled=blocker is not None,
        help=blocker,
    ):
        open_review_dialog(analysis["analysis_id"])
    return section.container(
        border=True, key="detail_summary_card", height="stretch", gap=DETAIL_CARD_GAP
    )


def review_target(analysis_id):
    """팝업이 다룰 분석 건의 최신 뷰. 저장·충돌 뒤 갱신된 값을 다시 읽기 위해 매번 찾는다."""
    current = st.session_state.get("analysis_result") or {}
    if current.get("analysis_id") == analysis_id:
        return current
    return find_batch_analysis(analysis_id)


def refresh_review_fields(analysis_id):
    """저장 뒤 해당 건의 판정 관련 값만 백엔드에서 다시 받아 화면 상태에 반영한다.

    종료된 건은 폴링이 다시 조회하지 않으므로 여기서 직접 갱신해야 한다. 그러지
    않으면 review_revision이 옛 값으로 남아 다음 저장이 409로 실패한다.
    심층 분석 상세 등 이미 받아 둔 값은 건드리지 않는다.
    """
    full = api_client.get_result(analysis_id)
    return apply_review_patch(
        analysis_id,
        {
            **review_fields(full),
            "final_verdict": full.get("final_verdict"),
            "final_assessment": full.get("final_assessment"),
        },
    )


def apply_saved_review(analysis_id, saved):
    """PATCH 응답만으로 화면 상태를 먼저 갱신한다.

    저장 직후 재조회(get_result)가 실패해도 서버에 저장된 판정과 새 revision이
    화면에 남도록, 재조회보다 먼저 호출한다. approval_status 계산은 백엔드
    views.analysis 와 같다.
    """
    target = review_target(analysis_id) or {}
    verdict = saved.get("analyst_final_verdict")
    if verdict is None:
        approval = "PENDING"
    elif verdict == target.get("final_verdict"):
        approval = "APPROVED"
    else:
        approval = "MODIFIED"
    return apply_review_patch(
        analysis_id,
        {
            "analyst_final_verdict": verdict,
            "approval_status": approval,
            "review_revision": saved["revision"],
        },
    )


def apply_review_patch(analysis_id, patch):
    """배치 목록과 현재 상세 결과 양쪽에서 해당 건에 patch를 덮어쓴다."""
    updated = None
    batch_data = st.session_state.get("batch_data")
    if batch_data:
        for index, analysis in enumerate(batch_data["analyses"]):
            if analysis["analysis_id"] == analysis_id:
                updated = {**analysis, **patch}
                batch_data["analyses"][index] = updated
                break
        st.session_state.batch_results = batch_data["analyses"]

    current = st.session_state.get("analysis_result") or {}
    if current.get("analysis_id") == analysis_id:
        updated = {**current, **patch}
        st.session_state.analysis_result = updated
    return updated


def format_review_time(value):
    """백엔드의 ISO 시각을 대시보드가 도는 서버의 현지 시각으로 짧게 바꾼다."""
    if not value:
        return "-"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def review_history_rows(items, analysis):
    """수정 이력 표. 최신 저장이 위로 오고, 각 줄은 직전 그룹 → 저장한 그룹으로 보여 준다."""
    previous = initial_group_key(analysis)
    rows = []
    for item in items:
        group = REVIEW_GROUP_BY_VERDICT.get(
            item.get("analyst_final_verdict"), "needs_review"
        )
        before = BATCH_GROUP_LABELS[previous].upper() if previous else "-"
        rows.append(
            {
                "Reviewed At": format_review_time(item.get("reviewed_at")),
                "Reviewer": item.get("reviewer_id") or "-",
                "Change": f"{before} → {BATCH_GROUP_LABELS[group].upper()}",
                "Notes": item.get("analyst_notes") or "",
            }
        )
        previous = group
    return list(reversed(rows))


def open_review_dialog(analysis_id):
    """판정 수정 팝업을 연다. 열기 직전에 판정 관련 값을 한 번 새로 받아 온다.

    완료된 건은 폴링이 다시 조회하지 않아서, 다른 검토자가 그사이 바꾼 판정이 화면에
    없을 수 있다. 그대로 열면 '현재 판정'은 옛 값인데 아래 수정 이력(매번 서버에서
    읽음)에는 새 저장이 보여 서로 어긋난다. 팝업 안에서 다시 그릴 때마다 받아 오면
    고르던 중에 선택이 바뀔 수 있으므로, 여는 순간 한 번만 받는다. 실패하면 화면에
    있던 값으로 열고, 저장 시 revision 확인(409)이 마지막 안전장치가 된다.
    """
    st.session_state.get("review_conflict", {}).pop(analysis_id, None)
    try:
        refresh_review_fields(analysis_id)
    except ApiError:
        pass
    review_dialog(analysis_id)


def handle_review_conflict(analysis_id):
    """다른 검토자가 먼저 저장한 경우. 최신 판정을 불러온 뒤 팝업을 다시 그린다.

    팝업을 다시 그리지 않으면 화면에는 이전 판정이 남은 채 내부 revision만 새 값이
    되어, 다시 저장하면 다른 검토자의 변경을 확인 없이 덮어쓰게 된다.
    """
    try:
        latest = refresh_review_fields(analysis_id) or review_target(analysis_id) or {}
    except ApiError as e:
        # 최신 값을 모르면 revision도 옛 값 그대로이므로 다시 저장해도 409로 막힌다
        message = (
            "그사이 판정이 먼저 수정되었지만 최신 판정을 불러오지 못했습니다. "
            f"팝업을 닫았다가 다시 열어 주세요. ({e.message})"
        )
    else:
        who = ""
        try:
            items = (api_client.list_reviews(analysis_id) or {}).get("items") or []
            if items:
                who = f"{items[-1].get('reviewer_id')}님이 "
        except ApiError:
            pass
        group = BATCH_GROUP_LABELS[triage_group_key(latest) or "needs_review"].upper()
        # 저장 버튼을 두 번 눌렀거나 응답 전에 연결이 끊겨 내 저장이 먼저 반영된
        # 경우에도 409가 나므로 '다른 검토자'라고 단정하지 않는다.
        message = (
            f"그사이 판정이 먼저 수정되었습니다. {who}{group}(으)로 저장한 상태입니다. "
            "최신 판정을 확인한 뒤 다시 선택해 저장하세요."
        )
    st.session_state.setdefault("review_conflict", {})[analysis_id] = message
    st.rerun(scope="fragment")


@st.dialog("판정 수정", width="large")
def review_dialog(analysis_id):
    """분석가 판정 수정 팝업. 저장에 성공하면 앱 전체를 다시 그려 팝업을 닫는다."""
    analysis = review_target(analysis_id)
    if analysis is None:
        st.error("선택한 분석을 찾을 수 없습니다. 화면을 새로 고친 뒤 다시 시도하세요.")
        return

    conflict = st.session_state.get("review_conflict", {}).get(analysis_id)
    if conflict:
        st.warning(conflict)
    current = triage_group_key(analysis)
    original = initial_group_key(analysis)
    st.caption(
        f"{analysis.get('filename') or '(이름 없음)'} · "
        f"SHA-256 {truncate_hash(analysis.get('sha256') or '-')}"
    )
    st.markdown(
        f"현재 판정 **{BATCH_GROUP_LABELS[current].upper()}**"
        + (
            f" · 시스템 초기 판정 {BATCH_GROUP_LABELS[original].upper()}"
            if original and original != current
            else ""
        )
    )

    choice = st.radio(
        "수정할 판정",
        options=REVIEW_GROUPS,
        index=REVIEW_GROUPS.index(current) if current in REVIEW_GROUPS else 0,
        format_func=lambda key: BATCH_GROUP_LABELS[key].upper(),
        horizontal=True,
        # revision을 key에 넣어, 충돌로 최신 판정을 받아 오면 이전 선택이 남지 않고
        # 최신 판정이 선택된 새 위젯으로 다시 만들어지게 한다. (key가 같으면 브라우저가
        # 이전 선택을 계속 보여 줘서 화면과 실제 선택값이 어긋난다)
        key=f"review_choice_{analysis_id}_{analysis.get('review_revision') or 0}",
    )
    notes = st.text_area(
        "메모 (선택)",
        max_chars=REVIEW_NOTES_MAX,
        key=f"review_notes_{analysis_id}",
    )
    reviewer = st.text_input(
        "검토자명",
        value=st.session_state.get("reviewer_id", ""),
        placeholder="예: HongGildong",
        help="수정 이력에 남는 이름입니다. 영문, 숫자, _ . @ - 만 쓸 수 있습니다(최대 128자).",
        key=f"review_reviewer_{analysis_id}",
    ).strip()

    # 같은 판정으로는 저장하지 않는다(메모만 남기는 저장도 막는다). 선택을 바꾸면
    # 팝업이 다시 그려지므로 버튼 상태가 바로 따라 바뀐다.
    unchanged = choice == current
    if unchanged:
        st.caption("현재 판정과 같습니다. 다른 판정을 선택해야 저장할 수 있습니다.")
    if st.button(
        "저장", type="primary", key=f"review_save_{analysis_id}", disabled=unchanged
    ):
        if not REVIEWER_ID_PATTERN.fullmatch(reviewer):
            st.error("검토자명은 영문, 숫자, _ . @ - 로 1~128자여야 합니다.")
        else:
            try:
                saved = api_client.save_review(
                    analysis_id,
                    REVIEW_VERDICT_BY_GROUP[choice],
                    reviewer,
                    analysis.get("review_revision") or 0,
                    notes.strip(),
                )
            except ApiError as e:
                if e.code == "REVIEW_CONFLICT":
                    handle_review_conflict(analysis_id)
                elif e.code == "REVIEW_FORBIDDEN":
                    st.error(
                        "판정 수정 권한이 없습니다. 대시보드의 "
                        "TRUST_TRIAGE_REVIEWER_TOKEN 설정을 확인하세요."
                    )
                else:
                    st.error(f"저장 실패: {e.message} (코드 {e.code})")
            else:
                st.session_state.reviewer_id = reviewer
                st.session_state.get("review_conflict", {}).pop(analysis_id, None)
                # 재조회가 실패해도 저장된 판정·revision이 화면에 남도록 응답부터 반영한다
                apply_saved_review(analysis_id, saved)
                try:
                    refresh_review_fields(analysis_id)
                except ApiError as e:
                    st.session_state.review_notice = (
                        f"판정을 {BATCH_GROUP_LABELS[choice].upper()}(으)로 저장했습니다. "
                        f"(다른 결과 항목은 새로 불러오지 못했습니다: {e.message})"
                    )
                else:
                    st.session_state.review_notice = f"판정을 {BATCH_GROUP_LABELS[choice].upper()}(으)로 저장했습니다."
                # 특정 그룹을 보고 있었다면 옮겨 간 그룹으로 따라간다. 그룹 위젯은
                # 다음 실행에서 만들어지기 전에 이 값으로 바꾼다.
                if st.session_state.get("batch_group") not in (None, "total"):
                    st.session_state.pending_batch_group = choice
                st.rerun()

    st.markdown("**수정 이력**")
    try:
        items = (api_client.list_reviews(analysis_id) or {}).get("items") or []
    except ApiError as e:
        st.caption(f"이력을 불러오지 못했습니다: {e.message}")
        return
    if not items:
        st.caption("아직 수정 이력이 없습니다.")
        return
    rows = review_history_rows(items, analysis)
    st.dataframe(
        rows,
        hide_index=True,
        width="stretch",
        height=min(35 * (len(rows) + 1) + 3, 250),
    )


def render_result_detail(analysis, target=st):
    """완료/진행/실패 결과가 공유하는 상세 shell. API 호출이나 polling은 하지 않는다."""
    state = result_detail_state(analysis)
    if not state["available"]:
        if analysis.get("status") == "FAILED":
            error = analysis.get("error") or {}
            target.error(
                "분석 실패: " + (error.get("message") or "원인을 확인할 수 없습니다.")
            )
            if error.get("code"):
                target.caption(
                    f"코드 {error['code']} · 단계 {error.get('stage') or '-'}"
                )
        else:
            target.info(
                f"Initial Analysis 결과를 기다리고 있습니다. (상태: {analysis.get('status') or 'QUEUED'})"
            )
        return

    shell = target.container(key="result_detail_shell", gap=DETAIL_COLUMN_GAP)
    # 배치 화면에서는 Batch Summary 머리글에 같은 버튼이 있으므로 여기서는 숨긴다.
    if not st.session_state.get("batch_data"):
        context, action = shell.columns([6, 1], gap=DETAIL_COLUMN_GAP)
    else:
        context, action = shell, None
    context.caption(
        f"{analysis.get('filename') or '(이름 없음)'} · "
        f"SHA-256 {analysis.get('sha256') or '-'}"
    )
    if action is not None and action.button(
        "새 파일 분석", key="progressive_new_file_analysis", width="stretch"
    ):
        reset_analysis_session()
        st.rerun()

    notice = st.session_state.pop("review_notice", None)
    if notice:
        st.toast(notice)

    initial = render_summary_section(shell, analysis)
    final_label, final_badge = final_verdict_cell(analysis)
    verdicts = [
        (
            "Initial Verdict",
            verdict_badge_markup(analysis.get("initial_verdict") or "Pending"),
        ),
        (final_label, final_badge),
        ("Route", route_badge_markup(analysis.get("route") or "-")),
    ]
    # (이름, 키, 서식, 이름에 마우스를 올리면 뜨는 설명)
    metrics = [
        (
            "Raw Probability",
            "raw_probability",
            "{:.1%}",
            "모델이 처음 예측한 악성일 확률",
        ),
        (
            "Calibrated Probability",
            "calibrated_probability",
            "{:.1%}",
            "실제 확률에 가깝도록 보정한 악성 확률\n0.65 초과 0.983645 미만일 때 보류",
        ),
        (
            "OOD Score",
            "ood_score",
            "{:.3f}",
            "학습 데이터와 얼마나 다른 샘플인지 나타내는 점수\n0 미만 때 보류",
        ),
        (
            "Disagreement",
            "disagreement",
            "{:.3f}",
            "두 모델의 예측이 얼마나 다른지 나타내는 값\n0.3 이상일 때 보류",
        ),
        (
            "Difficulty",
            "difficulty_score",
            "{:.1f}",
            "PE 구조 이상 등 분석이 얼마나 어려운지 나타내는 점수\n6 이상일 때 보류",
        ),
    ]
    signals = analysis.get("triggered_signals") or []
    # 예전 '라우팅 결정' 카드의 내용은 Route 오른쪽에 붙인다.
    route_detail_html = (
        '<div class="detail-route-detail">'
        '<div class="summary-label">Reason</div>'
        f'<div class="route-detail-value">{escape(analysis.get("reason") or "-")}</div>'
        '<div class="summary-label">Triggered Signals</div>'
        f'<div class="route-detail-value">{escape(", ".join(signals) if signals else "None")}</div>'
        "</div>"
    )

    if "queue_name" in analysis:
        queue_html = (
            '<div class="detail-route-detail" style="margin-left: 20px; padding-left: 20px; border-left: 1px solid var(--border-light);">'
            '<div class="summary-label">Queue</div>'
            f'<div class="route-detail-value">{escape(analysis.get("queue_name") or "-")}</div>'
            '<div class="summary-label">검토 유형</div>'
            f'<div class="route-detail-value">{escape(analysis.get("priority_reason") or "-")}</div>'
            '<div class="summary-label">검토 이유</div>'
            f'<div class="route-detail-value">{escape(analysis.get("queue_reason") or "-")}</div>'
            "</div>"
        )
        route_detail_html += queue_html
    initial.markdown(
        '<div class="detail-top"><div class="detail-verdicts">'
        + "".join(
            f'<div><div class="summary-label">{label}</div>{badge}</div>'
            for label, badge in verdicts
        )
        + "</div>"
        + route_detail_html
        + '</div><div class="summary-divider"></div><div class="detail-metrics">'
        + "".join(
            f'<div><div class="summary-label">'
            f'<span class="metric-tip" tabindex="0" data-tip="{tooltip_attr(tip)}">{label}</span></div>'
            f'<div class="summary-value">{escape(_metric_text(analysis.get(key), pattern))}</div></div>'
            for label, key, pattern, tip in metrics
        )
        + "</div>",
        unsafe_allow_html=True,
    )

    explain_col, pipeline_col = shell.columns([7, 3], gap=DETAIL_COLUMN_GAP)
    explanation = detail_section(explain_col, "설명 가능성", "shap")
    explanation.markdown("**SHAP 주요 특성 Top 5**")
    features = analysis.get("top_features") or analysis.get("shap_features") or []
    if features:
        render_shap_chart(explanation, features)
    else:
        explanation.info("표시할 SHAP 특성이 없습니다.")

    pipeline = detail_section(pipeline_col, "분석 파이프라인", "pipeline")
    steps = [("ML Triage", "COMPLETED")]
    steps.extend(
        (label, state["tools"][key])
        for label, key in (
            ("CAPA", "capa"),
            ("FLOSS", "floss"),
            ("Speakeasy", "speakeasy"),
        )
    )
    steps.append(("Final", analysis.get("status") or "QUEUED"))
    pipeline.markdown(
        '<div class="detail-pipeline">'
        + "".join(
            f'<div class="pipeline-node"><div class="pipeline-name">{label}</div>'
            f"{pipeline_state_markup(status)}</div>"
            for label, status in steps
        )
        + "</div>",
        unsafe_allow_html=True,
    )

    deep = detail_section(shell, "심층 분석", "deep")
    render_deep_analysis(analysis, deep, state)


def render_progressive_result(analysis, target=st):
    """기존 진입점도 동일한 상세 shell을 사용한다."""
    render_result_detail(analysis, target)


def deep_search_needle(query):
    """검색어를 비교용으로 정리한다. 비어 있으면 None(=검색하지 않음)."""
    needle = (query or "").strip().lower()
    return needle or None


def _cell_text(value):
    if isinstance(value, (list, tuple, set)):
        return " ".join(str(item) for item in value).lower()
    return str(value).lower()


def deep_search_rows(rows, needle):
    """어느 칸이든 검색어를 포함한 행만 남긴다. needle이 없으면 그대로."""
    if not needle:
        return rows
    return [
        row
        for row in rows
        if any(needle in _cell_text(value) for value in row.values())
    ]


def deep_search_table(target, rows, needle, **kwargs):
    """표를 그린다. 검색 중이면 일치한 칸을 파란색으로 칠한다."""
    if not needle:
        target.dataframe(rows, **kwargs)
        return
    if not rows:
        target.caption("검색어와 일치하는 항목이 없습니다.")
        return
    styled = pd.DataFrame(rows).style.map(
        lambda value: DEEP_SEARCH_HIGHLIGHT if needle in _cell_text(value) else ""
    )
    target.dataframe(styled, **kwargs)


def deep_search_label(title, shown, total, needle):
    """검색 중에는 표 제목 옆에 '일치 / 전체' 건수를 붙인다."""
    return f"{title} · {len(shown)} / {len(total)}건" if needle else title


def speakeasy_tables(speakeasy):
    """Speakeasy 결과를 화면에 그릴 표 단위로 나눈다. (API 표, 이벤트 표 3개)"""
    behavior = speakeasy.get("behavior") or {}
    calls = behavior.get("api_calls") or []
    counts = Counter(str(event["api_name"]) for event in calls if event.get("api_name"))
    tables = {
        "api": [{"API": name, "Calls": count} for name, count in counts.most_common()]
    }
    for key in ("files", "network", "registry"):
        tables[key] = [
            {str(field): str(value)[:200] for field, value in event.items()}
            for event in (behavior.get(key) or [])
        ]
    return tables


def render_speakeasy(target, speakeasy, needle=None):
    """실제 반환된 이벤트만 요약하며 행위 의미나 MITRE 매핑은 추측하지 않는다."""
    behavior = speakeasy.get("behavior") or {}
    original_counts = speakeasy.get("event_counts")
    if not isinstance(original_counts, dict):
        original_counts = {}
    calls = behavior.get("api_calls") or []
    counts = Counter(str(event["api_name"]) for event in calls if event.get("api_name"))
    total, unique = target.columns(2, gap=DETAIL_COLUMN_GAP)
    total.metric("API Calls", len(calls))
    unique.metric("Unique APIs", len(counts))
    target.caption("표시된 이벤트 기준 · unique 수는 api_name이 있는 호출 기준입니다.")
    if speakeasy.get("behavior_truncated"):
        original_calls = original_counts.get("api_calls")
        if isinstance(original_calls, int) and original_calls > len(calls):
            target.caption(f"API 호출 총 {original_calls}개 중 {len(calls)}개 미리보기")
        else:
            target.caption("행동 이벤트는 일부만 미리보기로 표시됩니다.")
    if speakeasy.get("adapter_events_truncated"):
        target.caption(
            "Speakeasy 결과 수집 시 카테고리별 100개를 넘는 상세 이벤트가 생략됐습니다."
        )
    if speakeasy.get("worker_events_truncated") or speakeasy.get("details_omitted"):
        target.caption("결과 크기 제한으로 일부 상세 이벤트가 저장되지 않았습니다.")
    elif speakeasy.get("events_truncated") and not speakeasy.get(
        "adapter_events_truncated"
    ):
        target.caption("일부 상세 이벤트가 저장되지 않았습니다.")
    tables = speakeasy_tables(speakeasy)
    if counts and needle:
        # 검색 중에는 미리보기 개수 제한 없이 일치한 API를 모두 보여 준다
        deep_search_table(
            target,
            deep_search_rows(tables["api"], needle),
            needle,
            hide_index=True,
            width="stretch",
        )
    elif counts:
        target.dataframe(
            [
                {"API": name, "Calls": count}
                for name, count in counts.most_common(SPEAKEASY_PREVIEW_LIMIT)
            ],
            hide_index=True,
            width="stretch",
        )
        if len(counts) > SPEAKEASY_PREVIEW_LIMIT:
            target.caption(f"호출 수 기준 상위 {SPEAKEASY_PREVIEW_LIMIT}개 API 표시")
    else:
        target.caption(
            "No API calls detected" if not calls else "API names unavailable"
        )

    for key, title, empty in (
        ("files", "Files", "No file activity detected"),
        ("network", "Network", "No network activity detected"),
        ("registry", "Registry", "No registry activity detected"),
    ):
        events = behavior.get(key) or []
        source_names = {
            "files": ("file_access", "dropped_files"),
            "network": ("network_events",),
            "registry": ("registry_access",),
        }[key]
        original_total = sum(
            count
            for name in source_names
            if isinstance((count := original_counts.get(name)), int)
        )
        suffix = (
            f" / 총 {original_total}개 중 미리보기"
            if speakeasy.get("behavior_truncated") and original_total > len(events)
            else ""
        )
        target.markdown(f"**{title}** · {len(events)} events{suffix}")
        if not events:
            target.caption(empty)
            continue
        if needle:
            deep_search_table(
                target,
                deep_search_rows(tables[key], needle),
                needle,
                hide_index=True,
                width="stretch",
            )
            continue
        # 키를 그대로 유지하고 중첩 값은 길이를 제한한 텍스트로 표시한다.
        rows = [
            {str(field): str(value)[:200] for field, value in event.items()}
            for event in events[:SPEAKEASY_PREVIEW_LIMIT]
        ]
        target.dataframe(rows, hide_index=True, width="stretch")
        if len(events) > SPEAKEASY_PREVIEW_LIMIT:
            target.caption(
                f"처음 {SPEAKEASY_PREVIEW_LIMIT}개 이벤트 표시 · 전체는 Raw details에서 확인"
            )
    if speakeasy.get("error"):
        target.warning(speakeasy["error"].get("message") or "Speakeasy 실행 오류")
    target.expander("Raw details", expanded=False).json(speakeasy)


def render_static_detail_notice(target, tool):
    """Distinguish successful analysis from omitted or unavailable detail storage."""
    status = tool.get("details_status")
    diagnostic = tool.get("details_error") or {}
    if status == "OMITTED_TOO_LARGE":
        actual, limit = diagnostic.get("actual_bytes"), diagnostic.get("limit_bytes")
        size = (
            f" ({actual:,} / {limit:,} bytes)"
            if isinstance(actual, int) and isinstance(limit, int)
            else ""
        )
        target.caption(
            f"분석은 완료됐지만 상세 결과가 저장 상한을 넘어 생략됐습니다{size}."
        )
    elif status == "ARCHIVE_FAILED":
        code = diagnostic.get("code")
        suffix = f" ({code})" if isinstance(code, str) else ""
        target.caption(f"분석은 완료됐지만 상세 결과 보관에 실패했습니다{suffix}.")


def render_deep_analysis(analysis, deep, state):
    status = state["deep"]
    deep.markdown(
        f"**{ {'QUEUED': '대기', 'RUNNING': '진행 중', 'COMPLETED': '완료', 'FAILED': '실패', 'NOT_REQUIRED': '미실행'}.get(status, status) }**"
    )
    if status == "QUEUED":
        deep.info("심층 분석 대기 중입니다. 완료되면 결과가 자동으로 갱신됩니다.")
    elif status == "RUNNING":
        deep.info("심층 분석이 진행 중입니다. 완료되면 결과가 자동으로 갱신됩니다.")
    elif status == "FAILED":
        error = analysis.get("deep_error") or analysis.get("error") or {}
        deep.error(
            "심층 분석에 실패했습니다. "
            + (error.get("message") or "오류 정보를 확인할 수 없습니다.")
        )
        if error.get("code"):
            deep.caption(
                f"코드 {error['code']} · 단계 {error.get('stage') or analysis.get('current_stage') or '-'}"
            )
    elif status == "COMPLETED":
        deep.success("심층 분석이 완료되었습니다.")
    else:
        deep.info("이 분석에는 심층 분석이 필요하지 않습니다.")
        return

    if status != "FAILED" and analysis.get("deep_error"):
        error = analysis["deep_error"]
        deep.warning(
            "심층 분석 상세 결과를 불러오지 못했습니다. "
            + (error.get("message") or "잠시 후 다시 확인해주세요.")
        )

    statuses = state["tools"]
    deep.markdown(deep_analysis_status_markup(statuses), unsafe_allow_html=True)

    if status not in {"COMPLETED", "FAILED"}:
        return

    # 완료·실패 시점에 존재하는 결과만 보여 준다. 일부 필드가 없어도 나머지
    # 결과와 Initial Analysis는 계속 렌더링한다.
    capa = analysis.get("capa") or {}
    capabilities = capa.get("capabilities") or []
    floss = analysis.get("floss") or {}
    strings = floss.get("strings") or {}
    string_rows = [
        {"Type": kind, "String": value}
        for kind, values in strings.items()
        for value in (values or [])
    ]
    speakeasy = analysis.get("speakeasy") or {}
    speakeasy_rows = [
        row
        for rows in (speakeasy_tables(speakeasy).values() if speakeasy else ())
        for row in rows
    ]
    show_evidence = evidence_visible(analysis)
    evidence = (analysis.get("evidence") or []) if show_evidence else []

    # 검색창 하나로 아래 표들을 한꺼번에 거른다.
    needle = deep_search_needle(
        deep.text_input(
            "Deep Analysis 결과에서 찾기",
            key="deep_filter_query",
            placeholder="문자열, API, 기술 ID, 규칙 이름 등의 일부",
        )
    )
    capa_hits = deep_search_rows(capabilities, needle)
    floss_hits = deep_search_rows(string_rows, needle)
    speakeasy_hits = deep_search_rows(speakeasy_rows, needle)
    evidence_hits = deep_search_rows(evidence, needle)
    if needle:
        hit_counts = [
            ("CAPA", capa_hits),
            ("FLOSS", floss_hits),
            ("Speakeasy", speakeasy_hits),
        ]
        if show_evidence:
            hit_counts.append(("MITRE", evidence_hits))
        deep.caption(" · ".join(f"{name} {len(hits)}" for name, hits in hit_counts))

    capa_box = deep.expander(
        deep_search_label("CAPA", capa_hits, capabilities, needle),
        expanded=bool(capa_hits) if needle else bool(capa),
    )
    if capabilities:
        deep_search_table(capa_box, capa_hits, needle, hide_index=True, width="stretch")
    else:
        capa_box.caption(f"Status: {statuses.get('capa', 'NOT_REQUIRED')}")
    render_static_detail_notice(capa_box, capa)

    floss_box = deep.expander(
        deep_search_label("FLOSS", floss_hits, string_rows, needle),
        expanded=bool(floss_hits) if needle else bool(floss),
    )
    if string_rows:
        deep_search_table(
            floss_box, floss_hits, needle, hide_index=True, width="stretch"
        )
    else:
        floss_box.caption(f"Status: {statuses.get('floss', 'NOT_REQUIRED')}")
    if floss.get("limited_mode"):
        action = (
            "분석했습니다"
            if floss.get("status") == "COMPLETED"
            else "분석을 시도했습니다"
        )
        floss_box.caption(
            f"FLOSS 제한 모드: 정적 문자열 중심으로 {action}. stack·tight·decoded·언어별 추가 문자열은 분석하지 않았습니다."
        )
    render_static_detail_notice(floss_box, floss)

    speakeasy_box = deep.expander(
        deep_search_label("Speakeasy", speakeasy_hits, speakeasy_rows, needle),
        expanded=bool(speakeasy_hits) if needle else bool(speakeasy),
    )
    if speakeasy:
        render_speakeasy(speakeasy_box, speakeasy, needle)
    else:
        speakeasy_box.caption(f"Status: {statuses.get('speakeasy', 'NOT_REQUIRED')}")

    # 근거·해석·최종 평가는 심층 분석이 끝난 뒤에만 그린다. 대기·진행 중에는 위의
    # 상태 안내만 남긴다. 실패 시 MITRE는 확보된 부분 근거가 있을 때만 보여 준다.
    if show_evidence:
        evidence_box = deep.expander(
            deep_search_label("MITRE Evidence", evidence_hits, evidence, needle),
            expanded=bool(evidence_hits) if needle else bool(evidence),
        )
        if evidence:
            deep_search_table(
                evidence_box, evidence_hits, needle, hide_index=True, width="stretch"
            )
        else:
            evidence_box.caption("표시할 MITRE ATT&CK 근거가 없습니다.")

    if status != "COMPLETED":
        return

    llm = analysis.get("llm_summary") or {}
    if llm:
        llm_box = deep.expander("LLM Summary", expanded=True)
        llm_box.write(llm.get("summary") or "-")
        behaviors = llm.get("suspicious_behaviors") or []
        if behaviors:
            llm_box.markdown("\n".join(f"- {item}" for item in behaviors))
        if llm.get("analyst_notes"):
            llm_box.caption(llm["analyst_notes"])

    assessment = analysis.get("final_assessment") or {}
    if assessment:
        assessment_box = deep.expander("Final Assessment", expanded=True)
        assessment_box.write(
            f"**Final Verdict:** {assessment.get('final_verdict') or analysis.get('final_verdict') or '-'}"
        )
        assessment_box.write(f"**Disposition:** {assessment.get('disposition') or '-'}")
        assessment_box.write(assessment.get("reason") or "-")


def commit_receipt(batch_data):
    """접수 결과를 그 시점 그대로 session_state에 반영한다.

    submit_batch()가 요청 하나를 끝낼 때마다 호출하므로, 여러 ZIP 중 뒤 요청이
    실패하거나 중간에 화면이 다시 그려져도 앞서 성공한 batch_id/analyses/제외
    사유는 이미 저장되어 있다. 같은 접수의 뒤 호출은 누적된 상태를 덮어쓴다.

    분석 작업으로 등록된 건이 하나도 없으면 batch_id와 제외 사유만 저장하고
    결과 화면으로는 넘기지 않는다(False). 전건 SKIPPED인 ZIP처럼 백엔드가
    202 + analyses: [] 를 정상 반환하는 경우가 있기 때문이다. 이때 batch_data는
    저장하지 않는다 — analyses가 빈 batch_data가 폴링 경로로 들어가면 조회할
    대상 없이 완료 판정이 나기 때문이다.

    반환: 결과 화면으로 넘길 수 있으면(등록된 분석이 하나 이상) True
    """
    analyses = batch_data.get("analyses") or []

    # 접수 단계의 제외/실패 사유는 등록된 분석이 없어도 화면에 남겨야 한다
    st.session_state.intake_receipt = batch_data

    if not analyses:
        return False

    groups = group_batch_analyses(analyses)
    initial_group = "needs_review"
    initial_analysis = (
        groups[initial_group][0] if groups[initial_group] else analyses[0]
    )
    st.session_state.batch_data = batch_data
    st.session_state.batch_ids = batch_id_list(batch_data)
    st.session_state.batch_results = analyses
    if not st.session_state.get("selected_analysis_id"):
        st.session_state.selected_analysis_id = initial_analysis["analysis_id"]
        st.session_state.analysis_result = initial_analysis
        # 첫 분석이 등록된 시점부터 폴링 상한을 센다
        st.session_state.poll_started_at = time.monotonic()
        st.session_state.poll_timed_out = False
    return True


def render_intake_notice(target, receipt):
    """접수 단계에서 제외되거나 실패한 입력을 분석 목록과 분리해 알린다."""
    skipped = receipt.get("skipped") or []
    errors = receipt.get("errors") or []
    if not skipped and not errors:
        return

    for item in errors:
        target.error(
            f"접수 실패 · {item['filename']} — {item['message']} (코드 {item['code']})"
        )

    if skipped:
        target.warning(f"분석 대상에서 제외된 입력 {len(skipped)}건")
        target.dataframe(
            [
                {
                    "File": item["filename"],
                    "Source": item["source"] or "직접 업로드",
                    "Reason": item["reason"],
                    "Code": item["reason_code"],
                }
                for item in skipped
            ],
            hide_index=True,
            width="stretch",
            height=min(38 * (len(skipped) + 1), 220),
        )


def normalize_hash_query(value):
    """검색어를 백엔드가 받는 형태로 맞춘다.

    붙여넣기에는 앞뒤 공백이, 도구 출력에는 대문자 해시가 섞여 들어온다.
    백엔드 정규식은 소문자만 받으므로 여기서 한 번 정규화한다.
    """
    return (value or "").strip().lower()


def is_valid_sha256(value):
    return SHA256_PATTERN.fullmatch(value or "") is not None


def search_result_view(full):
    """검색 응답 한 건을 상세 화면이 읽는 평면 뷰로 옮긴다.

    GET /analyses 의 analyses 항목은 GET /analyses/{id} 와 같은 종합 결과라서
    to_view()를 그대로 쓸 수 있다. 다만 to_view()는 filename/sha256/size를
    previous에서 물려받는 전제이므로, 접수 경로의 entry_view()가 채우던
    기본 키를 여기서 응답으로 직접 채운다.
    """
    base = {
        "analysis_id": full.get("analysis_id"),
        "batch_id": full.get("batch_id"),
        "created_at": full.get("created_at"),
        "sha256": full.get("sha256") or "",
        "filename": full.get("filename") or "(이름 없음)",
        "file_size": full.get("size_bytes") or 0,
    }
    return to_view(full, base)


def detail_blocker(analysis):
    """상세 화면으로 보낼 수 없는 이유. 보낼 수 있으면 None.

    상태가 COMPLETED여도 예외가 아니다. prediction/risk_signals는 백엔드
    스키마상 null이 될 수 있는데, 상세 화면은 그 값들을 `{...:.1%}` 처럼
    직접 서식에 넣으므로 비어 있으면 화면이 뜨는 대신 예외가 난다.
    이 경우 목록 표시까지만 하고 전환을 막는다.
    """
    status = analysis.get("status")
    # 심층 분석 실패는 Initial Analysis까지 숨길 이유가 아니다. 검색 이력에서도
    # 초기 결과가 완전한 HIGH_RISK_UNCERTAIN이면 실패 상태와 함께 열 수 있다.
    progressive_failure = status == "FAILED" and is_progressive_result(analysis)
    if status != "COMPLETED" and not progressive_failure:
        return f"완료된 분석만 상세 화면으로 열 수 있습니다. (상태: {status or '알 수 없음'})"

    missing = [key for key in DETAIL_REQUIRED_FIELDS if analysis.get(key) is None]
    if missing:
        return "상세 화면에 필요한 모델 결과가 이 이력에 없습니다: " + ", ".join(
            missing
        )
    return None


def clear_hash_search():
    """검색 결과만 비운다. 입력창 값은 그대로 둔다(위젯 키는 건드리지 않는다)."""
    for key in HASH_SEARCH_KEYS:
        st.session_state.pop(key, None)


def run_hash_search(query):
    """해시 하나를 조회해 결과를 검색 전용 키에만 남긴다.

    조회만으로는 batch/polling 상태를 전혀 바꾸지 않는다. 진행 중인 접수를
    검색이 끊어 놓지 않기 위해서다.
    """
    st.session_state.pop("hash_search", None)
    st.session_state.pop("hash_search_selector", None)

    if not is_valid_sha256(query):
        st.session_state.hash_search_error = (
            "SHA-256은 16진수 64자리여야 합니다. 입력을 확인하세요."
        )
        return

    st.session_state.pop("hash_search_error", None)
    try:
        with st.spinner("분석 이력을 조회하는 중입니다..."):
            response = api_client.search_analyses(
                query, limit=HASH_SEARCH_LIMIT, sort="newest"
            )
    except ApiError as e:
        st.session_state.hash_search_error = f"검색 실패: {e.message} (코드 {e.code})"
        return

    st.session_state.hash_search = {
        "query": query,
        # 없는 해시는 404가 아니라 total_count 0으로 온다. 결과 없음은 건수로 본다.
        "total_count": response.get("total_count") or 0,
        "analyses": [
            search_result_view(item) for item in (response.get("analyses") or [])
        ],
    }


def open_search_result(analysis_id):
    """검색 결과 한 건을 기존 상세 화면으로 넘긴다.

    접수 흐름과 상세 화면은 analysis_result/batch_data를 함께 쓴다. 배치
    상태를 남겨 두면 상세 대신 폴링 패널이나 배치 표가 먼저 뜨고,
    sync_selected_analysis()가 analysis_result를 덮어쓴다. 그래서 전환
    직전에 배치·폴링 상태를 비운다.

    selected_analysis_id는 일부러 비워 둔 채로 남긴다 — 값이 남아 있으면
    다음 접수에서 commit_receipt()가 첫 분석을 자동 선택하지 못한다.

    반환: 전환했으면 True
    """
    search = st.session_state.get("hash_search") or {}
    selected = next(
        (
            analysis
            for analysis in search.get("analyses") or []
            if analysis.get("analysis_id") == analysis_id
        ),
        None,
    )
    if selected is None or detail_blocker(selected):
        return False

    if selected.get("initial_verdict") == "HIGH_RISK_UNCERTAIN":
        selected = load_deep_result_once(selected)

    reset_analysis_result()
    clear_hash_search()
    st.session_state.analysis_result = selected
    return True


def hash_search_rows(analyses):
    """백엔드가 실제로 주는 필드만 표로 옮긴다."""
    return [
        {
            "Created At": analysis.get("created_at") or "-",
            "Analysis ID": analysis.get("analysis_id") or "-",
            "File": analysis.get("filename") or "-",
            "Status": analysis.get("status") or "-",
            "Initial Verdict": analysis.get("initial_verdict") or "-",
            "Final Verdict": analysis.get("final_verdict") or "-",
            # 분석가가 판정을 수정한 이력도 배치 표와 같은 글자로 보여 준다
            REVIEW_COLUMN: review_mark(analysis),
        }
        for analysis in analyses
    ]


def render_hash_search_results(target):
    """조회 결과를 목록으로 보여주고, 열 수 있는 건만 상세로 잇는다."""
    search = st.session_state.get("hash_search")
    if not search:
        return

    analyses = search.get("analyses") or []
    total = search.get("total_count") or 0
    if not analyses:
        target.info(
            "이 SHA-256으로 접수된 분석 이력이 없습니다. "
            f"({truncate_hash(search.get('query') or '-')})"
        )
        return

    rows = hash_search_rows(analyses)
    target.caption(f"분석 이력 {total}건")
    if total > len(analyses):
        # 이번 브랜치는 페이지 이동 UI 없이 최신 구간만 보여준다.
        target.info(f"이력이 {total}건입니다. 최신 {len(analyses)}건만 표시합니다.")
    target.dataframe(
        rows,
        hide_index=True,
        width="stretch",
        height=min(38 * (len(rows) + 1), 300),
    )

    analysis_by_id = {analysis["analysis_id"]: analysis for analysis in analyses}
    selector_key = "hash_search_selector"
    selected_id = target.selectbox(
        "상세 보기할 분석 선택",
        options=list(analysis_by_id),
        format_func=lambda analysis_id: (
            f"{analysis_by_id[analysis_id]['filename']} · "
            f"{analysis_by_id[analysis_id]['status']} · {analysis_id}"
        ),
        key=selector_key,
    )
    selected = analysis_by_id.get(
        selected_id or st.session_state.get(selector_key) or next(iter(analysis_by_id))
    )
    if selected is None:
        return

    blocker = detail_blocker(selected)
    if blocker:
        target.info(blocker)
        return

    if target.button(
        "상세 보기", key="hash_search_open", type="primary"
    ) and open_search_result(selected["analysis_id"]):
        st.rerun()


def render_hash_search():
    """업로드 패널 아래의 SHA-256 분석 이력 검색 패널.

    접수(unified upload)와 폴링에는 관여하지 않는다. 조회만으로는 어떤
    batch/polling 상태도 바꾸지 않고, 사용자가 상세 보기를 누른 순간에만
    화면을 기존 상세 결과로 전환한다.
    """
    panel = st.container(border=True, key="hash_search_panel")
    panel.markdown(
        '<div class="batch-panel-title">분석 이력 검색</div>',
        unsafe_allow_html=True,
    )
    panel.caption(
        "SHA-256으로 지난 분석을 찾습니다. 같은 파일을 여러 번 접수했으면 "
        "이력이 모두 나옵니다."
    )

    query_col, button_col = panel.columns([5, 1])
    raw_query = query_col.text_input(
        "SHA-256",
        key="hash_search_input",
        placeholder="소문자/대문자 구분 없이 64자리 SHA-256",
        label_visibility="collapsed",
    )
    if button_col.button("검색", key="hash_search_button", width="stretch"):
        run_hash_search(normalize_hash_query(raw_query))

    error = st.session_state.get("hash_search_error")
    if error:
        panel.error(error)
    render_hash_search_results(panel)


def render_input_view():
    """Render the unified PE/DLL/ZIP batch input controls."""
    st.title("EXCEPT 04 Trust Triage")
    st.caption("신뢰 기반 악성코드 트리아지 대시보드")

    input_panel = st.container(border=True, key="batch_input_panel")
    input_panel.markdown(
        '<div class="batch-panel-title">분석 입력</div>',
        unsafe_allow_html=True,
    )

    uploaded_files = input_panel.file_uploader(
        "PE 파일(.exe/.dll)과 ZIP을 함께 선택할 수 있습니다",
        type=["exe", "dll", "zip"],
        key="batch_file_uploader",
        on_change=reset_analysis_result,
        accept_multiple_files=True,
    )
    file_descriptors = uploaded_descriptors(uploaded_files)

    if file_descriptors:
        input_panel.dataframe(
            [
                {
                    "File": descriptor["filename"],
                    "Type": descriptor["kind"],
                    "Size": format_file_size(descriptor["size"]),
                }
                for descriptor in file_descriptors
            ],
            hide_index=True,
            width="stretch",
            height=min(38 * (len(file_descriptors) + 1), 260),
        )

    pe_count = sum(1 for d in file_descriptors if d["kind"] == "PE")
    zip_count = sum(1 for d in file_descriptors if d["kind"] == "ZIP")
    empty_names = [d["filename"] for d in file_descriptors if d["size"] == 0]

    # 개수 상한만 접수를 막는다. 나머지 판정은 백엔드가 하고 사유를 돌려준다.
    blocking = (
        f"PE/DLL은 한 번에 {MAX_BATCH_FILES}개까지 접수할 수 있습니다. "
        f"현재 {pe_count}개를 선택했습니다."
        if pe_count > MAX_BATCH_FILES
        else None
    )

    if file_descriptors:
        input_panel.caption(
            f"PE/DLL {pe_count}건은 한 번에, ZIP {zip_count}건은 파일별로 접수합니다. "
            "ZIP 해제와 내부 PE 검증은 백엔드가 수행합니다."
        )
    if empty_names:
        input_panel.warning(
            "내용이 빈 파일은 백엔드에서 제외됩니다: " + ", ".join(empty_names[:5])
        )
    if blocking:
        input_panel.error(blocking)

    if input_panel.button(
        "분석 시작",
        type="primary",
        disabled=not file_descriptors or bool(blocking),
    ):
        # 새 접수는 이전 접수 결과를 비우고 처음부터 누적한다
        reset_analysis_result()
        try:
            receipt = submit_batch(file_descriptors, on_progress=commit_receipt)
        except ApiError as e:
            input_panel.error(f"접수 실패: {e.message}")
        else:
            if commit_receipt(receipt):
                st.rerun()
            input_panel.info(
                "분석 작업으로 등록된 파일이 없습니다. 아래 사유를 확인하세요."
            )
            render_intake_notice(input_panel, receipt)
    elif st.session_state.get("intake_receipt"):
        # 접수 도중 화면이 다시 그려진 경우에도 직전 접수 결과는 남겨 둔다
        render_intake_notice(input_panel, st.session_state["intake_receipt"])


def render_batch_summary(batch_data):
    """배치 화면 머리글: 제목, Batch ID, 새 파일 분석 버튼.

    건수 타일과 분류 선택은 render_batch_triage()의 요약 카드가 그린다.
    """
    summary = derive_batch_summary(batch_data["analyses"])
    batch_data["summary"] = summary
    heading, action = st.columns([6, 1], vertical_alignment="center")
    heading.markdown(
        f"""
        <div class="batch-section-heading batch-section-heading-first batch-heading-inline">
            <span class="batch-title-large">분석 결과 요약</span>
            <span class="batch-context">Batch ID · {escape(batch_id_label(batch_data))}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    # 진행 중 화면에서는 이 버튼이 fragment 안에 있어서, 눌러도 fragment만 다시 그려진다.
    # 입력 화면으로 돌아가려면 st.rerun()으로 앱 전체를 다시 실행해야 한다.
    if action.button("새 파일 분석", key="batch_new_file_analysis", width="stretch"):
        reset_analysis_session()
        st.rerun()


def batch_group_rows(group_key, analyses):
    """Build group-specific table rows without leaking mock generation into UI."""
    if group_key == "total":
        # Group 열을 File 보다 먼저 넣어야 표 맨 왼쪽에 보인다.
        return [
            {
                "Group": triage_group_label(analysis),
                "File": analysis["filename"],
                "SHA-256": analysis.get("sha256") or "-",
                "Status": analysis["status"],
                "Initial Verdict": analysis.get("initial_verdict") or "-",
                "Reason": analysis.get("reason") or "-",
            }
            for analysis in analyses
        ]
    if group_key == "needs_review":
        return [
            {
                "File": analysis["filename"],
                "SHA-256": analysis.get("sha256") or "-",
                "Status": analysis["status"],
                REVIEW_COLUMN: review_mark(analysis),
                "JRR Reason": analysis["reason"],
                "Deep Analysis Status": deep_analysis_status_text(analysis),
            }
            for analysis in analyses
        ]
    if group_key in {"auto_malicious", "auto_benign"}:
        return [
            {
                "File": analysis["filename"],
                "SHA-256": analysis.get("sha256") or "-",
                "Status": analysis["status"],
                REVIEW_COLUMN: review_mark(analysis),
                "Calibrated Probability": (f"{analysis['calibrated_probability']:.4f}"),
                "Reason": analysis["reason"],
            }
            for analysis in analyses
        ]
    return [
        {
            "File": analysis["filename"],
            "SHA-256": analysis.get("sha256") or "-",
            "Status": analysis["status"],
            "Initial Verdict": analysis["initial_verdict"],
            "Reason": analysis["reason"],
        }
        for analysis in analyses
    ]


def render_batch_group_results(group_key, analyses, result_card=st):
    """Render one triage group and bind its selection to the detail view.

    표와 파일 선택은 요약 카드 안(result_card)에 이어서 그린다.
    """
    if not analyses:
        result_card.info("이 그룹에 해당하는 분석 결과가 없습니다.")
        return

    rows = batch_group_rows(group_key, analyses)
    result_card.dataframe(
        rows,
        hide_index=True,
        width="stretch",
        # 한 줄 35px(머리글 포함) + 테두리 3px. 38px로 잡으면 맨 아래에 빈 줄이 생긴다.
        height=min(35 * (len(rows) + 1) + 3, 300),
        # 64자 전체를 넣되 열 폭은 줄여 둔다. 셀을 클릭하면 전체 값을 보고 복사할 수 있다.
        column_config={"SHA-256": {"width": "medium"}},
    )

    analysis_by_id = {analysis["analysis_id"]: analysis for analysis in analyses}
    selector_key = "group_analysis_selector"
    selected_id = st.session_state.get(selector_key)
    if selected_id not in analysis_by_id:
        current_id = st.session_state.get("selected_analysis_id")
        selected_id = (
            current_id if current_id in analysis_by_id else next(iter(analysis_by_id))
        )
        st.session_state[selector_key] = selected_id
        st.session_state.selected_analysis_id = selected_id
        st.session_state.analysis_result = find_batch_analysis(selected_id)

    result_card.selectbox(
        "상세 분석 파일 선택",
        options=list(analysis_by_id),
        format_func=lambda analysis_id: (
            f"{analysis_by_id[analysis_id]['filename']} · "
            f"{analysis_by_id[analysis_id]['status']}"
        ),
        key=selector_key,
        on_change=select_analysis_result,
        args=(selector_key,),
    )

    selected = analysis_by_id.get(st.session_state.get(selector_key))
    if selected is not None and triage_group_key(selected) == "needs_review":
        result_card.markdown(
            f"""
            <div class="deep-status-row">
                <span class="deep-status-label">Deep Analysis</span>
                {deep_analysis_status_markup(selected["deep_analysis_status"])}
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_batch_triage(batch_data):
    """Render the analyst-first Batch Summary and result navigation.

    파일 검색은 그룹으로 나누기 직전에 목록을 한 번 거르는 것으로 끝난다.
    그룹 라벨 건수·표·선택 위젯·상세 연결은 걸러진 목록을 그대로 받아
    동작하므로 따로 손대지 않는다. 검색 결과가 없으면 안내만 남기고
    여기서 멈춘다 — 아래 상세 화면이 직전에 고른 파일을 계속 보여 주면
    "없음" 안내와 어긋나기 때문이다. analysis_result는 비우지 않으므로
    검색어를 지우거나 결과가 다시 생기면 이전 화면으로 그대로 돌아온다.
    """
    labels = BATCH_GROUP_LABELS
    options = tuple(labels)
    # 판정 수정 팝업이 남긴 '옮겨 간 그룹'. 그룹 위젯을 만들기 전에만 바꿀 수 있다.
    pending_group = st.session_state.pop("pending_batch_group", None)
    if pending_group in options:
        st.session_state.batch_group = pending_group

    batch_area = st.container(key="batch_triage_area")
    with batch_area:
        # 1. 머리글: Batch Summary, Batch ID, 새 파일 분석
        render_batch_summary(batch_data)
        render_intake_notice(st, batch_data)

        # 2. 검색
        query = st.text_input(
            "파일명 또는 SHA-256으로 찾기",
            key="batch_filter_query",
            placeholder="파일명 일부 또는 SHA-256 일부",
        )
        analyses = batch_data["analyses"]
        matched = filter_batch_analyses(analyses, query)
        searching = bool((query or "").strip())
        if searching:
            st.caption(f"검색 결과 {len(matched)}건 / 전체 {len(analyses)}건")
            if not matched:
                st.info("검색 조건에 맞는 파일이 없습니다.")
                st.stop()
        groups = group_batch_analyses(matched)
        totals = group_batch_analyses(analyses)
        # Total 타일은 걸러진 목록 전체를 그대로 보여 준다.
        groups["total"] = matched
        totals["total"] = analyses

        def count_text(shown, total):
            # 검색 중에는 "검색 결과 / 전체", 아닐 때는 숫자 하나만 보여 준다.
            return f"{shown} / {total}" if searching else f"{total}"

        # 3. 요약 + 분류 카드: 건수 타일을 눌러 분류를 고르고, 아래에 그 목록을 보여 준다.
        summary_card = st.container(border=True, key="batch_summary_card")
        with summary_card:
            # 타일 모양은 CSS(.st-key-batch_group)가 만든다. 첫 줄은 분류 이름, 둘째 줄은 건수.
            format_group = lambda key: (
                f"{labels[key]}\n{count_text(len(groups[key]), len(totals[key]))}"
            )
            if hasattr(st, "segmented_control"):
                group_options = dict(
                    options=options,
                    default="total",
                    format_func=format_group,
                    key="batch_group",
                    label_visibility="collapsed",
                )
                # Streamlit 1.50부터 생긴 width 옵션의 기본값("content")은 타일을 내용 크기로
                # 줄인다. 지원하는 버전에서는 카드 폭을 채우도록 "stretch"를 준다.
                if "width" in inspect.signature(st.segmented_control).parameters:
                    group_options["width"] = "stretch"
                group_key = st.segmented_control("분석 결과 분류", **group_options)
            else:
                group_key = st.radio(
                    "분석 결과 분류",
                    options=options,
                    index=0,
                    format_func=format_group,
                    key="batch_group",
                    horizontal=True,
                    label_visibility="collapsed",
                )
            group_key = group_key or "total"
            # 타일과 표 사이 구분선은 CSS(.st-key-batch_group의 border-bottom)가 그린다.
            render_batch_group_results(group_key, groups[group_key], summary_card)
            if searching and not groups[group_key]:
                # 매칭은 있지만 지금 보는 그룹에는 없다. render_batch_group_results()는
                # 빈 그룹에서 선택을 건드리지 않고 돌아오므로, 그대로 두면 검색과
                # 무관한 직전 파일의 상세가 아래에 남는다. 그룹 위젯은 이미 그려졌으니
                # 사용자가 건수가 표시된 그룹을 고르면 기존 선택 로직이 상세를 잇는다.
                # 그룹·선택·analysis_result는 바꾸지 않는다 — 검색어를 지우면 그대로 복귀.
                st.info(
                    f"검색 결과 {len(matched)}건은 다른 그룹에 있습니다. "
                    "위 분류에서 건수가 표시된 그룹을 선택하세요."
                )
                st.stop()
        if not groups[group_key]:
            # 빈 그룹에서 다른 그룹의 이전 상세 결과를 재사용하지 않는다.
            st.stop()
        st.markdown(
            '<div class="detail-section-break">선택 파일 상세 분석</div>',
            unsafe_allow_html=True,
        )


def render_polling_panel(batch_data, auto_refresh):
    """진행 상황만 보여주는 영역.

    그룹 테이블·selectbox·상세 결과는 여기에 넣지 않는다. 완료 후 화면과 구성이
    겹치면 자동 갱신 때마다 그 위젯들이 다시 그려지기 때문이다.
    """
    analyses = batch_data["analyses"]
    counts = poll_status_counts(analyses)
    total = len(analyses)
    finished = counts["COMPLETED"] + counts["FAILED"]

    st.markdown(
        f"""
        <div class="batch-section-heading batch-section-heading-first batch-heading-left">
            <span>분석 진행 중</span>
            <span class="batch-context">
                Batch ID · {escape(batch_id_label(batch_data))}
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    panel = st.container(border=True, key="batch_polling_panel")
    panel.markdown(
        f"""
        <div class="batch-summary-grid">
            <div class="batch-summary-item">
                <div class="batch-summary-label">Total</div>
                <div class="batch-summary-value">{total}</div>
            </div>
            <div class="batch-summary-item batch-summary-priority">
                <div class="batch-summary-label">Queued</div>
                <div class="batch-summary-value">{counts["QUEUED"]}</div>
            </div>
            <div class="batch-summary-item">
                <div class="batch-summary-label">Running</div>
                <div class="batch-summary-value">{counts["RUNNING"]}</div>
            </div>
            <div class="batch-summary-item">
                <div class="batch-summary-label">Completed</div>
                <div class="batch-summary-value">{counts["COMPLETED"]}</div>
            </div>
            <div class="batch-summary-item">
                <div class="batch-summary-label">Failed</div>
                <div class="batch-summary-value">{counts["FAILED"]}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    panel.progress(
        finished / total if total else 0.0,
        text=f"{finished} / {total} 처리 종료",
    )
    panel.dataframe(
        [
            {
                "File": analysis.get("filename", "(이름 없음)"),
                "Status": analysis.get("status") or "QUEUED",
            }
            for analysis in analyses
        ],
        hide_index=True,
        width="stretch",
        # 건수는 폴링 중 변하지 않으므로 높이가 흔들리지 않는다
        height=min(38 * (total + 1), 300),
    )

    elapsed = int(max(0.0, time.monotonic() - poll_started_at()))
    clock = f"{elapsed // 60:02d}:{elapsed % 60:02d}"
    if auto_refresh:
        panel.caption(
            f"경과 {clock} · {POLL_INTERVAL_SECONDS}초마다 이 영역만 자동 갱신됩니다."
        )
    else:
        panel.caption(f"경과 {clock} · 자동 갱신이 멈춘 상태입니다.")

    render_intake_notice(st, batch_data)


def render_progressive_batch_result(batch_data):
    """polling fragment 안에서 최신 선택 결과를 함께 보여 준다."""
    if not any(analysis.get("initial_verdict") for analysis in batch_data["analyses"]):
        return
    render_batch_triage(batch_data)
    selected = st.session_state.get("analysis_result") or {}
    render_result_detail(selected)


@st.fragment(run_every=POLL_INTERVAL_SECONDS)
def polling_fragment():
    """이 함수 안에서만 재실행된다.

    CSS 블록·상단 레이아웃·완료 결과 화면은 fragment 밖에 있어서 자동 갱신 대상이
    아니다. 모든 건이 종료되면 app 전체를 딱 한 번 재실행해 완료 화면으로 넘긴다.
    """
    batch_data = st.session_state.get("batch_data")
    if not batch_data:
        return

    still_running = refresh_batch(batch_data)
    sync_selected_analysis(batch_data)

    if not still_running:
        # 종료 조건 1: 전부 COMPLETED/FAILED. 완료 화면 전환용 app rerun 1회.
        st.rerun()

    if time.monotonic() - poll_started_at() > POLL_TIMEOUT_SECONDS:
        # 종료 조건 2: 상한 초과. fragment 렌더를 멈추게 해서 자동 갱신을 끊는다.
        st.session_state.poll_timed_out = True
        st.rerun()

    render_polling_panel(batch_data, auto_refresh=True)
    render_progressive_batch_result(batch_data)


def render_polling_view(batch_data):
    """진행 중 화면. 시간 초과 뒤에는 자동 갱신 없이 같은 패널을 그린다."""
    if st.session_state.get("poll_timed_out"):
        render_polling_panel(batch_data, auto_refresh=False)
        render_progressive_batch_result(batch_data)
        st.warning(
            f"{POLL_TIMEOUT_SECONDS // 60}분 안에 분석이 끝나지 않아 자동 갱신을 "
            "멈췄습니다. 백엔드 처리 상태를 확인한 뒤 다시 조회하세요."
        )
        st.button("지금 다시 확인", key="poll_resume", on_click=resume_polling)
        return

    polling_fragment()


st.set_page_config(
    page_title="EXCEPT 04 Trust Triage",
    page_icon="🛡️",
    layout="wide",
)

if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = False


def flip_theme():
    st.session_state.dark_mode = not st.session_state.dark_mode


dark = st.session_state.dark_mode

_, toggle_col = st.columns([12, 1])
with toggle_col:
    st.button(
        "",
        key="theme_toggle",
        on_click=flip_theme,
    )

TOGGLE_ICON = "var(--toggle-track)"

SUN_SHADOW = ", ".join(
    [f"0 0 0 2px {TOGGLE_ICON}"]  # 가운데 원
    + [
        f"{x}px {y}px 0 -1px {TOGGLE_ICON}"
        for x, y in [  # 햇살 8개
            (7, 0),
            (-7, 0),
            (0, 7),
            (0, -7),
            (5, 5),
            (-5, 5),
            (5, -5),
            (-5, -5),
        ]
    ]
)

LIGHT_THEME = {
    "bg": "#f8fafc",
    "surface": "#ffffff",
    "text": "#0f172a",
    "surface-muted": "#f8fafc",
    "text-2": "#334155",
    "text-3": "#475569",
    "text-muted": "#64748b",
    "text-faint": "#94a3b8",
    "border": "#e2e8f0",
    "border-strong": "#cbd5e1",
    "neutral-bg": "#f1f5f9",
    "danger-fg": "#991b1b",
    "danger-bg": "#fee2e2",
    "danger-border": "#fecaca",
    "success-fg": "#166534",
    "success-bg": "#dcfce7",
    "success-border": "#bbf7d0",
    "warning-fg": "#9a3412",
    "warning-bg": "#ffedd5",
    "warning-border": "#fed7aa",
    "warning-soft": "#fff7ed",
    "info-fg": "#1d4ed8",
    "info-bg": "#dbeafe",
    "info-border": "#bfdbfe",
    "info-strong": "#1e40af",
    "info-strong-border": "#93c5fd",
    "chart-malicious": "#dc2626",
    "chart-benign": "#2563eb",
    "df-filter": "none",
    # 토글
    "toggle-track": "#0f172a",
    "toggle-knob": "#ffffff",
    "toggle-knob-x": "4px",  # 손잡이 왼쪽
    "icon-size": "4px",
    "icon-top": "12px",
    "icon-offset": "10px",
    "icon-bg": TOGGLE_ICON,
    "icon-shadow": SUN_SHADOW,  # 해
}

DARK_THEME = {
    "bg": "#020617",
    "surface": "#0f172a",
    "text": "#f1f5f9",
    "surface-muted": "#1e293b",
    "text-2": "#cbd5e1",
    "text-3": "#a8b3c4",
    "text-muted": "#94a3b8",
    "text-faint": "#64748b",
    "border": "#1e293b",
    "border-strong": "#334155",
    "neutral-bg": "#1e293b",
    "danger-fg": "#fca5a5",
    "danger-bg": "#450a0a",
    "danger-border": "#7f1d1d",
    "success-fg": "#86efac",
    "success-bg": "#052e16",
    "success-border": "#14532d",
    "warning-fg": "#fdba74",
    "warning-bg": "#431407",
    "warning-border": "#7c2d12",
    "warning-soft": "#2a1106",
    "info-fg": "#93c5fd",
    "info-bg": "#172554",
    "info-border": "#1e3a8a",
    "info-strong": "#bfdbfe",
    "info-strong-border": "#1e40af",
    "chart-malicious": "#f87171",
    "chart-benign": "#60a5fa",
    "df-filter": "invert(1) hue-rotate(180deg)",
    # 토글
    "toggle-track": "#f1f5f9",
    "toggle-knob": "#0f172a",
    "toggle-knob-x": "calc(100% - 28px)",  # 손잡이 오른쪽
    "icon-size": "12px",
    "icon-top": "7px",
    "icon-offset": "6px",
    "icon-bg": "transparent",
    "icon-shadow": f"inset -4px -2px 0 0 {TOGGLE_ICON}",  # 달
}


def streamlit_theme_is_dark():
    """Streamlit이 실제로 쓰는 테마가 다크인지. 표(st.dataframe)는 이 테마로 그려진다.

    테마를 고정하지 않으면 Streamlit은 브라우저/OS 설정을 따른다. 그래서 Chrome이
    다크 모드면 앱이 라이트여도 표는 검게 그려진다. 알 수 없으면 라이트로 본다.
    """
    theme = getattr(st.context, "theme", None)  # Streamlit 1.46+
    return getattr(theme, "type", None) == "dark"


palette = dict(DARK_THEME if dark else LIGHT_THEME)
# 표는 CSS로 색을 바꿀 수 없어 필터로 뒤집는다. Streamlit 테마와 앱 테마가
# 다를 때만 뒤집어야 시스템 다크 모드에서도 표 색이 앱과 맞는다.
palette["df-filter"] = (
    "invert(1) hue-rotate(180deg)" if dark != streamlit_theme_is_dark() else "none"
)
css_vars = "\n".join(f"--{name}: {value};" for name, value in palette.items())
st.markdown(f"<style>:root {{ {css_vars} }}</style>", unsafe_allow_html=True)

st.markdown(
    """
    <style>
        .stApp {
            background: var(--bg);
            color: var(--text);
        }
        
        /* 트랙 (알약 모양 바탕) */
        .st-key-theme_toggle button {
            position: relative;
            width: 60px; height: 32px; min-height: 32px;
            padding: 0;
            border-radius: 999px;
            border: 2px solid var(--toggle-track);
            background: var(--toggle-track);
            transition: background .25s, border-color .25s;
        }
        
        .st-key-theme_toggle button:hover,
        .st-key-theme_toggle button:focus,
        .st-key-theme_toggle button:active {
            background: var(--toggle-track) !important;
        }
        
        /* 손잡이 */
        .st-key-theme_toggle button::before {
            content: "";
            position: absolute; top: 2px;
            left: var(--toggle-knob-x);
            width: 24px; height: 24px;
            border-radius: 50%;
            background: var(--toggle-knob);
            transition: left .25s;
        }
        
        /* 아이콘 (해 또는 달) */
        .st-key-theme_toggle button::after {
            content: "";
            position: absolute;
            top: var(--icon-top);
            left: calc(var(--toggle-knob-x) + var(--icon-offset));
            width: var(--icon-size); height: var(--icon-size);
            border-radius: 50%;
            background: var(--icon-bg);
            box-shadow: var(--icon-shadow);
            transform: rotate(-20deg);
            transition: left .25s;
        }

        header[data-testid="stHeader"],
        [data-testid="stToolbar"],
        [data-testid="stAppDeployButton"],
        [data-testid="stMainMenu"],
        #MainMenu {
            display: none !important;
        }

        [data-testid="stDecoration"] {
            display: none !important;
        }

        .block-container {
            max-width: 1450px;
            margin-top: 0 !important;
            padding-top: 1rem !important;
            padding-bottom: 1.5rem;
            transform: none !important;
        }

        .block-container [data-testid="stVerticalBlock"] {
            gap: 1.5rem;
        }

        /* Result-only spacing: native Streamlit cards retain their common padding. */
        .st-key-result_detail_shell {
            --detail-section-gap: 1.5rem;
            --detail-gap: 1rem;
            --detail-title-gap: 0.5rem;
        }

        .block-container .st-key-result_detail_shell {
            gap: var(--detail-section-gap);
        }

        .st-key-result_detail_shell [data-testid="stVerticalBlock"] {
            gap: var(--detail-gap);
        }

        .st-key-result_detail_shell [class*="_section"] {
            gap: var(--detail-title-gap);
        }

        .detail-verdicts, .detail-metrics, .detail-pipeline {
            display: grid;
            align-items: start;
            gap: var(--detail-gap);
        }

        .detail-verdicts {
            grid-template-columns: repeat(3, minmax(0, 1fr));
        }

        /* 분석 파이프라인은 좁은 오른쪽 칸에 들어가므로 2칸 x 3줄 */
        .detail-pipeline {
            grid-template-columns: repeat(2, minmax(0, 1fr));
        }

        /* 단계가 홀수(5개)라 마지막 Final은 두 칸을 모두 쓴다 */
        .detail-pipeline .pipeline-node:last-child:nth-child(odd) {
            grid-column: 1 / -1;
        }

        /* 분석 요약 첫 줄: 왼쪽은 판정 3개, 오른쪽은 라우팅 사유 */
        .detail-top {
            display: grid;
            grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
            align-items: start;
            gap: var(--detail-gap);
        }

        .detail-route-detail {
            border-left: 1px solid var(--border);
            padding-left: 1.25rem;
            min-width: 0;
        }

        .route-detail-value {
            color: var(--text);
            font-size: 0.95rem;
            line-height: 1.45;
            margin-bottom: 0.5rem;
            overflow-wrap: anywhere;
        }

        .route-detail-value:last-child {
            margin-bottom: 0;
        }

        .detail-metrics {
            grid-template-columns: repeat(5, minmax(0, 1fr));
        }

        .detail-verdicts > div, .detail-metrics > div {
            min-width: 0;
        }

        .st-key-result_detail_shell .status-badge {
            white-space: normal;
            overflow-wrap: anywhere;
        }

        @media (max-width: 700px) {
            .detail-verdicts, .detail-metrics {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .detail-top {
                grid-template-columns: 1fr;
            }

            .detail-route-detail {
                border-left: 0;
                border-top: 1px solid var(--border);
                padding-left: 0;
                padding-top: 0.75rem;
            }
        }

        div[data-testid="stVerticalBlockBorderWrapper"] {
            background: var(--surface);
            border-color: var(--border);
            box-sizing: border-box;
            color: var(--text);
        }

        hr {
            margin: 0.5rem 0;
        }

        .status-badge,
        .pipeline-badge {
            display: inline-block;
            border: 1px solid transparent;
            border-radius: 999px;
            font-size: 0.8rem;
            font-weight: 650;
            line-height: 1.2;
            padding: 0.5rem 1rem;
            white-space: nowrap;
        }

        .badge-danger {
            color: var(--danger-fg);
            background: var(--danger-bg);
            border-color: var(--danger-border);
        }

        .badge-success {
            color: var(--success-fg);
            background: var(--success-bg);
            border-color: var(--success-border);
        }

        .badge-warning {
            color: var(--warning-fg);
            background: var(--warning-bg);
            border-color: var(--warning-border);
        }

        .badge-info {
            color: var(--info-fg);
            background: var(--info-bg);
            border-color: var(--info-border);
        }

        .badge-neutral {
            color: var(--text-3);
            background: var(--neutral-bg);
            border-color: var(--border);
        }

        .route-focus {
            padding: 0 0 0.5rem;
            text-align: center;
        }

        .route-label {
            color: var(--text-muted);
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.08em;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
        }

        .route-badge {
            display: inline-block;
            color: var(--info-strong);
            background: var(--info-bg);
            border: 1px solid var(--info-strong-border);
            border-radius: 0.55rem;
            font-size: 1.05rem;
            font-weight: 750;
            letter-spacing: 0.04em;
            padding: 0.5rem 1rem;
        }

        .reason-row {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 0.5rem;
            margin-bottom: 1rem;
        }

        .reason-chip {
            color: var(--text-2);
            background: var(--surface-muted);
            border: 1px solid var(--border-strong);
            border-radius: 999px;
            font-size: 0.78rem;
            padding: 0.5rem 1rem;
        }

        .secondary-text {
            color: var(--text-muted);
            font-size: 0.85rem;
            overflow-wrap: anywhere;
        }

        .st-key-batch_input_panel [data-testid="stVerticalBlock"],
        .st-key-batch_triage_area [data-testid="stVerticalBlock"],
        .st-key-batch_polling_panel [data-testid="stVerticalBlock"],
        .st-key-batch_group_results [data-testid="stVerticalBlock"] {
            gap: 1.5rem;
        }

        .batch-panel-title,
        .batch-section-heading {
            color: var(--text);
            font-size: 1.05rem;
            font-weight: 700;
            line-height: 1.35;
        }

        .batch-panel-title {
            margin-bottom: 1rem;
        }

        .batch-section-heading {
            display: flex;
            align-items: baseline;
            justify-content: space-between;
            gap: 1rem;
            margin-top: 1.5rem;
            margin-bottom: 1rem;
        }

        .batch-section-heading-first {
            margin-top: 1.5rem;
        }

        .batch-heading-left {
            justify-content: flex-start;
        }

        .batch-heading-inline {
            justify-content: flex-start;
            margin-top: 0;
            /* Streamlit 마크다운의 -1rem 여백을 상쇄해 버튼과 세로 가운데를 맞춘다 */
            margin-bottom: 1rem;
        }
        
        .batch-title-large {
            font-size: 1.75rem;
            font-weight: 700;
            line-height: 1.2;
        }

        .batch-context {
            color: var(--text-muted);
            font-size: 0.76rem;
            font-weight: 500;
        }

        .batch-summary-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            align-items: stretch;
            gap: 1.5rem;
            padding: 1.5rem;
        }

        .batch-summary-item {
            display: flex;
            flex-direction: column;
            justify-content: center;
            min-width: 0;
            padding: 1rem;
            text-align: center;
        }

        .batch-summary-priority {
            background: var(--warning-soft);
            border: 1px solid var(--warning-border);
            border-radius: 0.5rem;
        }

        .batch-summary-priority .batch-summary-label,
        .batch-summary-priority .batch-summary-value {
            color: var(--warning-fg);
        }

        .batch-summary-label {
            color: var(--text-muted);
            font-size: 0.72rem;
            line-height: 1.2;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
        }

        .batch-summary-value {
            color: var(--text);
            font-size: 1.15rem;
            font-weight: 720;
            line-height: 1.2;
        }

        .deep-status-row {
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }

        .deep-status-label {
            color: var(--text-muted);
            font-size: 0.76rem;
            font-weight: 650;
        }

        .deep-status-list {
            display: inline-flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 0.5rem;
        }

        .deep-status-item {
            color: var(--text-2);
            background: var(--surface-muted);
            border: 1px solid var(--border-strong);
            border-radius: 999px;
            font-size: 0.72rem;
            line-height: 1.4;
            padding: 0.2rem 0.7rem;
        }

        .detail-section-break {
            color: var(--text-3);
            border-top: 1px solid var(--border);
            font-size: 0.82rem;
            font-weight: 650;
            margin-top: 2rem;
            padding-top: 1rem;
        }

        .file-header {
            display: flex;
            align-items: flex-end;
            justify-content: space-between;
            gap: 1rem;
            border-bottom: 1px solid var(--border);
            padding: 0 0 1rem;
        }

        .file-title {
            color: var(--text);
            font-size: 1rem;
            font-weight: 700;
            line-height: 1.25;
        }

        .file-hash,
        .file-meta {
            color: var(--text-muted);
            font-size: 0.76rem;
            line-height: 1.45;
        }

        .file-meta {
            display: flex;
            flex-wrap: wrap;
            justify-content: flex-end;
            gap: 0.5rem 1rem;
            text-align: right;
        }

        .verdict-arrow {
            color: var(--text-faint);
            font-size: 1rem;
            text-align: center;
        }

        .summary-top {
            display: grid;
            grid-template-columns: 1.35fr 0.15fr 1.15fr 0.7fr 1fr;
            align-items: center;
            gap: 1rem;
            padding: 1rem;
        }

        .summary-bottom {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 1rem;
            padding: 1rem;
        }

        .summary-divider {
            border-top: 1px solid var(--border);
            margin: 0.5rem 0;
        }

        .summary-label {
            color: var(--text-muted);
            font-size: 0.7rem;
            line-height: 1.2;
            margin-bottom: 0.5rem;
        }

        /* 지표 이름 위에 마우스를 올리면(또는 Tab으로 이동하면) 설명을 띄운다 */
        .metric-tip {
            position: relative;
            border-bottom: 1px dotted var(--text-faint);
        }
        .metric-tip::after {
            content: attr(data-tip);
            position: absolute;
            left: 0;
            bottom: calc(100% + 0.5rem);
            z-index: 1000;
            width: max-content;
            max-width: 20rem;
            word-break: keep-all;  /* 한국어를 단어 중간에서 끊지 않는다 */
            padding: 0.45rem 0.65rem;
            border-radius: 0.4rem;
            background: var(--text);
            color: var(--surface);
            box-shadow: 0 4px 12px rgba(15, 23, 42, 0.18);
            font-size: 0.75rem;
            font-weight: 500;
            line-height: 1.45;
            white-space: pre-line;
            opacity: 0;
            visibility: hidden;
            pointer-events: none;
            transition: opacity 0.12s ease-in-out;
        }
        .metric-tip:hover::after,
        .metric-tip:focus-visible::after {
            opacity: 1;
            visibility: visible;
        }
        /* 맨 오른쪽 지표의 설명은 오른쪽 끝에 맞춰 화면 밖으로 넘치지 않게 한다 */
        .detail-metrics > div:last-child .metric-tip::after {
            left: auto;
            right: 0;
        }

        .summary-value {
            color: var(--text);
            font-size: 0.98rem;
            font-weight: 650;
            line-height: 1.25;
            white-space: nowrap;
        }

        .summary-score {
            font-size: 1.35rem;
            font-weight: 750;
        }

        .evidence-grid {
            display: grid;
            grid-template-columns: 1.2fr 1fr;
            gap: 1rem;
        }

        .evidence-section + .evidence-section {
            border-left: 1px solid var(--border);
            padding-left: 1rem;
        }

        .evidence-title {
            color: var(--text-2);
            font-size: 0.8rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }

        .evidence-item {
            color: var(--text-2);
            font-size: 0.74rem;
            line-height: 1.35;
            margin-bottom: 0.5rem;
        }

        .technique-id {
            color: var(--info-fg);
            font-weight: 650;
        }

        .pipeline-flow {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-top: 0.5rem;
            padding-bottom: 1rem;
        }

        .pipeline-node {
            flex: 1 1 0;
            min-width: 0;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 0.45rem;
            padding: 0.5rem;
            text-align: center;
        }

        .pipeline-name {
            color: var(--text);
            font-size: 0.82rem;
            font-weight: 650;
            line-height: 1.2;
        }

        .pipeline-state {
            display: inline-block;
            border-radius: 999px;
            font-size: 0.7rem;
            font-weight: 650;
            line-height: 1.15;
            margin-top: 0.5rem;
            padding: 0.5rem;
        }

        .pipeline-complete {
            color: var(--success-fg);
            background: var(--success-bg);
        }

        .pipeline-skipped {
            color: var(--text-3);
            background: var(--neutral-bg);
        }

        .pipeline-running {
            color: var(--info-fg);
            background: var(--info-bg);
        }

        .pipeline-failed {
            color: var(--danger-fg);
            background: var(--danger-bg);
        }

        .pipeline-arrow {
            flex: 0 0 auto;
            color: var(--text-faint);
            font-size: 0.9rem;
        }

        /* 카드 (border=True 컨테이너) */
        div[data-testid="stVerticalBlock"]:is([class*="_card"], [class*="-card"], [class*="_panel"], .st-key-batch_group_results) {
            background: var(--surface);
            border-color: var(--border);
        }
        
        /* 제목, 위젯 라벨, 캡션 */
        h1, h2, h3, h4, h5, h6 { color: var(--text); }
        [data-testid="stWidgetLabel"], [data-testid="stWidgetLabel"] p { color: var(--text-2); }
        [data-testid="stCaptionContainer"] { color: var(--text-muted); }
        
        /* 일반 버튼 (테마 토글 버튼은 제외) */
        .stElementContainer:not(.st-key-theme_toggle) button[data-testid="stBaseButton-secondary"] {
            background: var(--surface);
            border-color: var(--border-strong);
            color: var(--text);
        }
        .stElementContainer:not(.st-key-theme_toggle) button[data-testid="stBaseButton-secondary"]:hover {
            border-color: var(--text-muted);
            color: var(--text);
        }
        /* 비활성 버튼. Streamlit의 :disabled:hover 기본 스타일이 덮어쓰지 않도록 !important */
        .stElementContainer:not(.st-key-theme_toggle) button[data-testid="stBaseButton-secondary"]:disabled,
        .stElementContainer:not(.st-key-theme_toggle) button[data-testid="stBaseButton-secondary"]:disabled:hover,
        button[data-testid="stBaseButton-primary"]:disabled,
        button[data-testid="stBaseButton-primary"]:disabled:hover {
            background: var(--surface-muted) !important;
            border-color: var(--border) !important;
            color: var(--text-muted) !important;
        }
        
        /* 입력창 */
        [data-testid="stTextInputRootElement"] {
            background: var(--surface-muted);
            border-color: var(--border-strong);
        }
        [data-testid="stTextInput"] input { color: var(--text); }
        [data-testid="stTextInput"] input::placeholder {
            color: var(--text-muted) !important;
            opacity: 1;
        }
        
        /* 여러 줄 입력창 (판정 수정 팝업의 메모) */
        [data-testid="stTextAreaRootElement"] {
            background: var(--surface-muted);
            border-color: var(--border-strong);
        }
        [data-testid="stTextArea"] textarea {
            background: transparent;
            color: var(--text);
            caret-color: var(--text);
        }

        /* 팝업(st.dialog): Streamlit 기본 테마로 그려지므로 앱 테마 색을 직접 입힌다 */
        [data-testid="stDialog"] > div {
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text);
        }
        [data-testid="stDialog"] [data-testid="stMarkdownContainer"],
        [data-testid="stDialog"] [data-testid="stRadio"] label p {
            color: var(--text);
        }
        [data-testid="stDialog"] button[aria-label="Close"] {
            color: var(--text-muted);
        }
        [data-testid="stDialog"] button[aria-label="Close"]:hover {
            color: var(--text);
        }
        /* 저장 후 뜨는 알림(st.toast)도 Streamlit 기본 테마로 그려진다 */
        [data-testid="stToast"] {
            background: var(--surface);
            border: 1px solid var(--border);
            color: var(--text);
        }
        [data-testid="stToast"] [data-testid="stMarkdownContainer"],
        [data-testid="stToast"] button {
            color: var(--text);
        }
        [data-testid="stDialog"] [data-testid="stWidgetLabel"] svg {
            color: var(--text-muted);
            stroke: var(--text-muted);
        }

        /* 파일 업로더 */
        [data-testid="stFileUploaderDropzone"] { background: var(--surface-muted); }
        [data-testid="stFileUploaderDropzoneInstructions"] * { color: var(--text-muted); }

        /* 업로더에 올린 파일 카드와 +(파일 추가), ×(삭제) 버튼 */
        [data-testid="stFileChip"] {
            background: var(--surface);
            border-color: var(--border-strong);
            color: var(--text-muted);
        }
        [data-testid="stFileChipName"] { color: var(--text); }
        [data-testid="stFileChipName"] ~ div { color: var(--text-muted); }  /* 파일 크기 */
        [data-testid="stFileUploader"] button[data-testid="stBaseButton-minimal"],
        [data-testid="stFileUploader"] button[data-testid="stBaseButton-borderlessIcon"] {
            color: var(--text-muted);
        }
        [data-testid="stFileUploader"] button[data-testid="stBaseButton-minimal"]:hover,
        [data-testid="stFileUploader"] button[data-testid="stBaseButton-borderlessIcon"]:hover {
            color: var(--text);
        }
        
        /* Expander */
        [data-testid="stExpander"] details { border-color: var(--border); }
        [data-testid="stExpander"] summary {
            background: var(--surface-muted);
            color: var(--text);
        }
        [data-testid="stExpander"] summary:hover { color: var(--info-fg); }
        
        /* Metric */
        [data-testid="stMetricLabel"], [data-testid="stMetricLabel"] p { color: var(--text-muted); }
        [data-testid="stMetricValue"] { color: var(--text); }
        
        /* 알림 상자 */
        [data-testid="stAlertContentSuccess"] { color: var(--success-fg); }
        [data-testid="stAlertContentInfo"] { color: var(--info-fg); }
        [data-testid="stAlertContentWarning"] { color: var(--warning-fg); }
        [data-testid="stAlertContentError"] { color: var(--danger-fg); }
        
        /* 선택 상자 (버전에 따라 구조가 달라 두 경우 모두 지정) */
        [data-testid="stSelectbox"] [data-baseweb="select"] > div,
        [data-testid="stSelectbox"] div[role="group"] {
            background: var(--surface-muted);
            border-color: var(--border-strong);
            color: var(--text);
        }
        [data-testid="stSelectbox"] input,
        [data-testid="stSelectbox"] [data-baseweb="select"] * {
            color: var(--text) !important;
        }
        [data-testid="stSelectbox"] svg { fill: var(--text-muted); color: var(--text-muted); }

        /* 선택 상자를 펼쳤을 때 나오는 목록 */
        [data-testid="stSelectboxVirtualDropdown"],
        [data-baseweb="popover"] ul {
            background: var(--surface) !important;
        }
        [role="listbox"] [role="option"],
        [data-baseweb="popover"] li {
            color: var(--text);
        }
        [role="listbox"] [role="option"]:hover,
        [role="listbox"] [role="option"][aria-selected="true"],
        [data-baseweb="popover"] li:hover {
            background: var(--surface-muted) !important;
        }

        /* 분류 버튼 (segmented control): 선택되지 않은 버튼 */
        [data-testid="stButtonGroup"] button[aria-checked="false"] {
            background: var(--surface);
            border-color: var(--border-strong);
            color: var(--text-2);
        }
        [data-testid="stButtonGroup"] button[aria-checked="false"]:hover {
            color: var(--text);
            border-color: var(--text-muted);
        }

        /* 분석 요약, 분석 결과 분류 카드: Streamlit 마크다운의 음수 margin 때문에 아래 여백이 사라지는 문제 */
        .st-key-detail_summary_card [data-testid="stMarkdownContainer"],
        .st-key-batch_summary_card > [data-testid="stElementContainer"]:last-child [data-testid="stMarkdownContainer"] {
            margin-bottom: 0;
        }

        /* 분석 파이프라인 카드: 옆의 라우팅 결정 카드 높이에 맞춰 늘어나므로 내용을 세로 가운데에 둔다 */
        .st-key-detail_pipeline_card {
            justify-content: center;
        }
        .st-key-detail_pipeline_card [data-testid="stMarkdownContainer"] {
            margin-bottom: 0;
        }

        /* 진행률 막대: 바탕(트랙)은 테마 색, 채워지는 부분은 파란색 */
        [data-testid="stProgress"] [role="progressbar"] > div {
            background: var(--border) !important;
        }
        [data-testid="stProgress"] [role="progressbar"] > div > div {
            background: var(--chart-benign) !important;
        }

        /* 배치 요약 카드: 안쪽 요소 사이 간격을 기본(24px)보다 좁힌다 */
        .st-key-batch_summary_card {
            gap: 1rem !important;
        }
        /* 타일 아래 구분선. 위아래 간격이 같도록 타일 묶음의 아래 테두리로 그린다 */
        .st-key-batch_group {
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--border);
        }

        /* 배치 요약 카드: 분류 타일 (segmented control을 타일 모양으로) */
        /* 버전마다 버튼을 감싸는 상자 구조가 달라서, 버튼을 품은 상자 전체에 폭을 준다 */
        .st-key-batch_group,
        .st-key-batch_group *:has(button) {
            width: 100% !important;
            max-width: 100% !important;
        }
        /* 버튼들의 바로 위 상자를 5칸 격자로 */
        .st-key-batch_group *:has(> button) {
            display: grid !important;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 0.75rem;
        }
        .st-key-batch_group [data-testid="stButtonGroup"] button {
            width: 100%;
            min-height: 5rem;
            margin: 0 !important;
            border: 1px solid var(--border) !important;
            border-radius: 0.6rem !important;
            background: var(--surface) !important;
        }
        .st-key-batch_group [data-testid="stButtonGroup"] button:hover {
            border-color: var(--text-muted) !important;
        }
        /* 버튼 글자는 "분류 이름\n건수" 한 덩어리라, 줄바꿈을 살리고 첫 줄만 작게 꾸민다 */
        .st-key-batch_group [data-testid="stButtonGroup"] button p {
            white-space: pre-line;
            text-align: center;
            color: var(--text) !important;
            font-size: 1.2rem;
            font-weight: 700;
            line-height: 1.7;
        }
        .st-key-batch_group [data-testid="stButtonGroup"] button p::first-line {
            color: var(--text-muted);
            font-size: 0.72rem;
            font-weight: 500;
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }
        /* 선택된 타일: 분류별 색 (1 Total, 2 Needs Review, 3 Auto Malicious, 4 Auto Benign, 5 Failed) */
        .st-key-batch_group button[aria-checked="true"] { border-width: 2px !important; }
        .st-key-batch_group button[aria-checked="true"] p::first-line { color: inherit; font-weight: 700; }
        .st-key-batch_group button:nth-of-type(1)[aria-checked="true"] {
            background: var(--neutral-bg) !important;
            border-color: var(--border-strong) !important;
        }
        .st-key-batch_group button:nth-of-type(1)[aria-checked="true"] p { color: var(--text) !important; }
        .st-key-batch_group button:nth-of-type(2)[aria-checked="true"] {
            background: var(--warning-soft) !important;
            border-color: var(--warning-border) !important;
        }
        .st-key-batch_group button:nth-of-type(2)[aria-checked="true"] p { color: var(--warning-fg) !important; }
        .st-key-batch_group button:nth-of-type(3)[aria-checked="true"] {
            background: var(--danger-bg) !important;
            border-color: var(--danger-border) !important;
        }
        .st-key-batch_group button:nth-of-type(3)[aria-checked="true"] p { color: var(--danger-fg) !important; }
        .st-key-batch_group button:nth-of-type(4)[aria-checked="true"] {
            background: var(--success-bg) !important;
            border-color: var(--success-border) !important;
        }
        .st-key-batch_group button:nth-of-type(4)[aria-checked="true"] p { color: var(--success-fg) !important; }
        .st-key-batch_group button:nth-of-type(5)[aria-checked="true"] {
            background: var(--neutral-bg) !important;
            border-color: var(--border-strong) !important;
        }
        .st-key-batch_group button:nth-of-type(5)[aria-checked="true"] p { color: var(--text-2) !important; }

        /* 머리글 오른쪽 버튼(새 파일 분석, 판정 수정): 열 비율 대신 고정 폭을 써서
           배치 화면·단건 화면 어디에 있든 같은 크기로 보이게 한다 */
        [data-testid="stColumn"]:has(.st-key-batch_new_file_analysis),
        [data-testid="stColumn"]:has(.st-key-progressive_new_file_analysis),
        [data-testid="stColumn"]:has(.st-key-open_review_dialog) {
            flex: 0 0 11rem !important;
            width: 11rem !important;
            min-width: 11rem !important;
            max-width: 11rem !important;
        }
        /* 같은 줄의 나머지 열(제목)이 남은 폭을 나눠 쓰게 해서 버튼이 다음 줄로 밀리지 않게 한다 */
        [data-testid="stHorizontalBlock"]:has(> [data-testid="stColumn"] :is(.st-key-batch_new_file_analysis, .st-key-progressive_new_file_analysis, .st-key-open_review_dialog)) {
            flex-wrap: nowrap !important;
        }
        [data-testid="stHorizontalBlock"]:has(> [data-testid="stColumn"] :is(.st-key-batch_new_file_analysis, .st-key-progressive_new_file_analysis, .st-key-open_review_dialog))
            > [data-testid="stColumn"]:not(:has(:is(.st-key-batch_new_file_analysis, .st-key-progressive_new_file_analysis, .st-key-open_review_dialog))) {
            flex: 1 1 0 !important;
            width: auto !important;
            min-width: 0 !important;
        }
        .st-key-batch_new_file_analysis button,
        .st-key-progressive_new_file_analysis button,
        .st-key-open_review_dialog button {
            width: 100%;
            height: 2.5rem;
            min-height: 2.5rem;
            padding: 0.25rem 0.75rem;
            font-size: 0.875rem;
        }

        /* 표: 캔버스로 그려져서 색을 바꿀 수 없으므로 다크 모드에서만 반전 */
        [data-testid="stDataFrame"] { filter: var(--df-filter); }

        @media (max-width: 900px) {
            /* 설명 가능성 + 분석 파이프라인 줄: 좁은 화면에서는 위아래로 쌓는다 */
            .st-key-result_detail_shell [data-testid="stHorizontalBlock"]:has(.st-key-detail_pipeline_section) {
                flex-wrap: wrap;
            }
            .st-key-result_detail_shell [data-testid="stHorizontalBlock"]:has(.st-key-detail_pipeline_section) > div {
                flex: 1 1 100% !important;
                min-width: 100% !important;
            }

            .batch-summary-grid,
            .st-key-batch_group *:has(> button) {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .batch-section-heading {
                align-items: flex-start;
                flex-direction: column;
                gap: 0.5rem;
            }

            .file-header {
                align-items: flex-start;
                flex-direction: column;
            }

            .file-meta {
                justify-content: flex-start;
                text-align: left;
            }

            .pipeline-flow {
                flex-wrap: wrap;
            }

            .pipeline-node {
                flex-basis: 30%;
            }

            .summary-top,
            .summary-bottom {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .verdict-arrow {
                display: none;
            }

            .evidence-grid {
                grid-template-columns: 1fr;
            }

            .evidence-section + .evidence-section {
                border-left: 0;
                border-top: 1px solid var(--border);
                padding-left: 0;
                padding-top: 1rem;
            }
        }

        /* 탭 색상(특히 다크모드) 개선 */
        [data-baseweb="tab-list"] button[data-baseweb="tab"] p {
            color: var(--text-2) !important;
            font-weight: 500;
        }
        [data-baseweb="tab-list"] button[data-baseweb="tab"][aria-selected="true"] p {
            color: var(--text) !important;
            font-weight: 700;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


def render_queue_table(queue_name, title, items, is_waiting=False, limit=20):
    if not items:
        import streamlit as st

        st.info(f"{title}에 해당하는 항목이 없습니다.")
        return

    import api_client
    import pandas as pd
    import streamlit as st

    # Pagination Logic
    total_count = len(items)
    page_key = f"{queue_name}_{title}_page"
    if page_key not in st.session_state:
        st.session_state[page_key] = 0

    total_pages = max(1, (total_count + limit - 1) // limit)
    if st.session_state[page_key] >= total_pages:
        st.session_state[page_key] = max(0, total_pages - 1)

    current_page = st.session_state[page_key]
    offset = current_page * limit

    # If it's the RETRAIN queue, it's already server-side paginated before calling this function,
    # so we don't slice it. Otherwise we slice the items.
    if queue_name.lower() == "retrain":
        page_items = items
    else:
        page_items = items[offset : offset + limit]

    df = pd.DataFrame(page_items)

    if "calibrated_probability" in df.columns:
        df["calibrated_probability_display"] = df["calibrated_probability"].apply(
            lambda x: f"{x * 100:.2f}%" if pd.notnull(x) else "N/A"
        )

    display_cols = {
        "rank": "순위" if queue_name.lower() != "auto" else "순서",
        "filename": "파일명",
        "sha256": "SHA-256",
        "initial_verdict": "모델 판정 결과",
        "priority_reason": "검토 유형",
        "calibrated_probability_display": "악성 확률",
        "queue_reason": "검토 이유",
    }

    if queue_name.lower() == "auto":
        # 역순 넘버링: 가장 밑(오래된 파일)이 1번, 가장 위(최신 파일)가 N번
        df["rank"] = list(range(len(df), 0, -1))
        display_cols.pop("priority_reason", None)

    if queue_name.lower() == "retrain":
        display_cols["selection_reason"] = "판정 변경 내역"

    df_display = df[[c for c in display_cols if c in df.columns]].rename(
        columns=display_cols
    )

    st.write(f"### {title} ({total_count}건)")
    if queue_name.lower() == "deep":
        st.markdown(
            "**정렬 기준**: 확률 불확실성 → 모델 불일치 → 분포 이탈 → 분석 난이도. 같은 유형에서는 신호 강도순으로 정렬합니다."
        )

    event = st.dataframe(
        df_display,
        use_container_width=True,
        hide_index=True,
        selection_mode="single-row",
        on_select="rerun",
        key=f"df_{queue_name}_{title}",
    )

    # Client-side pagination controls (only if we have more than one page and it's not RETRAIN)
    if queue_name.lower() != "retrain" and total_pages > 1:
        cols = st.columns([1, 2, 1])
        with cols[0]:
            if st.button(
                "이전 페이지",
                disabled=(current_page == 0),
                key=f"{queue_name}_{title}_prev",
            ):
                st.session_state[page_key] = current_page - 1
                st.rerun()
        with cols[1]:
            st.write(
                f"<div style='text-align: center;'>페이지 {current_page + 1} / {total_pages}</div>",
                unsafe_allow_html=True,
            )
        with cols[2]:
            if st.button(
                "다음 페이지",
                disabled=(current_page + 1 >= total_pages),
                key=f"{queue_name}_{title}_next",
            ):
                st.session_state[page_key] = current_page + 1
                st.rerun()

    if (
        event
        and getattr(event, "selection", None)
        and getattr(event.selection, "rows", None)
    ):
        row_idx = event.selection.rows[0]
        selected_item = page_items[row_idx]
        st.write(f"**선택됨**: {selected_item['filename']}")
        if st.button(
            "상세 결과 보기",
            key=f"btn_view_{selected_item['analysis_id']}",
            type="primary",
        ):
            try:
                full_result = api_client.get_result(selected_item["analysis_id"])
                view_data = search_result_view(full_result)
                view_data["queue_name"] = selected_item.get("queue_name")
                view_data["queue_reason"] = selected_item.get("queue_reason")
                view_data["priority_score"] = selected_item.get("priority_score")
                view_data["score_policy"] = selected_item.get("score_policy")
                view_data["priority_reason"] = selected_item.get("priority_reason")
                view_data["triggered_signals"] = selected_item.get("triggered_signals")
                view_data["is_waiting"] = is_waiting
                st.session_state.analysis_result = view_data
                st.session_state.batch_id = None
                st.session_state.batch_ids = []
                st.session_state.hash_search = None
                st.session_state.pop("batch_data", None)
                st.session_state.pop("batch_results", None)
                st.session_state.pop("batch_id", None)
                st.session_state.pop("batch_ids", None)
                st.rerun()
            except Exception as e:
                st.error(f"상세 결과 로드 실패: {e}")


def render_analyst_priority_queue():
    import api_client
    import streamlit as st

    st.markdown("---")
    st.subheader("분석가 큐 기반 업무 할당 (Analyst Queues)")

    # 1. 예산 조회 및 설정
    col1, col2 = st.columns([1, 1])
    try:
        budget_data = api_client.get_analyst_budget()
        current_budget = budget_data.get("daily_budget", 0)
        current_emergency = budget_data.get("emergency_budget", 0)
        current_deep = budget_data.get("deep_budget", 0)
        current_fp = 0
        is_unlimited = budget_data.get("is_unlimited", False)

        today_completed = budget_data.get("today_completed_count", 0)
        remaining = budget_data.get("remaining_budget", 0)
    except api_client.ApiError as e:
        st.error(f"예산 설정 조회 실패: {e.message}")
        return

    with col1:
        if is_unlimited:
            st.metric("오늘 검토 완료", f"{today_completed}")
            st.write("예산을 고려하지 않습니다.")
        else:
            st.metric("오늘 검토 완료", f"{today_completed} / {current_budget}")
            st.write(f"남은 예산: {remaining}")
    with col2:
        with st.expander("예산 설정"):
            new_unlimited = st.checkbox("예산 무제한 (제한 없음)", value=is_unlimited)
            new_budget = st.number_input(
                "전체 일일 검토 한도",
                min_value=0,
                value=current_budget,
                step=1,
                disabled=new_unlimited,
            )
            new_em = st.number_input(
                "긴급 대응 큐 할당량",
                min_value=0,
                value=current_emergency,
                step=1,
                disabled=new_unlimited,
            )
            new_deep = st.number_input(
                "심층 분석 큐 할당량",
                min_value=0,
                value=current_deep,
                step=1,
                disabled=new_unlimited,
            )
            new_fp = 0

            if st.button("예산 업데이트"):
                if not new_unlimited and (new_em + new_deep + new_fp > new_budget):
                    st.error("각 큐의 할당량 합이 전체 예산을 초과할 수 없습니다.")
                else:
                    try:
                        # Need to add is_unlimited to set_analyst_budget in api_client
                        api_client.set_analyst_budget(
                            new_budget,
                            new_em,
                            new_deep,
                            new_fp,
                            is_unlimited=new_unlimited,
                        )
                        st.success("예산이 업데이트되었습니다.")
                        st.rerun()
                    except api_client.ApiError as e:
                        st.error(f"예산 설정 실패: {e.message}")

    # 2. 추천 목록 조회
    try:
        recs_data = api_client.get_priority_recommendations()
    except api_client.ApiError as e:
        st.error(f"추천 목록 조회 실패: {e.message}")
        return

    if is_unlimited:
        em_label = "긴급 대응 (EMERGENCY) - 무제한"
        deep_label = "심층 분석 (DEEP) - 무제한"
    else:
        em_label = (
            f"긴급 대응 (EMERGENCY) - 잔여 {budget_data.get('remaining_emergency', 0)}"
        )
        deep_label = f"심층 분석 (DEEP) - 잔여 {budget_data.get('remaining_deep', 0)}"

    tab_labels = [
        em_label,
        deep_label,
        "자동 처리 (AUTO)",
        "재학습 데이터 (RETRAIN)",
        "오류 항목 (ERROR)",
    ]
    tabs = st.tabs(tab_labels)

    with tabs[0]:
        st.markdown(
            "**대상**: 악성 의심/판정 파일 중 **데이터 파괴, 랜섬웨어 암호화 등 고위험 행위** 관련 정적·동적 증거가 확인된 건"
        )
        render_queue_table(
            "emergency",
            "할당된 분석 대상",
            recs_data.get("emergency_recommendations", []),
        )
        if recs_data.get("emergency_waiting"):
            with st.expander("예산 초과 대기열"):
                render_queue_table(
                    "emergency",
                    "대기열",
                    recs_data.get("emergency_waiting", []),
                    is_waiting=True,
                )

    with tabs[1]:
        st.markdown(
            "**대상**: 모델 불일치(DISAGREEMENT), 분포 외(OOD) 및 초기 불확실 의심 건"
        )
        render_queue_table(
            "deep", "할당된 분석 대상", recs_data.get("deep_recommendations", [])
        )
        if recs_data.get("deep_waiting"):
            with st.expander("예산 초과 대기열"):
                render_queue_table(
                    "deep", "대기열", recs_data.get("deep_waiting", []), is_waiting=True
                )

    with tabs[2]:
        st.markdown("**대상**: 자동 판정 조건을 충족하여 추가 검토가 필요 없는 건")
        render_queue_table("auto", "처리 대상", recs_data.get("auto_queue", []))

    with tabs[3]:
        st.markdown(
            "**대상**: 초기 모델 판정과 분석가의 최종 판정이 달라진 건 (오탐/미탐)"
        )
        try:
            if "retrain_page" not in st.session_state:
                st.session_state.retrain_page = 0
            limit = 20
            offset = st.session_state.retrain_page * limit
            res = api_client.search_analyses(
                overturned_only=True, limit=limit, offset=offset
            )
            overturned_data = res.get("analyses", []) if res else []
            total_count = res.get("total_count", 0) if res else 0

            if overturned_data:
                cands = []
                for d in overturned_data:
                    cands.append(
                        {
                            "analysis_id": d["analysis_id"],
                            "filename": d.get("filename", ""),
                            "sha256": d.get("sha256", ""),
                            "queue_name": "RETRAIN",
                            "queue_reason": "분석가 판정으로 모델 결과가 뒤집힘",
                            "priority_score": None,
                            "selection_reason": f"초기 판정: {d.get('initial_verdict')} -> 최종 판정: {d.get('analyst_final_verdict')}",
                        }
                    )
                render_queue_table("retrain", "오탐/미탐 내역", cands)

                cols = st.columns([1, 2, 1])
                with cols[0]:
                    if st.button(
                        "이전 페이지",
                        disabled=(st.session_state.retrain_page == 0),
                        key="retrain_prev",
                    ):
                        st.session_state.retrain_page -= 1
                        st.rerun()
                with cols[1]:
                    st.write(
                        f"<div style='text-align: center;'>페이지 {st.session_state.retrain_page + 1} / {max(1, (total_count + limit - 1) // limit)} (총 {total_count}건)</div>",
                        unsafe_allow_html=True,
                    )
                with cols[2]:
                    if st.button(
                        "다음 페이지",
                        disabled=(offset + limit >= total_count),
                        key="retrain_next",
                    ):
                        st.session_state.retrain_page += 1
                        st.rerun()
            else:
                st.info("조건에 해당하는 오탐/미탐 데이터가 없습니다.")
        except api_client.ApiError as e:
            st.error(f"오탐/미탐 내역 조회 실패: {e.message}")

    with tabs[4]:
        st.markdown(
            "**대상**: 확률 값 오류, NaN, 무한대, 누락 등으로 시스템 처리가 불가능한 비정상 건"
        )
        render_queue_table(
            "error", "비정상 오류 대상", recs_data.get("error_queue", [])
        )


if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None
if "batch_results" not in st.session_state:
    st.session_state.batch_results = []
if "batch_data" not in st.session_state and st.session_state.batch_results:
    st.session_state.batch_data = {
        "batch_ids": st.session_state.get("batch_ids") or [],
        "batch_id": st.session_state.get("batch_id"),
        "summary": derive_batch_summary(st.session_state.batch_results),
        "analyses": st.session_state.batch_results,
    }

result = st.session_state.analysis_result

if result is None:
    render_input_view()
    render_hash_search()
    render_analyst_priority_queue()

else:
    batch_data = st.session_state.get("batch_data")
    if batch_data:
        sync_selected_analysis(batch_data)

        if pending_analyses(batch_data):
            # 진행 패널과 선택 파일 상세를 같은 fragment에서 갱신한다.
            render_polling_view(batch_data)
            st.stop()

        render_batch_triage(batch_data)
        result = st.session_state.analysis_result

    render_result_detail(result)
