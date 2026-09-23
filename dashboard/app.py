import hashlib
import re
import time
from collections import Counter
from html import escape
from uuid import uuid4

import api_client
import matplotlib.pyplot as plt
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


def reset_analysis_session():
    """Return the console to its upload state for a new batch."""
    reset_analysis_result()
    st.session_state.pop("batch_file_uploader", None)


def select_analysis_result(widget_key="selected_analysis_id"):
    """Bind the selected batch row to the existing detail view."""
    selected_id = st.session_state.get(widget_key)
    selected = load_mock_analysis(selected_id)
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

    return (
        f'<span class="status-badge {badge_class}">'
        f"{escape(label)}</span>"
    )


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

    return (
        f'<span class="status-badge {badge_class}">'
        f"{escape(label)}</span>"
    )


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

    return (
        f'<span class="pipeline-state {status_class}">'
        f"{label}</span>"
    )


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
    return "".join(
        (
            '<span class="deep-status-item">'
            f'<strong>{tool_name}</strong> · {escape(statuses.get(key, "NOT_REQUIRED"))}'
            "</span>"
        )
        for tool_name, key in tools
    )


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
    colors = ["#dc2626" if value >= 0 else "#2563eb" for value in values]
    limit = max((abs(value) for value in values), default=0.1) * 1.22

    # Keep full-width labels; the tighter figure is ~230-255px in the wide panel.
    figure, axis = plt.subplots(figsize=(6.2, 1.0))
    positions = list(range(len(names)))
    axis.barh(positions, values, color=colors, height=0.55)
    axis.axvline(0, color="#64748b", linewidth=1.1, zorder=0)
    axis.set_xlim(-limit, limit)
    axis.set_yticks(positions, labels=names)
    axis.invert_yaxis()
    axis.xaxis.grid(True, color="#e2e8f0", linewidth=0.7)
    axis.set_axisbelow(True)
    axis.tick_params(axis="both", labelsize=6.5, colors="#475569", pad=1)

    for position, value in zip(positions, values):
        offset = limit * 0.025
        axis.text(
            value + (offset if value >= 0 else -offset),
            position,
            f"{value:+.2f}",
            va="center",
            ha="left" if value >= 0 else "right",
            fontsize=6.5,
            color="#334155",
        )

    axis.text(
        0.01,
        1.04,
        "← Benign contribution",
        transform=axis.transAxes,
        color="#2563eb",
        fontsize=6.5,
        fontweight="bold",
    )
    axis.text(
        0.99,
        1.04,
        "Malicious contribution →",
        transform=axis.transAxes,
        color="#dc2626",
        fontsize=6.5,
        fontweight="bold",
        ha="right",
    )

    for spine in axis.spines.values():
        spine.set_visible(False)

    axis.set_xlabel("SHAP value", fontsize=6.5, color="#64748b", labelpad=1)
    figure.patch.set_facecolor("#ffffff")
    axis.set_facecolor("#ffffff")
    figure.tight_layout(pad=0.35)
    target.pyplot(figure, width="stretch")
    plt.close(figure)


def mock_status_for_index(index, total):
    """Create a deterministic mix of polling states for the batch UI."""
    if total == 1:
        return "COMPLETED"
    sequence = (
        "COMPLETED",
        "RUNNING",
        "QUEUED",
        "COMPLETED",
        "FAILED",
        "COMPLETED",
        "RUNNING",
        "COMPLETED",
        "COMPLETED",
        "COMPLETED",
    )
    return sequence[index % len(sequence)]


def mock_triage_profile(index):
    """Return interface-spec-aligned triage values for one mock analysis."""
    profile_sequence = (
        "HIGH_RISK_UNCERTAIN",
        "HIGH_RISK_UNCERTAIN",
        "HIGH_RISK_UNCERTAIN",
        "AUTO_MALICIOUS",
        "AUTO_MALICIOUS",
        "AUTO_BENIGN",
        "HIGH_RISK_UNCERTAIN",
        "AUTO_MALICIOUS",
        "AUTO_BENIGN",
        "AUTO_MALICIOUS",
    )
    initial_verdict = profile_sequence[index % len(profile_sequence)]

    if initial_verdict == "AUTO_BENIGN":
        return {
            "raw_probability": 0.081,
            "calibrated_probability": 0.057,
            "disagreement": 0.02,
            "ood_score": 0.084,
            "difficulty_score": 2,
            "initial_verdict": initial_verdict,
            "route": "FINAL",
            "reason": "High Benign Confidence",
            "final_verdict": "BENIGN",
        }

    if initial_verdict == "AUTO_MALICIOUS":
        return {
            "raw_probability": 0.997,
            "calibrated_probability": 0.9981,
            "disagreement": 0.01,
            "ood_score": 0.072,
            "difficulty_score": 3,
            "initial_verdict": initial_verdict,
            "route": "FINAL",
            "reason": "High Malicious Confidence",
            "final_verdict": "MALICIOUS",
        }

    review_reasons = (
        "OOD Detected",
        "High Model Disagreement",
        "High Analysis Difficulty",
        "Uncertain Probability",
    )
    return {
        "raw_probability": 0.978,
        "calibrated_probability": 0.942,
        "disagreement": 0.13,
        "ood_score": -0.031,
        "difficulty_score": 6,
        "initial_verdict": initial_verdict,
        "route": "DEEP_ANALYSIS",
        "reason": review_reasons[index % len(review_reasons)],
        "final_verdict": "MALICIOUS",
    }


def mock_deep_analysis_status(route, status, index):
    """Keep per-tool polling states separate from the overall analysis status."""
    if route == "FINAL":
        return {
            "capa": "NOT_REQUIRED",
            "floss": "NOT_REQUIRED",
            "speakeasy": "NOT_REQUIRED",
            "cape": "NOT_REQUIRED",
        }
    if status == "COMPLETED":
        return {
            "capa": "COMPLETED",
            "floss": "COMPLETED",
            "speakeasy": "COMPLETED",
            "cape": "NOT_REQUIRED",
        }
    if status == "RUNNING":
        return {
            "capa": "COMPLETED",
            "floss": "COMPLETED",
            "speakeasy": "RUNNING" if index % 2 == 0 else "QUEUED",
            "cape": "NOT_REQUIRED",
        }
    if status == "FAILED":
        return {
            "capa": "COMPLETED",
            "floss": "COMPLETED",
            "speakeasy": "FAILED",
            "cape": "NOT_REQUIRED",
        }
    return {
        "capa": "QUEUED",
        "floss": "QUEUED",
        "speakeasy": "QUEUED",
        "cape": "NOT_REQUIRED",
    }


def build_mock_analysis(file_descriptor, batch_id, index, total):
    """Build one mock API response using the interface specification fields."""
    status = mock_status_for_index(index, total)
    triage = mock_triage_profile(index)
    deep_status = mock_deep_analysis_status(triage["route"], status, index)
    final_verdict = (
        triage["final_verdict"] if status == "COMPLETED" else "UNCERTAIN"
    )
    top_features = [
        {
            "feature_name": "SectionMaxEntropy",
            "feature_value": 7.92,
            "shap_value": 0.31,
            "direction": "MALICIOUS",
        },
        {
            "feature_name": "ImportsNb",
            "feature_value": 142,
            "shap_value": 0.24,
            "direction": "MALICIOUS",
        },
        {
            "feature_name": "SizeOfCode",
            "feature_value": 286720,
            "shap_value": 0.18,
            "direction": "MALICIOUS",
        },
        {
            "feature_name": "LegitCertificate",
            "feature_value": 1,
            "shap_value": -0.10,
            "direction": "BENIGN",
        },
        {
            "feature_name": "PackerSignature",
            "feature_value": 0,
            "shap_value": -0.06,
            "direction": "BENIGN",
        },
    ]
    evidence = [
        {
            "technique_id": "T1059.003",
            "technique_name": "Windows Command Shell",
            "sources": ["CAPA", "SPEAKEASY"],
            "summary": "Command execution related behavior detected.",
            "tactic": "Execution",
        },
        {
            "technique_id": "T1105",
            "technique_name": "Ingress Tool Transfer",
            "sources": ["CAPA", "SPEAKEASY"],
            "summary": "External file transfer behavior detected.",
            "tactic": "Command and Control",
        },
        {
            "technique_id": "T1140",
            "technique_name": "Deobfuscate/Decode Files or Information",
            "sources": ["CAPA"],
            "summary": "Encoded content was decoded in memory.",
            "tactic": "Defense Evasion",
        },
    ]

    return {
        "analysis_id": f"a_{uuid4().hex[:16]}",
        "batch_id": batch_id,
        "filename": file_descriptor["filename"],
        "file_size": file_descriptor["size"],
        "file_type": (
            "PE/DLL"
            if file_descriptor["filename"].lower().endswith(".dll")
            else "PE/EXE"
        ),
        "sha256": hashlib.sha256(file_descriptor["content"]).hexdigest(),
        "created_at": "2026-09-01T17:04:00+09:00",
        "analyzed_at": "2026-09-01 17:04",
        "status": status,
        **triage,
        "final_verdict": final_verdict,
        "top_features": top_features,
        "deep_analysis_status": deep_status,
        "evidence": evidence,
        "llm_summary": {
            "summary": "의심 행위와 모델 위험 신호를 종합한 Mock 분석 요약입니다.",
            "suspicious_behaviors": [
                "명령 실행 및 외부 파일 전송 행위",
                "인코딩된 데이터의 메모리 내 디코딩",
            ],
            "analyst_notes": "원본 Evidence와 함께 검토가 필요합니다.",
        },
        "capa_behaviors": [
            "PowerShell 명령 실행 기능",
            "외부 URL에서 파일 다운로드",
            "인코딩된 데이터 디코딩 및 메모리 전개",
        ],
    }


def derive_batch_summary(analyses):
    """Derive mutually exclusive analyst-facing counts from analysis records."""
    summary = {
        "total": len(analyses),
        "high_risk_uncertain": 0,
        "auto_malicious": 0,
        "auto_benign": 0,
        "failed": 0,
    }
    for analysis in analyses:
        if analysis["status"] == "FAILED":
            summary["failed"] += 1
        elif analysis["initial_verdict"] == "HIGH_RISK_UNCERTAIN":
            summary["high_risk_uncertain"] += 1
        elif analysis["initial_verdict"] == "AUTO_MALICIOUS":
            summary["auto_malicious"] += 1
        elif analysis["initial_verdict"] == "AUTO_BENIGN":
            summary["auto_benign"] += 1
    return summary


def load_mock_batch(file_descriptors):
    """Mock batch endpoint; replace with get_batch_from_api(batch_id)."""
    batch_id = f"b_20260909_{uuid4().hex[:8]}"
    analyses = [
        build_mock_analysis(
            file_descriptor,
            batch_id,
            index,
            len(file_descriptors),
        )
        for index, file_descriptor in enumerate(file_descriptors)
    ]
    return {
        "batch_id": batch_id,
        "summary": derive_batch_summary(analyses),
        "analyses": analyses,
    }

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
                "code": e.code, "message": e.message, "stage": e.stage,
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
                "code": e.code, "message": e.message, "stage": e.stage,
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
    if (
        analysis.get("initial_verdict") != "HIGH_RISK_UNCERTAIN"
        or analysis.get("deep_detail_loaded")
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

    완료 화면의 derive_batch_summary()는 초기 판정을 세고, 이쪽은 작업 상태를 센다.
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


def load_mock_analysis(analysis_id, batch_data=None):
    """Mock detail endpoint; replace with get_analysis_from_api(analysis_id)."""
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


def group_batch_analyses(analyses):
    """Partition results by analyst workflow priority."""
    groups = {
        "needs_review": [],
        "auto_malicious": [],
        "auto_benign": [],
        "failed": [],
    }
    for analysis in analyses:
        if analysis["status"] == "FAILED":
            groups["failed"].append(analysis)
        elif analysis["initial_verdict"] == "HIGH_RISK_UNCERTAIN":
            groups["needs_review"].append(analysis)
        elif analysis["initial_verdict"] == "AUTO_MALICIOUS":
            groups["auto_malicious"].append(analysis)
        elif analysis["initial_verdict"] == "AUTO_BENIGN":
            groups["auto_benign"].append(analysis)
    return groups


def deep_analysis_status_text(analysis):
    """Summarize tool states for the Needs Review result table."""
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
        f'{escape(technique.get("technique_id", technique.get("id", "")))}'
        "</span> "
        f'{escape(technique.get("technique_name", technique.get("name", "")))}'
        " · "
        f'{escape(technique.get("tactic", ", ".join(technique.get("sources", []))))}'
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
        + section("MITRE ATT&amp;CK", mitre_items, "표시할 MITRE ATT&CK 근거가 없습니다.")
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
        has_finished_tool = any(
            value in {"COMPLETED", "FAILED"} for value in selected
        )
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


def result_detail_state(analysis):
    """Batch 상태가 아닌 현재 파일의 확보된 결과로 표시 여부를 결정한다."""
    return {
        "available": initial_detail_available(analysis),
        "deep": deep_analysis_state(analysis),
        "tools": {
            tool: "NOT_REQUIRED" if analysis.get("route") == "FINAL" else
            (analysis.get("deep_analysis_status") or {}).get(tool)
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


def render_result_detail(analysis, target=st):
    """완료/진행/실패 결과가 공유하는 상세 shell. API 호출이나 polling은 하지 않는다."""
    state = result_detail_state(analysis)
    if not state["available"]:
        if analysis.get("status") == "FAILED":
            error = analysis.get("error") or {}
            target.error("분석 실패: " + (error.get("message") or "원인을 확인할 수 없습니다."))
            if error.get("code"):
                target.caption(f"코드 {error['code']} · 단계 {error.get('stage') or '-'}")
        else:
            target.info(f"Initial Analysis 결과를 기다리고 있습니다. (상태: {analysis.get('status') or 'QUEUED'})")
        return

    shell = target.container(key="result_detail_shell", gap=DETAIL_COLUMN_GAP)
    context, action = shell.columns([6, 1], gap=DETAIL_COLUMN_GAP)
    context.caption(
        f"{analysis.get('filename') or '(이름 없음)'} · "
        f"SHA-256 {truncate_hash(analysis.get('sha256') or '-')}"
    )
    if action.button(
        "새 파일 분석", key="progressive_new_file_analysis", width="stretch"
    ):
        reset_analysis_session()
        st.rerun()

    initial = detail_section(shell, "분석 요약", "summary")
    verdicts = [
        ("Initial Verdict", verdict_badge_markup(analysis.get("initial_verdict") or "Pending")),
        ("Final Verdict", verdict_badge_markup(analysis.get("final_verdict") or "Pending")),
        ("Route", route_badge_markup(analysis.get("route") or "-")),
    ]
    metrics = [
        ("Raw Probability", "raw_probability", "{:.1%}"),
        ("Calibrated Probability", "calibrated_probability", "{:.1%}"),
        ("OOD Score", "ood_score", "{:.3f}"),
        ("Disagreement", "disagreement", "{:.3f}"),
        ("Difficulty", "difficulty_score", "{:.1f}"),
    ]
    initial.markdown(
        '<div class="detail-verdicts">' + "".join(
            f'<div><div class="summary-label">{label}</div>{badge}</div>'
            for label, badge in verdicts
        ) + '</div><div class="summary-divider"></div><div class="detail-metrics">'
        + "".join(
            f'<div><div class="summary-label">{label}</div>'
            f'<div class="summary-value">{escape(_metric_text(analysis.get(key), pattern))}</div></div>'
            for label, key, pattern in metrics
        ) + '</div>',
        unsafe_allow_html=True,
    )

    decision_col, pipeline_col = shell.columns(2, gap=DETAIL_COLUMN_GAP)
    routing = detail_section(decision_col, "라우팅 결정", "routing")
    routing.markdown(route_badge_markup(analysis.get("route") or "-"), unsafe_allow_html=True)
    routing.write(f"**Reason**  \n{analysis.get('reason') or '-'}")
    signals = analysis.get("triggered_signals") or []
    routing.write("**Triggered Signals**  \n" + (", ".join(signals) if signals else "None"))
    pipeline = detail_section(pipeline_col, "분석 파이프라인", "pipeline")
    steps = [("ML Triage", "COMPLETED")]
    steps.extend((label, state["tools"][key]) for label, key in (
        ("CAPA", "capa"), ("FLOSS", "floss"), ("Speakeasy", "speakeasy"), ("CAPE", "cape")
    ))
    steps.append(("Final", analysis.get("status") or "QUEUED"))
    pipeline.markdown('<div class="detail-pipeline">' + "".join(
        f'<div class="pipeline-node"><div class="pipeline-name">{label}</div>'
        f'{pipeline_state_markup(status)}</div>' for label, status in steps
    ) + '</div>', unsafe_allow_html=True)

    explanation = detail_section(shell, "설명 가능성", "shap")
    explanation.markdown("**SHAP 주요 특성 Top 5**")
    features = analysis.get("top_features") or analysis.get("shap_features") or []
    if features:
        render_shap_chart(explanation, features)
    else:
        explanation.info("표시할 SHAP 특성이 없습니다.")

    deep = detail_section(shell, "Deep Analysis", "deep")
    render_deep_analysis(analysis, deep, state)
    technical = shell.expander("기술 세부 정보", expanded=False)
    technical.write(f"**파일명:** {analysis.get('filename') or '-'}")
    technical.write(f"**SHA256:** `{analysis.get('sha256') or '-'}`")
    if analysis.get("analyzed_at"):
        technical.write(f"**분석 시각:** {analysis['analyzed_at']}")


def render_progressive_result(analysis, target=st):
    """기존 진입점도 동일한 상세 shell을 사용한다."""
    render_result_detail(analysis, target)


def render_speakeasy(target, speakeasy):
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
    target.caption(
        "표시된 이벤트 기준 · "
        "unique 수는 api_name이 있는 호출 기준입니다."
    )
    if speakeasy.get("behavior_truncated"):
        original_calls = original_counts.get("api_calls")
        if isinstance(original_calls, int) and original_calls > len(calls):
            target.caption(f"API 호출 총 {original_calls}개 중 {len(calls)}개 미리보기")
        else:
            target.caption("행동 이벤트는 일부만 미리보기로 표시됩니다.")
    if speakeasy.get("adapter_events_truncated"):
        target.caption("Speakeasy 결과 수집 시 카테고리별 100개를 넘는 상세 이벤트가 생략됐습니다.")
    if speakeasy.get("worker_events_truncated") or speakeasy.get("details_omitted"):
        target.caption("결과 크기 제한으로 일부 상세 이벤트가 저장되지 않았습니다.")
    elif speakeasy.get("events_truncated") and not speakeasy.get("adapter_events_truncated"):
        target.caption("일부 상세 이벤트가 저장되지 않았습니다.")
    if counts:
        target.dataframe(
            [{"API": name, "Calls": count} for name, count in counts.most_common(SPEAKEASY_PREVIEW_LIMIT)],
            hide_index=True, width="stretch",
        )
        if len(counts) > SPEAKEASY_PREVIEW_LIMIT:
            target.caption(f"호출 수 기준 상위 {SPEAKEASY_PREVIEW_LIMIT}개 API 표시")
    else:
        target.caption("No API calls detected" if not calls else "API names unavailable")

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
            count for name in source_names
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
        # 키를 그대로 유지하고 중첩 값은 길이를 제한한 텍스트로 표시한다.
        rows = [
            {str(field): str(value)[:200] for field, value in event.items()}
            for event in events[:SPEAKEASY_PREVIEW_LIMIT]
        ]
        target.dataframe(rows, hide_index=True, width="stretch")
        if len(events) > SPEAKEASY_PREVIEW_LIMIT:
            target.caption(f"처음 {SPEAKEASY_PREVIEW_LIMIT}개 이벤트 표시 · 전체는 Raw details에서 확인")
    if speakeasy.get("error"):
        target.warning(speakeasy["error"].get("message") or "Speakeasy 실행 오류")
    target.expander("Raw details", expanded=False).json(speakeasy)


def render_static_detail_notice(target, tool):
    """Distinguish successful analysis from omitted or unavailable detail storage."""
    status = tool.get("details_status")
    diagnostic = tool.get("details_error") or {}
    if status == "OMITTED_TOO_LARGE":
        actual, limit = diagnostic.get("actual_bytes"), diagnostic.get("limit_bytes")
        size = f" ({actual:,} / {limit:,} bytes)" if isinstance(actual, int) and isinstance(limit, int) else ""
        target.caption(f"분석은 완료됐지만 상세 결과가 저장 상한을 넘어 생략됐습니다{size}.")
    elif status == "ARCHIVE_FAILED":
        code = diagnostic.get("code")
        suffix = f" ({code})" if isinstance(code, str) else ""
        target.caption(f"분석은 완료됐지만 상세 결과 보관에 실패했습니다{suffix}.")


def render_deep_analysis(analysis, deep, state):
    status = state["deep"]
    deep.markdown(f"**Status: {status}**")
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
    capa_box = deep.expander("CAPA", expanded=bool(capa))
    capabilities = capa.get("capabilities") or []
    if capabilities:
        capa_box.dataframe(capabilities, hide_index=True, width="stretch")
    else:
        capa_box.caption(f"Status: {statuses.get('capa', 'NOT_REQUIRED')}")
    render_static_detail_notice(capa_box, capa)

    floss = analysis.get("floss") or {}
    floss_box = deep.expander("FLOSS", expanded=bool(floss))
    strings = floss.get("strings") or {}
    string_rows = [
        {"Type": kind, "String": value}
        for kind, values in strings.items()
        for value in (values or [])
    ]
    if string_rows:
        floss_box.dataframe(string_rows, hide_index=True, width="stretch")
    else:
        floss_box.caption(f"Status: {statuses.get('floss', 'NOT_REQUIRED')}")
    render_static_detail_notice(floss_box, floss)

    speakeasy = analysis.get("speakeasy") or {}
    speakeasy_box = deep.expander("Speakeasy", expanded=bool(speakeasy))
    if speakeasy:
        render_speakeasy(speakeasy_box, speakeasy)
    else:
        speakeasy_box.caption(
            f"Status: {statuses.get('speakeasy', 'NOT_REQUIRED')}"
        )

    # 근거·해석·최종 평가는 심층 분석이 끝난 뒤에만 그린다. 대기·진행 중에는 위의
    # 상태 안내만 남긴다. 실패 시 MITRE는 확보된 부분 근거가 있을 때만 보여 준다.
    if evidence_visible(analysis):
        evidence = analysis.get("evidence") or []
        evidence_box = deep.expander("MITRE Evidence", expanded=bool(evidence))
        if evidence:
            evidence_box.dataframe(evidence, hide_index=True, width="stretch")
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
        assessment_box.write(
            f"**Disposition:** {assessment.get('disposition') or '-'}"
        )
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
            f"접수 실패 · {item['filename']} — {item['message']} "
            f"(코드 {item['code']})"
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
        return (
            "상세 화면에 필요한 모델 결과가 이 이력에 없습니다: "
            + ", ".join(missing)
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

    if target.button("상세 보기", key="hash_search_open", type="primary") and open_search_result(selected["analysis_id"]):
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
    """Render the analyst-priority summary derived from analysis records."""
    summary = derive_batch_summary(batch_data["analyses"])
    batch_data["summary"] = summary
    st.markdown(
        f"""
        <div class="batch-section-heading batch-section-heading-first">
            <span>Batch Summary</span>
            <span class="batch-context">Batch ID · {escape(batch_id_label(batch_data))}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    summary_card = st.container(border=True, key="batch_summary_card")
    summary_card.markdown(
        f"""
        <div class="batch-summary-grid">
            <div class="batch-summary-item">
                <div class="batch-summary-label">Total</div>
                <div class="batch-summary-value">{summary['total']}</div>
            </div>
            <div class="batch-summary-item batch-summary-priority">
                <div class="batch-summary-label">Needs Review</div>
                <div class="batch-summary-value">{summary['high_risk_uncertain']}</div>
            </div>
            <div class="batch-summary-item">
                <div class="batch-summary-label">Auto Malicious</div>
                <div class="batch-summary-value">{summary['auto_malicious']}</div>
            </div>
            <div class="batch-summary-item">
                <div class="batch-summary-label">Auto Benign</div>
                <div class="batch-summary-value">{summary['auto_benign']}</div>
            </div>
            <div class="batch-summary-item">
                <div class="batch-summary-label">Failed</div>
                <div class="batch-summary-value">{summary['failed']}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def batch_group_rows(group_key, analyses):
    """Build group-specific table rows without leaking mock generation into UI."""
    if group_key == "needs_review":
        return [
            {
                "File": analysis["filename"],
                "Status": analysis["status"],
                "JRR Reason": analysis["reason"],
                "Deep Analysis Status": deep_analysis_status_text(analysis),
            }
            for analysis in analyses
        ]
    if group_key in {"auto_malicious", "auto_benign"}:
        return [
            {
                "File": analysis["filename"],
                "Status": analysis["status"],
                "Calibrated Probability": (
                    f"{analysis['calibrated_probability']:.4f}"
                ),
                "Reason": analysis["reason"],
            }
            for analysis in analyses
        ]
    return [
        {
            "File": analysis["filename"],
            "Status": analysis["status"],
            "Initial Verdict": analysis["initial_verdict"],
            "Reason": analysis["reason"],
        }
        for analysis in analyses
    ]


def render_batch_group_results(group_key, analyses):
    """Render one triage group and bind its selection to the detail view."""
    result_card = st.container(border=True, key="batch_group_results")
    if not analyses:
        result_card.info("이 그룹에 해당하는 분석 결과가 없습니다.")
        return

    rows = batch_group_rows(group_key, analyses)
    result_card.dataframe(
        rows,
        hide_index=True,
        width="stretch",
        height=min(38 * (len(rows) + 1), 300),
    )

    analysis_by_id = {analysis["analysis_id"]: analysis for analysis in analyses}
    selector_key = "group_analysis_selector"
    selected_id = st.session_state.get(selector_key)
    if selected_id not in analysis_by_id:
        current_id = st.session_state.get("selected_analysis_id")
        selected_id = (
            current_id
            if current_id in analysis_by_id
            else next(iter(analysis_by_id))
        )
        st.session_state[selector_key] = selected_id
        st.session_state.selected_analysis_id = selected_id
        st.session_state.analysis_result = load_mock_analysis(selected_id)

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
    if group_key == "needs_review" and selected is not None:
        result_card.markdown(
            f"""
            <div class="deep-status-row">
                <span class="deep-status-label">Deep Analysis</span>
                {deep_analysis_status_markup(selected['deep_analysis_status'])}
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
    labels = {
        "needs_review": "Needs Review",
        "auto_malicious": "Auto Malicious",
        "auto_benign": "Auto Benign",
        "failed": "Failed",
    }
    options = tuple(labels)

    batch_area = st.container(key="batch_triage_area")
    with batch_area:
        render_batch_summary(batch_data)
        render_intake_notice(st, batch_data)

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

        st.markdown(
            '<div class="batch-section-heading">분석 결과 분류</div>',
            unsafe_allow_html=True,
        )
        format_group = lambda key: f"{labels[key]} ({len(groups[key])})"
        if hasattr(st, "segmented_control"):
            group_key = st.segmented_control(
                "분석 결과 분류",
                options=options,
                default="needs_review",
                format_func=format_group,
                key="batch_group",
                label_visibility="collapsed",
            )
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
        group_key = group_key or "needs_review"
        render_batch_group_results(group_key, groups[group_key])
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
        <div class="batch-section-heading batch-section-heading-first">
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

st.markdown(
    """
    <style>
        .stApp {
            background: #f8fafc;
            color: #0f172a;
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

        .detail-verdicts, .detail-pipeline {
            grid-template-columns: repeat(3, minmax(0, 1fr));
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
            .detail-verdicts, .detail-metrics, .detail-pipeline {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }

        div[data-testid="stVerticalBlockBorderWrapper"] {
            background: #ffffff;
            border-color: #e2e8f0;
            box-sizing: border-box;
            color: #0f172a;
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
            color: #991b1b;
            background: #fee2e2;
            border-color: #fecaca;
        }

        .badge-success {
            color: #166534;
            background: #dcfce7;
            border-color: #bbf7d0;
        }

        .badge-warning {
            color: #9a3412;
            background: #ffedd5;
            border-color: #fed7aa;
        }

        .badge-info {
            color: #1d4ed8;
            background: #dbeafe;
            border-color: #bfdbfe;
        }

        .badge-neutral {
            color: #475569;
            background: #f1f5f9;
            border-color: #e2e8f0;
        }

        .route-focus {
            padding: 0 0 0.5rem;
            text-align: center;
        }

        .route-label {
            color: #64748b;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.08em;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
        }

        .route-badge {
            display: inline-block;
            color: #1e40af;
            background: #dbeafe;
            border: 1px solid #93c5fd;
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
            color: #334155;
            background: #f8fafc;
            border: 1px solid #cbd5e1;
            border-radius: 999px;
            font-size: 0.78rem;
            padding: 0.5rem 1rem;
        }

        .secondary-text {
            color: #64748b;
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
            color: #0f172a;
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

        .batch-context {
            color: #64748b;
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
            background: #fff7ed;
            border: 1px solid #fed7aa;
            border-radius: 0.5rem;
        }

        .batch-summary-priority .batch-summary-label,
        .batch-summary-priority .batch-summary-value {
            color: #9a3412;
        }

        .batch-summary-label {
            color: #64748b;
            font-size: 0.72rem;
            line-height: 1.2;
            margin-bottom: 0.5rem;
            text-transform: uppercase;
        }

        .batch-summary-value {
            color: #0f172a;
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
            color: #64748b;
            font-size: 0.76rem;
            font-weight: 650;
            margin-right: 0.5rem;
        }

        .deep-status-item {
            color: #334155;
            background: #f8fafc;
            border: 1px solid #cbd5e1;
            border-radius: 999px;
            font-size: 0.72rem;
            padding: 0.5rem 1rem;
        }

        .detail-section-break {
            color: #475569;
            border-top: 1px solid #e2e8f0;
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
            border-bottom: 1px solid #e2e8f0;
            padding: 0 0 1rem;
        }

        .file-title {
            color: #0f172a;
            font-size: 1rem;
            font-weight: 700;
            line-height: 1.25;
        }

        .file-hash,
        .file-meta {
            color: #64748b;
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
            color: #94a3b8;
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
            border-top: 1px solid #e2e8f0;
            margin: 0.5rem 0;
        }

        .summary-label {
            color: #64748b;
            font-size: 0.7rem;
            line-height: 1.2;
            margin-bottom: 0.5rem;
        }

        .summary-value {
            color: #0f172a;
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
            border-left: 1px solid #e2e8f0;
            padding-left: 1rem;
        }

        .evidence-title {
            color: #334155;
            font-size: 0.8rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }

        .evidence-item {
            color: #334155;
            font-size: 0.74rem;
            line-height: 1.35;
            margin-bottom: 0.5rem;
        }

        .technique-id {
            color: #1d4ed8;
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
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 0.45rem;
            padding: 0.5rem;
            text-align: center;
        }

        .pipeline-name {
            color: #0f172a;
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
            color: #166534;
            background: #dcfce7;
        }

        .pipeline-skipped {
            color: #475569;
            background: #f1f5f9;
        }

        .pipeline-running {
            color: #1d4ed8;
            background: #dbeafe;
        }

        .pipeline-failed {
            color: #991b1b;
            background: #fee2e2;
        }

        .pipeline-arrow {
            flex: 0 0 auto;
            color: #94a3b8;
            font-size: 0.9rem;
        }

        @media (max-width: 900px) {
            .batch-summary-grid {
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
                border-top: 1px solid #e2e8f0;
                padding-left: 0;
                padding-top: 1rem;
            }
        }
    </style>
    """,
    unsafe_allow_html=True,
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
