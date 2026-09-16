import hashlib
import api_client
import time
from html import escape
from uuid import uuid4
from api_client import ApiError

import matplotlib.pyplot as plt
import streamlit as st

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
    if "ood_score" in result:
        return result["ood_score"] < 0
    return bool(result.get("ood", False))


def difficulty_label(score):
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


def render_shap_chart(target, features):
    chart_features = features[:5]
    names = [
        feature.get(
            "feature_name",
            feature.get("feature", feature.get("SHAP 특성", "Unknown")),
        )
        for feature in chart_features
    ]
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

    figure, axis = plt.subplots(figsize=(6.2, 2.15))
    positions = list(range(len(names)))
    axis.barh(positions, values, color=colors, height=0.55)
    axis.axvline(0, color="#64748b", linewidth=1.1, zorder=0)
    axis.set_xlim(-limit, limit)
    axis.set_yticks(positions, labels=names)
    axis.invert_yaxis()
    axis.xaxis.grid(True, color="#e2e8f0", linewidth=0.7)
    axis.set_axisbelow(True)
    axis.tick_params(axis="both", labelsize=8, colors="#475569")

    for position, value in zip(positions, values):
        offset = limit * 0.025
        axis.text(
            value + (offset if value >= 0 else -offset),
            position,
            f"{value:+.2f}",
            va="center",
            ha="left" if value >= 0 else "right",
            fontsize=8,
            color="#334155",
        )

    axis.text(
        0.01,
        1.04,
        "← Benign contribution",
        transform=axis.transAxes,
        color="#2563eb",
        fontsize=8,
        fontweight="bold",
    )
    axis.text(
        0.99,
        1.04,
        "Malicious contribution →",
        transform=axis.transAxes,
        color="#dc2626",
        fontsize=8,
        fontweight="bold",
        ha="right",
    )

    for spine in axis.spines.values():
        spine.set_visible(False)

    axis.set_xlabel("SHAP value", fontsize=8, color="#64748b")
    figure.patch.set_facecolor("#ffffff")
    axis.set_facecolor("#ffffff")
    figure.tight_layout(pad=0.55)
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
        "top_features": [],
        "deep_analysis_status": {},
        "evidence": [],
        "llm_summary": None,
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
        analysis["error"] = progress.get("error")

        if analysis["status"] == "COMPLETED":
            # 완료된 것만 전체 결과를 한 번 가져온다
            try:
                full = api_client.get_result(analysis["analysis_id"])
                batch_data["analyses"][index] = to_view(full, analysis)
            except ApiError as e:
                analysis["error"] = {
                    "code": e.code, "message": e.message, "stage": e.stage,
                }
        elif analysis["status"] != "FAILED":
            still_running = True

    return still_running

def to_view(full, previous):
    """API 응답을 대시보드가 읽는 평면 키로 옮긴다."""
    prediction = full.get("prediction") or {}
    signals = full.get("risk_signals") or {}

    return {
        **previous,
        "status": full.get("status"),
        "initial_verdict": full.get("initial_verdict"),
        "route": full.get("route"),
        "reason": full.get("reason"),
        "final_verdict": full.get("final_verdict"),
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

        status = full.get("status") or analysis.get("status") or "QUEUED"
        if status == "COMPLETED":
            # 완료된 건만 상세 뷰 모델로 옮긴다. refresh_pending과 같은 기준이다.
            batch_data["analyses"][index] = to_view(full, analysis)
        else:
            analysis["status"] = status
            analysis["error"] = full.get("error")
            if status != "FAILED":
                still_running = True

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
    statuses = analysis["deep_analysis_status"]
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
    """Render the analyst-first Batch Summary and result navigation."""
    groups = group_batch_analyses(batch_data["analyses"])
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


def render_polling_view(batch_data):
    """진행 중 화면. 시간 초과 뒤에는 자동 갱신 없이 같은 패널을 그린다."""
    if st.session_state.get("poll_timed_out"):
        render_polling_panel(batch_data, auto_refresh=False)
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

else:
    batch_data = st.session_state.get("batch_data")
    if batch_data:
        sync_selected_analysis(batch_data)

        if pending_analyses(batch_data):
            # 진행 중에는 폴링 패널만 그린다. 아래 완료 화면은 종료 후에 렌더된다.
            render_polling_view(batch_data)
            st.stop()

        render_batch_triage(batch_data)
        result = st.session_state.analysis_result

    status = result.get("status")
    if status != "COMPLETED":
        if status == "FAILED":
            error = result.get("error") or {}
            st.error(f"분석 실패: {error.get('message', '원인을 확인할 수 없습니다.')}")
            if error.get("code"):
                st.caption(f"코드 {error['code']} · 단계 {error.get('stage') or '-'}")
        else:
            st.info(f"분석이 진행 중입니다. (상태: {status or '대기 중'})")
        st.stop()

    difficulty_labels = {
        "Low": "낮음 (Low)",
        "Medium": "보통 (Medium)",
        "High": "높음 (High)",
    }
    difficulty_level = result.get("difficulty") or difficulty_label(
        result.get("difficulty_score", 0)
    )
    deep_status = result.get(
        "deep_analysis_status",
        {
            "capa": result.get("capa", "Completed"),
            "floss": "Not Required",
            "speakeasy": result.get("speakeasy", "Completed"),
            "cape": result.get("cape", "Not Required"),
        },
    )
    overall_status = result.get("status", "COMPLETED")
    final_pipeline_status = (
        "COMPLETED" if overall_status == "COMPLETED" else overall_status
    )
    file_type = result.get(
        "file_type",
        "PE/DLL" if result["filename"].lower().endswith(".dll") else "PE/EXE",
    )
    analyzed_at = result.get("analyzed_at", "2026-09-01 17:04")
    display_hash = truncate_hash(result["sha256"])

    # Compact file context header
    context_col, action_col = st.columns([6, 1], gap="medium")
    with context_col:
        st.markdown(
            f"""
            <div class="file-header">
                <div>
                    <div class="file-title">{escape(result['filename'])}</div>
                    <div class="file-hash">SHA256 · {escape(display_hash)}</div>
                </div>
                <div class="file-meta">
                    <span>File Type · {escape(file_type)}</span>
                    <span>Analyzed At · {escape(analyzed_at)}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    action_col.button(
        "새 파일 분석",
        key="new_file_analysis",
        on_click=reset_analysis_session,
        width="stretch",
    )

    # Analysis summary
    st.subheader("분석 요약")
    summary = st.container(border=True)
    difficulty = difficulty_labels.get(
        difficulty_level,
        difficulty_level,
    )
    summary.markdown(
        f"""
        <div class="summary-top">
            <div>
                <div class="summary-label">Initial Verdict</div>
                {verdict_badge_markup(result.get('initial_verdict', 'High-Risk Uncertain'))}
            </div>
            <div class="verdict-arrow">→</div>
            <div>
                <div class="summary-label">Final Verdict</div>
                {verdict_badge_markup(result.get('final_verdict') or 'Pending')}
            </div>
            <div>
                <div class="summary-label">Route</div>
                {route_badge_markup(result['route'])}
            </div>
        </div>
        <div class="summary-divider"></div>
        <div class="summary-bottom">
            <div>
                <div class="summary-label">Raw Probability</div>
                <div class="summary-value">{result['raw_probability']:.1%}</div>
            </div>
            <div>
                <div class="summary-label">Calibrated Probability</div>
                <div class="summary-value">{result['calibrated_probability']:.1%}</div>
            </div>
            <div>
                <div class="summary-label">OOD</div>
                <div class="summary-value">{'Detected' if is_ood_detected(result) else 'Normal'}</div>
            </div>
            <div>
                <div class="summary-label">Model Disagreement</div>
                <div class="summary-value">{result['disagreement']:.2f}</div>
            </div>
            <div>
                <div class="summary-label">Difficulty</div>
                <div class="summary-value">{escape(difficulty_level)}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Routing Decision and Analysis Pipeline
    decision_col, pipeline_col = st.columns(2, gap="medium")

    with decision_col:
        st.subheader("라우팅 결정")
        routing = st.container(
            border=True,
            key="routing-card",
            height=120,
            vertical_alignment="center",
        )
        routing.markdown(
            f"""
            <div class="route-focus">
                <div class="route-label">선택된 분석 경로</div>
                <div class="route-badge">{escape(route_display_name(result['route']).upper())}</div>
            </div>
            <div class="reason-row">
                <span class="reason-chip">OOD · {'Detected' if is_ood_detected(result) else 'Normal'}</span>
                <span class="reason-chip">Disagreement · {result['disagreement']:.2f}</span>
                <span class="reason-chip">Calibrated · {result['calibrated_probability']:.1%}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with pipeline_col:
        st.subheader("분석 파이프라인")
        pipeline = st.container(
            border=True,
            key="pipeline-card",
            height=120,
            vertical_alignment="center",
        )
        pipeline.markdown(
            f"""
            <span class="pipeline-badge badge-info">
                Selected · {escape(route_display_name(result['route']))}
            </span>
            <div class="pipeline-flow">
                <div class="pipeline-node">
                    <div class="pipeline-name">ML Triage</div>
                    {pipeline_state_markup('Completed')}
                </div>
                <span class="pipeline-arrow">→</span>
                <div class="pipeline-node">
                    <div class="pipeline-name">CAPA</div>
                    {pipeline_state_markup(deep_status['capa'])}
                </div>
                <span class="pipeline-arrow">→</span>
                <div class="pipeline-node">
                    <div class="pipeline-name">Speakeasy</div>
                    {pipeline_state_markup(deep_status['speakeasy'])}
                </div>
                <span class="pipeline-arrow">→</span>
                <div class="pipeline-node">
                    <div class="pipeline-name">CAPE</div>
                    {pipeline_state_markup(deep_status['cape'])}
                </div>
                <span class="pipeline-arrow">→</span>
                <div class="pipeline-node">
                    <div class="pipeline-name">Final</div>
                    {pipeline_state_markup(final_pipeline_status)}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Evidence and explainability
    evidence_col, explainability_col = st.columns(2, gap="medium")

    with evidence_col:
        st.subheader("위협 근거")
        evidence = st.container(
            border=True,
            key="evidence-card",
            height="stretch",
            vertical_alignment="center",
        )
        mitre_items = "".join(
            (
                '<div class="evidence-item">'
                '<span class="technique-id">'
                f'{escape(technique.get("technique_id", technique.get("id", "")))}'
                "</span> "
                f'{escape(technique.get("technique_name", technique.get("name", "")))}'
                " · "
                f'{escape(technique.get("tactic", ", ".join(technique.get("sources", []))))}'
                "</div>"
            )
            for technique in result.get(
                "evidence",
                result.get("mitre_attack", []),
            )
        )
        capa_items = "".join(
            f'<div class="evidence-item">· {escape(behavior)}</div>'
            for behavior in result.get("capa_behaviors", [])
        )
        evidence.markdown(
            f"""
            <div class="evidence-grid">
                <div class="evidence-section">
                    <div class="evidence-title">MITRE ATT&CK</div>
                    {mitre_items}
                </div>
                <div class="evidence-section">
                    <div class="evidence-title">CAPA Behavior</div>
                    {capa_items}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with explainability_col:
        st.subheader("설명 가능성")
        explanation = st.container(
            border=True,
            key="explainability-card",
            height=245,
            vertical_alignment="top",
        )
        explanation.markdown(
            '<div class="evidence-title">SHAP 주요 특성 Top 5</div>',
            unsafe_allow_html=True,
        )
        render_shap_chart(
            explanation,
            result.get("top_features", result.get("shap_features", [])),
        )

    # Technical Details
    with st.expander("기술 세부 정보"):
        detail_col, model_col = st.columns(2, gap="large")
        detail_col.write(f"**파일명:** {result['filename']}")
        detail_col.write(f"**SHA256:** `{result['sha256']}`")
        detail_col.write(f"**분석 난이도:** {difficulty}")
        model_col.write(f"**원시 확률:** {result['raw_probability']:.3f}")
        model_col.write(
            f"**보정 확률:** {result['calibrated_probability']:.3f}"
        )
        model_col.write(f"**모델 불일치도:** {result['disagreement']:.2f}")
