import hashlib
from html import escape
from uuid import uuid4

import matplotlib.pyplot as plt
import streamlit as st


def reset_analysis_result():
    """Clear stale batch results whenever the selected uploads change."""
    st.session_state.analysis_result = None
    st.session_state.pop("batch_data", None)
    st.session_state.pop("batch_results", None)
    st.session_state.pop("batch_id", None)
    st.session_state.pop("selected_analysis_id", None)
    st.session_state.pop("batch_group", None)
    st.session_state.pop("group_analysis_selector", None)


def reset_analysis_session():
    """Return the console to its upload state for a new batch."""
    reset_analysis_result()
    st.session_state.pop("pe_file_uploader", None)
    st.session_state.pop("zip_file_uploader", None)
    st.session_state.pop("input_mode", None)


def reset_input_mode():
    """Discard incompatible uploader state when PE/ZIP mode changes."""
    reset_analysis_result()
    st.session_state.pop("pe_file_uploader", None)
    st.session_state.pop("zip_file_uploader", None)


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


def uploaded_pe_descriptors(uploaded_files):
    """Normalize Streamlit uploads before passing them to the mock transport."""
    return [
        {
            "filename": uploaded_file.name,
            "size": uploaded_file.size,
            "content": uploaded_file.getvalue(),
        }
        for uploaded_file in (uploaded_files or [])
    ]


def mock_zip_descriptors(uploaded_zip):
    """Represent ZIP contents without extracting or validating the archive."""
    if uploaded_zip is None:
        return []

    archive_stem = uploaded_zip.name.rsplit(".", 1)[0] or "batch"
    archive_bytes = uploaded_zip.getvalue()
    extensions = (
        "exe",
        "dll",
        "exe",
        "exe",
        "dll",
        "exe",
        "dll",
        "exe",
        "exe",
        "dll",
    )
    size_steps = (1.2, 0.8, 2.1, 1.5, 0.9, 1.8, 1.1, 2.4, 0.7, 1.4)

    return [
        {
            "filename": f"{archive_stem}_{index:02d}.{extension}",
            "size": int(size_mb * 1024 * 1024),
            "content": archive_bytes + f"::{index}".encode(),
        }
        for index, (extension, size_mb) in enumerate(
            zip(extensions, size_steps),
            start=1,
        )
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
            "risk_score": 8,
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
            "risk_score": 96,
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
        "risk_score": 82,
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


def store_mock_batch(batch_data):
    """Persist the mock response using the existing session-state contract."""
    groups = group_batch_analyses(batch_data["analyses"])
    initial_group = "needs_review"
    initial_analysis = (
        groups[initial_group][0]
        if groups[initial_group]
        else batch_data["analyses"][0]
    )
    st.session_state.batch_data = batch_data
    st.session_state.batch_id = batch_data["batch_id"]
    st.session_state.batch_results = batch_data["analyses"]
    st.session_state.selected_analysis_id = initial_analysis["analysis_id"]
    st.session_state.analysis_result = initial_analysis


def render_input_view():
    """Render single/multiple PE and mock ZIP batch input controls."""
    st.title("EXCEPT 04 Trust Triage")
    st.caption("신뢰 기반 악성코드 트리아지 대시보드")

    input_panel = st.container(border=True, key="batch_input_panel")
    input_panel.markdown(
        '<div class="batch-panel-title">분석 입력</div>',
        unsafe_allow_html=True,
    )
    input_mode = input_panel.radio(
        "입력 유형",
        options=("PE 파일", "ZIP 파일"),
        horizontal=True,
        key="input_mode",
        on_change=reset_input_mode,
    )

    file_descriptors = []
    preview_rows = []
    if input_mode == "PE 파일":
        uploaded_files = input_panel.file_uploader(
            "단일 또는 다중 PE 파일을 선택하세요",
            type=["exe", "dll"],
            key="pe_file_uploader",
            on_change=reset_analysis_result,
            accept_multiple_files=True,
        )
        file_descriptors = uploaded_pe_descriptors(uploaded_files)
        preview_rows = [
            {
                "File": descriptor["filename"],
                "Size": format_file_size(descriptor["size"]),
            }
            for descriptor in file_descriptors
        ]
    else:
        uploaded_zip = input_panel.file_uploader(
            "PE 파일이 포함된 ZIP을 선택하세요",
            type=["zip"],
            key="zip_file_uploader",
            on_change=reset_analysis_result,
        )
        file_descriptors = mock_zip_descriptors(uploaded_zip)
        if uploaded_zip is not None:
            preview_rows = [
                {
                    "File": uploaded_zip.name,
                    "Size": format_file_size(uploaded_zip.size),
                }
            ]
            input_panel.caption(
                "ZIP 해제·PE 검증은 수행하지 않습니다. 이번 화면에서는 "
                f"Mock PE {len(file_descriptors)}개로 분석 결과를 구성합니다."
            )

    if preview_rows:
        input_panel.dataframe(
            preview_rows,
            hide_index=True,
            width="stretch",
            height=min(38 * (len(preview_rows) + 1), 260),
        )

    if input_panel.button(
        "분석 시작",
        type="primary",
        disabled=not file_descriptors,
    ):
        store_mock_batch(load_mock_batch(file_descriptors))
        st.rerun()


def render_batch_summary(batch_data):
    """Render the analyst-priority summary derived from analysis records."""
    summary = derive_batch_summary(batch_data["analyses"])
    batch_data["summary"] = summary
    st.markdown(
        f"""
        <div class="batch-section-heading batch-section-heading-first">
            <span>Batch Summary</span>
            <span class="batch-context">Batch ID · {escape(batch_data['batch_id'])}</span>
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
        "batch_id": st.session_state.get("batch_id", "legacy_batch"),
        "summary": derive_batch_summary(st.session_state.batch_results),
        "analyses": st.session_state.batch_results,
    }

result = st.session_state.analysis_result

if result is None:
    render_input_view()

else:
    batch_data = st.session_state.get("batch_data")
    if batch_data:
        render_batch_triage(batch_data)
        result = st.session_state.analysis_result

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
                <div class="summary-label">Risk Score</div>
                <div class="summary-value summary-score">{result['risk_score']}</div>
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
