from html import escape

import matplotlib.pyplot as plt
import streamlit as st


def reset_analysis_result():
    """Clear stale results whenever the selected upload changes."""
    st.session_state.analysis_result = None


def reset_analysis_session():
    """Return the console to its upload state for a new file."""
    st.session_state.analysis_result = None
    st.session_state.pop("pe_file_uploader", None)


def verdict_badge_markup(verdict):
    labels = {
        "Malicious": "악성 (Malicious)",
        "Benign": "정상 (Benign)",
        "Analyst Review": "분석가 검토 (Analyst Review)",
        "High-Risk Uncertain": "HIGH-RISK UNCERTAIN",
    }
    label = labels.get(verdict, verdict)

    if verdict == "Malicious":
        badge_class = "badge-danger"
    elif verdict == "Benign":
        badge_class = "badge-success"
    elif verdict in {"Analyst Review", "High-Risk Uncertain"}:
        badge_class = "badge-warning"
    else:
        badge_class = "badge-neutral"

    return (
        f'<span class="status-badge {badge_class}">'
        f"{escape(label)}</span>"
    )


def route_badge_markup(route):
    if route == "Deep Analysis":
        badge_class = "badge-info"
    elif route == "Analyst Review":
        badge_class = "badge-warning"
    else:
        badge_class = "badge-neutral"

    return (
        f'<span class="status-badge {badge_class}">'
        f"{escape(route)}</span>"
    )


def pipeline_state_markup(status):
    if status == "Completed":
        label = "✓ 완료"
        status_class = "pipeline-complete"
    elif status == "Not Required":
        label = "○ 미실행"
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


def render_shap_chart(target, features):
    chart_features = features[:5]
    names = [
        feature.get("feature", feature.get("SHAP 특성", "Unknown"))
        for feature in chart_features
    ]
    values = [
        float(feature.get("value", feature.get("영향도", 0)))
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


def build_mock_result(uploaded_file):
    return {
        "filename": uploaded_file.name,
        "sha256": "5a8d7f2c...example...91e3",
        "raw_probability": 0.978,
        "calibrated_probability": 0.942,
        "ood": True,
        "disagreement": 0.13,
        "difficulty": "Medium",
        "risk_score": 82,
        "route": "Deep Analysis",
        "capa": "Completed",
        "speakeasy": "Completed",
        "cape": "Not Required",
        "initial_verdict": "High-Risk Uncertain",
        "final_verdict": "Malicious",
        "file_type": (
            "PE/DLL" if uploaded_file.name.lower().endswith(".dll") else "PE/EXE"
        ),
        "analyzed_at": "2026-09-01 17:04",
        "mitre_attack": [
            {
                "id": "T1059.003",
                "name": "Windows Command Shell",
                "tactic": "Execution",
            },
            {
                "id": "T1105",
                "name": "Ingress Tool Transfer",
                "tactic": "Command and Control",
            },
            {
                "id": "T1140",
                "name": "Deobfuscate/Decode Files or Information",
                "tactic": "Defense Evasion",
            },
        ],
        "capa_behaviors": [
            "PowerShell 명령 실행 기능",
            "외부 URL에서 파일 다운로드",
            "인코딩된 데이터 디코딩 및 메모리 전개",
        ],
        "shap_features": [
            {"feature": "SectionMaxEntropy", "value": 0.31},
            {"feature": "ImportsNb", "value": 0.24},
            {"feature": "SizeOfCode", "value": 0.18},
            {"feature": "LegitCertificate", "value": -0.10},
            {"feature": "PackerSignature", "value": -0.06},
        ],
    }


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
            gap: 0.55rem;
        }

        div[data-testid="stVerticalBlockBorderWrapper"] {
            background: #ffffff;
            border-color: #e2e8f0;
            box-sizing: border-box;
            color: #0f172a;
        }

        hr {
            margin: 0.45rem 0;
        }

        .status-badge,
        .pipeline-badge {
            display: inline-block;
            border: 1px solid transparent;
            border-radius: 999px;
            font-size: 0.8rem;
            font-weight: 650;
            line-height: 1.2;
            padding: 0.3rem 0.65rem;
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
            padding: 0 0 0.4rem;
            text-align: center;
        }

        .route-label {
            color: #64748b;
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.08em;
            margin-bottom: 0.3rem;
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
            padding: 0.4rem 1rem;
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
            padding: 0.25rem 0.6rem;
        }

        .secondary-text {
            color: #64748b;
            font-size: 0.85rem;
            overflow-wrap: anywhere;
        }

        .file-header {
            display: flex;
            align-items: flex-end;
            justify-content: space-between;
            gap: 1rem;
            border-bottom: 1px solid #e2e8f0;
            padding: 0.1rem 0.15rem 0.55rem;
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
            gap: 0.35rem 1rem;
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
            gap: 0.65rem;

            padding: 0.75rem 0.85rem 0.6rem 0.85rem;
        }

        .summary-bottom {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 0.7rem;

            padding: 0.6rem 0.85rem 0.75rem 0.85rem;
        }

        .summary-divider {
            border-top: 1px solid #e2e8f0;
            margin: 0.55rem 0;
        }

        .summary-label {
            color: #64748b;
            font-size: 0.7rem;
            line-height: 1.2;
            margin-bottom: 0.22rem;
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
            gap: 0.85rem;
        }

        .evidence-section + .evidence-section {
            border-left: 1px solid #e2e8f0;
            padding-left: 0.85rem;
        }

        .evidence-title {
            color: #334155;
            font-size: 0.8rem;
            font-weight: 700;
            margin-bottom: 0.35rem;
        }

        .evidence-item {
            color: #334155;
            font-size: 0.74rem;
            line-height: 1.35;
            margin-bottom: 0.28rem;
        }

        .technique-id {
            color: #1d4ed8;
            font-weight: 650;
        }

        .pipeline-flow {
            display: flex;
            align-items: center;
            gap: 0.35rem;
            margin-top: 0.45rem;
            padding-bottom: 1rem;
        }

        .pipeline-node {
            flex: 1 1 0;
            min-width: 0;
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 0.45rem;
            padding: 0.4rem 0.5rem;
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
            margin-top: 0.25rem;
            padding: 0.18rem 0.45rem;
        }

        .pipeline-complete {
            color: #166534;
            background: #dcfce7;
        }

        .pipeline-skipped {
            color: #475569;
            background: #f1f5f9;
        }

        .pipeline-arrow {
            flex: 0 0 auto;
            color: #94a3b8;
            font-size: 0.9rem;
        }

        @media (max-width: 900px) {
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
                padding-top: 0.6rem;
            }
        }
    </style>
    """,
    unsafe_allow_html=True,
)

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None

result = st.session_state.analysis_result

if result is None:
    st.title("EXCEPT 04 Trust Triage")
    st.caption("신뢰 기반 악성코드 트리아지 대시보드")

    uploaded_file = st.file_uploader(
        "분석할 PE 파일을 업로드하세요",
        type=["exe", "dll"],
        key="pe_file_uploader",
        on_change=reset_analysis_result,
    )

    if st.button(
        "분석 시작",
        type="primary",
        disabled=uploaded_file is None,
    ):
        st.session_state.analysis_result = build_mock_result(uploaded_file)
        st.rerun()

else:
    difficulty_labels = {
        "Low": "낮음 (Low)",
        "Medium": "보통 (Medium)",
        "High": "높음 (High)",
    }
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
        result["difficulty"],
        result["difficulty"],
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
                {verdict_badge_markup(result['final_verdict'])}
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
                <div class="summary-value">{'Detected' if result['ood'] else 'Normal'}</div>
            </div>
            <div>
                <div class="summary-label">Model Disagreement</div>
                <div class="summary-value">{result['disagreement']:.2f}</div>
            </div>
            <div>
                <div class="summary-label">Difficulty</div>
                <div class="summary-value">{escape(result['difficulty'])}</div>
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
                <div class="route-badge">{escape(result['route']).upper()}</div>
            </div>
            <div class="reason-row">
                <span class="reason-chip">OOD · {'Detected' if result['ood'] else 'Normal'}</span>
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
                Selected · {escape(result['route'])}
            </span>
            <div class="pipeline-flow">
                <div class="pipeline-node">
                    <div class="pipeline-name">ML Triage</div>
                    {pipeline_state_markup('Completed')}
                </div>
                <span class="pipeline-arrow">→</span>
                <div class="pipeline-node">
                    <div class="pipeline-name">CAPA</div>
                    {pipeline_state_markup(result['capa'])}
                </div>
                <span class="pipeline-arrow">→</span>
                <div class="pipeline-node">
                    <div class="pipeline-name">Speakeasy</div>
                    {pipeline_state_markup(result['speakeasy'])}
                </div>
                <span class="pipeline-arrow">→</span>
                <div class="pipeline-node">
                    <div class="pipeline-name">CAPE</div>
                    {pipeline_state_markup(result['cape'])}
                </div>
                <span class="pipeline-arrow">→</span>
                <div class="pipeline-node">
                    <div class="pipeline-name">Final</div>
                    {pipeline_state_markup('Completed')}
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
                f'<span class="technique-id">{escape(technique["id"])}</span> '
                f'{escape(technique["name"])} · {escape(technique["tactic"])}'
                "</div>"
            )
            for technique in result.get("mitre_attack", [])
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
        render_shap_chart(explanation, result.get("shap_features", []))

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
