import io
import json
from pathlib import Path

from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Table, TableStyle

root = Path.cwd()
out = root / "output/pdf/TRUST-Triage_Lockbox_검증보고서.pdf"
data = root / "docs/validation/lockbox-2026-10-06-r2"
reader = PdfReader(out)
count = len(reader.pages)
W, H = map(float, [reader.pages[1].mediabox.width, reader.pages[1].mediabox.height])
M = 38
pdfmetrics.registerFont(TTFont("K", "C:/Windows/Fonts/malgun.ttf"))
pdfmetrics.registerFont(TTFont("KB", "C:/Windows/Fonts/malgunbd.ttf"))
navy = colors.HexColor("#142D45")
gray = colors.HexColor("#536579")
line = colors.HexColor("#D9E3EA")
b = io.BytesIO()
c = canvas.Canvas(b, pagesize=(W, H))
s = ParagraphStyle(
    "body", fontName="K", fontSize=10, leading=15, textColor=navy, wordWrap="CJK"
)


def p(t, y, size=10, bold=False):
    a = Paragraph(
        t,
        ParagraphStyle(
            "x",
            parent=s,
            fontName="KB" if bold else "K",
            fontSize=size,
            leading=size * 1.5,
        ),
    )
    _, h = a.wrap(W - 2 * M, 900)
    a.drawOn(c, M, y - h)
    return y - h


c.setFillColor(colors.HexColor("#007E86"))
c.rect(M, H - 34, 30, 3, fill=1, stroke=0)
c.setFont("K", 8)
c.setFillColor(gray)
c.drawString(M + 40, H - 34, "TRUST-TRIAGE  /  LOCKBOX VALIDATION")
c.setFillColor(navy)
c.setFont("KB", 23)
c.drawString(M, H - 74, "정책 확정 이력과 검증 근거")
p(
    "Engineering Eval은 기존 별도 보고서로 유지했습니다. 이 페이지는 Lockbox 검증 근거를 기록합니다.",
    H - 88,
    8.4,
)
y = H - 130
rows = [
    ["항목", "상태", "근거 또는 확인 범위"],
    [
        "모델·신호·입력 무결성",
        "확인",
        "jrr_inference_metadata_test.json / jrr_inference_metadata_challenge.json의 해시와 일치",
    ],
    [
        "라우팅·현재 Top500 계약",
        "확인",
        "전체 행 판정 일치, 경계/오류 테스트 243건 통과",
    ],
    [
        "최초 개방 및 변경 관리",
        "운영 이력",
        "제공된 가이드라인에 따르면 모델·정책 확정 후 최초 개방했으며 결과 확인 후 추가 조정 없음",
    ],
]
cells = [
    [
        Paragraph(
            v,
            ParagraphStyle(
                "cell",
                parent=s,
                fontName="KB" if i == 0 else "K",
                fontSize=9,
                leading=12.15,
                textColor=colors.white if i == 0 else navy,
            ),
        )
        for v in row
    ]
    for i, row in enumerate(rows)
]
t = Table(cells, colWidths=[180, 90, 495.89])
t.setStyle(
    TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), navy),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [colors.white, colors.HexColor("#F0F5F8")],
            ),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ]
    )
)
_, h = t.wrap(W - 2 * M, H)
t.drawOn(c, M, y - h)
y -= h + 14
y = p("검증에 사용한 파일 (data/)", y, 11, True) - 4
y = (
    p(
        "확률: jrr_calibrated_proba_test.npy / jrr_calibrated_proba_challenge.npy<br/>라벨: y_test.npy / y_challenge.npy · 저장 라우팅 대조: jrr_routes_test.npy<br/>위험 신호: model_disagreement_{split}.npy, jrr_ood_scores_{split}.npy, jrr_difficulty_scores_{split}.npy<br/>입력·행 정렬: X_{split}.npy, valid_mask_{split}.npy, selected_rows_{split}.npy (split = test 또는 challenge)",
        y,
        8.4,
    )
    - 10
)
f = json.loads((data / "audit_freeze.json").read_text())
y = p("재현 기록", y, 11, True) - 4
y = (
    p(
        "감사 시각: "
        + f["audit_started"]
        + " / 스크립트: audit_lockbox.py v1.0.0<br/>Git: "
        + f["git_commit"]
        + "<br/>고정값: tau_low 0.65 · tau_high 0.983645 · tau_disagree 0.30 · tau_ood 0.0 · tau_difficulty 6.0",
        y,
        8.4,
    )
    - 8
)
y = (
    p(
        "제공된 운영 이력에 따르면 모델 및 JRR 정책 확정 후 Lockbox를 최초 개방했으며, 결과 확인 후 추가 조정은 수행하지 않았습니다. 이번 검증에서는 모델·보정기·특징 목록의 해시 일치와 고정 임계값·라우팅 규칙의 재현성을 확인했습니다.<br/>감사 스크립트의 Windows 경로 처리 오류만 수정해 재실행했으며 모델·정책·지표 정의는 변경하지 않았습니다.",
        y,
        8.4,
    )
    - 7
)
p(
    "출처: docs/validation/lockbox-2026-10-06-r2/ 내 report.md, test_metrics.json, challenge_metrics.json, audit_freeze.json, verification_notes.md. 향후 개선은 별도 버전·독립 평가로 분리합니다.",
    y,
    8.4,
)
c.setStrokeColor(line)
c.line(M, 35, W - M, 35)
c.setFillColor(gray)
c.setFont("K", 8)
c.drawString(M, 21, "2026.10.06  |  고정 정책 검증  |  모델·임계값 변경 없음")
c.drawRightString(W - M, 21, f"6 / {count}")
c.save()
b.seek(0)
w = PdfWriter()
w.clone_document_from_reader(reader)
w.remove_page(5)
w.insert_page(PdfReader(b).pages[0], 5)
tmp = out.with_suffix(".updated.pdf")
w.write(tmp)
check = PdfReader(tmp)
assert len(check.pages) == count and "사용자 변경" not in check.pages[5].extract_text()
for i in range(count):
    if i != 5:
        assert check.pages[i].extract_text() == reader.pages[i].extract_text()
tmp.replace(out)
pth = data / "report.md"
md = pth.read_text(encoding="utf-8")
md = (
    "\n".join(l for l in md.splitlines() if not l.startswith("- 현재 작업 트리는"))
    + "\n"
)
pth.write_text(md, encoding="utf-8")
print("PASS: page 6 updated; other pages preserved")
