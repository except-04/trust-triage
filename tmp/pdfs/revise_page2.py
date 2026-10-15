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
c.drawString(M, H - 74, "고정 정책별 운영 결과")
p(
    "동일 데이터에 고정된 각 정책을 적용한 운영 결과입니다. 검토 예산을 동일하게 맞춘 정책 간 우열 평가가 아닙니다.",
    H - 88,
    8.4,
)
y = H - 130
for split, title in [
    ("test", "Test · 960,000건"),
    ("challenge", "Challenge · 6,315건"),
]:
    r = json.loads((data / f"{split}_metrics.json").read_text(encoding="utf-8"))
    y = p(title, y, 11, True) - 8
    rows = [
        [
            "정책",
            "자동 정상",
            "자동 악성",
            "자동 비율",
            "FP",
            "FN",
            "검토 대상",
            "검토 비율",
            "Review Yield",
        ]
    ]
    for k, m in r["policies"].items():
        pc = lambda v: "해당 없음" if v is None else f"{100 * v:.2f}%"
        rows.append(
            [
                k,
                f"{m['auto_benign']:,}",
                f"{m['auto_malicious']:,}",
                pc(m["automatic_rate"]),
                str(m["fp"]),
                f"{m['fn']:,}",
                f"{m['review_count']:,}",
                pc(m["review_rate"]),
                pc(m["review_yield"]),
            ]
        )
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
    t = Table(cells, colWidths=[60, 80, 80, 78, 48, 65, 90, 78, 86.89])
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
                ("RIGHTPADDING", (0, 0), (-1, -1), 9),
                ("LINEBELOW", (0, -1), (-1, -1), 0.5, line),
            ]
        )
    )
    _, h = t.wrap(W - 2 * M, H)
    t.drawOn(c, M, y - h)
    y -= h + 21
p(
    "2-way: p ≥ 0.983645이면 악성. 3-way: 0.65 &lt; p &lt; 0.983645이면 검토로 보류. JRR: 여기에 OOD·모델 불일치·분석 난이도·시스템 오류를 적용합니다.<br/><br/>Review Yield = 검토 대상 중 실제 악성 비율입니다. Challenge는 전부 악성이므로 100%라는 값만으로 선별력이 좋다고 해석할 수 없습니다.",
    y,
)
c.setStrokeColor(line)
c.line(M, 35, W - M, 35)
c.setFillColor(gray)
c.setFont("K", 8)
c.drawString(M, 21, "2026.10.06  |  고정 정책 검증  |  모델·임계값 변경 없음")
c.drawRightString(W - M, 21, f"2 / {count}")
c.save()
b.seek(0)
w = PdfWriter()
w.clone_document_from_reader(reader)
w.remove_page(1)
w.insert_page(PdfReader(b).pages[0], 1)
tmp = out.with_suffix(".updated.pdf")
w.write(tmp)
check = PdfReader(tmp)
assert len(check.pages) == count
assert "고정 정책별 운영 결과" in check.pages[1].extract_text()
for i in range(count):
    if i != 1:
        assert check.pages[i].extract_text() == reader.pages[i].extract_text()
tmp.replace(out)
pth = data / "report.md"
md = (
    pth.read_text(encoding="utf-8")
    .replace("## 정책 비교", "## 고정 정책별 운영 결과")
    .replace(
        "같은 모델 출력 위의 판정 정책 비교다.",
        "같은 모델 출력에 고정된 각 정책을 적용한 운영 결과다. 동일 검토 예산에서의 정책 간 우열 평가가 아니다.",
    )
)
pth.write_text(md, encoding="utf-8")
print("PASS: page 2 replaced; other pages unchanged")
