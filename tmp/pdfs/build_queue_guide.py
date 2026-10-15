from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.colors import HexColor, white
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph, Table, TableStyle
from reportlab.lib.pagesizes import A4

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'output/pdf/analyst-queue-team-guide.pdf'
OUT.parent.mkdir(parents=True, exist_ok=True)
pdfmetrics.registerFont(TTFont('KR', 'C:/Windows/Fonts/HanSantteutDotum-Regular.ttf'))
pdfmetrics.registerFont(TTFont('KR-Bold', 'C:/Windows/Fonts/HanSantteutDotum-Bold.ttf'))
pdfmetrics.registerFontFamily('KR', normal='KR', bold='KR-Bold')
W, H = A4
M = 44
CW = W - 2*M
INK = HexColor('#18243A')
MUTED = HexColor('#56657B')
LINE = HexColor('#DFE6EF')
RED = HexColor('#C63D49')
BLUE = HexColor('#2764AB')
GREEN = HexColor('#237C65')
PURPLE = HexColor('#7554A5')
ORANGE = HexColor('#AD6E19')
STYLES = {
 'body': ParagraphStyle('body', fontName='KR', fontSize=10.8, leading=16.8, textColor=INK, wordWrap='CJK'),
 'small': ParagraphStyle('small', fontName='KR', fontSize=9, leading=13.8, textColor=MUTED, wordWrap='CJK'),
 'cell': ParagraphStyle('cell', fontName='KR', fontSize=10, leading=15, textColor=INK, wordWrap='CJK'),
 'head': ParagraphStyle('head', fontName='KR-Bold', fontSize=10, leading=15, textColor=white, wordWrap='CJK'),
}
c = canvas.Canvas(str(OUT), pagesize=A4)
c.setTitle('TRUST-TRIAGE | 분석가 큐 안내')
c.setAuthor('TRUST-TRIAGE')
y = 0

def p(text, style='body', x=M, width=CW, gap=9):
 global y
 para=Paragraph(text, STYLES[style])
 _,h=para.wrap(width, H)
 para.drawOn(c,x,H-y-h)
 y+=h+gap

def label(text, color=BLUE):
 global y
 y+=7
 c.setFillColor(color); c.setFont('KR-Bold',13)
 c.drawString(M,H-y-14,text)
 y+=25

def box(text, color=BLUE, background='#EFF5FC'):
 global y
 para=Paragraph(text,STYLES['body']); _,h=para.wrap(CW-28,H)
 height=h+24
 c.setFillColor(HexColor(background)); c.roundRect(M,H-y-height,CW,height,8,fill=1,stroke=0)
 c.setFillColor(color); c.rect(M,H-y-height,3,height,fill=1,stroke=0)
 para.drawOn(c,M+14,H-y-12-h)
 y+=height+13

def table(headers, rows, widths, color=BLUE):
 global y
 data=[[Paragraph(escape(t),STYLES['head']) for t in headers]]
 data += [[Paragraph(t,STYLES['cell']) for t in row] for row in rows]
 t=Table(data,colWidths=widths)
 t.setStyle(TableStyle([
  ('BACKGROUND',(0,0),(-1,0),color),('VALIGN',(0,0),(-1,-1),'TOP'),
  ('LEFTPADDING',(0,0),(-1,-1),11),('RIGHTPADDING',(0,0),(-1,-1),11),
  ('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8),
  ('ROWBACKGROUNDS',(0,1),(-1,-1),[HexColor('#F3F6FA'),white]),
  ('LINEBELOW',(0,1),(-1,-1),.5,LINE),
 ]))
 _,h=t.wrap(CW,H); t.drawOn(c,M,H-y-h); y+=h+12

def start(num,title,subtitle):
 global y
 c.setFillColor(HexColor('#F6F8FB')); c.rect(0,H-31,W,31,fill=1,stroke=0)
 c.setFillColor(MUTED); c.setFont('KR',8)
 c.drawString(M,H-20,'TRUST-TRIAGE  /  TEAM GUIDE')
 c.drawRightString(W-M,H-20,'현재 구현 기준 · 2026.10.07')
 y=57
 c.setFillColor(INK); c.setFont('KR-Bold',24)
 c.drawString(M,H-y-26,title); y+=41
 p(subtitle,'small',gap=18)

def finish(num):
 assert y < H-58, (num,y,H-58)
 c.setStrokeColor(LINE); c.line(M,43,W-M,43)
 c.setFont('KR',8); c.setFillColor(MUTED)
 c.drawString(M,28,'분석가 업무 큐 안내 | feature/analyst-priority-budget')
 c.drawRightString(W-M,28,f'{num} / 4')
 c.showPage()

start(1,'파일은 어떤 큐로 들어가나요?','팀 공유용 안내 · 모델의 초기 판정과 사람의 검토 업무를 구분합니다.')
box('<b>핵심:</b> 악성 확률이 높은 순으로만 나누지 않습니다.<br/>확률 오류, 고위험 증거, 추가 검토 신호, 자동 판정 여부를 차례로 확인합니다.')
label('화면의 다섯 탭을 한눈에 보기')
table(['탭','들어가는 대상','팀원이 할 일'],[
 ['<b>긴급 대응</b><br/>EMERGENCY','CAPA·Speakeasy에서 고위험 기능·행동 관련 증거가 확보된 파일','증거를 먼저 확인하고 대응 필요성 판단'],
 ['<b>심층 분석</b><br/>DEEP','확률 불확실성, 모델 불일치, 분포 이탈, 분석 난이도 신호가 있는 파일','추가 분석·사람 검토로 판정 확정'],
 ['<b>자동 처리</b><br/>AUTO','긴급·추가 검토 조건이 없고 초기 자동 정상/악성 판정을 받은 파일','자동 판정 결과 확인'],
 ['<b>재학습 데이터</b><br/>RETRAIN','초기 정상/악성 판정을 분석가가 반대로 수정한 이력','오탐·미탐 사례 검토'],
 ['<b>오류 항목</b><br/>ERROR','보정된 악성 확률이 누락·비정상인 파일','데이터·확률 오류 확인'],
],[110,235,CW-345])
label('대표 큐 배정 순서')
p('<b>① 확률이 비정상인가?</b> → ERROR<br/><b>② 고위험 증거가 있는가?</b> → EMERGENCY<br/><b>③ 추가 검토 신호가 있는가?</b> → DEEP<br/><b>④ 자동 정상/악성 판정인가?</b> → AUTO')
p('RETRAIN은 이 분기와 별도로 조회하는 판정 변경 이력입니다. 따라서 다섯 탭이 모두 동일한 성격의 작업 큐는 아닙니다.','small')
box('<b>예:</b> 악성 확률이 99%여도 고위험 증거가 없고 추가 검토 신호가 없으면 AUTO입니다. 반대로 확률이 낮더라도 구체적 고위험 증거가 있으면 EMERGENCY가 될 수 있습니다.',background='#F3F6FA')
finish(1)

start(2,'긴급 대응: 고위험 증거를 먼저','EMERGENCY · 실제 피해 확정이 아니라, 긴급 검토가 필요한 증거를 기준으로 배정합니다.')
label('배정에 필요한 세 가지 조건',RED)
p('<b>출처:</b> CAPA 또는 Speakeasy<br/><b>상태:</b> OBSERVED인 증거<br/><b>내용:</b> 아래 고위험 기법 ID 또는 대응하는 기법명이 포함됨')
table(['위험 등급','검토 유형','대표 기법'],[
 ['최상위','데이터·디스크 파괴','T1485 / T1561'],
 ['최상위','랜섬웨어 암호화','T1486'],
 ['다음 등급','복구 방해','T1490'],
 ['다음 등급','서비스 중단','T1489'],
],[82,225,CW-307],RED)
label('증거 출처에 따라 의미가 다릅니다',RED)
p('<b>CAPA = 정적 규칙 일치</b><br/>파일 내부에서 고위험 기능에 해당하는 패턴을 찾았습니다. 해당 기능이 실제 실행됐다는 뜻은 아닙니다.')
p('<b>Speakeasy = 동적 관측, 결과 미확인</b><br/>분석 환경의 실행 기록에서 관련 행동을 찾았습니다. 실제 운영 시스템의 피해나 행위 성공을 확정한 것은 아닙니다.')
label('현재 Speakeasy의 주요 인식 조건',RED)
p('<b>파괴:</b> 물리 디스크 경로의 쓰기·삭제·덮어쓰기 기록.<br/><b>암호화:</b> 암호화 API 성공 + 같은 PID 또는 연결 가능한 실행 지점 + 랜섬노트 이름/의심 확장자의 파일 변경.<br/><b>복구 방해:</b> 백업·복구 기능을 제거하거나 비활성화하는 명령 기록.<br/><b>서비스 중단:</b> 서비스 정지 명령에 해당하는 프로세스 기록.')
box('<b>긴급 큐 안의 순위</b><br/>위험 등급 → 동적 관측 우선, 정적 증거 다음 → 악성 확률 높은 순 → 오래된 접수 순 → 분석 ID',color=RED,background='#FFF2F2')
p('일반 Impact 태그, 높은 악성 확률, 파일 읽기, 확장자만으로는 긴급 배정하지 않습니다. 실제 유입량·자산 중요도·피해 범위는 이 정책의 판단 근거가 아닙니다.','small')
finish(2)

start(3,'심층 분석과 자동 처리의 차이','DEEP / AUTO · 추가 검토 신호가 있으면 자동 판정보다 사람 검토를 우선합니다.')
label('심층 분석: 아래 신호 중 하나라도 있으면 대상')
table(['검토 유형','의미','유형 안에서 먼저 보는 파일'],[
 ['확률 불확실성','JRR의 확률 보류 구간','확률이 0.5에 더 가까운 파일'],
 ['모델 불일치','두 모델의 예측 확률 차이가 큼','모델 간 차이가 더 큰 파일'],
 ['분포 이탈','학습 데이터와 다른 특성','OOD 점수가 더 낮은 파일'],
 ['분석 난이도','PE 구조 경고 등 분석이 어려움','난이도 점수가 더 큰 파일'],
],[100,202,CW-302])
box('<b>대표 검토 유형과 정렬 순서</b><br/>확률 불확실성 → 모델 불일치 → 분포 이탈 → 분석 난이도<br/>여러 신호가 있으면 이 순서에서 가장 앞선 유형을 대표로 선택합니다.')
p('신호가 없더라도 초기 판정이 HIGH_RISK_UNCERTAIN이면 DEEP의 “예외 처리” 대상으로 들어갑니다. 같은 유형·같은 점수는 오래된 접수, 분석 ID 순으로 정렬합니다.')
label('확률 기준은 파일에 적용된 JRR 설정을 따릅니다')
p('코드 기본값은 확률 보류 구간 <b>65% 초과 ~ 98.3645% 미만</b>, 모델 간 차이 <b>30%p 이상</b>, OOD 점수 <b>0 미만</b>, 난이도 <b>6 이상</b>입니다. 실제 적용값은 초기 결과의 jrr_thresholds가 기준입니다.','small')
label('자동 처리: 추가 사람 검토 조건이 없는 경우',GREEN)
p('EMERGENCY·DEEP 조건에 해당하지 않고 초기 판정이 <b>AUTO_BENIGN</b> 또는 <b>AUTO_MALICIOUS</b>이면 AUTO에 표시합니다. 최신 접수 순으로 보여주며 사람 검토 예산에서 제외합니다.')
table(['사례','배정 결과'],[
 ['확률 99% + OOD 신호, 긴급 증거 없음','DEEP'],
 ['확률 99% + 추가 신호·긴급 증거 없음 + 자동 악성 판정','AUTO'],
 ['자동 악성 판정 + 고위험 기법 증거 확보','EMERGENCY'],
],[CW-105,105],GREEN)
p('DEEP 탭은 사람의 추가 검토 대상입니다. Speakeasy가 완료된 파일만 모은 목록이 아닙니다. AUTO 표시도 실제 차단·격리 실행을 의미하지 않습니다.','small')
finish(3)

start(4,'이력·오류·예산은 이렇게 봅니다','RETRAIN / ERROR / BUDGET · 추천 대상과 작업 완료 상태를 구분합니다.')
label('재학습 데이터: 판정이 뒤집힌 이력',PURPLE)
table(['초기 모델 판정','분석가 최종 판정','의미'],[
 ['AUTO_MALICIOUS','BENIGN','오탐'],
 ['AUTO_BENIGN','MALICIOUS','미탐'],
],[185,185,CW-370],PURPLE)
p('초기 HIGH_RISK_UNCERTAIN을 정상·악성으로 확정한 건은 현재 RETRAIN 조건에 포함되지 않습니다. 이 탭에 표시된다고 모델 재학습이 자동 실행되는 것은 아닙니다.','small')
label('오류 항목: 악성 확률 자체가 비정상',ORANGE)
p('보정된 악성 확률이 <b>누락, 빈 값, 숫자 변환 불가, NaN, 무한대, 0~1 범위 밖</b>이면 ERROR입니다. 오류를 먼저 검사하므로 고위험 증거가 있더라도 ERROR가 우선합니다.')
p('CAPA 실패나 Speakeasy 타임아웃 등 모든 도구 오류를 모으는 탭은 아닙니다. 초기 결과가 없는 건도 이 추천 조회 경로의 대상이 아닙니다.','small')
label('예산: 큐 배정 이후 추천 수를 제한')
p('<b>제한 모드:</b> 긴급·심층 큐의 남은 예산과 전체 남은 예산 안에서 상위 파일을 추천하고, 나머지는 대기로 표시합니다.<br/><b>무제한 모드:</b> 배정 조건은 그대로이며 예산 때문에 대기로 넘기지 않습니다.<br/><b>완료량:</b> 자동 분석 완료가 아니라 사람의 완료 리뷰를 기준으로 집계합니다. AUTO·ERROR는 추천 시 사람 예산을 제한하지 않습니다.')
box('<b>중복과 재평가</b><br/>같은 SHA-256은 추천 목록에서 대표 한 건만 표시합니다. 동일 해시의 사람 검토가 완료되면 추천에서 제외합니다. 추가 증거가 저장되면 다음 조회에서 DEEP → EMERGENCY 등으로 배정이 달라질 수 있습니다.')
label('팀원들이 기억할 세 가지')
p('<b>① 큐는 업무 목적입니다.</b> 초기 판정·자동 분석 진행 상태와 다릅니다.<br/><b>② 선정 근거를 확인하세요.</b> 확률뿐 아니라 증거 출처·검토 유형이 중요합니다.<br/><b>③ 추가 증거가 순위를 바꿉니다.</b> 화면의 추천은 고정된 작업 예약이 아닙니다.')
p('작성 근거: backend_api/repository.py, service.py, dashboard/app.py, deep_analysis/normalizer.py, jrr/jrr_router.py. 현재 브랜치 구현을 설명하며 탐지 정확도나 운영 배포 완료를 보증하는 자료는 아닙니다.','small',gap=0)
finish(4)
c.save()
print(str(OUT))
