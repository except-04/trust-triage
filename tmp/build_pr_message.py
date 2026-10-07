from pathlib import Path
import ast
import subprocess

root = Path.cwd()
files = subprocess.check_output(['git', 'diff', '--name-only', 'origin/main'], encoding='utf-8').splitlines()

body = '''# PR 제목

feat: 분석가 업무 큐와 일일 예산 기반 검토 우선순위 도입

# PR 본문

## 변경 목적

기존 화면에서는 분석가가 오늘 어떤 파일부터 검토해야 하는지, 사람 검토가 필요한 이유가 무엇인지, 일일 처리 가능량을 얼마나 사용했는지 확인하기 어려웠습니다. 이번 변경은 초기 모델 판정과 사람의 검토 업무를 구분하고, 목적별 업무 큐와 전체·큐별 일일 예산을 제공하여 우선 검토할 파일을 선택할 수 있게 합니다.

악성 확률 하나로 모든 파일을 정렬하는 대신, 긴급 대응은 확인된 고위험 증거를 기준으로, 심층 분석은 검토가 필요한 신호의 종류와 강도를 기준으로 순위를 결정합니다. 각 추천에는 배정 사유와 검토 유형을 표시하고 기존 상세 결과 및 리뷰 저장 흐름으로 연결합니다.

## 업무 큐와 우선순위

| 화면 | 배정·조회 기준 | 정렬·운영 방식 |
| --- | --- | --- |
| 긴급 대응 `EMERGENCY` | CAPA 또는 Speakeasy 출처의 `OBSERVED` 증거에 구체적인 고위험 ATT&CK 기법·행위 이름이 있는 경우 | 위험 행위 등급 → 관측 수준 → 보정된 악성 확률 → 접수 시각 → 분석 ID |
| 심층 분석 `DEEP` | 확률 불확실성·모델 불일치·분포 이탈·분석 난이도 신호가 있거나 초기 판정이 `HIGH_RISK_UNCERTAIN`인 경우 | 확률 불확실성 → 모델 불일치 → 분포 이탈 → 분석 난이도 순으로 유형을 우선하고, 같은 유형에서는 해당 신호 강도순으로 정렬 |
| 자동 처리 `AUTO` | 긴급·심층 조건에 해당하지 않는 초기 `AUTO_BENIGN` 또는 `AUTO_MALICIOUS` | 추천 할당 시 사람 예산에서 제외하고 최신 접수 건부터 조회 |
| 재학습 데이터 `RETRAIN` | 초기 자동 정상·악성 판정을 분석가의 최종 판정이 반대로 변경한 완료 결과 | 별도 이력 조회와 서버 페이지네이션 제공. 재학습 작업을 실행하는 기능은 아님 |
| 오류 항목 `ERROR` | 초기 악성 확률이 누락되거나 숫자로 변환할 수 없거나 유한한 0~1 범위 값이 아닌 경우 | 정상 추천과 분리하여 오류 원인을 표시. 모든 Worker 실행 오류를 통합한 큐는 아님 |

후보 분류는 잘못된 확률을 먼저 오류로 분리한 뒤 긴급 대응, 심층 분석, 자동 처리 조건을 검사합니다. `RETRAIN`은 이 후보 분류와 별도로 완료 이력을 조회하는 화면입니다. `FP` 타입과 예산 필드는 확장 호환용으로 남아 있지만 독립적인 오탐 검증 큐의 배정 정책은 구현하지 않습니다.

### 긴급 대응의 증거 정책

- 1등급: 데이터·디스크 파괴(`T1485`, `T1561`), 피해 목적 암호화(`T1486`).
- 2등급: 복구 방해(`T1490`), 서비스 중단(`T1489`).
- 같은 위험 등급에서는 Speakeasy 동적 관측을 CAPA 정적 규칙 일치보다 우선합니다.
- `CANDIDATE`, 알 수 없는 출처, 일반적인 `Impact` 태그, 악성 확률만으로 긴급 배정하지 않습니다.
- 표시 문구는 CAPA의 정적 기능과 Speakeasy의 분석 환경 내 관측을 구분합니다. 동적 관측도 실제 운영 환경의 피해 결과를 확정하는 의미는 아닙니다.
- 실제 유입량·자산 중요도·피해 범위는 이번 변경에서 측정하지 않습니다.

### 심층 분석의 점수 정책

서로 다른 유형의 원시 점수를 하나의 공통 척도로 비교하지 않습니다. 유형의 우선순위를 먼저 적용합니다.

- 확률 불확실성: `1 - 2 × abs(p - 0.5)`로 같은 유형 내 순위를 계산합니다.
- 모델 불일치: 저장된 모델 간 불일치 값을 사용합니다.
- 분포 이탈: `max(0, -ood_score)`를 사용합니다.
- 분석 난이도: 저장된 난이도 값을 사용합니다.
- 초기 `HIGH_RISK_UNCERTAIN`이지만 구체적인 신호가 없는 건은 별도 예외 정책으로 처리합니다.

대표 검토 유형은 위 우선순위를 따르며, 여러 신호가 동시에 발생한 경우 전체 신호 목록도 유지합니다. 초기 JRR 판정 정책의 순서와 분석가 큐 내부 정렬 순서는 별개입니다.

## 예산·리뷰 집계

- 전체 일일 예산과 긴급·심층·FP 예산, 무제한 설정을 저장합니다.
- 제한 모드에서는 큐별 예산 합이 전체 예산을 넘지 않도록 요청 모델과 DB에서 검증합니다.
- 추천 목록과 예산 밖 대기 목록을 큐별 잔여량 및 전체 잔여량에 맞춰 분리합니다.
- 일일 완료량은 서울 시간 기준으로 계산하며 자동 분석 완료와 사람 리뷰 완료를 구분합니다.
- SHA-256별 최초 완료 리뷰를 기준으로 집계하여 동일 파일의 반복 업로드나 리뷰 revision 증가가 완료량을 중복 차감하지 않게 합니다.
- 완료 시점의 큐와 정책을 리뷰에 보관하여 이후 큐 재평가가 과거 집계의 의미를 바꾸지 않게 합니다.
- 리뷰 저장 시 같은 SHA-256의 분석 행을 잠가 동시 완료 처리의 중복 집계를 방지합니다.
- 미검토 후보는 SHA-256로 묶고, 이미 완료된 같은 해시는 추천에서 제외합니다.

## 화면 변경

초기 화면에 전체 완료량·남은 예산과 예산 설정을 추가하고, 긴급 대응·심층 분석·자동 처리·재학습 데이터·오류 항목 탭을 제공합니다. 큐 표는 순위, 파일명, 해시, 초기 모델 판정, 검토 유형, 악성 확률, 검토 이유를 표시하며 확률은 백분율로 표현합니다.

행을 선택하면 상세 결과로 이동합니다. API 결과를 기존 화면용 데이터로 변환한 뒤 큐 이름·배정 이유·우선순위 정책·추천 또는 대기 상태를 함께 전달합니다. 큐별 표와 페이지 이동 컴포넌트의 키를 구분하고, 상세 진입 시 기존 배치 캐시가 다른 결과를 표시하지 않도록 정리합니다.

## DB 변경과 적용 시 주의점

`schema.sql`에 리뷰 큐·정책 컬럼, 예산 테이블 및 제약조건, 1회성 마이그레이션 기록을 추가합니다. 기존 단일 예산만 설정된 데이터는 조건에 맞으면 심층 예산으로 이관합니다. 기존 테이블에는 `ADD COLUMN IF NOT EXISTS`를 적용하고 리뷰 큐 제약에 `ERROR`를 포함합니다.

이번 변경은 DB 스키마 적용이 필요합니다. 실제 기존 DB 복사본에서 마이그레이션 재실행, 기존 리뷰 보존, 리뷰 저장, 예산 조회·설정을 확인해야 합니다. 코드에 마이그레이션이 있다는 사실과 운영 DB 적용 완료는 구분합니다.

S3 버킷·접속 설정, SQS 주소, DB 연결 설정을 바꾸는 변경은 포함하지 않습니다. 다만 기존 Speakeasy 결과를 소비하는 정규화 및 긴급 큐 분류 동작은 변경됩니다.

## 검증 범위

최근 수행한 관련 검증 기록:

- 긴급 큐·Speakeasy 연결·Worker 결과 처리·ATT&CK 정규화·동적 증거 경계 관련 테스트: **91개 통과**.
- 저장소·원본/산출물 저장·Worker 계약 및 연결 관련 호환성 테스트: **198개 통과, PostgreSQL 환경이 필요한 43개 건너뜀**.
- 두 결과는 서로 겹치는 테스트를 포함하므로 통과 개수를 합산하지 않습니다.
- Speakeasy 원본 report 형식 fixture → 요약 → Worker 결과 계약 검증 → 정규화 → 큐 분류 → 서비스 → 추천 HTTP API의 연결을 검사했습니다.
- 정상 암호화 API 사용, 읽기 전용 이벤트, README 단독, 암호화 확장자 단독, 암호화 호출 실패·결과 누락, 서로 다른 PID/entry point의 이벤트가 고위험 행위로 잘못 승격되지 않는 조건을 검사했습니다.

이 수치는 최근 실행한 범위의 기록이며 현재 변경된 84개 추적 파일 전체에 대한 회귀 검증 완료를 뜻하지 않습니다. 실제 Speakeasy 엔진의 악성 샘플 실행, 운영 AWS SQS/S3 연결, 기존 PostgreSQL 복사본 마이그레이션, 브라우저에서의 전체 UI 흐름은 별도 검증이 필요합니다.

## 함께 포함된 변경

다수의 JRR·모델·전처리·특징 추출·테스트 파일에서 import, 줄바꿈, 타입 표기 등을 정리했습니다. 초기 JRR 라우터와 위험 신호 산출식의 기능 변경으로 설명하지 않습니다. 별도 Lockbox 감사 스크립트와 보고서는 저장된 예측 결과를 재검산하는 자료이며 모델 재학습이나 정책 재최적화를 수행하지 않습니다.

## 파일별 변경 상세

아래 목록은 작성 당시 `origin/main` 대비 추적 파일 84개의 차이와 신규 파일을 구분합니다.

'''

details = {
'dashboard/api_client.py': '일일 예산 조회·설정과 추천 목록 조회 API 호출을 추가합니다. 검색에 overturned_only 필터를 전달하여 재학습 데이터 탭에서 판정이 뒤집힌 이력을 조회하게 합니다.',
'dashboard/app.py': '분석가 큐 화면, 전체·큐별 예산 설정, 무제한 모드, 추천·대기 표, 큐별 페이지 이동, 행 선택과 상세 결과 연결을 추가합니다. 상세 상단에 큐 사유·검토 정책을 표시하고 API 결과 변환과 배치 캐시 정리를 적용합니다. 재학습 이력과 오류 항목을 별도 탭으로 표시합니다.',
'src/trust_triage/backend_api/app.py': 'GET/PUT /analyst/budget 및 GET /analyst/recommendations 엔드포인트를 추가합니다. 기존 분석 목록 필터에 overturned_only를 연결합니다. 요청·응답 모델을 통해 예산 입력 및 추천 응답 형식을 검증합니다.',
'src/trust_triage/backend_api/repository.py': '큐 배정·정렬, 확률 검증, 고위험 증거 평가, SHA-256 중복 제거와 완료 해시 제외를 구현합니다. 서울 날짜 및 최초 완료 리뷰 기준 예산 집계, 완료 시 큐·정책 저장, 동일 해시 잠금, 판정 변경 이력 필터를 추가합니다. 내부 긴급 정렬 필드는 공개 응답에서 제거합니다.',
'src/trust_triage/backend_api/schema.sql': 'api_reviews에 review_queue/review_policy를 추가하고 ERROR를 허용합니다. api_budget_config에 전체·큐별 예산과 무제한 설정 및 합계 제약을 정의합니다. 기존 테이블 컬럼 추가와 단일 예산 이관을 위한 api_migrations 기록을 포함합니다.',
'src/trust_triage/backend_api/schemas.py': 'QueueType, 예산 요청·응답, 추천 후보·큐별 추천 응답 모델을 추가합니다. 후보에 큐 사유·검토 유형·점수 정책·발생 신호를 담고 오류 확률을 nullable로 취급합니다. 예산 합계 초과는 입력 검증 오류로 처리합니다.',
'src/trust_triage/backend_api/service.py': '저장소의 후보·예산을 읽어 큐별 추천과 예산 밖 대기로 분리합니다. 큐 잔여량과 전체 잔여량을 함께 적용하며 AUTO/ERROR의 추천 할당은 사람 예산을 소비하지 않습니다. 재학습 이력 필터를 저장소에 전달합니다.',
'src/trust_triage/deep_analysis/normalizer.py': 'Speakeasy의 파일·프로세스·API 이벤트를 조합하여 데이터 파괴, 피해 목적 암호화, 복구 방해, 서비스 중단의 ATT&CK 증거를 생성합니다. 암호화 API별 반환값, 파일 변경 조건, PID/entry point 문맥을 검사하고 불충분한 단독 이벤트는 긴급 증거로 승격하지 않습니다.',
'tests/backend_api/fake_repository.py': '메모리 저장소에 큐·예산·SHA-256 최초 완료 집계·리뷰 큐 기록·판정 변경 필터를 반영합니다. 긴급 증거 평가는 실제 저장소와 공유하며 응답에 내부 정렬 필드를 남기지 않도록 맞춥니다.',
'tests/backend_api/test_service_processor.py': 'Windows 테스트 저장 경로에 긴 경로 접두사를 적용하여 임시 경로 길이에 따른 테스트 실패를 줄입니다. 제품의 원본 저장 설정을 바꾸는 변경은 아닙니다.',
'docs/jrr_summary.md': '고정 임계값으로 현재 Eval 배열에서 계산한 TPR/FPR 설명과 실측 수치를 갱신하고 표·문서 형식을 정리합니다. 모델 재학습 변경은 아닙니다. 문서 내 과거/현재 수치 설명의 일관성은 최종 리뷰 대상입니다.',
'docs/docs_sqlite_schema.md': '문서의 코드 블록 전후 빈 줄을 정리합니다. 실제 큐·예산 DB 변경은 backend_api/schema.sql에 있습니다.',
'docs/dynamic-analysis/PLAN.md': '설정 인터페이스 예시의 줄바꿈을 정리합니다. 새로운 Worker 아키텍처를 도입하는 변경은 아닙니다.',
'docs/worker/contracts.md': 'Worker 계약 문서의 코드 예시 형식을 정리합니다. 계약 필드의 추가·삭제로 설명하지 않습니다.',
'src/preprocessing/README.md': '데이터 로딩 코드 예시의 공백·줄바꿈을 정리합니다.',
'src/jrr/_jrr_eval_core.py': '평가 함수의 줄바꿈과 불필요한 f-string을 정리합니다. 지표 산식은 유지합니다.',
'src/jrr/optimize_threshold.py': 'import·출력 형식을 정리하고 캐시/입력 파일 누락 조건을 하나의 논리식으로 단순화합니다. Grid Search 대상과 임계값 최적화 정책을 새로 도입하는 변경은 아닙니다.',
'src/jrr/train_calibrator.py': 'import·줄바꿈 및 보간 없는 f-string을 정리합니다. 보정기 학습 정책 변경은 아닙니다.',
'src/models/check_gain_vs_split.py': '모듈 설명 들여쓰기, import와 줄바꿈을 정리합니다. 중요도 비교 계산은 유지합니다.',
'src/models/classify_feature_blocks.py': '모듈 설명과 import·코드 형식을 정리합니다. 특징 블록 분류 규칙은 유지합니다.',
'src/preprocessing/build_index.py': 'import·줄바꿈을 정리하고 이미 정수인 len(meta)의 중복 int 변환을 제거합니다. 데이터 분할 정책은 유지합니다.',
'src/preprocessing/common.py': 'import·줄바꿈과 Timer 반환 타입 표기를 정리합니다. 전처리 산출물 계약을 새로 변경하는 기능은 아닙니다.',
'src/trust_triage/explanation/shap_lightgbm.py': 'import·줄바꿈 및 반환 타입 표기를 정리합니다. SHAP 계산과 특징 순서 검증 정책은 유지합니다.',
'src/trust_triage/feature_extraction/__init__.py': 'import와 __all__의 나열 순서를 정리합니다. 공개 이름의 집합은 유지합니다.',
'src/trust_triage/feature_extraction/result.py': 'import와 자기 클래스 반환 타입 표기를 정리합니다. 특징 추출 결과 필드는 유지합니다.',
'src/trust_triage/feature_extraction/selection.py': 'import·줄바꿈과 자기 클래스 반환 타입 표기를 정리합니다. manifest 검증 및 특징 선택 규칙은 유지합니다.',
'src/trust_triage/static_analysis/__init__.py': 'import와 __all__ 순서를 정리합니다. 공개 분석기·증거 이름의 집합은 유지합니다.',
}

class WithoutImports(ast.NodeTransformer):
    def visit_Import(self, node):
        return None
    def visit_ImportFrom(self, node):
        return None

groups = [
 ('화면 및 API·DB', lambda f: f.startswith('dashboard/') or f.startswith('src/trust_triage/backend_api/')),
 ('심층·동적·정적 분석과 특징 설명', lambda f: f.startswith('src/trust_triage/')),
 ('JRR·모델·전처리', lambda f: f.startswith('src/')),
 ('문서', lambda f: f.startswith('docs/')),
 ('기존 테스트 파일', lambda f: f.startswith('tests/')),
]
seen = set()
for title, accepts in groups:
    rows = [f for f in files if f not in seen and accepts(f)]
    if not rows:
        continue
    body += f'### {title}\n\n| 파일 | 변경 내용 |\n| --- | --- |\n'
    for f in rows:
        seen.add(f)
        desc = details.get(f)
        if desc is None and f.endswith('.py'):
            old = ast.parse(subprocess.check_output(['git', 'show', 'origin/main:' + f], encoding='utf-8'))
            new = ast.parse((root / f).read_text(encoding='utf-8-sig'))
            if ast.dump(old) == ast.dump(new):
                desc = ('기존 테스트의 줄바꿈·공백 등 형식을 정리합니다. 테스트 조건과 단언은 유지합니다.' if f.startswith('tests/') else '줄바꿈·공백 등 코드 형식을 정리합니다. AST 비교상 실행 구조는 동일하며 이 파일에서 새 기능을 도입하지 않습니다.')
            elif ast.dump(WithoutImports().visit(old)) == ast.dump(WithoutImports().visit(new)):
                desc = ('테스트 import와 코드 형식을 정리합니다. import 외 테스트 실행 구조는 동일합니다.' if f.startswith('tests/') else 'import 순서·사용 타입 import·미사용 import와 코드 형식을 정리합니다. import 외 실행 구조는 동일합니다.')
        if desc is None:
            raise RuntimeError('Missing description: ' + f)
        body += f'| `{f}` | {desc} |\n'
    body += '\n'

assert len(seen) == len(files) == 84, (len(seen), len(files))
body += '''### 신규 소스·테스트

| 파일 | 변경 내용 |
| --- | --- |
| `src/jrr/audit_lockbox.py` | 저장된 test/challenge 확률·위험 신호와 라벨을 읽어 고정 정책별 결과, 신호 조합, 지표, 파일 해시를 검산하는 읽기 중심 감사 CLI를 추가합니다. 모델 fitting·추론·임계값 재최적화를 수행하지 않습니다. |
| `tests/__init__.py` | 로컬 tests 패키지의 import 경로를 명시하여 테스트 저장소·공통 fixture 참조를 지원합니다. |
| `tests/backend_api/test_analyst_priority.py` | 미검토 추천, 예외 정책의 동점 정렬, 완료 건 제외, 확률 누락 오류 분리, 예산 및 임시 리뷰 제외 조건을 검사합니다. |
| `tests/backend_api/test_analyst_priority_missing.py` | 확률 누락 데이터가 추천 API의 정상 후보처럼 처리되지 않고 오류 목록으로 분리되는 조건을 검사합니다. |
| `tests/backend_api/test_emergency_queue.py` | 긴급 위험 등급·증거 출처·관측 상태·정렬, 심층 정책, 일반 태그 제외, 실제 정규화 결과 형태의 큐 연결을 검사합니다. |
| `tests/backend_api/test_speakeasy_emergency_integration.py` | 원본 report fixture부터 Worker 계약·정규화·추천 HTTP API까지의 연결을 검사합니다. 정상/실패 암호화, 읽기 전용 파일 이벤트, README·확장자 단독, 무관한 PID/entry point의 오승격을 방지하는 회귀 사례를 포함합니다. |

### 신규 검증 자료·PDF — 포함 여부를 별도로 선택

아래 자료는 현재 미추적 파일입니다. 소스 PR에 자동으로 포함되었다고 가정하지 않으며, 실제 선택한 파일만 PR 본문에 남깁니다.

| 파일 또는 묶음 | 내용 |
| --- | --- |
| `docs/validation/speakeasy-emergency-integration-2026-10-07.md` | 최초 연결 검증에서 확인한 HTTP 응답 문제와 수집 경로 제한을 기록합니다. 최초 실패 결과가 남아 있으므로 최신 통과 결과로 교체된 문서라고 설명하면 안 됩니다. |
| `docs/validation/lockbox-2026-10-06/audit_freeze.json` | 앞선 감사 시점의 정책·입력 등 고정 상태 기록입니다. |
| `docs/validation/lockbox-2026-10-06-r2/audit_freeze.json` | 재검증 실행의 고정 정책·입력·해시 등 감사 기준 기록입니다. |
| `docs/validation/lockbox-2026-10-06-r2/audit_verification.json` | 감사 재현성과 고정 상태 대조 결과입니다. |
| `docs/validation/lockbox-2026-10-06-r2/test_metrics.json` | test 세트의 고정 정책별 지표입니다. |
| `docs/validation/lockbox-2026-10-06-r2/challenge_metrics.json` | challenge 세트의 고정 정책별 지표입니다. |
| `docs/validation/lockbox-2026-10-06-r2/test_signal_combinations.csv` | test 세트의 동시 발생 신호 조합별 집계입니다. |
| `docs/validation/lockbox-2026-10-06-r2/challenge_signal_combinations.csv` | challenge 세트의 동시 발생 신호 조합별 집계입니다. |
| `docs/validation/lockbox-2026-10-06-r2/evidence_review.json` | 로컬 증거 검토 결과입니다. |
| `docs/validation/lockbox-2026-10-06-r2/raw_pe_summary.json` | 원본 PE 자료 검토 요약입니다. |
| `docs/validation/lockbox-2026-10-06-r2/final_checks.json` | 최종 검증 체크 결과입니다. |
| `docs/validation/lockbox-2026-10-06-r2/review_local_evidence.py` | 감사 결과와 로컬 증거 자료를 검토하는 보조 스크립트입니다. |
| `docs/validation/lockbox-2026-10-06-r2/report.md` | 정책 비교 및 test/challenge 지표를 설명하는 검증 보고서입니다. |
| `docs/validation/lockbox-2026-10-06-r2/verification_notes.md` | 검증 절차·해석에 관한 보충 기록입니다. |
| `docs/validation/lockbox-2026-10-06-r2/user_guideline.md` | 검증 결과의 사용·해석 안내입니다. |
| `docs/validation/lockbox-2026-10-06-r2/raw_pe_sources/*.csv` | 샘플 목록·실패 목록·오탐/미탐 원인 등 원본 검토 자료입니다. 포함한다면 평가 근거 부록으로 설명합니다. |
| `output/pdf/TRUST-Triage_Lockbox_검증보고서.pdf` | 팀 공유용 Lockbox 검증 보고서 PDF입니다. |
| `output/pdf/analyst-queue-team-guide.pdf` | 다섯 업무 탭의 배정 조건·정렬·예산을 설명하는 팀 공유용 PDF입니다. |

`tmp/`의 테스트 임시 파일, 렌더링 PNG와 생성 스크립트는 PR의 제품 변경 목록에서 제외합니다. 이 PR 메시지 파일 역시 설명용 산출물이며 제품 소스 변경은 아닙니다.

## 리뷰 시 확인할 사항

- 기존 DB 복사본에서 신규 컬럼·제약과 1회성 예산 이관이 적용되는지 확인합니다.
- 기존 리뷰 데이터를 유지하면서 같은 SHA-256의 최초 완료량과 서울 날짜 경계 집계가 맞는지 확인합니다.
- 큐별 예산과 전체 예산을 함께 설정했을 때 추천·대기 개수가 맞는지 확인합니다.
- 실제 환경에서 새 동적 증거가 저장되면 미완료 파일의 긴급 배정 및 순위가 재평가되는지 확인합니다.
- 큐 표 → 상세 결과 → 리뷰 저장 흐름을 실제 화면에서 확인합니다.
- 추천 API 설명에 남아 있는 ‘악성 확률이 높은 파일 우선’ 문구를 실제 큐별 정책에 맞춰 보완합니다.
- 광범위한 서식 변경과 Lockbox 자료를 함께 포함할 경우 핵심 기능 변경과 구분해 리뷰합니다.

---

작성 기준: 2026-10-07, 현재 작업 트리 `feature/analyst-priority-budget`와 로컬에 저장된 `origin/main` (`d828dd7`)의 비교. 이번 작성 중 fetch·commit·push·병합은 수행하지 않았습니다. 이후 추가 수정 또는 staging 선택에 따라 최종 PR 파일 목록과 검증 설명을 조정해야 합니다.
'''
dest = root / 'output/pr/analyst-priority-budget-pr.md'
dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_text(body, encoding='utf-8')
print(str(dest))
print('Tracked file descriptions:', len(seen))
print('Document characters:', len(body))
