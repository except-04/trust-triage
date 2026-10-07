# PR 제목

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

이 수치는 최근 실행한 범위의 기록이며 이번 PR의 90개 변경 파일 전체에 대한 회귀 검증 완료를 뜻하지 않습니다. 이번 문서 갱신에서는 테스트를 재실행하지 않았습니다. 실제 Speakeasy 엔진의 악성 샘플 실행, 운영 AWS SQS/S3 연결, 기존 PostgreSQL 복사본 마이그레이션, 브라우저에서의 전체 UI 흐름은 별도 검증이 필요합니다.

## 함께 포함된 변경

다수의 JRR·모델·전처리·특징 추출·테스트 파일에서 import, 줄바꿈, 타입 표기 등을 정리했습니다. 초기 JRR 라우터와 위험 신호 산출식의 기능 변경으로 설명하지 않습니다. Lockbox 감사 스크립트는 저장된 예측 결과를 재검산하며 모델 재학습이나 정책 재최적화를 수행하지 않습니다. 검증 보고서·PDF는 이번 커밋에 포함하지 않습니다.

## 파일별 변경 상세

`origin/main...HEAD` 기준 총 **90개 파일**입니다. 기능·내용 변경 16개, 경미한 조건식 수정·테스트 환경 보완 3개, 형식 정리 71개로 나누어 설명합니다.

### 기능 및 문서 내용 변경

| 파일 | 변경 내용 |
| --- | --- |
| `dashboard/api_client.py` | 일일 예산 조회·설정과 추천 목록 조회 API 호출을 추가합니다. 검색에 overturned_only 필터를 전달하여 재학습 데이터 탭에서 판정이 뒤집힌 이력을 조회하게 합니다. |
| `dashboard/app.py` | 분석가 큐 화면, 전체·큐별 예산 설정, 무제한 모드, 추천·대기 표, 큐별 페이지 이동, 행 선택과 상세 결과 연결을 추가합니다. 상세 상단에 큐 사유·검토 정책을 표시하고 API 결과 변환과 배치 캐시 정리를 적용합니다. 재학습 이력과 오류 항목을 별도 탭으로 표시합니다. |
| `src/trust_triage/backend_api/app.py` | GET/PUT /analyst/budget 및 GET /analyst/recommendations 엔드포인트를 추가합니다. 기존 분석 목록 필터에 overturned_only를 연결합니다. 요청·응답 모델을 통해 예산 입력 및 추천 응답 형식을 검증합니다. |
| `src/trust_triage/backend_api/repository.py` | 큐 배정·정렬, 확률 검증, 고위험 증거 평가, SHA-256 중복 제거와 완료 해시 제외를 구현합니다. 서울 날짜 및 최초 완료 리뷰 기준 예산 집계, 완료 시 큐·정책 저장, 동일 해시 잠금, 판정 변경 이력 필터를 추가합니다. 내부 긴급 정렬 필드는 공개 응답에서 제거합니다. |
| `src/trust_triage/backend_api/schema.sql` | api_reviews에 review_queue/review_policy를 추가하고 ERROR를 허용합니다. api_budget_config에 전체·큐별 예산과 무제한 설정 및 합계 제약을 정의합니다. 기존 테이블 컬럼 추가와 단일 예산 이관을 위한 api_migrations 기록을 포함합니다. |
| `src/trust_triage/backend_api/schemas.py` | QueueType, 예산 요청·응답, 추천 후보·큐별 추천 응답 모델을 추가합니다. 후보에 큐 사유·검토 유형·점수 정책·발생 신호를 담고 오류 확률을 nullable로 취급합니다. 예산 합계 초과는 입력 검증 오류로 처리합니다. |
| `src/trust_triage/backend_api/service.py` | 저장소의 후보·예산을 읽어 큐별 추천과 예산 밖 대기로 분리합니다. 큐 잔여량과 전체 잔여량을 함께 적용하며 AUTO/ERROR의 추천 할당은 사람 예산을 소비하지 않습니다. 재학습 이력 필터를 저장소에 전달합니다. |
| `src/trust_triage/deep_analysis/normalizer.py` | Speakeasy의 파일·프로세스·API 이벤트를 조합하여 데이터 파괴, 피해 목적 암호화, 복구 방해, 서비스 중단의 ATT&CK 증거를 생성합니다. 암호화 API별 반환값, 파일 변경 조건, PID/entry point 문맥을 검사하고 불충분한 단독 이벤트는 긴급 증거로 승격하지 않습니다. |
| `docs/jrr_summary.md` | 고정 임계값으로 현재 Eval 배열에서 계산한 TPR/FPR 설명과 실측 수치를 갱신하고 표·문서 형식을 정리합니다. 모델 재학습 변경은 아닙니다. 문서 내 과거/현재 수치 설명의 일관성은 최종 리뷰 대상입니다. |
| `tests/backend_api/fake_repository.py` | 메모리 저장소에 큐·예산·SHA-256 최초 완료 집계·리뷰 큐 기록·판정 변경 필터를 반영합니다. 긴급 증거 평가는 실제 저장소와 공유하며 응답에 내부 정렬 필드를 남기지 않도록 맞춥니다. |

### 조건식 단순화 및 테스트 환경 보완

| 파일 | 변경 내용 |
| --- | --- |
| `src/jrr/optimize_threshold.py` | import·출력 형식을 정리하고 캐시/입력 파일 누락 조건을 하나의 논리식으로 단순화합니다. Grid Search 대상과 임계값 최적화 정책을 새로 도입하는 변경은 아닙니다. |
| `src/preprocessing/build_index.py` | import·줄바꿈을 정리하고 이미 정수인 len(meta)의 중복 int 변환을 제거합니다. 데이터 분할 정책은 유지합니다. |
| `tests/backend_api/test_service_processor.py` | Windows 테스트 저장 경로에 긴 경로 접두사를 적용하여 임시 경로 길이에 따른 테스트 실패를 줄입니다. 제품의 원본 저장 설정을 바꾸는 변경은 아닙니다. |

### 코드·문서 형식 정리 (71개 파일)

아래 파일은 줄바꿈·공백·import 순서 및 미사용 import, 타입 표기, 공개 이름 나열 순서, 설명 들여쓰기를 정리했습니다. 보간이 없는 f-string도 일반 문자열로 정리했습니다. 알고리즘·판정 정책·테스트 조건을 새로 추가한 변경은 없습니다.

대상 파일은 다음과 같습니다.

```text
views.py

attack_mapping.py
feature_names.py

llm_interpreter.py
models.py
service.py

models.py

shap_lightgbm.py

__init__.py
api_groups.py
ember_v3.py
result.py
schema.py
selection.py

models.py

__init__.py
floss_analyzer.py
floss_cli.py

_jrr_eval_core.py
compare_policies.py
disagreement.py
evaluate_jrr.py
evaluate_jrr_final.py
generate_raw_probas.py
jrr_router.py
risk_signals.py
train_calibrator.py

check_gain_vs_split.py
classify_feature_blocks.py
compare_baseline_models.py
compare_lgb_xgb.py
data_contract.py
export_baseline_pkl.py
export_mlflow_result.py
train_xgboost_500.py
tune_lightgbm.py

README.md
common.py
download.py
manifest.py
materialize.py
split_qc.py
vectorize.py

docs_sqlite_schema.md
PLAN.md
contracts.md

test_views.py
conftest.py
conftest.py
test_analyst_review.py
test_batch_filter.py
test_deep_search.py
test_evidence_rendering.py
test_hash_search.py
test_progressive_result.py
test_result_detail.py
test_shap_labels.py
test_unified_upload.py
test_repository.py
test_service.py
test_contract.py
test_dynamic_analysis.py
test_dynamic_evidence_boundaries.py
test_feature_extraction.py
test_feature_names.py
test_floss_analysis.py
test_floss_transport.py
test_llm_input_limits.py
test_mlflow_tracking.py
test_model_data_contract.py
test_shap_lightgbm.py
```

### 이번 커밋에 추가된 소스·테스트 (6개)

| 파일 | 변경 내용 |
| --- | --- |
| `src/jrr/audit_lockbox.py` | 저장된 test/challenge 확률·위험 신호와 라벨을 읽어 고정 정책별 결과, 신호 조합, 지표, 파일 해시를 검산하는 읽기 중심 감사 CLI를 추가합니다. 모델 fitting·추론·임계값 재최적화를 수행하지 않습니다. |
| `tests/__init__.py` | 로컬 tests 패키지의 import 경로를 명시하여 테스트 저장소·공통 fixture 참조를 지원합니다. |
| `tests/backend_api/test_analyst_priority.py` | 미검토 추천, 예외 정책의 동점 정렬, 완료 건 제외, 확률 누락 오류 분리, 예산 및 임시 리뷰 제외 조건을 검사합니다. |
| `tests/backend_api/test_analyst_priority_missing.py` | 확률 누락 데이터가 추천 API의 정상 후보처럼 처리되지 않고 오류 목록으로 분리되는 조건을 검사합니다. |
| `tests/backend_api/test_emergency_queue.py` | 긴급 위험 등급·증거 출처·관측 상태·정렬, 심층 정책, 일반 태그 제외, 실제 정규화 결과 형태의 큐 연결을 검사합니다. |
| `tests/backend_api/test_speakeasy_emergency_integration.py` | 원본 report fixture부터 Worker 계약·정규화·추천 HTTP API까지의 연결을 검사합니다. 정상/실패 암호화, 읽기 전용 파일 이벤트, README·확장자 단독, 무관한 PID/entry point의 오승격을 방지하는 회귀 사례를 포함합니다. |

## 리뷰 시 확인할 사항

- 기존 DB 복사본에서 신규 컬럼·제약과 1회성 예산 이관이 적용되는지 확인합니다.
- 기존 리뷰 데이터를 유지하면서 같은 SHA-256의 최초 완료량과 서울 날짜 경계 집계가 맞는지 확인합니다.
- 큐별 예산과 전체 예산을 함께 설정했을 때 추천·대기 개수가 맞는지 확인합니다.
- 실제 환경에서 새 동적 증거가 저장되면 미완료 파일의 긴급 배정 및 순위가 재평가되는지 확인합니다.
- 큐 표 → 상세 결과 → 리뷰 저장 흐름을 실제 화면에서 확인합니다.
- 추천 API 설명에 남아 있는 ‘악성 확률이 높은 파일 우선’ 문구를 실제 큐별 정책에 맞춰 보완합니다.
- 광범위한 형식 정리와 Lockbox 감사 스크립트는 업무 큐의 기능 변경과 구분해 리뷰합니다.

---

작성 기준: 2026-10-07, `feature/analyst-priority-budget`의 커밋 `a6b1101`와 로컬에 저장된 `origin/main` (`d828dd7`)의 PR 비교(`origin/main...HEAD`). 현재 로컬 브랜치와 원격 추적 브랜치가 같은 커밋을 가리킵니다. 이번 작성 중 fetch·commit·push·병합은 수행하지 않았습니다. `output/`, `tmp/`의 로컬 산출물은 PR 변경 목록에 포함하지 않습니다.
