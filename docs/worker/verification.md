# Worker 구현·검증 기록

검증일: 2026-09-13. 기준은 `main`의 `064e1db`(Backend PR #105 병합)이며 작업 브랜치는 `feature/worker`다.

## 구현 파일

| 위치 | 역할 |
| --- | --- |
| `src/trust_triage/speakeasy_worker/models.py` | SQS 다섯 필드 요청과 단계 결과 계약 |
| `queue.py`, `publisher.py` | SQS 수신·삭제·visibility·DLQ 검사, DB 등록 후 전송과 미전송 복구 |
| `repository.py`, `schema.sql` | PostgreSQL 상태·결과 저장, 점유 토큰, 중복·만료·재시도 관리 |
| `storage.py`, `reports.py` | 원본 다운로드·크기·해시·시간 검사, 공통 SHA-256 규격의 정규화 리포트 보관 |
| `worker.py`, `runtime.py`, `cli.py` | Worker 처리 루프, 실제 어댑터 구성, 실행·점검·조회 명령 |
| `src/trust_triage/deep_analysis/service*.py`, `service_schema.sql`, `checkpoints.py`, `worker_results.py` | 정적 분석 저장, SQS 요청 등록, Worker 결과 검증·수신·재개 |
| `src/trust_triage/deep_analysis/orchestrator.py` | 기존 동기 호출 유지, `prepare`·`resume_speakeasy`·`finalize_static`로 분리 |
| `src/trust_triage/backend_api/__main__.py` | `init-db --deep`으로 같은 DB에 세 계층의 테이블 초기화 |
| `src/trust_triage/dynamic_analysis/speakeasy_analyzer.py` | 자식 결과를 먼저 수신해 큰 결과 때문에 종료 대기가 막히는 문제 수정 |
| `.env.worker.example`, `requirements-worker*.txt` | 실행 설정과 Worker·검증용 설치 목록 |
| `tests/speakeasy_worker/`, `docs/worker/` | 계약·오류·AWS 대역·실제 DB 검증과 실행 안내 |

분석 알고리즘은 기존 모듈을 사용한다. Worker 요청 전송과 결과 수신은 Deep Analysis 서비스가 담당하고 기존 Backend 처리기가 전체 분석 상태를 저장한다. JRR, CAPA/FLOSS, LLM 알고리즘과 전문가 판정 정책을 새로 구현하거나 변경한 작업은 아니다.

## 결과

Python 3.11.9, 독립 가상환경, 임시 PostgreSQL 17.11에서 확인했다. PostgreSQL은 이 작업의 로컬 테스트 데이터 디렉터리와 loopback 포트를 사용했고 검증 후 종료했다.

| 범위 | 결과 |
| --- | --- |
| Worker | 118 passed: 일반·AWS 대역·프로세스 전송 103개 + PostgreSQL 15개 |
| Deep Analysis·Backend↔Worker 연결 | 200 passed: 일반 161개 + PostgreSQL 39개. 요청부터 결과 반영까지의 통합 사례 10개 포함 |
| Backend 회귀 | 598 passed, 2 skipped |
| 기존 Dynamic / Deep / ATT&CK / LLM 입력 제한 / FLOSS | 37 passed |
| 합계 | **953 passed, 2 skipped** |
| Ruff lint / format | 변경 Python 파일 통과 |
| `pip check` | 의존성 충돌 없음 |
| Wheel 생성 | 성공, Worker·Backend·Deep Analysis의 SQL 스키마 포함 확인 |
| CLI·예시·diff | `--help`, 요청 JSON, IAM JSON, `git diff --check` 확인 |

건너뛴 두 항목은 Backend 메모리 저장소에 적용할 수 없는 PostgreSQL 전용 검사다. 실제 PostgreSQL 검사도 함께 실행했다. 기존 Starlette/httpx·anyio 사용에서 deprecation warning 두 건이 있었으며 해당 의존성 전환은 이 변경에 포함하지 않았다.

## 재현

```powershell
$workerPython = ".\trust-triage-env\Scripts\python.exe"
& $workerPython -m pip install -r requirements-deep-analysis-dev.txt
& $workerPython -m pip install -e . --no-deps

# 실제 PostgreSQL 검사에는 테스트 전용 DB URL을 두 변수에 지정
# WORKER_TEST_DATABASE_URL
# BACKEND_TEST_DATABASE_URL
& $workerPython -m pytest tests/speakeasy_worker tests/deep_analysis_service tests/backend_api tests/test_dynamic_analysis.py tests/test_deep_analysis.py -q
& $workerPython -m pytest tests/test_attack_normalization.py tests/test_llm_input_limits.py tests/test_floss_analysis.py -q
& $workerPython -m ruff check src/trust_triage/speakeasy_worker tests/speakeasy_worker src/trust_triage/dynamic_analysis/speakeasy_analyzer.py
& $workerPython -m ruff format --check src/trust_triage/speakeasy_worker tests/speakeasy_worker src/trust_triage/dynamic_analysis/speakeasy_analyzer.py
```

## 검증한 동작과 남은 연결

완료 결과 commit 전에는 SQS 메시지를 삭제하지 않는지, 중복 수신 시 재분석하지 않는지, 살아 있는 작업의 점유·결과를 다른 Worker가 변경하지 않는지 확인했다. S3 크기·해시·경로·시간 검사, 장애 후 재시도, DLQ 실패 기록, 원본 임시 파일 정리, 리포트 저장 실패 시 DB 관찰 결과 보존도 검사했다. 동일 원본의 새 분석은 별도 리포트로 보관한다.

Backend↔Worker 통합 사례는 실제 HTTP 접수, 초기 심층 분석 경로, CAPA/FLOSS 체크포인트 저장, 실제 런타임의 SQS 전송 어댑터, Worker 소비, DB 결과 수신·증거 반영·LLM 호출 지점, 전체 분석 종료와 API 조회를 통과한다. 정적 분석만으로 종료하는 경우와 자동 초기 판정 경로는 SQS에 작업을 보내지 않는다. Worker 시간 초과는 Backend 실패와 전문가 검토 상태로 반영되며 악성으로 확정하지 않는다. 재시작과 중복 전달 후 CAPA/FLOSS·Speakeasy·저장 완료된 후처리가 반복되지 않는지 확인했다.

Speakeasy 결과 전송 검사는 일반 자식 프로세스가 무해한 큰 문자열을 보내도록 하여 수행했다. SQS/S3는 SDK·클라이언트 대역, 초기 모델·분석기·LLM은 가짜 결과를 반환하는 대역을 사용했다. 실제 PE 실행·에뮬레이션과 AWS/RDS·외부 LLM 접속은 수행하지 않았다.

CAPA/FLOSS 이후 자동 요청과 Worker 결과 수신·후처리 코드는 포함되어 있다. 실제 배포에는 SQS·S3·PostgreSQL 연결, 기존 모델·분석 도구 설치, 격리 Worker 서버, 승인된 PE를 통한 배포 환경 검증이 필요하다. 현재 리포트는 정규화 결과이며 전체 엔진 raw report·메모리 덤프는 수집하지 않는다. [연결·실행 절차](backend-integration.md)를 참고한다.
