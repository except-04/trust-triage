# Speakeasy Worker

SQS에서 요청을 받아 S3 파일의 SHA-256을 확인하고, 기존 `SpeakeasyAnalyzer`로 분석한 결과를 PostgreSQL에 저장한다. 한 프로세스가 한 번에 한 작업을 처리한다. 정규화 리포트는 Backend와 같은 SHA-256 경로 규격으로 S3에도 보관한다.

`backend_api ... serve`는 HTTP 요청을 받고, `backend_api ... run`은 전체 분석 단계를 진행한다. `speakeasy_worker ... run`은 SQS로 전달된 Speakeasy 작업을 처리한다. Worker의 `COMPLETED`는 Speakeasy 단계와 DB 저장의 완료다.

[팀 공유용 짧은 안내](team-handoff.md) · [Backend 연결·실행 절차](backend-integration.md) · [요청·결과 계약](contracts.md) · [검증 기록](verification.md)

## 로컬 설치와 테스트

저장소 루트에서 실행한다. Python 3.11 기준이며, 기존 가상환경이 있으면 첫 줄은 생략한다.

```powershell
python -m venv trust-triage-env
$workerPython = ".\trust-triage-env\Scripts\python.exe"
& $workerPython -m pip install -r requirements-worker-dev.txt
& $workerPython -m pip install -e . --no-deps
& $workerPython -m pytest tests/speakeasy_worker -q
& $workerPython -m ruff check src/trust_triage/speakeasy_worker tests/speakeasy_worker
```

기본 테스트는 AWS에 접속하지 않고 분석 도구를 대역으로 바꿔 검증한다. 실제 PostgreSQL 테스트도 실행하려면 **테스트 전용 DB**의 접속 문자열을 `WORKER_TEST_DATABASE_URL`에 설정한다. 테스트마다 임시 schema를 만들고 해당 schema만 지운다.

Worker 서버에서는 `requirements-worker.txt`만 설치하면 된다. 개발 목록에는 Backend 계약·회귀 테스트 의존성도 포함한다. AWS 연결용 `boto3`, PostgreSQL 연결용 `psycopg`, `python-dotenv`는 현재 Backend와 같은 버전 범위를 사용한다. Speakeasy는 기존 `1.5.11`을 재사용한다.

## 가영이 준비할 설정

| 항목 | 설정 |
| --- | --- |
| 요청 SQS | Standard 큐, 보존 4일, Visibility timeout 180초 |
| 실패 SQS(DLQ) | Standard 큐, 보존 14일. 요청 큐의 DLQ로 연결하고 `maxReceiveCount=3` |
| S3 | Backend와 같은 비공개 버킷·접두사. 원본 읽기와 Speakeasy 리포트 쓰기 권한 |
| PostgreSQL/RDS | Backend와 공유할 DB 주소·이름·인증 정보·SSL 조건과 Worker 서버 접속 허용. `speakeasy_jobs` 테이블 사용 |
| Worker 서버 | 승인된 격리 환경, CPU·메모리 제한. DB, SQS, S3에 필요한 통신 허용 |
| IAM 역할 | [권한 예시](worker-iam-policy.example.json)의 리소스 이름을 실제 값으로 바꿔 EC2 역할에 부여 |

SQS 전송 누락을 Worker도 복구하므로 요청 큐의 `SendMessage` 권한이 필요하다. 요청 큐와 DLQ는 같은 AWS 계정·리전에 둔다. IAM 예시는 SQS 관리형 암호화와 S3 SSE-S3 기준이며, 별도 KMS 키를 사용하면 해당 키 정책과 권한도 맞춘다. 원본과 리포트가 `raw/`를 공유하므로 접두사 전체를 일괄 만료시키지 않는다. 원본 정리는 Backend의 DB 참조·보관 기간 검사와 조율한다.

## 서버 실행

[.env.worker.example](../../.env.worker.example)을 `.env`에 복사하고 큐 URL, 버킷 이름, DB 접속 문자열을 채운다. 이미 `.env`가 있으면 필요한 항목만 추가한다. `WORKER_S3_BUCKET`·`WORKER_S3_PREFIX`는 Backend와 같은 값을 사용한다. EC2의 AWS 인증은 IAM 역할로 처리한다.

```powershell
& $workerPython -m trust_triage.speakeasy_worker --env-file .env init-db
& $workerPython -m trust_triage.speakeasy_worker --env-file .env check
& $workerPython -m trust_triage.speakeasy_worker --env-file .env run
```

`init-db`는 최초 테이블 생성용이며 기존 데이터를 지우지 않는다. CLI는 기본 `.env`를 읽고 이미 설정된 환경변수를 우선한다. `check`는 DB와 SQS/DLQ 설정을 확인한다. S3 읽기·쓰기 권한과 실제 분석까지 확인하는 명령은 아니다. Linux에서는 가상환경의 `bin/python`으로 같은 명령을 실행한다.

큐 점검은 `QueueArn`, `RedrivePolicy`, `MessageRetentionPeriod`만 조회한다. `FifoQueue`는 FIFO 전용 속성이므로 Standard 큐에 요청하지 않는다. 큐 유형은 [AWS가 안내하는 `.fifo` 이름 접미사](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html)를 반환된 ARN에서 확인한다. `Unknown Attribute FifoQueue` 오류가 발생했던 배포에서는 이 수정이 포함된 코드를 반영하고 `check`를 다시 실행한다.

요청은 Backend 함수로 등록하거나, [예시 JSON](job.example.json)을 실제 값으로 바꿔 아래처럼 넣는다. 예시에 적힌 해시와 S3 파일은 설명용이다.

```powershell
& $workerPython -m trust_triage.speakeasy_worker enqueue .\docs\worker\job.example.json
& $workerPython -m trust_triage.speakeasy_worker get analysis-001
```

## 현재 범위

기본값은 분석 30초, 다운로드 60초, 작업 처리 기한 120초, 파일 50 MiB다. 다운로드·분석 시간의 합은 작업 기한보다 짧아야 한다. 작업 기한은 처리 지점마다 확인하며 DB 저장·리포트 보관·정리에는 별도 시간이 걸릴 수 있다. 서버에서도 프로세스 전체의 메모리·CPU 제한을 적용해야 한다. Speakeasy 자식 프로세스 분리만으로 안전한 격리 환경이 완성되지는 않는다.

`run --once`는 미전송 요청 복구, DLQ 최대 한 건 확인, 요청 큐 최대 한 건 처리를 수행한다. 등록된 작업 전체를 끝내는 명령은 아니다. `dispatch`는 DB의 미전송 요청을 최대 10개 재전송한다. `run` 중 종료 신호를 받으면 현재 작업이 제한 시간·정리 경로를 거친 뒤 종료한다.

정규화 리포트는 `raw/<sha256>/analyses/<analysis_id>/speakeasy/<tool_run_id>/report.json`에 저장하고 DB의 `result.artifact`에 참조를 남긴다. 리포트 저장 오류는 `artifact_error`와 로그에 기록하며 관찰 결과는 DB에 보존한다. `COMPLETED`여도 리포트 보관 여부는 `artifact`로 별도 확인한다. 현재 리포트는 제한된 이벤트를 포함한 정규화 결과이며 전체 엔진 raw report·메모리 덤프는 수집하지 않는다.

이 브랜치에는 `deep_analysis.service_runtime`과 저장 단계 재개 서비스도 포함된다. `backend_api run`이 CAPA/FLOSS 결과를 저장한 뒤 SQS 요청을 등록하고, Worker 종료 결과를 수신하면 증거 반영·선택적 LLM 요약·전체 분석 상태 갱신을 진행한다. [Backend 연결 안내](backend-integration.md)의 의존성·DB 초기화·설정과 세 프로세스 실행이 필요하다. SQS·S3와 분석기는 대역으로, DB는 실제 PostgreSQL로 검증하며 실제 AWS와 승인된 PE를 사용하는 통합 테스트는 배포 환경에서 수행해야 한다.
