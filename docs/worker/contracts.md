# Backend 연결

Backend와 Worker는 같은 PostgreSQL의 `speakeasy_jobs` 테이블을 사용한다. 전체 분석 테이블과 별개이며, `analysis_id` 하나당 Speakeasy 작업 하나를 저장한다. 다른 파일이나 새 분석을 실행할 때는 새 `analysis_id`를 만든다.

## 건우가 호출할 함수

프로세스 시작 시 환경변수를 읽어 전송기를 만들고, CAPA/FLOSS 이후 Speakeasy가 필요한 경우에만 `submit`을 호출한다. 아래 코드는 동기 함수이므로 별도 분석 처리 프로세스에서 호출한다.

```python
from trust_triage.speakeasy_worker import (
    SpeakeasyJob, WorkerConfig, create_publisher, utc_now,
)

publisher = create_publisher(WorkerConfig.from_env())

def request_speakeasy(analysis_id, sha256, file_location):
    return publisher.submit(SpeakeasyJob(
        analysis_id=analysis_id,
        sha256=sha256,
        file_location=file_location,
        requested_at=utc_now(),
    )).to_dict()

def get_speakeasy_result(analysis_id):
    record = publisher.repository.get(analysis_id)
    return record.to_dict() if record else None
```

`WorkerConfig.from_env()`는 이미 설정된 환경변수를 읽는다. Python 코드에서 `.env`를 쓰려면 애플리케이션 시작 시 `dotenv.load_dotenv()`를 먼저 호출한다. CLI는 `.env`를 자동으로 읽는다.

`submit`에서 `RetryableError`가 나면 같은 분석 번호로 재호출한다. DB 등록 후 SQS 전송에 실패한 요청은 `dispatch_pending=True`로 남고 실행 중인 Worker가 재전송한다. `InvalidJob`은 입력 형식 오류, `JobConflict`는 이미 다른 파일에 사용한 분석 번호다. 두 오류는 입력을 수정해야 한다. 오류 클래스는 `models.py`, `errors.py`에 있다.

## 요청과 결과

SQS에는 [요청 JSON의 다섯 필드](job.example.json)만 넣는다. `analysis_id`는 영문·숫자로 시작하는 영문·숫자·`-`·`_` 1~128자, `sha256`은 64자리 16진수, `requested_at`은 시간대가 포함된 ISO-8601 시각이다. `file_location`은 `s3://<bucket>/<prefix><sha256>/sample.bin`이며 해시 경로는 [공통 저장 규격](../backend-api/storage.md)을 사용한다. 이미 접수된 이전 `<prefix><analysis_id>/sample.bin`도 지원한다. 다른 원본·리포트 경로는 거부하며 다운로드한 바이트의 해시를 다시 확인한다. `requested_stage`는 항상 `SPEAKEASY`다. 원본 파일이나 실행 명령은 메시지에 넣지 않는다.

`get_speakeasy_result`는 아래 상태와 `result`를 반환한다. 원본 입력의 위치는 제외하지만 결과의 `artifact.file_location`은 내부 리포트 참조로 보존한다. 이 내부 객체를 그대로 공개 HTTP 응답으로 전달하지 않는다.

| `status` | 의미 |
| --- | --- |
| `QUEUED` | 대기 또는 일시적인 오류 후 재시도 대기 |
| `RUNNING` | Worker가 처리 중 |
| `COMPLETED` | Speakeasy 분석 성공, `result` 저장 완료 |
| `FAILED` | Speakeasy 단계 실패, `result.error`에 이유 저장 |

`result`의 `schema_version`은 `speakeasy-result-v1`이다. `analysis_id`, `sha256`, `tool`, `status`, `tool_status`, `behavior`, `error`, `started_at`, `completed_at`, `analysis`를 담는다. `behavior`에는 `processes`, `api_calls`, `files`, `registry`, `network` 배열이 있다. `analysis`에는 기존 `DynamicAnalysisResult.to_dict()`를 저장해 도구 버전·상세 상태·경고·부분 결과를 유지한다. 대형 `raw_report`는 수집하지 않는다.

보관 필드는 `tool_run_id`(처리 시도의 DB lease UUID), `artifact`(공통 산출물 참조 또는 null), `artifact_error`(보관 오류 또는 null)다. 리포트는 `report_kind="normalized_worker_result"`와 참조를 붙이기 전 `result`를 담는다. 참조에는 경로, 리포트 체크섬·크기, 도구 버전과 실제 실행 설정의 해시가 있다. 리포트 파일을 먼저 조건부 쓰기로 발행하고 결과·참조·상태를 DB에 함께 commit한다. 보조 리포트 쓰기 오류는 제한적으로 재시도한 뒤 `artifact_error`에 남기며 관찰 결과는 DB에 보존한다. 따라서 `COMPLETED`는 분석·DB 저장의 성공이며 보관 성공은 `artifact`도 확인한다.

DB가 수락한 참조만 공식 산출물이다. 저장 도중 프로세스 종료로 참조 없는 파일이 남을 수 있으며 자동 수거는 포함하지 않는다. 엔진 전체 raw report 보관과도 구분한다.

도구 성공은 `COMPLETED`, `TIMEOUT`·`UNSUPPORTED_API` 등은 `FAILED`로 표시하되 `tool_status`에 원래 상태를 남긴다. 다운로드 등 분석 전 실패는 `analysis`와 `tool_status`가 `null`이다. 직렬화할 수 없거나 4 MiB를 넘는 결과도 명시적으로 실패 처리한다. 실패는 악성 판정이 아니다.

Backend의 `run` 처리기가 `ExistingDeepGateway`를 통해 이 브랜치의 `DeepAnalysisService`를 재개한다. 서비스는 CAPA/FLOSS 결과를 `deep_analysis_runs`에 저장한 뒤 `JobPublisher.submit()`을 호출한다. Worker의 완료·실패 결과는 요청 번호·SHA-256·리포트 참조를 검증하고 체크포인트에 복사하여 `resume_speakeasy()`로 넘긴다. 브라우저 조회는 후처리를 실행하지 않는다. Worker의 `COMPLETED` 뒤에도 전체 분석은 `RUNNING`이며, Backend가 최종 처리까지 저장하면 종료한다.

정적 분석이 끝나면 `prepare()` 체크포인트를 저장하고, Worker가 필요 없을 때는 `finalize_static()`을 호출한다. Worker가 필요하면 그 결과를 받은 뒤 `resume_speakeasy()`를 호출한다. 이 경로는 CAPA/FLOSS를 다시 실행하지 않는다. 기존 동기식 `run()`도 이 메서드를 사용하여 기존 호출 계약을 유지한다. 실행과 상태 전이는 [Backend 연결 안내](backend-integration.md)를 참고한다.

## 중복과 실패 처리

- 같은 요청이 다시 도착해도 완료 결과가 있으면 재분석하지 않는다. 처리 중인 작업은 DB 점유 토큰으로 다른 Worker의 동시 저장을 막는다.
- 결과와 단계 상태를 같은 DB 트랜잭션에 저장한 뒤 SQS 메시지를 삭제한다. 저장 실패 시 먼저 메모리에 있는 결과로 저장을 재시도한다.
- S3·DB 통신 오류는 재전달하고, 입력·해시 오류나 도구 실패는 결과를 저장하고 끝낸다. 저장 전에 프로세스가 죽으면 재전달 때 분석이 다시 실행될 수 있다.
- 반복 전달된 요청은 AWS의 `maxReceiveCount` 설정에 따라 DLQ로 이동한다. 이것은 분석 횟수가 아니라 메시지 수신 횟수 기준이다.
- Worker는 DLQ를 읽어 기한이 지난 미완료 작업만 `RETRY_EXHAUSTED`로 저장한다. 진행 중이거나 이미 끝난 결과를 덮어쓰지 않는다. 잘못된 JSON·충돌 요청은 DLQ에 남기며 `dead_letter_requires_review` 로그를 운영자가 확인한다.

S3 다운로드 후 임시 파일은 정상·오류 경로 모두 정리한다. 강제 종료로 남은 임시 파일은 Worker가 멈춘 상태에서 운영자가 정리한다. 큐와 DB 저장 사이에 장애가 나도 완료 상태를 임의로 만들지 않는다.

기준: [팀 이슈 #77](https://github.com/except-04/trust-triage/issues/77)와 [현재 Backend 저장 계약](../backend-api/storage.md). 재전달·DLQ 동작은 [AWS Standard Queue](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/standard-queues-at-least-once-delivery.html), [Visibility timeout](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html), [DLQ](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html)를 따른다.
