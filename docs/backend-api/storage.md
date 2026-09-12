# SHA-256 원본 공유와 분석 산출물 저장

현재 백엔드는 원본을 SHA-256으로 묶고, 분석 요청과 도구 실행 이력을 그 아래에 보관한다. 저장 규격은 `sha256-artifacts-v1`이며, 경로 생성 규칙은 [`trust_triage.storage.layout`](../../src/trust_triage/storage/layout.py) 한 곳에서 관리한다.

## 1. 실제 저장 구조

로컬 기본 경로는 `artifacts/backend/samples`다.

```text
artifacts/backend/samples/
└─ <sha256>/
   ├─ sample.bin
   └─ analyses/
      ├─ <analysis_id_1>/
      │  ├─ initial_analysis/<tool_run_id>/report.json
      │  ├─ deep_analysis/<tool_run_id>/report.json
      │  └─ final_assessment/<tool_run_id>/report.json
      └─ <analysis_id_2>/
         └─ ...
```

`deep_analysis` 리포트는 심층 분석이 실제로 수행되고 종료 결과를 받은 경우 생성한다. 초기 분석 실패도 가능한 경우 `final_assessment` 리포트에 오류와 시스템 제안을 남긴다. 리포트 저장소가 고장 나도 실패 정보는 PostgreSQL에 기록하며, 실패를 악성 판정으로 바꾸지 않는다.

S3는 같은 상대 경로 앞에 설정된 `BACKEND_S3_PREFIX`를 붙인다. 기본값 `raw/`에서는 `s3://<bucket>/raw/<sha256>/sample.bin`과 `s3://<bucket>/raw/<sha256>/analyses/...`가 된다. S3의 폴더 표시는 객체 키의 접두사다. [AWS 객체 키 문서](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html)

| 식별자 | 의미 |
| --- | --- |
| `sha256` | 원본 PE 바이트의 식별자. 같은 저장소의 동일 원본은 공유한다. |
| `analysis_id` | 접수·분석 요청의 식별자. 파일명·접수 시각·판정·검토 이력은 요청별로 유지한다. |
| `tool_run_id` | 도구 실행의 식별자. 현재 백엔드는 해당 처리 시도의 lease UUID를 사용한다. |
| `content_sha256` | 리포트 바이트의 체크섬. 원본 PE의 SHA-256과 구분한다. |

동일 파일을 새 요청으로 접수하면 새로운 분석 번호를 발급하고 분석을 수행한다. 원본 공유가 모델 판정이나 도구 결과의 자동 재사용을 뜻하지 않는다. 같은 `Idempotency-Key`로 같은 요청을 다시 보내면 이전 접수 결과를 돌려주며 새 원본이나 분석을 만들지 않는다. 이전 원본의 보관 기간이 끝났더라도 재전송만으로 원본을 복원하지 않는다. 다시 분석하려면 새 요청을 접수한다.

## 2. PostgreSQL의 역할

| 테이블 | 보관하는 정보 |
| --- | --- |
| `api_sample_objects` | 저장 원본의 내부 위치, SHA-256, 크기, 생성·삭제 시각 |
| `api_analyses` | 해당 원본을 참조하는 분석 요청과 진행·판정 상태 |
| `api_analysis_artifacts` | 실행별 리포트의 위치, 체크섬, 크기, 버전·설정 메타데이터 |
| `api_batches` | 단일·일괄·ZIP 접수, 요청 재전송 식별자, 제외 내역 |
| `api_reviews` | 전문가 검토 이력 |

새 접수에서는 한 원본 위치를 여러 `api_analyses` 행이 참조한다. 위치가 같으면서 SHA-256이나 크기가 다른 입력은 거부한다. 산출물은 분석 번호와 SHA-256을 함께 외래 키로 연결하므로 다른 샘플의 증거를 등록할 수 없다.

API 조회에 사용하는 초기·심층·최종 결과는 기존 DB 필드에 유지한다. 산출물 파일과 DB의 조회용 상태는 용도가 다르며, 파일을 다시 읽어 현재 상태나 전문가 결정을 추정하지 않는다. 공개 API의 주소와 응답 형식은 유지하고 내부 저장 위치는 노출하지 않는다.

## 3. 접수와 저장의 순서

```text
입력 검사와 임시 파일 생성 → SHA-256 계산
    → 해당 SHA-256의 DB 잠금 획득
    → 분석 요청 등록(아직 다른 연결에서는 보이지 않음)
    → 새 요청이면 원본 발행 또는 동일 바이트 확인
    → DB commit → 접수 응답
```

같은 원본에 대한 접수와 삭제는 동일한 PostgreSQL 트랜잭션 잠금을 사용한다. 배치는 SHA-256을 정렬해서 잠금을 얻으므로 서로 반대 순서의 파일 목록도 처리할 수 있다. 원본 바이트 준비는 잠금 전에 끝낸다.

로컬 파일은 같은 볼륨에 완성한 임시 파일을 hard link로 발행한다. S3는 `If-None-Match: *` 조건부 쓰기를 사용한다. 기존 키가 있으면 실제 크기와 SHA-256을 확인하고 재사용하며, 다른 바이트를 덮어쓰지 않는다. [AWS 조건부 쓰기 문서](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)

산출물도 완성된 파일부터 발행한다. 이후 `record_artifact()`와 단계 상태 저장을 같은 DB 트랜잭션으로 확정한다. 처리 권한을 잃었거나 DB 저장에 실패한 시도의 리포트가 완료 결과로 등록되지 않는다.

원본·산출물 발행과 DB commit은 하나의 분산 트랜잭션이 아니다. 그 사이의 강제 종료나 DB rollback은 DB에 등록되지 않은 파일을 남길 수 있다. 서비스가 사용하는 공식 산출물 목록은 `api_analysis_artifacts`이며, 폴더의 모든 파일을 성공 결과로 간주하면 안 된다. 등록되지 않은 파일의 자동 수거 기능은 포함하지 않는다.

## 4. 기존 DB에서 전환

기존 백엔드 `serve`, `run`, `cleanup` 프로세스를 중지하고 새 코드로 테이블을 갱신한 뒤 재시작한다. 아래 `.env`는 사용 중인 설정 파일의 예시 경로다.

```powershell
python -m trust_triage.backend_api --env-file .env init-db
python -m trust_triage.backend_api --env-file .env check
```

`init-db`는 새 테이블과 외래 키를 만들고 기존 분석의 원본 메타데이터를 채운다. `api_analyses.file_location`의 이전 UNIQUE 제약은 공유를 허용하도록 제거한다. 다시 실행해도 기존 분석·검토·산출물 기록을 지우지 않는다.

이전 `<analysis_id>/sample.bin` 원본과 저장 위치는 그대로 유지한다. 새 코드는 이전 `local://<analysis_id>/sample.bin` 및 설정된 S3 접두사 아래의 이전 경로도 읽고 정리할 수 있다. 기존 작업의 입력 위치를 바꾸거나 원본 파일을 일괄 이동하지 않는다. 전환 전 중복 원본은 각자의 보관 기간까지 남을 수 있다.

새 접수부터 해시 경로를 사용한다. 같은 DB를 사용하는 로컬 `serve`·`run`·`cleanup`은 같은 `BACKEND_STORAGE_ROOT`를 사용해야 한다. S3에서는 동일한 버킷과 접두사를 사용한다. 이전 버전의 삭제 처리기를 새 버전과 함께 실행하지 않는다.

## 5. 원본 정리와 리포트 보관

```powershell
python -m trust_triage.backend_api --env-file .env cleanup --limit 100
python -m trust_triage.backend_api --env-file .env cleanup --delete --limit 100
```

삭제 전에 원본 위치를 공유하는 모든 분석을 다시 조회한다. 모든 분석이 종료되고 각각의 보관 기간이 지났으며 연결된 Deep Analysis·Worker도 종료됐다고 확인할 수 있어야 원본을 정리한다. 새 분석이 진행 중이거나 최근에 끝난 분석이 있으면 이전 분석의 원본 삭제도 보류한다.

삭제 대상은 `sample.bin` 하나다. `analyses/`의 리포트와 DB 결과·전문가 검토는 유지한다. 리포트에는 별도의 자동 만료 정책을 적용하지 않는다.

- `candidate_ids`: 보관 기간이 지난 종료 분석 중 이번에 검사할 번호.
- `skipped_ids`: 공유 중인 분석이나 외부 도구 상태 때문에 정리를 보류한 후보 번호.
- `deleted_ids`: 해당 원본의 정리가 완료되어 삭제 시각을 기록한 분석 번호.
- `deleted_sample_count`: 원본 정리가 완료된 저장 객체 수.

`--limit`은 처음 조회할 후보 분석 수다. 공유 원본 하나를 정리할 때 관련된 모든 분석의 삭제 시각을 함께 기록하므로 `deleted_ids`의 길이는 `--limit`보다 클 수 있다. 운영 원본 정리는 DB 참조를 확인하는 `BackendService.cleanup()`을 사용한다. 저장소의 낮은 수준 `delete()` 메서드는 자체적으로 DB 참조를 확인하지 않는다.

## 6. Worker에서 재사용할 인터페이스

공통 저장 모듈은 FastAPI나 백엔드 서비스에 의존하지 않는다. CAPA·FLOSS·Speakeasy 원본 리포트는 후속 통합 브랜치에서 각 도구 실행부가 다음 인터페이스로 저장한다.

```python
from trust_triage.storage import ArtifactIdentity, S3ArtifactStorage

store = S3ArtifactStorage(
    s3_client,
    bucket=configured_bucket,
    prefix=configured_prefix,
    temp_root=temporary_directory,
)
identity = ArtifactIdentity(
    sha256=sample_sha256,
    analysis_id=analysis_id,
    tool="SPEAKEASY",  # CAPA, FLOSS 등도 같은 규칙
    tool_run_id=execution_id,
)
reference = store.put_json(
    identity,
    tool_report,
    tool_version=actual_tool_version,
    config_sha256=actual_config_sha256,
)
# 이미 생성된 리포트 파일은 rb로 열어 store.put_stream(identity, stream, ...) 사용.
# 이후 결과 계약에 reference.to_dict()를 담아 완료 처리와 함께 등록한다.
```

`tool_version`과 `config_sha256`은 실제로 확인한 값을 사용하며, 제공되지 않으면 `null`이다. 초기 분석의 모델 파일 해시·Feature 규격·JRR 임계값은 기존 `feature_metadata`와 초기 분석 리포트에 보존된다. `created_at`은 저장 시각이며, 도구 실행 시작·종료 시각을 대신하지 않는다.

현재 백엔드에서 등록된 리포트는 `repository.list_artifacts(analysis_id)`로 얻는다. `storage.artifact_store(max_bytes=...).read(reference)`는 체크섬을 검증한 바이트를 반환한다. 리포트 기본 상한은 64 MiB이며 `BACKEND_MAX_ARTIFACT_BYTES`로 설정한다.

이번 변경은 백엔드 단계 리포트 저장과 공통 저장 인터페이스까지 적용한다. 기존 Worker의 `include_raw_report=False`나 CAPA/FLOSS 실행부는 수정하지 않았다. `deep_analysis/report.json`은 Gateway에서 받은 종료 스냅샷이며 각 도구의 전체 원본 리포트를 뜻하지 않는다. 개별 도구 리포트 저장, 결과의 산출물 참조 전달, S3 산출물 쓰기 권한은 후속 Worker·Deep Analysis 통합에서 연결한다. 원본을 읽던 Worker 역할에는 산출물 경로의 쓰기 권한도 필요하다.

## 7. 검증

```powershell
python -m pytest tests/backend_api -m "not postgres" -q
# 격리된 테스트 DB를 BACKEND_TEST_DATABASE_URL로 지정한 환경
python -m pytest tests/backend_api -m postgres -q
python -m ruff check src/trust_triage/backend_api src/trust_triage/storage tests/backend_api
```

테스트는 실행 코드 없는 기존 헤더 fixture와 모의 분석기를 사용한다. 로컬/S3 대역의 중복·무결성·리포트 보존, 공유 원본의 보관 기간, 만료 후 재접수, 기록과 상태의 원자적 저장, 실제 PostgreSQL에서의 동시 접수/삭제와 이전 스키마 전환을 확인한다.
