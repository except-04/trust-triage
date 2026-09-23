# Deep review 수정 기록

기준 커밋은 `30bd83ff2c70231b479961618015a941bcad19d4`다. 운영 AWS,
실제 CAPA/FLOSS/Speakeasy, 실제 MonoGPT와 PostgreSQL은 이 작업 환경에서 실행하지
않았다. 테스트는 공개 가능한 비실행 바이트와 로컬 HTTP 서버, 저장소 대역을
사용했다.

## 수정 항목

- **F01 결과 크기 계약**: `DeepAnalysisService.get()`의 `deep-view-v2` 조회는
  최상위 `evidence`와 `tool_statuses`를 정본으로 사용한다. 중첩 `result`에는
  `#/evidence`, `#/tool_statuses` JSON 참조를 둔다. 128 KiB보다 큰 CAPA/FLOSS
  상세 결과는 S3 artifact로 저장하고 체크포인트와 조회 응답에는 요약 및 무결성
  참조를 둔다. 기존 inline 체크포인트는 DB를 바꾸지 않고 조회 응답만 축약한다.
- **F02 부모·하위 종료 연결**: 부모의 `DEEP_WAIT_TIMEOUT` 전에 취소 사유를
  `deep_analysis_runs.cancellation`에 기록한다. 기존 소유자의 renew/save는
  거부하고, 독립 조정 단계가 lease 만료 후 실패 결과를 확정한다. 대기 Worker는
  취소하고 활성 Worker 결과는 덮어쓰지 않는다. cleanup은 keyset pagination으로
  한 번에 최대 1,000개 후보를 검사한다. 한도를 채우면 응답의 `next_cursor`를
  `cleanup --after`에 전달해 이어서 실행할 수 있다.

```powershell
python -m trust_triage.backend_api --env-file .env cleanup --delete --after '{"completed_at":"<next_cursor의 시간>","analysis_id":"<next_cursor의 ID>"}'
```
- **F07 LLM 전체 기한**: MonoGPT HTTP 호출을 disposable process에서 실행한다.
  전체 응답 기한에 도달하면 프로세스를 종료하고, 응답 크기는 기본 1 MiB로
  제한한다. timeout 또는 과대 응답 뒤의 다음 요청도 새 프로세스에서 처리한다.
- **F03 CAPA match 구조**: 공식 ResultDocument의 `[Address, Match]` 쌍에서
  주소만 `match_locations`로 정규화하고 MatchTree는 `match_details`에 보존한다.
- **F04 도구 보고서 해시**: CAPA/FLOSS 보고서가 SHA-256을 제공하면 입력 파일의
  로컬 해시와 비교한다. 불일치는 `PARSE_ERROR`이며 Evidence를 생성하지 않는다.
  해시가 없는 기존 지원 형식은 로컬 입력 해시를 정본으로 사용하고 경고를 남긴다.
- **F05 최소 보고서 구조**: CAPA는 `meta/analysis/sample/rules`, FLOSS는
  `metadata/analysis/strings` 컨테이너를 검증한다. 종료 코드 0의 `{}`는 성공이
  아니다. 정상적인 빈 `rules` 또는 빈 `strings`는 허용한다.
- **F06 서비스 생성 매핑**: `OpenSCManagerA/W`는 SCM 연결로만 취급한다.
  `CreateServiceA/W` 호출만 `T1543.003` 후보가 되며 명시적인 NULL/0 반환은
  매핑하지 않는다.

Backend의 최종 판정 정책과 전문가 검토 정책은 변경하지 않았다. 분석 실패도 악성
Evidence로 변환하지 않는다.

## 2026-09-23 재검토 보완

- MonoGPT의 자식 프로세스 read timeout에서 고정 1초 상한을 제거했다. 부모의
  전체 호출 기한과 응답 크기 제한은 유지한다. 헤더와 본문이 각각 1.5초 늦는
  정상 응답을 회귀 테스트에 추가했다.
- Speakeasy 결과가 4 MiB를 넘으면 중복된 `behavior` 표시 복사본을 먼저
  줄인다. 원래 이벤트 자체도 상한을 넘으면 일부를 보존하고 원래 개수와
  생략 여부를 기록한다. 크기 때문에 성공 상태와 분석 객체를 통째로 잃지 않는다.
- CAPA/FLOSS 개별 상세가 8 MiB를 넘으면 도구 상태와 실제 크기·상한을
  체크포인트에 남기고 상세만 생략한다. S3 보관 실패도 별도 진단으로 남긴다.
- 기존 PostgreSQL 테이블에도 `cancellation` JSON 객체 CHECK 제약을 별도
  마이그레이션으로 추가한다. 위반 데이터가 있으면 제약 검증이 실패하므로
  배포 전에 해당 행을 조사해야 한다.
- 동적 분석의 두 할당 API만으로 Process Injection 후보를 만들지 않는다.
  파일 경로·네트워크 목적지 등 제한된 이벤트 관찰을 Evidence와 LLM 입력에
  전달한다. 첫 Evidence가 입력 예산을 넘으면 생략하고, 응답의 필수 필드와
  확정 판정의 근거 ID를 검증한다.
- 선택적 Speakeasy raw report 저장 오류는 분석 엔진 경고와 분리해 기록한다.

## 호환성과 배포

`deep-view-v2`는 최상위 필드를 기존과 동일하게 유지한다. 중첩
`result.evidence`와 `result.tool_statuses`를 직접 읽던 내부 소비자는 각각
최상위 `evidence`, `tool_statuses`를 읽어야 한다. 현재 Gateway, Backend 저장,
REST API와 Dashboard 경로는 최상위 필드를 사용한다.

기존 `deep-checkpoint-v1`과 완료 결과는 그대로 읽는다. PostgreSQL에는 nullable
`cancellation` 열과 JSON 객체 CHECK 제약을 추가한다. 배포 순서는 다음과 같다.

```bash
./venv/bin/python -m trust_triage.backend_api --env-file .env init-db --deep
sudo systemctl restart trust-triage-api.service
sudo systemctl restart trust-triage-processor.service
sudo systemctl restart trust-triage-speakeasy.service
sudo systemctl restart trust-triage-dashboard.service
```

큰 CAPA/FLOSS 상세 결과를 artifact로 보관하려면 Worker와 동일한 S3 prefix에서
`s3:PutObject` 및 `s3:GetObject` 권한이 필요하다. 상세 JSON은 8 MiB 이하로
제한되고, archive된 결과는 API 조회에 최대 64개 CAPA/FLOSS 항목만 미리보기로
포함된다.

## 검증 범위

이전 커밋의 전체 저장소 시험 명령 `$env:MPLBACKEND='Agg'; python -m pytest -q`
결과는 `1195 passed, 110 skipped`였다. 이번 재검토 보완 후에는 심층분석,
Worker, Backend 연결 관련 시험에서 `434 passed, 58 skipped`였고 수정 파일의
Ruff 검사가 통과했다. 현재 환경의 전체 저장소 실행은 대시보드 시험 구간에서
오래 진행되지 않아 중단했으므로 이번 변경의 전체 suite 통과를 주장하지 않는다.
skip에는 `BACKEND_TEST_DATABASE_URL` 또는 `WORKER_TEST_DATABASE_URL`이 필요한
PostgreSQL 검사, 외부 MonoGPT 자격 증명이 필요한 검사, 공식 LightGBM 모델 산출물이
필요한 검사가 포함된다. 메모리 저장소 통합시험은 HTTP 접수부터 Deep Analysis,
Worker, Gateway, Backend 저장과 API 조회까지 실행했다. 실제 PostgreSQL
취소/fencing 시험도 추가했으며 DB URL이 있는 CI 또는 배포 전 환경에서 실행해야
한다. pytest 출력에서 의존 라이브러리 deprecation warning 5개가 보고되었다.
