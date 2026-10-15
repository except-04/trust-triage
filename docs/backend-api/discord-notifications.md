# Discord 분석 알림

BackendProcessor가 Discord Incoming Webhook으로 한국어 Embed를 전송한다.
Bot 계정, OAuth2, Gateway, 새 패키지, DB 테이블/마이그레이션, 외부 메시지 큐는 필요 없다.
판정 정책과 분석 결과를 변경하지 않으며, 알림 실패로 분석 재시도를 요청하지 않는다.

## 설정

분석 작업을 수행하는 Backend processor 프로세스에 `DISCORD_WEBHOOK_URL` 환경변수 하나를 주입한다.
값을 지정하지 않거나 공백만 지정하면 스레드/HTTP 요청 없이 비활성화된다.
BackendConfig는 기존 DB/API 비밀 설정과 동일하게 이 필드를 `repr=False`로 관리한다.

실제 값은 운영 비밀 설정에서 주입한다. 소스 코드, 테스트, 쉘 명령 이력, 로그 또는
GitHub 공개 변수에 붙여 넣지 않는다. 이 작업은 실제 .env를 생성하거나 수정하지 않았다.
CLI는 .env를 자동으로 읽지 않는다. 기존 실행 방식이 `--env-file`을 사용한다면
그 설정을 통해 로딩된 환경변수도 사용한다. 이미 설정된 프로세스 환경변수가 우선한다.

일반 텍스트 채널의 Incoming Webhook을 사용한다. HTTPS의 discord.com,
canary.discord.com, ptb.discord.com 호스트와 표준 /api/webhooks 또는
/api/v10/webhooks 경로만 허용한다. 쿼리/fragment가 붙은 URL, 다른 호스트,
포럼 채널용 thread 지정은 지원하지 않는다. 잘못된 형식이면 알림만 비활성화하고
고정된 경고 코드만 기록한다. 운영 URL은 문서와 예제에 넣지 않는다.

## 이벤트와 영속화 경계

| 이벤트 | 실제 알림 요청 시점 | 색상 / 주요 내용 |
| --- | --- | --- |
| ANALYSIS_STARTED | 전송 중단 | 없음 |
| RISK_ALERT | _checkpoint의 sample_transaction이 성공적으로 종료되어 save_initial이 commit된 뒤 | 주황색 / 초기 JRR 판정, 보정 확률, 발현 위험 신호 |
| ANALYSIS_COMPLETED | 배치에 속하지 않은 단일 분석의 finish가 commit된 뒤 | 초록색 / 초기 판정, 최종 시스템 판정, 전문가 검토 필요 여부 |
| ANALYSIS_FAILED | 심층 실패의 _finalize 또는 최종 예외 처리에서 FAILED 저장이 commit된 뒤 | 빨간색 / 실패 단계, 허용된 오류 코드 |
| BATCH_SUMMARY | 파일별 최종 commit 후 기존 batch_record 조회에서 모든 분석의 종료를 확인한 경우 | 초록색 / 배치 ID, 대상·완료·실패·SKIPPED 및 최종 판정별 건수 |

업로드 접수 및 실제 claim 모두 시작 알림을 보내지 않는다.
batch_id가 없는 단일 파일은 정상 완료 알림 1건을 유지한다. 복수 파일 또는 ZIP 배치에서는
파일별 완료 알림을 생략한다. 배치로 접수했다면 분석 대상이 1개만 남은 경우도 요약으로 처리한다.
배치 중 위험 판정 및 최종 실패는 배치 종료를 기다리지 않고 기존 시점에 전송 버퍼에 넣는다.

배치 조회에는 기존 repository.batch_record(), BatchRecord, BatchInputReport를 재사용한다.
분석 대상이 1건 이상이고 모든 작업이 COMPLETED 또는 FAILED일 때만 요약을 생성한다.
QUEUED/RUNNING이 남아 있거나 전부 SKIPPED여서 분석 대상이 0건이면 보내지 않는다.
SKIPPED는 입력 보고서의 제외 항목을 세며, 입력 보고서가 없는 이전 배치는 0으로 표시한다.
MALICIOUS/SUSPICIOUS/BENIGN/INCONCLUSIVE는 COMPLETED 작업의
final_assessment.final_verdict만 집계한다. FAILED 작업의 판정은 포함하지 않으며
초기 JRR 또는 분석가의 수정 판정을 대신 사용하지 않는다. 파일명 목록은 전송하지 않는다.

RISK_ALERT는 HIGH_RISK_UNCERTAIN(심층 분석 대상)과 AUTO_MALICIOUS(악성 경보 및
전문가 검토 대상)에만 전송한다. 둘 다 분석가가 확정한 악성으로 표현하지 않는다.
AUTO_BENIGN에는 위험 경고가 없다.

완료는 MALICIOUS / SUSPICIOUS / BENIGN / INCONCLUSIVE를 그대로 표시한다.
시스템 판정과 분석가의 확정 판정은 별도이며, 최종 악성 판정이어도 완료 이벤트는 초록색이다.
실패 이벤트는 판정을 표시하지 않으며 실패를 악성의 증거로 해석하지 않는다.
일시적 release/retry에는 실패 이벤트를 만들지 않는다.
실패 artifact 저장 불가 시 기존 DB-only finish 경로도, finish가 True를 반환해야 알린다.

알림 호출과 배치 조회는 파일별 저장 트랜잭션이 성공적으로 종료된 뒤 수행하며,
DB 결과를 수정하지 않는다. 최종 저장 실패·rollback·lease 거절에는 배치를 조회하지 않는다.
알림 비활성화 또는 단일 파일에서는 배치 조회도 하지 않는다.
배치 조회·집계 예외는 고정 로그 discord_notification_completion_failed 또는
discord_notification_enqueue_failed로 격리하여 저장된 결과나 분석 재시도에 영향을 주지 않는다.
배치 작업마다 최종 저장 후 기존 DB 조회 1회가 추가된다. 조회는 기존 repository의 연결 및
statement timeout을 따르므로 DB 지연만큼 다음 작업 시작이 늦어질 수 있다.
emit은 허용된 필드만 추출하여 작은 JSON을 만든 후 메모리 버퍼에 비차단 방식으로 넣는다.
전용 daemon 스레드 하나가 HTTP를 처리하므로 Worker는 네트워크 응답을 기다리지 않는다.

## 전송 및 보안

- 표준 라이브러리만 사용하며, 이벤트당 HTTP 시도는 최대 1회(재시도 0회)다.
  429, 5xx, TLS/DNS 오류, 타임아웃을 포함해 재전송하지 않는다.
- HTTP 소켓 타임아웃은 2초이며 응답 본문을 읽지 않는다. 서버 저장 확인을 위해
  wait=true를 사용한다. 리다이렉트와 환경변수 기반 HTTP 프록시를 사용하지 않는다.
- 소켓 타임아웃은 DNS 해석을 포함한 엄격한 전체 요청 시간 상한이 아니다.
  DNS/저속 응답이 길어져도 분석 Worker는 기다리지 않는다. 전송 스레드는 하나로 제한된다.
- 대기 버퍼는 프로세서당 최대 128개이고 초과 이벤트는 버린다.
  버퍼에는 정리된 JSON만 보관하며, 전체 AnalysisRecord나 PE 데이터는 넣지 않는다.
- close는 최대 0.2초만 전송 스레드를 기다린다. 프로세스가 종료되면 남은 알림은 유실될 수 있다.
- URL/토큰, 예외 본문, 응답 본문은 로그에 남기지 않는다.
  관측용 로그는 discord_notification_delivery_failed, discord_notification_http_failed,
  discord_notification_enqueue_failed, discord_notification_buffer_full 등 고정 문자열이다.
- PE 원문, storage 경로, DB 정보, API 키, 스택, 분석 reason/LLM 원문,
  분석가 의견은 payload로 복사하지 않는다.
- 파일명은 경로를 제거하고 128자로 제한한다. URL, 알려진 설정 비밀값, 긴 토큰,
  제어문자, Markdown/링크/멘션 문법을 제거한다. allowed_mentions도 비워 둔다.
  임의의 짧은 문자열이 비밀인지 완벽히 판별할 수는 없으므로 파일명 자체에 비밀을 넣지 않는다.
- 오류 code와 stage는 고정 allowlist로 제한한다. 알 수 없는 code는 ANALYSIS_ERROR,
  stage는 '확인 불가'로 표시한다. 상세 조사는 내부의 안전한 운영 도구로 수행한다.

Discord 메시지 형식은 [공식 Execute Webhook 문서](https://docs.discord.com/developers/resources/webhook#execute-webhook)의
embeds, allowed_mentions, wait 동작을 따른다.

## 중복 및 유실의 한계

이 기능은 best-effort 알림이다. DB 이벤트 기록/outbox가 없으므로 정확히 한 번 전달이나
최소 한 번 전달을 보장하지 않는다. 알림을 분석 결과의 원장으로 사용하지 않는다.

정상 resume는 INITIAL → WAITING_DEEP/FINALIZING → DONE 체크포인트와 lease fencing을
따르므로 초기 경고/완료를 다시 발송하지 않는다. 완료된 작업은 claim되지 않는다.
파일별 이벤트의 중복 억제는 기존 DB 상태에 의존한다.

배치 요약은 같은 DiscordNotifier 인스턴스 안에서 잠금으로 확인·enqueue·기록을 함께 수행한다.
최근 요약 1,024개 배치 ID만 OrderedDict에 보관하고 한도를 넘으면 가장 오래된 ID를 제거한다.
기록 기준은 HTTP 성공이 아닌 전송 버퍼 삽입 성공이다. HTTP 오류·타임아웃 뒤 같은 배치의
콜백이 다시 와도 재전송하지 않는다. 버퍼 포화 등으로 삽입하지 못한 배치는 기록하지 않는다.
원래의 파일별 경고·실패 알림에는 이 배치 중복 방지 기록을 적용하지 않는다.

- 재시작/인스턴스 교체 시 배치 기록이 사라지고, 여러 Processor 사이에서도 공유되지 않는다.
  동시 실행되는 별도 인스턴스나 재시작 후 종료 콜백 재실행, 오래된 ID의 캐시 퇴출 이후
  재처리에서는 중복 요약이 가능하다. 단일 인스턴스 내 동시 호출만 잠금으로 억제한다.
- 재시작 자체가 완료 배치를 다시 보내지는 않는다. 기존 terminal 작업은 claim되지 않으며,
  완료 배치를 검색하여 알림을 복구하는 별도의 sweep/replay 기능도 없다.
- 마지막 작업 commit 후 배치 조회가 실패하거나 enqueue 전에 프로세스가 종료되면
  요약이 유실될 수 있다. 추가 종료 콜백이 없다면 자동으로 복구하지 않는다.
- 결과 commit 직후 enqueue 전에 프로세스가 종료되면 파일별 알림도 유실된다.
  commit은 됐지만 응답이 유실된 경우도 알림을 보내지 않을 수 있다.
- 버퍼 포화, 종료, 장애, rate limit은 유실로 이어진다. 자동 재전송과 영속 재생 기능은 없다.
- Discord가 수신했지만 응답이 유실된 경우 전송 성공 여부를 알 수 없다.
  이를 보고 운영자가 수동 재전송하면 중복이 될 수 있다.
- 같은 analysis_id의 과거 DB 백업을 복원하거나 단계를 수동으로 되돌려 재처리하면,
  이미 Discord에 남아 있는 메시지가 다시 전송될 수 있다.
- 여러 Worker/프로세스 사이의 메시지 순서 또는 Discord의 처리까지 포함한
  전역 순서는 보장하지 않는다. 같은 SHA-256의 독립 분석 ID들은 각각 정상 알림 대상이다.

## 로컬 테스트와 CI

tests/backend_api/test_notifications.py는 기존 MemoryAnalysisRepository, FakeInitial,
FakeDeep, harness를 재사용한다. HTTP opener는 모든 활성 알림 테스트에서 mock한다.
실제 PostgreSQL/S3/SQS, 모델 아티팩트, Speakeasy, Discord가 필요하지 않다.

Windows 기존 가상환경의 실행 예:

```powershell
& .\trust-triage-env\Scripts\python.exe -m pytest tests/backend_api/test_notifications.py -q -p no:cacheprovider --basetemp=artifacts/pytest_discord
```

GitHub Actions의 .github/workflows/ci.yml은 이미 tests/backend_api 전체를
실행하므로 새 테스트도 포함된다. CI/배포 workflow 수정은 필요 없다.
실제 GitHub Actions 실행은 commit/push/PR 없이 이번 작업에서 시작하지 않는다.

## 향후 EC2 적용 시

이미 Webhook이 동작하는 환경에서는 이번 정책 변경에 새 환경변수, Webhook URL 변경,
DB migration, AWS 설정 또는 workflow 변경이 필요 없다. 승인된 코드 배포 후 기존
Backend processor를 재시작하면 적용된다. 아래는 신규 설정 환경을 위한 기존 안내다.

1. 승인된 코드 배포 후 trust-triage-processor.service가 읽는 기존 비밀 설정 경로에
   DISCORD_WEBHOOK_URL을 안전하게 주입한다. API나 Speakeasy 프로세스만 설정하면 알림이 생기지 않는다.
2. 해당 서비스의 EnvironmentFile 또는 기존 --env-file 연결을 확인한다.
   systemd 설정 자체를 바꿨다면 daemon-reload 후 processor를 재시작해야 한다.
   프로세스 환경변수 변경은 실행 중인 processor에 자동 반영되지 않는다.
3. EC2에서 Discord로 나가는 DNS 및 HTTPS 443 경로와 TLS 인증서 신뢰 구성을 확인한다.
   신규 인바운드 포트, Bot 권한, SQS, DB migration, AWS 리소스는 필요 없다.
   프록시만으로 외부 접속이 가능한 환경은 현재 전송 방식과 맞지 않는다.
4. 초기 운영 시 고정 알림 오류 로그와 버퍼 포화 여부를 관찰한다.
   대량 접수 시 Discord rate limit 때문에 누락될 수 있다.
5. 기존 GitHub Actions 배포 workflow는 이 비밀값을 자동 전달하지 않는다.
   별도 운영 설정이 필요하며 이번 변경에는 비밀값이나 배포 구조 변경이 없다.

이번 작업에서는 실제 Discord 메시지 전송, AWS 리소스 변경, EC2 배포를 수행하지 않는다.


## 경량 알림 정책 검증 기록

HTTP를 전부 mock한 로컬 검증에서 알림·processor·배치/ZIP 접수·조회·repository·API·runtime
회귀 테스트가 358 passed, 2 skipped, 41 deselected (115.10초)로 완료됐다.
두 skip은 실제 PostgreSQL이 필요한 schema upgrade 및 직접 SQL 제약 검증이고,
41개는 not postgres 조건으로 제외했다. 기존 Starlette/httpx deprecation 경고 1건이 있었다.
처음 알림 테스트 113개가 통과한 뒤, 동시 최초 요약 제출 검증을 보강하고
재시도·누락 배치·버퍼 포화 테스트 3개를 추가하여 위 회귀 실행에 포함했다.

```powershell
$env:DISCORD_WEBHOOK_URL = ''
$env:BACKEND_TEST_DATABASE_URL = ''
$env:WORKER_TEST_DATABASE_URL = ''
$env:AWS_EC2_METADATA_DISABLED = 'true'
$env:LLM_ENABLED = 'false'
& .\trust-triage-env\Scripts\python.exe -m pytest tests/backend_api/test_notifications.py tests/backend_api/test_service_processor.py tests/backend_api/test_batch_inputs.py tests/backend_api/test_batch_results.py tests/backend_api/test_repository.py tests/backend_api/test_app.py tests/backend_api/test_runtime_cli.py -m 'not postgres' -q -p no:cacheprovider --basetemp=artifacts/pytest_policy_final
```

실제 Discord 전송, 운영 환경 검증 또는 원격 GitHub Actions 실행은 수행하지 않았다.

## 최초 알림 구현 시 검증 기록 (이전 정책)

실제 Discord/DB/AWS 연결 없이 로컬 가상환경에서 검증했다.
알림 최종 테스트는 60 passed이며, 전체 회귀는 1132 passed, 2 skipped,
55 deselected (431.70초)였다. 전체 회귀 수집 이후 보강한 알림 테스트 3개는
최종 60개 실행에서 추가 검증했다. 두 skip은 PostgreSQL 전용 schema/SQL 제약 검증이며,
55개는 not postgres 조건으로 제외했다. 기존 Starlette/httpx deprecation 경고 1건이 있었다.
첫 알림 실행의 pytest cache 디렉터리 권한 경고는 후속 실행에서 cacheprovider를
비활성화하여 피했다. 테스트 실패를 숨긴 것이 아니며 테스트별 임시 디렉터리는 artifacts 아래에 두었다.

최종 알림 테스트 명령:

```powershell
& .\trust-triage-env\Scripts\python.exe -m pytest tests/backend_api/test_notifications.py -q -p no:cacheprovider --basetemp=artifacts/pytest_discord_final
```

CI와 동일한 테스트 경로/marker 범위의 회귀 명령 (로컬 Windows 실행):

```powershell
$env:DISCORD_WEBHOOK_URL = ''
$env:BACKEND_TEST_DATABASE_URL = ''
$env:WORKER_TEST_DATABASE_URL = ''
$env:AWS_EC2_METADATA_DISABLED = 'true'
$env:LLM_ENABLED = 'false'
$env:MPLBACKEND = 'Agg'
& .\trust-triage-env\Scripts\python.exe -m pytest tests/dashboard tests/backend_api tests/test_feature_names.py tests/test_model_data_contract.py tests/test_floss_analysis.py tests/test_floss_transport.py tests/test_llm_input_limits.py tests/test_deep_analysis.py tests/deep_analysis_service/test_service.py tests/deep_analysis_service/test_backend_worker_flow.py tests/test_mlflow_tracking.py -m 'not postgres' -q -p no:cacheprovider --basetemp=artifacts/pytest_discord_ci
```

`python -m pip check`도 기존 가상환경에서 통과했다.
GitHub Actions의 Ubuntu/Python 3.12.3 원격 실행 자체를 수행한 것은 아니다.

