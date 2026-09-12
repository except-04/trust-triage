# 백엔드 소스코드 구조와 처리 흐름

이 문서는 백엔드를 처음 개발하는 팀원이 **어떤 파일이 무슨 일을 하고, 요청이 어떤 순서로 처리되는지** 이해하기 위한 안내다. 실제 API 주소와 입력·응답은 [API 종류와 설명](api-reference.md)에 정리했다.

처음부터 모든 파일을 외울 필요는 없다. 먼저 아래 그림에서 **요청을 받는 쪽, 분석하는 쪽, 저장하는 쪽** 세 부분을 찾아보면 된다. Streamlit·Swagger는 백엔드에 요청을 보낼 수 있는 클라이언트의 예다. 실제 화면의 연결 여부는 해당 화면 구현에 따라 달라진다.

```text
Streamlit / Swagger / 다른 클라이언트
        │ "이 파일을 분석해 주세요."
        ▼
     app.py                    요청이 들어오는 입구
        ▼
   service.py                  파일 접수·조회·검토 업무
        ├─ storage.py ──────→ 로컬 폴더 / S3
        │                     원본 파일 보관
        └─ repository.py ───→ PostgreSQL
                              분석할 작업 기록
                                  │
                    별도 run 프로세스가 기록을 읽음
                                  ▼
                            processor.py
                                  │
          ┌───────────────────────┴────────────────────┐
          │ ① 초기 분석                                │ ② 필요할 때
          ▼                                            ▼
  initial_analysis.py                          deep_gateway.py
          │                                            │
  기존 Feature·모델·JRR·SHAP                    별도 Deep Analysis 서비스
                                                       │
                                               CAPA·FLOSS·Speakeasy 등

processor.py ── repository.py ──→ PostgreSQL에 중간 결과·최종 제안 저장
```

위 그림의 ①과 ②는 **초기 분석 후, 필요한 경우 심층 분석으로 이어지는 순서**다. `processor.py`는 초기 분석에 필요한 원본을 `storage.py`를 통해 읽는다. 접수된 작업과 분석 결과는 DB에 남기므로 `serve`와 `run`이 같은 기록을 보고 이어서 일할 수 있다.

## 1. 백엔드가 맡는 일

사용자가 PE 파일을 올리면 백엔드는 원본을 보관하고 분석 요청을 DB에 등록한다. 이후 초기 분석과 필요한 심층 분석을 진행하고, 화면에서 조회할 결과와 전문가 검토 이력을 저장한다.

여기서 DB는 작업 기록을 보관하는 PostgreSQL이고, 파일 저장소는 SHA-256별 원본과 실행별 리포트를 보관하는 로컬 폴더 또는 S3다. 같은 원본을 여러 분석이 공유해도 판정과 검토 이력은 각 분석 번호에 남는다. 자세한 경로·전환 절차는 [저장 구조 안내](storage.md)를 참고한다.

파일 하나를 **분석 의뢰서 한 장**에 대응시켜 생각하면 이해하기 쉽다.

```text
원본 PE 파일                 분석 의뢰서와 처리 기록
    │                                │
storage.py                       repository.py
    ▼                                ▼
로컬 폴더 / S3                  PostgreSQL
"분석할 파일 보관"              "누구의 파일인지, 어디까지 했는지 기록"
```

예를 들어 `demo.exe`를 접수하면 DB에는 분석 번호, SHA-256, 원본 위치, 현재 상태가 저장된다. 분석이 진행되면서 그 기록에 초기 결과와 심층 결과가 추가된다.

## 2. 서버와 분석 처리기를 따로 실행하는 이유

프로그램은 `serve`와 `run`이라는 두 실행 명령으로 나뉜다.

| 실행 명령 | 맡은 일 | 켜져 있어야 하는 때 |
|---|---|---|
| `serve` | 파일 접수, 상태·결과 조회, 검토 의견 저장 등 HTTP 요청 처리 | 화면이나 Swagger에서 API를 사용할 때 |
| `run` | DB의 대기 작업을 읽고 실제 분석 단계 실행 | 접수된 파일의 분석을 진행할 때 |

분석에는 시간이 걸리므로 `serve`는 파일 저장과 DB 등록을 마치면 먼저 분석 번호를 돌려준다. 사용자는 분석이 끝날 때까지 업로드 요청을 계속 열어 둘 필요 없이 그 번호로 진행 상황을 조회한다.

```text
사용자 / Dashboard / Swagger
        │ 파일 업로드
        ▼
    serve 프로세스
        ├─ 원본 파일 → 로컬 저장소 또는 S3
        ├─ 분석 요청 → PostgreSQL
        └─ analysis_id와 HTTP 202 반환

    run 프로세스
        │ PostgreSQL에서 대기 작업 읽기
        ▼
    Feature → 모델 → Calibration / Risk → JRR → SHAP
        ├─ 자동 정상·악성 경로 → 최종 제안 저장
        └─ 불확실 경로 → 심층 분석 연결 → 최종 제안 저장

사용자는 serve를 통해 진행 상황·결과를 조회하고 전문가 검토를 저장
```

백엔드의 `run`은 DB를 읽어 작업을 고른다. SQS는 별도 심층 분석 서비스가 Speakeasy Worker에 작업을 전달할 때 사용한다. Speakeasy까지 연결하면 Worker 실행 프로세스가 추가된다.

실행할 때는 다음처럼 두 터미널의 역할을 구분하면 된다. 여기서 **프로세스**는 실행 중인 프로그램 하나를 뜻한다.

```text
터미널 A: serve                  터미널 B: run
"접수하고 결과를 보여줄게요."    "대기 중인 분석을 진행할게요."
           │                                │
           └──────── 같은 PostgreSQL ────────┘
```

`serve`만 켜 두면 설정이 준비된 환경에서 접수·조회는 할 수 있고, 새로 접수한 작업은 처리기를 기다린다. `run`이 켜지면 대기 작업을 읽고 분석을 진행한다. 화면을 닫아도 `run`이 계속 실행 중이면 분석은 이어진다.

## 3. 폴더 구조

아래 경로는 저장소 루트를 기준으로 한다.

```text
backend-api/
├─ src/trust_triage/backend_api/
│  ├─ __init__.py          ← Python 패키지 표시
│  ├─ __main__.py          ← 터미널 명령의 시작점
│  ├─ app.py               ← API 주소와 요청 처리
│  ├─ api_docs.py          ← Swagger 안내 문구와 예시
│  ├─ schemas.py           ← 요청·응답 데이터 형식
│  ├─ service.py           ← 접수·조회·검토 업무
│  ├─ batch_inputs.py      ← 다중·ZIP 입력 검사와 제외 내역
│  ├─ batch_results.py     ← 배치 요약·진행 상태·결과 정렬
│  ├─ processor.py         ← 분석 단계 진행
│  ├─ repository.py        ← DB 읽기·쓰기
│  ├─ schema.sql           ← DB 테이블 설계
│  ├─ storage.py           ← 원본 파일 보관·읽기
│  ├─ initial_analysis.py  ← 기존 초기 분석 모듈 호출
│  ├─ model_bundle.py      ← 모델 묶음·Feature 규격 검사
│  ├─ deep_gateway.py      ← 심층 분석 서비스 연결
│  ├─ views.py             ← 결과를 API 응답으로 정리
│  ├─ config.py            ← 환경 설정 읽기
│  ├─ runtime.py           ← 필요한 부품 조립
│  └─ errors.py            ← 공통 오류 형식
├─ src/trust_triage/storage/
│  ├─ layout.py            ← SHA-256·분석·도구 실행별 공통 경로 규칙
│  └─ artifacts.py         ← 변경 불가 리포트 저장·읽기·체크섬 검사
├─ tests/backend_api/      ← 동작을 확인하는 테스트
├─ requirements-backend.txt           ← API 실행 패키지
├─ requirements-backend-analysis.txt  ← 실제 초기 분석 패키지
├─ requirements-backend-dev.txt       ← 개발·테스트 패키지
└─ docs/backend-api/
   ├─ backend-structure.md  ← 이 문서
   ├─ api-reference.md      ← API 종류와 설명
   ├─ storage.md            ← 원본 공유·산출물 저장·기존 DB 전환
   ├─ openapi.json          ← 자동 생성된 상세 API 명세
   ├─ verification.md      ← 기존 검증 기록
   ├─ batch-verification.md ← 배치 요약·필터·ZIP 확장 검증
   └─ usage.md.bak          ← 이전 사용 안내 원문 백업
```

## 4. 소스 파일별 역할

| 파일 | 쉽게 설명하면 | 코드에서 확인할 부분 |
|---|---|---|
| [app.py](../../src/trust_triage/backend_api/app.py) | 화면이 호출할 주소와 HTTP 처리의 입구 | `create_app()`, `@app.get/post/patch`, 업로드 형식·인증·요청 크기 검사 |
| [api_docs.py](../../src/trust_triage/backend_api/api_docs.py) | Swagger 안에서 읽는 사용 설명서 | 첫 화면 안내, API 그룹·설명, 요청·응답 예시, 오류별 안내 |
| [schemas.py](../../src/trust_triage/backend_api/schemas.py) | 주고받을 데이터의 이름·자료형·허용 값에 대한 약속 | `AnalysisResponse`, `ReviewRequest`, 판정·상태 Enum |
| [service.py](../../src/trust_triage/backend_api/service.py) | 접수·조회·검토·원본 정리 같은 업무 처리 | `BackendService.submit()`, `get()`, `review()`, `cleanup()` |
| [batch_inputs.py](../../src/trust_triage/backend_api/batch_inputs.py) | 다중·ZIP 입력을 제한된 임시 공간에서 검사 | `BatchInputHandler.prepare()`, PE 접수·SKIPPED 사유, ZIP 경로·용량·압축률 검사 |
| [batch_results.py](../../src/trust_triage/backend_api/batch_results.py) | 접수 내역과 배치 전체 진행 현황을 응답으로 정리 | `accepted()`, `response()`, 초기 판정별 요약·고위험 우선 정렬 |
| [processor.py](../../src/trust_triage/backend_api/processor.py) | 다음 분석 단계를 실행하는 담당 | `BackendProcessor.resume()`, `resume_ready()`, 최종 처리 규칙 `assess()` |
| [repository.py](../../src/trust_triage/backend_api/repository.py) | DB에 읽고 쓰는 작업을 모은 파일 | `PostgresAnalysisRepository`, 등록·단계 저장·검토 이력 메서드 |
| [schema.sql](../../src/trust_triage/backend_api/schema.sql) | DB 테이블을 만드는 설계도 | 테이블, 필드, 중복 방지·상태 제약 조건 |
| [storage.py](../../src/trust_triage/backend_api/storage.py) | 원본 파일의 보관·다운로드·삭제 담당 | `LocalSampleStorage`, `S3SampleStorage`, SHA-256·크기·헤더 검사 |
| [storage/artifacts.py](../../src/trust_triage/storage/artifacts.py) | 실행별 리포트를 원본과 같은 해시 폴더 아래 보관 | `ArtifactIdentity`, `ArtifactReference`, Local/S3 산출물 저장소 |
| [initial_analysis.py](../../src/trust_triage/backend_api/initial_analysis.py) | 기존 Feature·모델·JRR·SHAP 모듈을 순서대로 호출 | `InitialAnalysisService.analyze()`, 분석용 자식 프로세스와 시간 제한 |
| [model_bundle.py](../../src/trust_triage/backend_api/model_bundle.py) | 분석에 사용할 모델 파일 묶음과 Feature 규격 검사 | `ModelBundleConfig`, `ModelBundle.load()` |
| [deep_gateway.py](../../src/trust_triage/backend_api/deep_gateway.py) | 별도 심층 분석 서비스와 연결하는 담당 | `ExistingDeepGateway.advance()`, `get()`, `can_delete()` |
| [views.py](../../src/trust_triage/backend_api/views.py) | DB·도구 결과를 화면용 응답으로 정리 | `analysis()`, `triage()`, `deep_analysis()`, `xai()` |
| [config.py](../../src/trust_triage/backend_api/config.py) | DB·저장소·토큰·시간 제한 등의 설정 읽기 | `BackendConfig.from_env()` |
| [runtime.py](../../src/trust_triage/backend_api/runtime.py) | 위 부품들을 실제 연결 설정에 맞춰 조립 | `create_service()`, `create_processor()`, `check()` |
| [errors.py](../../src/trust_triage/backend_api/errors.py) | 공통 오류 형식 | `BackendError`: 오류 코드·메시지·단계·재시도 가능 여부 |
| [__main__.py](../../src/trust_triage/backend_api/__main__.py) | 터미널 명령을 받아 실행을 시작하는 곳 | `main()`, `serve`, `run`, `init-db` 등 명령 분기 |
| [__init__.py](../../src/trust_triage/backend_api/__init__.py) | Python 패키지를 구분하는 파일 | 패키지 설명 |

처음에는 **`app.py → schemas.py → service.py → processor.py → repository.py`** 순서로 읽으면 된다. 이 다섯 파일을 읽으면 요청 형식, 업무 처리, 분석 실행, 저장의 관계를 이해할 수 있다. 이후 실제 분석이 궁금하면 `initial_analysis.py`와 `deep_gateway.py`를 보면 된다.

### 이름이 비슷한 파일 구분하기

`schemas.py`와 `schema.sql`은 모두 데이터의 구조를 정의하지만 사용하는 곳이 다르다.

```text
화면과 주고받는 JSON의 형식 ──→ schemas.py
  예: review_revision은 정수, final_verdict는 정해진 값

DB에 저장할 테이블의 형식 ───→ schema.sql
  예: api_analyses 테이블의 열, 기본값, 중복 방지 조건
```

`service.py`는 접수·조회·검토 업무를 처리하고, `processor.py`는 초기·심층·최종 분석의 다음 단계를 진행한다. `views.py`는 저장된 결과를 API 응답으로 정리한다. 실제 화면을 그리는 일은 Streamlit 같은 클라이언트가 맡는다.

설정과 조립도 나누어져 있다.

```text
루트 .env (실행할 때 --env-file .env 지정)
        ↓
__main__.py   "파일 내용을 환경변수로 불러온다."
        ↓
config.py     "DB 주소와 저장소 종류를 읽는다."
        ↓
runtime.py    "그 설정으로 DB·저장소·분석기를 연결한다."
        ↓
serve의 app / service 또는 run의 processor 실행
```

## 5. 파일 하나가 처리되는 실제 순서

아래에서는 정상 데모 파일 `demo.exe`를 접수했다고 가정하고 흐름만 따라가 본다. 파일 이름과 분석 번호는 설명용 예시다.

### ① 파일 접수

```text
화면에서 demo.exe 선택
        ↓ POST /analyses
app.py
  "파일 접수 요청이 들어왔어요."
        ↓ BackendService.submit()
service.py
        ├─ storage.prepare() → 헤더·크기 검사, SHA-256 계산, 임시 파일 준비
        └─ repository.sample_transaction() → 공유 원본에 대한 잠금
             ├─ repository.register() → QUEUED 작업 등록
             ├─ storage.publish() → 해시 경로로 원본 발행 또는 기존 바이트 확인
             └─ DB commit → 등록 확정
        ↓
화면에 analysis_id와 HTTP 202 반환
  "접수됐어요. 이 번호로 진행 상황을 확인하세요."
```

`POST /analyses`를 호출하면 `app.py`가 multipart 업로드를 확인하고 `BackendService.submit()`을 호출한다. `storage.py`가 파일 확장자·기본 PE 헤더·크기를 검사하고 SHA-256을 계산한 뒤 원본을 저장한다.

원본 발행까지 성공하면 DB 등록을 확정하고 `analysis_id`와 `QUEUED` 상태를 HTTP `202`로 반환한다. 다른 연결에서는 확정 전의 요청이 보이지 않는다. 이 시점에는 모델 분석 결과가 아직 없다.

### ② 초기 분석

```text
run의 processor.py
        │ DB에서 처리 가능한 작업 선택
        ▼
storage.py에서 원본 읽기
        ▼
initial_analysis.py
        ├─ model_bundle.py로 모델·Feature 규격 확인
        └─ 기존 분석 모듈 호출
                ↓
       Feature 추출 → 모델 예측 → 보정·위험 신호 → JRR → SHAP
                ↓
processor.py가 repository.save_initial() 호출
                ↓
PostgreSQL의 initial_result에 결과 저장
```

별도로 실행 중인 `run`이 `resume_ready()`로 대기 작업을 찾는다. `resume()`은 해당 작업의 처리 권한을 얻고, `initial_analysis.py`에 분석을 요청한다.

초기 분석은 기존 Feature 추출 결과에서 모델 입력을 만들고 LightGBM·XGBoost 예측, Calibration, 위험 신호, JRR, SHAP을 연결한다. 모델 파일과 Feature 이름·순서·개수·형식이 맞는지도 확인한다. 리포트 파일을 발행한 뒤 DB의 `initial_result`와 산출물 참조를 함께 저장한다. 심층 분석 종료 결과와 최종 제안도 같은 방식으로 보관한다.

JRR의 `reason`은 대표 사유이고 `triggered_signals`는 동시에 발현된 신호 전체다. 백엔드는 이 배열을 검증해 DB·리포트에 저장하고 `/triage`, 종합 결과, 분석 목록·배치 결과까지 전달한다. 새 분석에는 배열이 필수이며 발현 신호가 없으면 `[]`다. 이전 기록에서 누락된 필드는 `null`로 조회하고 이전 분석을 다시 실행하지 않는다. 기본 임계값은 공용 `JointRiskRouter`를 사용하며 실제 값은 `feature_metadata.jrr_thresholds`에 남긴다.

### ③ 필요한 심층 분석

```text
초기 JRR의 경로
        ├─ FINAL ──────────→ 최종 제안 저장 단계로 이동
        │
        └─ DEEP_ANALYSIS
                ↓
          deep_gateway.py
                ↓
          별도 심층 분석 서비스
                ├─ CAPA / FLOSS
                └─ 필요하면 SQS → Speakeasy Worker
                ↓
          도구 결과·Evidence·LLM 해석 상태
                ↓
          processor.py → repository.save_deep() → PostgreSQL
```

JRR 결과가 `HIGH_RISK_UNCERTAIN`이면 `deep_gateway.py`로 심층 분석을 요청한다. 이 연결부는 같은 분석 번호와 SHA-256을 유지하고, 별도 Deep Analysis 서비스의 진행 상태와 결과를 읽어 `deep_result`에 저장한다.

심층 분석 서비스가 설치된 환경에서는 CAPA·FLOSS와 필요한 Speakeasy 처리를 연결한다. HTTP 조회 요청 자체가 이 도구나 LLM을 실행하지는 않는다.

### ④ 최종 제안과 전문가 검토

```text
processor.assess()
        ↓ 시스템 최종 제안
repository.finish() → PostgreSQL
        ↓
화면에서 결과와 증거 확인
        ↓ 전문가가 검토 의견 입력
PATCH /analyses/{analysis_id}/verdict
        ↓
app.py → service.review() → repository.save_review()
        ↓
api_reviews에 새 검토 이력 추가
```

`processor.assess()`가 현재 정책에 따른 최종 제안을 만들고 DB에 저장한다. 이후 화면은 `GET /analyses/{analysis_id}`로 결과를 조회한다.

전문가가 `PATCH /analyses/{analysis_id}/verdict`로 의견을 보내면 별도 검토 이력이 추가된다. 초기 JRR 판정과 시스템 최종 제안은 보존된다.

### ⑤ 저장된 결과가 화면으로 돌아오는 길

결과를 보여 주는 과정까지 보면 한 번의 작업 흐름이 완성된다.

```text
요청이 가는 길
화면 → GET /analyses/{analysis_id}
     → app.py → service.get() → repository.get() → PostgreSQL

읽은 기록이 돌아오는 길
PostgreSQL → repository → service → app.py
                                      ↓
                                 views.analysis()
                                      ↓
                            요청·응답 Schema에 맞춘 JSON
                                      ↓
                               화면에서 결과 표시
```

화면은 같은 분석 번호를 여러 번 조회할 수 있다. 이 조회 경로에서는 DB에 저장된 상태와 결과를 읽는다.

## 6. DB에는 무엇이 저장되는가

| 테이블 | 저장하는 내용 |
|---|---|
| `api_batches` | 한 번의 접수 요청 정보. 단일·일괄 요청 구분, `Idempotency-Key`, ZIP 식별 정보와 파일별 접수·제외 내역(`input_report`) |
| `api_analyses` | 파일별 분석 번호, SHA-256, 내부 원본 위치, 단계·상태, 초기·심층 결과, 최종 제안 |
| `api_sample_objects` | 여러 분석이 공유할 수 있는 저장 원본의 위치·해시·크기·삭제 시각 |
| `api_analysis_artifacts` | 실행별 리포트의 위치·체크섬·크기·버전·설정 메타데이터 |
| `api_reviews` | 전문가별 검토 의견과 판정, 수정 번호, 검토 시각 |

`api_batches`라는 이름이지만 단일 파일 접수도 요청 단위 기록을 남긴다. 여러 파일을 한 번에 올린 경우에만 공개 `batch_id`가 생긴다.

다중 파일과 ZIP 입력에서는 `batch_inputs.py`가 파일을 검사한다. 지원하지 않는 파일은 `SKIPPED`와 사유를 남기고 `service.py`가 지원 PE의 분석 작업과 접수 내역을 같은 DB 트랜잭션에 등록한다. 모두 제외돼도 `api_batches`에는 접수 내역이 남고 `api_analyses`는 추가되지 않는다. ZIP 자체는 영구 보관하지 않는다.

`batch_results.py`는 전체 배치의 진행 상태·초기 판정 요약을 만들고 고위험 결과를 먼저 표시한다. 필터·페이지 API는 `repository.py`에서 전체 결과를 필터링·정렬한 다음 페이지를 가져온다. 원본 접수 내역 순서는 결과 정렬과 별도로 유지한다. 현재 Streamlit은 Mock 화면이므로 실제 화면 연결 시 이 응답을 사용한다.

원본 파일은 로컬 저장소 또는 S3에 있고, DB에는 그 위치를 보관한다. 화면용 응답은 `views.py`가 필요한 필드를 골라 만들며 내부 원본 저장 위치는 공개 응답에서 제외한다.

일괄 접수를 예로 들면 테이블 사이의 관계가 더 잘 보인다.

```text
한 번의 접수                       api_batches
        │
        ├─ demo-a.exe의 분석        api_analyses
        │       ├─ 첫 검토          api_reviews, revision 1
        │       └─ 수정 검토        api_reviews, revision 2
        │
        └─ demo-b.dll의 분석        api_analyses
                └─ 아직 검토 없음
```

### 내부 처리 단계와 화면 상태

| 내부 `phase` | 뜻 | 다음 처리 |
|---|---|---|
| `INITIAL` | 초기 분석 필요 | 결과에 따라 `FINALIZING` 또는 `WAITING_DEEP` |
| `WAITING_DEEP` | 심층 분석을 진행하거나 결과를 기다리는 중 | 심층 결과가 끝나면 `FINALIZING` |
| `FINALIZING` | 최종 제안을 DB에 저장할 차례 | `DONE` |
| `DONE` | 백엔드 처리 종료 | 조회·전문가 검토 가능 |

화면에는 전체 작업의 `status`와 현재 단계의 `current_stage`를 제공한다. 실패하면 초기·심층 단계에서도 바로 `DONE`이 될 수 있다. `run --once`는 준비된 작업마다 다음 단계 한 번을 처리하므로 전체 분석이 한 명령 안에서 모두 끝난다는 뜻은 아니다.

```text
INITIAL
  ├─ 추가 분석 필요 없음 ────────────────┐
  └─ 추가 분석 필요 → WAITING_DEEP      │
                        │ 결과가 끝나면 │
                        └───────────────┤
                                        ▼
                                   FINALIZING
                                        ▼
                                      DONE
```

`status`는 “대기·진행·종료 중 어디에 있는지”, `current_stage`는 “무슨 분석을 하고 있는지”, 내부 `phase`는 “처리기가 다음에 무엇을 실행할지”를 표현한다.

## 7. 재시작·중복·오류를 처리하는 방식

**재시작:** 중간 결과를 DB에 저장해 두고 다음 단계에서 이어간다. 작업을 처리할 때는 일정 시간 동안의 처리 권한인 lease를 얻는다. 처리기는 heartbeat로 권한을 갱신하고, 권한을 잃은 이전 처리자는 결과를 덮어쓸 수 없다. 결과 저장 전에 프로세스가 종료되면 해당 단계는 재실행될 수 있다.

**중복 접수:** 같은 파일을 새 요청으로 올리면 독립된 분석이 생긴다. 네트워크 오류로 같은 요청을 재전송할 때는 같은 `Idempotency-Key`를 사용해 기존 접수 결과를 돌려받는다.

**오류:** 분석 실패는 오류 코드와 함께 남기고 전문가 검토가 필요한 상태로 처리한다. SHAP 실패는 이미 얻은 모델 예측과 JRR 판정을 보존한다. 재시도 가능한 처리 오류에는 횟수와 대기 시간을 적용한다.

**원본 정리:** 원본 위치를 공유하는 모든 분석이 종료되고 각각의 보관 기간이 지나야 한다. S3의 심층 분석 대상은 연결된 Deep Analysis·Worker도 종료됐는지 확인하며, 진행 중이거나 확인할 수 없으면 삭제를 보류한다. 실제 삭제는 `sample.bin`에만 적용하고 실행별 리포트는 유지한다.

재시작 사례를 그림으로 보면 다음과 같다.

```text
초기 분석 완료 → initial_result 저장 → WAITING_DEEP 저장
                                            │
                                      처리기 중단
                                            │
                                  run을 다시 실행
                                            ▼
                            처리 권한을 얻을 수 있는지 확인
                                            ▼
                         저장된 WAITING_DEEP부터 이어서 처리
```

lease는 “이 작업을 지금 처리해도 되는 권한의 유효기간”, heartbeat는 “아직 처리 중이니 유효기간을 갱신하는 신호”로 이해하면 된다. 그래서 이전 처리자가 늦게 돌아와도 다른 처리자가 저장한 결과를 덮어쓰지 못하게 할 수 있다.

## 8. 현재 최종 처리 정책과 연결 준비

현재 정책 이름은 `backend-review-first-v1`이다.

| 상황 | 시스템 최종 제안 | 처리 방향 |
|---|---|---|
| `AUTO_BENIGN`, SHAP 실패 없음 | `BENIGN` | 자동 정상 처리 제안 |
| `AUTO_MALICIOUS` | `MALICIOUS` | 악성 경보 제안 후 전문가 검토 |
| 심층 분석 대상 또는 자동 정상 경로의 SHAP 실패 | `UNCERTAIN` | 전문가 검토 |
| 전체 분석 처리 실패 | `UNCERTAIN` | 분석 실패로 기록하고 전문가 검토 |

심층 분석 후 자동으로 최종 악성·정상을 정하는 새 규칙은 팀 합의 후 `assess()`에 반영해야 한다. LLM 설명은 전문가가 참고할 증거 해석으로 제공한다.

초기 분석에는 팀이 검증한 LightGBM, XGBoost, Calibration, Risk Signals, Top-500 인덱스, Feature selection manifest가 필요하다. 각 파일 경로는 `runtime.py`의 `BACKEND_*_PATH` 설정으로 받는다.

기존 `feature/deep-analysis`·`feature/speakeasy-worker` 초안은 별도 작업이다. 이 백엔드는 옆 폴더의 코드를 자동으로 가져오지 않는다. 실제 연결에는 검토한 서비스 코드와 도구 의존성, 같은 PostgreSQL·S3 설정, SQS·Worker 환경이 필요하다.

## 9. 실행 명령과 수정할 위치

설정 예시는 저장소 루트의 [.env.backend.example](../../.env.backend.example)에 있다. 항목마다 어떤 값을 넣는지 주석으로 설명해 두었다. `.env` 파일이 아직 없을 때 다음처럼 복사하고, 새 `.env`에 실제 DB·AWS 연결 정보를 입력한다.

```powershell
Copy-Item .env.backend.example .env
```

`.env.backend.example`은 팀에 공유할 백엔드 예시이고, `.env`는 각자 사용할 실제 설정이다. 처음에는 DB 주소를 채우고 저장소를 `local`로 두어 접수·조회를 확인할 수 있다. S3를 사용하려면 `BACKEND_STORAGE_MODE=s3`로 바꾸고 버킷·리전·AWS 인증 정보를 준비한다. 실제 분석에는 모델 경로 6개도 필요하다.

저장소 루트에서 사용하는 명령 형식은 다음과 같다. `--env-file .env`를 지정하면 `__main__.py`가 파일 내용을 환경변수로 불러오고, `config.py`가 그 값을 읽는다. 이미 지정된 프로세스 환경변수가 있으면 그 값이 우선한다. AWS 인증 정보는 `boto3`가 읽는다.

```powershell
.\trust-triage-env\Scripts\python.exe -m trust_triage.backend_api --env-file .env <명령>
```

| 명령 | 역할 |
|---|---|
| `init-db` | 준비된 PostgreSQL DB 안에 백엔드 테이블 생성 또는 추가 필드 갱신 |
| `check` | DB·저장소 연결 확인. `--analysis`는 모델 파일·의존성 존재, `--deep`은 심층 환경도 확인 |
| `serve` | HTTP 서버 실행 |
| `run` | 분석 처리기 실행 |
| `cleanup` | 원본 삭제 후보 조회. `--delete`를 붙이면 삭제 실행 |
| `export-openapi` | DB 연결 없이 API 명세 JSON 생성 |

`--env-file`을 생략하면 `.env`를 자동으로 읽지 않는다. `usage.md.bak`은 이전 안내를 그대로 보관한 백업이므로 예전 설정 파일 경로를 참조하는 문장이 남아 있다.

배치 확장을 적용한 기존 DB에는 API 서버를 갱신하기 전에 아래 명령을 실행한다. `input_report` 열과 배치·초기 판정 조회용 인덱스를 추가하며 기존 접수·분석·검토 기록은 보존한다. 이전 배치는 기존 분석 목록에서 접수 내역을 구성해 조회한다.

```powershell
.\trust-triage-env\Scripts\python.exe -m trust_triage.backend_api --env-file .env init-db
```

ZIP 제한은 [.env.backend.example](../../.env.backend.example)의 `BACKEND_MAX_ZIP_*`, `BACKEND_ZIP_TIMEOUT_SECONDS`를 사용한다. Python 표준 `zipfile`을 사용하므로 새 설치 의존성은 없다.

| 바꾸려는 내용 | 먼저 볼 파일 |
|---|---|
| API 주소·요청 방식 | `app.py` |
| Swagger의 설명 문구·사용 순서·예시 | `api_docs.py` |
| 요청·응답 필드 | `schemas.py`, `views.py` |
| 접수·검토 업무 규칙 | `service.py` |
| 분석 단계·최종 처리 규칙 | `processor.py` |
| DB 필드·저장 방식 | `schema.sql`, `repository.py` |
| 모델 연결 | `initial_analysis.py`, `model_bundle.py` |
| 심층 분석 연결 | `deep_gateway.py` |

관련 검증 코드는 `tests/backend_api/`에 있으며 기존 검증 범위는 [verification.md](verification.md)에 기록되어 있다.

팀원에게 처음 설명할 때는 이렇게 말하면 된다.

> “화면의 요청은 app.py가 받아서 service.py로 넘겨요. service.py는 원본과 분석할 작업을 저장하고 먼저 접수 번호를 돌려줘요. 별도로 켜 둔 processor.py가 DB에서 작업을 읽고 초기 분석과 필요한 심층 분석을 진행해요. 결과도 DB에 저장하니까 화면은 그 번호로 진행 상황과 결과를 조회하고 전문가 의견을 남길 수 있어요.”
