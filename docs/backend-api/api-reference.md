# API 종류와 설명

이 문서는 **화면에서 어떤 API를 언제 호출하고, 어떤 데이터를 주고받는지** 설명한다. 현재 `app.py`와 [openapi.json](openapi.json)에 정의된 HTTP API 15개를 기준으로 한다. 소스 파일별 역할은 [백엔드 구조 설명](backend-structure.md)을 참고한다.

먼저 화면에서 할 일을 떠올리면 API 이름을 읽기 쉬워진다.

```text
화면에서 하려는 일
        ├─ "파일을 올릴게요."       → POST /analyses
        ├─ "지금 어디까지 됐나요?"  → GET /analyses/{analysis_id}/status
        ├─ "결과를 보여 주세요."    → GET /analyses/{analysis_id}
        └─ "검토 의견을 남길게요."  → PATCH /analyses/{analysis_id}/verdict
```

이 네 가지 흐름을 먼저 이해한 뒤, 여러 파일·상세 증거·검토 이력이 필요할 때 나머지 API를 사용하면 된다.

## 1. API 주소를 읽는 방법

API는 화면과 백엔드가 요청·응답을 주고받는 접점이다. 기본 서버 주소는 `http://127.0.0.1:8000`이며, 뒤에 `/analyses` 같은 경로를 붙인다.

```text
Streamlit / Swagger / 다른 클라이언트
        │ 요청: "이 번호의 결과를 주세요."
        ▼
    백엔드 API
        │ 응답: 번호에 해당하는 결과를 JSON으로 전달
        ▼
클라이언트가 받은 데이터를 화면에 표시
```

**요청**은 클라이언트가 백엔드에 보내는 내용이고, **응답**은 백엔드가 돌려주는 내용이다. **JSON**은 `"status": "RUNNING"`처럼 필드 이름과 값을 묶어 데이터를 표현하는 형식이다.

| 표기 | 뜻 | 이 프로젝트에서의 예 |
|---|---|---|
| `GET` | 저장된 내용을 조회 | 분석 결과 조회 |
| `POST` | 새 요청을 등록 | 파일 분석 접수 |
| `PATCH` | 특정 항목의 변경 요청 | 전문가 판정·의견 저장 |
| `{analysis_id}` | 실제 분석 번호로 바꿀 자리 | `/analyses/analysis_abc123` |
| `{batch_id}` | 실제 일괄 접수 번호로 바꿀 자리 | `/batches/batch_abc123` |
| `?limit=20&offset=0` | 조회 조건 | 한 번에 20개, 처음부터 조회 |

`analysis_id`는 **분석 요청 하나의 번호**, `sha256`은 **파일 내용의 해시**다. 같은 파일을 새로 접수하면 SHA-256은 같아도 분석 번호는 달라질 수 있다.

번호가 쓰이는 곳을 묶어서 보면 다음과 같다.

```text
일괄 접수 한 묶음: batch_id
        ├─ 파일 A 분석: analysis_id A ── 파일 내용 확인: sha256
        └─ 파일 B 분석: analysis_id B ── 파일 내용 확인: sha256

상세 결과를 볼 때 → analysis_id 사용
묶음 진행률을 볼 때 → batch_id 사용
같은 파일인지 확인할 때 → sha256 비교
```

## 2. API 전체 목록

| 종류 | 메서드 | 경로 | 용도 | 성공 응답 |
|---|---|---|---|---|
| 서버 상태 | GET | `/health` | HTTP 서버가 켜져 있는지 확인 | 200 |
| 서버 상태 | GET | `/ready` | 백엔드 DB 테이블에 접근 가능한지 확인 | 200 |
| 단일 접수 | POST | `/analyses` | PE 파일 한 개 분석 접수 | 202 |
| 일괄 접수 | POST | `/batches` | 여러 PE 파일을 한 묶음으로 접수 | 202 |
| ZIP 접수 | POST | `/batches/zip` | ZIP 내부의 지원 PE를 한 묶음으로 접수 | 202 |
| 목록 조회 | GET | `/analyses` | 분석 목록과 총 개수 조회 | 200 |
| 결과 조회 | GET | `/analyses/{analysis_id}` | 한 분석의 화면용 결과 조회 | 200 |
| 진행 조회 | GET | `/analyses/{analysis_id}/status` | 전체 진행 상태·현재 단계 조회 | 200 |
| 초기 분석 | GET | `/analyses/{analysis_id}/triage` | 모델 확률·위험 신호·최초 JRR 판정 조회 | 200 |
| 심층 분석 | GET | `/analyses/{analysis_id}/deep-analysis` | 도구 결과·Evidence·LLM 설명 조회 | 200 |
| 모델 설명 | GET | `/analyses/{analysis_id}/xai` | SHAP 설명 조회 | 200 |
| 일괄 조회 | GET | `/batches/{batch_id}` | 묶음에 포함된 분석과 처리 현황 조회 | 200 |
| 일괄 필터 조회 | GET | `/batches/{batch_id}/analyses` | 묶음 안의 초기 판정·상태 필터와 페이지 조회 | 200 |
| 전문가 검토 | PATCH | `/analyses/{analysis_id}/verdict` | 전문가 판정·의견 저장 | 200 |
| 검토 이력 | GET | `/analyses/{analysis_id}/reviews` | 해당 분석의 검토 이력 조회 | 200 |

`202`는 **분석 요청 접수 완료**다. 분석이 끝났는지는 이후 조회 응답의 `status`로 확인한다. GET 요청은 저장된 내용을 읽으며 새로운 분석이나 LLM 호출을 시작하지 않는다.

주소를 고를 때는 현재 화면에 필요한 정보로 나누어 보면 된다.

```text
분석 목록 화면      → GET /analyses
        ↓ 목록에서 하나 선택
분석 상세 화면      → GET /analyses/{analysis_id}
        ├─ 초기 모델 판단을 더 보기 → /triage
        ├─ 도구·증거를 더 보기     → /deep-analysis
        └─ 모델의 설명을 더 보기  → /xai
```

마지막 세 경로는 `/analyses/{analysis_id}` 뒤에 붙인다. 예를 들어 설명 조회의 전체 경로는 `/analyses/{analysis_id}/xai`다.

## 3. 공통 설정과 응답 읽기

### 요청 헤더

헤더는 파일·JSON 본문과 함께 보내는 부가 정보다.

| 헤더 | 사용하는 때 | 의미 |
|---|---|---|
| `X-API-Key` | 서버에 `BACKEND_API_TOKEN`이 설정된 경우 | API 접근 토큰. `/health`와 문서 화면은 공개 |
| `X-Reviewer-Key` | 검토 전용 토큰이 설정된 상태에서 판정을 저장할 때 | `BACKEND_REVIEWER_TOKEN`에 해당하는 추가 검토 권한 |
| `Idempotency-Key` | 단일·일괄 접수 요청을 재전송할 때 선택 사용 | 같은 요청의 중복 등록 방지 |

두 토큰이 모두 설정됐다면 전문가 검토 요청에는 두 헤더를 함께 보낸다. `reviewer_id`는 기록에 남길 검토자 식별자이며, 접근 권한 확인은 토큰이 맡는다.

같은 `Idempotency-Key`로 같은 접수를 다시 보내면 기존 분석 번호를 반환한다. 파일 순서·SHA-256·크기·이름·단일/일괄 종류가 바뀌면 `409` 충돌이다. 키는 공백 없는 ASCII 문자열 1~200자를 사용한다.
ZIP 요청은 ZIP 전체 바이트의 SHA-256·크기·이름으로 구분한다. 제외된 내부 파일의 내용도 이 해시에 포함된다. 내용이 같은 파일을 다시 압축했더라도 ZIP 바이트가 달라지면 다른 요청이다.

```text
첫 접수
  파일 A + Idempotency-Key: request-001 → analysis_id A 발급

응답을 받지 못해 같은 접수를 다시 보냄
  같은 파일·같은 이름 + 같은 키       → 기존 analysis_id A 반환

같은 파일을 독립적으로 다시 분석하고 싶음
  새 키를 쓰거나 키 없이 새로 접수     → 새 analysis_id 발급
```

### 상태와 판정

| 필드 | 뜻 | 주요 값 |
|---|---|---|
| `status` | 분석 처리의 진행 상태 | `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED` |
| `current_stage` | 현재 어느 분석 단계인지 | `UPLOAD`, `INITIAL_ANALYSIS`, `JRR`, `CAPA_FLOSS`, `SPEAKEASY`, `LLM`, `FINAL_ASSESSMENT` |
| `initial_verdict` | 최초 JRR의 처리 경로 제안 | `AUTO_BENIGN`, `AUTO_MALICIOUS`, `HIGH_RISK_UNCERTAIN` |
| `final_verdict` | 시스템의 최종 판정 제안 | `BENIGN`, `MALICIOUS`, `UNCERTAIN` |
| `analyst_final_verdict` | 전문가가 기록한 판정 | `BENIGN`, `MALICIOUS`, `null` |
| `approval_status` | 자동 처리·전문가 검토 상태 | `AUTO_POLICY`, `PENDING`, `APPROVED`, `MODIFIED` |

`COMPLETED`는 처리가 끝났다는 뜻이다. 파일의 정상·악성 여부는 판정 필드를 따로 읽어야 한다. 단계별 응답에는 해당 분석이 필요 없다는 `NOT_REQUIRED`도 사용한다. 결과가 아직 만들어지지 않은 필드는 `null` 또는 빈 목록으로 표시될 수 있다.

`AUTO_POLICY`는 자동 처리 정책 적용, `PENDING`은 검토 대기·보류, `APPROVED`는 전문가 판정이 시스템 제안과 일치, `MODIFIED`는 전문가 판정이 시스템 제안과 다름을 뜻한다.

아래는 **처리가 끝났지만 아직 전문가의 판정을 기다리는 상황**을 설명한 예다.

```text
status                  = COMPLETED   "백엔드의 분석 처리가 끝났어요."
final_verdict           = UNCERTAIN   "시스템은 확정하기 어렵다고 제안했어요."
analyst_final_verdict   = null        "전문가 판정은 아직 없어요."
approval_status         = PENDING     "검토를 기다리고 있어요."
```

이처럼 처리 상태와 판정을 따로 보면 화면의 “완료” 표시를 해석하기 쉽다.

## 4. 서버 상태 API

### GET /health

입력 없이 HTTP 서버의 동작 여부를 확인한다. `status`, `service`, `version`을 반환한다. DB·모델·분석 도구 전체의 준비 여부를 검사하는 요청은 아니다.

### GET /ready

입력 없이 백엔드가 사용하는 PostgreSQL 테이블에 접근할 수 있는지 확인한다. 성공하면 `{"status":"ready"}`를 반환한다. 모델 파일이나 CAPA·FLOSS·SQS 준비 여부는 이 요청의 검사 대상에 포함되지 않는다.

## 5. 파일 접수 API

### POST /analyses

PE 파일 한 개를 접수한다.

```text
사용자가 파일 선택
        ↓ 파일을 multipart의 file 필드에 담음
POST /analyses
        ↓ 원본 저장 + DB 등록
HTTP 202와 analysis_id 받기
        ↓
받은 번호를 화면에서 보관하고 /status 조회에 사용
```

multipart는 **파일을 HTTP 요청 본문에 담아 보내는 형식**이다. Swagger에서는 파일 선택 버튼을 사용하면 되므로 파일 내용을 직접 JSON으로 바꿀 필요가 없다.

| 입력 | 위치 | 필수 | 설명 |
|---|---|---|---|
| `file` | multipart 본문 | 예 | `.exe` 또는 `.dll` 파일 한 개 |
| `Idempotency-Key` | 헤더 | 아니요 | 동일 접수 요청 재전송 시 사용할 키 |

기본 파일 크기 제한은 **50 MiB**다. 현재 업로드 검사는 x86/x64 PE의 기본 헤더 구조를 확인하고, 실제 Feature 파싱은 분석 처리 단계에서 수행한다. 용량과 일괄 개수는 서버 설정으로 변경할 수 있다.

다음은 형식을 설명하기 위한 접수 응답 예시다. 실제 분석 결과가 아니다.

```json
{
  "analysis_id": "analysis_abc123",
  "batch_id": null,
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "created_at": "2026-09-08T12:00:00Z",
  "status": "QUEUED",
  "duplicate_of": null
}
```

응답의 `analysis_id`를 보관하고 진행 조회에 사용한다. 같은 SHA-256의 이전 분석이 있으면 `duplicate_of`에 이전 번호가 표시될 수 있다. 키 없이 새로 올린 요청은 독립된 분석이다.

예시 응답에서 `analysis_id`가 `analysis_abc123`이었다면, 진행 조회 주소는 다음과 같이 만든다.

```text
받은 번호: analysis_abc123
        ↓ 주소의 {analysis_id} 자리에 넣기
GET /analyses/analysis_abc123/status
```

### POST /batches

여러 파일을 한 묶음으로 접수한다. multipart 본문의 **`files` 필드를 파일 개수만큼 반복**해서 보낸다. 기본 최대 개수는 10개이고 한 파일의 크기 제한은 단일 업로드와 같다. ZIP은 아래의 `/batches/zip`으로 접수한다.

응답의 `batch_id`는 묶음 번호, `total_count`는 접수 파일 수, `analyses`는 파일별 접수 결과 목록이다. 각 파일에는 별도의 `analysis_id`가 생긴다.

```text
POST /batches
        ├─ files: demo-a.exe
        ├─ files: demo-b.dll
        └─ files: demo-c.exe
                ↓
          batch_id 하나 발급
                ├─ analysis_id A
                ├─ analysis_id B
                └─ analysis_id C
```

지원하지 않는 확장자·유효하지 않은 PE·미지원 PE 형식은 `SKIPPED`로 기록하고, 유효한 PE만 분석 작업으로 등록한다. 접수 후 파일별 성공·실패 상태도 독립적으로 관리한다. 파일 수·업로드 크기 제한 초과나 저장소·DB 장애는 묶음 전체 접수 오류다.

### POST /batches/zip

`multipart/form-data`의 **`file` 필드로 ZIP 한 개**를 보낸다. 하위 폴더의 `.exe`·`.dll`도 검사하고, 지원 PE는 단일·다중 입력과 같은 `BackendService`와 분석 처리기를 사용한다. 분석이 필요한 파일만 이후 심층 분석으로 전달된다.

두 배치 접수 API의 공통 응답은 다음과 같다.

| 필드 | 의미 |
|---|---|
| `batch_id` | 접수 묶음 번호 |
| `input_count` | 검사한 입력 파일 수. ZIP의 폴더 제외 |
| `accepted_count` / `total_count` | 실제 분석 작업을 등록한 수 |
| `skipped_count` | 분석 작업을 만들지 않은 수 |
| `archive_file_count` | ZIP 내부 파일 수. 일반 다중 입력이면 `null` |
| `entries` | 입력 순서·이름·`ACCEPTED`/`SKIPPED`·사유·분석 번호 |
| `analyses` | 등록한 파일별 분석 접수 결과 |

`input_count = accepted_count + skipped_count`다. `entries[].input_index`는 같은 이름의 파일도 구분하며, ZIP 폴더가 빠진 자리는 번호가 건너뛸 수 있다. ZIP 항목의 원래 경로는 `entries[].filename`에, 개별 분석의 파일명은 경로를 제거한 이름으로 저장한다. 접수 항목의 `ACCEPTED`는 최초 접수 사실을 뜻하므로 이후 분석이 실패해도 바뀌지 않는다.

`SKIPPED`에는 `analysis_id`를 발급하지 않고 `reason_code`와 `reason`을 남긴다. 모두 제외돼도 조회할 수 있는 배치를 저장한다. 이 경우 `analyses=[]`, `total_count=0`, 조회 `status=COMPLETED`다. 빈 ZIP이나 폴더만 있는 ZIP은 `422 / EMPTY_ZIP`다.
ZIP에서 해제하지 않고 제외한 항목은 `sha256=null`이고 `size_bytes`는 ZIP에 선언된 크기다. 지원 PE는 실제 읽은 크기와 SHA-256을 확인한 뒤 등록한다.

| 제외 코드 | 대상 |
|---|---|
| `UNSUPPORTED_FILE_TYPE` | `.exe`·`.dll` 이외의 파일 |
| `NESTED_ZIP_UNSUPPORTED` | ZIP 안의 ZIP |
| `INVALID_PE` / `UNSUPPORTED_PE_ARCH` | 잘못된 헤더 또는 미지원 PE 형식 |
| `ENCRYPTED_ENTRY_UNSUPPORTED` | 암호화 항목 |
| `ZIP_COMPRESSION_UNSUPPORTED` | STORED·DEFLATE 이외의 압축 방식 |
| `ZIP_FEATURE_UNSUPPORTED` | 패치 데이터 기능을 사용하는 항목 |
| `FILE_TOO_LARGE` | ZIP 내부 PE가 파일별 크기 제한을 초과함 |

ZIP의 기본 제한은 압축 파일 50 MiB, 전체 항목 100개(폴더 포함), 분석 대상 PE 10개, 파일별 50 MiB, 선언된 해제 후 총 크기 200 MiB, 항목별 압축률 200배, ZIP 처리 60초다. 제외 대상도 선언된 총량·압축률·항목 수 검사에 포함한다. 실제 해제 중에도 읽은 크기와 경과 시간을 검사한다. 시간 검사는 청크 처리 사이에서 수행한다.

위험 경로(`..`, 절대 경로 등), 링크·특수 파일, 손상된 중앙 디렉터리, 분석 대상 항목의 압축 데이터·CRC 오류, 총량·압축률·항목 제한 위반은 **배치 전체 접수를 거절**한다. 분할 ZIP과 ZIP64는 지원하지 않는다. 제외 대상의 본문은 해제하지 않으므로 그 본문의 CRC까지 검사하지는 않는다.

ZIP 내부 이름은 추출 경로로 사용하지 않는다. 임시 폴더의 고정 이름으로 읽고 검증이 끝난 PE만 원본 저장소에 보관한다. ZIP 자체와 임시 파일은 처리 후 정리한다. Python 표준 라이브러리 [zipfile](https://docs.python.org/3/library/zipfile.html)을 사용하며 추가 패키지는 없다.

로컬 클라이언트 호출 예시:

```powershell
curl.exe -X POST http://127.0.0.1:8000/batches/zip -F "file=@C:/approved-fixtures/demo.zip" -H "Idempotency-Key: demo-zip-001"
```

위 경로는 사용할 승인된 입력 파일의 실제 경로로 바꾼다. API 인증이 설정됐다면 `X-API-Key`도 필요하다.

## 6. 목록·진행·결과 조회 API

### GET /analyses

분석 목록을 조회한다.

| 조회 조건 | 기본값 | 허용 값·의미 |
|---|---|---|
| `limit` | 20 | 한 번에 가져올 개수, 1~100 |
| `offset` | 0 | 앞에서 건너뛸 개수, 0 이상 |
| `status` | 지정하지 않음 | `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED` 중 하나 |
| `sha256` | 지정하지 않음 | 소문자 16진수 64자리 해시 |
| `verdict` | 지정하지 않음 | 초기 JRR 판정: `HIGH_RISK_UNCERTAIN`, `AUTO_MALICIOUS`, `AUTO_BENIGN` |
| `batch_id` | 지정하지 않음 | 특정 배치에 속한 결과만 조회 |
| `sort` | `high_risk_first` | 고위험 우선. `newest`로 최신 접수순 선택 가능 |

예: `GET /analyses?limit=20&offset=20&status=COMPLETED`는 완료된 분석의 앞 20개를 건너뛴 다음 목록을 가져온다. 응답에는 조건에 맞는 `total_count`, 적용된 `limit`·`offset`, `analyses` 목록이 있다.

기본 표시 순서는 **초기 고위험 → 자동 악성 → 자동 정상 → 미판정 → 실패**다. `FAILED`이면 초기 판정과 관계없이 마지막으로 표시하며, 같은 우선순위는 최신 접수순이다. 필터·정렬을 먼저 적용하고 그 결과를 페이지로 나눈다. 조회 정렬은 작업 실행 순서를 바꾸지 않는다. `verdict`는 초기 판정만 조회하므로 이후 시스템·전문가 판정이 달라져도 초기 고위험 결과를 다시 모아 볼 수 있다.

### GET /analyses/{analysis_id}/status

진행 표시를 갱신할 때 사용한다. 분석 번호와 함께 다음 필드를 반환한다.

| 필드 | 뜻 |
|---|---|
| `status` | 전체 작업의 진행 상태 |
| `current_stage` | 현재 처리 단계 |
| `created_at` / `updated_at` | 접수 시각 / 최근 갱신 시각 |
| `completed_at` | 종료 시각. 처리 중에는 `null` |
| `error` | 기록된 오류. 없으면 `null` |

화면에서 일정 간격으로 조회하고 `COMPLETED` 또는 `FAILED`가 되면 완료 상태를 표시하면 된다. `error`는 재시도를 기다리는 중에도 존재할 수 있으므로 전체 `status`와 함께 읽는다.

같은 번호를 주기적으로 확인하는 방식을 **폴링(polling)**이라고 한다. 다음은 이해를 위한 조회 흐름 예시다.

```text
첫 조회     GET .../status → QUEUED      "아직 대기 중이에요."
잠시 후     GET .../status → RUNNING     "분석하고 있어요."
다시 조회   GET .../status → COMPLETED   "처리가 끝났어요."
                                또는 FAILED "실패 이유를 확인해 주세요."
```

조회 간격에 따라 중간 상태를 건너뛰고 바로 완료 상태를 받을 수도 있다. 화면은 특정 순서의 응답이 모두 올 것을 기다리기보다 현재 반환된 상태를 표시하면 된다.

### GET /analyses/{analysis_id}

한 분석의 종합 결과를 화면에 표시할 때 사용한다. 파일 정보, 최초 모델 확률·위험 신호·JRR 판정, SHAP 주요 Feature, 심층 도구 상태, Evidence 요약, LLM 설명, 시스템 최종 제안, 전문가 판정·검토 상태를 반환한다.

`final_assessment`에는 최종 제안의 이유, `disposition` 처리 방향, `requires_human_review` 검토 필요 여부, 적용 정책 이름이 있다. 현재 심층 분석 대상은 `UNCERTAIN`으로 전문가 검토에 넘기며, 자동 최종 재판정 규칙은 팀에서 확정해야 한다.

이 응답은 화면용으로 합친 결과다. CAPA·FLOSS·Speakeasy 세부 결과는 `/deep-analysis`, Feature 메타데이터는 `/triage`, 설명 오류는 `/xai`에서 확인한다.

### GET /batches/{batch_id}

묶음 전체의 처리 현황을 조회한다.

| 필드 | 뜻 |
|---|---|
| `total_count` | 묶음에 등록된 분석 수. `SKIPPED` 제외 |
| `finished_count` | `COMPLETED` 또는 `FAILED`로 종료된 파일 수 |
| `status_counts` | 각 상태별 파일 수 |
| `analyses` | 파일별 종합 결과 목록 |
| `status` | 묶음의 진행 상태 |
| `summary` | 분석 상태별 개수와 초기 판정별 개수 |
| `input_count` / `accepted_count` / `skipped_count` / `entries` | 최초 접수 내역. 제외 사유도 보존 |

예를 들어 완료 3개·실패 1개면 `finished_count`는 4다. 이 숫자가 정상 파일 수를 뜻하지는 않는다.

```text
파일 5개 접수
        ├─ COMPLETED 3개
        ├─ FAILED    1개
        └─ RUNNING   1개

total_count    = 5
finished_count = 4       → 화면에 "5개 중 4개 처리 종료" 표시
```

`summary`는 다음 두 집계를 독립적으로 제공한다.

- 작업 상태: `queued`, `running`, `completed`, `failed`의 합계 = `total`
- 초기 판정: `auto_benign`, `auto_malicious`, `high_risk_uncertain`, `unclassified`의 합계 = `total`

고위험 파일이 심층 분석 중이면 `running`과 `high_risk_uncertain`에 각각 포함된다. 분석 실패는 악성 판정을 뜻하지 않으며 `SKIPPED`는 실패 분석 수에 포함하지 않는다.

| 배치 `status` | 의미 |
|---|---|
| `QUEUED` | 등록된 분석이 모두 대기 중 |
| `RUNNING` | 진행 중이며 아직 종료된 분석 없음 |
| `PARTIALLY_COMPLETED` | 일부가 종료됐고 나머지는 대기 또는 진행 중 |
| `COMPLETED` | 모두 종료됨. 일부 실패나 전체 입력 제외도 포함 |
| `FAILED` | 등록된 분석이 1건 이상이고 모두 실패 |

기본 `sort=high_risk_first`이며, `newest`와 `input_order`도 지원한다. 이 API의 `analyses`에는 배치에 등록된 전체 분석이 담긴다. 요약은 아래의 필터 조회 결과와 관계없이 항상 배치 전체를 집계한다.

### GET /batches/{batch_id}/analyses

배치 내부의 결과만 필터링하고 페이지로 가져온다. `GET /analyses`의 `status`, `sha256`, `verdict`, `limit`, `offset`을 지원하며, `sort`는 `high_risk_first`, `newest`, `input_order` 중 하나다.

```text
GET /batches/batch_abc123/analyses?verdict=HIGH_RISK_UNCERTAIN&limit=20&offset=0
```

응답은 `batch_id`, 필터에 맞는 `total_count`, `limit`, `offset`, `analyses`다. 일치 결과가 없거나 모든 입력이 제외된 배치는 빈 목록, 존재하지 않는 배치는 `404 / BATCH_NOT_FOUND`를 반환한다.

## 7. 분석별 상세 API

### GET /analyses/{analysis_id}/triage

초기 모델과 JRR 결과를 조회한다. 이 응답의 `status`는 초기 분석 부분의 상태다. 심층 분석이 진행 중이어도 초기 결과가 저장되어 있다면 `COMPLETED`일 수 있다.

| 주요 필드 | 내용 |
|---|---|
| `prediction.lgbm_raw_probability` | LightGBM이 계산한 악성 확률 |
| `prediction.xgb_raw_probability` | XGBoost가 계산한 악성 확률 |
| `prediction.calibrated_probability` | Calibration을 적용한 확률 |
| `risk_signals.disagreement` | 모델 사이의 불일치 |
| `risk_signals.ood_score` | Isolation Forest 점수. 음수도 나올 수 있음 |
| `risk_signals.difficulty_score` | 분석 난이도 신호 |
| `initial_verdict` / `route` / `reason` | 최초 JRR 판정, `FINAL` 또는 `DEEP_ANALYSIS` 경로, 선택 이유 |
| `feature_metadata` | 사용한 Feature Schema·모델 산출물 식별 정보 등 |

### GET /analyses/{analysis_id}/xai

LightGBM의 원래 출력에 대한 SHAP 설명을 조회한다. `explained_output`은 `LIGHTGBM_RAW_OUTPUT`이다.

`top_features`의 각 항목은 `feature_name`, `feature_value`, `shap_value`, `direction`으로 구성된다. `direction`은 악성 방향 `MALICIOUS`, 정상 방향 `BENIGN`, 중립 `NEUTRAL` 중 하나다. 기본 반환 개수는 5개이며 설정으로 변경할 수 있다.

설명 생성이 실패하면 이 응답은 `FAILED`와 오류를 반환할 수 있다. 이미 저장한 초기 모델 예측과 JRR 결과는 유지된다.

### GET /analyses/{analysis_id}/deep-analysis

심층 분석의 도구 결과와 증거를 조회한다.

| 필드 | 내용 |
|---|---|
| `status` | 심층 분석 응답의 전체 상태 |
| `deep_analysis_status` | `capa`, `floss`, `speakeasy`, `cape`별 진행 상태. 현재 `cape`는 `NOT_REQUIRED` |
| `tool_details` | 원래 도구 상태·버전·실행 시간 등 |
| `capa` / `floss` / `speakeasy` | 각 도구의 정리된 결과 |
| `evidence` | ATT&CK 기법별로 모은 증거 요약 |
| `evidence_details` | 개별 Evidence의 식별자·출처·신뢰도·요약 등 |
| `llm_summary` / `llm_status` | LLM 설명과 해석 단계 상태 |
| `error` | 오류 정보 |

도구의 `TIMEOUT` 같은 원래 상태는 `tool_details`에 보존한다. LLM 설명은 전문가 보조 정보이고 원본 Evidence와 함께 확인해야 한다.

백엔드가 시간 초과로 `FAILED`가 된 뒤에도 별도 Worker는 계속 실행 중일 수 있다. 이때 전체 실패 상태와 도구의 `RUNNING` 상태가 함께 보일 수 있다. 조회는 별도 Worker를 취소하거나 다시 실행하지 않는다.

## 8. 전문가 검토 API

### PATCH /analyses/{analysis_id}/verdict

분석이 `COMPLETED` 또는 `FAILED`로 종료된 뒤 전문가 판정과 의견을 저장한다. JSON 본문을 보낸다.

```text
분석 결과와 증거 읽기
        ↓ 현재 review_revision 확인
전문가가 정상 / 악성 / 보류 선택, 의견 입력
        ↓
PATCH /analyses/{analysis_id}/verdict
        ↓
검토 이력 추가 + 새 revision 반환
```

| 필드 | 필수 | 허용 값·설명 |
|---|---|---|
| `analyst_final_verdict` | 예 | `BENIGN`, `MALICIOUS`, 또는 판단 보류 `null` |
| `reviewer_id` | 예 | 검토자 식별자, 1~128자. 영문·숫자·`_ . @ -` 사용 |
| `expected_revision` | 예 | 직전 조회에서 받은 `review_revision`, 0 이상 |
| `analyst_notes` | 아니요 | 검토 의견. 기본 빈 문자열, 최대 4,000자 |

예시:

```json
{
  "analyst_final_verdict": "BENIGN",
  "reviewer_id": "sangwook",
  "expected_revision": 0,
  "analyst_notes": "분석 증거를 확인한 뒤 정상으로 판단했습니다."
}
```

처음 검토할 때 현재 `review_revision`이 0이면 `expected_revision=0`을 보낸다. 저장하면 응답의 `revision`은 1이 된다. 이후 수정은 새로 조회한 번호를 사용한다. 다른 사람이 먼저 검토해 번호가 달라졌다면 `409`이므로 최신 결과를 확인해야 한다.

`revision`은 검토 기록이 몇 번째로 저장됐는지를 나타내는 번호다. 두 사람이 같은 분석을 보고 있을 때 다음처럼 기존 의견을 보호한다.

```text
상욱과 건우가 같은 분석을 조회 → 둘 다 review_revision 0 확인
        │
        ├─ 상욱: expected_revision 0으로 저장 → 성공, revision 1
        │
        └─ 건우: expected_revision 0으로 저장 → 409 충돌
                    ↓
               최신 결과와 상욱의 의견을 다시 조회
                    ↓
               내용을 확인한 후 필요하면 revision 1 기준으로 저장
```

응답에는 `analysis_id`, `revision`, `analyst_final_verdict`, `analyst_notes`, `reviewer_id`, `reviewed_at`이 있다. 검토는 새 이력으로 추가되며 시스템의 `final_verdict`를 덮어쓰지 않는다. `null`로 저장하면 판단 보류 의견을 남긴다.

### GET /analyses/{analysis_id}/reviews

검토 이력을 조회한다. 응답의 `items`에 검토 기록이 revision 순으로 들어 있다. 아직 검토가 없다면 빈 목록이다.

## 9. 오류 응답

오류는 다음 공통 형태를 사용한다.

```json
{
  "error": {
    "code": "ANALYSIS_NOT_FOUND",
    "message": "해당 분석을 찾을 수 없습니다.",
    "stage": null,
    "retryable": false
  }
}
```

| HTTP 상태 | 대표 의미 |
|---|---|
| 400 | 잘못된 multipart·HTTP 요청 형식 |
| 401 | API 토큰 확인 필요 |
| 403 | 검토 권한 토큰 확인 필요 |
| 404 | 요청한 분석·묶음 번호 없음 |
| 408 | 요청 본문 업로드 시간 초과 |
| 409 | 중복 접수 키 충돌, 검토 번호 충돌, 미종료 분석에 검토 요청 |
| 413 | 업로드 용량 초과 |
| 422 | 필수 필드·자료형·허용 값·파일 형식 오류 |
| 500 | 서버 처리 오류 |
| 503 | DB·저장소 설정 또는 연결 등 확인 필요 |

분석 중 도구나 모델이 실패하는 경우에는 조회 요청 자체가 정상 처리되어 HTTP `200`을 반환하면서, JSON 안의 `status`가 `FAILED`일 수 있다. HTTP 성공 여부와 분석 성공 여부를 함께 확인한다.

```text
GET /analyses/{analysis_id}
        ↓
HTTP 200                "결과 조회 요청은 정상 처리됐어요."
JSON의 status = FAILED  "조회한 분석 작업은 실패했어요."
JSON의 error            "어느 단계에서 실패했는지 확인하세요."
```

## 10. 화면에서 호출하는 순서

```text
POST /analyses                       파일 접수 → analysis_id 받기
        ↓
GET /analyses/{analysis_id}/status   진행 상황 주기적으로 조회
        ↓
GET /analyses/{analysis_id}          종료 후 종합 결과 표시
        ↓
필요하면 /triage, /deep-analysis, /xai 조회
        ↓
PATCH /analyses/{analysis_id}/verdict 전문가 의견 저장
        ↓
GET /analyses/{analysis_id}/reviews  검토 이력 확인
```

일괄 업로드 화면은 `POST /batches`로 받은 `batch_id`를 이용해 `GET /batches/{batch_id}`를 조회한다. 개별 상세 화면은 묶음 안의 `analysis_id`를 사용한다.

## 11. OpenAPI와 Swagger UI

Swagger UI는 API를 **서비스 상태, 분석 접수, 분석 조회, 배치 분석, 전문가 검토**의 다섯 영역으로 구분한다. 첫 화면의 표는 다음 표준 처리 흐름과 각 operation을 연결한다.

```text
GET /health
    ↓
POST /analyses → analysis_id
    ↓
GET /analyses/{analysis_id}/status
    ↓
GET /analyses/{analysis_id}
```

각 operation 설명은 목적, 요청 계약, 응답 의미, 일관성 또는 실패 특성을 명시한다. `Example Value`는 OpenAPI 스키마의 대표 값이며 실제 요청 결과와 구분된다. 실행 결과는 Swagger UI의 `Server response → Response body`에 표시된다. `/status`는 수명주기의 각 상태 예시를, 전문가 검토 API는 보류·정상·악성 요청 예시를 제공한다.

현재 가상환경에서 문서 서버를 실행하는 PowerShell 명령은 다음과 같다.

```powershell
cd C:\Users\lsu01\Desktop\except_04\backend-api
.\trust-triage-env\Scripts\python.exe -m uvicorn trust_triage.backend_api.app:create_app --factory --app-dir src --host 127.0.0.1 --port 8000
```

Swagger UI는 [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)에서 제공된다. `Try it out`과 `Execute`는 명세에 정의된 요청을 실제 서버로 전송한다. API 키 검증이 활성화된 환경에서는 상단 `Authorize`의 `ApiKeyAuth`에 접근 키를 설정하며, 전문가 검토 키가 별도로 활성화된 경우 `ReviewerKeyAuth`도 필요하다.

문서 화면과 `/health`는 데이터베이스 설정 없이 사용할 수 있다. 분석 접수 및 저장 결과 조회에는 데이터베이스가 필요하고, 비동기 분석 수행에는 모델·도구 환경과 별도의 `run` 처리기가 필요하다. `202 Accepted`는 분석 완료가 아니라 작업 등록을 의미한다.

문서 관련 주소는 업무 API 15개와 별도다.

| 주소 | 용도 |
|---|---|
| `/docs` | Swagger UI 및 대화형 요청 실행 |
| `/redoc` | ReDoc 기반 API 계약 문서 |
| `/openapi.json` | OpenAPI 3.1 JSON 명세 |

실행 중인 서버의 `/openapi.json`이 API 계약의 기준이다. 저장소의 [openapi.json](openapi.json)은 배포 또는 검토용 스냅샷이며 코드 변경 시 함께 다시 생성한다. operation 설명과 예시는 [api_docs.py](../../src/trust_triage/backend_api/api_docs.py), 필드 설명은 [schemas.py](../../src/trust_triage/backend_api/schemas.py)에서 관리한다. Swagger UI 설정은 FastAPI의 [Swagger UI 구성 방식](https://fastapi.tiangolo.com/how-to/configure-swagger-ui/)을 사용한다.
