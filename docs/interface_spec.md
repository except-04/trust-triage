# TRUST-Triage Interface Specification

> **문서 목적**  
> TRUST-Triage 서비스의 각 컴포넌트가 **어떤 데이터를 주고받아야 하는지**를 정의하는 공통 인터페이스 명세서입니다.  
> Frontend, Backend, JRR, Deep Analysis, Task Queue/Worker, Database, MCP 담당자가 동일한 필드명·상태값·데이터 구조를 사용하도록 하는 것을 목표로 합니다.

---

## 0. 문서 상태

| 항목 | 내용 |
|---|---|
| 문서명 | `TRUST-Triage Interface Specification` |
| 권장 파일명 | `interface_spec.md` |
| 적용 범위 | M4 서비스 통합 및 백엔드 구축 |
| 주요 대상 | Frontend / Backend / DB / Deep Analysis / Task Queue / AWS / System Integration |
| 상태 | Draft |
| 변경 원칙 | 인터페이스 필드명·Enum·필수값 변경 시 팀 공유 후 문서 우선 수정 |

---

# 🚨 Critical 사항

아래 항목은 **모듈 간 호환성을 위해 반드시 동일하게 지켜야 하는 공통 계약**입니다.

## CRITICAL-01. 공통 식별자 이름을 통일한다

모든 서비스에서 아래 필드명을 동일하게 사용합니다.

- `analysis_id`: 개별 파일 분석 1건의 고유 ID
- `batch_id`: 다중 파일 분석 요청의 고유 ID
- `sha256`: 분석 대상 파일의 SHA-256
- `created_at`: 분석 요청 생성 시각

> **Critical**  
> `id`, `job_id`, `sample_id` 등 임의의 이름으로 바꾸지 않습니다.  
> 개별 분석의 기준 ID는 `analysis_id`로 통일합니다.

---

## CRITICAL-02. 분석 상태 Enum을 통일한다

비동기 작업 및 분석 진행 상태는 아래 값을 사용합니다.

```text
QUEUED
RUNNING
COMPLETED
FAILED
NOT_REQUIRED
```

| 상태 | 의미 |
|---|---|
| `QUEUED` | 작업이 Queue에 등록되어 대기 중 |
| `RUNNING` | Worker 또는 분석 모듈이 실행 중 |
| `COMPLETED` | 정상적으로 분석 완료 |
| `FAILED` | 분석 실패 |
| `NOT_REQUIRED` | 해당 분석 단계가 필요하지 않아 실행하지 않음 |

> **Critical**  
> Frontend, Backend, Worker, DB가 서로 다른 상태 문자열을 사용하지 않습니다.

---

## CRITICAL-03. JRR Verdict 값을 통일한다

초기 JRR 판정은 아래 3개 값만 사용합니다.

```text
AUTO_BENIGN
AUTO_MALICIOUS
HIGH_RISK_UNCERTAIN
```

> **Critical**  
> `HIGH_RISK`, `UNCERTAIN`, `REVIEW` 등 유사 표현을 별도 값으로 추가하지 않습니다.  
> UI 표시 문구가 필요하면 Frontend에서 별도 Label로 변환합니다.

---

## CRITICAL-04. Raw PE 파일 자체를 Queue 메시지에 넣지 않는다

Task Queue에는 PE 바이너리 자체를 전달하지 않고 **파일 위치를 참조할 수 있는 식별자만 전달**합니다.

예:

```json
{
  "analysis_id": "a_20260907_000001",
  "sha256": "....",
  "file_location": "s3://trust-triage-temp/...."
}
```

> **Critical**  
> Raw PE는 Queue 메시지, DB JSON, 로그 등에 Base64 형태로 직접 삽입하지 않습니다.

---

## CRITICAL-05. 판정 단계는 서로 덮어쓰지 않는다

TRUST-Triage는 판정을 단계별로 분리하여 보존합니다.

```text
initial_verdict
    ↓
final_verdict
    ↓
analyst_final_verdict
```

| 필드 | 의미 |
|---|---|
| `initial_verdict` | JRR의 초기 판정 |
| `final_verdict` | 심층분석 및 자동화 결과를 반영한 최종 시스템 판정 |
| `analyst_final_verdict` | 분석가가 최종 검토 후 확정한 판정 |

> **Critical**  
> 심층분석 결과가 나왔다고 `initial_verdict`를 덮어쓰지 않습니다.

---

## CRITICAL-06. SHAP과 Behavioral Evidence를 분리한다

- `top_features`: **모델이 왜 그렇게 예측했는지** 설명하는 SHAP 기반 모델 근거
- `evidence`: CAPA / FLOSS / Speakeasy 등에서 확보한 **행위·분석 근거**

> **Critical**  
> SHAP 결과와 CAPA/Speakeasy Evidence를 하나의 근거 필드에 섞어 저장하지 않습니다.

---

## CRITICAL-07. 외부 LLM에는 Raw PE를 직접 전달하지 않는다

LLM Analyst Assist에는 아래처럼 **정형화된 분석 결과와 추출된 텍스트 정보**만 전달합니다.

- CAPA 결과
- FLOSS 추출 문자열
- Speakeasy 행위 결과
- MITRE ATT&CK Evidence
- JRR / SHAP 요약 정보

> **Critical**  
> 외부 LLM API에 Raw PE 바이너리를 직접 전송하지 않습니다.

---

## CRITICAL-08. `file_location`은 내부 서비스 전용 필드로 사용한다

`file_location`은 Backend, Worker, Storage 간 파일 참조를 위한 내부 값입니다.

> **Critical**  
> S3 URI 또는 내부 경로를 Frontend / 외부 REST Client / MCP 응답에 그대로 노출하지 않습니다.

---

## CRITICAL-09. 전체 분석 상태와 도구별 상태를 구분한다

- `status`: 분석 1건 전체의 진행 상태
- `deep_analysis_status`: CAPA / FLOSS / Speakeasy 등 도구별 상태

예:

```json
{
  "status": "RUNNING",
  "deep_analysis_status": {
    "capa": "COMPLETED",
    "floss": "COMPLETED",
    "speakeasy": "QUEUED"
  }
}
```

> **Critical**  
> Speakeasy 하나가 `QUEUED`라고 해서 전체 분석 객체의 상태를 임의로 같은 값으로 덮어쓰지 않습니다.

---

# 1. 전체 인터페이스 흐름

```text
[Streamlit Frontend]
        │
        │ Raw PE / Batch Upload
        ▼
[FastAPI Backend]
        │
        ├── SHA-256 / analysis_id 생성
        ├── 파일 임시 저장
        │
        ▼
[Initial Analysis Pipeline]
Feature Extraction
→ LightGBM / XGBoost
→ Calibration
→ Risk Signals
→ JRR
→ SHAP
        │
        ├── AUTO_BENIGN
        ├── AUTO_MALICIOUS
        │
        └── HIGH_RISK_UNCERTAIN
                    │
                    ▼
             [Deep Analysis]
             CAPA + FLOSS
                    │
                    ▼
              [Task Queue]
                    │
                    ▼
           [Speakeasy Worker]
                    │
                    ▼
              [LLM Summary]
                    │
                    ▼
            [Final Assessment]

        ↕ PostgreSQL
        ↕ Temporary File Storage / S3

[Optional MCP Server]
        │
        └── 기존 Backend/API 기능 재사용
```

---

# 2. 공통 데이터 규칙

## 2.1 공통 필드

가능한 모든 분석 결과 객체는 아래 공통 필드를 포함합니다.

```json
{
  "analysis_id": "a_20260907_000001",
  "batch_id": null,
  "sha256": "64-character-sha256",
  "created_at": "2026-09-07T14:30:00+09:00"
}
```

### 필드 정의

| 필드 | 타입 | 필수 | 설명 |
|---|---|---:|---|
| `analysis_id` | string | O | 개별 분석 고유 ID |
| `batch_id` | string / null | O | Batch 요청이 아니면 `null` |
| `sha256` | string | O | 분석 파일 SHA-256 |
| `created_at` | ISO 8601 datetime | O | 분석 요청 생성 시각 |

---

## 2.2 시간 형식

모든 시간값은 **ISO 8601** 형식 사용을 권장합니다.

```text
2026-09-07T14:30:00+09:00
```

서버 내부 UTC 사용 여부는 Backend/AWS 구현 시 확정하되, API 응답 형식은 일관되게 유지합니다.

---

## 2.3 Null 처리

분석하지 않은 값은 빈 문자열(`""`) 대신 `null`을 사용합니다.

예:

```json
{
  "batch_id": null,
  "analyst_final_verdict": null
}
```

---

# 3. Raw PE Input Interface

## 3.1 Single File Upload

### 입력

```text
POST /analyses
Content-Type: multipart/form-data
```

| 필드 | 타입 | 필수 | 설명 |
|---|---|---:|---|
| `file` | binary | O | Raw PE 파일 |

### Backend 생성값

Backend는 업로드 후 다음 값을 생성합니다.

- `analysis_id`
- `sha256`
- `file_location`
- `created_at`

### 초기 응답 예시

```json
{
  "analysis_id": "a_20260907_000001",
  "batch_id": null,
  "sha256": "....",
  "status": "RUNNING",
  "created_at": "2026-09-07T14:30:00+09:00"
}
```

---

## 3.2 Batch / Multiple File Upload

### 입력

```text
POST /batches
Content-Type: multipart/form-data
```

```text
files = [sample1.exe, sample2.exe, sample3.exe]
```

### 응답 예시

```json
{
  "batch_id": "b_20260907_000001",
  "total_count": 3,
  "analyses": [
    {
      "analysis_id": "a_001",
      "sha256": "...",
      "status": "QUEUED"
    },
    {
      "analysis_id": "a_002",
      "sha256": "...",
      "status": "QUEUED"
    },
    {
      "analysis_id": "a_003",
      "sha256": "...",
      "status": "QUEUED"
    }
  ]
}
```

> **Critical**  
> Batch 전체에 하나의 `analysis_id`를 부여하지 않습니다.  
> **파일마다 독립적인 `analysis_id`를 생성**하고, 상위 그룹 식별자로 `batch_id`를 사용합니다.

---

# 4. Initial Analysis / JRR Interface

## 4.1 Initial Triage Result

Initial Analysis Pipeline 완료 후 Backend가 저장·제공하는 표준 구조입니다.

```json
{
  "analysis_id": "a_20260907_000001",
  "sha256": "...",
  "prediction": {
    "lgbm_raw_probability": 0.9123,
    "xgb_raw_probability": 0.6842,
    "calibrated_probability": 0.8871
  },
  "risk_signals": {
    "disagreement": 0.2281,
    "ood_score": -0.031,
    "difficulty_score": 6
  },
  "initial_verdict": "HIGH_RISK_UNCERTAIN",
  "route": "DEEP_ANALYSIS",
  "reason": "Uncertain Probability (0.8871)"
}
```

## 4.2 Prediction Fields

| 필드 | 타입 | 설명 |
|---|---|---|
| `lgbm_raw_probability` | float | LightGBM 원시 악성 확률 |
| `xgb_raw_probability` | float | XGBoost 원시 악성 확률 |
| `calibrated_probability` | float | Isotonic Calibration 적용 확률 |

## 4.3 Risk Signals

```json
{
  "disagreement": 0.2281,
  "ood_score": -0.031,
  "difficulty_score": 6
}
```

| 필드 | 설명 |
|---|---|
| `disagreement` | `abs(LGBM - XGBoost)` |
| `ood_score` | Isolation Forest `decision_function` 결과 |
| `difficulty_score` | PEFormatWarnings 기반 분석 난이도 점수 |

### 현재 기준값

| 항목 | 현재 값 |
|---|---:|
| `tau_low` | `0.65` |
| `tau_high` | `0.983645` |
| `tau_disagree` | `0.30` |
| `tau_difficulty` | `5` |
| OOD 조건 | `ood_score < 0` |

> Threshold 값이 변경될 경우 코드만 수정하지 말고 관련 설계/평가 문서와 본 명세서를 함께 갱신합니다.

## 4.4 JRR Reason

JRR은 Priority-ordered Rule-based Router이며, 가장 먼저 만족한 규칙을 대표 `reason`으로 기록합니다.

권장 Reason Label:

```text
OOD Detected
High Model Disagreement
High Analysis Difficulty
Uncertain Probability
High Malicious Confidence
High Benign Confidence
```

> **Critical**  
> `Uncertain Probability`는 별도의 확률 필드가 아닙니다.  
> `tau_low < calibrated_probability < tau_high`인 **Calibrated Probability Gray Zone**에 대한 설명용 Reason Label입니다.  
> 공식 확률 필드명은 계속 `calibrated_probability`를 사용합니다.

## 4.5 Route

권장 Route 값:

```text
FINAL
DEEP_ANALYSIS
```

예:

```json
{
  "initial_verdict": "AUTO_BENIGN",
  "route": "FINAL"
}
```

또는

```json
{
  "initial_verdict": "HIGH_RISK_UNCERTAIN",
  "route": "DEEP_ANALYSIS"
}
```

---

# 5. SHAP / XAI Interface

SHAP은 **LightGBM 모델의 판정 근거**를 설명합니다.

```json
{
  "analysis_id": "a_20260907_000001",
  "top_features": [
    {
      "feature_name": "feature_102",
      "feature_value": 1.34,
      "shap_value": 0.281,
      "direction": "MALICIOUS"
    },
    {
      "feature_name": "feature_031",
      "feature_value": 0.22,
      "shap_value": -0.194,
      "direction": "BENIGN"
    }
  ]
}
```

> **Critical**  
> SHAP은 **Raw LightGBM 출력에 대한 모델 설명**입니다.  
> `calibrated_probability`를 SHAP이 직접 설명하는 것처럼 표현하지 않습니다.

---

# 6. Deep Analysis Job Interface

`HIGH_RISK_UNCERTAIN` 샘플은 먼저 **Tier 1(CAPA + FLOSS)** 분석을 수행합니다.  
Tier 1 결과만으로 충분하지 않아 Speakeasy가 필요한 경우에만 Tier 2 비동기 Job을 Queue에 등록합니다.

```text
HIGH_RISK_UNCERTAIN
        ↓
CAPA + FLOSS
        ↓
Speakeasy 필요
        ↓
Task Queue
        ↓
Speakeasy Worker
```

현재 Task Queue는 **AWS SQS를 우선 적용 후보로 두며, 팀 최종 확정 후 본 문서에서 TBD를 제거합니다.**

## 6.1 SQS Message Body

```json
{
  "analysis_id": "a_20260907_000001",
  "sha256": "...",
  "file_location": "s3://trust-triage-temp/sample.exe",
  "requested_stage": "SPEAKEASY",
  "requested_at": "2026-09-07T15:30:00+09:00"
}
```

| 필드 | 필수 | 설명 |
|---|---:|---|
| `analysis_id` | O | 분석 ID |
| `sha256` | O | 파일 해시 |
| `file_location` | O | Worker가 Raw PE를 가져올 위치 |
| `requested_stage` | O | 실행할 심층분석 단계 (`SPEAKEASY`) |
| `requested_at` | O | Queue 등록 시각 |

> **Critical**  
> Queue 메시지는 가능한 한 작게 유지하고, 분석 원본/대형 JSON 전체를 메시지에 포함하지 않습니다.
>
> SQS Standard Queue 사용 시 중복 전달 가능성을 고려하여 Worker는 `analysis_id` 기준으로 **중복 완료 처리 방지(Idempotency)** 로직을 가져야 합니다.
>
> `file_location`은 Worker용 내부 필드이며 외부 API 응답에는 노출하지 않습니다.

---

# 7. CAPA Interface

```json
{
  "analysis_id": "a_20260907_000001",
  "tool": "CAPA",
  "status": "COMPLETED",
  "capabilities": [
    {
      "name": "example capability",
      "namespace": "example/namespace"
    }
  ],
  "mitre_techniques": [
    {
      "technique_id": "T1059",
      "technique_name": "Command and Scripting Interpreter"
    }
  ],
  "raw_result_location": null
}
```

---

# 8. FLOSS Interface

```json
{
  "analysis_id": "a_20260907_000001",
  "tool": "FLOSS",
  "status": "COMPLETED",
  "strings": {
    "static": [],
    "stack": [],
    "tight": [],
    "decoded": []
  }
}
```

> FLOSS 문자열 자체를 곧바로 악성 근거로 확정하지 않습니다.  
> CAPA / Speakeasy / LLM Analyst Assist와 함께 해석합니다.

---

# 9. Speakeasy Worker Interface

## 9.1 Worker Status Flow

```text
QUEUED
   ↓
RUNNING
   ↓
COMPLETED
```

오류 발생 시:

```text
RUNNING
   ↓
FAILED
```

## 9.2 Speakeasy Result

```json
{
  "analysis_id": "a_20260907_000001",
  "tool": "SPEAKEASY",
  "status": "COMPLETED",
  "behavior": {
    "processes": [],
    "api_calls": [],
    "files": [],
    "registry": [],
    "network": []
  },
  "error": null
}
```

실패 예시:

```json
{
  "analysis_id": "a_20260907_000001",
  "tool": "SPEAKEASY",
  "status": "FAILED",
  "behavior": null,
  "error": {
    "code": "SPEAKEASY_EXECUTION_FAILED",
    "message": "..."
  }
}
```

---

# 10. Deep Analysis Status Interface

```json
{
  "deep_analysis_status": {
    "capa": "COMPLETED",
    "floss": "COMPLETED",
    "speakeasy": "RUNNING",
    "cape": "NOT_REQUIRED"
  }
}
```

> CAPE는 현재 자동 파이프라인 필수 구현 대상이 아니며, 외부 Behavioral Report 활용 여부에 따라 변경될 수 있습니다.

---

# 11. MITRE ATT&CK Evidence Interface

```json
{
  "evidence": [
    {
      "technique_id": "T1059",
      "technique_name": "Command and Scripting Interpreter",
      "sources": ["CAPA", "SPEAKEASY"],
      "summary": "Command execution related behavior detected."
    },
    {
      "technique_id": "T1055",
      "technique_name": "Process Injection",
      "sources": ["SPEAKEASY"],
      "summary": "Process injection related behavior observed."
    }
  ]
}
```

---

# 12. LLM Analyst Assist Interface

## 12.1 LLM 입력

```json
{
  "analysis_id": "a_20260907_000001",
  "initial_verdict": "HIGH_RISK_UNCERTAIN",
  "risk_signals": {
    "disagreement": 0.31,
    "ood_score": -0.04,
    "difficulty_score": 7
  },
  "capa": {},
  "floss": {},
  "speakeasy": {},
  "evidence": []
}
```

## 12.2 LLM 출력

```json
{
  "analysis_id": "a_20260907_000001",
  "llm_summary": {
    "summary": "분석 결과 요약",
    "suspicious_behaviors": [
      "의심 행위 1",
      "의심 행위 2"
    ],
    "analyst_notes": "추가 확인이 필요한 사항"
  }
}
```

> **Critical**  
> LLM Summary는 **분석가 보조 정보**입니다.  
> CAPA/Speakeasy 등 원본 Evidence를 대체하지 않습니다.

---

# 13. Final Assessment Interface

```json
{
  "analysis_id": "a_20260907_000001",
  "initial_verdict": "HIGH_RISK_UNCERTAIN",
  "final_verdict": "MALICIOUS",
  "analyst_final_verdict": null,
  "evidence": [],
  "llm_summary": {},
  "completed_at": "2026-09-07T14:35:00+09:00"
}
```

## `initial_verdict`

```text
AUTO_BENIGN
AUTO_MALICIOUS
HIGH_RISK_UNCERTAIN
```

## `final_verdict`

```text
BENIGN
MALICIOUS
UNCERTAIN
```

> **TBD**  
> `final_verdict`의 정확한 Enum은 Final Assessment 로직 확정 시 최종 결정합니다.

## `analyst_final_verdict`

```text
BENIGN
MALICIOUS
```

필요한 경우 `UNRESOLVED` 추가 여부를 별도로 결정합니다.

---

# 14. Analyst Feedback Interface

```json
{
  "analysis_id": "a_20260907_000001",
  "analyst_final_verdict": "MALICIOUS",
  "analyst_comment": "Suspicious process injection behavior confirmed.",
  "updated_at": "2026-09-07T15:00:00+09:00"
}
```

> 현재 모델 재학습 자동화 방식은 M4 이후 별도 결정합니다.

---

# 15. REST API Interface

아래 Endpoint는 권장 초안이며 Backend 구현 시 최종 확정합니다.

분석 요청은 심층분석이 비동기로 이어질 수 있으므로 `POST /analyses`, `POST /batches`는 작업 접수 후 `analysis_id` 또는 `batch_id`를 반환하는 구조를 권장합니다.

```text
HTTP 202 Accepted
```

를 기본 응답 후보로 사용합니다.

| Method | Endpoint | 설명 |
|---|---|---|
| `POST` | `/analyses` | 단일 PE 분석 요청 |
| `GET` | `/analyses/{analysis_id}` | 전체 분석 결과 조회 |
| `GET` | `/analyses/{analysis_id}/status` | 분석 상태 조회 |
| `GET` | `/analyses/{analysis_id}/triage` | Initial Triage 결과 조회 |
| `GET` | `/analyses/{analysis_id}/deep-analysis` | 심층분석 결과 조회 |
| `GET` | `/analyses/{analysis_id}/xai` | SHAP 결과 조회 |
| `POST` | `/batches` | 다중 파일 분석 요청 |
| `GET` | `/batches/{batch_id}` | Batch 진행 상태 및 결과 조회 |
| `PATCH` | `/analyses/{analysis_id}/verdict` | Analyst Verdict 저장 |

> 실제 URI 구조는 Backend 담당 구현 전에 팀 검토 후 확정합니다.

---

# 16. Frontend ↔ Backend Polling Interface

예:

```text
GET /analyses/{analysis_id}/status
```

응답:

```json
{
  "analysis_id": "a_20260907_000001",
  "status": "RUNNING",
  "current_stage": "SPEAKEASY"
}
```

완료 시:

```json
{
  "analysis_id": "a_20260907_000001",
  "status": "COMPLETED",
  "current_stage": "FINAL_ASSESSMENT"
}
```

---

## 16.1 권장 `current_stage`

```text
UPLOAD
INITIAL_ANALYSIS
JRR
CAPA_FLOSS
SPEAKEASY
LLM
FINAL_ASSESSMENT
```

---

# 17. MCP Interface

MCP는 기존 TRUST-Triage 분석 기능을 AI Agent가 Tool 형태로 사용할 수 있도록 하는 확장 인터페이스입니다.

## 권장 MCP Tools

```text
analyze_sample
get_analysis_status
get_analysis_result
get_deep_analysis_result
get_final_assessment
```

### 설계 원칙

```text
AI Agent
   ↓
MCP Server
   ↓
기존 FastAPI / Service Layer
   ↓
TRUST-Triage Pipeline
```

> **Critical**  
> MCP용 별도 분석 파이프라인을 만들지 않습니다.  
> Web, REST API, MCP는 **동일한 Backend 및 분석 엔진을 재사용**해야 합니다.

---

# 18. File Storage Interface

```json
{
  "analysis_id": "a_20260907_000001",
  "sha256": "...",
  "file_location": "s3://bucket/object-key"
}
```

## 저장 원칙

1. Raw PE 업로드
2. SHA-256 계산
3. 임시 저장
4. 분석 수행
5. 필요한 분석 결과 및 Feature 저장
6. Raw PE 삭제 또는 Lifecycle 정책 적용

> **TBD**  
> Raw PE 보존 기간 및 S3 Lifecycle 세부 정책은 AWS/보안 정책 확정 후 반영합니다.

---

# 19. Database 저장 최소 항목

## Analysis Metadata

- `analysis_id`
- `batch_id`
- `sha256`
- filename
- created_at
- completed_at
- status

## Initial Analysis

- LightGBM probability
- XGBoost probability
- calibrated probability
- disagreement
- OOD score
- difficulty score
- initial verdict
- route

## XAI

- SHAP `top_features`

## Deep Analysis

- CAPA result
- FLOSS result
- Speakeasy result
- Deep Analysis status

## Evidence

- MITRE ATT&CK normalized evidence

## Final

- LLM summary
- final verdict
- analyst final verdict
- analyst comment

---

# 20. Error Interface

```json
{
  "analysis_id": "a_20260907_000001",
  "status": "FAILED",
  "error": {
    "stage": "SPEAKEASY",
    "code": "SPEAKEASY_EXECUTION_FAILED",
    "message": "Analysis failed."
  }
}
```

### 권장 Error Stage

```text
UPLOAD
FEATURE_EXTRACTION
MODEL_INFERENCE
CALIBRATION
JRR
SHAP
CAPA
FLOSS
QUEUE
SPEAKEASY
LLM
DATABASE
FINAL_ASSESSMENT
```

> **Critical**  
> 한 모듈의 실패가 전체 분석의 원인을 알 수 없는 `500 error` 하나로만 남지 않도록 실패 Stage를 기록합니다.

---

# 21. 담당 영역별 확인 항목

## Frontend

- API 필드명을 임의로 변경하지 않음
- Polling 상태 Enum 준수
- Batch 결과를 `batch_id` + 개별 `analysis_id` 기준으로 표시
- SHAP과 Behavioral Evidence를 화면에서 분리

## Backend / DB

- 공통 ID 생성 및 관리
- REST API 계약 유지
- JRR / Deep Analysis / Final Verdict를 분리 저장
- Worker가 조회 가능한 파일 위치 및 Job 정보 제공

## Deep Analysis / Task Queue

- SQS Message Body 구조 준수
- `analysis_id` 기준 Idempotency 처리
- 상태값 업데이트
- CAPA / FLOSS / Speakeasy 결과 표준 구조 반환
- Worker 실패 시 Error Interface 준수
- SQS 확정 시 Visibility Timeout / Retry / DLQ 정책을 Service Architecture와 함께 반영

## AWS / Infrastructure

- Raw PE 임시 저장소 구성
- Main Server ↔ Worker ↔ DB 간 접근 권한 관리
- Queue 및 Storage 권한 최소화
- Secret / API Key를 코드에 직접 저장하지 않음

## System Integration

- 모듈 간 필드명 및 상태 Enum 검증
- End-to-End 데이터 흐름 확인
- Web / REST API / MCP가 동일 분석 결과를 사용하는지 검증

---

# 22. 현재 TBD 항목

- [ ] Task Queue 최종 확정: **AWS SQS 우선안** (팀 확정 후 TBD 제거)
- [ ] Main Server / Worker 단일·분산 배치 최종 구조
- [ ] PostgreSQL 배포 방식: EC2 / RDS 등
- [ ] Raw PE 저장 방식 및 보존 기간
- [ ] Batch 최대 파일 수 / 파일 크기 제한
- [ ] ZIP 입력 지원 여부
- [ ] CAPA + FLOSS → Speakeasy Tier 진입 조건
- [ ] `final_verdict` 최종 Enum
- [ ] MCP 구현 범위 및 Tool 목록
- [ ] LLM API 및 Prompt/Output Schema 확정
- [ ] Final Assessment 자동 판정 로직

---

# 23. 변경 관리 규칙

```text
1. interface_spec.md 수정
        ↓
2. 관련 담당자 검토
        ↓
3. Backend / Worker / Frontend 코드 반영
        ↓
4. Integration Test
```

> **Critical**  
> 통합 단계에서는 **코드를 먼저 변경하고 문서를 나중에 맞추는 방식보다, 인터페이스 명세를 먼저 합의한 뒤 구현하는 방식**을 기본 원칙으로 합니다.

---

# 24. 핵심 계약 요약

```text
개별 분석 ID       → analysis_id
Batch ID           → batch_id
파일 식별           → sha256

분석 상태           → QUEUED / RUNNING / COMPLETED / FAILED / NOT_REQUIRED

JRR 판정            → AUTO_BENIGN / AUTO_MALICIOUS / HIGH_RISK_UNCERTAIN
JRR 대표 사유         → reason
Uncertain Probability → Gray Zone 설명용 Label (별도 확률 필드 아님)

모델 근거           → top_features (SHAP)
행위 근거           → evidence (CAPA/FLOSS/Speakeasy/MITRE)

비동기 작업         → CAPA/FLOSS → 필요 시 SQS → Speakeasy Worker
SQS 메시지           → analysis_id + sha256 + file_location + requested_stage
Raw PE              → 메시지/DB에 직접 삽입 금지

판정 이력           → initial_verdict
                      final_verdict
                      analyst_final_verdict

Web / REST / MCP    → 동일 Backend 및 분석 파이프라인 사용
```
