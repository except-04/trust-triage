# TRUST-Triage Service Architecture

> **문서 목적**  
> TRUST-Triage를 실제 서비스 형태로 운영하기 위한 **서비스 구성요소, 서버 배치, 통신 흐름, 저장소, 비동기 처리 구조**를 정의합니다.
>
> 본 문서는 **“어떤 모듈이 어디에서 실행되고, 서로 어떻게 연결되는가”**를 설명합니다.
>
> - 분석 로직 순서: `pipeline_architecture.md`
> - 세부 JSON/API/Queue 계약: `interface_spec.md`
> - 본 문서: `service_architecture.md`

---

## 0. 문서 상태

| 항목 | 내용 |
|---|---|
| 문서명 | `TRUST-Triage Service Architecture` |
| 파일명 | `service_architecture.md` |
| 적용 범위 | M4 서비스 통합 및 AWS 기반 PoC 구축 |
| 상태 | Draft |
| 주요 대상 | Frontend / Backend / DB / Deep Analysis / Task Queue / AWS / System Integration |
| 기본 방향 | Web + REST API + Optional MCP / PostgreSQL / 비동기 Deep Analysis / AWS 배포 |

---

# 🚨 Critical

## CRITICAL-01. 분석 엔진은 하나만 유지한다

Web, REST API, MCP가 각각 별도의 분석 로직을 가지지 않습니다.

```text
Streamlit ─┐
REST API ──┼──> FastAPI / Service Layer ──> TRUST-Triage Pipeline
MCP ───────┘
```

> **Critical**  
> Web용 JRR, API용 JRR, MCP용 JRR처럼 분석 엔진을 중복 구현하지 않습니다.  
> 모든 진입점은 동일한 Backend 및 분석 파이프라인을 재사용합니다.

---

## CRITICAL-02. PostgreSQL을 분석 상태의 기준 저장소(Source of Truth)로 사용한다

분석 상태와 결과는 Backend 메모리나 Frontend Session에만 보관하지 않습니다.

최소 저장 대상:

- `analysis_id`
- `batch_id`
- `sha256`
- 분석 상태
- Initial Verdict
- Risk Signals
- SHAP
- Deep Analysis 상태 및 결과
- Final Verdict
- Analyst Final Verdict

> **Critical**  
> Streamlit을 새로고침하거나 Worker가 재시작되어도 DB를 기준으로 분석 상태를 복구할 수 있어야 합니다.

---

## CRITICAL-03. Speakeasy는 FastAPI 요청 흐름에서 직접 오래 대기시키지 않는다

Speakeasy는 실행 시간이 길고 자원 사용량이 높을 수 있으므로 비동기 작업으로 분리합니다.

```text
FastAPI
   ↓
Task Queue
   ↓
Worker
   ↓
Speakeasy
```

> **Critical**  
> FastAPI Request Handler 안에서 Speakeasy 완료까지 수십 초~수분간 동기 대기하는 구조를 기본 구조로 사용하지 않습니다.

---

## CRITICAL-04. Raw PE 자체를 Queue 메시지에 넣지 않는다

Queue에는 다음과 같은 참조 정보만 전달합니다.

```json
{
  "analysis_id": "...",
  "sha256": "...",
  "file_location": "..."
}
```

Raw PE는 별도의 임시 파일 저장소에서 Worker가 읽습니다.

---

## CRITICAL-05. 외부 LLM에 Raw PE를 직접 전송하지 않는다

LLM Analyst Assist에는 다음과 같은 **정형화된 분석 결과**만 전달합니다.

- JRR 결과
- Risk Signals
- CAPA 결과
- FLOSS 문자열
- Speakeasy 행동 결과
- MITRE ATT&CK Evidence
- 필요한 경우 SHAP 요약

> **Critical**  
> Raw PE 바이너리를 외부 LLM API Payload에 포함하지 않습니다.

---

## CRITICAL-06. Batch 요청에서도 파일별 Job을 독립적으로 관리한다

```text
Batch
 ├─ analysis_id A
 ├─ analysis_id B
 └─ analysis_id C
```

> **Critical**  
> 하나의 파일이 실패해도 Batch 전체가 하나의 실패 Job으로 처리되지 않도록 합니다.

---

## CRITICAL-07. 인터페이스 필드와 상태값은 `interface_spec.md`를 따른다

서비스 구성요소마다 임의의 필드명 또는 상태 문자열을 만들지 않습니다.

예:

```text
analysis_id
batch_id
sha256

QUEUED
RUNNING
COMPLETED
FAILED
NOT_REQUIRED
```

---

## CRITICAL-08. 악성 파일 처리 서버와 권한을 최소화한다

Raw PE를 다루는 서비스와 Worker는 다음 원칙을 적용합니다.

- 최소 IAM 권한
- 외부 공개 최소화
- Raw PE Storage Private 설정
- Secret/API Key 코드 내 하드코딩 금지
- 필요 이상의 인터넷 접근 제한
- 분석 파일 로그/Queue/DB 직접 삽입 금지

---

# 1. 전체 서비스 구조

## 1.1 Logical Architecture

```text
                         ┌───────────────────┐
                         │   Analyst / User  │
                         └─────────┬─────────┘
                                   │
                         ┌─────────▼─────────┐
                         │ Streamlit Frontend│
                         └─────────┬─────────┘
                                   │ REST
                                   ▼
┌─────────────┐          ┌───────────────────┐
│  AI Agent   │          │  FastAPI Backend  │
└──────┬──────┘          │  / Service Layer  │
       │                 └─────────┬─────────┘
       │ MCP                         │
       ▼                             │
┌─────────────┐                      │
│ MCP Server  │──────────────────────┘
│  (Optional) │
└─────────────┘
                                     │
                                     ▼
                        ┌────────────────────────┐
                        │ Initial Analysis Engine│
                        │                        │
                        │ Feature Extraction     │
                        │ LightGBM / XGBoost     │
                        │ Calibration            │
                        │ Risk Signals           │
                        │ JRR                    │
                        │ SHAP                   │
                        └────────────┬───────────┘
                                     │
                  ┌──────────────────┴─────────────────┐
                  │                                    │
       AUTO_BENIGN / AUTO_MALICIOUS          HIGH_RISK_UNCERTAIN
                  │                                    │
                  │                                    ▼
                  │                         ┌─────────────────────┐
                  │                         │ Tier 1 Deep Analysis│
                  │                         │ CAPA + FLOSS        │
                  │                         └──────────┬──────────┘
                  │                                    │
                  │                         Tier 2 필요 여부 판단
                  │                                    │
                  │                                    ▼
                  │                         ┌─────────────────────┐
                  │                         │    Task Queue       │
                  │                         │ SQS candidate       │
                  │                         └──────────┬──────────┘
                  │                                    │
                  │                                    ▼
                  │                         ┌─────────────────────┐
                  │                         │ Speakeasy Worker    │
                  │                         └──────────┬──────────┘
                  │                                    │
                  │                                    ▼
                  │                         ┌─────────────────────┐
                  │                         │ Evidence Normalize  │
                  │                         │ + LLM Analyst Assist│
                  │                         └──────────┬──────────┘
                  │                                    │
                  └─────────────────┬──────────────────┘
                                    ▼
                         ┌─────────────────────┐
                         │  Final Assessment   │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │    PostgreSQL       │
                         └─────────────────────┘

Raw PE Upload
     │
     ▼
Temporary Storage / S3
     │
     ├── Initial Analysis Engine
     └── Speakeasy Worker
```

---

# 2. 서비스 구성요소

## 2.1 Streamlit Frontend

**담당: 김정윤**

### 역할

- Raw PE 업로드 UI
- 다중 파일/Batch 입력 UI
- 분석 요청
- 분석 진행 상태 표시
- Polling 기반 상태 갱신
- Initial Triage 결과 표시
- Risk Signals 표시
- SHAP 표시
- Deep Analysis 상태 표시
- MITRE ATT&CK Evidence 표시
- Final Assessment 표시

### 통신

```text
Streamlit
   ↓ HTTP / REST
FastAPI
```

> Frontend가 분석 모델이나 Speakeasy를 직접 호출하지 않습니다.

---

## 2.2 FastAPI Backend

**담당: 김건우**

### 역할

- 서비스 진입점
- Raw PE 분석 요청 수신
- `analysis_id`, `batch_id` 생성
- SHA-256 계산 및 중복 식별
- 분석 Job 생성
- Initial Analysis Pipeline 호출
- 결과 DB 저장
- Deep Analysis 진입 판단
- Queue Job 생성
- 분석 상태 조회 API 제공
- Final Result 조회 API 제공
- Analyst Feedback 저장

### Backend 기본 원칙

```text
Client
  ↓
FastAPI
  ↓
Service Layer
  ↓
Pipeline / DB / Queue
```

FastAPI Router 내부에 모든 분석 로직을 직접 작성하기보다 Service Layer에서 파이프라인을 호출하는 구조를 권장합니다.

---

## 2.3 Initial Analysis Engine

### 포함 모듈

```text
EMBER2024 v3 Feature Extraction
       ↓
Top-500
       ↓
LightGBM + XGBoost
       ↓
Isotonic Calibration
       ↓
Risk Signal Computation
       ↓
Priority-ordered Rule-based JRR
       ↓
SHAP
```

### 입력

```text
Raw PE
```

### 출력

- Model Probabilities
- Calibrated Probability
- Risk Signals
- Initial Verdict
- Route
- Reason
- SHAP Top Features

세부 데이터 형식은 `interface_spec.md`를 따릅니다.

---

## 2.4 PostgreSQL

**담당: 김건우 / AWS 배포 협업: 이가영**

### 역할

서비스의 상태 및 결과 저장소.

### 주요 저장 범위

```text
Analysis Metadata
Initial Analysis
JRR Result
SHAP
Deep Analysis Status
Deep Analysis Result
MITRE Evidence
LLM Summary
Final Verdict
Analyst Feedback
```

### 비정형 데이터

CAPA / FLOSS / Speakeasy / MITRE 등의 결과는 필요 시 PostgreSQL `JSONB` 활용을 검토합니다.

### 배포 방식

```text
TBD:
- PostgreSQL on EC2
- Amazon RDS for PostgreSQL
```

> 서비스 코드에서는 가능한 한 DB 배포 위치와 무관하게 동일한 Connection 설정으로 접근하도록 구성합니다.

---

# 3. Deep Analysis Architecture

## 3.1 Tier 1 — CAPA + FLOSS

**담당: 이상욱**

### 목적

`HIGH_RISK_UNCERTAIN` 샘플에 대해 비교적 빠르게 정적 Evidence를 확보합니다.

### CAPA

- Capability
- Rule Match
- MITRE ATT&CK 정보

### FLOSS

- Static Strings
- Stack Strings
- Tight Strings
- Decoded Strings

### 기본 흐름

```text
HIGH_RISK_UNCERTAIN
        ↓
CAPA + FLOSS
        ↓
Tier 1 Evidence
        ↓
Speakeasy 필요 여부 판단
```

> Tier 1 → Tier 2 진입 조건은 별도 정책으로 확정합니다.

---

## 3.2 Task Queue

**담당: 이상욱 / AWS 구성 협업: 이가영**

### 역할

Speakeasy처럼 오래 걸리는 작업을 Backend 요청 처리와 분리합니다.

```text
FastAPI / Deep Analysis Orchestrator
               ↓
           Task Queue
               ↓
             Worker
```

### 현재 후보

```text
AWS SQS
```

기존 검토안:

```text
Redis + RQ
```

### 최종 선택 상태

```text
TBD
```

> AWS 중심 배포 구조에서는 SQS를 우선 검토합니다.

---

## 3.3 Speakeasy Worker

**담당: 이상욱**

Worker는 별도의 상용 제품명이 아니라,  
**Queue에서 작업을 받아 Speakeasy 분석을 수행하는 Python 실행 프로세스**를 의미합니다.

### Worker 흐름

```text
Queue에서 Job 수신
      ↓
analysis_id 확인
      ↓
Raw PE 임시 저장소에서 로드
      ↓
DB status = RUNNING
      ↓
Speakeasy 실행
      ↓
결과 표준 Schema 변환
      ↓
PostgreSQL 저장
      ↓
DB status = COMPLETED
```

실패 시:

```text
FAILED
```

### Queue Message 예

```json
{
  "analysis_id": "a_001",
  "sha256": "...",
  "file_location": "s3://...",
  "requested_stage": "SPEAKEASY"
}
```

---

## 3.4 Worker Retry / Failure

Task Queue가 AWS SQS로 확정될 경우 다음 항목을 구성합니다.

- Visibility Timeout
- Retry Count
- Dead Letter Queue
- 중복 실행 방지
- `analysis_id` 기반 Idempotency

> **Critical**  
> SQS Standard Queue는 중복 전달 가능성을 고려하여 동일 `analysis_id`를 여러 Worker가 중복 완료 처리하지 않도록 방어합니다.

---

# 4. File / Storage Architecture

## 4.1 Raw PE 처리

```text
Upload
  ↓
SHA-256
  ↓
Temporary Storage
  ↓
Initial Analysis / Deep Analysis
  ↓
Delete or Lifecycle
```

### 기본 원칙

- Raw PE 장기 보관을 기본 전제로 하지 않음
- SHA-256을 영구 식별자로 사용
- 분석에 필요한 Feature 및 결과는 DB에 저장
- Raw PE 보존은 별도 정책으로 결정

---

## 4.2 Storage 후보

### Local Temporary Volume

장점:

- 구현 단순
- 로컬 개발 편리

단점:

- Main Server와 Worker가 분리되면 공유 어려움
- EC2 장애 시 파일 유실 가능

### Amazon S3

장점:

- Main Server / Worker에서 동일 파일 접근 가능
- Lifecycle 적용 가능
- 서버 분리 구조와 잘 맞음

단점:

- IAM 및 Storage 정책 필요

### 현재 권장 방향

```text
Local Development
→ Local Temporary Storage

AWS Deployment
→ Private S3 Temporary Storage
```

---

# 5. Batch / Multiple Input Architecture

## 5.1 기본 구조

```text
Batch Request
      ↓
batch_id 생성
      ↓
┌────────────┬────────────┬────────────┐
│ analysis A │ analysis B │ analysis C │
└─────┬──────┴─────┬──────┴─────┬──────┘
      ↓            ↓            ↓
 Individual Analysis Jobs
```

각 파일은 독립적으로 처리합니다.

---

## 5.2 Initial Triage

가능한 경우 초기 분석은 Batch 단위 최적화를 검토할 수 있습니다.

```text
Multiple PE
    ↓
Feature Extraction
    ↓
Batch Model Inference
    ↓
Individual JRR Result
```

---

## 5.3 Deep Analysis

JRR에서 `HIGH_RISK_UNCERTAIN`인 파일만 Deep Analysis 대상으로 전달합니다.

```text
100 Files
   ↓
Initial Triage
   ├─ AUTO_BENIGN
   ├─ AUTO_MALICIOUS
   └─ HIGH_RISK_UNCERTAIN
            ↓
       Deep Analysis Jobs
            ↓
          Queue
```

### Backpressure

다중 입력이 들어와도 Worker 처리 가능량 이상을 동시에 Speakeasy로 실행하지 않습니다.

Queue가 작업 대기열 역할을 담당합니다.

---

# 6. Polling Architecture

Frontend는 장시간 작업 완료를 기다리며 HTTP 연결을 유지하지 않습니다.

```text
Streamlit
    │
    ├─ POST Analysis
    │      ↓
    │   analysis_id
    │
    └─ GET /status 반복 조회
           ↓
    QUEUED / RUNNING /
    COMPLETED / FAILED
```

### 현재 방향

```text
Polling
```

WebSocket은 PoC 필수 범위에서 제외하고 향후 확장 가능합니다.

---

# 7. Web / REST API / MCP

## 7.1 Web

사람이 사용하는 Analyst UI.

```text
Streamlit
   ↓
FastAPI
```

---

## 7.2 REST API

외부 프로그램 및 Frontend가 사용하는 기본 서비스 인터페이스.

```text
Client
  ↓
FastAPI REST API
  ↓
TRUST-Triage Service Layer
```

REST API 구현은 Backend 영역입니다.

---

## 7.3 MCP

**담당: 최지원**

MCP는 AI Agent가 TRUST-Triage 기능을 Tool 형태로 사용할 수 있도록 하는 확장 인터페이스입니다.

```text
AI Agent
   ↓
MCP Server
   ↓
기존 FastAPI / Service Layer
   ↓
TRUST-Triage
```

### 예시 Tool

```text
analyze_sample
get_analysis_status
get_analysis_result
get_deep_analysis_result
get_final_assessment
```

### 상태

```text
Optional / M4 확장 범위
```

> MCP 때문에 기존 Backend나 분석 파이프라인을 복제하지 않습니다.

---

# 8. LLM Analyst Assist

## 역할

Deep Analysis 결과를 Analyst가 빠르게 이해할 수 있도록 요약합니다.

```text
CAPA
FLOSS
Speakeasy
MITRE Evidence
JRR Context
       ↓
     LLM
       ↓
Analyst Summary
```

### 외부 LLM API

프로젝트에서 사용하는 LLM API는 구현 시 환경변수 또는 AWS Secret 관리 방식으로 구성합니다.

```text
LLM_API_KEY
LLM_BASE_URL
LLM_MODEL
```

> API Key를 Repository에 Commit하지 않습니다.

---

# 9. AWS Deployment Architecture

## 9.1 Logical Target

```text
                          Internet / Client
                                 │
                    ┌────────────▼────────────┐
                    │       Main Server       │
                    │                        │
                    │ Streamlit              │
                    │ FastAPI                │
                    │ Initial Analysis       │
                    │ CAPA + FLOSS           │
                    │ MCP (Optional)         │
                    └────────────┬───────────┘
                                 │
                     ┌───────────┼──────────────┐
                     │           │              │
                     ▼           ▼              ▼
                PostgreSQL      S3          Task Queue
                                             (SQS?)
                                                │
                                                ▼
                                    ┌────────────────────┐
                                    │ Speakeasy Worker   │
                                    │       Server       │
                                    └──────────┬─────────┘
                                               │
                                               ├── S3
                                               └── PostgreSQL
```

---

# 10. 단일 서버 vs 분산 서버

## Option A. 단일 EC2

```text
EC2
├─ Streamlit
├─ FastAPI
├─ Initial Analysis
├─ CAPA/FLOSS
├─ Worker
├─ Speakeasy
└─ PostgreSQL(optional)
```

### 장점

- 구축 단순
- 비용 절감
- 빠른 PoC 가능

### 단점

- Speakeasy 부하가 API/UI에 영향
- 장애 영역 분리 어려움
- 확장성 낮음
- 분석 동시 실행 시 자원 경합 가능

---

## Option B. Main + Worker 분리

```text
Main Server
├─ Streamlit
├─ FastAPI
├─ Initial Analysis
└─ CAPA/FLOSS

        ↓ Queue

Worker Server
└─ Speakeasy

Shared
├─ PostgreSQL
└─ S3
```

### 장점

- 장시간 분석 부하 격리
- API 응답 안정성 향상
- Worker 확장 용이
- 역할 및 장애 영역 명확

### 단점

- AWS 구성 복잡도 증가
- IAM / Network / Storage 공유 설계 필요
- 비용 증가

---

## 현재 권장 방향

M4의 AWS 기반 서비스형 PoC에서는 다음 구조를 우선 권장합니다.

```text
Main EC2
+
Speakeasy Worker EC2
+
PostgreSQL
+
Private S3
+
Managed Task Queue
```

> **TBD**  
> 실제 AWS 예산·권한·교육 계정 제약을 확인한 뒤 최종 확정합니다.

---

# 11. Component Placement Matrix

| Component | Logical Role | 권장 실행 위치 | 담당 |
|---|---|---|---|
| Streamlit | Frontend | Main Server | 김정윤 |
| FastAPI | Backend/API | Main Server | 김건우 |
| PostgreSQL | State/Result DB | RDS 또는 DB Host | 김건우 / 이가영 |
| Feature Extraction | Initial Analysis | Main Server | 분석 모듈 |
| LightGBM/XGBoost | Initial Analysis | Main Server | 분석 모듈 |
| Calibration / JRR | Initial Analysis | Main Server | 분석 모듈 |
| SHAP | XAI | Main Server | 김정윤 |
| CAPA | Tier 1 Deep Analysis | Main Server 우선 | 이상욱 |
| FLOSS | Tier 1 Deep Analysis | Main Server 우선 | 이상욱 |
| Task Queue | Async Job Broker | AWS Managed 또는 별도 Queue | 이상욱 / 이가영 |
| Speakeasy Worker | Tier 2 Deep Analysis | Worker Server | 이상욱 |
| S3 | Temporary Raw PE Storage | AWS Managed | 이가영 |
| MCP Server | AI Agent Interface | Main Server 또는 별도 Process | 최지원 |
| System Integration | E2E 연결 | 전체 | 최지원 |

---

# 12. 데이터 흐름

## 12.1 AUTO_BENIGN / AUTO_MALICIOUS

```text
Raw PE
  ↓
FastAPI
  ↓
Initial Analysis
  ↓
JRR
  ↓
AUTO_BENIGN / AUTO_MALICIOUS
  ↓
PostgreSQL
  ↓
Frontend / API / MCP
```

---

## 12.2 HIGH_RISK_UNCERTAIN

```text
Raw PE
  ↓
FastAPI
  ↓
Initial Analysis
  ↓
JRR
  ↓
HIGH_RISK_UNCERTAIN
  ↓
CAPA + FLOSS
  ↓
[필요 시]
Task Queue
  ↓
Speakeasy Worker
  ↓
Evidence Normalization
  ↓
LLM Analyst Assist
  ↓
Final Assessment
  ↓
PostgreSQL
  ↓
Frontend / API / MCP
```

---

# 13. 상태 관리

분석 전체 상태는 DB에 저장합니다.

```text
QUEUED
  ↓
RUNNING
  ↓
COMPLETED
```

실패 시:

```text
FAILED
```

실행하지 않는 Deep Analysis Stage:

```text
NOT_REQUIRED
```

### Stage 예

```text
UPLOAD
INITIAL_ANALYSIS
JRR
CAPA
FLOSS
SPEAKEASY
LLM
FINAL_ASSESSMENT
```

Frontend는 현재 Stage와 Status를 Polling으로 조회합니다.

---

# 14. 장애 처리 원칙

## FastAPI 실패

- HTTP Error 반환
- DB에 가능한 범위까지 오류 Stage 기록

## CAPA / FLOSS 실패

- 해당 Tool Status = `FAILED`
- 전체 Deep Analysis를 무조건 중단할지 여부는 Tier 정책에 따라 결정

## Speakeasy 실패

- Worker에서 오류 저장
- Queue Retry 정책 적용
- 최대 Retry 초과 시 `FAILED`
- SQS 사용 시 DLQ 적용 검토

## LLM 실패

LLM은 Analyst Assist 계층이므로:

- 원본 Evidence는 유지
- LLM 실패가 기존 CAPA/Speakeasy Evidence를 삭제하지 않음

---

# 15. 보안 및 Secret 관리

다음 값은 Source Code에 직접 저장하지 않습니다.

```text
DB_PASSWORD
AWS_ACCESS_KEY
AWS_SECRET_ACCESS_KEY
LLM_API_KEY
기타 외부 API Credential
```

### 권장

Local:

```text
.env
```

AWS:

```text
IAM Role
AWS Secrets Manager / Parameter Store 검토
```

> `.env` 파일은 Git 추적 대상에서 제외합니다.

---

# 16. 역할 분담

## 김정윤 — Frontend

- Streamlit
- Backend 실데이터 연동
- Polling
- Batch UI
- SHAP / Evidence 분리 표시
- Service Architecture 문서 관리

## 김건우 — Backend / DB

- FastAPI
- REST API
- Raw PE 입력 처리
- Batch Job 관리
- PostgreSQL
- 분석 상태 관리

## 이상욱 — Deep Analysis / Task Queue

- CAPA
- FLOSS
- Speakeasy
- Task Queue
- Worker
- Deep Analysis 결과 연동

## 이가영 — AWS / Infrastructure

- AWS 전체 배포 구조
- EC2
- S3
- Queue AWS Resource
- IAM / Network / Secret
- PostgreSQL 배포 환경 협업

## 최지원 — System Integration

- 전체 E2E Integration
- 모듈 인터페이스 검증
- 대표 샘플 기반 통합 테스트
- MCP PoC

---

# 17. M4 End-to-End 완료 기준

최소 다음 흐름이 AWS 환경에서 실제로 동작해야 합니다.

## Case A — 자동 판정

```text
Raw PE Upload
→ Feature Extraction
→ LGBM/XGB
→ Calibration
→ Risk Signals
→ JRR
→ AUTO_BENIGN or AUTO_MALICIOUS
→ DB
→ Streamlit Result
```

## Case B — 심층분석

```text
Raw PE Upload
→ Initial Analysis
→ HIGH_RISK_UNCERTAIN
→ CAPA + FLOSS
→ Queue
→ Speakeasy Worker
→ Evidence
→ LLM Summary
→ Final Assessment
→ DB
→ Streamlit Result
```

---

# 18. 현재 TBD

M4 초기에 아래 사항을 최종 결정하고 본 문서를 업데이트합니다.

- [ ] **Task Queue 최종 선택** — AWS SQS / Redis + RQ
- [ ] **서버 구조 최종 결정** — 단일 / Main + Worker 분산
- [ ] **PostgreSQL 배포 방식** — RDS / EC2
- [ ] **S3 Raw PE 보존 기간 및 Lifecycle**
- [ ] **CAPA + FLOSS → Speakeasy 진입 기준**
- [ ] **Batch 최대 파일 수**
- [ ] **최대 파일 크기**
- [ ] **ZIP 입력 지원 여부**
- [ ] **MCP 구현 범위**
- [ ] **Final Assessment 로직**
- [ ] **AWS 네트워크 접근 범위**
- [ ] **Worker 동시 실행 수 / Backpressure 정책**

---

# 19. 문서 간 관계

```text
pipeline_architecture.md
│
│ "분석이 어떤 순서로 진행되는가?"
│
├──────────────────────────────┐
│                              │
▼                              ▼
service_architecture.md     interface_spec.md

"어디서 실행되는가?"        "무엇을 주고받는가?"
"서버가 어떻게 나뉘는가?"   "필드명/JSON/API는 무엇인가?"
```

---

# 20. 변경 관리

서비스 구조 변경 시 다음 순서로 반영합니다.

```text
1. 서비스 구조 결정
       ↓
2. service_architecture.md 수정
       ↓
3. interface_spec.md 영향 확인
       ↓
4. pipeline_architecture.md 영향 확인
       ↓
5. 담당 모듈 구현
       ↓
6. E2E Integration Test
```

> **Critical**  
> 서버 배치 또는 Queue/Storage 구조가 바뀌었다고 분석 로직 자체를 중복 구현하지 않습니다.

---

# 21. 변경 이력

| 날짜 | 버전 | 변경 내용 | 작성자 |
|---|---|---|---|
| 2026-09-07 | v1 | M4 서비스 통합을 위한 최초 서비스 아키텍처 정의 | 김정윤 |
