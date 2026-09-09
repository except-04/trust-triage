# TRUST-TRIAGE 파이프라인 아키텍처 문서

> **현재 구현 기준 (2026-09-09):** HTTP API와 PostgreSQL 저장 구조는 `trust_triage.backend_api` 구현을 기준으로 설명합니다. 공개 필드와 Endpoint는 [공통 인터페이스](interface_spec.md)와 [Backend OpenAPI](backend-api/openapi.json)를 따릅니다. 파일별 초기 판정, 시스템 최종 제안, 전문가 최종 판정은 서로 덮어쓰지 않고 별도로 보존합니다.

> 각 모듈의 입력과 출력이 바뀌면 이 문서와 실제 Schema를 함께 수정하고 팀에 공유합니다. 상세 파일 설명은 [백엔드 소스코드 구조](backend-api/backend-structure.md), API 사용법은 [API 종류와 설명](backend-api/api-reference.md)을 참고합니다.

---

## 0. 전체 흐름

API 서버는 요청을 접수하고, 별도 분석 처리기가 DB에서 작업을 가져가 실행합니다. 시간이 오래 걸리는 Speakeasy는 SQS와 별도 Worker로 분리합니다.

```text
[Streamlit / Swagger / 다른 클라이언트]
                    │ PE 파일 업로드
                    ▼
              [FastAPI app.py]
                    │
                    ▼
              [service.py]
                 ├──────────────→ [Local Storage / S3]
                 │                     원본 파일 저장
                 └──────────────→ [PostgreSQL]
                                       QUEUED 작업 등록
                                             │
                              별도 run 프로세스가 작업 조회
                                             ▼
                                      [processor.py]
                                             │
          ┌──────────────────────────────────┴──────────────────────────────────┐
          │                                                                     │
          ▼                                                                     ▼
[① Feature Extraction] → [② LightGBM / XGBoost] → [③ Calibration] → [④ Risk Signals]
                                             │
                                             ▼
                                 [⑤ JRR + ⑦ SHAP]
                                             │
                    ┌────────────────────────┴────────────────────────┐
                    │                                                 │
          FINAL / AUTO 경로                              DEEP_ANALYSIS 경로
                    │                                                 ▼
                    │                                      [⑥ CAPA + FLOSS]
                    │                                                 │ 근거 부족
                    │                                                 ▼
                    │                                      [SQS 작업 메시지]
                    │                                                 ▼
                    │                                      [Speakeasy Worker]
                    │                                                 │
                    │                              [Evidence 정규화 + 선택적 LLM 설명]
                    └────────────────────────┬────────────────────────┘
                                             ▼
                                  [Final Assessment]
                                             │
                                             ▼
                                  [PostgreSQL 결과 저장]
                                             │
                              API 상태 조회 / Dashboard Polling
                                             ▼
                                [필요하면 전문가 검토]
```

### 판정과 상태

- JRR의 `initial_verdict`는 `AUTO_BENIGN`, `AUTO_MALICIOUS`, `HIGH_RISK_UNCERTAIN` 중 하나입니다.
- `HIGH_RISK_UNCERTAIN`만 심층 분석 경로로 이동합니다.
- 시스템 `final_verdict`는 `BENIGN`, `MALICIOUS`, `UNCERTAIN` 중 하나입니다.
- 현재 Backend 정책에서 정상 자동 경로는 `AUTO_ALLOW_RECOMMENDED`, 악성·불확실·분석 실패는 전문가가 확인할 수 있도록 별도 disposition과 승인 상태를 남깁니다.
- 전체 작업 상태 `QUEUED/RUNNING/COMPLETED/FAILED`와 CAPA·FLOSS·Speakeasy 같은 도구별 상태는 구분합니다.
- Ghidra와 CAPE는 현재 자동 실행 경로에 포함하지 않습니다. 이후 확장하거나 전문가가 별도 환경에서 사용합니다.

### 현재 저장소 구현 구조

```text
trust-triage/
├─ requirements.txt                       전체 프로젝트 의존성
├─ requirements-backend.txt               API·PostgreSQL·S3 실행 의존성
├─ requirements-backend-analysis.txt      실제 초기 분석까지 실행할 때 추가 설치
├─ requirements-backend-dev.txt           Backend 테스트·Lint 개발 의존성
├─ .env.backend.example                   Backend 환경변수 예시
│
├─ src/trust_triage/backend_api/
│  ├─ app.py                               FastAPI Endpoint와 Swagger
│  ├─ schemas.py                           공개 요청·응답 형식
│  ├─ service.py                           접수·조회·검토 업무
│  ├─ processor.py                         DB 작업을 가져와 분석 단계 실행
│  ├─ initial_analysis.py                  Feature→모델→Calibration→JRR→SHAP
│  ├─ model_bundle.py                      모델 산출물 로딩·검증
│  ├─ deep_gateway.py                      별도 Deep Analysis 연결
│  ├─ repository.py                        PostgreSQL 읽기·쓰기
│  ├─ schema.sql                           Backend 테이블 정의
│  ├─ storage.py                           Local Storage·S3 파일 처리
│  ├─ views.py                             내부 결과를 공개 응답으로 변환
│  ├─ config.py                            환경변수 읽기·검증
│  ├─ runtime.py                           실제 구성요소 조립
│  ├─ api_docs.py                          Swagger 한국어 설명과 예시
│  └─ __main__.py                          init-db/check/serve/run 명령
│
├─ tests/backend_api/                      Backend 단위·통합 테스트
└─ docs/backend-api/                       구조·API·검증 문서
```

스크린샷에 보이는 requirements 파일의 용도는 다음과 같습니다.

| 파일 | 언제 사용하는가 |
|---|---|
| `requirements-backend.txt` | API 서버, PostgreSQL, Local/S3 저장 기능만 실행할 때 |
| `requirements-backend-analysis.txt` | 실제 모델·Feature 추출·SHAP까지 포함한 분석 처리기를 실행할 때 |
| `requirements-backend-dev.txt` | Backend 테스트와 Ruff 검사를 실행할 때 |
| `requirements.txt` | 저장소 전체 모듈을 한 환경에 설치할 때 |

각 파일은 목적이 다르므로 하나로 합치지 않습니다. Backend만 개발할 때는 전체 ML 의존성을 매번 설치하지 않아도 됩니다.

---

## 1. 표준 데이터 스키마

외부 모듈은 `file_id` 대신 `analysis_id`를 공통 식별자로 사용합니다. 아래는 `GET /analyses/{analysis_id}`에서 제공하는 종합 결과의 축약 예시입니다. 아직 실행되지 않은 단계는 `null` 또는 `NOT_REQUIRED`로 표시합니다.

```json
{
  "analysis_id": "a_20260909_000001",
  "batch_id": null,
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "filename": "sample.exe",
  "size_bytes": 245760,
  "status": "COMPLETED",
  "current_stage": "FINAL_ASSESSMENT",
  "prediction": {
    "lgbm_raw_probability": 0.72,
    "xgb_raw_probability": 0.64,
    "calibrated_probability": 0.68
  },
  "risk_signals": {
    "disagreement": 0.08,
    "ood_score": -0.03,
    "difficulty_score": 2.0
  },
  "initial_verdict": "HIGH_RISK_UNCERTAIN",
  "route": "DEEP_ANALYSIS",
  "reason": "추가 증거가 필요한 경로입니다.",
  "top_features": [
    {
      "feature_name": "section_entropy_max",
      "feature_value": 7.31,
      "shap_value": 0.047,
      "direction": "MALICIOUS"
    }
  ],
  "deep_analysis_status": {
    "capa": "COMPLETED",
    "floss": "COMPLETED",
    "speakeasy": "COMPLETED",
    "cape": "NOT_REQUIRED"
  },
  "evidence": [
    {
      "technique_id": "T1055",
      "technique_name": "Process Injection",
      "sources": ["CAPA", "SPEAKEASY"],
      "summary": "두 도구에서 관련 행위가 관찰되었습니다.",
      "evidence_ids": ["evt-0001", "evt-0002"]
    }
  ],
  "llm_summary": null,
  "final_verdict": "UNCERTAIN",
  "final_assessment": {
    "final_verdict": "UNCERTAIN",
    "disposition": "MANUAL_REVIEW",
    "requires_human_review": true,
    "reason": "심층 증거를 전문가가 확인해야 합니다.",
    "policy_version": "backend-review-first-v1"
  },
  "analyst_final_verdict": null,
  "approval_status": "PENDING",
  "review_revision": 0,
  "error": null,
  "created_at": "2026-09-09T01:00:00Z",
  "updated_at": "2026-09-09T01:02:00Z",
  "completed_at": "2026-09-09T01:02:00Z"
}
```

### 필드 구분

- `analysis_id`: 파일 분석 한 건을 끝까지 추적하는 식별자입니다.
- `batch_id`: 여러 파일을 한 번에 접수했을 때만 사용하는 묶음 식별자입니다.
- `status`: 전체 작업 상태입니다. `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`를 사용합니다.
- `current_stage`: 현재 또는 마지막 단계입니다. `UPLOAD`, `INITIAL_ANALYSIS`, `JRR`, `CAPA_FLOSS`, `SPEAKEASY`, `LLM`, `FINAL_ASSESSMENT`를 사용합니다.
- `initial_verdict`: 모델·Calibration·위험 신호·JRR이 만든 최초 판정입니다.
- `final_verdict`: Backend 정책이 제안한 시스템 최종 판정입니다.
- `analyst_final_verdict`: 전문가가 검토 후 입력한 판정입니다. 보류하거나 검토 전이면 `null`입니다.
- `approval_status`: 자동 정책 또는 전문가 검토 진행 상태입니다.
- `file_location`: Storage와 Worker 사이에서만 쓰는 내부 필드이므로 공개 API 응답에 포함하지 않습니다.

작업, 단계별 결과, 시스템 제안, 전문가 검토 이력은 PostgreSQL에 저장합니다. 원본 PE는 Local Storage 또는 S3에 보관하고 DB에는 내부 위치만 기록합니다.

---

## 2. 모듈별 상세 명세

### ① 특징 추출 모듈 — 담당: 이상욱

| 항목       | 내용                                                    |
| -------- | ----------------------------------------------------- |
| 입력       | PE 파일 바이너리 또는 SHA256 해시                               |
| 내부 처리    | EMBER2024 v3 기준 2568차원 PE 정적 특징 추출                    |
| 모델 입력 출력 | Top-500 Feature Selection이 적용된 500차원 특징 벡터            |
| 추가 출력    | SHA256, 파일 유형, .NET 여부, PEFormatWarnings 등            |
| 참고       | `feature_schema.md`, `top_feature_indices_500.npy` 기준 |

#### 구현 내용

* EMBER2024 v3 기준 PE 정적 특징 2568차원 추출
* Feature Schema 및 특징 순서 검증
* 모델팀 선정 Top-500 Feature Selection 적용
* SHA256, PE32/PE32+, .NET 여부 등 메타데이터 추출
* Import Table 기반 Registry / Injection / Network 관련 API 그룹 분석
* 비정상 PE 및 파싱 실패 예외 처리
* PEFormatWarnings 정보 제공

#### 모듈 간 전달 예시

```json
{
  "sha256": "8f31...a20c",
  "file_type": "PE32+",
  "is_dotnet": false,
  "status": "success",

  "feature_count": 500,
  "features": [0.0, 0.12],

  "pe_format_warnings": [],

  "api_groups": {
    "registry": [],
    "injection": [],
    "network": []
  }
}
```

> 2568차원 벡터는 내부 특징 추출 결과이며, Baseline 모델로 전달되는 공식 인터페이스는 Top-500 특징 벡터를 기준으로 합니다.

---

### ② Baseline 모델 — 담당: 김정윤

| 항목          | 내용                                                    |
| ----------- | ----------------------------------------------------- |
| 입력          | ①의 Top-500 특징 벡터                                      |
| 공식 Baseline | LightGBM                                              |
| 비교 모델       | XGBoost                                               |
| 출력          | `lgbm_raw_probability`, `xgb_raw_probability` |
| 모델 공유       | Google Drive의 `.pkl` 파일                               |
| 실험 관리       | MLflow                                                |

#### 모델 역할

**LightGBM**

* 공식 Baseline 모델
* Calibration 입력 확률 생성
* SHAP 설명 대상 모델

**XGBoost**

* LightGBM과의 Model Disagreement 계산용 비교 모델

#### 모델 파일

```text
baseline_model_lightgbm_tuned_500.pkl
→ 공식 Baseline
→ TPR@FPR 0.1% = 91.20%

baseline_model_xgb_500.pkl
→ Disagreement 계산용

baseline_model_500.pkl
→ 튜닝 전 LightGBM
→ 참고용 보관
```

#### Threshold

```text
LightGBM tuned threshold = 0.9834
```

Calibration 세트에서 목표 FPR 0.1% 기준으로 산출.

#### 특징 인덱스

```text
top_feature_indices_500.npy
```

LightGBM과 XGBoost 모두 동일한 Top-500 Feature Index 사용.

---

### ③ Calibration — 담당: 김건우

| 항목     | 내용                                   |
| ------ | ------------------------------------ |
| 입력     | LightGBM의 `lgbm_raw_probability` |
| 런타임 출력 | `calibrated_probability`             |
| 방법     | Isotonic Regression                  |
| 학습 산출물 | `jrr_calibrator.pkl`                 |

#### 구현 내용

* LightGBM 원시 확률에 Isotonic Regression 적용
* Calibration 세트를 이용해 확률 보정
* 목표 FPR 0.1% 기준 운영 Threshold 산출
* 학습된 calibrator와 관련 설정을 `jrr_calibrator.pkl`로 저장
* Calibration 관련 평가 메트릭 MLflow 기록

> `jrr_calibrator.pkl`은 학습 산출물이며, 후속 모듈에 전달되는 런타임 데이터는 `calibrated_probability`입니다.

---

### ④ 다중 위험 신호 계산 — 담당: 김건우

| 위험 신호                  | 의미                      | 기준 / 출처              |
| ---------------------- | ----------------------- | -------------------- |
| Calibrated Probability | 보정된 악성 확률               | Isotonic Calibration |
| Model Disagreement     | LightGBM과 XGBoost 예측 차이 | LightGBM vs XGBoost  |
| OOD Score              | 학습 데이터 분포와의 이탈 정도       | Isolation Forest     |
| Analysis Difficulty    | PE 구조상 분석 난이도           | PEFormatWarnings     |

#### 런타임 출력

```json
{
  "calibrated_probability": 0.61,

  "risk_signals": {
    "disagreement": 0.14,
    "ood_score": 0.82,
    "difficulty_score": 0.35
  }
}
```

#### 구현 내용

* Isolation Forest 기반 OOD Score 산출
* 학습 데이터 10만 개 샘플링을 이용한 OOD 기준 모델 학습
* Top-500 특징 내 PEFormatWarnings 관련 특징을 동적으로 추적
* PEFormatWarnings 기반 Analysis Difficulty 산출
* LightGBM과 XGBoost의 예측 결과를 이용해 Disagreement 계산

#### 학습 산출물

```text
jrr_risk_signals.pkl
```

포함 내용:

* Isolation Forest
* Analysis Difficulty 계산에 필요한 feature mapping 정보

> Disagreement는 별도의 학습 모델이 아니라 추론 시 LightGBM과 XGBoost의 출력값을 이용해 동적으로 계산합니다.

---

### ⑤ Joint Risk Router / Initial Triage — 담당: 김건우

| 항목 | 내용 |
|---|---|
| 입력 | `calibrated_probability` + `disagreement` + `ood_score` + `difficulty_score` |
| 출력 | `initial_verdict`, `route`, `reason` |
| Initial Verdict | `AUTO_BENIGN`, `AUTO_MALICIOUS`, `HIGH_RISK_UNCERTAIN` |
| 후속 처리 | `HIGH_RISK_UNCERTAIN`이면 Deep Analysis, 나머지는 Final Assessment |

#### 입력 예시

```json
{
  "calibrated_probability": 0.61,
  "risk_signals": {
    "disagreement": 0.14,
    "ood_score": -0.03,
    "difficulty_score": 6.0
  }
}
```

#### 출력 예시

```json
{
  "initial_verdict": "HIGH_RISK_UNCERTAIN",
  "route": "DEEP_ANALYSIS",
  "reason": "High analysis difficulty detected."
}
```

#### 라우팅 의미

```text
AUTO_BENIGN
→ route=FINAL
→ 정상 자동 처리 제안

AUTO_MALICIOUS
→ route=FINAL
→ 악성 경보 제안과 전문가 검토 상태 생성

HIGH_RISK_UNCERTAIN
→ route=DEEP_ANALYSIS
→ CAPA·FLOSS와 필요 시 Speakeasy 수행
```

JRR은 `risk_score`라는 합산 점수를 새로 만들지 않습니다. 각 위험 신호의 원값과 판정 이유를 함께 저장하므로 화면에서도 개별 신호를 확인할 수 있습니다.

---

### ⑥ 심층분석 모듈 — 담당: 이상욱

| 항목 | 내용 |
|---|---|
| 입력 | `HIGH_RISK_UNCERTAIN`으로 라우팅된 원본 PE의 내부 위치와 SHA-256 |
| Tier 1 | CAPA + FLOSS |
| Tier 2 | AWS SQS → 별도 Speakeasy Worker |
| 선택 단계 | 정규화된 Evidence에 대한 LLM 요약 |
| 출력 | 도구별 상태, MITRE ATT&CK Evidence, 오류와 신뢰도 정보 |
| 확장 | CAPE와 Ghidra는 현재 자동 파이프라인 밖에서 검토 |

### 단계별 흐름

```text
HIGH_RISK_UNCERTAIN
        │
        ▼
CAPA + FLOSS
        │
        ├─ 근거가 충분함 ───────────────┐
        │                               │
        └─ 근거가 부족함                │
                  ▼                     │
          SQS에 작은 작업 메시지 전송    │
                  ▼                     │
          Speakeasy Worker              │
                  │                     │
                  └─────────────┬───────┘
                                ▼
                    Evidence 정규화·통합
                                │
                       선택적 LLM 설명
                                │
                                ▼
                   Backend Final Assessment
```

SQS 메시지에는 원본 파일을 넣지 않습니다. `analysis_id`, `sha256`, 내부 `file_location`, `requested_stage`, `requested_at`만 전달합니다. Worker는 S3에서 파일을 내려받고 SHA-256을 다시 확인한 뒤 Speakeasy를 실행합니다.

Backend의 `deep_gateway.py`는 별도 Deep Analysis 서비스를 호출하고 상태를 가져오는 연결부입니다. 실제 CAPA·FLOSS 서비스와 Speakeasy Worker는 Backend API 서버와 분리해 실행하며, PostgreSQL의 동일한 `analysis_id`를 기준으로 이어서 처리합니다.

### Evidence 표준화

도구 결과는 원본 로그를 그대로 판정값으로 쓰지 않고 공통 Evidence로 변환합니다. 내부 Evidence는 출처, 심각도, 신뢰도, 요약, 도구 상태를 보존합니다. 공개 API에서는 같은 ATT&CK Technique의 증거를 다음처럼 묶어서 제공합니다.

```json
{
  "technique_id": "T1055",
  "technique_name": "Process Injection",
  "sources": ["CAPA", "SPEAKEASY"],
  "summary": "관련 행위가 두 도구에서 관찰되었습니다.",
  "evidence_ids": ["evt-0001", "evt-0002"]
}
```

분석 실패나 Timeout은 악성 증거로 바꾸지 않습니다. 도구별 `status`와 상세 `tool_status`를 따로 남겨 부분 성공과 실패를 구분합니다.

### 공개 API 축약 예시

```json
{
  "status": "COMPLETED",
  "deep_analysis_status": {
    "capa": "COMPLETED",
    "floss": "COMPLETED",
    "speakeasy": "NOT_REQUIRED",
    "cape": "NOT_REQUIRED"
  },
  "tool_details": {
    "capa": {"tool_status": "SUCCESS"},
    "floss": {"tool_status": "SUCCESS"}
  },
  "evidence": [
    {
      "technique_id": "T1055",
      "technique_name": "Process Injection",
      "sources": ["CAPA"],
      "summary": "CAPA 규칙에서 관련 기법이 관찰되었습니다.",
      "evidence_ids": ["evt-0001"]
    }
  ],
  "llm_summary": null,
  "error": null
}
```

### Analyst Review

```text
Backend Final Assessment
        │
        ├─ 자동 정상 정책 → AUTO_POLICY
        │
        └─ 악성·불확실·분석 실패 → PENDING
                                      │
                                      ▼
                              전문가 증거 확인
                                      │
                                      ▼
                         APPROVED 또는 MODIFIED
```

전문가 의견은 초기 판정이나 시스템 제안을 덮어쓰지 않고 별도 검토 이력으로 추가합니다.

---

### ⑦ SHAP 설명 — 담당: 김정윤 / 김건우·이가영

| 항목 | 내용 |
|---|---|
| 입력 | LightGBM 모델 + Top-500 특징 벡터 |
| 출력 | `top_features` |
| 설명 대상 | 보정 확률이 아닌 LightGBM 원출력 |
| 표시 개수 | 기본 상위 5개, 서버 설정으로 변경 가능 |

#### 출력 예시

```json
{
  "top_features": [
    {
      "feature_name": "imports_entropy",
      "feature_value": 5.41,
      "shap_value": 0.092,
      "direction": "MALICIOUS"
    },
    {
      "feature_name": "section_entropy_max",
      "feature_value": 7.31,
      "shap_value": 0.047,
      "direction": "MALICIOUS"
    }
  ]
}
```

```text
SHAP Top Feature
→ 정적 모델 출력에 어떤 Feature가 영향을 주었는지 설명

MITRE ATT&CK Evidence
→ CAPA·FLOSS·Speakeasy에서 실제로 관찰한 분석 증거 설명
```

두 정보는 목적이 다르므로 API와 Dashboard에서도 별도 영역으로 제공합니다. SHAP 실패는 전체 분석 실패로 바꾸지 않고 `xai_status`와 `xai_error`로 기록합니다.

---

### ⑧ API / Dashboard / DB

| 항목 | 현재 구조 |
|---|---|
| API | FastAPI |
| 분석 실행 | API 서버와 분리된 Backend Processor |
| Dashboard | Streamlit이 REST API를 호출하고 상태를 Polling |
| 상태·결과 DB | PostgreSQL |
| 원본 파일 저장 | 로컬 임시 저장소 또는 Amazon S3 |
| 비동기 동적 분석 | AWS SQS + Speakeasy Worker |
| API 명세 | OpenAPI / Swagger |
| 모델 실험 | MLflow |

### FastAPI와 분석 처리기

```text
HTTP 요청                         별도 분석 프로세스
   │                                      │
   ▼                                      ▼
app.py                               __main__.py run
   ▼                                      ▼
service.py                           processor.py
   │                                      │
   └────────────── PostgreSQL ────────────┘
      접수·조회·검토       분석할 작업·중간 결과·최종 결과
```

FastAPI는 파일을 받고 작업을 등록한 뒤 `202 Accepted`를 반환합니다. 요청 Handler에서 모델이나 Speakeasy가 끝날 때까지 기다리지 않습니다. 별도 `run` 프로세스가 PostgreSQL에서 처리할 작업을 가져와 초기 분석과 필요한 심층 분석을 이어갑니다.

주요 공개 기능은 다음과 같습니다.

- 단일·일괄 파일 접수
- 전체 목록, 종합 결과, 상태, 초기 판정, SHAP, 심층 분석 결과 조회
- 전문가 판정 또는 보류 의견 등록
- 전문가 검토 이력 조회
- `/docs`의 한국어 Swagger 안내와 실행 예시

정확한 Endpoint와 JSON 형식은 [API 종류와 설명](backend-api/api-reference.md)을 기준으로 합니다.

### Streamlit Dashboard

Dashboard는 Backend API만 호출하고 DB나 분석 도구를 직접 실행하지 않습니다.

```text
분석 목록 / 파일 정보 / SHA-256
        │
        ├─ 전체 상태와 현재 단계
        ├─ 모델 확률과 Calibration
        ├─ Disagreement / OOD / Difficulty
        ├─ Initial Verdict와 JRR 이유
        ├─ SHAP Top Features
        ├─ CAPA / FLOSS / Speakeasy 상태와 Evidence
        ├─ 시스템 Final Assessment
        └─ 전문가 검토 상태와 이력
```

### PostgreSQL

PostgreSQL을 분석 상태의 기준 저장소로 사용합니다.

| 테이블 | 역할 |
|---|---|
| `api_batches` | 접수 요청, 일괄 요청, Idempotency 정보 |
| `api_analyses` | 파일별 식별자, 단계, 초기·심층·최종 결과와 내부 저장 위치 |
| `api_reviews` | 전문가 판정, 메모, 검토자, revision 이력 |

API 서버나 분석 처리기가 재시작되어도 DB의 단계와 lease를 기준으로 이어서 처리합니다. 전문가 검토는 기존 판정값을 수정하는 방식이 아니라 `api_reviews`에 새 이력으로 저장합니다.

### Storage, SQS, AWS

```text
FastAPI / Processor ──→ S3 원본 저장
Processor ────────────→ SQS 작업 등록
SQS ──────────────────→ 격리된 Speakeasy Worker
Worker ───────────────→ PostgreSQL 결과 저장
```

로컬 개발에서는 Local Storage를 사용할 수 있습니다. 실제 분산 실행에서는 Backend, Deep Analysis, Worker가 같은 S3 객체와 PostgreSQL 작업을 보도록 설정합니다. SQS 메시지는 원본 PE나 큰 결과 JSON을 담지 않고 내부 위치와 식별자만 전달합니다.

AWS의 실제 S3·SQS·DB 주소와 IAM 역할은 환경변수와 서버 권한으로 주입하며 Git에 저장하지 않습니다. 설정 항목은 루트의 [.env.backend.example](../.env.backend.example)을 참고합니다.

### MLflow와 모델 산출물

MLflow는 모델 실험과 성능 지표를 관리합니다. Backend에서 실제 초기 분석을 실행할 때는 검증된 LightGBM, XGBoost, Calibrator, Risk Signals, Top Feature Index, Selection Manifest 경로가 모두 필요합니다. 산출물은 Git에 포함하지 않습니다.

---

## 3. 다음 확인 사항

- [x] FastAPI 공개 Endpoint와 요청·응답 Schema 구현
- [x] PostgreSQL 작업·결과·전문가 검토 Schema 구현
- [x] Local Storage와 S3 저장 Adapter 구현
- [x] API 서버와 분석 처리기 프로세스 분리
- [ ] 팀에서 검증한 모델 산출물 6개의 실제 경로와 버전 확정
- [ ] Deep Analysis 서비스와 Speakeasy Worker 브랜치 통합 검증
- [ ] 실제 PostgreSQL·S3·SQS·IAM 연결 정보로 개발 환경 검증
- [ ] Streamlit을 Mock 데이터에서 Backend API 호출로 전환
- [ ] Final Assessment와 전문가 승인 정책을 팀에서 최종 확정
- [ ] CAPE 도입 여부는 MVP 이후 확장 범위로 검토

---

## 4. 변경 이력

| 날짜         | 변경 내용                                               | 작성자 |
| ---------- | --------------------------------------------------- | --- |
| 2026-08-06 | 최초 작성 (뼈대)                                          | 김정윤 |
| 2026-08-22 | JRR, 위험 신호, Tiered Deep Analysis, 판정 이력 및 서비스 구조 반영 | 김정윤 |
| 2026-09-09 | Backend API, PostgreSQL, S3, SQS Worker, 실제 파일·의존성 구조 반영 | 이상욱 |
