# TRUST-EDR 파이프라인 아키텍처 문서

> 각 모듈의 입출력(인터페이스)을 정의합니다.
>
> **담당자는 본인 파트의 출력 형식을 실제 구현에 맞춰 확정·수정해주세요.**
>
> 여기 정의된 형식이 변경되는 경우 이 문서를 우선 업데이트하고 팀 전체에 공유합니다.
>
> 초기 ML 판정, 심층분석 판정, 분석가 판정은 각각 별도의 단계로 관리하며 판정 이력은 DB에 보존합니다.

---

## 0. 전체 흐름

```text
[파일/해시 입력]
        │
        ▼
[① 특징 추출 모듈] ───────────────── 담당: 이상욱
        │
        │ 출력
        │ - 500차원 모델 입력 특징 벡터
        │ - 파일 메타데이터
        │ - PEFormatWarnings
        ▼
[② Baseline 모델] ─────────────────── 담당: 김정윤
        │
        │ - LightGBM → 공식 Baseline
        │ - XGBoost  → Disagreement 비교 모델
        │
        │ 출력
        │ - lightgbm_raw_probability
        │ - xgboost_raw_probability
        ▼
[③ Calibration] ───────────────────── 담당: 김건우
        │
        │ LightGBM 확률 보정
        │ 출력: calibrated_probability
        ▼
[④ 위험 신호 계산] ────────────────── 담당: 김건우
        │
        │ - Calibrated Probability
        │ - Model Disagreement
        │ - OOD Score
        │ - Analysis Difficulty
        ▼
[⑤ Joint Risk Router / Initial Triage] ─ 담당: 이가영
        │
        │ 출력
        │ - initial_verdict
        │ - risk_score
        │
        ├── AUTO_BENIGN ─────────────────────┐
        │                                     │
        ├── AUTO_MALICIOUS ──────────────────┤
        │                                     │
        └── HIGH_RISK_UNCERTAIN               │
                    │                         │
                    ▼                         │
             [⑥ Deep Analysis]               │
                    │                         │
                    ├─ Tier 1: CAPA           │
                    │       │                 │
                    │       └─ 근거 부족      │
                    │              ▼          │
                    ├─ Tier 2: Speakeasy      │
                    │       │                 │
                    │       └─ 근거 부족/실패 │
                    │              ▼          │
                    └─ Tier 3: CAPE           │
                           (필요 시)           │
                    │                         │
                    ▼                         │
          [MITRE ATT&CK Evidence 정규화]      │
                    │                         │
                    ▼                         │
             [Final Assessment]               │
                    │                         │
                    ├─ BENIGN ────────────────┤
                    ├─ MALICIOUS ─────────────┤
                    │                         │
                    └─ 판정 불가              │
                          ▼                   │
                 [Analyst Review Queue]       │
                          │                   │
                          └─ Ghidra 수동 분석 │
                                              │
[⑦ SHAP 설명]                                 │
  ▲                                           │
  └── LightGBM + 500차원 특징 벡터           │
                                              ▼
                              [⑧ API / Dashboard / DB]
```

### 판정 단계

* `Initial Verdict`

  * `AUTO_BENIGN`
  * `AUTO_MALICIOUS`
  * `HIGH_RISK_UNCERTAIN`

* `HIGH_RISK_UNCERTAIN`인 경우에만 자동 심층분석 수행

* 심층분석 후 `Final Verdict`

  * `BENIGN`
  * `MALICIOUS`
  * 판정 불가 시 `Analyst Review Queue`

* Ghidra는 자동 파이프라인에서 제외하고 분석가 요청 또는 검토 단계에서 수동 분석 도구로 사용

---

## 1. 표준 데이터 스키마

파이프라인 전체에서 사용하는 공통 결과 객체는 아래 형식을 기준으로 각 모듈이 필요한 필드를 채워나가는 구조로 정의합니다.

```json
{
  "file_id": "string",
  "sha256": "string",

  "model_outputs": {
    "lightgbm_raw_probability": 0.0,
    "xgboost_raw_probability": 0.0
  },

  "calibrated_probability": 0.0,

  "risk_signals": {
    "disagreement": 0.0,
    "ood_score": 0.0,
    "difficulty_score": 0.0
  },

  "risk_score": 0.0,

  "initial_verdict": "AUTO_BENIGN | AUTO_MALICIOUS | HIGH_RISK_UNCERTAIN",

  "route": "COMPLETE | DEEP_ANALYSIS | ANALYST_REVIEW",

  "top_features": [
    {
      "name": "string",
      "contribution": 0.0,
      "direction": "BENIGN | MALICIOUS"
    }
  ],

  "deep_analysis_status": {
    "capa": "COMPLETE | NOT_REQUIRED | FAILED",
    "speakeasy": "COMPLETE | NOT_REQUIRED | FAILED",
    "cape": "COMPLETE | NOT_REQUIRED | PENDING | FAILED"
  },

  "evidence": [
    {
      "technique_id": "T1055",
      "name": "Process Injection",
      "source": "CAPA",
      "confidence": "HIGH | MEDIUM | LOW"
    }
  ],

  "final_risk_score": null,

  "final_verdict": "BENIGN | MALICIOUS | null",

  "analyst_review_required": false,

  "review_status": "N/A | PENDING | IN_PROGRESS | COMPLETE",

  "analyst_final_verdict": "BENIGN | MALICIOUS | null",

  "created_at": "ISO8601"
}
```

### 필드 구분

* `initial_verdict`

  * ML + 위험 신호 + JRR 기반 최초 판정

* `final_verdict`

  * 심층분석이 수행된 경우 CAPA/Speakeasy/CAPE 결과를 반영한 자동화 시스템의 최종 판정

* `analyst_final_verdict`

  * 자동화 파이프라인에서도 결론이 나지 않아 분석가가 직접 검토한 경우의 판정

판정 변경 이력은 SQLite에 별도로 저장하며 대시보드에 전체 이력을 표시하는 것은 필수 요구사항으로 두지 않습니다.

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
| 출력          | `lightgbm_raw_probability`, `xgboost_raw_probability` |
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
| 입력     | LightGBM의 `lightgbm_raw_probability` |
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

### ⑤ Joint Risk Router / Initial Triage — 담당: 이가영

| 항목              | 내용                                                                           |
| --------------- | ---------------------------------------------------------------------------- |
| 입력              | `calibrated_probability` + `disagreement` + `ood_score` + `difficulty_score` |
| 출력              | `risk_score`, `initial_verdict`, `route`                                     |
| Initial Verdict | `AUTO_BENIGN`, `AUTO_MALICIOUS`, `HIGH_RISK_UNCERTAIN`                       |
| 후속 처리           | `HIGH_RISK_UNCERTAIN`인 경우 Deep Analysis 수행                                   |

#### 입력 예시

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

#### 출력 예시

```json
{
  "risk_score": 0.78,
  "initial_verdict": "HIGH_RISK_UNCERTAIN",
  "route": "DEEP_ANALYSIS"
}
```

#### 라우팅 의미

```text
AUTO_BENIGN
→ 자동화 종료

AUTO_MALICIOUS
→ 자동화 종료

HIGH_RISK_UNCERTAIN
→ Deep Analysis 진입
```

> Risk Score 계산식, 신호별 가중치 및 최종 Threshold는 JRR 구현 결과에 맞춰 담당자가 확정합니다.

---

### ⑥ 심층분석 모듈 — 담당: 이상욱

| 항목     | 내용                                                   |
| ------ | ---------------------------------------------------- |
| 입력     | `HIGH_RISK_UNCERTAIN`으로 라우팅된 원본 PE 파일                |
| Tier 1 | CAPA                                                 |
| Tier 2 | Speakeasy                                            |
| Tier 3 | CAPE                                                 |
| 출력     | 분석 단계 상태, MITRE ATT&CK Evidence, Final Verdict 판단 정보 |
| Ghidra | 자동화 제외, Analyst Review 시 수동 분석                       |

### Tiered Deep Analysis

```text
HIGH_RISK_UNCERTAIN
        │
        ▼
Tier 1 — CAPA
        │
        ├─ 충분한 악성 근거 확보 → 결과 통합
        │
        └─ 근거 부족
               ▼
Tier 2 — Speakeasy
        │
        ├─ 충분한 근거 확보 → 결과 통합
        │
        └─ 근거 부족 / 분석 실패
               ▼
Tier 3 — CAPE
        │
        ▼
분석 결과 통합
```

### 현재 구현 우선순위

```text
CAPA + Speakeasy 중심 구현
```

CAPE는 VM 구축 비용과 프로젝트 일정을 고려해 확장 단계로 유지합니다.

직접 CAPE 환경을 구축하지 못하는 경우 외부에서 확보한 CAPE Behavioral Analysis 결과를 파싱하여 활용하는 방안도 검토합니다.

### Evidence 표준화

도구별 원본 결과를 그대로 제공하는 것이 아니라 MITRE ATT&CK Technique 기준으로 정규화합니다.

예:

```json
{
  "technique_id": "T1055",
  "name": "Process Injection",
  "source": "CAPA",
  "confidence": "HIGH"
}
```

### 출력 예시

```json
{
  "deep_analysis_status": {
    "capa": "COMPLETE",
    "speakeasy": "COMPLETE",
    "cape": "NOT_REQUIRED"
  },

  "evidence": [
    {
      "technique_id": "T1055",
      "name": "Process Injection",
      "source": "CAPA",
      "confidence": "HIGH"
    },
    {
      "technique_id": "T1059",
      "name": "Command and Scripting Interpreter",
      "source": "Speakeasy",
      "confidence": "MEDIUM"
    }
  ],

  "final_risk_score": 0.87,
  "final_verdict": "MALICIOUS",
  "analyst_review_required": false
}
```

### Analyst Review

자동 심층분석을 완료했음에도 판정 근거가 충분하지 않은 경우:

```text
Analyst Review Queue
        ↓
분석가 직접 검토
        ↓
필요 시 Ghidra 수동 분석
```

---

### ⑦ SHAP 설명 — 담당: 김정윤 / 김건우·이가영

| 항목    | 내용                           |
| ----- | ---------------------------- |
| 입력    | LightGBM 모델 + Top-500 특징 벡터  |
| 출력    | `top_features`               |
| 목적    | LightGBM이 해당 판정을 내린 주요 특징 제공 |
| 표시 개수 | 상위 5개 기준                     |

#### 출력 예시

```json
{
  "top_features": [
    {
      "name": "imports_entropy",
      "contribution": 0.092,
      "direction": "MALICIOUS"
    },
    {
      "name": "section_entropy_max",
      "contribution": 0.047,
      "direction": "MALICIOUS"
    }
  ]
}
```

### 역할 구분

```text
SHAP
→ ML 모델이 왜 해당 예측을 했는지 설명

MITRE ATT&CK Evidence
→ 심층분석 도구에서 확인된 보안 행위 정보 제공
```

두 정보는 서로 다른 목적으로 대시보드에 제공합니다.

---

### ⑧ API / Dashboard / DB — 담당: 최지원

| 항목        | 내용             |
| --------- | -------------- |
| 입력        | 전체 파이프라인 결과 객체 |
| API       | FastAPI        |
| Dashboard | Streamlit      |
| DB        | SQLite         |
| 배포 환경     | AWS            |
| 모델 파일 공유  | Google Drive   |
| 실험 관리     | MLflow         |

### FastAPI

* 파일 분석 요청 수신
* 파이프라인 실행
* 분석 결과 REST API 반환
* Streamlit과 분석 모듈 간 연계

### Streamlit Dashboard

화면에는 다음 정보를 제공합니다.

```text
파일 정보 / SHA256

Initial ML Triage
- Calibrated Probability
- Initial Verdict

Risk Signals
- Model Disagreement
- OOD Score
- Analysis Difficulty

XAI
- SHAP Top Features

고위험 불확실 파일인 경우
- Deep Analysis 진행 상태
- CAPA 결과
- Speakeasy 결과
- 필요 시 CAPE 결과
- MITRE ATT&CK Evidence

Final Assessment
- Final Risk Score
- Final Verdict
- Analyst Review Required
```

판정 변경 이력 전체는 대시보드에 표시하지 않고 DB에 저장합니다.

### SQLite

주요 저장 대상:

* 파일 ID / SHA256
* 모델 예측 결과
* 위험 신호
* Initial Verdict
* Deep Analysis 실행 상태 및 결과
* Final Verdict
* Analyst Review 상태
* Analyst Final Verdict
* 판정 변경 이력

Analyst Review가 필요한 파일은 SQLite 기반 Review Queue에 저장합니다.

### AWS

FastAPI, Streamlit 및 필요한 서비스 컴포넌트를 AWS 환경에 배포하는 것을 목표로 합니다.

### MLflow

* 모델 실험 관리
* 성능 Metric 기록
* LightGBM 튜닝 이력
* Calibration 실험 이력

현재 각 팀원의 로컬 환경에서 운영하며, 필요 시 향후 공용 MLflow 서버 도입을 검토합니다.

### Google Drive

현재 모델 `.pkl` 파일 및 관련 산출물 공유 용도로 사용합니다.

---

## 3. 다음 확인 사항

* [ ] JRR Risk Score 계산 방식 및 Threshold 확정
* [ ] CAPA → Speakeasy 다음 Tier 진입 기준 확정
* [ ] CAPA / Speakeasy 결과의 MITRE ATT&CK 정규화 방식 확정
* [ ] CAPE 직접 구축 여부 및 외부 Behavioral Report 활용 여부 결정
* [ ] SQLite 판정 이력 및 Analyst Review Queue Schema 확정
* [ ] SHAP Top Feature 표시 방식 확정
* [ ] FastAPI / Streamlit 간 API Contract 확정
* [ ] AWS 배포 구조 확정

---

## 4. 변경 이력

| 날짜         | 변경 내용                                               | 작성자 |
| ---------- | --------------------------------------------------- | --- |
| 2026-08-06 | 최초 작성 (뼈대)                                          | 김정윤 |
| 2026-08-22 | JRR, 위험 신호, Tiered Deep Analysis, 판정 이력 및 서비스 구조 반영 | 김정윤 |
