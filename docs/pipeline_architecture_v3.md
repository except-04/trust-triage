# TRUST-Triage 파이프라인 아키텍처 문서 v3

> TRUST-Triage의 **분석 파이프라인 흐름과 모듈 간 책임 경계**를 정의합니다.
>
> 서비스 배치 구조는 `service_architecture.md`, 세부 데이터 계약은 `interface_spec.md`를 기준으로 합니다.
>
> **담당자는 본인 파트의 실제 구현이 변경될 경우 관련 문서를 함께 업데이트합니다.**
>
> 초기 ML 판정, 심층분석 기반 시스템 판정, 분석가 최종 판정은 서로 덮어쓰지 않고 별도 단계로 보존합니다.

---

# 🚨 Critical

## CRITICAL-01. Eval 결과를 이용해 Threshold를 다시 조정하지 않는다

Threshold 및 라우팅 정책은 **Calibration 세트에서 결정 후 고정**하고, Eval에서는 고정된 정책의 성능만 측정합니다.

현재 주요 운영 기준:

```text
tau_low        = 0.65
tau_high       = 0.983645
tau_disagree   = 0.30
tau_difficulty = 5
OOD condition  = ood_score < 0
```

---

## CRITICAL-02. OOD와 Model Disagreement를 동일한 개념으로 취급하지 않는다

```text
Model Disagreement
= abs(LightGBM probability - XGBoost probability)

OOD Score
= Isolation Forest decision_function
```

- Disagreement: 두 모델의 예측 차이
- OOD: 학습 분포와의 이탈 신호

두 신호는 서로 다른 위험 신호이며 각각 독립된 필드로 관리합니다.

---

## CRITICAL-03. JRR은 Priority-ordered Rule-based Router로 정의한다

현재 JRR은 임의의 가중합 `risk_score`를 계산하는 방식이 아니라,  
고정된 Threshold 조건을 **정해진 우선순위대로 순차 평가하는 Priority-ordered Rule-based 3-Way Router**입니다.

현재 우선순위:

```text
1. OOD
2. Model Disagreement
3. Analysis Difficulty
4. Calibrated Probability Gray Zone
5. High Malicious Confidence
6. High Benign Confidence
```

따라서 `risk_score`는 필수 런타임 출력으로 간주하지 않습니다.

---

## CRITICAL-04. SHAP과 Behavioral Evidence를 분리한다

- SHAP → LightGBM 모델 판정 근거
- CAPA / FLOSS / Speakeasy / MITRE ATT&CK → 분석·행위 근거

두 근거는 저장 및 UI 표현에서 구분합니다.

---

## CRITICAL-05. Raw PE는 자동 분석 대상이지만 장기 저장을 기본 전제로 하지 않는다

Raw PE는 분석 과정에서 임시 저장하며, 장기 보관 여부는 별도 보안·스토리지 정책에 따릅니다.

Queue에는 Raw PE 자체가 아니라 `analysis_id`, `sha256`, `file_location` 등 참조 정보만 전달합니다.

---

# 0. 전체 분석 흐름

```text
[Raw PE 입력]
      │
      ▼
[① 입력 처리 / 식별]
      │
      ├─ analysis_id 생성
      ├─ SHA-256 계산
      └─ Raw PE 임시 저장
      │
      ▼
[② EMBER2024 v3 특징 추출]
      │
      ├─ 2568차원 원본 특징
      ├─ 고정 Top-500 특징 선택
      ├─ 파일 메타데이터
      └─ PEFormatWarnings
      │
      ▼
[③ Baseline Inference]
      │
      ├─ LightGBM
      │    └─ lgbm_raw_probability
      │
      └─ XGBoost
           └─ xgb_raw_probability
      │
      ├───────────────────────────────┐
      ▼                               │
[④ Isotonic Calibration]             │
      │                               │
      └─ calibrated_probability       │
      │                               │
      ▼                               │
[⑤ Risk Signal Computation]           │
      │                               │
      ├─ calibrated_probability       │
      ├─ disagreement ◀───────────────┘
      ├─ ood_score
      └─ difficulty_score
      │
      ▼
[⑥ JRR / Initial Triage]
      │
      ├─ AUTO_BENIGN ──────────────┐
      │                            │
      ├─ AUTO_MALICIOUS ───────────┤
      │                            │
      └─ HIGH_RISK_UNCERTAIN       │
               │                   │
               ▼                   │
      [⑧ Deep Analysis]            │
               │                   │
               ├─ Tier 1           │
               │   ├─ CAPA         │
               │   └─ FLOSS        │
               │                   │
               └─ 필요 시 Tier 2   │
                   └─ Speakeasy    │
               │                   │
               ▼                   │
      [⑨ Evidence Normalization]   │
               │                   │
               └─ MITRE ATT&CK     │
               │                   │
               ▼                   │
      [⑩ LLM Analyst Assist]       │
               │                   │
               ▼                   │
      [⑪ Final Assessment]         │
               │                   │
               ├─ BENIGN           │
               ├─ MALICIOUS        │
               └─ UNCERTAIN        │
                      │             │
                      ▼             │
              [Analyst Review]     │
                      │             │
                      └─ 필요 시    │
                         Ghidra     │
                                    │
[⑦ SHAP / XAI]                      │
      ▲                             │
      └─ LightGBM + Top-500         │
                                    ▼
                         [결과 저장 / API / UI]

Optional Extension:
- CAPE 직접 구축 또는 외부 Behavioral Report 연동
- MCP 기반 AI Agent Interface
```

---

# 1. 판정 단계

TRUST-Triage의 판정은 아래 3단계로 분리합니다.

## 1.1 Initial Verdict

JRR의 초기 판정:

```text
AUTO_BENIGN
AUTO_MALICIOUS
HIGH_RISK_UNCERTAIN
```

- `AUTO_BENIGN` → 자동 초기 판정 완료
- `AUTO_MALICIOUS` → 자동 초기 판정 완료
- `HIGH_RISK_UNCERTAIN` → Deep Analysis 진입

---

## 1.2 Final Verdict

심층분석이 수행된 경우 자동화 시스템이 산출하는 최종 판정:

```text
BENIGN
MALICIOUS
UNCERTAIN
```

> `final_verdict`의 정확한 자동 판정 로직은 Final Assessment 구현 시 확정합니다.

---

## 1.3 Analyst Final Verdict

자동 파이프라인에서도 결론이 충분하지 않을 경우 분석가가 최종 검토합니다.

```text
BENIGN
MALICIOUS
```

필요 시 향후 `UNRESOLVED` 상태 추가를 검토할 수 있습니다.

---

# 2. 표준 결과 객체

세부 필드 정의는 `interface_spec.md`를 기준으로 하며, 파이프라인 수준에서는 아래 구조를 사용합니다.

```json
{
  "analysis_id": "string",
  "batch_id": null,
  "sha256": "string",

  "prediction": {
    "lgbm_raw_probability": 0.0,
    "xgb_raw_probability": 0.0,
    "calibrated_probability": 0.0
  },

  "risk_signals": {
    "disagreement": 0.0,
    "ood_score": 0.0,
    "difficulty_score": 0
  },

  "initial_verdict": "AUTO_BENIGN | AUTO_MALICIOUS | HIGH_RISK_UNCERTAIN",
  "route": "FINAL | DEEP_ANALYSIS",
  "reason": "string",

  "top_features": [],

  "deep_analysis_status": {
    "capa": "QUEUED | RUNNING | COMPLETED | FAILED | NOT_REQUIRED",
    "floss": "QUEUED | RUNNING | COMPLETED | FAILED | NOT_REQUIRED",
    "speakeasy": "QUEUED | RUNNING | COMPLETED | FAILED | NOT_REQUIRED",
    "cape": "QUEUED | RUNNING | COMPLETED | FAILED | NOT_REQUIRED"
  },

  "evidence": [],
  "llm_summary": null,

  "final_verdict": "BENIGN | MALICIOUS | UNCERTAIN | null",
  "analyst_final_verdict": "BENIGN | MALICIOUS | null",

  "created_at": "ISO8601",
  "completed_at": null
}
```

> **Critical**  
> `initial_verdict`, `final_verdict`, `analyst_final_verdict`는 서로 다른 판정 단계이며 기존 값을 덮어쓰지 않습니다.

---

# 3. 모듈별 상세 명세

## ① 입력 처리 / 파일 식별

| 항목 | 내용 |
|---|---|
| 기본 입력 | Raw PE |
| 다중 입력 | Batch / Multiple File 지원 범위 구현 |
| 생성값 | `analysis_id`, `batch_id`, `sha256` |
| 파일 저장 | Local Temporary Storage 또는 S3 |
| 중복 식별 | SHA-256 기반 |

### 처리 흐름

```text
Raw PE Upload
    ↓
analysis_id 생성
    ↓
SHA-256 계산
    ↓
임시 저장
    ↓
특징 추출
```

Batch 요청의 경우 **파일마다 개별 `analysis_id`**를 생성하고 상위 그룹에 `batch_id`를 부여합니다.

---

# ② 특징 추출 모듈

| 항목 | 내용 |
|---|---|
| 입력 | Raw PE |
| 내부 특징 | EMBER2024 v3 2568차원 |
| 공식 모델 입력 | 고정 Top-500 특징 벡터 |
| 추가 출력 | 파일 메타데이터, PEFormatWarnings |
| 기준 | `feature_schema.md`, `top_feature_indices_500.npy` |

### 구현 원칙

- EMBER2024 v3 기준 특징 추출
- Top-500 Feature Set은 기존 TRUST-Triage 입력 계약으로 고정
- 새 4-Way 재학습 과정에서 Top-500을 재선택하지 않음
- PEFormatWarnings는 Analysis Difficulty 계산에 사용

---

# ③ Baseline 모델

## LightGBM

역할:

- 공식 Baseline
- Calibration 입력 생성
- SHAP 설명 대상

현재 4-Way 모델:

```text
models/baseline_model_lightgbm_tuned_500_4way.pkl
```

Validation 기준:

```text
TPR@FPR0.1% ≈ 92.49%
Best iteration = 998
```

> 위 수치는 Validation 기반 모델 선택 결과이며 Eval 최종 성능과 구분합니다.

---

## XGBoost

역할:

- LightGBM과의 Model Disagreement 계산용 비교 모델

현재 모델:

```text
baseline_model_xgb_500_4way_1000cap.pkl
```

특징:

```text
n_estimators = 1000
best_iteration = 999
Validation AUC ≈ 0.99712
```

> 1000 iteration ceiling에서 종료되었으며 완전 수렴 모델로 해석하지 않습니다.

---

# ④ Calibration

| 항목 | 내용 |
|---|---|
| 입력 | `lgbm_raw_probability` |
| 방법 | Isotonic Regression |
| 출력 | `calibrated_probability` |
| 산출물 | `jrr_calibrator.pkl` |

현재 운영 기준:

```text
tau_high = 0.983645
```

Calibration에서 FPR ≤ 0.1% 조건으로 선택한 Threshold입니다.

> Eval에서는 해당 Threshold를 재조정하지 않습니다.

---

# ⑤ Risk Signal Computation

## Calibrated Probability

LightGBM 원시 확률에 Isotonic Calibration을 적용한 값.

---

## Model Disagreement

```text
disagreement = abs(
    lgbm_raw_probability
    - xgb_raw_probability
)
```

현재 기준:

```text
tau_disagree = 0.30
```

---

## OOD Score

Isolation Forest의 `decision_function` 결과를 사용합니다.

학습:

- `X_tr`에서만 학습
- Top-500 Feature 사용
- X_tr에서 seed 42로 무작위 100,000개 샘플 사용
- Eval 데이터는 Isolation Forest 학습에 사용하지 않음

현재 기준:

```text
ood_score < 0
→ OOD 위험 신호 Trigger
```

> **Critical**  
> OOD로 판별된 샘플이 HIGH_RISK로 라우팅되는 것은 **라우팅 동작 검증**이며, 그 자체가 OOD 탐지 정확도 100%를 의미하지 않습니다.

---

## Analysis Difficulty

PEFormatWarnings 관련 Top-500 특징을 기반으로 계산합니다.

현재 기준:

```text
tau_difficulty = 5
```

`tau_difficulty=5`는 Calibration에서 후보 Threshold별 심층분석 유입량과 운영 Trade-off를 비교해 선택 후 고정합니다.

---

# ⑥ Joint Risk Router / Initial Triage

## 입력

```text
p_calib (= calibrated_probability)
disagreement
ood_score
difficulty_score
```

## 현재 운영 Threshold

```text
tau_low        = 0.65
tau_high       = 0.983645
tau_disagree   = 0.30
tau_difficulty = 5
tau_ood        = 0
```

## JRR 구조

JRR은 현재 **Priority-ordered Rule-based 3-Way Router**입니다.

각 조건을 위에서부터 `if / elif` 방식으로 순차 평가하며,  
**가장 먼저 만족한 규칙이 해당 샘플의 `initial_verdict`와 대표 `reason`을 결정합니다.**

```text
1. IF ood_score < tau_ood
      → HIGH_RISK_UNCERTAIN
      → reason: OOD Detected

2. ELIF disagreement >= tau_disagree
      → HIGH_RISK_UNCERTAIN
      → reason: High Model Disagreement

3. ELIF difficulty_score >= tau_difficulty
      → HIGH_RISK_UNCERTAIN
      → reason: High Analysis Difficulty

4. ELIF tau_low < p_calib < tau_high
      → HIGH_RISK_UNCERTAIN
      → reason: Uncertain Probability

5. ELIF p_calib >= tau_high
      → AUTO_MALICIOUS
      → reason: High Malicious Confidence

6. ELSE
      → AUTO_BENIGN
      → reason: High Benign Confidence
```

### 실제 구현 형태

```python
if ood_score < self.tau_ood:
    decision = "HIGH_RISK_UNCERTAIN"
    reason = f"OOD Detected (Score: {ood_score:.4f})"

elif disagreement >= self.tau_disagree:
    decision = "HIGH_RISK_UNCERTAIN"
    reason = f"High Model Disagreement ({disagreement:.4f})"

elif difficulty_score >= self.tau_difficulty:
    decision = "HIGH_RISK_UNCERTAIN"
    reason = f"High Analysis Difficulty (Score: {difficulty_score:.1f})"

elif self.tau_low < p_calib < self.tau_high:
    decision = "HIGH_RISK_UNCERTAIN"
    reason = f"Uncertain Probability ({p_calib:.4f})"

elif p_calib >= self.tau_high:
    decision = "AUTO_MALICIOUS"
    reason = f"High Malicious Confidence ({p_calib:.4f})"

else:
    decision = "AUTO_BENIGN"
    reason = f"High Benign Confidence ({p_calib:.4f})"
```

## `Uncertain Probability` 표현

`Uncertain Probability`는 별도의 확률값 또는 별도 모델 출력이 아닙니다.

```text
p_calib
= calibrated_probability
```

이며,

```text
tau_low < p_calib < tau_high
```

인 **Calibrated Probability Gray Zone**에 들어온 경우 사용하는 라우팅 사유(`reason`) 표현입니다.

따라서 공식 런타임 필드명은 계속:

```text
calibrated_probability
```

를 사용합니다.

> **Critical**  
> `calibrated_probability` 필드를 `uncertain_probability`로 변경하지 않습니다.  
> `Uncertain Probability`는 Gray Zone에 대한 설명용 Reason Label입니다.

## 우선순위와 Reason 기록

현재 구현은 `if / elif` 구조이므로 하나의 샘플이 여러 위험 조건을 동시에 만족하더라도  
**가장 먼저 매칭된 규칙 하나가 대표 `reason`으로 기록됩니다.**

예:

```text
OOD 조건 충족
+ disagreement >= 0.30
+ difficulty_score >= 5
```

인 샘플은 첫 번째 OOD 규칙에서 라우팅이 종료되므로:

```text
initial_verdict = HIGH_RISK_UNCERTAIN
reason = OOD Detected
```

로 기록됩니다.

이는 실제로 다른 위험 신호가 존재하지 않는다는 의미가 아니라  
**JRR의 대표 라우팅 사유가 우선순위상 OOD였다는 의미**입니다.

필요한 경우 향후 `triggered_signals` 배열을 추가하여 동시에 충족된 모든 위험 신호를 별도 보존할 수 있습니다.

## Route

```text
AUTO_BENIGN
→ route = FINAL

AUTO_MALICIOUS
→ route = FINAL

HIGH_RISK_UNCERTAIN
→ route = DEEP_ANALYSIS
```

> **Critical**  
> 현재 공식 JRR에 임의 가중치를 적용한 Weighted Risk Score는 사용하지 않습니다.

---

## Eval 평가 원칙

Calibration에서 모든 Threshold를 확정한 뒤 Eval에는 고정 적용합니다.

현재 주요 Eval 결과:

```text
ROC-AUC ≈ 0.9978
TPR      ≈ 89.11%
FPR      ≈ 0.12%
```

정확한 표현:

> Calibration에서 FPR ≤ 0.1% 조건으로 확정한 `tau_high=0.983645`를 고정 적용한 결과 Eval TPR 89.11%, FPR 0.12%를 기록하였다.

---

# ⑦ SHAP / XAI

| 항목 | 내용 |
|---|---|
| 대상 모델 | LightGBM |
| 입력 | LightGBM + Top-500 Feature |
| 방법 | TreeExplainer |
| 출력 | `top_features` |
| 목적 | 모델 판정의 주요 특징 및 방향 제공 |

### 출력 예시

```json
{
  "top_features": [
    {
      "feature_name": "feature_102",
      "feature_value": 1.34,
      "shap_value": 0.281,
      "direction": "MALICIOUS"
    }
  ]
}
```

> **Critical**  
> SHAP은 **Raw LightGBM 모델 출력의 근거**를 설명합니다.  
> 보정된 확률(`calibrated_probability`)을 SHAP이 직접 설명하는 것으로 표현하지 않습니다.

---

# ⑧ Deep Analysis

대상:

```text
initial_verdict == HIGH_RISK_UNCERTAIN
```

## Tier 1 — CAPA + FLOSS

두 도구를 정적 심층분석의 1차 Evidence 수집 단계로 사용합니다.

### CAPA

주요 역할:

- Capability 탐지
- Rule 기반 정적 Evidence
- MITRE ATT&CK 연계 정보

### FLOSS

주요 역할:

- Static Strings
- Stack Strings
- Tight Strings
- Decoded Strings

> FLOSS 문자열 자체를 악성 판정으로 사용하지 않고 분석 Evidence로 활용합니다.

---

## Tier 2 — Speakeasy

Tier 1만으로 충분하지 않은 경우 Speakeasy 에뮬레이션을 수행합니다.

주요 Evidence:

- Process
- API Call
- File
- Registry
- Network 관련 행위

Speakeasy는 장시간 실행될 수 있으므로 서비스 단계에서는 **비동기 Task Queue + Worker** 구조로 실행합니다.

---

## Optional Tier — CAPE / External Behavioral Report

CAPE는 현재 Core PoC 필수 모듈로 두지 않습니다.

가능한 확장:

- CAPE 환경 직접 구축
- 외부에서 생성된 CAPE Behavioral Report 연동/파싱

Ghidra는 자동 파이프라인에서 제외하고 Analyst Review용 수동 도구로 유지합니다.

---

# ⑨ MITRE ATT&CK Evidence Normalization

도구별 결과를 MITRE ATT&CK Technique 단위로 정규화합니다.

```json
{
  "technique_id": "T1055",
  "technique_name": "Process Injection",
  "sources": ["CAPA", "SPEAKEASY"],
  "summary": "..."
}
```

Evidence Source 예:

```text
CAPA
FLOSS
SPEAKEASY
CAPE_REPORT
```

> FLOSS가 직접 MITRE Technique을 제공하지 않는 경우 LLM/후처리 단계에서 임의 확정하지 않고 원본 문자열 Evidence로 별도 보존합니다.

---

# ⑩ LLM Analyst Assist

LLM은 심층분석 Evidence를 분석가가 빠르게 확인할 수 있도록 요약·해석하는 보조 계층입니다.

## 입력

- Initial Verdict
- Risk Signals
- CAPA
- FLOSS
- Speakeasy
- MITRE ATT&CK Evidence
- 필요한 경우 SHAP 요약

## 출력

- 주요 분석 요약
- 의심 행위 정리
- Analyst Notes

> **Critical**
> LLM이 Raw PE를 직접 분석하도록 보내지 않습니다.
>
> LLM Summary는 CAPA/Speakeasy 등의 원본 Evidence를 대체하지 않습니다.

---

# ⑪ Final Assessment

Deep Analysis와 정규화 Evidence를 기반으로 최종 자동화 판정을 생성합니다.

예정 출력:

```json
{
  "final_verdict": "BENIGN | MALICIOUS | UNCERTAIN",
  "evidence": [],
  "llm_summary": {}
}
```

> Final Assessment의 정확한 자동 판정 규칙은 서비스 통합 단계에서 확정합니다.

---

# ⑫ Analyst Review

자동화 파이프라인에서 최종 판단이 충분하지 않은 경우 Analyst Review 대상으로 전달합니다.

```text
UNCERTAIN
    ↓
Analyst Review
    ↓
필요 시 Ghidra 수동 분석
    ↓
analyst_final_verdict
```

분석가의 최종 판정은 기존 `initial_verdict` 및 `final_verdict`를 덮어쓰지 않습니다.

---

# 4. 서비스 계층과의 연결

본 문서는 분석 파이프라인 자체를 정의합니다.

실제 서비스에서는 아래 구조를 통해 실행됩니다.

```text
Streamlit
   ↓
FastAPI
   ↓
TRUST-Triage Analysis Pipeline
   ↓
PostgreSQL

HIGH_RISK_UNCERTAIN
   ↓
CAPA + FLOSS
   ↓
Task Queue
   ↓
Speakeasy Worker
   ↓
PostgreSQL

Raw PE
   ↕
Temporary Storage / S3
```

세부 서버 배치 및 AWS 구성은:

```text
service_architecture.md
```

세부 JSON/API/Queue 데이터 계약은:

```text
interface_spec.md
```

를 기준으로 합니다.

---

# 5. API / Web / MCP 관계

분석 엔진은 하나만 유지합니다.

```text
                 ┌─ Streamlit Web
                 │
Client ──────────┼─ REST API
                 │
AI Agent ────────┴─ MCP
                        │
                        ▼
                 동일 Backend /
                 Analysis Pipeline
```

> **Critical**
> Web, REST API, MCP를 위해 별도의 분석 파이프라인을 각각 구현하지 않습니다.

---

# 6. 현재 확인 / 결정 필요 사항

- [ ] CAPA + FLOSS → Speakeasy Tier 진입 조건 최종 확정
- [ ] Final Assessment 자동 판정 규칙 확정
- [ ] `final_verdict` Enum 최종 확정
- [ ] Task Queue 최종 선택: Redis + RQ / AWS SQS
- [ ] 단일 / 분산 서버 배치 구조 확정
- [ ] Raw PE 임시 저장 위치 및 삭제/Lifecycle 정책 확정
- [ ] Batch 최대 파일 수 및 파일 크기 제한 확정
- [ ] PostgreSQL 배포 방식 확정
- [ ] MCP 구현 범위 확정
- [ ] End-to-End 통합 후 Lockbox 실행 전 전체 Pipeline Freeze

---

# 7. 모델 평가 Protocol

현재 모델 평가 구조:

```text
Train
Weeks 0–33
   ↓
Validation
Weeks 34–39
   ↓
Calibration
Weeks 40–45
   ↓
Eval
Weeks 46–51
   ↓
Lockbox / Challenge
Final One-Time Evaluation
```

## 역할

### Train

모델 학습.

### Validation

- Hyperparameter tuning
- Early stopping
- Model selection

### Calibration

- Isotonic Calibration
- 운영 Threshold 선택
- JRR routing policy 선택

### Eval

- 고정된 모델/Threshold/정책 성능 평가
- 재튜닝 금지

### Lockbox

전체 Pipeline과 정책을 Freeze한 후 **최종 1회 평가**에만 사용합니다.

---

# 8. 변경 이력

| 날짜 | 버전 | 변경 내용 | 작성자 |
|---|---|---|---|
| 2026-08-06 | v1 | 최초 작성 | 김정윤 |
| 2026-08-22 | v2 | JRR, 위험 신호, Tiered Deep Analysis, 판정 이력 및 서비스 구조 반영 | 김정윤 |
| 2026-09-07 | v3 | 4-Way 평가 Protocol, Priority-ordered Rule-based JRR, JRR Reason/Gray Zone 표현, Isolation Forest OOD, Difficulty Threshold, CAPA+FLOSS, Speakeasy Worker, LLM Analyst Assist 및 M4 서비스 통합 구조 반영 | 김정윤 |
