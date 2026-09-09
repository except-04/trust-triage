# Joint Risk Router (JRR) — Final Design & Evaluation

> 이 문서는 **현재 리포지토리에 실제로 구현되어 있는 코드**를 최우선 근거로 작성되었습니다. 설계 문서(`docs/pipeline_architecture.md`)나 과거 커밋에만 존재하고 코드로 아직 구현되지 않은 부분은 반드시 "설계상" / "미통합"으로 구분해 표기했습니다. 실제 코드와 설계 문서가 다른 지점은 본문에서 명시하고, 이 문서 맨 끝의 채팅 답변(불일치 목록)에서 다시 요약합니다.

---

## 1. Overview

### JRR의 목적

JRR(Joint Risk Router)은 "모델 확률이 얼마인가"만으로 자동 판정하지 않고, **보정된 확률 + 추가 위험 신호**를 근거로 파일을 세 갈래(`AUTO_BENIGN` / `AUTO_MALICIOUS` / `HIGH_RISK_UNCERTAIN`)로 나누는 **규칙 기반 라우터**입니다. 목적은 "이 파일이 악성인가"를 최종 판정하는 것이 아니라, **어떤 파일에 심층분석·분석가 자원을 투입할지 결정**하는 것입니다.

### TRUST-Triage 파이프라인에서의 위치

`docs/pipeline_architecture.md` 기준 전체 흐름 중 ③~⑤ 구간을 담당합니다.

```
Raw PE
  → Feature Extraction (EMBER2024 v3, Top-500 선택)
  → LightGBM (공식 Baseline) / XGBoost (Disagreement 비교 모델)
  → Calibration (Isotonic Regression, LightGBM raw prob → calibrated_probability)
  → Risk Signals (Disagreement / OOD / Analysis Difficulty)
  → JRR (jrr_router.py::JointRiskRouter)
  → AUTO_BENIGN / AUTO_MALICIOUS / HIGH_RISK_UNCERTAIN
```

> **중요:** 위 다이어그램의 "Risk Signals → JRR" 화살표는 설계 의도를 나타냅니다. **현재 `src/jrr/jrr_router.py`에 실제로 연결되어 있는 신호는 `calibrated_probability`와 `disagreement` 두 가지뿐**이며, OOD Score와 Analysis Difficulty는 별도 파이프라인(`src/jrr/risk_signals.py`)에서 컴포넌트만 생성되고 라우터 입력으로는 아직 연결되어 있지 않습니다. 자세한 내용은 2장, 4장 참고.

### 단순 malware classifier와의 차이

단순 classifier는 확률 하나로 이분(또는 threshold 하나로 삼분) 판정을 내립니다. JRR은 (1) 확률을 그대로 쓰지 않고 Isotonic Calibration을 거친 값을 쓰고, (2) 모델 간 불일치(Disagreement)처럼 "확률 자체는 안전해 보여도 실제로는 불확실한" 상황을 별도로 탐지해 자동판정에서 배제합니다.

### 자동 판정과 심층분석 대상 분리 목적

FPR 0.1% 같은 강한 방어선을 지키면서도(=오탐을 최소화), 그레이존/불일치 샘플을 놓치지 않기 위해 "확신 있는 구간만 자동화하고 나머지는 심층분석/분석가에게 넘긴다"는 보수적 전략을 취합니다.

---

## 2. JRR Inputs

`docs/pipeline_architecture.md` 및 `docs/확률보정_위험신호.md`가 정의하는 4대 위험 신호는 다음과 같습니다. 신호별로 **"현재 `jrr_router.py`에서 실제로 사용되는지"를 명시**합니다.

### Calibrated Probability — **라우터에서 사용 중**

- **의미**: LightGBM이 내놓는 원시 확률(`lightgbm_raw_probability`)은 과신(over-confident)되어 있어 실제 정답률과 어긋납니다. 이를 실제 신뢰도로 보정한 값입니다.
- **산출 방식**: `src/jrr/train_calibrator.py` — `sklearn.isotonic.IsotonicRegression(out_of_bounds="clip")`을 Calibration 세트(`X_calib`/`y_calib`)에 학습된 LightGBM(`baseline_model_lightgbm_tuned_500_4way.pkl`)의 raw 확률에 대해 fit. 결과 calibrator는 `jrr_calibrator_4way.pkl`(`{'model':..., 'threshold':...}`)로 저장.
- **JRR에서 사용 방향**: 값이 낮을수록 정상, 높을수록 악성. `tau_low`/`tau_high` 두 경계값으로 3구간(정상/그레이존/악성) 판정에 사용.
- **Threshold**: `tau_low = 0.60`, `tau_high = 0.983645` (3장 참고).

### Model Disagreement — **라우터에서 사용 중**

- **의미**: LightGBM과 XGBoost 두 모델의 예측이 얼마나 다른지. **"분산"이 아니라 두 원시 확률의 절대 차이**입니다.
- **산출 방식**: `JointRiskRouter.compute_disagreement()` (`src/jrr/jrr_router.py:14-16`)
  ```python
  def compute_disagreement(self, p_lgb: float, p_xgb: float) -> float:
      return abs(p_lgb - p_xgb)
  ```
  배치 재현용 스크립트는 `src/jrr/disagreement.py`(`np.abs(p_lgb - p_xgb)`, 동일 정의).
- **JRR에서 사용 방향**: 값이 클수록(두 모델이 서로 동의하지 않을수록) 위험 — 확률이 아무리 확신에 차 보여도 `HIGH_RISK_UNCERTAIN`으로 격상.
- **Threshold**: `tau_disagree = 0.3` (고정값, 3장 참고).

### OOD (Out-of-Distribution) Score — **컴포넌트만 존재, 라우터 미통합**

- **의미**: 학습 데이터 분포와 얼마나 동떨어져 있는지(신종/변종 의심도).
- **산출 방식(설계·구현된 부분)**: `src/jrr/risk_signals.py` — 학습 데이터(`data/X_tr.npy`)에서 최대 10만 개를 mmap 샘플링(`sample_size = min(100000, len(X_tr_raw))`)하고 Top-500 인덱스로 슬라이싱한 뒤, `sklearn.ensemble.IsolationForest(n_estimators=200, contamination="auto", random_state=42, n_jobs=-1)`을 학습해 `data/jrr_risk_signals.pkl`에 저장.
- **`decision_function` 사용 여부**: 리포지토리 전체를 검색한 결과 **`decision_function()`(또는 `score_samples()`)을 호출해 실제 `ood_score` 스칼라를 산출하는 코드는 현재 존재하지 않습니다.** 즉 IsolationForest 모델 객체는 학습·저장되어 있지만, 이를 이용해 개별 파일의 OOD 점수를 계산하는 함수/엔드포인트가 아직 구현되지 않았습니다.
- **JRR에서 어떤 조건에서 OOD로 판단하는지**: `jrr_router.py`의 `route_sample()`은 OOD 관련 파라미터를 아예 받지 않으므로 **현재 라우팅 판정에 OOD가 전혀 관여하지 않습니다.**
- **Threshold**: 없음(미구현). `dashboard/app.py`의 `is_ood_detected()`가 `ood_score < 0`을 OOD 판정 기준으로 쓰지만, 이는 **대시보드 목업(mock) 데이터에 대한 표시 로직**이며(`mock_triage_profile()`에서 하드코딩된 예시 값 `0.084`, `0.072`, `-0.031`을 사용), 실제 IsolationForest 출력과 연결되어 있지 않습니다.

### Analysis Difficulty — **컴포넌트만 존재, 라우터 미통합**

- **의미**: 악성도 점수가 아니라 **"이 PE 파일을 정적으로 분석/파싱하기가 얼마나 어려운가/구조가 얼마나 비정상인가"**를 나타내는 신호입니다.
- **산출 방식(설계·구현된 부분)**: `feature_schema.md`가 정의하는 `PEFormatWarnings` 블록(원본 인덱스 2480–2568, pefile 파싱 경고 87종 + 총 경고 개수)이 Top-500 선택 이후 몇 번째 인덱스로 이동했는지를 `src/jrr/risk_signals.py`가 동적으로 추적합니다.
  ```python
  raw_start, raw_end = 2480, 2568
  difficulty_indices_in_top500 = np.where((top_500_idx >= raw_start) & (top_500_idx < raw_end))[0]
  ```
  결과 인덱스 배열은 `data/jrr_risk_signals.pkl`의 `difficulty_indices` 키에 저장됩니다. 정확한 인덱스 개수는 실행 시점의 `top_feature_indices_500.npy`에 의해 동적으로 결정되며, 리포지토리에서 정적으로 확인할 수 없어 **확인 필요**로 표기합니다.
- **Top-500 안에서의 사용**: 위 인덱스들이 가리키는 Top-500 벡터의 서브셋 값(경고 발생 여부/개수)을 이용해 난이도 점수를 만드는 것이 의도이지만, **이 인덱스들로부터 실제 스칼라 `difficulty_score`를 계산하는 함수는 리포지토리에 존재하지 않습니다.**
- **JRR에서 사용 방향 / Threshold**: 없음(미구현). `jrr_router.py`는 difficulty 관련 파라미터를 받지 않습니다. `dashboard/app.py`의 `difficulty_label()`(`<=3` Low, `<=6` Medium, 그 외 High)도 목업 값(`2`, `3`, `6`)에만 적용되는 표시 로직입니다.

---

## 3. Final Thresholds

`src/jrr/jrr_router.py::JointRiskRouter.__init__`의 기본값을 그대로 인용합니다.

| Signal | Threshold | Role | 선정 출처 |
|---|---|---|---|
| `calibrated_probability` (상한) | `tau_high = 0.983645` | 이 값 이상이면 `AUTO_MALICIOUS` | **Calibration 세트**에서 목표 FPR ≤ 0.1%를 만족하는 마지막 ROC 지점의 threshold (`train_calibrator.py`, `TARGET_FPR = 0.001`). 고정 운영 상수로 라우터에 하드코딩됨(커밋 `207d346`). |
| `calibrated_probability` (하한) | `tau_low = 0.60` | 이 값 이하면 `AUTO_BENIGN` | **Calibration 세트**에서 `optimize_threshold.py::optimize_lower_bound()`가 Review Yield 극대화(동률 시 악성 누락 최소화) 기준으로 후보 `[0.10, 0.20, ..., 0.80]` 중 선택. 고정 운영 상수로 라우터에 하드코딩됨(커밋 `f6a0094`/`bf08142`, `jrr_router.py` 주석: "Calibration 최적화 확정: 0.60"). |
| `disagreement` | `tau_disagree = 0.3` | 이 값 이상이면 `HIGH_RISK_UNCERTAIN`으로 격상 | **고정 운영 상수**. 리포지토리 내에서 이 값이 Calibration 데이터로부터 최적화되었다는 코드/로그는 확인되지 않음 — **선정 근거 문서 확인 필요** (`disagreement.py`는 `> 0.2`/`> 0.5` 구간 통계만 출력할 뿐, 0.3 선택 근거는 아님). |
| `ood_score` | 없음(미구현) | — | 라우터 미통합 (2장 참고) — **확인 필요** |
| `difficulty_score` | 없음(미구현) | — | 라우터 미통합 (2장 참고) — **확인 필요** |

> Eval 결과를 보고 위 threshold를 재조정한 사실은 리포지토리 어디에도 없습니다. 정책(`docs_eval_lockbox_policy.md` §2)도 "threshold는 calibration 세트에서만 산출, eval 세트에는 적용만"으로 이를 명시적으로 금지합니다.

---

## 4. Routing Logic

`JointRiskRouter`는 **가중합(Weighted Risk Score) 방식이 아니라, 우선순위가 있는 규칙 기반(Priority-ordered Rule-based) 3-Way 라우터**입니다. `route_sample()`(`src/jrr/jrr_router.py:18-50`)의 실제 if/elif 순서를 그대로 옮기면 다음과 같습니다.

| 순서 | 조건 | 결과 | reason 예시 |
|---|---|---|---|
| 0 | `p_calib`가 NaN 또는 `disagreement`가 NaN | `HIGH_RISK_UNCERTAIN` | `System Error: NaN values detected (Fail-Closed)` |
| 1 | `disagreement >= tau_disagree` | `HIGH_RISK_UNCERTAIN` | `High Model Disagreement (0.xxxx)` |
| 2 | `tau_low < p_calib < tau_high` | `HIGH_RISK_UNCERTAIN` | `Uncertain Probability (0.xxxx)` |
| 3 | `p_calib >= tau_high` | `AUTO_MALICIOUS` | `High Malicious Confidence (0.xxxx)` |
| 4 (else) | 그 외 (`p_calib <= tau_low`) | `AUTO_BENIGN` | `High Benign Confidence (0.xxxx)` |

경계값을 명시하면:

- `p_calib <= tau_low` → `AUTO_BENIGN` (단, 위 0/1번 조건에 걸리지 않았을 때)
- `tau_low < p_calib < tau_high` → `HIGH_RISK_UNCERTAIN` (그레이존)
- `p_calib >= tau_high` → `AUTO_MALICIOUS` (단, 위 0/1번 조건에 걸리지 않았을 때)

**우선순위가 실제 판정을 뒤집는 예**: `p_calib`가 0.999처럼 `tau_high`를 훨씬 넘더라도, `disagreement >= 0.3`이면 1번 규칙이 먼저 매칭되어 `AUTO_MALICIOUS`가 아니라 `HIGH_RISK_UNCERTAIN`으로 라우팅됩니다.

> **설계와의 차이 (중요)**: `docs/pipeline_architecture.md`가 그리는 목표 우선순위는 "OOD → Disagreement → Difficulty → Probability Gray Zone → AUTO_MALICIOUS → AUTO_BENIGN"(4개 위험 신호 전부 사용) 6단계이지만, **현재 코드가 실제로 구현한 것은 위 표의 5단계(NaN → Disagreement → Gray Zone → Malicious → Benign)이며 OOD/Difficulty 단계는 존재하지 않습니다.** 이 문서는 실제 코드를 기준으로 작성했습니다.

---

## 5. Fail-Closed Behavior

`route_sample()` 최상단에서 입력값 NaN 여부를 가장 먼저 검사합니다.

```python
if np.isnan(p_calib) or np.isnan(disagreement):
    return {
        "decision": "HIGH_RISK_UNCERTAIN",
        "calibrated_prob": -1.0,
        "disagreement": -1.0,
        "reason": "System Error: NaN values detected (Fail-Closed)"
    }
```

- `calibrated_probability` 또는 `disagreement` 계산 과정에서 NaN이 발생하면 무조건 `HIGH_RISK_UNCERTAIN`으로 보냅니다(정상/악성으로 자동 판정하지 않음).
- 반환되는 `calibrated_prob`/`disagreement` 값 자체도 `-1.0`으로 오염 표시되어, 다운스트림이 실수로 이 값을 정상 확률처럼 사용하는 것을 막습니다.
- 커밋 이력상 이 로직은 "라우터 Fail-Open 보안 취약점 차단"(`33c51f8`)이라는 명시적 보안 수정으로 도입되었습니다 — 즉 과거에는 예외/NaN 상황에서 자동 통과(Fail-Open)될 위험이 있었고, 이를 막기 위한 Fail-Closed 정책입니다.
- 현재 코드는 이 경로를 `HIGH_RISK_UNCERTAIN` verdict로만 표현하며, `route`를 별도로 `DEEP_ANALYSIS`라는 문자열로 내보내지는 않습니다(6장 참고).

---

## 6. JRR Output Schema

### 현재 코드가 실제로 반환하는 dict

`route_sample()`의 반환값은 다음 4개 키만 가집니다(`src/jrr/jrr_router.py:45-50`):

```json
{
  "decision": "AUTO_BENIGN | AUTO_MALICIOUS | HIGH_RISK_UNCERTAIN",
  "calibrated_prob": 0.0,
  "disagreement": 0.0,
  "reason": "string"
}
```

- `decision`: 3가지 verdict 중 하나. `docs/pipeline_architecture.md`의 표준 스키마는 이 필드를 `initial_verdict`로 부릅니다 — **필드명이 다릅니다** (아래 참고).
- `calibrated_prob`: 필드명이 `calibrated_probability`가 아니라 `calibrated_prob`입니다.
- `route`(`FINAL`/`DEEP_ANALYSIS`), `ood_score`, `difficulty_score` 키는 **현재 반환 dict에 존재하지 않습니다.**
- `reason`: 여러 위험 신호를 전부 나열한 목록이 아니라, **4장 우선순위 규칙에서 최초로 매칭된 대표 사유 하나**입니다. `"Uncertain Probability"`는 별도의 불확실성 점수가 아니라, **확률이 `tau_low`와 `tau_high` 사이 그레이존에 걸렸을 때 붙는 reason 라벨**입니다.

### `tests/demo/01/demo.py`가 만드는 응답 (레거시 데모, 참고용)

`demo.py`는 위 4개 키를 그대로 감싸 `response["route"] = routed["decision"]`으로 매핑하고, `verdict` 필드는 `"AUTO_PASS"`/`"AUTO_QUARANTINE"` 문자열과 비교합니다. 하지만 현재 `jrr_router.py`는 `"AUTO_BENIGN"`/`"AUTO_MALICIOUS"`를 반환하므로 **이 비교는 항상 실패하고 `verdict`는 항상 "심층 분석"으로 떨어집니다.** 이는 용어 통일 커밋(`dbba689`) 이후 갱신되지 않은 레거시 데모의 버그이며, 현재 공식 스키마로 사용하면 안 됩니다.

### 설계상 표준 스키마 (`docs/pipeline_architecture.md`, 아직 코드와 불일치)

파이프라인 전체 결과 객체는 다음 필드를 포함하도록 설계되어 있으나, 이 중 `route`, `risk_signals.ood_score`, `risk_signals.difficulty_score`, `risk_score`는 **현재 `jrr_router.py` 출력에 없습니다.**

```json
{
  "calibrated_probability": 0.0,
  "risk_signals": {
    "disagreement": 0.0,
    "ood_score": 0.0,
    "difficulty_score": 0.0
  },
  "risk_score": 0.0,
  "initial_verdict": "AUTO_BENIGN | AUTO_MALICIOUS | HIGH_RISK_UNCERTAIN",
  "route": "COMPLETE | DEEP_ANALYSIS | ANALYST_REVIEW"
}
```

**Verdict** 값(공통): `AUTO_BENIGN`, `AUTO_MALICIOUS`, `HIGH_RISK_UNCERTAIN`.
**Route** 값: 설계 문서는 `FINAL`/`DEEP_ANALYSIS`(또는 `COMPLETE`/`DEEP_ANALYSIS`/`ANALYST_REVIEW`) 개념을 정의하지만, 현재 라우터 코드에는 `route` 필드 자체가 없습니다 — 호출자가 `decision`을 보고 `HIGH_RISK_UNCERTAIN`이면 `DEEP_ANALYSIS`로, 그 외는 `FINAL`로 스스로 매핑해야 합니다.

---

## 7. Evaluation Protocol

`src/preprocessing/README.md`(§ 분할 계약)와 `src/models/data_contract.py`가 확정한 **시간 기반(week_id) 4분할**입니다. `EXPECTED_ROWS`가 코드 레벨에서 이 행 수를 강제합니다.

| 분할 | 주차(week_id) | 행 수 | 역할 | 금지 |
|---|---|---:|---|---|
| **tr (Train)** | 0–33 | 2,720,000 | 모델 fit, 전처리 통계 산출 | 성능 보고 |
| **val (Validation)** | 34–39 | 480,000 | 하이퍼파라미터 튜닝, early stopping, 모델 선택(Optuna 등) | threshold 산출, 최종 성능 보고, 학습 포함 |
| **calib (Calibration)** | 40–45 | 480,000 | probability calibration + 라우팅 threshold(`tau_low`/`tau_high`) 선정 | 모델 선택, 학습 포함 |
| **eval (Eval)** | 46–51 | 480,000 | threshold 고정 후 engineering evaluation (6주 이동 성능 확인) | eval 결과 보고 후 threshold 재조정 |
| **Lockbox / Challenge** | — | test 960,000 / challenge 6,315 | 프로젝트 종료 시점 전체 파이프라인 freeze 후 **단 1회** 평가 | 개발 중 열람 금지 |

- 순서: **tr에서 학습 → val에서 모델 확정 → calib에서 threshold → eval에서 유지 확인 → lockbox 단 한 번.** (`src/preprocessing/README.md`)
- **Eval은 tuning에 사용되지 않습니다.** `docs_eval_lockbox_policy.md` §2: threshold는 반드시 calibration 세트에서만 산출하고, eval 세트에는 "적용만" 합니다.
- Validation(`val`, 34–39주차)은 원래 없었으나, calib/eval이 모델 선택 역할까지 겸하면 threshold가 자기가 고른 모델 위에서 추정되는 낙관 편향(FPR optimistic bias)이 생기기 때문에 train 뒤쪽 6주를 떼어 신설된 조각입니다.
- **Top-500 feature 선택은 이 평가 protocol에서 새로 정한 것이 아니라, 기존 TRUST-Triage 입력 계약(`docs/500개_특징_선택_근거.md`, `docs/feature_schema.md`, `top_feature_indices_500.npy`)으로 고정된 값**을 그대로 사용합니다. LightGBM/XGBoost 모두 동일 인덱스를 사용합니다(`data_contract.py::load_top_indices`가 인덱스 무결성을 검증).

---

## 8. Model Artifacts

### LightGBM (Primary Classifier)

| 항목 | 내용 |
|---|---|
| 파일명(현재) | `data/baseline_model_lightgbm_tuned_500_4way.pkl` |
| 학습 스크립트 | `src/models/tune_lightgbm.py` |
| 튜닝 방식 | Optuna (`TPESampler(seed=42)`, 기본 `N_TRIALS = 20`), `tr`에서 fit, `val`에서 `early_stopping(stopping_rounds=100)` + `validation_tpr_at_fpr`(목표 FPR 0.001) 기준 모델 선택 |
| 최종 학습 | 최적 trial의 `best_iteration`으로 `n_estimators` 고정 후 `tr` 전체로 재학습 (`lightgbm_tuned_500_train_only` run) |
| MLflow 실험 | `trust-triage-baseline`, 태그 `split_type=temporal_week_id_4way`, `top_n=500` |
| Run ID | **확인 필요** — 이 4way 모델의 MLflow run id는 리포지토리에서 확인되지 않음 |
| sha256 | **확인 필요** — 리포지토리에 기록 없음 |

**레거시 구분 주의**: `data/baseline_model_lightgbm_tuned_500_v4_9120.pkl`은 4-way 분할 이전의 **구버전** 모델이며, `docs/pipeline_architecture.md`에 적힌 "TPR@FPR 0.1% = 91.20%"는 **이 구버전 모델의 수치**입니다. `src/models/export_baseline_pkl.py`에 하드코딩된 `run_id = "69a92b2033d346ac930fe2ec889199a2"`도 그보다 더 이전의 **튜닝 전** 참고용 모델(`baseline_model_500.pkl`)의 run id이며, 현재 공식 4-way LightGBM과 무관합니다. 두 수치를 혼용하지 않도록 주의.

### XGBoost (Disagreement Comparator)

| 항목 | 내용 |
|---|---|
| 파일명(현재) | `data/baseline_model_xgb_500_4way_1000cap.pkl` |
| 학습 스크립트 | `src/models/train_xgboost_500.py` |
| 설정 | `XGBClassifier(n_estimators=1000, max_depth=6, learning_rate=0.05, random_state=42, tree_method="hist", eval_metric="auc", early_stopping_rounds=50)`, `tr`에서 fit, `val`에서 early stopping |
| MLflow 실험 | `TRUST-Triage-XGBoost-500`, `best_iteration`/`validation_best_auc` 기록 |
| Run ID / best_iteration | **확인 필요** — 실제 `best_iteration`이 1000 cap 이전에 조기 종료되었는지, cap에 도달했는지는 로그 확인 필요. 파일명의 `1000cap`은 상한 설정을 의미할 뿐, **완전히 수렴했다는 의미로 해석하면 안 됨.** |
| 역할 | LightGBM과의 Disagreement 계산용 비교 모델일 뿐, 공식 판정 모델이 아님 |

---

## 9. Calibration Results

### tau_high (상한, 자동 악성 커트라인)

- **산출 코드**: `src/jrr/train_calibrator.py` — Calibration 세트(`X_calib`/`y_calib`)에 대해 Isotonic 보정된 확률로 `roc_curve`를 계산하고, `fpr <= TARGET_FPR(0.001)`을 만족하는 마지막 지점의 threshold를 채택.
  ```python
  idx = np.where(fpr <= TARGET_FPR)[0][-1]
  optimal_threshold = thresholds[idx]
  ```
- **값**: `0.983645` (라우터에 하드코딩, 커밋 `207d346`).
- **선정 기준**: **Calibration 세트의 FPR ≤ 0.1% 조건**으로 선정 — Eval 세트 결과를 보고 조정된 값이 아닙니다.

### tau_low (하한, 자동 정상 커트라인)

- **산출 코드**: `src/jrr/optimize_threshold.py::optimize_lower_bound()` — Calibration 세트에서 `tau_high`를 고정한 채 하한 후보(`[0.10, 0.20, 0.30, 0.40, 0.50, 0.55, 0.60, 0.65, 0.70, 0.80]`, `tau_high` 미만만 채택)를 순회하며 `daily_budget=100` 기준 **Review Yield를 극대화**하고, 동률이면 **자동정상(AUTO_BENIGN)으로 새는 악성(leaked malware) 건수가 더 적은 후보**를 최종 선택.
- **값**: `0.60`.
- **선정 기준**: deep-analysis 트래픽 양, 분석가 검토 가성비(Review Yield), 악성 누락(leakage) 사이의 trade-off를 Calibration 세트에서 시뮬레이션하여 선정 — Eval 결과로 재조정된 것이 아닙니다.

### tau_disagree

- **값**: `0.3` (고정).
- **선정 기준**: 리포지토리 내에 Calibration 데이터 기반으로 이 값을 비교·선정한 스크립트/로그가 확인되지 않습니다. `disagreement.py`는 참고용으로 `> 0.2`/`> 0.5` 구간의 비율만 출력할 뿐 threshold 선택 로직이 아닙니다. **선정 근거 문서 확인 필요.**

### difficulty threshold

- 2장/3장에서 설명한 대로 Analysis Difficulty는 라우터에 통합되어 있지 않으므로 threshold 자체가 존재하지 않습니다. **선정 근거 문서 확인 필요(현재 존재하지 않음).**

---

## 10. Final Eval Results

**이 섹션의 수치는 리포지토리에서 확인할 수 없습니다.** `evaluate_jrr.py`는 ECE, Brier Score, Review Yield, 실측 TPR/FPR, ROC-AUC, Confusion Matrix, Kill Test FPR을 계산해 MLflow 실험 `JRR_Evaluation_and_KillTest`에 기록하도록 되어 있지만:

- `data/`는 `.gitkeep`만 있고 `.npy`/`.pkl` 산출물이 커밋되어 있지 않습니다(구글 드라이브로 팀원 간 공유되는 구조).
- 이 워크스페이스에는 `mlruns/`/`mlflow.db`가 존재하지 않아 로컬 MLflow 기록도 조회할 수 없습니다.
- git 커밋 메시지/본문에도 구체적 수치가 기록되어 있지 않습니다.

따라서 아래 지표는 **모두 "확인 필요"**로 남깁니다. 이 문서 작성자가 로컬에서 `mlflow ui`로 `JRR_Calibration` / `JRR_Threshold_Optimization` / `JRR_Evaluation_and_KillTest` 세 실험을 열어 채워 넣어야 합니다.

| 지표 | 값 |
|---|---|
| ROC-AUC (Eval) | 확인 필요 |
| 실측 TPR @ tau_high 적용 시 (Eval) | 확인 필요 |
| 실측 FPR @ tau_high 적용 시 (Eval) | 확인 필요 |
| ECE | 확인 필요 |
| Brier Score | 확인 필요 |
| Deep Analysis Traffic (HIGH_RISK_UNCERTAIN 비율) | 확인 필요 |
| Review Yield (`daily_budget=100`) | 확인 필요 |
| Confusion Matrix (TP/FP/TN/FN) | 확인 필요 |
| Kill Test FPR | 확인 필요 |

> **주의**: `docs/pipeline_architecture.md`의 "TPR@FPR 0.1% = 91.20%"는 4-way 분할 이전 구버전 LightGBM(`baseline_model_lightgbm_tuned_500.pkl`)의 수치이며, 현재 4-way 파이프라인의 Eval 결과가 아닙니다. **혼용 금지.** 위 표가 채워지면, "Calibration에서 FPR ≤ 0.1% 기준으로 선정한 threshold(`tau_high=0.983645`)를 고정 적용한 결과, Eval에서 TPR __%, FPR __%를 기록했다"의 형태로 작성해야 하며, Calibration 시점의 목표 FPR(0.1%)과 Eval에서 실측된 FPR을 절대 같은 값으로 혼동해 쓰면 안 됩니다.

---

## 11. Risk Signal Analysis

- **OOD 유입 / difficulty 유입 / probability gray-zone 유입 비율**: OOD와 Difficulty가 라우터에 통합되어 있지 않으므로(2장), 이 신호들로 인한 라우팅 유입량 자체를 계산할 방법이 현재 코드에 없습니다. **확인 필요(향후 통합 이후 재작성).**
- **Disagreement 유입 / probability gray-zone 유입**: `evaluate_jrr.py`/`jrr_router.py` 실행 결과(`data/jrr_routes.npy`)를 집계하면 산출 가능하지만, 10장과 동일한 이유로 이 리포지토리에는 산출물이 없어 **확인 필요**.
- **Signal overlap**: 현재 라우터가 실제로 참조하는 신호가 2개(calibrated_probability, disagreement)뿐이므로, "신호 overlap이 낮다"는 관찰 자체가 아직 성립하지 않습니다. 향후 4개 신호가 모두 통합된 뒤 overlap을 측정하더라도, **overlap이 낮다는 것을 "통계적으로 독립"이라고 표현해서는 안 됩니다** — 표본 크기, 신호 정의 방식에 따라 우연히 낮게 관측될 수 있습니다.
- **"OOD로 표시된 샘플이 모두 HIGH_RISK로 갔다" 같은 관찰**은 (향후 통합되었을 때) OOD 탐지의 정확도를 증명하는 것이 아니라, **JRR의 우선순위 규칙(4장)이 정상적으로 적용된 결과**일 뿐이라는 점을 유의해야 합니다 — OOD 조건이 매칭되면 다른 신호와 무관하게 무조건 `HIGH_RISK_UNCERTAIN`으로 보내도록 설계될 것이기 때문입니다.

---

## 12. Deep Analysis Integration

`docs/pipeline_architecture.md`와 `docs/static-analysis/deep_analysis.md` 두 문서가 심층분석 흐름을 정의합니다(두 문서 간 Tier 3 명칭이 다릅니다 — 아래 참고).

```
HIGH_RISK_UNCERTAIN
  → Tier 1: CAPA
      ├─ ATT&CK 근거 충분 → COMPLETE
      └─ 근거 부족/상충
  → Tier 2: Speakeasy
      ├─ 근거 충분 → COMPLETE
      └─ 근거 부족 또는 실패
  → Tier 3: (문서 간 불일치 — 아래 참고)
  → MITRE ATT&CK Evidence 정규화
  → Final Assessment (BENIGN / MALICIOUS / 판정 불가 → Analyst Review Queue → 필요 시 Ghidra 수동 분석)

AUTO_BENIGN / AUTO_MALICIOUS
  → FINAL (자동화 종료, 심층분석 미수행)
```

- **Tier 3 명칭 불일치**: `docs/pipeline_architecture.md`는 Tier 3를 "CAPE"로 표기하는 반면, `docs/static-analysis/deep_analysis.md`(계약 문서, `DeepAnalysisOrchestrator` 구현 대상)는 Tier 3를 "Ghidra CAPA"로 명시합니다. 어느 쪽이 최신 계약인지는 이 문서 범위 밖이므로 **확인 필요**로 남깁니다. 리포지토리에 "LLM Analyst Assist"라는 개념/코드는 존재하지 않아 포함하지 않았습니다.
- JRR은 심층분석 로직 자체(CAPA/Speakeasy/Ghidra 실행, ATT&CK 매핑)를 수행하지 않고, **"어떤 샘플에 추가 분석 자원을 쓸지"만 결정하는 라우터**입니다. `feature/dynamic-analysis`의 Speakeasy 구현은 복사하지 않고 `SpeakeasyAnalyzer` 객체를 `DeepAnalysisOrchestrator`에 주입하는 방식으로 통합합니다(`deep_analysis.md`).

---

## 13. XAI Relationship

- **SHAP은 LightGBM raw model output(원시 점수)의 설명입니다.** `docs/shap-explanation-module.md`: `shap.TreeExplainer(model, model_output="raw")`로 LightGBM raw score를 설명하며, **"calibration 이후의 `calibrated_probability`는 설명하지 않는다"**고 명시되어 있습니다.
- **SHAP 대상 모델 버전 주의**: 현재 SHAP 모듈의 공식 대상은 `baseline_model_lightgbm_tuned_500_v4_9120.pkl`(구버전)이며, 이 문서 8장의 현재 JRR 파이프라인이 쓰는 `baseline_model_lightgbm_tuned_500_4way.pkl`과 **다른 아티팩트**입니다. 문서 원문도 "기존 inference, Calibration, JRR 동작과는 연결되어 있지 않다"고 명시합니다 — 즉 SHAP 모듈은 현재 JRR 파이프라인과 **아직 통합되지 않은 독립 모듈**입니다.
- **역할 구분**:
  - `SHAP` = **Model Evidence** — ML 모델이 왜 그런 raw score를 냈는지에 대한 기여도 설명 (500차원 Top-K).
  - `CAPA / FLOSS(Speakeasy 등) / MITRE ATT&CK Evidence` = **Behavioral Evidence** — 심층분석 도구가 실제로 관찰한 행위 기반 근거.
  - 둘은 서로 다른 목적으로 대시보드에 별도 제공되며, `calibrated_probability`나 JRR의 `initial_verdict`를 SHAP이 설명한다고 서술하면 안 됩니다.

---

## 14. Service Integration

`docs/docs_api_contract.md`(초안)와 `dashboard/app.py`(Streamlit) 기준입니다. **현재 대시보드는 실제 JRR 라우터를 호출하지 않고, `mock_triage_profile()` 등으로 생성한 목업 데이터를 사용합니다** — FastAPI 백엔드 자체가 아직 구현되어 있지 않습니다(CLAUDE.md: "API/dashboard는 아직 진행 중").

설계상 의도된 흐름:

```
AUTO_BENIGN      → FINAL (자동화 종료)
AUTO_MALICIOUS   → FINAL (자동화 종료)
HIGH_RISK_UNCERTAIN → DEEP_ANALYSIS → 비동기 심층분석 파이프라인 (12장)
```

- Batch(여러 파일/ZIP) 환경에서는 `HIGH_RISK_UNCERTAIN`으로 라우팅된 항목이 분석가의 **Needs Review** 대상으로 우선 표시되도록 대시보드가 설계되어 있습니다(`dashboard/app.py`의 `mock_triage_profile()`이 이 3-way verdict를 그대로 보여주는 구조).
- `docs_api_contract.md`가 언급하는 `risk_score` 기반 Slack Alert(잠정 threshold 0.9)는 **팀 확정 필요** 상태이며, 현재 JRR 출력에는 `risk_score` 필드 자체가 없습니다(6장).

---

## 15. Known Limitations

- **Rule-based priority 방식**: 가중합/스코어링이 아니라 if/elif 우선순위이므로, 상위 규칙 하나가 나머지 신호를 전부 무시하고 결정을 확정합니다(4장). 신호 간 상호작용을 세밀하게 반영하지 못합니다.
- **대표 reason 하나만 반환**: 여러 위험 신호가 동시에 임계값을 넘어도 `reason`에는 최초 매칭된 규칙 하나만 기록됩니다(6장). 사후 분석 시 "이 파일이 실제로 몇 개 신호에 걸렸는지"를 reason만으로는 알 수 없습니다.
- **OOD/Difficulty 미통합**: 컴포넌트(IsolationForest, difficulty 인덱스 매핑)는 존재하지만 라우터 입력으로 연결되어 있지 않고, `decision_function`/스칼라 difficulty score 계산 로직 자체가 아직 없습니다(2장). External OOD benchmark(진짜 신종/변종 정상 파일로 검증) 여부도 `docs_eval_lockbox_policy.md`의 Kill Test 정책에 언급은 있으나 실행 결과가 이 리포지토리에는 없습니다(10장).
- **Difficulty score 의미의 한계**: 설계상으로도 difficulty는 "악성도"가 아니라 "분석 난이도/구조 이상" 신호일 뿐이며, PEFormatWarnings 경고가 많다고 곧바로 악성/정상을 시사하지 않습니다.
- **Final Assessment 로직 미확정**: 12장의 Tier 3(CAPE vs Ghidra CAPA) 문서 간 불일치, `docs_api_contract.md`의 Alert threshold 미확정 등 다운스트림 다수 항목이 TBD 상태입니다.
- **`risk_score`는 현재 공식 JRR 설계/코드에 존재하지 않습니다.** `docs/pipeline_architecture.md`, `docs/docs_api_contract.md`가 필드를 언급하지만 이는 미확정 설계이며(둘 다 "다음 확인 사항"으로 남아있음), `jrr_router.py`가 실제로 반환하는 값이 아닙니다. Weighted Risk Score 방식 자체도 현재 공식 설계에는 없습니다(4장).
- **`src/jrr/__init__.py` import 오류**: `from .router import JRRRouter`를 시도하지만 `src/jrr/router.py`라는 파일은 존재하지 않고 실제 라우터는 `jrr_router.py::JointRiskRouter`입니다. 현재 `import jrr`는 `ModuleNotFoundError: No module named 'jrr.router'`로 실패합니다(직접 확인함). 이번 작업은 문서 작성만 수행하므로 코드는 수정하지 않았으나, 별도 이슈로 트래킹이 필요합니다.

---

## 16. Reproducibility / Relevant Files

| File | Role |
|---|---|
| `src/jrr/jrr_router.py` | `JointRiskRouter` — 실제 라우팅 엔진 (calibrated_probability + disagreement, 3-way) |
| `src/jrr/train_calibrator.py` | Isotonic Calibration 학습, `tau_high` 산출, `jrr_calibrator_4way.pkl` 생성 |
| `src/jrr/optimize_threshold.py` | Calibration 세트 기반 `tau_low` 최적화 시뮬레이터 |
| `src/jrr/disagreement.py` | LightGBM/XGBoost 원시 확률로부터 배치 Disagreement 계산·저장 |
| `src/jrr/risk_signals.py` | OOD(IsolationForest) 모델 학습 + Analysis Difficulty 인덱스 동적 매핑 (`jrr_risk_signals.pkl`) — 라우터 미통합 |
| `src/jrr/generate_raw_probas.py` | Eval 세트에 대한 LightGBM/XGBoost 원시 확률 생성 |
| `src/jrr/_jrr_eval_core.py` | 평가 지표 공용 함수: `calculate_ece`, `calculate_review_yield`, `calculate_true_tpr`, `run_kill_test` |
| `src/jrr/evaluate_jrr.py` | 최종 Eval 실행 스크립트 (ECE/Brier/Review Yield/ROC-AUC/Confusion Matrix/Kill Test → MLflow) |
| `src/models/tune_lightgbm.py` | LightGBM 4-way 학습/튜닝 (Optuna) |
| `src/models/train_xgboost_500.py` | XGBoost 4-way 학습 (disagreement 비교 모델) |
| `src/models/data_contract.py` | 4분할(tr/val/calib/eval) row-count·스키마 계약 검증 |
| `docs/pipeline_architecture.md` | 전체 파이프라인 설계 문서 (일부 필드는 아직 코드와 불일치, 4장/6장 참고) |
| `docs/확률보정_위험신호.md` | Calibration + Risk Signals 파이프라인 인수인계 문서 |
| `docs/docs_jrr_eval_and_optimize.md` | JRR 평가/최적화 파이프라인 실행 순서 가이드 |
| `docs/docs_eval_lockbox_policy.md` | 지표/threshold/lockbox/kill-test 공식 정책 |
| `docs/feature_schema.md` | PEFormatWarnings(2480–2568) 등 전체 feature 스키마 |
| `docs/static-analysis/deep_analysis.md` | Tiered 심층분석 계약 (`DeepAnalysisOrchestrator`) |
| `docs/shap-explanation-module.md` | SHAP 설명 모듈 (JRR과 별도 통합, v4_9120 아티팩트 대상) |
| `dashboard/app.py` | Streamlit 대시보드 (현재 전량 목업 데이터, 실제 JRR 미연동) |
| `tests/demo/01/demo.py`, `DEMO_SETUP.md` | 레거시 CLI 데모 (구 threshold/구 용어 사용 — 현재 값과 다름, 참고용으로만 사용) |

---

## 17. Final Summary

JRR은 EMBER2024 기반 LightGBM Baseline의 원시 확률을 Isotonic Calibration으로 보정한 뒤, Calibration 세트에서 산출한 두 개의 고정 threshold(`tau_high=0.983645`: FPR≤0.1% 기준, `tau_low=0.60`: Review Yield 최적화 기준)와 LightGBM–XGBoost 간 Disagreement(고정값 `tau_disagree=0.3`)를 이용해, 우선순위가 정해진 규칙(Fail-Closed NaN 처리 → Disagreement → 확률 그레이존 → 악성 확신 → 정상 확신 순)으로 세 갈래 판정을 내리는 라우터입니다. OOD Score와 Analysis Difficulty는 설계·부품(IsolationForest, PEFormatWarnings 인덱스 매핑)까지는 구현되어 있으나 아직 라우팅 결정에 통합되지 않았고, `risk_score`나 가중합 방식은 현재 공식 구현에 존재하지 않습니다. Eval 세트에 대한 최신 정량 지표(ROC-AUC, TPR/FPR, ECE, Brier, Review Yield 등)는 이 리포지토리에 커밋되어 있지 않아 로컬 MLflow 확인이 필요합니다.

> **JRR은 모델의 확률만으로 자동 판정하지 않고, Calibration된 확률과 다중 위험 신호를 이용해 자동 판정과 심층분석 대상을 보수적으로 분리하는 Priority-ordered Rule-based Triage Router이다.**
> (단, 2026-09-09 기준 현재 코드는 이 신호들 중 Calibrated Probability와 Disagreement 두 가지만 실제로 사용하고 있으며, OOD/Difficulty는 통합 예정 상태입니다.)
