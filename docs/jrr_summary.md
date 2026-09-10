# Joint Risk Router (JRR) — Final Design & Evaluation

> **재검증 안내**: 이 문서는 `docs/jrr-summary` 브랜치(= `main` 최신 상태, 병합 기준 커밋 `7e1d8de`)를 기준으로 리포지토리 전체를 처음부터 다시 조사하여 **전면 재작성**했습니다. 이전 버전은 다른 feature 브랜치 시점의 초안이었고, 그 시점에는 OOD/Analysis Difficulty가 라우터에 통합되지 않은 상태였습니다. **현재 `main`에서는 두 신호 모두 라우터에 완전히 통합되어 있습니다.** 근거는 실제 코드(`src/jrr/*.py`)와 코드와 사실상 1:1로 일치하는 최신 설계 문서(`docs/pipeline_architecture_v3.md`, `docs/interface_spec.md`, `docs/service_architecture.md`, `docs/risk_routing_simulation_test.md`)이며, 이번 조사에서 실제로 `import jrr`을 실행하고 `route_sample()` 소스를 직접 대조해 검증했습니다. 코드와 문서가 충돌하는 지점은 코드를 기준으로 삼고 본문에 명시했습니다. 확인할 수 없는 값은 추측하지 않고 "확인 필요"로 표기했습니다.
>
> **2026-09-10 갱신 안내**: `main` 병합 커밋 `2eaad68`(PR #101, "JRR 라우팅 임계값 최적화 로직 전면 개편")을 기준으로 아래 항목을 다시 반영했습니다: (1) `route_sample()` 반환값에 `triggered_signals` 필드 추가, (2) `tau_low=0.60`·`tau_difficulty=5.0` 모두 **Calibration 세트(48만 건) 전체 재탐색**으로 재확정(과거 재현 불가/Eval 세트 관여 이슈는 해결됨), (3) 지금까지의 Eval 수치는 threshold freeze 이전 **Engineering Eval**로 재분류하고, threshold freeze 이후 재실행될 **Final Eval**과 명확히 구분. 이 개정에서 코드는 수정하지 않았습니다.
>
> **2026-09-10 추가 갱신 안내(2D Grid Search 반영)**: `feature/jrr-evaluation` 브랜치 커밋 `06c8ffc`("Refactor: Replace circular reasoning with 2D Grid Search...")·`f4ce7a1`("Update jrr_router.py default thresholds to Global Optimum")을 기준으로, 바로 위 2026-09-10 갱신에서 채택했던 `tau_low=0.60`/`tau_difficulty=5.0`(순차·단변수 최적화 결과)가 **`tau_low=0.65`/`tau_difficulty=6.0`(Calibration 세트 2차원 Grid Search 결과)로 대체**되었습니다. `tau_low`와 `tau_difficulty`는 JRR의 OR 조건에서 서로 상호작용하므로, 한쪽을 고정한 채 다른 한쪽만 순차 탐색하면 순환 논리(Circular Reasoning) 문제가 생길 수 있습니다 — 이 문제를 없애기 위해 두 변수를 **동시에** 2차원 Grid Search로 탐색했습니다. 이번 개정으로 문서 곳곳에 `0.60`/`0.65`, `5.0`/`6.0`이 섞여 있던 병합 잔재를 정리하고, `tau_low=0.65`/`tau_difficulty=6.0`을 현재 공식 값으로 통일했습니다. 과거 `0.60`/`5.0` 값은 삭제하지 않고 이전 순차 최적화 단계의 이력으로만 남겼습니다(3, 9장). 이 개정에서도 코드는 수정하지 않았습니다.

---

## 1. Overview

### JRR의 목적

JRR(Joint Risk Router)은 "모델 확률이 얼마인가"만으로 자동 판정하지 않고, **보정된 확률 + 3개의 추가 위험 신호(Model Disagreement, OOD, Analysis Difficulty)**를 근거로 파일을 세 갈래(`AUTO_BENIGN` / `AUTO_MALICIOUS` / `HIGH_RISK_UNCERTAIN`)로 나누는 **우선순위 규칙 기반 라우터**입니다. 목적은 "이 파일이 악성인가"를 최종 판정하는 것이 아니라, **어떤 파일에 심층분석·분석가 자원을 투입할지 결정**하는 것입니다.

### TRUST-Triage 파이프라인에서의 위치

`docs/pipeline_architecture_v3.md`(2026-09-07, v3) 기준 전체 흐름 중 ④~⑥ 구간을 담당합니다. (구버전 `docs/pipeline_architecture.md`는 v3로 대체된 **레거시 문서**이며, `risk_score`·구형 모델 수치 등 현재 코드와 맞지 않는 내용을 담고 있어 참고하지 않았습니다.)

```
Raw PE
  → Feature Extraction (EMBER2024 v3, 고정 Top-500 선택)
  → LightGBM (공식 Baseline) / XGBoost (Disagreement 비교 모델)
  → Isotonic Calibration (LightGBM raw prob → calibrated_probability)
  → Risk Signal Computation (Disagreement / OOD / Analysis Difficulty)
  → JRR (jrr_router.py::JointRiskRouter)
  → AUTO_BENIGN / AUTO_MALICIOUS / HIGH_RISK_UNCERTAIN
```

이 다이어그램은 이제 **설계 의도가 아니라 실제 코드 그대로**입니다. `src/jrr/jrr_router.py::JointRiskRouter.route_sample()`은 4개 인자(`p_calib, disagreement, ood_score, difficulty_score`)를 모두 받아 판정하며, `route_sample()`이 반환하는 `initial_verdict`/`route` 필드도 `docs/interface_spec.md`가 정의한 이름과 일치합니다.

### 단순 malware classifier와의 차이

단순 classifier는 확률 하나로 이분(또는 threshold 하나로 삼분) 판정을 내립니다. JRR은 (1) 확률을 그대로 쓰지 않고 Isotonic Calibration을 거친 값을 쓰고, (2) 모델 간 불일치(Disagreement)·학습 분포 이탈(OOD)·PE 구조 이상(Difficulty)처럼 "확률 자체는 안전해 보여도 실제로는 불확실한" 상황을 별도로 탐지해 자동판정에서 배제합니다.

### 자동 판정과 심층분석 대상 분리 목적

FPR 0.1% 같은 강한 방어선을 지키면서도(=오탐을 최소화), 확률만으로는 드러나지 않는 그레이존/불일치/이상치 샘플을 놓치지 않기 위해 "4가지 조건 중 하나라도 걸리면 심층분석"이라는 **보수적(Conservative) OR 조건** 전략을 취합니다(`docs/risk_routing_simulation_test.md` §2.5).

---

## 2. JRR Inputs

`src/jrr/jrr_router.py::JointRiskRouter.route_sample(self, p_calib, disagreement, ood_score, difficulty_score)`의 실제 시그니처 기준입니다. **4개 신호 모두 현재 라우터 판정에 실제로 사용됩니다.**

### Calibrated Probability

- **의미**: LightGBM 원시 확률(`lgbm_raw_probability`)은 과신(over-confident)되어 있어 실제 정답률과 어긋납니다. 이를 실제 신뢰도로 보정한 값입니다.
- **산출 방식**: `src/jrr/train_calibrator.py` — `sklearn.isotonic.IsotonicRegression(out_of_bounds="clip")`을 Calibration 세트(`X_calib`/`y_calib`)에서 학습된 LightGBM(`baseline_model_lightgbm_tuned_500_4way.pkl`)의 raw 확률에 대해 fit. 결과는 `jrr_calibrator_4way.pkl`(`{'model':..., 'threshold':...}`)로 저장.
- **JRR에서 사용 방향**: 값이 낮을수록 정상, 높을수록 악성. `tau_low`/`tau_high` 두 경계값으로 그레이존을 정의.
- **Threshold**: `tau_low = 0.65`, `tau_high = 0.983645` (3장). `tau_low=0.65`는 `tau_difficulty`와 함께 Calibration 세트 2차원 Grid Search로 동시 선정된 값입니다(9장).

### Model Disagreement

- **의미**: LightGBM과 XGBoost 두 모델의 예측이 얼마나 다른지. **"분산"이 아니라 두 원시 확률의 절대 차이**입니다.
- **산출 방식**: `JointRiskRouter.compute_disagreement()` (`src/jrr/jrr_router.py:16-18`)
  ```python
  def compute_disagreement(self, p_lgb: float, p_xgb: float) -> float:
      return abs(p_lgb - p_xgb)
  ```
  배치 재현용 스크립트는 `src/jrr/disagreement.py`(`np.abs(p_lgb - p_xgb)`, 동일 정의).
- **JRR에서 사용 방향**: 값이 클수록(두 모델이 서로 동의하지 않을수록) 위험 — 확률이 아무리 확신에 차 보여도 `HIGH_RISK_UNCERTAIN`으로 격상.
- **Threshold**: `tau_disagree = 0.3` (고정값).

### OOD (Out-of-Distribution) Score

- **의미**: 학습 데이터 분포와 얼마나 동떨어져 있는지(신종/변종 의심도).
- **산출 방식**: `src/jrr/risk_signals.py`가 `IsolationForest(n_estimators=200, contamination="auto", random_state=42, n_jobs=-1)`을 학습합니다. 학습 데이터는 `X_tr`(272만 행)에서 `np.random.seed(42)` 후 `np.random.choice(..., 100000, replace=False)`로 **무작위 균등 샘플링한 10만 행**을 Top-500 인덱스로 슬라이싱한 것이며, Eval 등 다른 분할은 학습에 사용하지 않습니다(`risk_signals.py:55-62`). 결과 모델은 `data/jrr_risk_signals.pkl`의 `ood_model` 키로 저장됩니다.
- **`decision_function` 사용 여부**: **사용합니다.** `jrr_router.py`의 실행 스크립트(`__main__`)에서 `ood_model.decision_function(X_eval_500)`을 직접 호출해 개별 파일의 `ood_score`를 산출하고 `data/jrr_ood_scores.npy`로 저장합니다(`jrr_router.py:103-105`).
- **JRR에서 OOD로 판단하는 조건**: `ood_score < tau_ood`. sklearn `IsolationForest.decision_function()`의 관례상 **음수(0 미만)가 이상치**이므로, `tau_ood = 0.0`은 별도로 튜닝한 값이라기보다 이 라이브러리 컨벤션을 그대로 채택한 것입니다.
- **Threshold**: `tau_ood = 0.0` (`ood_score < 0.0`).

### Analysis Difficulty

- **의미**: 악성도 점수가 아니라 **"이 PE 파일을 정적으로 분석/파싱하기가 얼마나 어려운가/구조가 얼마나 비정상인가"**를 나타내는 신호입니다.
- **Top-500 안에서의 사용**: `feature_schema.md`가 정의하는 `PEFormatWarnings` 블록(원본 인덱스 2480–2568)이 Top-500 선택 이후 몇 번째 인덱스로 이동했는지를 `risk_signals.py`가 동적으로 추적합니다(`difficulty_indices_in_top500 = np.where((top_500_idx >= 2480) & (top_500_idx < 2568))[0]`, `data/jrr_risk_signals.pkl`의 `difficulty_indices` 키).
- **스칼라 점수 산출**: `jrr_router.py`의 실행 스크립트가 이 인덱스들이 가리키는 Top-500 벡터 값을 **행 단위로 합산**합니다.
  ```python
  difficulty_scores = np.sum(X_eval_500[:, difficulty_indices], axis=1)
  ```
  (`jrr_router.py:107-110`, PEFormatWarnings 경고 발생 여부/개수의 합)
- **JRR에서 사용 방향 / Threshold**: `difficulty_score >= tau_difficulty`이면 `HIGH_RISK_UNCERTAIN`으로 격상. `tau_difficulty = 6.0`. 악성도 신호가 아니라 **구조 이상/분석 난이도 신호**라는 점은 `docs/pipeline_architecture_v3.md`(⑤ Analysis Difficulty)와 `docs/risk_routing_simulation_test.md`(§2.3) 모두 명시합니다. `tau_difficulty=6.0`은 `tau_low`와 함께 Calibration 세트 2차원 Grid Search로 동시 선정된 값입니다(9장).

---

## 3. Final Thresholds

`src/jrr/jrr_router.py::JointRiskRouter.__init__`의 기본값을 그대로 인용합니다. `docs/interface_spec.md` §4.3 "현재 기준값"과 `docs/pipeline_architecture_v3.md` CRITICAL-01의 값도 동일합니다(세 곳 모두 일치 확인).

| Signal | Threshold | Role | 선정 출처 |
|---|---|---|---|
| `calibrated_probability` (상한) | `tau_high = 0.983645` | 이상이면 `AUTO_MALICIOUS` | **Calibration 세트**에서 목표 FPR ≤ 0.1%를 만족하는 마지막 ROC 지점 (`train_calibrator.py`, `TARGET_FPR = 0.001`). 고정 운영 상수. |
| `calibrated_probability` (하한) | `tau_low = 0.65` | 이하면 `AUTO_BENIGN` | **Calibration 세트(48만 건) 전체**를 대상으로 `tau_difficulty`와 함께 **2차원 Grid Search**(후보 `tau_low ∈ {0.50, 0.55, ..., 0.80}` × `tau_difficulty ∈ {1.0, ..., 10.0}`)로 동시 탐색해 확정. 목적함수 `Utility = Review Yield × (1 − 악성 누출률)` 기준 정의된 후보 grid 범위 내 최적 조합(`src/jrr/optimize_threshold.py::optimize_grid_search()`, `docs/risk_routing_simulation_test.md` §4.1). 9장 참고. |
| `disagreement` | `tau_disagree = 0.3` | 이상이면 `HIGH_RISK_UNCERTAIN` | **고정 운영 상수**. `docs/risk_routing_simulation_test.md`는 "인식론적 불확실성과의 상관관계"라는 정성적 근거만 제시하며, 이 값을 Calibration 그리드 탐색으로 산출한 코드/로그는 리포지토리에서 확인되지 않음. |
| `ood_score` | `tau_ood = 0.0` | 미만이면 `HIGH_RISK_UNCERTAIN` | `IsolationForest.decision_function()`의 표준 이상치 경계(0 미만=이상치)를 그대로 채택. Calibration 그리드 탐색으로 별도 산출되지 않음. |
| `difficulty_score` | `tau_difficulty = 6.0` | 이상이면 `HIGH_RISK_UNCERTAIN` | **Calibration 세트(48만 건) 전체**를 대상으로 `tau_low`와 함께 **2차원 Grid Search**로 동시 탐색해 확정(위 `tau_low` 행과 동일한 탐색). `tau_low`와 `tau_difficulty`는 JRR OR 조건에서 서로 상호작용하므로 하나씩 순차 최적화하지 않고 동시에 탐색했습니다. 9장 참고. |

> `tau_low`/`tau_difficulty` 모두 **Calibration 세트에서 결정 후 고정(freeze)**되었으며, Eval 결과는 이번 2차원 탐색에도 사용되지 않았습니다. `docs/pipeline_architecture_v3.md` CRITICAL-01: "Threshold 및 라우팅 정책은 Calibration 세트에서 결정 후 고정하고, Eval에서는 고정된 정책의 성능만 측정한다." Calibration에서 threshold를 freeze한 뒤 수행하는 **Final Eval**은 아직 재실행되지 않았습니다(7, 10장 참고).
>
> **이전 값(이력)**: 이전 개정에서는 `tau_low`와 `tau_difficulty`를 한쪽을 고정한 채 순차적으로 각각 최적화해 `tau_low=0.60`, `tau_difficulty=5.0`을 채택했습니다. 두 변수가 OR 조건에서 상호작용하는 것을 반영하지 못하는 방식이었기 때문에, 이후 2차원 Grid Search로 대체되어 현재는 `0.65`/`6.0`이 공식 값입니다(9장에 이력으로 보존).

---

## 4. Routing Logic

`JointRiskRouter`는 **가중합(Weighted Risk Score) 방식이 아니라, 우선순위가 있는 규칙 기반(Priority-ordered Rule-based) 3-Way 라우터**입니다(`docs/pipeline_architecture_v3.md` CRITICAL-03). `route_sample()`(`src/jrr/jrr_router.py:20-73`)의 실제 if/elif 순서 그대로입니다.

| 순서 | 조건 | 결과 | reason 예시 |
|---|---|---|---|
| 0 | `p_calib`/`disagreement`/`ood_score`/`difficulty_score` 중 하나라도 NaN | `HIGH_RISK_UNCERTAIN` (`route=DEEP_ANALYSIS`) | `System Error: NaN values detected (Fail-Closed)` |
| 1 | `ood_score < tau_ood` | `HIGH_RISK_UNCERTAIN` | `OOD Detected (Score: -0.0310)` |
| 2 | `disagreement >= tau_disagree` | `HIGH_RISK_UNCERTAIN` | `High Model Disagreement (0.3100)` |
| 3 | `difficulty_score >= tau_difficulty` | `HIGH_RISK_UNCERTAIN` | `High Analysis Difficulty (Score: 6.0)` |
| 4 | `tau_low < p_calib < tau_high` | `HIGH_RISK_UNCERTAIN` | `Uncertain Probability (0.8871)` |
| 5 | `p_calib >= tau_high` | `AUTO_MALICIOUS` | `High Malicious Confidence (0.9910)` |
| 6 (else) | 그 외 (`p_calib <= tau_low`) | `AUTO_BENIGN` | `High Benign Confidence (0.0570)` |

경계값을 명시하면:

- `p_calib <= tau_low` → `AUTO_BENIGN` (단, 위 0~3번 조건에 걸리지 않았을 때)
- `tau_low < p_calib < tau_high` → `HIGH_RISK_UNCERTAIN` (그레이존)
- `p_calib >= tau_high` → `AUTO_MALICIOUS` (단, 위 0~3번 조건에 걸리지 않았을 때)

**우선순위가 실제 판정을 뒤집는 예**: `p_calib`가 0.999로 `tau_high`를 훨씬 넘더라도, `ood_score < 0.0`이면 1번 규칙이 가장 먼저 매칭되어 `AUTO_MALICIOUS`가 아니라 `HIGH_RISK_UNCERTAIN`으로 라우팅됩니다. 마찬가지로 OOD·Disagreement·Difficulty 세 조건을 동시에 만족하더라도 대표 `reason`은 **가장 먼저 매칭된 OOD 하나만** 기록됩니다(6장 참고). 다만 이 경우에도 `triggered_signals`에는 `["OOD", "DISAGREEMENT", "DIFFICULTY"]`처럼 동시에 만족한 신호가 모두 기록되므로, 대표 사유 하나만 남기는 `reason`과 달리 다중 신호 발현 여부는 `triggered_signals`로 확인할 수 있습니다(6장 참고). `triggered_signals`는 각 규칙이 매칭될 때마다 독립적으로 추가되는 부가 필드일 뿐, 위 Priority-ordered Routing 순서나 `decision`/`reason` 산출 로직 자체를 바꾸지 않습니다.

이전(구) 문서/구현에서는 `calibrated_probability`와 `disagreement` 2개 신호·4단계 판정만 존재했으나, 커밋 `b2d3fe3`(2026-09-03, "Joint Risk Router (OOD & Difficulty) 신호 연동 및 종합 라우팅 파이프라인 완성")로 OOD·Difficulty가 라우터에 통합되어 현재의 6단계 구조가 되었습니다. 이후 커밋 `49bc244`(2026-09-10, "JRR 라우팅 임계값 최적화 로직 전면 개편")에서 판정 로직/우선순위 변경 없이 `triggered_signals` 필드가 추가되었습니다.

---

## 5. Fail-Closed Behavior

`route_sample()` 최상단에서 4개 입력값의 NaN 여부를 가장 먼저 검사합니다.

```python
if np.isnan(p_calib) or np.isnan(disagreement) or np.isnan(ood_score) or np.isnan(difficulty_score):
    return {
        "initial_verdict": "HIGH_RISK_UNCERTAIN",
        "route": "DEEP_ANALYSIS",
        "calibrated_probability": -1.0,
        "disagreement": -1.0,
        "ood_score": 0.0,
        "difficulty_score": 0.0,
        "reason": "System Error: NaN values detected (Fail-Closed)"
    }
```

- 4개 입력 중 하나라도 NaN이면 무조건 `HIGH_RISK_UNCERTAIN` + `route="DEEP_ANALYSIS"`로 보냅니다(정상/악성으로 자동 판정하지 않음).
- **오염 표시(sentinel) 값이 신호마다 다릅니다.** `calibrated_probability`/`disagreement`는 `-1.0`(정상 범위 `[0,1]` 밖의 값)으로 표시되는 반면, `ood_score`/`difficulty_score`는 `0.0`으로 채워집니다 — `0.0`은 두 신호의 정상적인 관측값 범위 안에 있는 값이라, 다운스트림이 이 반환값을 원인 분석 없이 그대로 로그/집계에 사용하면 실제 관측치와 혼동될 수 있습니다. 문서화 목적상 이 비대칭은 사실 그대로 기록합니다.
- 커밋 이력상 이 로직은 "라우터 Fail-Open 보안 취약점 차단"(`33c51f8`, 4-way 통합 이전)이라는 명시적 보안 수정으로 도입되었고, OOD/Difficulty 통합(`b2d3fe3`) 시점에 4개 인자 전체로 확장되었습니다.

---

## 6. JRR Output Schema

### 현재 코드가 실제로 반환하는 dict

`route_sample()`의 반환값(`src/jrr/jrr_router.py:65-73`):

```json
{
  "initial_verdict": "AUTO_BENIGN | AUTO_MALICIOUS | HIGH_RISK_UNCERTAIN",
  "route": "FINAL | DEEP_ANALYSIS",
  "calibrated_probability": 0.0,
  "disagreement": 0.0,
  "ood_score": 0.0,
  "difficulty_score": 0.0,
  "reason": "string",
  "triggered_signals": []
}
```

이 필드명은 `docs/interface_spec.md` §4.1(Initial Triage Result)의 `initial_verdict`/`route`/`calibrated_probability`/`disagreement`/`ood_score`/`difficulty_score`/`reason`/`triggered_signals`와 **정확히 일치**합니다. 이는 커밋 `a957512`("fix: align JRR output fields with interface spec", 2026-09-07)에서 의도적으로 맞춘 결과이며, `triggered_signals`는 이후 커밋 `49bc244`(2026-09-10)에서 공식 필드로 추가되었습니다. (이전 버전 코드는 `decision`/`calibrated_prob`라는 다른 필드명을 썼으나 현재는 사용되지 않습니다.)

- `route`: `initial_verdict == "HIGH_RISK_UNCERTAIN"`이면 `"DEEP_ANALYSIS"`, 그 외에는 `"FINAL"` (`jrr_router.py:59-63`).
- `reason`: 여러 위험 신호를 전부 나열한 목록이 아니라, **4장 우선순위 규칙에서 최초로 매칭된 대표 사유 하나**입니다. `"Uncertain Probability"`는 별도의 불확실성 점수가 아니라, **확률이 `tau_low`와 `tau_high` 사이 그레이존에 걸렸을 때 붙는 reason 라벨**입니다(`docs/interface_spec.md` §4.4 CRITICAL, `docs/pipeline_architecture_v3.md` "Uncertain Probability 표현" 절에서 동일하게 재확인).
- `triggered_signals`: `reason`과 별개로, **동시에 발현된 모든 위험 신호**를 담는 배열입니다(`src/jrr/jrr_router.py:36-60`). 각 규칙(OOD → Disagreement → Difficulty → Uncertain Probability)이 독립적으로 검사되어 조건을 만족할 때마다 `"OOD"`/`"DISAGREEMENT"`/`"DIFFICULTY"`/`"UNCERTAIN_PROBABILITY"` 중 해당 값이 추가됩니다. 위험 신호가 하나도 없는 `AUTO_BENIGN`/`AUTO_MALICIOUS`에서는 빈 배열 `[]`입니다. 4장에서 설명한 Priority-ordered Routing과 대표 `reason` 산출 방식은 `triggered_signals` 도입 이후에도 그대로입니다.

### 파이프라인 표준 결과 객체와의 관계 (아직 코드로 조립되지 않음)

`docs/interface_spec.md` §4.1과 `docs/pipeline_architecture_v3.md` §2가 정의하는 전체 분석 결과 객체는 `calibrated_probability`를 `prediction.calibrated_probability`로, 나머지 3개 신호를 `risk_signals.{disagreement, ood_score, difficulty_score}`로 **중첩(nest)** 시킵니다. 그러나 `JointRiskRouter.route_sample()`이 실제로 반환하는 것은 **평평한(flat) dict**입니다. 이 중첩은 FastAPI 백엔드(아직 리포지토리에 구현 없음, 14장 참고)가 라우터 출력과 모델 예측값을 하나의 분석 레코드로 조립할 때 수행하도록 설계되어 있으며, 현재는 그 조립 코드 자체가 존재하지 않습니다.

### 레거시 데모(`tests/demo/01/demo.py`)는 현재 시그니처와 맞지 않음

`demo.py`는 여전히 `router.route_sample(p_calib, disagreement)`를 **인자 2개**로 호출합니다(`demo.py:156-157`). 하지만 현재 `route_sample()`은 `(p_calib, disagreement, ood_score, difficulty_score)` **4개의 위치 인자**를 요구하므로, 이 데모를 그대로 실행하면 `TypeError: route_sample() missing 2 required positional arguments`가 발생합니다. 또한 `verdict` 판정부는 여전히 `"AUTO_PASS"`/`"AUTO_QUARANTINE"`이라는 구용어와 비교하는데, 라우터는 `"AUTO_BENIGN"`/`"AUTO_MALICIOUS"`를 반환하므로 이 비교도 항상 실패합니다. **`demo.py`는 현재 라우터 인터페이스와 더 이상 호환되지 않는 레거시 코드이며, 사용 예시로 참고하면 안 됩니다.**

---

## 7. Evaluation Protocol

`src/preprocessing/README.md`(§ 분할 계약), `src/models/data_contract.py`, `docs/pipeline_architecture_v3.md` §7("모델 평가 Protocol") 세 곳이 동일하게 확정한 **시간 기반(week_id) 4분할**입니다.

| 분할 | 주차(week_id) | 행 수 | 역할 | 금지 |
|---|---|---:|---|---|
| **Train** | 0–33 | 2,720,000 | 모델 fit | 성능 보고 |
| **Validation** | 34–39 | 480,000 | 하이퍼파라미터 튜닝, early stopping, 모델 선택 | threshold 산출, 최종 성능 보고, 학습 포함 |
| **Calibration** | 40–45 | 480,000 | Isotonic Calibration + JRR 라우팅 threshold 선택 | 모델 선택, 학습 포함 |
| **Eval** (Final Eval 산출용) | 46–51 | 480,000 | 고정된 모델/threshold/정책의 성능 평가, 재튜닝 금지 | threshold 재조정 |
| **Lockbox / Challenge** | — | test 960,000 / challenge 6,315 | 전체 Pipeline Freeze 후 **최종 1회** 평가 | 개발 중 열람 |

- 순서: **Train → Validation(모델 확정) → Calibration(threshold freeze) → Final Eval(고정 성능 확인) → 전체 Pipeline Freeze → Lockbox / Challenge(단 1회)**.
- **Eval은 tuning에 사용되지 않습니다.** (`docs_eval_lockbox_policy.md` §2, `pipeline_architecture_v3.md` CRITICAL-01)
- **Engineering Eval vs Final Eval**: `tau_low`/`tau_difficulty`는 커밋 `49bc244`/`ed2ffd5`(2026-09-10)에서 Calibration 세트 단변수 순차 탐색으로 먼저 재확정됐다가, 이후 커밋 `06c8ffc`/`f4ce7a1`(2026-09-10)에서 두 변수를 동시에 탐색하는 **2차원 Grid Search**로 다시 확정되어 현재 공식 값은 `tau_low=0.65`/`tau_difficulty=6.0`입니다(9장). 이 값이 확정되기까지 Eval 세트로 반복 산출된 결과(9, 10, 11장에 인용된 수치)는 모두 개발 중 참고용 **Engineering Eval**로 구분합니다 — 이 Eval 세트는 이미 여러 차례 확인에 사용됐으므로 "미지의(unseen) 데이터"가 아닙니다. Threshold freeze 이후 별도로 실행·보고하는 결과만 공식 **Final Eval**이라고 부르며, 이 문서 작성 시점 기준 Final Eval은 아직 실행되지 않았습니다. Final Eval과 Lockbox/Challenge(전체 Pipeline Freeze 후 최종 1회 평가)는 서로 다른 단계이며 동일 개념으로 혼동하지 않습니다.
- **Top-500 feature 선택은 이 4-Way 재학습 과정에서 새로 정한 것이 아니라, 기존 TRUST-Triage 입력 계약(`top_feature_indices_500.npy`, `docs/feature_schema.md`)으로 고정된 값**입니다. `pipeline_architecture_v3.md`: "새 4-Way 재학습 과정에서 Top-500을 재선택하지 않음." LightGBM/XGBoost 모두 동일 인덱스를 사용하며 `data_contract.py::load_top_indices`가 무결성을 검증합니다.

---

## 8. Model Artifacts

### LightGBM (Primary Classifier)

| 항목 | 내용 |
|---|---|
| 파일명(현재) | `baseline_model_lightgbm_tuned_500_4way.pkl` |
| 학습 스크립트 | `src/models/tune_lightgbm.py` |
| 튜닝 방식 | Optuna (`TPESampler(seed=42)`, `N_TRIALS = 20`), Train에서 fit, Validation에서 `early_stopping(stopping_rounds=100)` + `validation_tpr_at_fpr`(목표 FPR 0.001) 기준 모델 선택 후 `best_iteration`으로 `n_estimators` 고정, Train 전체로 재학습 |
| MLflow 실험 | `trust-triage-baseline`, 태그 `split_type=temporal_week_id_4way`, `top_n=500` |
| **Validation 결과(모델 선택 근거)** | `TPR@FPR0.1% ≈ 92.49%`, `Best iteration = 998` (`docs/pipeline_architecture_v3.md` ③) — **Validation 세트 기준이며 Eval 최종 성능과는 구분됩니다.** |
| MLflow Run ID / sha256 | **확인 필요** — 리포지토리에 이 4-way 모델의 run id/hash가 기록되어 있지 않음 |

**레거시 구분 주의**: `baseline_model_lightgbm_tuned_500_v4_9120.pkl`은 4-way 분할 이전의 **구버전** 모델이며, 구 `docs/pipeline_architecture.md`에 적힌 "TPR@FPR 0.1% = 91.20%"는 **이 구버전 모델의 수치**입니다. `src/models/export_baseline_pkl.py`의 `run_id = "69a92b2033d346ac930fe2ec889199a2"`도 더 이전의 튜닝 전 참고용 모델(`baseline_model_500.pkl`)의 run id로, 현재 공식 4-way LightGBM과 무관합니다. 이 두 레거시 수치를 현재 4-way 모델 수치와 혼용하지 않도록 주의.

### XGBoost (Disagreement Comparator)

| 항목 | 내용 |
|---|---|
| 파일명(현재) | `baseline_model_xgb_500_4way_1000cap.pkl` |
| 학습 스크립트 | `src/models/train_xgboost_500.py` |
| 설정 | `XGBClassifier(n_estimators=1000, max_depth=6, learning_rate=0.05, random_state=42, tree_method="hist", eval_metric="auc", early_stopping_rounds=50)`, Train에서 fit, Validation에서 early stopping |
| MLflow 실험 | `TRUST-Triage-XGBoost-500` |
| **Validation 결과** | `best_iteration = 999`, `Validation AUC ≈ 0.99712` (`docs/pipeline_architecture_v3.md` ③) |
| 수렴 여부 | **"1000 iteration ceiling에서 종료되었으며 완전 수렴 모델로 해석하지 않는다"**(`pipeline_architecture_v3.md` 원문). `best_iteration=999`는 `n_estimators=1000` 상한 직전이므로, early stopping이 실질적으로 발동했다기보다 상한에 근접해 종료됐을 가능성을 배제할 수 없음 — 파일명 `1000cap`도 상한 설정을 의미할 뿐 수렴을 의미하지 않습니다. |
| 역할 | LightGBM과의 Disagreement 계산용 비교 모델일 뿐, 공식 판정 모델이 아님 |

---

## 9. Calibration Results

### tau_high (상한, 자동 악성 커트라인)

- **산출 코드**: `src/jrr/train_calibrator.py` — Calibration 세트에 대해 Isotonic 보정된 확률로 `roc_curve`를 계산하고 `fpr <= TARGET_FPR(0.001)`을 만족하는 마지막 지점의 threshold를 채택.
- **값**: `0.983645`.
- **선정 기준**: Calibration 세트의 FPR ≤ 0.1% 조건. Eval 결과로 재조정되지 않음.

### tau_low & tau_difficulty (Calibration 2차원 Grid Search, 현재 공식 값)

- **채택된 값**: `tau_low = 0.65`, `tau_difficulty = 6.0` — `jrr_router.py::JointRiskRouter.__init__`의 기본값이자 `docs/interface_spec.md`가 명시하는 현재 운영 기준.
- **선정 방식**: `tau_low`와 `tau_difficulty`는 JRR의 OR 조건 안에서 서로 상호작용합니다(둘 중 하나라도 걸리면 `HIGH_RISK_UNCERTAIN`). 한쪽을 고정한 채 다른 한쪽만 순차적으로 최적화하면 이 상호작용을 반영하지 못하는 순환 논리(Circular Reasoning) 문제가 생기므로, 두 변수를 **`src/jrr/optimize_threshold.py::optimize_grid_search()`로 동시에 2차원 Grid Search** 했습니다(`docs/risk_routing_simulation_test.md` §4). 탐색은 **Calibration 세트(48만 건) 전체**만 사용했으며 Eval 데이터는 이번 2차원 탐색에도 사용하지 않았습니다.
  - 후보 grid: `tau_low ∈ {0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80}` × `tau_difficulty ∈ {1.0, 2.0, ..., 10.0}` (총 70개 조합).
  - 목적함수: `Utility = Review Yield × (1 − 악성 누출률)` — 타율(Yield)과 악성 누출 방어를 함께 고려하는 단일 점수로, 조합마다 계산 후 내림차순 정렬.
  - Calibration 세트 기준 상위 결과(Top 5, `docs/risk_routing_simulation_test.md` §4.1):

    | Rank | tau_low | tau_diff | 심층분석 비율(건수) | Review Yield | 악성 누출 |
    |---:|---:|---:|---|---:|---:|
    | **1 (채택)** | **0.65** | **6.0** | **9.01% (43,240건)** | **74.90%** | **5,190건** |
    | 2 | 0.70 | 6.0 | 9.01% | 74.90% | 5,190건 |
    | 4 | 0.75 | 6.0 | 8.64% | 75.19% | 6,384건 |
    | 5 | 0.50 | 6.0 | 9.46% | 74.18% | 3,900건 |

    위 수치는 모두 **Calibration 세트**에서 후보 조합을 비교하기 위해 산출한 시뮬레이션 값이며, 실제 Eval 세트에 이 threshold를 고정 적용했을 때의 결과는 별도입니다(10장 Eval Results 참고).
  - **선정 근거**: `tau_low=0.65`/`tau_difficulty=6.0` 조합이 정의된 후보 grid와 목적함수 범위 내에서 Utility 기준 최적 조합으로 나타났습니다. 순차 최적화 방식으로 찾았던 이전 부분 최적점(`tau_low=0.65`, `tau_difficulty=5.0`)과 비교하면, 심층분석 큐 트래픽을 추가로 줄이면서(9.08%→9.01%대) Review Yield도 74.79%→74.90%로 소폭 개선되는 지점입니다.
- **이전 값(이력, 순차·단변수 최적화)**: 이전 개정에서는 `tau_low`와 `tau_difficulty`를 하나씩 고정하며 순차적으로 최적화해 `tau_low=0.60`, `tau_difficulty=5.0`(Calibration 세트 기준 Review Yield 71.83%)을 채택했습니다. 이 방식은 두 변수의 상호작용을 반영하지 못했기 때문에, 이후 2차원 Grid Search로 대체되었습니다. 과거 `optimize_threshold.py`의 탐색 범위가 `0.90~tau_high`로 한정되어 그보다 더 이전 채택값(`0.60`)을 재현하지 못하던 문제는 커밋 `49bc244`에서 먼저 해결되었고, 이후 커밋 `06c8ffc`/`f4ce7a1`에서 순차 최적화 자체가 2차원 Grid Search로 전면 교체되었습니다.

### tau_disagree

- **값**: `0.3` (고정).
- **선정 기준**: `docs/risk_routing_simulation_test.md` §2.2는 "앙상블 모델 간 의견 불일치도는 인식론적 불확실성과 매우 높은 상관관계를 갖는다"는 **정성적** 근거만 제시합니다. `tau_low`/`tau_difficulty`처럼 Calibration/Eval 세트에서 threshold 후보를 그리드 탐색한 코드·로그는 확인되지 않습니다. **선정 근거 문서(정량적 그리드 탐색)는 확인 필요.**

### tau_ood

- **값**: `0.0`.
- **선정 기준**: 별도 그리드 탐색이 아니라 `sklearn.ensemble.IsolationForest.decision_function()`의 표준 관례(0 미만 = 이상치)를 그대로 채택.

### tau_difficulty — 과거 순차 탐색 이력 (상세)

`tau_difficulty`는 위 "tau_low & tau_difficulty" 절의 2차원 Grid Search로 `tau_low`와 함께 동시에 재확정되었습니다(현재 공식 값 `6.0`). 아래는 2차원 Grid Search 이전, `tau_difficulty`만 단독으로 순차 탐색하던 시기의 이력입니다.

- **최초(Engineering Eval, 해결됨)**: Eval 세트(48만 건) 기준 1.0~10.0 그리드 탐색으로 `5.0`이 선택되었으나, threshold 선정에 Eval을 사용한 것으로 판단되어 재작업되었습니다(10장 Engineering Eval Results 참고).
- **1차 재작업(Calibration, 단변수 순차 탐색)**: `tau_low=0.60`으로 고정한 채 `tau_difficulty`만 Calibration 세트(48만 건)에서 `1.0~10.0` 후보로 재탐색해 다시 `5.0`(Review Yield 71.83%)이 선정되었습니다.

  | 임계값(tau_diff) | 심층분석 비율 | 심층분석 건수 | Review Yield | 정상 중 악성 누출 건수 |
  |---:|---:|---:|---:|---:|
  | 1.0 | 55.81% | 267,894건 | 69.85% | 4,138건 |
  | 4.0 | 22.78% | 109,366건 | 61.80% | 4,860건 |
  | **5.0 (당시 확정)** | **14.15%** | **67,910건** | **71.83%** | **4,954건** |
  | 6.0 | 9.08% | 43,596건 | 74.79% | 4,970건 |
  | 10.0 | 6.00% | 28,802건 | 68.35% | 5,030건 |

- **2차 재작업(현재, Calibration 2차원 Grid Search)**: `tau_low=0.60`으로 고정한 채 탐색한 위 1차 재작업은 `tau_low` 자체도 변경 가능하다는 점을 반영하지 못하는 순환 논리 문제가 있었습니다. 이를 해소하기 위해 `tau_low`와 `tau_difficulty`를 동시에 2차원 Grid Search하여 `tau_low=0.65`, `tau_difficulty=6.0`으로 다시 확정했습니다(위 "tau_low & tau_difficulty" 절 참고). 최종 `tau_difficulty=6.0`은 **Calibration 세트에서 확정(freeze)**되었으며, Eval 세트는 이번 2차원 탐색에도 사용되지 않았습니다.

---

## 10. Engineering Eval Results (Threshold Freeze 이전 기록)

> **Final Eval 아님**: 아래 수치는 Eval 세트(48만 건)로 산출된 **Engineering Eval** 결과입니다. Eval 세트는 개발 중 여러 차례(순차 최적화 단계, 2차원 Grid Search 단계) 반복해서 성능을 확인하는 용도로 이미 사용되었으므로 "미지의(unseen) Eval 데이터"가 아닙니다. threshold freeze 이후 정책에 따라 별도로 실행·보고하는 공식 **Final Eval**은 이 문서 작성 시점 기준 아직 수행되지 않았으며, 아래 Engineering Eval 수치를 Final Eval로 표기하지 않습니다(7장 참고). Final Eval과 Lockbox/Challenge(최종 1회 평가)는 서로 다른 단계이며 동일 개념으로 합치지 않습니다.

`evaluate_jrr.py`(+ `_jrr_eval_core.py`)가 산출한 Engineering Eval 결과입니다. ROC-AUC/TPR/FPR/ECE/Brier Score/Confusion Matrix는 `tau_high=0.983645`(변경 없음)와 확률 Calibration에만 의존하므로 `tau_low`/`tau_difficulty` 값과 무관하게 동일합니다. Review Yield와 HIGH_RISK_UNCERTAIN(Deep Analysis) 유입량은 `tau_low`/`tau_difficulty`에 의존하므로 threshold가 바뀌면 함께 바뀝니다 — 아래는 **현재 공식 값(`tau_low=0.65`, `tau_difficulty=6.0`)을 Eval 세트에 적용한 최신 결과**입니다.

| 지표 | 값 | 비고 |
|---|---|---|
| ROC-AUC (Eval) | 0.997783 | `tau_low`/`tau_difficulty`와 무관 |
| 실측 TPR @ `tau_high=0.983645` (Eval) | 0.8911 (89.11%) | 동일 |
| 실측 FPR @ `tau_high=0.983645` (Eval) | 0.0012 (0.12%) | 동일 |
| ECE | 0.0031 | 동일 |
| Brier Score | 0.0163 | 동일 |
| Confusion Matrix (Eval, n=480,000) | TP=213,866 / FP=296 / TN=239,704 / FN=26,134 | 동일 |
| **Review Yield** (심층분석 큐 전체 기준, 일일 예산 제한 없음) | **79.19%** | `tau_low=0.65`/`tau_difficulty=6.0` 적용 결과 |
| **HIGH_RISK_UNCERTAIN / Deep Analysis 유입** (Eval, n=480,000) | **55,114건 (11.48%)** | 동일 |
| Kill Test FPR | 0.0000 (0%) | `tau_low`/`tau_difficulty`와 무관 |
| OOD 방어 성공률(OOD Score < 0.0 샘플 중 `HIGH_RISK_UNCERTAIN` 라우팅 비율) | 100.00% | OOD로 판별된 샘플이 JRR 정책에 따라 모두 `HIGH_RISK_UNCERTAIN`으로 라우팅되었다는 **라우팅 동작 검증**이며, OOD 탐지 정확도가 100%라는 의미는 아님(11장 참고) |
| AUTO_BENIGN / AUTO_MALICIOUS 개별 건수 (Eval, n=480,000) | **미제공 — 확인 필요** | `HIGH_RISK_UNCERTAIN`을 제외한 나머지 424,886건(88.52%)의 두 판정 간 분할은 아직 문서화되지 않음(15장 TBD) |

**정확한 표현**: Calibration에서 목표 FPR ≤ 0.1% 조건으로 `tau_high=0.983645`를 선정했고, 이를 고정 적용한 Eval 실측 결과 TPR **89.11%**, 실측 FPR **0.12%**를 기록했습니다. Calibration 시점의 목표 FPR(0.1%)과 Eval에서 실측된 FPR(0.12%)은 서로 다른 값이며 "TPR 89.11% @ FPR 0.1%"처럼 하나의 조건으로 뭉뚱그려 표현하지 않습니다.

> **레거시 수치와 혼동 금지**: 구 `docs/pipeline_architecture.md`의 "TPR@FPR 0.1% = 91.20%"는 4-way 분할 이전 구버전 LightGBM의 수치이며 위 Eval 결과와 다른 모델·다른 데이터 분할 기준입니다.

**이전 threshold 적용 결과(이력)**: `tau_low=0.60`/`tau_difficulty=5.0`(순차 최적화 결과)을 Eval 세트에 적용했던 이전 기록은 Review Yield 74.90%, HIGH_RISK_UNCERTAIN 77,784건(16.20%)이었습니다(`docs/risk_routing_simulation_test.md` 구버전 §5). 현재 공식 threshold(`0.65`/`6.0`)로 대체되며 위 79.19%/55,114건(11.48%)이 최신 값입니다.

**Review Yield 계산 방식 변경 참고**: `docs_eval_lockbox_policy.md` §7은 원래 "검토예산 1/5/10/20%"별 정책 비교를 요구하지만, 현재 `_jrr_eval_core.py::calculate_review_yield()`는 예산 제한 없이 `HIGH_RISK_UNCERTAIN` 큐 전체를 대상으로 Yield를 계산합니다(함수 docstring: "현재 예산 제한 정책 유보에 따라, 예산 제약 없이 큐 전체를 대상으로 계산"). 즉 예산 기반 비교 정책은 아직 구현되지 않고 **보류(deferred)** 상태이며, 위 79.19%는 예산 제약이 없는 전량 기준 수치입니다.

---

## 11. Risk Signal Analysis

> **주의 — 아래 세부 수치는 이전 threshold(`tau_low=0.60`, `tau_difficulty=5.0`) 기준입니다.** `docs/risk_routing_simulation_test.md`(48만 건 Eval 세트 기준)에 남아 있는 신호별 세부 breakdown은 2차원 Grid Search로 `tau_low=0.65`/`tau_difficulty=6.0`이 확정되기 이전 시점의 Engineering Eval 기록입니다. `ood_score`/`disagreement`의 원시 판정 기준(`tau_ood=0.0`, `tau_disagree=0.3`)은 이번 threshold 재확정과 무관하게 그대로이므로 OOD/Disagreement 건수(아래)는 현재도 유효하지만, `difficulty`·그레이존·Signal Overlap·전체 큐 총량처럼 `tau_low`/`tau_difficulty`에 의존하는 수치는 새 threshold(`0.65`/`6.0`) 기준으로 아직 재산출되지 않았습니다 — 현재 공식 총량은 10장의 **55,114건(11.48%)**, Review Yield **79.19%**를 참고하십시오. 신호별 breakdown 재산출은 15장 TBD로 남겨둡니다.

- **OOD 유입**: `ood_score < 0.0`인 샘플 **3,384건**(전체의 0.71%)이 식별되었고, 이 중 100%가 `HIGH_RISK_UNCERTAIN`으로 라우팅되었습니다(OOD 방어 성공률 100%, 10장). 이 3,384건 중 "실제로는 정상 파일인데 모델이 0.98 이상으로 확신했던" 사례가 2건 있었고, 이 2건이 OOD 조건으로 격리되어 Kill Test FPR 0%에 기여했습니다. (`tau_ood` 불변이므로 현재도 유효)
- **Disagreement 유입**: `disagreement >= 0.3`인 샘플 **약 11,728건**(전체의 2.44%)이 100% `HIGH_RISK_UNCERTAIN`으로 라우팅되었습니다. (`tau_disagree` 불변이므로 현재도 유효)
- **Difficulty 유입 (이전 threshold `5.0` 기준 — 이력)**: 이전 threshold 조합(`tau_low=0.60`, `tau_difficulty=5.0`)에서, 9장 표의 `difficulty_score >= 5.0`(다른 3개 신호와 OR 결합된 전체 시스템 기준)일 때 최종 심층분석 큐가 77,784건(16.2%)이었습니다. 이와 별개로 `difficulty >= 5` **단독** 조건만으로는 정상 파일 9,068건(3.78%)·악성 파일 37,146건(15.48%)이 식별되었습니다(`risk_routing_simulation_test.md` §6.2, 4개 조건 결합 이전의 difficulty 단독 통계, 구버전). 현재 공식 threshold(`tau_difficulty=6.0`) 기준의 동등한 breakdown은 아직 산출되지 않았습니다 — 확인 필요.
- **Probability Gray-zone 유입**: 문서는 "OOD·Disagreement·Difficulty가 없는 파일 중에서도 그레이존(현재 기준 `0.65~0.9836`)에 해당하면 100% 안전하게 심층분석으로 분기되었다"고 정성적으로만 서술하며, **정확한 건수는 원문에 명시되어 있지 않습니다 — 확인 필요.**
- **Signal Overlap (이전 threshold `0.60`/`5.0` 기준 — 이력)**: 48만 건 전체 기준 (이전 threshold 조합으로 산출됨, 현재 threshold 기준 재산출 필요)
  | 매칭된 조건 수 | 건수 | 비율 |
  |---|---:|---:|
  | 0개(자동 정상/악성 직행) | 402,216 | 83.80% |
  | 1개 | 69,924 | 14.57% |
  | 2개 | 7,658 | 1.60% |
  | 3개 | 202 | 0.04% |
  | 4개 | 0 | 0.00% |

  2개 이상 겹치는 샘플은 전체의 1.64%입니다.

**해석상 주의(원문 스스로도 명시)**:
- 신호 간 overlap이 낮다는 관측(1.64%)은 **"이 신호들이 통계적으로 독립"임을 증명하지 않습니다.** 표본과 신호 정의에 따라 우연히 낮게 관측될 수 있습니다.
- "OOD로 표시된 샘플이 100% `HIGH_RISK_UNCERTAIN`으로 갔다"는 결과는 **OOD 탐지 정확도가 100%라는 의미가 아니라**, `ood_score < tau_ood`이면 무조건 `HIGH_RISK_UNCERTAIN`으로 보내도록 짜여진 **JRR 라우팅 규칙이 설계대로 정상 동작했다는 검증**일 뿐입니다. `docs/pipeline_architecture_v3.md` CRITICAL-02 원문: "OOD로 판별된 샘플이 HIGH_RISK로 라우팅되는 것은 라우팅 동작 검증이며, 그 자체가 OOD 탐지 정확도 100%를 의미하지 않는다."

---

## 12. Deep Analysis Integration

JRR 이후 흐름은 `docs/pipeline_architecture_v3.md`(설계) + `docs/static-analysis/deep_analysis.md`(실제 `DeepAnalysisOrchestrator` 코드 계약, `src/trust_triage/deep_analysis/`) 기준입니다.

```
HIGH_RISK_UNCERTAIN
  → Tier 1: CAPA + FLOSS (정적 분석, 같은 단계에서 함께 실행)
      ├─ ATT&CK 근거 충분(EvidenceSufficiencyPolicy 점수 ≥ 0.55) → LLM 해석 → COMPLETE
      └─ 근거 부족/상충 또는 CAPA 실패
  → Tier 2: Speakeasy (비동기 Task Queue + Worker)
      ├─ 근거 충분 → LLM 해석 → COMPLETE
      └─ 근거 부족 또는 실패
  → (선택, 기본 비활성화) Ghidra backend CAPA — `enable_ghidra_capa=True`일 때만 1회 실행
      ├─ 활성화 후 정상 종료 → LLM 해석 → COMPLETE
      ├─ 비활성화 상태 → UNKNOWN + MANUAL_REVIEW
      └─ 활성화 후 오류 → FAILED
  → MonoGPT(Claude) 기반 LLM 해석(`MonoGPTClaudeInterpreter`, 환경변수로 활성화) — 정규화된 Evidence만 전달, Raw PE/원본 리포트는 전송하지 않음
  → Final Assessment (BENIGN / MALICIOUS / UNCERTAIN)
       └─ UNCERTAIN → Analyst Review → 필요 시 Ghidra 수동 분석

AUTO_BENIGN / AUTO_MALICIOUS
  → route = FINAL (자동화 종료, 심층분석 미수행)
```

- **Tier 3 명칭 주의**: 실제 코드 계약(`docs/static-analysis/deep_analysis.md`, `DeepAnalysisOrchestrator`)은 3번째 Tier를 **"Ghidra backend CAPA"(기본값 비활성화)**로 구현합니다. 반면 상위 설계 문서 `docs/pipeline_architecture_v3.md`의 다이어그램은 이 확장 지점을 **"CAPE / External Behavioral Report"**로 표기합니다. 두 문서가 가리키는 "선택적 3차 확장 Tier"라는 개념은 같지만 **실제로 구현된 코드는 Ghidra CAPA**이므로, "현재 코드와 문서가 충돌하면 코드를 기준으로 삼는다"는 원칙에 따라 이 문서는 Ghidra CAPA를 실제 Tier 3로 기술합니다.
- **EvidenceSufficiencyPolicy**(`deep_analysis.md`)의 0.55 임계값은 Tier 진입 여부만 결정하는 **심층분석 내부 점수**이며, JRR의 `calibrated_probability`/`risk_score`와는 다른 별개의 지표입니다 — 혼동 금지.
- JRR은 심층분석 로직 자체(CAPA/FLOSS/Speakeasy/Ghidra 실행, ATT&CK 매핑, LLM 해석)를 수행하지 않고, **"어떤 샘플에 추가 분석 자원을 쓸지"만 결정하는 라우터**입니다.

---

## 13. XAI Relationship

- **SHAP은 LightGBM raw model output(원시 점수)의 설명입니다.** `shap.TreeExplainer(model, model_output="raw")`로 raw score를 설명하며, `docs/shap-explanation-module.md`: **"calibration 이후의 `calibrated_probability`는 설명하지 않는다"**고 명시. `docs/interface_spec.md` §5 CRITICAL도 동일하게 재확인합니다.
- **SHAP 대상 모델, 현재 4-way 공식 모델과 정렬 완료(해결됨)**: SHAP 모듈의 공식 대상은 이제 8장의 현재 4-way JRR 파이프라인이 쓰는 `baseline_model_lightgbm_tuned_500_4way.pkl`과 **동일한 아티팩트**입니다(`src/trust_triage/explanation/shap_lightgbm.py:9`, `docs/shap-explanation-module.md` §2). 이전 버전에서 공식 대상이었던 구버전 `baseline_model_lightgbm_tuned_500_v4_9120.pkl`은 더 이상 SHAP 설명 대상이 아닙니다.
- **Top-500 feature contract/order 검증 완료**: `LightGBMShapExplainer` 초기화 시 selection manifest(`docs/feature-extraction/feature-selection-ember-v3-top500.json`)와 `data/top_feature_indices_500.npy`의 feature 수·순서·SHA-256·schema version을 모두 대조하며, 하나라도 어긋나면 `FeatureOrderingError`로 fail-fast합니다(`shap-explanation-module.md` §5). 관련 계약 테스트(`test_documented_ember_schema_matches_runtime_schema`, `test_top500_selection_manifest_matches_runtime_schema`) 2건이 모두 통과합니다.
- **출력 필드명 정렬 완료**: `explain()`의 공개 출력(`to_dict()`)은 `docs/interface_spec.md` §5와 동일하게 `feature_name`/`feature_value`/`shap_value`/`direction`을 반환합니다(`group`/`model_input_index`/`source_index`는 내부 추적용 추가 필드). 기존 Python 속성 `name`/`contribution`은 내부 호환성 목적으로만 유지되며, 대외 공개 스키마는 `interface_spec.md`와 일치합니다.
- **검증 상태**: `pytest tests/test_shap_lightgbm.py` 28건 통과. 합성 500차원 입력 3건에 대해 실제 TreeExplainer로 `base_value + sum(contributions) == LightGBM raw score` raw-score additivity를 재검증했고, 실제 PE 파일 1건을 `Feature Extraction → Top-500 선택 → 공식 4-way LightGBM → SHAP` 전 구간으로 수동 E2E 실행해 성공을 확인했습니다(자동화된 PE E2E 회귀 테스트는 아직 없음, 15장 참고).
- **역할 구분**:
  - `SHAP` = **Model Evidence** — ML 모델이 왜 그런 raw score를 냈는지에 대한 기여도 설명(Top-500 중 Top-5).
  - `CAPA / FLOSS / Speakeasy / MITRE ATT&CK Evidence` = **Behavioral Evidence** — 심층분석 도구가 실제로 관찰한 행위 기반 근거.
  - 둘은 서로 다른 목적으로 별도 필드(`top_features` vs `evidence`)에 저장·표시하며, `calibrated_probability`나 `initial_verdict`를 SHAP이 설명한다고 서술하면 안 됩니다.

---

## 14. Service Integration

`docs/interface_spec.md`, `docs/service_architecture.md`(둘 다 2026-09-07, 상태: Draft) 기준 설계입니다. **FastAPI 백엔드는 이 세션 시점 리포지토리(`src/` 하위)에 구현되어 있지 않습니다** — `src/` 아래에는 `jrr`, `models`, `preprocessing`, `trust_triage`(feature_extraction/explanation/static_analysis/dynamic_analysis/deep_analysis)만 있고 API/서비스 계층 코드는 없습니다.

설계상 의도된 흐름:

```
AUTO_BENIGN      → route = FINAL
AUTO_MALICIOUS   → route = FINAL
HIGH_RISK_UNCERTAIN → route = DEEP_ANALYSIS → CAPA+FLOSS → (필요 시) Task Queue → Speakeasy Worker → LLM Analyst Assist → Final Assessment
```

- `docs/interface_spec.md`는 상태 조회(`current_stage`), Batch(`batch_id`+개별 `analysis_id`), Task Queue 메시지(SQS 후보) 등을 정의하지만 다수가 **TBD**입니다(§22): Task Queue 최종 확정, PostgreSQL 배포 방식, Batch 파일 수/크기 제한, `final_verdict` Enum, Final Assessment 자동 판정 로직 등.
- **`dashboard/app.py`(현재 `main`)는 위 인터페이스 계약과 다른 필드명을 쓰는 단순 단일 목업**입니다(`build_mock_result()`): `route: "Deep Analysis"`(문자열 표기가 `"DEEP_ANALYSIS"`가 아님), `initial_verdict: "High-Risk Uncertain"`(`"HIGH_RISK_UNCERTAIN"`이 아님), `ood: True`(불리언, `ood_score`가 아님), `risk_score: 82`(현재 JRR 공식 출력에 없는 필드, 15장 참고). 즉 현재 대시보드는 `interface_spec.md`의 CRITICAL 규칙이 확정되기 이전에 작성된 것으로 보이는 **자체 목업 스키마**를 쓰고 있어, 실제 JRR 출력이나 `interface_spec.md`와 아직 정렬되어 있지 않습니다.
- (참고) 다중 파일/ZIP 배치 업로드 UI가 담긴 `dashboard/app.py` 버전은 이번 조사에서 확인한 `main`에는 없었습니다. 그런 코드가 존재한다면 이는 아직 `main`에 병합되지 않은 별도 feature 브랜치의 구현이며, 이 문서에는 포함하지 않았습니다(사용자 지시: unmerged 브랜치 구현을 현재 공식 설계로 섞지 말 것).

---

## 15. Known Limitations

- **`tau_disagree`/`tau_ood`의 정량적 선정 근거 부재**: `tau_low`/`tau_difficulty`는 Calibration 데이터 그리드 탐색 기록이 문서화되어 있지만, `tau_disagree=0.3`과 `tau_ood=0.0`은 정성적 근거(상관관계 서술, 라이브러리 컨벤션)만 있고 그리드 탐색 로그는 확인되지 않습니다(9장).
- **Kill Test/OOD 검증이 내부 시뮬레이션 방식**: 별도의 외부 미지 OOD 데이터셋을 주입하는 대신, Eval 세트 자체에서 `ood_score < 0`인 샘플을 "가상의 OOD 테스트셋"으로 재활용합니다(`risk_routing_simulation_test.md` §2 "새로운 외부 데이터셋을 수집하는 대신"). 이는 팀이 의도적으로 선택한 방법론이지만, 완전히 독립적인 held-out OOD 벤치마크는 아닙니다.
- **Review Yield 예산 정책 보류**: `docs_eval_lockbox_policy.md` §7이 요구하는 "검토예산 1/5/10/20%별 비교"는 현재 구현되지 않았고, `calculate_review_yield()`는 예산 제약 없이 큐 전체를 기준으로 계산합니다(10장).
- **Deep Analysis Tier 3 명칭 불일치**: 코드 계약(`deep_analysis.md`: Ghidra CAPA, 기본 비활성화)과 상위 설계 문서(`pipeline_architecture_v3.md`: CAPE)가 다른 이름을 사용합니다(12장).
- **SHAP — Backend inference와 모델 인스턴스 공유 wiring 미구현**: SHAP 대상 모델은 현재 4-way 공식 LightGBM(`baseline_model_lightgbm_tuned_500_4way.pkl`)과 정렬됐지만(13장), FastAPI/Streamlit 등 서비스 계층이 아직 없어 inference가 로드한 것과 **동일한 `LGBMClassifier` 인스턴스를 SHAP explainer에 전달하는 배선**은 구현되어 있지 않습니다(`shap-explanation-module.md` §8).
- **SHAP — `models/`/`data/` artifact 경로 미통일**: 공식 artifact 위치는 `models/baseline_model_lightgbm_tuned_500_4way.pkl`이지만 현재 JRR inference 스크립트는 같은 파일명을 `data/` 아래에서 별도로 staging해 로드합니다(`shap-explanation-module.md` §2). 서비스 통합 전 두 경로를 하나로 통일해야 합니다.
- **SHAP — `top_feature_indices_500.npy` 배포 경로 미정**: 모델 artifact 자체에는 feature metadata가 없어, 배포 시 모델과 `data/top_feature_indices_500.npy`, selection manifest를 하나의 검증 가능한 bundle로 함께 배치하는 방식이 아직 정해지지 않았습니다(`shap-explanation-module.md` §8). 자동화된 PE E2E 회귀 테스트 추가도 마찬가지로 남은 작업입니다.
- **레거시 데모(`tests/demo/01/demo.py`)가 현재 라우터 시그니처와 불일치해 실행 시 오류 발생**(6장) — 사용 예시로 삼지 말 것.
- **서비스 계층(FastAPI/PostgreSQL/Task Queue/대시보드 연동) 대부분 미구현/TBD**: JRR 자체는 구현·평가가 끝났지만, 이를 감싸는 API/DB/큐/프론트엔드 통합은 아직 설계 초안(Draft) 단계입니다(14장).
- **`risk_score`는 현재 공식 JRR 설계/코드에 존재하지 않습니다.** `docs/pipeline_architecture_v3.md` CRITICAL-03: "risk_score는 필수 런타임 출력으로 간주하지 않는다." `dashboard/app.py`의 목업 데이터에만 레거시로 남아 있습니다(14장). Weighted Risk Score 방식 자체도 현재 공식 설계에 없습니다(4장).
- **Final Eval 미실행**: `tau_low=0.65`/`tau_difficulty=6.0`이 Calibration 세트 2차원 Grid Search로 freeze된 이후의 공식 Final Eval이 아직 별도로 실행·보고되지 않았습니다. 10, 11장에 인용된 수치는 개발 중 반복 확인해 온 Engineering Eval 기록입니다(7장 참고).
- **§11 Risk Signal Analysis의 신호별 breakdown이 현재 threshold(`0.65`/`6.0`) 기준으로 재산출되지 않음**: Difficulty 단독/결합 건수, Probability Gray-zone 건수, Signal Overlap 표는 모두 이전 threshold(`tau_low=0.60`, `tau_difficulty=5.0`) 기준 수치입니다. 현재 공식 총량(HIGH_RISK_UNCERTAIN 55,114건/11.48%, 10장)은 확인되었으나, 신호별 세부 breakdown 재산출은 아직 없습니다(11장 참고).
- **AUTO_BENIGN/AUTO_MALICIOUS 개별 건수(현재 threshold 기준) 미제공**: 10장의 최신 Eval 결과는 HIGH_RISK_UNCERTAIN 총량(55,114건/11.48%)만 확인되었고, 나머지 424,886건이 AUTO_BENIGN/AUTO_MALICIOUS로 어떻게 나뉘는지는 아직 문서화되지 않았습니다 — 확인 필요.

**해결된 항목(이전 버전에서 제거)**:
- ~~대표 reason 하나만 반환~~ — `triggered_signals` 필드 도입(커밋 `49bc244`)으로 해결. 동시에 발현된 모든 위험 신호는 `triggered_signals`에, 대표 사유는 `reason`에 함께 반환됩니다(4, 6장).
- ~~`optimize_threshold.py`가 채택된 `tau_low=0.60`을 재현하지 못함~~ — 탐색 범위가 `0.50~0.98` 전체로 개편되어 `0.60`을 실제로 재현합니다(9장, 이후 2차원 Grid Search로 추가 대체됨).
- ~~`tau_difficulty` 선정에 Eval 세트가 관여했을 가능성~~ — Calibration 세트 전체 재탐색으로 `5.0`이 다시 확정되어 해소되었습니다(9장, 이후 2차원 Grid Search로 `6.0`으로 추가 대체됨).
- ~~`tau_low`/`tau_difficulty`를 한쪽씩 고정해 순차 최적화하는 순환 논리(Circular Reasoning)~~ — 두 변수를 동시에 탐색하는 2차원 Grid Search(`optimize_grid_search()`, 커밋 `06c8ffc`/`f4ce7a1`)로 대체되어 해결. 현재 공식 값은 `tau_low=0.65`, `tau_difficulty=6.0`입니다(9장).
- ~~SHAP 대상 모델이 구버전(`_v4_9120`)이며 현재 4-way 파이프라인과 분리되어 있음~~ — SHAP 공식 대상이 `baseline_model_lightgbm_tuned_500_4way.pkl`로 전환되어 해결(13장).
- ~~SHAP 출력 필드명이 `interface_spec.md`와 불일치~~ — 공개 `to_dict()` 스키마가 `feature_name`/`feature_value`/`shap_value`/`direction`으로 정렬되어 해결(13장).

---

## 16. Reproducibility / Relevant Files

| File | Role |
|---|---|
| `src/jrr/jrr_router.py` | `JointRiskRouter` — 실제 라우팅 엔진 (4신호, 6단계 Priority-ordered Rule) |
| `src/jrr/__init__.py` | `from .jrr_router import JointRiskRouter` — 패키지 진입점(현재 정상 동작 확인) |
| `src/jrr/train_calibrator.py` | Isotonic Calibration 학습, `tau_high` 산출, `jrr_calibrator_4way.pkl` 생성 |
| `src/jrr/optimize_threshold.py` | Calibration 세트(48만 건) 전체 기반 `tau_low`×`tau_difficulty` **2차원 Grid Search**(`optimize_grid_search()`) — 커밋 `06c8ffc`/`f4ce7a1`에서 기존 단변수 순차 탐색을 대체, 현재 채택값 `0.65`/`6.0` 산출(9장) |
| `src/jrr/disagreement.py` | LightGBM/XGBoost 원시 확률로부터 배치 Disagreement 계산·저장 |
| `src/jrr/risk_signals.py` | OOD(IsolationForest, seed 42 무작위 10만 샘플) 모델 학습 + Analysis Difficulty 인덱스 동적 매핑 |
| `src/jrr/generate_raw_probas.py` | Eval 세트에 대한 LightGBM/XGBoost 원시 확률 생성 |
| `src/jrr/_jrr_eval_core.py` | 평가 지표 공용 함수: `calculate_ece`, `calculate_review_yield`, `calculate_true_tpr`, `run_ood_and_kill_test` |
| `src/jrr/evaluate_jrr.py` | 최종 Eval 실행 스크립트 (ECE/Brier/Review Yield/ROC-AUC/Confusion Matrix/OOD 방어율/Kill Test → MLflow) |
| `src/models/tune_lightgbm.py` | LightGBM 4-way 학습/튜닝 (Optuna) |
| `src/models/train_xgboost_500.py` | XGBoost 4-way 학습 (disagreement 비교 모델) |
| `src/models/data_contract.py` | 4분할(tr/val/calib/eval) row-count·스키마 계약 검증 |
| `docs/pipeline_architecture_v3.md` | **현재 최신** 전체 파이프라인 설계 (2026-09-07, 코드와 실질적으로 1:1 일치) |
| `docs/interface_spec.md` | 서비스 컴포넌트 간 데이터 계약 (JRR 출력 필드명의 근거) |
| `docs/service_architecture.md` | 서버 배치/AWS/Queue/Worker 구조 |
| `docs/risk_routing_simulation_test.md` | 4신호 라우팅 시뮬레이션 방법론 + Calibration 기반 `tau_low`×`tau_difficulty` 2차원 Grid Search 결과(§4, 현재 공식값 `0.65`/`6.0`) + Engineering Eval 실측 결과 원본(§5-§7, 신호별 breakdown은 구 threshold `0.60`/`5.0` 기준 — 11장 참고) |
| `docs/docs_eval_lockbox_policy.md` | 지표/threshold/lockbox/kill-test 공식 정책 |
| `docs/feature_schema.md` | PEFormatWarnings(2480–2568) 등 전체 feature 스키마 |
| `docs/static-analysis/deep_analysis.md` | Tiered 심층분석 계약 (`DeepAnalysisOrchestrator`, 실제 Tier 3 = Ghidra CAPA) |
| `docs/shap-explanation-module.md` | SHAP 설명 모듈 — 대상 모델 `baseline_model_lightgbm_tuned_500_4way.pkl`로 정렬 완료, Top-500 contract/order 검증 완료, 출력 스키마 `interface_spec.md`와 정렬. 서비스 계층(Backend wiring, `models/`/`data/` 경로 통일, `.npy` 배포)은 아직 미구현 |
| `src/trust_triage/explanation/shap_lightgbm.py` | `LightGBMShapExplainer` — TreeSHAP 계산, feature ordering 검증, Top-K 매핑 (`model_output="raw"`) |
| `tests/test_shap_lightgbm.py` | SHAP 단위/공식 artifact 통합 테스트, 28건 통과 |
| `docs/pipeline_architecture.md` | **레거시(v3로 대체됨)** — 91.20%, 구 필드 스키마 등 현재 코드와 불일치하는 구버전 |
| `dashboard/app.py` | Streamlit 대시보드 (현재 `main`에는 단일 목업만 존재, `interface_spec.md`와 필드명 불일치) |
| `tests/demo/01/demo.py`, `DEMO_SETUP.md` | **레거시, 현재 라우터와 호환 불가** — 참고용으로도 사용 금지 |

---

## 17. Final Summary

JRR은 EMBER2024 기반 LightGBM Baseline의 원시 확률을 Isotonic Calibration으로 보정한 뒤, **Calibration 세트(48만 건) 전체를 대상으로 `tau_low`×`tau_difficulty`를 2차원 Grid Search로 동시 확정·freeze한** 확률 임계값(`tau_high=0.983645`: FPR≤0.1% 기준, `tau_low=0.65`)에 더해 LightGBM–XGBoost 간 Disagreement(`tau_disagree=0.3`), Isolation Forest 기반 OOD Score(`tau_ood=0.0`), PEFormatWarnings 기반 Analysis Difficulty(`tau_difficulty=6.0`, `tau_low`와 함께 동일한 2차원 Grid Search로 확정) 세 위험 신호를 **모두 실제로 라우팅에 사용**해, 우선순위가 정해진 규칙(Fail-Closed NaN 처리 → OOD → Disagreement → Difficulty → 확률 그레이존 → 악성 확신 → 정상 확신 순)으로 세 갈래 판정을 내리는 라우터입니다. `tau_low`와 `tau_difficulty`는 JRR의 OR 조건에서 상호작용하므로 하나씩 순차 최적화하지 않고 동시에 탐색했으며, 이 과정에 Eval 데이터는 사용하지 않았습니다. 이전 순차 최적화 결과였던 `tau_low=0.60`/`tau_difficulty=5.0`은 이력으로만 남아 있습니다(9장). 동시에 발현된 모든 위험 신호는 `triggered_signals` 배열에, 최초 매칭된 대표 사유는 `reason`에 각각 보존됩니다.

현재 공식 threshold(`0.65`/`6.0`)를 Eval 세트(48만 건)에 적용한 **Engineering Eval** 결과는 ROC-AUC 0.997783, 실측 TPR 89.11% / 실측 FPR 0.12%(Calibration에서 목표한 FPR 0.1%와는 별개의 실측값), ECE 0.0031, Brier Score 0.0163, Kill Test FPR 0%이며, 전체 트래픽 중 **11.48%(55,114건)**만 심층분석 큐(`HIGH_RISK_UNCERTAIN`)로 라우팅되고 Review Yield는 **79.19%**입니다. OOD 방어 성공률 100%는 OOD 탐지 자체의 정확도가 아니라 OOD로 판별된 샘플이 정책대로 모두 `HIGH_RISK_UNCERTAIN`으로 라우팅되었다는 동작 검증입니다. Eval 세트는 개발 중 이미 여러 차례 확인에 사용된 데이터이므로 "미지의 Eval 데이터"가 아니며, threshold freeze 이후 공식적으로 별도 실행·보고하는 **Final Eval**은 아직 이루어지지 않았습니다 — Final Eval과 Lockbox/Challenge(전체 Pipeline Freeze 후 최종 1회 평가)는 서로 다른 단계입니다. `risk_score`나 가중합 방식은 현재 공식 구현에 존재하지 않으며, 반환 필드명(`initial_verdict`/`route`/`calibrated_probability`/`disagreement`/`ood_score`/`difficulty_score`/`reason`/`triggered_signals`)은 `docs/interface_spec.md`와 완전히 일치합니다. 다만 `tau_disagree`/`tau_ood`의 정량적 재현성, Tier 3 명칭, 서비스 계층 구현, §11 신호별 breakdown의 신규 threshold 재산출, AUTO_BENIGN/AUTO_MALICIOUS 개별 건수, Final Eval 재실행은 아직 정리되지 않은 부분으로 남아 있습니다.

> **JRR은 모델의 확률만으로 자동 판정하지 않고, Calibration된 확률과 다중 위험 신호(Disagreement·OOD·Analysis Difficulty)를 이용해 자동 판정과 심층분석 대상을 보수적으로 분리하는 Priority-ordered Rule-based Triage Router이다.**
> (2026-09-09 재조사 기준 4개 신호가 모두 라우터에 실제로 통합되어 있음을 코드 레벨에서 확인했고, 2026-09-10 `tau_low`×`tau_difficulty` 2차원 Grid Search 반영으로 threshold를 `0.65`/`6.0`으로 갱신했습니다.)
