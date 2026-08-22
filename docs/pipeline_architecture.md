# TRUST-EDR 파이프라인 아키텍처 문서

> 각 모듈의 입출력(인터페이스)을 정의합니다.
> 
> 
> **담당자는 본인 파트의 "출력 형식" 섹션을 실제 구현에 맞춰 확정·수정해주세요.** 
> 
> 여기 정의된 형식이 바뀌면 반드시 이 문서부터 업데이트하고 팀 전체에 공지합니다.
> 

---

## 0. 전체 흐름

```
[파일/해시 입력]
        │
        ▼
[① 특징 추출 모듈]  ─────────────── 담당: 이상욱
        │  출력: 500차원 특징 벡터
        ▼
[② Baseline 모델]  ─────────────── 담당: 김정윤
        │  출력: raw_probability
        ▼
[③ Calibration]  ──────────────── 담당: 김건우·이가영
        │  출력: calibrated_probability
        ▼
[④ 다중 위험 신호 결합]  ────────── 담당: 김건우·이가영
        │  출력: disagreement, ood_score, difficulty_score
        ▼
[⑤ Joint Risk Router]  ─────────── 담당: 김건우·이가영
        │  출력: route, risk_score, priority_rank
        │
        ├──[자동 정상]──┐
        ├──[자동 악성]──┤
        ├──[심층분석] → [⑥ 심층분석 확장모듈 (설계 검토 중)] ── 담당: 이상욱
        └──[분석가 검토]┘         출력: behavior_flags
                        │
                        ▼
                [⑦ SHAP 설명]  ────────────── 담당: 김정윤 / 건우·가영
                        │  출력: top_features
                        ▼
                [⑧ API/대시보드/Alert/DB]  ─── 담당: 최지원
```

---

## 1. 표준 데이터 스키마 (모듈 간 공통 형식)

파이프라인 전체를 관통하는 결과 객체는 아래 형식을 기준으로 각 모듈이 필드를 하나씩 채워나가는 구조입니다.

```json
{
  "file_id": "string",
  "sha256": "string",

  "initial_verdict": "정상 | 악성 | 고위험_불확실",
  "final_verdict": "정상 | 악성 | null",
  "verdict_diff": "일치 | 불일치 | null",

  "route": "자동_정상 | 자동_악성 | 고위험_불확실 | 분석가_검토",
  "raw_probability": 0.0,
  "calibrated_probability": 0.0,
  "risk_signals": {
    "disagreement": 0.0,
    "ood_score": 0.0,
    "difficulty_score": 0.0
  },
  "risk_score": 0.0,
  "priority_rank": null,

  "top_features": [
    {"name": "string", "contribution": 0.0, "direction": "정상 | 악성"}
  ],

  "evidence": [
    {"technique_id": "string", "name": "string", "source": "string", "confidence": "string"}
  ],

  "deep_analysis_status": {
    "capa": "COMPLETE | NOT_REQUIRED | FAILED",
    "speakeasy": "COMPLETE | NOT_REQUIRED | FAILED",
    "cape": "COMPLETE | NOT_REQUIRED | PENDING"
  },

  "review_status": "N/A | 대기중 | 완료",
  "analyst_final_verdict": null,
  "created_at": "ISO8601"
}
```

---

## 2. 모듈별 상세 명세

### ① 특징 추출 모듈 — 담당: 이상욱

| 항목 | 내용 |
| --- | --- |
| 입력 | 파일(바이너리) 또는 SHA256 해시 문자열 |
| 출력 | 500차원 특징 벡터 (JSON: `{"features": [...], "sha256": "..."}`) |
| 참고 | `feature_schema.md` 기준, 갈래 A(EMBER 재현) |
| **담당자 확인 필요** | 실제 출력이 JSON array인지, dict(이름:값)인지 확정해서 아래 채워주세요 |

```
(
구현 내용
- EMBER2024 v3 기준 PE 정적 특징 2568차원 추출
- Feature Schema 및 특징 순서 검증을 통한 모델 입력 일관성 보장
- 모델팀 선정 Top-500 Feature Selection 적용 지원
- SHA-256, PE32/PE32+, .NET 여부 등 파일 메타데이터 추출
- Import Table 기반 Registry / Injection / Network 관련 API 그룹 분석- 비정상 PE 및 파싱 실패에 대한 예외 처리

실제 출력 예시:
{
  "sha256": "8f31...a20c",
  "file_type": "PE32+",
  "is_dotnet": false,
  "status": "success",
  "feature_count": 2568,
  "features": [0.0, 0.12, ...],
  "api_groups": {
    "registry": [...],
    "injection": [...],
    "network": [...]
  }
}
```

### ② Baseline 모델 — 담당: 김정윤

| 항목 | 내용 |
| --- | --- |
| 입력 | ①의 500차원 특징 벡터 |
| 출력 | `raw_probability` (float, 0~1) |
| 모델 파일 | MLflow run_id 또는 `.pkl` |
| **담당자 확인 필요** | 튜닝 완료 시점, 모델 파일 최종 경로/참조 방식 |

```
모델 참조 방식: 세 모델(LightGBM 튜닝전, LightGBM 튜닝후, XGBoost)을 구글드라이브 baseline_model 폴더에 .pkl 파일로 저장해 공유. MLflow는 팀원 각자 로컬 환경에서 운영 중이라 run_id 공유는 어려움. 추후 팀 공용 MLflow 서버 도입 시 run_id 기반 참조로 전환 예정.

threshold 값: 0.9834 (LightGBM 튜닝 완료 모델 기준, calibration 세트에서 목표 FPR 0.1%로 산출) — 2026-08-14 업데이트, 이전 값(0.932079718)은 튜닝 전 모델 기준이라 더 이상 사용하지 않음

특징 참조: top_feature_indices_500.npy (2568개 중 상위 500개 인덱스, LightGBM/XGBoost 모두 동일 인덱스 사용). 단, 튜닝된 LightGBM 최종 모델은 로그상 500개 중 498개만 실제 학습에 사용된 것으로 확인됨 (문제되는 수준 아니나 참고)

모델 파일:
- baseline_model_lightgbm_tuned_500.pkl (LightGBM, 튜닝 완료·공식 Baseline, TPR@FPR0.1% 91.20%)
- baseline_model_xgb_500.pkl (XGBoost, disagreement 계산용)
- baseline_model_500.pkl (LightGBM 튜닝 전, 참고용으로 보관)

하이퍼파라미터 튜닝 결과: Optuna 기반 4차 튜닝 완료. 
82.77%(튜닝전) → 91.20%(최종) 개선. 
상세 이력은 `500개_특징_선택_근거.md`, `lightgbm_hyperparameter_tuning_results.md` 및 관련 PR 참고.
```

### ③ Calibration — 담당: 김건우

| 항목 | 내용 |
| --- | --- |
| 입력 | `y_calib.npy`: 확률 보정을 위한 Calibration 세트의 실제 정답 `y_pred_proba.npy`: Baseline 1차 모델이 출력한 원시 예측 확률 배열 |
| 출력 | jrr_calibrator.pkl |
| 방법 | Isotonic Regression (등방성 회귀) |
| **담당자 확인 필요** | 최종 채택 방법, calibrator 객체 저장/공유 방식 |

```
Isotonic Regression(등방성 회귀)을 적용하여 1차 Baseline 모델(LightGBM)의 과장된 원시 예측 확률을 실제 신뢰도 수준으로 영점 조절(Calibration)하는 파이프라인(07_train_calibrator.py) 구현 완료.

프로젝트 핵심 방어선인 목표 오탐률(FPR 0.1%)을 달성하기 위해, Calibration 세트 내부적으로 계산 및 확정된 최적의 컷오프 임계값(Threshold) 산출.

jrr_calibrator.pkl 파일 하나에 학습된 보정기 모델 객체와 최적 임계값 변수를 모두 직렬화하여 내장 저장.

MLflow의 JRR_Calibration 실험 공간에 확률 보정 평가 메트릭을 자동 기록하도록 연동하여 성능 추적 기반 마련.
```

### ④ 다중 위험 신호 결합 — 담당: 김건우

| 항목 | 내용 |
| --- | --- |
| 입력 | `X_tr.py` : OOD 기준점 학습을 위한 과거 원본 데이터   `top_feature_indices_500.npy` : 500개 피처 내 분석 난이도 인덱스 동적 추적용 번호표 |
| 출력 | jrr_risk_signals.pkl |
| **담당자 확인 필요** | OOD 산출 알고리즘, 불일치 비교 대상 모델 |

```
AI가 1차적으로 판단하기 어려운 '그레이존' 식별을 돕기 위해, 다중 위험 신호(Risk Signals) 산출 파이프라인(08_train_risk_signals.py) 구현 완료.

대용량 데이터의 메모리 초과 방지를 위해 10만 개 무작위 샘플링(mmap 적용)된 원본 학습 데이터를 기준으로, 이상치 탐지 전용 모델인 Isolation Forest를 학습시켜 OOD(Out-of-Distribution) 점수 산출 로직 확정.

기존 2568차원 기준의 하드코딩(2480~2568번)으로 인한 인덱스 에러를 방지하고자, Top 500 특징 배열 내에서 PEFormatWarnings(분석 난이도) 인덱스 17개를 동적으로 추적해 내는 매핑 로직 구현 및 버그 수정 완료.

학습된 OOD 모델 객체와 분석 난이도 매핑 정보 테이블을 후속 파이프라인이 즉시 로드할 수 있도록 jrr_risk_signals.pkl 파일로 직렬화하여 저장.

참고 (아키텍처 최적화): '모델 간 불일치도(Disagreement)' 지표는 사전 학습 부품으로 생성할 필요가 없으므로 08번 파이프라인에서 제외하고, 추후 09번 메인 라우터(09_jrr_router.py) 추론 단계에서 두 모델(LightGBM, XGBoost) 예측값의 분산을 통해 실시간 동적 산출되도록 설계 최적화.
```

### ⑤ Joint Risk Router — 담당: 이가영

| 항목 | 내용 |
| --- | --- |
| 입력 | `calibrated_probability` + ④의 위험 신호 dict |
| 출력 | `route`, `risk_score`, `priority_rank`(검토 대상인 경우) |
| 평가 기준 | Review Yield(그레이존 품질), 검토예산별 회수율 |
| **담당자 확인 필요** | 라우팅 정책(규칙/가중합/Risk Model 중 최종 채택안), 검토예산 기본값 |

```
(가영 작성)
```

### ⑥ 심층분석 확장모듈 (설계 검토 중) — 담당: 이상욱

| 항목 | 내용 |
| --- | --- |
| 입력 | 원본 PE 파일(route가 "심층분석"인 경우만) |
| 출력 | `{"malicious_behavior": [...], "sensitive_file_access": [...]}` |
| 도구 | 미정 (Speakeasy / CAPA / Ghidra / CAPE 조합 검토 중) |
| **담당자 확인 필요** | 행위 분류 카테고리 목록 확정 |

```
(이상욱님 작성)
```

### ⑦ SHAP 설명 — 담당: 김정윤 / 김건우·이가영

| 항목 | 내용 |
| --- | --- |
| 입력 | 모델 + ①의 특징 벡터 |
| 출력 | `top_features` (상위 5개, {name, contribution, direction}) |
| **담당자 확인 필요** | 해싱된 특징에 대한 "카테고리 힌트" 표시 방식 |

```
(작성)
```

### ⑧ API / 대시보드 / Alert / DB — 담당: 최지원

| 항목 | 내용 |
| --- | --- |
| 입력 | 위 전체 파이프라인 결과 객체(표준 스키마) |
| 출력 | REST API 응답, 대시보드 화면, Slack Alert, SQLite 저장 |
| 상세 명세 | `docs_api_contract.md`, `docs_sqlite_schema.md` 참고 |
| **담당자 확인 필요** | 서버 구조(단일/분산) 확정, Alert 임계값 |

```
(최지원 작성)
```

---

## 3. 다음 확인 사항

- [ ]  각 담당자, 본인 파트 "담당자 작성 필요" 칸 채우기 (3주차 내)
- [ ]  서버 구조(단일 서버 vs 분산) 확정 → ⑧ 항목에 반영
- [ ]  표준 스키마 필드 변경 시 이 문서 최우선 업데이트

## 4. 변경 이력

| 날짜 | 변경 내용 | 작성자 |
| --- | --- | --- |
| 2026-08-06 | 최초 작성 (뼈대) | 김정윤 |