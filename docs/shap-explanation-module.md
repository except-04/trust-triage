# SHAP 설명 모듈 인수인계

## 1. 구현 목적

XAI(설명 가능한 AI)는 모델의 판단 근거를 사람이 검토할 수 있게 만드는 접근이다. 이 모듈은 TreeSHAP을 이용해 TRUST-Triage의 LightGBM 예측에서 각 입력 feature가 모델 점수를 어느 방향으로 얼마나 움직였는지 계산한다.

TRUST-Triage에서는 모델 점수만 제시하는 대신, 영향이 큰 feature를 분석가에게 함께 제공하기 위해 SHAP을 사용한다. SHAP 결과는 모델 판단의 기여도이지 악성 행위에 대한 독립적인 증거나 인과 설명은 아니다. 특히 hashed feature가 어떤 DLL, API, section을 의미하는지는 추정하지 않는다.

## 2. 현재 구현 범위

- 공식 설명 대상은 `models/baseline_model_lightgbm_tuned_500_4way.pkl`이다.
- `shap.TreeExplainer(model, model_output="raw")`로 LightGBM의 raw score를 설명한다.
- calibration 이후의 `calibrated_probability`는 설명하지 않는다.
- positive class는 모델의 `classes_ == [0, 1]`, `objective == "binary"`를 검사하며, class `1`을 악성으로 해석한다.
- XGBoost는 모델 간 disagreement 계산용이며 이 모듈의 SHAP 대상이 아니다.
- 단일 `(500,)` 또는 `(1, 500)` 벡터만 지원한다. 기존 inference, Calibration, JRR 동작과는 연결되어 있지 않다.

저장소의 공식 artifact 위치는 `models/`이지만 현재 JRR inference 스크립트는 같은 파일명을 `data/` 아래에서 staging해 로드한다. 서비스 통합 시 SHAP에는 별도 모델을 다시 선택하지 말고 inference가 `data/baseline_model_lightgbm_tuned_500_4way.pkl`에서 로드한 동일 `LGBMClassifier` 인스턴스를 전달한다.

## 3. 관련 파일

| 파일 | 역할 |
|---|---|
| `src/trust_triage/explanation/__init__.py` | 공개 클래스와 예외 export |
| `src/trust_triage/explanation/shap_lightgbm.py` | artifact 검증, TreeSHAP 계산, Top-K 매핑 |
| `tests/test_shap_lightgbm.py` | 단위 테스트와 공식 artifact 통합 테스트 |
| `docs/feature-extraction/feature-selection-ember-v3-top500.json` | 모델 입력 순서의 feature name, 원본 index, schema version 및 `.npy` 해시 |
| `data/top_feature_indices_500.npy` | inference 시 사용하는, 학습에서 선택한 원본 2568차원 index 500개 |
| `models/baseline_model_lightgbm_tuned_500_4way.pkl` | 현재 공식 4-way LightGBM 모델 |
| `data/baseline_model_lightgbm_tuned_500_4way.pkl` | 현재 JRR inference가 공식 모델을 staging해 로드하는 경로 |

## 4. 데이터 흐름

```text
500차원 feature vector
  → LightGBM raw prediction
  → TreeSHAP
  → 500개 contribution
  → |SHAP| 내림차순 Top 5
  → manifest의 feature name 및 group 매핑
  → BENIGN / MALICIOUS / NEUTRAL direction 반환
```

SHAP 값은 `base_value + sum(contributions) == LightGBM raw score` 관계를 만족해야 한다. 구현은 SHAP의 `check_additivity=True`에 더해 LightGBM의 `predict(..., raw_score=True)` 결과와 독립적으로 다시 비교한다.

현재 설치 환경에서 공식 모델의 정상 반환 형태는 다음과 같이 확인되었다.

```text
shap.Explanation.values:      (1, 500)
shap.Explanation.base_values: (1,)
```

다른 class/axis 형태는 임의로 해석하지 않고 `ShapExplanationError`로 중단한다.

## 5. Feature ordering 검증

LightGBM artifact에는 원본 feature name이나 EMBER index가 없고 `Column_0`부터 `Column_499`까지의 일반 이름만 남는다. 따라서 이름과 원본 index를 함께 보존하는 selection manifest를 mapping의 source of truth로 사용한다. 한편 학습 코드는 `np.sort(np.load("top_feature_indices_500.npy"))` 순서로 열을 선택했으므로, `.npy`는 학습 ordering을 독립적으로 확인하는 기준이다.

`LightGBMShapExplainer` 초기화 시 다음을 검사하고, 하나라도 맞지 않으면 SHAP 계산 전에 `FeatureOrderingError`를 발생시킨다.

- manifest의 feature 수, 이름/index 개수, 중복, index 범위
- `selection_order == "ascending_source_index"` 및 엄격한 오름차순
- manifest `source_indices`와 `.npy`의 값과 순서가 `np.array_equal`로 완전히 동일한지
- `.npy`의 shape, 정수 dtype 및 manifest에 기록된 SHA-256
- manifest의 `source_schema_version`이 비어 있지 않은지
- 호출자가 `expected_source_schema_version`을 전달한 경우 manifest version과 정확히 같은지

마지막 schema 대조는 선택 사항이다. 이 모듈은 PE extraction 의존성을 직접 import하지 않으므로 live schema를 자체 생성하지 않는다. 실제 feature extraction/inference 파이프라인에 연결할 때는 `EmberV3Extractor().schema.version`을 `expected_source_schema_version`으로 전달해야 완전한 live-schema 검증이 수행된다.

잘못된 ordering을 허용하면 정상적인 SHAP 숫자에 엉뚱한 이름이 붙어 분석가를 오도할 수 있으므로 자동 정렬이나 추측 대신 fail-fast한다.

## 6. 출력 스키마

`explain()`은 기본적으로 `list[ShapContribution]` 형태의 Top 5를 반환한다. `to_dict()`는 `interface_spec.md`의 필드와 내부 추적용 metadata를 포함한 JSON 직렬화 가능한 dict를 반환한다. 기존 Python 속성 `name`과 `contribution`은 내부 호환성을 위해 유지한다.

| 필드 | 설명 |
|---|---|
| `feature_name` | manifest의 해당 모델 입력 열 feature 이름 |
| `feature_value` | 해당 모델 입력 열에 실제로 전달된 값 |
| `shap_value` | 악성 class raw score에 대한 SHAP 기여도 |
| `direction` | 양수 `MALICIOUS`, 음수 `BENIGN`, 정확히 0이면 `NEUTRAL` |
| `group` | `group[index]` 이름에서 구조적으로 분리한 group 이름 |
| `model_input_index` | 500차원 모델 입력에서의 위치, `0..499` |
| `source_index` | 원본 2568차원 EMBER 벡터에서의 위치 |

`group`은 이름 prefix만 반환한다. hashed bucket의 구체적인 의미는 복원하거나 추정하지 않는다.

`data/top_feature_indices_500.npy`는 데이터 artifact이므로 source checkout에 없을 수 있다. 공식 artifact 통합 테스트는 파일이 없을 때 manifest의 `source_indices`로 임시 `.npy`를 만들고, manifest에 고정된 SHA-256과 byte 단위로 일치할 때만 사용한다. 운영 explainer는 이런 fallback을 사용하지 않으며 실제 `.npy`가 없거나 hash/order가 다르면 초기화에 실패한다.

## 7. 사용 및 테스트

기본 사용 예시는 다음과 같다. artifact는 신뢰할 수 있는 로컬 파일만 로드해야 한다.

```python
import joblib

from trust_triage.explanation import LightGBMShapExplainer

model = joblib.load("data/baseline_model_lightgbm_tuned_500_4way.pkl")
explainer = LightGBMShapExplainer(
    model,
    "docs/feature-extraction/feature-selection-ember-v3-top500.json",
    "data/top_feature_indices_500.npy",
    expected_source_schema_version=live_schema_version,
)

top5 = [item.to_dict() for item in explainer.explain(feature_vector_500)]
```

테스트 실행:

```powershell
pytest tests/test_shap_lightgbm.py --basetemp=.pytest_tmp
```

2026-09-09 실행 결과는 `28 passed`이다. 테스트에는 ordering/schema/hash 실패 조건, 모델 계약, 입력 및 SHAP shape, `feature_value`, direction, Top-K 정렬, 공식 4-way artifact 로드, 합성 입력 3개에 대한 실제 TreeExplainer 실행과 raw-score additivity 검증이 포함된다.

공식 4-way LightGBM artifact에 합성 500차원 입력 3개를 넣은 TreeExplainer 실행은 성공했다. 또한 2026-09-09 로컬 Python PE 1개를 대상으로 `EMBER v3 2568차원 추출 → manifest 기반 Top-500 선택 → 공식 LightGBM prediction → SHAP Top-5` 수동 E2E 검증을 완료했다. 자동화된 PE E2E 회귀 테스트는 아직 포함하지 않았다.

## 8. 현재 한계와 향후 작업

- 실제 PE → 2568차원 추출 → Top-500 선택 → SHAP까지의 자동화된 E2E 회귀 테스트 추가
- feature extraction/inference 계층에서 live schema version을 전달하도록 pipeline schema 연결
- FastAPI 또는 Streamlit 응답에 `ShapContribution` 연결
- explainer 초기화 비용을 고려해 서비스에서 인스턴스를 재사용하는 lifecycle 설계
- 모델 artifact 자체에는 feature metadata가 없으므로, 배포 시 모델과 `data/top_feature_indices_500.npy`, selection manifest를 하나의 검증 가능한 bundle로 함께 배치
- SHAP/LightGBM 버전 변경 시 공식 artifact로 반환 타입과 `(1, 500)` / `(1,)` shape를 다시 검증

