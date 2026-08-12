# 모델 입력 Feature 선택 및 검증

이 문서는 EMBER v3에서 추출한 원본 Feature와 실제 모델이 입력으로 사용하는
Feature를 안전하게 연결하는 방법을 설명한다.

핵심 원칙은 다음과 같다.

- 원본 추출 Schema의 버전을 반드시 확인한다.
- Feature 개수뿐 아니라 Feature 이름과 순서를 함께 확인한다.
- 부분집합을 사용할 때 manifest에 적은 순서가 모델 입력 순서가 된다.
- 선택된 입력은 항상 `float32`로 변환한다.
- 이름을 자동 정렬하거나, 모르는 Feature를 조용히 삭제하지 않는다.

## 왜 별도의 선택 manifest가 필요한가

현재 기본 추출기는 EMBER2024 v3의 2568개 Feature를 모두 반환한다. 그러나
모델팀이 중요 Feature 일부만 사용하기로 결정할 수도 있다. 추출기 안에서
Feature를 삭제하거나 순서를 바꾸면 학습 데이터와 실제 PE 추출 결과가 서로
달라질 수 있으므로, 추출기는 원본 2568차원 Schema를 유지하고 모델 입력
선택은 별도의 manifest로 관리한다.

따라서 다음 두 가지를 같은 코드로 처리할 수 있다.

1. `mode: all`: 원본 Feature 2568개 전체 사용
2. `mode: subset`: 모델팀이 정한 Feature 이름 목록만 사용

## 선택 manifest 형식

### 전체 Feature 사용

`feature_names`를 생략하거나 빈 배열로 둘 수 있다.

```json
{
  "selection_schema_version": "feature-selection-v1",
  "source_schema_version": "ember2024-v3-pe-873e612248d4",
  "selection_id": "ember-v3-all",
  "mode": "all",
  "dtype": "float32",
  "feature_names": []
}
```

### 일부 Feature 사용

목록의 순서가 그대로 모델 입력 열의 순서가 된다. 아래 예시는 설명을 위한
형식이다. 현재 모델팀이 전달한 실제 상위 500개 목록은
`feature-selection-ember-v3-top500.json` manifest로 관리한다.

```json
{
  "selection_schema_version": "feature-selection-v1",
  "source_schema_version": "ember2024-v3-pe-873e612248d4",
  "selection_id": "ember-v3-demo-subset",
  "mode": "subset",
  "dtype": "float32",
  "feature_names": [
    "general[0]",
    "section[0]",
    "imports[0]"
  ]
}
```

현재 상위 500개 선택 manifest:

`feature-selection-ember-v3-top500.json`

`source_schema_version`은 실행 중인 `EmberV3Extractor`의 Schema 버전과 정확히
같아야 한다. 모델을 다시 학습하거나 Feature 규격이 바뀌면 새
`selection_id`와 새 manifest를 만든다.

## Python 사용법

```python
from trust_triage.feature_extraction import (
    EmberV3Extractor,
    FeatureSelector,
)

extractor = EmberV3Extractor()
result = extractor.extract("sample.exe")

if result.status.value == "SUCCESS":
    selector = FeatureSelector.from_feature_names(
        extractor.schema,
        ["general[0]", "section[0]"],
        selection_id="demo-subset",
    )
    model_input = result.to_model_input(selector)
    # model_input: 검증된 1차원 numpy.float32 배열
```

JSON manifest를 사용할 때는 다음과 같이 읽는다.

```python
selector = FeatureSelector.from_json_file(
    extractor.schema,
    "feature-selection.json",
)
model_input = result.to_model_input(selector)
```

여러 샘플을 한 번에 처리하는 데이터 전처리 모듈은
`selector.select_matrix(matrix)`를 사용한다. 행렬의 열 개수와 유한값 여부도
자동으로 검증한다.

## CLI 사용법

기존 명령은 원본 추출 결과를 출력한다.

```powershell
python -m trust_triage.feature_extraction.cli .\Notepad.exe
```

선택 manifest를 지정하면 모델 입력용 선택 결과만 출력한다.

```powershell
python -m trust_triage.feature_extraction.cli `
  .\Notepad.exe `
  --selection-file .\docs\feature-extraction\feature-selection.example.json
```

전체 벡터를 출력하지 않고 선택 결과의 핵심 정보만 확인하려면 `--summary`를
추가한다.

```powershell
python -m trust_triage.feature_extraction.cli `
  .\Notepad.exe `
  --selection-file .\docs\feature-extraction\feature-selection.example.json `
  --summary
```

## 검증되는 오류

다음 상황은 오류로 처리한다.

- 선택 manifest 버전이 지원 버전과 다름
- manifest의 원본 Schema 버전이 현재 추출기와 다름
- 등록되지 않은 Feature 이름 사용
- 선택 목록에 중복 이름 존재
- 전체 선택인데 원본 순서와 다른 목록 사용
- 부분집합인데 전체 Feature를 다시 지정
- 원본 벡터의 차원 또는 행렬 열 수가 다름
- Feature 이름·순서 메타데이터가 Schema와 다름
- 양의 무한대 또는 음의 무한대 포함
- 모델 입력 자료형이 `float32`가 아님

이 검증들은 모델 성능을 높이는 기능이 아니라, 학습 때와 서비스 추론 때
서로 다른 열을 연결하는 치명적인 데이터 계약 오류를 조기에 막는 기능이다.

NaN은 LightGBM이 결측값으로 처리할 수 있도록 내부 `float32` 모델 입력에서
보존한다. 표준 JSON에는 NaN 표현이 없으므로 CLI JSON에서는 `null`로 출력하고,
`nan_feature_count`와 `nan_feature_indices`에 개수와 위치를 함께 기록한다.
무한대는 허용하지 않는다. 다른 모델을 사용할 때 대치가 필요하면 Train에서
학습한 규칙을 별도 모델 전처리 산출물로 저장하고 실제 추론에도 동일하게 적용한다.

## 팀 모듈 연결 규칙

Data Processing과 Baseline Model은 다음 값을 함께 보관해야 한다.

- 원본 `source_schema_version`
- 모델 입력 `schema_version`
- `selection_id`
- 선택된 `feature_names`
- 모델 입력 `dtype`
- 최종 Feature 개수

모델 파일만 전달하지 말고 이 manifest와 함께 전달해야 한다. 그래야 실제 PE
추출 결과가 학습 당시의 열 순서와 같은지 확인할 수 있다.
