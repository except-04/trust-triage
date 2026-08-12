# EMBER2024 Feature Version 3 추출

이 모듈은 공식 EMBER2024 Feature Version 3(`thrember`) 구현을 사용해 PE
파일의 정적 Feature 벡터를 추출합니다. 입력 파일을 실행하거나 DLL을
로드하지 않습니다.

구현 진행 상황과 추후 작업은 [plan.md](plan.md)에서 관리합니다.
EMBER v3 고정 Schema manifest는 [ember-v3-schema.json](ember-v3-schema.json)에서
확인할 수 있습니다.
모델 입력 Feature를 전체 또는 부분집합으로 선택하는 방법은
[feature-selection.md](feature-selection.md)에서 확인할 수 있습니다.

## 설치

저장소 루트에서 다음 명령어를 실행합니다.

```powershell
.\trust-triage-env\Scripts\python.exe -m pip install -r requirements.txt
.\trust-triage-env\Scripts\python.exe -m pip install -e . --no-deps --no-build-isolation
```

공식 EMBER2024 저장소는 커밋을 고정해 설치합니다. `signify`는 공식
`thrember` 코드가 사용하는 API와 호환되는 버전으로 고정되어 있습니다.

## CLI 실행

```powershell
.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli .\path\to\sample.exe
```

성공하면 다음 정보를 포함한 JSON을 출력합니다.

- 공식 EMBER2024 v3 Schema 버전
- SHA-256
- PE32 또는 PE32+
- .NET 여부
- 고정된 `float32` Feature 벡터
- Feature 개수와 각 원소 이름
- NaN 결측값의 개수와 위치
- 파싱 오류와 경고
- `thrember` 출처와 실행 방식이 담긴 `metadata`

현재 공식 PE Feature 그룹 전체를 사용하면 2,568차원 벡터가 생성됩니다.
Schema 버전의 뒤쪽 지문은 사용한 Feature 그룹과 차원을 식별합니다.

내부 NumPy 모델 입력에서는 NaN을 결측값으로 보존합니다. JSON 표준에는 NaN
표현이 없으므로 `features` 배열에서는 `null`로 출력하고,
`nan_feature_count`와 `nan_feature_indices`에 개수와 위치를 기록합니다.
양의 무한대와 음의 무한대는 잘못된 모델 입력으로 처리합니다.

CLI는 기본적으로 정적 추출을 별도 프로세스에서 실행하고 30초 제한 시간을
적용합니다. 제한 시간을 바꾸려면 `--timeout`을 사용합니다.

```powershell
.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli `
  .\path\to\sample.exe --timeout 60
```

JSON 출력을 한 줄로 보려면 `--compact`를 추가합니다.

```powershell
.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli .\path\to\sample.exe --compact
```

공식 `thrember` Feature 그룹 자체를 바꾸고 싶을 때는 `--features-file`을
사용합니다. 이 옵션은 모델팀이 정한 최종 Feature 목록을 지정하는 옵션과
다릅니다. 모델 입력 Feature의 부분집합은 `--selection-file`과 별도 manifest로
관리합니다.

```powershell
.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli .\path\to\sample.exe --features-file .\path\to\features.json
```

모델팀의 선택 목록을 적용하는 예시는 다음과 같습니다.

```powershell
.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli `
  .\path\to\sample.exe `
  --selection-file .\docs\feature-extraction\feature-selection.example.json
```

## 요약 출력

전체 Feature 벡터를 JSON으로 출력하지 않고 핵심 정보만 확인하려면
`--summary` 옵션을 사용합니다.

```powershell
.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli .\path\to\sample.exe --summary
```

다음 정보를 표시합니다.

- 분석 상태, SHA-256, 파일 형식, EMBER Schema
- Feature 개수와 Schema 버전
- Import 개수와 API_GROUPS 매칭 결과
- 누락 Feature, 경고, 오류

## API_GROUPS 분류 결과

추출 결과에는 EMBER 모델 입력과 별도로 `api_groups` 필드가 포함됩니다. 이 필드는
원본 PE의 Import Table에 선언된 API 이름을 팀에서 정한 그룹으로 분류한 정보입니다.

현재 기본 그룹은 다음과 같습니다.

- `registry`: 레지스트리 관련 API
- `injection`: 프로세스 메모리 조작·인젝션 관련 API
- `network`: 네트워크 통신 관련 API

예시:

```json
{
  "api_groups": {
    "schema_version": "api-groups-mvp-v2",
    "source": "PE_IMPORT_TABLE",
    "named_import_count": 120,
    "ordinal_import_count": 0,
    "groups": {
      "injection": {
        "matched": true,
        "match_count": 1,
        "apis": ["WriteProcessMemory"],
        "dlls": ["kernel32.dll"],
        "matches": [
          {
            "dll": "kernel32.dll",
            "api": "WriteProcessMemory"
          }
        ]
      }
    }
  }
}
```

`api_groups`는 EMBER v3의 2568개 모델 Feature를 대체하지 않습니다. 원본 Import
목록에 선언된 API를 기준으로 하므로, 동적 API 로딩과 난독화된 API는 놓칠 수 있습니다.
이름이 없는 ordinal Import는 `dll`, `ordinal`, `resolved: false` 형태로 별도 보존합니다.
따라서 이 결과는 악성 확정값이 아니라 설명, Evidence 또는 JRR 위험 신호로 사용해야
합니다.

## Python API

```python
from trust_triage.feature_extraction import EmberV3Extractor, extract_file

extractor = EmberV3Extractor()
result = extractor.extract("sample.exe")

if result.status.value == "SUCCESS":
    vector = result.to_float32(extractor.schema)

# 외부 파일을 받는 CLI/API에서는 제한 시간을 강제할 수 있다.
timed_result = extractor.extract_with_timeout("sample.exe", timeout_seconds=30)

# 기본 진입점도 EMBER v3만 사용합니다.
result = extract_file("sample.exe")
```

## 처리 상태

```text
SUCCESS
INVALID_PE
PARSE_ERROR
UNSUPPORTED
FILE_TOO_LARGE
TIMEOUT
TOOL_ERROR
```

실패한 파일을 0으로 채워 성공한 것처럼 처리하지 않습니다. PE가 아니거나
파싱에 실패하면 상태와 오류 메시지를 함께 반환합니다.

## 다른 팀 모듈과 연결할 때

Baseline 모델은 `status == "SUCCESS"`인 결과만 사용해야 합니다. 모델 학습에
사용한 EMBER2024 Feature 그룹, 순서, 차원, `thrember` 커밋이 실제 추출기와
같아야 합니다. 모델 학습과 실제 파일 추출에 서로 다른 Feature 구성을
사용하면 안 됩니다.
