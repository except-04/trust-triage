# EMBER2024 Feature Version 3 추출

이 모듈은 공식 EMBER2024 Feature Version 3(`thrember`) 구현을 사용해 PE
파일의 정적 Feature 벡터를 추출합니다. 입력 파일을 실행하거나 DLL을
로드하지 않습니다.

구현 진행 상황과 추후 작업은 [plan.md](plan.md)에서 관리합니다.
EMBER v3 고정 Schema manifest는 [ember-v3-schema.json](ember-v3-schema.json)에서
확인할 수 있습니다.

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
- 파싱 오류와 경고

현재 공식 PE Feature 그룹 전체를 사용하면 2,568차원 벡터가 생성됩니다.
Schema 버전의 뒤쪽 지문은 사용한 Feature 그룹과 차원을 식별합니다.

JSON 출력을 한 줄로 보려면 `--compact`를 추가합니다.

```powershell
.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli .\path\to\sample.exe --compact
```

공식 구현에서 특정 Feature 그룹만 선택한 JSON 설정을 사용할 수도 있습니다.
팀원이 사용할 최종 Feature 목록 MD를 받으면 이 방식으로 구성을 맞추고
학습 데이터와 실제 추출 결과의 차원을 검증합니다.

```powershell
.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli .\path\to\sample.exe --features-file .\path\to\features.json
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
```

실패한 파일을 0으로 채워 성공한 것처럼 처리하지 않습니다. PE가 아니거나
파싱에 실패하면 상태와 오류 메시지를 함께 반환합니다.

## 다른 팀 모듈과 연결할 때

Baseline 모델은 `status == "SUCCESS"`인 결과만 사용해야 합니다. 모델 학습에
사용한 EMBER2024 Feature 그룹, 순서, 차원, `thrember` 커밋이 실제 추출기와
같아야 합니다. 모델 학습과 실제 파일 추출에 서로 다른 Feature 구성을
사용하면 안 됩니다.
