# Feature Extraction 진행 계획

최종 수정일: 2026-08-03

이 문서는 TRUST-TRIAGE의 Feature 추출 모듈 진행 상황과 팀 협의가 필요한 사항,
추후 확장 작업을 한 곳에서 관리하기 위한 문서다.

## 1. 현재 목표

원본 PE 파일을 실행하지 않고 정적으로 읽어서 다음 결과를 제공한다.

1. EMBER2024 v3 모델 입력용 2568차원 Feature 벡터
2. 파일 식별과 상태 확인을 위한 메타데이터
3. 사람이 이해할 수 있는 Import API 그룹 정보

EMBER Feature 벡터와 API 그룹 정보는 목적이 다르다.

```text
PE 파일
 ├─ EMBER2024 v3 → 2568차원 모델 입력
 └─ Import Table → API_GROUPS 설명·Evidence·JRR 보조 정보
```

## 2. 현재 구현 상태

### 완료된 기능

- [x] 원본 PE를 실행하지 않는 정적 분석
- [x] SHA-256 계산
- [x] PE32·PE32+ 형식 판별
- [x] 잘못된 파일과 파싱 실패 상태 구분
- [x] 파일 크기 제한
- [x] EMBER2024 v3 `thrember` 추출기 연동
- [x] EMBER Feature Schema와 Feature 순서 고정
- [x] 기본 설정에서 2568차원 `float32` 벡터 생성
- [x] 반복 추출 결과의 결정성 테스트
- [x] Import Table의 API_GROUPS 분류
- [x] JSON 전체 출력 CLI
- [x] 핵심 정보만 출력하는 `--summary` CLI
- [x] pytest 테스트 작성

현재 테스트 결과는 `13 passed`다.

### 현재 API_GROUPS

현재 `api-groups-mvp-v1`에는 다음 세 그룹이 있다.

- `registry`: 레지스트리 관련 API
- `injection`: 프로세스 메모리 조작·인젝션 관련 API
- `network`: 네트워크 통신 관련 API

API_GROUPS는 원본 PE의 정적 Import Table에 이름으로 기록된 API를 분류한다.
따라서 API를 Import했다고 실제로 실행했다는 뜻은 아니다.

또한 동적 API 로딩, 난독화, ordinal Import는 놓칠 수 있다. 그러므로 현재
API_GROUPS 결과는 악성 확정값이 아니라 설명, Evidence 또는 JRR 위험 신호로만
사용한다.

## 3. 사용 방법

저장소 루트에서 실행한다.

### JSON 전체 결과

```powershell
.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli .\Notepad.exe
```

JSON에는 다음 정보가 포함된다.

- `schema_version`
- `sha256`
- `file_type`
- `status`
- `feature_count`
- `feature_names`
- `features`
- `api_groups`
- `warnings`
- `errors`

### 핵심 정보 요약

전체 2568개 벡터를 보고 싶지 않을 때는 `--summary`를 사용한다.

```powershell
.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli .\Notepad.exe --summary
```

요약 출력에는 다음 정보만 표시된다.

- 분석 상태
- SHA-256
- PE 형식
- EMBER Schema 버전
- Feature 개수
- 이름이 있는 Import와 Ordinal Import 개수
- API_GROUPS별 매칭 결과
- 경고·오류

## 4. 다른 모듈과 연결하는 방법

### Baseline 모델

성공한 결과의 `features`를 `float32` 벡터로 사용한다.

```python
from trust_triage.feature_extraction import EmberV3Extractor

extractor = EmberV3Extractor()
result = extractor.extract("sample.exe")

if result.status.value == "SUCCESS":
    vector = result.to_float32(extractor.schema)
```

모델 학습 데이터와 실제 PE 추출 결과는 다음 항목이 같아야 한다.

- Feature 개수
- Feature 이름
- Feature 순서
- 자료형
- EMBER Feature 그룹 구성

### API_GROUPS 사용

`result.api_groups`는 모델 Feature 벡터와 분리된 메타데이터다.

JRR에서 사용할 경우 예를 들어 다음과 같이 위험 신호로 전달할 수 있다.

```text
registry 매칭 여부
injection 매칭 여부
network 매칭 여부
매칭된 API 이름과 DLL 이름
```

단, Import 존재만으로 악성 행위나 실제 실행을 확정하지 않는다.

## 5. 아직 결정하지 않은 사항

### 5.1 2568개 전체 사용 여부

현재 추출기는 EMBER2024 v3의 2568개 전체를 출력한다. 그러나 최종 모델이
2568개를 모두 사용할지, 중요도가 높은 일부 Feature만 사용할지는 아직 확정하지
않았다.# EMBER2024 Feature Version 3 추출

이 모듈은 공식 EMBER2024 Feature Version 3(`thrember`) 구현을 사용해 PE
파일의 정적 Feature 벡터를 추출합니다. 입력 파일을 실행하거나 DLL을
로드하지 않습니다.

구현 진행 상황과 추후 작업은 [plan.md](plan.md)에서 관리합니다.

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
    "schema_version": "api-groups-mvp-v1",
    "source": "PE_IMPORT_TABLE",
    "named_import_count": 120,
    "ordinal_import_count": 0,
    "groups": {
      "injection": {
        "matched": true,
        "match_count": 1,
        "apis": ["WriteProcessMemory"],
        "dlls": ["kernel32.dll"]
      }
    }
  }
}
```

`api_groups`는 EMBER v3의 2568개 모델 Feature를 대체하지 않습니다. 원본 Import
목록에 선언된 API를 기준으로 하므로, 동적 API 로딩·난독화·ordinal Import는 놓칠 수
있습니다. 따라서 이 결과는 악성 확정값이 아니라 설명, Evidence 또는 JRR 위험 신호로
사용해야 합니다.

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


권장 실험 순서는 다음과 같다.

1. 2568개 전체로 기준 모델 학습
2. Feature Importance 또는 SHAP으로 후보 Feature 확인
3. 후보 Feature만 사용해 별도 모델 재학습
4. 같은 검증 조건에서 성능과 학습 시간을 비교
5. 결과에 따라 최종 Feature 선택

일부 Feature를 선택하더라도 추출기를 임의로 다시 만들지 않는다. 선택한 Feature의
이름·인덱스·순서를 별도 목록으로 고정하고, 모델 학습과 실제 추출에서 동일하게
적용해야 한다.

### 5.2 API_GROUPS의 최종 용도

다음 중 어떤 용도로 사용할지 팀 합의가 필요하다.

- 분석 결과 설명용
- 공통 Evidence용
- JRR의 위험 신호용
- 모델 학습 입력용

API_GROUPS를 모델 학습 입력으로 사용하면 EMBER 2568개 모델과는 별도의 Feature
Schema와 학습 모델이 필요하다. 현재 구현은 API_GROUPS를 설명·Evidence·JRR 보조
정보로 사용하는 방향이다.

## 6. 추후 추가 작업

### 우선순위 높음

- [ ] 팀에서 최종 모델 Feature 사용 범위 결정
- [ ] EMBER 학습 데이터의 Feature Schema와 실제 추출 Schema 대조
- [ ] 모델 학습 결과에 맞는 Feature 이름·인덱스 목록 문서화
- [ ] API_GROUPS를 JRR에 전달할 공통 필드 확정
- [ ] API_GROUPS 결과의 근거와 한계 문서화

### 우선순위 중간

- [ ] `process`, `file`, `persistence`, `anti-analysis` 등 추가 그룹 검토
- [ ] API_GROUPS 목록을 Python 코드 밖의 버전 관리되는 설정 파일로 분리
- [ ] DLL 이름과 API 이름을 함께 사용하는 정밀 매칭 추가
- [ ] 매칭된 API를 그룹별 위험 신호로 집계하는 함수 추가
- [ ] 대용량 PE 처리 시간과 메모리 측정
- [ ] API_GROUPS 결과를 공통 Evidence Schema로 변환

### 우선순위 낮음

- [ ] 동적 API 로딩 탐지 보조
- [ ] Import가 없는 파일에 대한 별도 설명 필드
- [ ] YARA·Deep Static 등 추가 분석 결과와 Evidence 연결
- [ ] 모델 Feature Importance를 그룹 단위로 집계하는 리포트

## 7. 구현하지 않는 범위

- PE 파일 실행
- DLL 로딩 또는 함수 호출
- Import 목록만으로 악성 여부 확정
- 해싱된 EMBER Feature에서 원래 API 이름 역추적
- Feature Extraction 브랜치에서 Baseline·Calibration·JRR 전체 구현
- 원본 악성 PE나 대용량 학습 데이터를 저장소에 포함

## 8. 변경 기록

### 2026-08-03

- EMBER2024 v3 기반 2568개 Feature 추출 확인
- API_GROUPS MVP(`registry`, `injection`, `network`) 추가
- JSON 출력에 `api_groups` 필드 추가
- `--summary` 요약 CLI 추가
- Feature Extraction 문서를 전용 폴더로 정리
