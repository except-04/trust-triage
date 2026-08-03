# Feature Extraction 진행 계획

최종 수정일: 2026-08-03

이 문서는 TRUST-TRIAGE의 Feature 추출 모듈 진행 상황과 팀 협의가 필요한 사항,
추후 확장 작업을 한 곳에서 관리하기 위한 문서다.

## 1. 현재 목표

원본 PE 파일을 실행하지 않고 정적으로 읽어서 다음 결과를 제공한다.

1. EMBER2024 v3 모델 입력용 2568차원 Feature 벡터
2. 파일 식별과 상태 확인을 위한 메타데이터
3. 사람이 이해할 수 있는 Import API 그룹 정보

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
- [x] .NET 여부 판별
- [x] 잘못된 파일과 파싱 실패 상태 구분
- [x] 파일 크기 제한
- [x] EMBER2024 v3 `thrember` 추출기 연동
- [x] EMBER Feature Schema와 Feature 순서 고정
- [x] 그룹별 시작·끝 인덱스가 포함된 Schema manifest 작성
- [x] 기본 설정에서 2568차원 `float32` 벡터 생성
- [x] 반복 추출 결과의 결정성 테스트
- [x] Import Table의 API_GROUPS 분류
- [x] API_GROUPS 결과에 DLL과 API의 정확한 연결 정보 포함
- [x] Ordinal Import의 DLL·ordinal 상세 정보 보존
- [x] JSON 전체 출력 CLI
- [x] 핵심 정보만 출력하는 `--summary` CLI
- [x] 모델팀 연동 문서 작성
- [x] pytest 테스트 작성

현재 테스트 결과는 `19 passed`다.

### 현재 API_GROUPS

현재 `api-groups-mvp-v2`에는 다음 세 그룹이 있다.

- `registry`: 레지스트리 관련 API
- `injection`: 프로세스 메모리 조작·인젝션 관련 API
- `network`: 네트워크 통신 관련 API

API_GROUPS는 원본 PE의 정적 Import Table에 이름으로 기록된 API를 분류한다.
이름이 없는 Import는 DLL 이름과 ordinal 번호를 별도로 보존한다.

따라서 API를 Import했다고 실제로 실행했다는 뜻은 아니다. 동적 API 로딩,
난독화된 API, Export 정보를 확보하지 못한 ordinal API는 정확한 의미를 알 수 없다.
현재 결과는 악성 확정값이 아니라 설명, Evidence 또는 JRR 위험 신호로 사용한다.

## 3. 주요 파일

- `src/trust_triage/feature_extraction/ember_v3.py`: EMBER v3 추출과 .NET 판별
- `src/trust_triage/feature_extraction/api_groups.py`: Import API 그룹 분류
- `src/trust_triage/feature_extraction/schema.py`: Feature Schema와 그룹 범위
- `src/trust_triage/feature_extraction/result.py`: 공통 JSON 결과 구조
- `src/trust_triage/feature_extraction/cli.py`: JSON·요약 CLI
- `docs/feature-extraction/feature-extraction.md`: 사용법과 인터페이스
- `docs/feature-extraction/ember-v3-schema.json`: EMBER v3 Schema manifest
- `tests/test_feature_extraction.py`: 단위 테스트

## 4. 사용 방법

저장소 루트에서 실행한다.

### JSON 전체 결과

```powershell
.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli .\Notepad.exe
```

JSON에는 다음 정보가 포함된다.

- `schema_version`
- `sha256`
- `file_type`
- `is_dotnet`
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
- PE 형식과 .NET 여부
- EMBER Schema 버전
- Feature 개수
- 이름이 있는 Import와 Ordinal Import 개수
- Ordinal Import의 DLL·번호
- API_GROUPS별 매칭 결과
- 경고·오류

## 5. 다른 모듈과 연결하는 방법

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

### Schema manifest

`ember-v3-schema.json`에는 모델팀이 확인해야 할 다음 정보가 들어 있다.

- Schema 버전
- 자료형
- 전체 Feature 개수
- 그룹별 시작 인덱스와 끝 인덱스
- 그룹별 차원
- Feature 이름 생성 규칙

실제 Python Schema 객체는 전체 Feature 이름 목록도 제공한다.

### API_GROUPS와 Ordinal Import

`result.api_groups`는 모델 Feature 벡터와 분리된 메타데이터다.

JRR에서 사용할 경우 다음 정보를 위험 신호 또는 Evidence로 전달할 수 있다.

- `registry`, `injection`, `network` 매칭 여부
- 매칭된 API 이름과 DLL 이름
- 각 API와 해당 API를 제공하는 DLL의 정확한 연결 정보
- 이름을 확인하지 못한 ordinal Import의 DLL과 번호

Import 존재만으로 악성 행위나 실제 실행을 확정하지 않는다.

## 6. 아직 결정하지 않은 사항

### 6.1 2568개 전체 사용 여부

현재 추출기는 EMBER2024 v3의 2568개 전체를 출력한다. 그러나 최종 모델이
2568개를 모두 사용할지, 중요도가 높은 일부 Feature만 사용할지는 아직 확정하지
않았다.

권장 실험 순서는 다음과 같다.

1. 2568개 전체로 기준 모델 학습
2. Feature Importance 또는 SHAP으로 후보 Feature 확인
3. 후보 Feature만 사용해 별도 모델 재학습
4. 같은 검증 조건에서 성능과 학습 시간을 비교
5. 결과에 따라 최종 Feature 선택

일부 Feature를 선택하더라도 추출기를 임의로 다시 만들지 않는다. 선택한 Feature의
이름·인덱스·순서를 별도 목록으로 고정하고, 모델 학습과 실제 추출에서 동일하게
적용해야 한다.

### 6.2 API_GROUPS의 최종 용도

다음 중 어떤 용도로 사용할지 팀 합의가 필요하다.

- 분석 결과 설명용
- 공통 Evidence용
- JRR의 위험 신호용
- 모델 학습 입력용

API_GROUPS를 모델 학습 입력으로 사용하면 EMBER 2568개 모델과는 별도의 Feature
Schema와 학습 모델이 필요하다. 현재 구현은 API_GROUPS를 설명·Evidence·JRR 보조
정보로 사용하는 방향이다.

## 7. 추후 추가 작업

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

- [ ] 동일 버전 DLL Export Table을 이용한 ordinal 이름 보완
- [ ] 동적 API 로딩 탐지 보조
- [ ] YARA·Deep Static 등 추가 분석 결과와 Evidence 연결
- [ ] 모델 Feature Importance를 그룹 단위로 집계하는 리포트

## 8. 구현하지 않는 범위

- PE 파일 실행
- DLL 로딩 또는 함수 호출
- Import 목록만으로 악성 여부 확정
- 해싱된 EMBER Feature에서 원래 API 이름 역추적
- Feature Extraction 브랜치에서 Baseline·Calibration·JRR 전체 구현
- 원본 악성 PE나 대용량 학습 데이터를 저장소에 포함

## 9. 변경 기록

### 2026-08-03

- EMBER2024 v3 기반 2568개 Feature 추출 확인
- API_GROUPS MVP(`registry`, `injection`, `network`) 추가
- JSON 출력에 `api_groups` 필드 추가
- `--summary` 요약 CLI 추가
- Feature Schema manifest와 그룹 범위 문서 추가
- .NET PE 판별 필드 추가
- Ordinal Import DLL·번호 상세 정보 추가
- PE32·PE32+·실제 .NET 정상 파일 테스트 추가
- API_GROUPS에 DLL·API 정확한 연결 정보와 v2 Schema 추가
- Feature Extraction 문서를 전용 폴더로 정리
