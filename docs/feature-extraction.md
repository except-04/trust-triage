# Feature 추출 MVP

이 모듈은 PE 파일을 바이트와 메타데이터로만 읽어 정적 Feature를
추출합니다. 입력 파일을 실행하거나 DLL을 로드하지 않습니다.

## CLI 실행

PowerShell에서 저장소 루트 기준으로 실행합니다.

```powershell
.\trust-edr-env\Scripts\python.exe -m pip install -e . --no-deps --no-build-isolation
.\trust-edr-env\Scripts\python.exe -m trust_triage.feature_extraction.cli .\path\to\sample.exe
```

명령어는 공통 추출 결과를 JSON으로 출력합니다. 성공한 결과는
`pe-static-mvp-v1` Schema를 사용하며, 고정된 순서의 `float32` 변환 가능
Feature 벡터를 제공합니다.

파싱에 실패한 경우에는 명확한 상태를 반환합니다. 실패한 파일을 0으로
채워 성공한 것처럼 처리하지 않습니다.

## Python API

```python
from trust_triage.feature_extraction import PE_STATIC_FEATURE_SCHEMA, extract_file

result = extract_file("sample.exe")
if result.status.value == "SUCCESS":
    vector = result.to_float32(PE_STATIC_FEATURE_SCHEMA)
```

Feature 이름과 순서는
`src/trust_triage/feature_extraction/schema.py`에서만 관리합니다.
Feature를 추가하거나 순서를 변경하면 Schema 버전을 올리고, 호환되는
모델을 다시 학습해야 합니다.

## 지원 Feature 범위

- SHA-256 및 파일 크기
- PE32 / PE32+ 형식
- PE Header와 Entry Point
- Section 크기·권한·Entropy 통계
- Import / Export 개수
- ASCII / Unicode 문자열 통계
- 전체 파일 Entropy
- .NET 여부와 서명 존재 여부

## 다른 파일 형식으로 확장

새로운 파일 형식을 지원하려면 `BaseExtractor`를 구현하고 파일 시그니처
판별 방식과 형식별 `FeatureSchema`를 추가하면 됩니다. 결과 형식은
그대로 유지할 수 있으므로, 이후 ELF나 Mach-O 추출기를 추가해도
하위 모델·API 모듈과의 연결 방식을 통일할 수 있습니다.
