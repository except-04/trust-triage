# Speakeasy 동적 분석

이 모듈은 Windows PE를 Speakeasy 에뮬레이터에서 분석하고, 후속 JRR과 Evidence
Aggregator가 사용할 수 있는 공통 결과를 반환한다.

## 범위와 안전장치

- 원본 PE를 Windows에서 직접 실행하지 않는다.
- Speakeasy는 별도 프로세스에서 실행한다.
- 부모 프로세스의 전체 제한 시간과 Speakeasy 엔진의 제한 시간을 함께 적용한다.
- 최대 명령어 수, API 호출 수, 입력 파일 크기를 제한한다.
- 제한 시간이 지나면 프로세스를 종료하고, 종료되지 않을 때는 강제 종료한다.
- 분석 실패나 에뮬레이터 미지원 기능은 악성 증거로 간주하지 않는다.
- Speakeasy 1.5.11은 .NET PE를 지원하지 않으므로 해당 입력은 `UNSUPPORTED_TARGET`이 될 수 있다.

## 실행

저장소 루트에서 의존성을 설치하고 패키지를 editable 모드로 설치한다.

```powershell
python -m pip install -r requirements.txt
python -m pip install -e . --no-deps --no-build-isolation
```

기본 분석:

```powershell
python -m trust_triage.dynamic_analysis.cli .\Notepad.exe
```

제한 시간과 명령어 수를 지정하는 예시:

```powershell
python -m trust_triage.dynamic_analysis.cli .\Notepad.exe `
  --timeout 15 `
  --max-instructions 500000
```

원본 Speakeasy report가 필요할 때는 큐로 큰 JSON을 반환하지 않고 artifact 파일로 저장한다.
기본 저장 위치는 `artifacts/speakeasy/<sha256>.json`이며, 결과의 `raw_reference`가 그 경로를 가리킨다.
`artifacts/`는 Git에 커밋하지 않는다.

```powershell
python -m trust_triage.dynamic_analysis.cli .\Notepad.exe `
  --include-raw-report `
  --raw-report-dir .\artifacts\speakeasy
```

## 결과 상태

```text
SUCCESS
TIMEOUT
UNSUPPORTED_API
UNSUPPORTED_TARGET
TOOL_ERROR
INVALID_INPUT
FILE_TOO_LARGE
```

`SUCCESS`는 분석이 오류 없이 끝났다는 뜻이지, 파일이 정상이라는 뜻이 아니다.
`TIMEOUT`과 `UNSUPPORTED_API`는 종료 전에 얻은 부분 결과를 함께 반환할 수 있다.
원인을 알 수 없는 report 경고는 `TOOL_ERROR`로 표시하여 성공으로 숨기지 않는다.

## 주요 출력 필드

- `observed_apis`: 관찰된 API 이름의 중복 제거 목록
- `api_call_counts`: API별 관찰 횟수
- `behaviors`: 네트워크, 파일, 레지스트리 등 행동 그룹
- `events`: API 호출과 행동별 세부 이벤트. 각 이벤트에는 `entry_point`가 포함된다.
- `warnings`, `errors`: 분석 중 발생한 경고와 오류
- `raw_reference`: 별도 저장된 원본 report 경로
- `tool_version`: 실행된 Speakeasy 버전
- `started_at`, `completed_at`: 분석 시작·종료 시각(UTC)
- `metadata`: 파일 크기, 제한 시간, 명령어 수, API 수 등 실행 설정

이벤트와 원본 report는 크기 폭증을 막기 위해 요약 결과에서는 제한한다. 전체 report가 필요하면
`--include-raw-report`로 저장된 파일을 확인한다.

## Evidence 사용 시 주의

동적 분석 결과만으로 최종 악성 여부를 확정하지 않는다. `status`, `warnings`,
`analysis_time_ms`, `metadata`, 도구 버전을 함께 보존하고, 분석 실패와 실제 행동 증거를
분리해서 JRR 또는 Evidence Fusion에 전달한다.
