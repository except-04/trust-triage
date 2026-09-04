# FLOSS 정적 분석 모듈

이 모듈은 JRR이 심층분석 대상으로 보낸 PE를 대상으로 FLOSS를 별도
프로세스에서 실행하고, 일반·stack·tight·decoded 문자열을 공통 Evidence로
변환한다. FLOSS는 CAPA와 같은 정적 분석 단계에서 함께 실행할 수 있다.

## 설치

FLOSS는 저장소에 포함하지 않는다. 분석 환경에서 standalone binary를
설치하거나 Python 패키지를 별도로 설치한다.

```powershell
pip install flare-floss
```

실행 파일 이름이 `floss`가 아니면 CLI의 `--floss-command`로 전체 경로를
지정한다.

## CLI

```powershell
python -m trust_triage.static_analysis.floss_cli .\sample.exe --summary
python -m trust_triage.static_analysis.floss_cli .\sample.exe --min-length 8 --summary
```

JSON 결과가 필요하면 `--summary`를 생략한다. 원본 FLOSS JSON 전체를
결과에 포함하려면 `--include-raw-report`를 사용한다.

## Python API

```python
from trust_triage.static_analysis import FlossAnalyzer, FlossConfig

analyzer = FlossAnalyzer(
    FlossConfig(
        executable="floss",
        timeout_seconds=120,
        min_string_length=4,
    )
)
result = analyzer.analyze(
    "sample.exe",
    raw_reference="reports/floss/sample.json",
)
evidence = result.to_evidence(max_strings=64)
```

FLOSS 결과는 다음 단계로 전달된다.

```text
FLOSS JSON
    ↓
FlossString 그룹
    ↓
공통 Evidence
```

`STRING_SUMMARY`, `STRING_OBSERVED`, `OBFUSCATED_STRING` Evidence를 만들며,
문자열 하나만으로 ATT&CK Technique이나 악성 판정을 만들지 않는다. 복원된
문자열은 CAPA·Speakeasy 결과를 보조하는 분석 근거로 사용한다.

## 상태와 안전 제한

- `SUCCESS`, `INVALID_INPUT`, `TIMEOUT`, `ENVIRONMENT_MISMATCH`,
  `PARSE_ERROR`, `UNSUPPORTED`, `TOOL_ERROR`를 반환한다.
- timeout·실행 오류·파싱 오류는 Evidence로 변환하지 않는다.
- `subprocess.run(..., shell=False)`와 제한 시간을 사용한다.
- 입력 PE를 Windows에서 직접 실행하거나 로드하지 않는다.
- 결과 문자열과 원본 report는 Evidence의 `raw_reference`로 연결할 수 있다.
- FLOSS 결과의 schema는 버전에 따라 바뀔 수 있으므로 분석 환경의 FLOSS
  버전을 결과에 기록하고 고정하는 것을 권장한다.
