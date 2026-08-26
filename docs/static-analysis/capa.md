# CAPA 정적 분석 모듈

이 모듈은 JRR이 `CAPA_SCAN`을 선택했을 때 CAPA를 별도 프로세스로 실행하고,
CAPA JSON 결과를 TRUST-TRIAGE의 공통 Evidence 형식으로 변환한다.

## 분석 흐름

```text
Baseline / Risk Signals
        ↓
JRR 1차 판단
        ↓  (CAPA_SCAN 선택 시)
CAPA 정적 분석
        ↓
CAPA JSON → Capability → Evidence
        ↓
Evidence Fusion
        ↓
JRR 1회 재판단
```

CAPA 분석 실패, timeout, 환경 불일치는 악성 Evidence로 변환하지 않는다.
실패 상태는 `CapaAnalysisResult.status`로 보존한다.

## Backend

`CapaBackend.DEFAULT`는 CAPA 명령에 backend 옵션을 추가하지 않는 일반 실행이다.
`CapaBackend.GHIDRA`는 CAPA에 `-b ghidra`를 전달한다.

```text
DEFAULT: capa -j sample.exe
GHIDRA:  capa -b ghidra -j sample.exe
```

Ghidra는 이 저장소에 포함하지 않는다. GHIDRA backend를 선택한 분석 환경에만
Ghidra와 PyGhidra를 설치하고, 필요하면 `GHIDRA_INSTALL_DIR`을 설정한다.
Ghidra를 사용하지 않는 DEFAULT 실행에는 Ghidra가 필요하지 않다.

## Python API

```python
from trust_triage.static_analysis import CapaAnalyzer, CapaBackend, CapaConfig

analyzer = CapaAnalyzer(
    CapaConfig(
        executable="capa",
        backend=CapaBackend.DEFAULT,
        timeout_seconds=120,
        rules_version="v9.4.0",
    )
)
result = analyzer.analyze(
    "sample.exe",
    raw_reference="reports/capa/sample.json",
)

evidence = result.to_evidence()
```

`GHIDRA`를 선택할 때만 backend를 바꾼다.

Python launcher를 사용해야 하는 환경에서는 실행 파일 prefix를 지정할 수
있다. 예를 들어 `python -m capa.main`은 다음과 같이 구성한다.

```python
config = CapaConfig(
    executable=r".venv\Scripts\python.exe",
    executable_args=("-m", "capa.main"),
)
```

```python
config = CapaConfig(
    backend=CapaBackend.GHIDRA,
    ghidra_install_dir=r"C:\tools\ghidra",
)
```

한 샘플에 DEFAULT를 실행한 뒤 GHIDRA를 자동으로 재실행하지 않는다.
MVP의 추가 분석 단계 예산을 지키기 위해 JRR 또는 실행 정책이 한 번의
CAPA 분석 backend를 선택해야 한다.

## CLI

```powershell
py -m trust_triage.static_analysis.cli .\sample.exe --summary
py -m trust_triage.static_analysis.cli .\sample.exe --backend ghidra --summary
```

Ghidra 결과를 사용하려면 외부 분석 환경을 먼저 준비해야 한다. CAPA의
standalone binary를 사용하거나, Python package 방식으로 CAPA를 설치할 수 있다.
CAPA rules와 library-identification signatures의 버전도 분석 기록에 남기는 것을
권장한다.

## Evidence 규칙

Capability 매칭마다 다음 Evidence를 만든다.

```json
{
  "source": "CAPA",
  "category": "CAPABILITY_MATCH",
  "status": "OBSERVED",
  "details": {
    "backend": "default",
    "rule_name": "create service",
    "namespace": "persistence/service"
  }
}
```

CAPA capability는 프로그램이 해당 동작을 수행할 수 있음을 시사하는 정적
증거다. 그 자체로 `MALICIOUS` 또는 `BENIGN` 최종 라벨이 아니며, CAPA 미매칭도
정상 증거로 해석하지 않는다.

## 안전 원칙

- `subprocess.run(..., shell=False)`로 CAPA만 실행한다.
- 입력 PE를 직접 실행하거나 DLL로 로드하지 않는다.
- 모든 분석에는 timeout을 적용한다.
- 원본 악성 PE를 fixture나 저장소에 추가하지 않는다.
- Ghidra backend가 준비되지 않으면 `ENVIRONMENT_MISMATCH`를 반환하고
  DEFAULT로 조용히 대체하지 않는다.
