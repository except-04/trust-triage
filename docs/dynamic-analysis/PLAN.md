# 동적 분석 확장 계획

이 문서는 `trust-triage-emulator`의 현재 구현 범위와 앞으로 추가할 동적 분석 경로를
정리한 계획서다. 현재 MVP의 기본 도구는 Speakeasy이며, CAPE와 Qiling은 현재 구현을
대체하지 않고 필요할 때 연결하는 확장 경로로 둔다.

## 1. 최종 방향

```text
정적 분석 결과
    ↓
JRR이 추가 분석 필요 여부와 예산을 판단
    ├─ Windows PE의 빠른 동적 분석 → Speakeasy
    ├─ 높은 위험도·정밀 행위 분석 → CAPE Sandbox
    └─ ELF 등 다중 포맷 확장       → Qiling
            ↓
공통 DynamicAnalysisResult / Evidence
            ↓
Evidence Aggregator → Evidence Fusion → JRR 재판단
```

핵심 원칙은 특정 도구의 결과를 그대로 최종 판정으로 사용하지 않는 것이다. 각 도구의
결과를 동일한 Evidence 형식으로 변환하고, 도구의 신뢰도·실패 상태·분석 비용을 함께
전달한다.

## 2. 현재 상태 — Speakeasy MVP

### 완료된 범위

- Windows PE 입력 확인
- SHA-256 계산
- 별도 프로세스에서 Speakeasy 실행
- 전체 분석 시간 제한
- Speakeasy 엔진의 명령어 수·API 수 제한
- 입력 파일 크기 제한
- `SUCCESS`, `TIMEOUT`, `UNSUPPORTED_API`, `UNSUPPORTED_TARGET`, `TOOL_ERROR` 등 상태 구분
- 제한 시간 또는 미지원 API로 중단되어도 확보한 부분 결과 반환
- 관찰 API 목록과 API별 호출 횟수 추출
- 네트워크·파일·레지스트리·프로세스 등의 행동 그룹 추출
- API 호출 및 행동 이벤트 요약
- 분석 도구 버전, 실행 시각, 파일 크기, 제한 설정 기록
- 원본 Speakeasy report를 `artifacts/`에 저장하는 선택 기능
- pytest 기반 단위 테스트

### 현재 사용 명령

```powershell
python -m trust_triage.dynamic_analysis.cli .\sample.exe --timeout 30
```

원본 report가 필요할 때만 다음 옵션을 사용한다.

```powershell
python -m trust_triage.dynamic_analysis.cli .\sample.exe `
  --include-raw-report `
  --raw-report-dir .\artifacts\speakeasy
```

### 현재 한계

- Speakeasy가 지원하지 않는 API나 실행 환경은 분석이 중단될 수 있다.
- 정적 분석에서 확인되는 모든 행위가 동적 분석에서 재현된다는 보장은 없다.
- 실행되지 않은 분기, 지연 로딩 API, 환경 의존 행위는 관찰하지 못할 수 있다.
- 현재는 Windows PE 중심이며 ELF 분석은 아직 구현하지 않는다.
- CAPE와 Qiling은 아직 연결하지 않는다.

분석 실패나 미지원 API는 악성 증거가 아니다. 반드시 `status`, `warnings`,
`errors`, `analysis_time_ms`, `metadata`를 함께 보존하고 후속 모듈에서 구분한다.

## 2.1 Speakeasy 한계와 보완 경로

Speakeasy의 분석 범위를 무리하게 넓혀 모든 실행 환경을 재현하려고 하지 않는다.
Speakeasy에서 개선할 수 있는 영역과, 별도 도구로 넘겨야 하는 영역을 구분한다.

| 문제 | Speakeasy에서 할 수 있는 보완 | Speakeasy로 해결하지 않는 영역 | 다음 경로 |
|---|---|---|---|
| 지원하지 않는 API | 자주 사용되는 API의 제한적인 Stub·Hook 추가, 미지원 API 이름 기록 | 임의의 모든 API 동작을 정확히 재현하는 것 | 부분 Evidence 반환 또는 CAPE |
| 지연 로딩 API·미실행 코드 | 실행 프로필 추가, 가능한 진입점 실행, API·행동 Coverage 기록 | 모든 입력·분기·환경 조건을 탐색하는 것 | 여러 실행 프로필 또는 CAPE |
| 실제 프로세스·네트워크 행위 | 자식 프로세스 에뮬레이션, 네트워크 Mock, 호출 이벤트 기록 | 실제 Windows 프로세스·네트워크 환경의 완전한 재현 | 격리 VM 기반 CAPE |
| .NET 분석 | PE 내부의 .NET 여부 판별과 분석 경로 분기 | Speakeasy 안에서 CLR·IL 실행을 완전히 지원하는 것 | 별도 .NET 메타데이터·IL 분석기 |

### 2.1.1 미지원 API 보완 원칙

- 자주 등장하고 의미가 명확한 API만 우선 Stub·Hook 대상으로 선정한다.
- Stub이 실제 API의 부작용을 재현하지 못하면 `SUCCESS`로 숨기지 않는다.
- Stub으로 관찰한 결과에는 사용한 Stub 이름과 버전을 metadata에 기록한다.
- 알 수 없는 API는 기존처럼 `UNSUPPORTED_API`와 부분 결과로 반환한다.
- 미지원 API가 여러 개 발생하면 지원 범위를 억지로 추정하지 않고 CAPE 또는 전문가 검토로 넘긴다.

### 2.1.2 실행 경로와 Coverage 보완

지연 로딩 API나 실행되지 않은 코드 경로는 한 번의 에뮬레이션만으로 모두 확인할 수
없다. 다음 순서로 제한적으로 보완한다.

1. 기본 진입점 실행 결과를 저장한다.
2. DLL의 분석 가능한 Export 또는 알려진 진입점을 별도 프로필로 실행한다.
3. API 호출·행동 이벤트와 실행 경로 Coverage를 분석 결과에 기록한다.
4. 새로운 증거가 기대될 때만 추가 프로필을 실행한다.
5. 프로필 수와 총 실행 시간을 제한한다.

Coverage가 낮다는 사실은 그 자체로 악성 증거가 아니다. `coverage`,
`analysis_reliability`, `warnings`를 별도 값으로 저장한다.

### 2.1.3 실제 행위 재현의 경계

Speakeasy의 결과는 빠른 에뮬레이션 기반 관찰 결과로 취급한다.

- `emulate_children=True`는 자식 프로세스 관찰 가능성을 높이지만 실제 Windows 프로세스 환경을 완전히 재현하지 않는다.
- 네트워크는 기본적으로 호출과 인자 관찰·Mock 중심으로 다룬다.
- 실제 외부 통신이나 파일 시스템 변경이 필요한 분석은 개발 PC에서 수행하지 않는다.
- 실제 행위와 메모리·프로세스·네트워크 상호작용이 필요하면 격리된 CAPE 경로로 보낸다.

### 2.1.4 .NET 분리 원칙

.NET PE는 우선 다음과 같이 별도 경로로 처리한다.

```text
.NET PE 판별
    ├─ Metadata·IL 정적 분석 → DOTNET_ANALYSIS Evidence
    └─ 동적 CLR 행위 필요   → 승인된 샌드박스 또는 별도 .NET 도구
```

Speakeasy에서 .NET 지원을 억지로 추가하지 않는다. .NET 분석 결과도 동일한
`DynamicAnalysisResult`와 Evidence 형식으로 변환해 JRR이 도구 차이를 알지 못해도
처리할 수 있게 한다.

### 2.1.5 완료 기준

- [ ] 미지원 API가 성공으로 잘못 표시되지 않음
- [ ] Stub·Hook의 적용 여부와 버전이 기록됨
- [ ] 부분 결과와 Coverage가 함께 저장됨
- [ ] 추가 실행 프로필에 최대 횟수·시간 제한이 있음
- [ ] 실제 프로세스·네트워크 재현 한계가 문서화됨
- [ ] .NET 입력이 Speakeasy 경로에서 별도 분석 경로로 분기됨
- [ ] CAPE 전환 조건이 JRR 정책에 정의됨

## 3. 공통 분석기 인터페이스

추가 도구를 연결할 때는 도구별 출력 형식을 그대로 노출하지 않고 공통 결과로 변환한다.

```python
class DynamicAnalyzer(Protocol):
    def analyze(self, sample_path: str | Path) -> DynamicAnalysisResult:
        ...
```

모든 분석기는 최소한 다음 정보를 반환해야 한다.

```text
evidence_id
sha256
source
category
status
summary
observed_apis
api_call_counts
behaviors
events
warnings
errors
analysis_time_ms
tool_version
started_at
completed_at
metadata
raw_reference
```

### 도구별 역할

| 도구 | 역할 | 기본 대상 | 비용 | 현재 계획 |
|---|---|---|---|---|
| Speakeasy | 빠른 에뮬레이션과 1차 행동 확인 | Windows PE | 낮음~중간 | 현재 MVP 기본 경로 |
| CAPE Sandbox | 격리 환경의 정밀 행위·페이로드 분석 | Windows 악성코드 중심 | 높음 | 확장 또는 시연용 |
| Qiling | 다중 포맷 에뮬레이션과 시스템 호출 후킹 | ELF, PE 등 | 중간~높음 | ELF 확장 시 검토 |

## 4. CAPE Sandbox 연계 계획

CAPE는 단순히 현재 Python 프로세스에 import해서 사용하는 보조 라이브러리라기보다,
샘플을 격리된 샌드박스에서 실행하고 분석 결과를 수집하는 별도 분석 환경으로 취급한다.
CAPE는 정적·동적 분석과 설정·페이로드 추출을 제공하는 샌드박스 프로젝트다.

### 도입 목적

- Speakeasy가 재현하지 못하는 실제 실행 흐름을 보완
- 프로세스 생성, 파일 생성, 네트워크 연결 등 더 풍부한 행위 수집
- 패킹된 샘플의 설정값·페이로드 추출 경로 제공
- 발표 시 “저비용 1차 분석 → 고비용 정밀 분석” 구조 시연

### 연계 방식

현재 코드에 CAPE 실행 로직을 직접 넣지 않고 다음 어댑터를 별도로 둔다.

```text
CapeSandboxAnalyzer
    ↓
CAPE 제출 방식
    ├─ 격리 환경의 API
    ├─ 작업 큐
    └─ 사전에 정의한 CLI/리포트 디렉터리
    ↓
CAPE 결과 수집 및 timeout 처리
    ↓
공통 DynamicAnalysisResult
```

### CAPE 결과 매핑

```text
CAPE 완료             → SUCCESS
작업 제한 시간 초과    → TIMEOUT
샌드박스 환경 미지원   → UNSUPPORTED_TARGET
분석 작업 실패         → TOOL_ERROR
결과는 받았지만 경고 있음 → 경고 내용에 따라 TOOL_ERROR 또는 부분 결과
```

CAPE의 원본 결과는 JSON·HTML·스크린샷 등 형식이 다양할 수 있으므로 전체 결과를
Evidence JSON에 넣지 않는다. 결과 파일은 artifact로 저장하고 `raw_reference`와
분석 ID만 공통 결과에 기록한다.

### CAPE 구현 순서

1. CAPE를 실행할 격리 환경의 운영 방식 결정
2. 샘플 제출·상태 조회·결과 다운로드 인터페이스 결정
3. 가짜 CAPE 응답을 사용하는 `CAPE` 어댑터 단위 테스트 작성
4. timeout, 제출 실패, 결과 누락, 환경 미지원 상태 매핑
5. 정상·악성 공개 테스트 샘플로 실제 연계 확인
6. JRR이 꼭 필요한 경우에만 CAPE를 선택하도록 연결
7. 분석 비용과 지연 시간을 Demo 화면에 표시

### CAPE 도입 조건

- 격리 환경이 별도로 준비되어 있을 것
- 호스트 파일 시스템과 네트워크가 보호되어 있을 것
- 분석 시간과 동시 작업 수에 제한이 있을 것
- 결과를 SHA-256으로 원본 샘플과 연결할 것
- CAPE가 실패해도 악성으로 자동 판정하지 않을 것

## 5. Qiling 기반 ELF 확장 계획

Qiling은 PE뿐 아니라 ELF, Mach-O 등 여러 실행 형식을 다루는 바이너리 에뮬레이션
프레임워크다. 따라서 “ELF 전용 도구”라고 문서화하기보다 “ELF를 포함한 다중 포맷
확장용 분석 엔진”으로 정의한다.

### 도입 목적

- Linux ELF 분석으로 대상 파일 형식 확장
- 시스템 호출과 파일·네트워크 접근을 후킹
- PE 전용 모듈과 ELF 전용 모듈을 공통 Evidence 흐름에 연결
- 향후 IoT·임베디드 바이너리 분석 가능성 확보

### 예상 구조

```text
파일 형식 판별
    ├─ PE  → SpeakeasyAnalyzer
    ├─ PE 정밀 분석 필요 → CapeSandboxAnalyzer
    └─ ELF → QilingAnalyzer
                         ↓
              DynamicAnalysisResult
```

### Qiling 구현 범위

초기 ELF 지원은 다음으로 제한한다.

- ELF32·ELF64 기본 판별
- 아키텍처와 엔디언 기록
- 실행 파일·공유 라이브러리 구분
- 프로세스 실행 없이 에뮬레이션
- 파일 접근·네트워크·프로세스 관련 시스템 호출 후킹
- timeout과 명령어 수 제한
- rootfs를 읽기 전용 또는 통제된 임시 디렉터리로 제한
- 관찰 이벤트를 공통 `events` 형식으로 변환

처음부터 모든 Linux 배포판과 모든 아키텍처를 지원하지 않는다. 먼저 하나의 ELF
아키텍처와 공개 가능한 정상 fixture로 계약 테스트를 통과시키고 확장한다.

### Qiling 구현 순서

1. 파일 형식 판별 결과에 `ELF32`, `ELF64`와 아키텍처 정보 추가
2. `DynamicAnalyzer` 공통 인터페이스와 상태 매핑 확정
3. Qiling을 선택적 의존성으로 분리
4. 읽기 전용 rootfs와 자원 제한 설정
5. 시스템 호출 이벤트를 공통 Evidence로 변환
6. 정상 ELF fixture에서 반복 실행 일관성 검증
7. JRR이 ELF 입력일 때 Qiling 경로를 선택하도록 연결

## 6. JRR 연결 방향

추가 분석은 모든 파일에 실행하지 않는다. 정적 모델과 위험 신호가 추가 분석을 요구할
때만 실행한다.

```text
정적 분석
    ↓
JRR 1차 판단
    ├─ 신뢰 가능한 정상 → 자동 처리 제안
    ├─ 신뢰 가능한 악성 → 악성 경보 제안
    ├─ PE 불확실·중위험 → Speakeasy
    ├─ PE 고위험·정밀 분석 필요 → CAPE
    ├─ ELF 입력 → Qiling
    └─ 도구 미지원·실패 → MANUAL_REVIEW 또는 ANALYSIS_INCOMPLETE
```

MVP에서는 추가 분석 단계를 최대 1회로 제한한다. CAPE와 Qiling을 추가하더라도 다음
제한은 유지한다.

- 동일 도구와 동일 설정을 반복하지 않는다.
- 남은 시간·비용을 초과하는 분석을 시작하지 않는다.
- 분석 실패를 악성 증거로 취급하지 않는다.

## 7. 평가 계획

도구를 추가하는 것이 실제로 유용한지는 단순히 “더 많은 로그가 나왔다”로 평가하지
않는다.

### 비교 경로

- 정적 분석만 사용
- 정적 분석 + Speakeasy
- 정적 분석 + CAPE
- 정적 분석 + Speakeasy 후 필요 시 CAPE
- ELF 정적 분석 + Qiling

### 측정 항목

- 악성 미탐 회수율
- False Negative Recovery
- 자동 처리 구간의 FNR
- 전문가 검토 유입량
- 분석 성공률과 timeout 비율
- 평균 분석 시간
- 파일당 평균 비용
- 도구 미지원 비율
- 중복 분석 횟수
- Evidence의 SHA-256 연결 정확성

CAPE는 분석 비용이 높으므로 Speakeasy보다 항상 성능이 좋아야 하는 것이 아니다.
동일한 분석 예산에서 추가로 회수한 오류와 악성 미탐이 있는지를 비교한다.

## 8. 안전 및 운영 원칙

- 원본 악성 PE를 개발 PC에서 직접 실행하지 않는다.
- CAPE는 별도의 격리 VM 또는 승인된 분석 환경에서만 실행한다.
- CAPE 분석 VM은 스냅샷 복구와 네트워크 차단 정책을 사용한다.
- Qiling rootfs는 샘플별 임시 영역으로 분리하고 호스트 경로를 직접 노출하지 않는다.
- 모든 도구에 timeout, 명령어 수, 파일 크기, 출력 크기 제한을 둔다.
- 원본 샘플·메모리 덤프를 Git이나 외부 LLM에 업로드하지 않는다.
- 원본 report는 `artifacts/` 또는 별도 저장소에 두고 Git에는 커밋하지 않는다.
- 도구 버전, 실행 시각, 설정, SHA-256, 실패 상태를 기록한다.
- 분석 실패와 실제 행위 증거를 별도 필드로 보존한다.

## 9. 단계별 우선순위

### 1단계 — 현재 MVP 안정화

- [x] Speakeasy 공통 Evidence 출력
- [x] 부분 결과와 실패 상태 구분
- [x] API 호출 수와 이벤트 요약
- [x] 실행 메타데이터 기록
- [x] timeout 종료 안전장치
- [x] 원본 report artifact 저장
- [ ] 다른 팀 모듈이 사용할 출력 계약 리뷰

### 2단계 — 시연용 확장

- [ ] CAPE 격리 환경 확보 여부 결정
- [ ] CAPE 어댑터 인터페이스 설계
- [ ] CAPE mock 응답 테스트 작성
- [ ] CAPE 결과의 Evidence 변환
- [ ] JRR의 고위험 경로에 CAPE 연결
- [ ] Demo 화면에 도구·비용·상태 표시

### 3단계 — ELF 확장

- [ ] ELF 파일 형식 판별
- [ ] Qiling 선택적 의존성 분리
- [ ] QilingAnalyzer 기본 구현
- [ ] 시스템 호출 이벤트 매핑
- [ ] ELF fixture와 계약 테스트 추가
- [ ] ELF 입력에 대한 JRR 경로 연결

### 4단계 — 통합 평가

- [ ] 동일 샘플의 정적·Speakeasy·CAPE·Qiling 결과 연결
- [ ] 도구별 비용과 실패율 기록
- [ ] 단순 정책과 JRR 비교
- [ ] 발표용 시나리오 작성
- [ ] 지원하지 않는 기능과 한계 문서화

## 10. 지금 당장 하지 않을 것

- CAPE를 현재 Windows 개발 환경에 바로 설치하지 않는다.
- Qiling을 현재 PE 분석 코드에 억지로 추가하지 않는다.
- 도구마다 다른 결과 JSON을 JRR에 직접 연결하지 않는다.
- CAPE나 Qiling 결과만으로 최종 악성 판정을 내리지 않는다.
- ELF 전체 아키텍처를 한 번에 지원하려고 하지 않는다.
- 실제 악성 샘플을 저장소 fixture로 추가하지 않는다.

## 11. 참고 자료

- [CAPE 공식 저장소](https://github.com/ctxis/CAPE)
- [CAPE 공식 문서](https://capev2.readthedocs.io/en/latest/introduction/what.html)
- [Qiling 공식 저장소](https://github.com/qilingframework/qiling)
- [Qiling 공식 문서](https://docs.qiling.io/en/latest/)
- [현재 Speakeasy 분석 모듈 문서](./speakeasy.md)
