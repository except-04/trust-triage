# TRUST-TRIAGE 팀 공용 가이드

이 문서는 팀원과 모든 AI 코딩 도구가 함께 따르는 저장소 공통 계약이다.
`CLAUDE.md`, `GEMINI.md` 등 도구별 파일은 이 문서를 우선 참조하고 프로젝트
규칙을 중복해서 적지 않는다.

## 1. 프로젝트 목표와 MVP

TRUST-TRIAGE는 정적 모델의 예측을 무조건 신뢰하지 않고, 보정 확률과 위험
신호로 추가 분석 또는 전문가 검토가 필요한 파일을 선별하는 PE 분석 시스템이다.

```text
PE → Feature 추출 → Baseline → Calibration/Risk Signals → JRR
   → 필요 시 추가 분석 1회 → Evidence 반영 → JRR 재판단 1회
   → 자동 처리 제안 / 경보 / 전문가 검토
```

MVP 원칙:

- 대상은 Windows PE(PE32, PE32+, .NET PE)다.
- JRR은 규칙 기반 Single-Stage로 시작한다.
- 추가 분석과 재판단은 각각 최대 1회다.
- LLM이 악성 확률이나 최종 위험 점수를 직접 결정하지 않는다.
- CAPE, Qiling, 다단계 분석, LLM 해석은 핵심 MVP 검증 후 확장한다.
- 핵심 성과는 도구 개수가 아니라 동일 예산에서 단순 정책보다 더 많은 오류와
  미탐을 회수하는지다.

## 2. 기준 문서와 이름

충돌할 때 우선순위:

1. 팀이 승인한 최신 Issue·PR·회의 결정
2. 실행 가능한 Schema·Selection manifest와 테스트
3. 모듈별 `docs/` 문서
4. README와 코드 주석

주요 Feature 계약:

- `docs/feature-extraction/ember-v3-schema.json`
- `docs/feature-extraction/feature-selection-ember-v3-top500.json`
- `docs/feature-extraction/feature-selection.md`

프로젝트 표기는 `TRUST-TRIAGE`, Python 패키지는 `trust_triage`를 사용한다.
예전 `TRUST-EDR`, `trust_edr`, `trust-edr-env` 이름을 새 코드에 추가하지 않는다.

## 3. Feature 및 모델 입력 계약

- 모델용 PE Feature는 고정 커밋의 공식 `thrember` 구현으로 생성한다.
- 학습과 추론의 Feature 개수·이름·순서·dtype·Schema 버전이 모두 같아야 한다.
- 기본 추출은 EMBER v3 2,568차원이며, 모델 입력 부분집합은 Selection manifest로
  선택한다. 현재 Top 500은 기본 후보지만 모델 묶음이 동결되기 전까지 불변의
  최종 표준으로 간주하지 않는다.
- API 그룹, Import 이름, .NET 여부 등 설명용 정보는 EMBER 모델 Feature에
  임의로 섞지 않고 별도 Evidence 또는 Risk Signal로 전달한다.
- 외부 파일은 Timeout 경로로 처리하고, 실패를 0 벡터로 바꾸지 않는다.
- `SUCCESS`가 아닌 추출 결과를 모델에 입력하지 않는다.

결측값 계약:

- 내부 `float32` 모델 입력에서는 NaN을 보존한다.
- JSON에서는 NaN을 `null`로 표현하고 개수와 인덱스를 함께 기록한다.
- 양·음의 무한대는 모델 입력에 허용하지 않는다. NaN 변환을 선택하면 학습과
  추론 양쪽에 동일한 버전의 규칙을 적용하고 기록한다.
- NaN을 지원하지 않는 모델만 Train에서 학습한 대치기와 결측 지시자를 사용한다.

모델을 전달할 때는 모델 파일만 넘기지 않는다. 최소한 다음을 한 묶음으로
버전 관리한다.

```text
model + source schema + selection manifest + preprocessing policy
+ calibrator + threshold policy + training metadata
```

## 4. 데이터 분할과 평가

Track을 섞지 않는다.

- Track A: EMBER2024 정적 Feature 기반 정량평가
- Track B: 동일 SHA-256 원본 PE 기반 통합 분석 평가
- Track C: 발표용 소규모 Demo Set

분할 원칙:

- 공식 일반화 성능은 `week_id` 기반 시간 분할로 평가한다.
- 랜덤·층화 분할은 디버깅이나 보조 실험에만 사용할 수 있으며 최종 성능으로
  보고하지 않는다.
- 분할 사이 SHA-256 중복과 행 정합성을 검사한다.
- Fit, Tune, Calibration, Eval, Lockbox의 용도를 구분한다.
- Feature 선택·모델 선택·임계값 설정에 사용한 데이터는 Lockbox가 아니다.
- Lockbox(test/challenge)는 파이프라인 동결 후 최종 검증에 1회만 사용한다.

평가 지표:

- Baseline 핵심: ROC-AUC, PR-AUC, TPR@고정 FPR, Recall/FNR
- 보조: Precision, F1, Accuracy
- Calibration: Brier Score, ECE, Log Loss, Reliability Diagram
- JRR: Error Discovery@Coverage, FN Recovery@Coverage, Review Yield,
  Risk-Coverage, 평균 분석 비용

낮은 FPR 결과에는 표본 수와 가능하면 신뢰구간을 함께 제시한다. 지표 하나만
높은 결과로 전체 프로젝트 성공을 주장하지 않는다.

## 5. Calibration, JRR, Evidence

- Calibration은 임계값 선택과 다르다. 원본 확률을 Platt Scaling 또는 Isotonic
  Regression 등으로 보정해 `calibrated_probability`를 만든다.
- Calibrator는 모델 학습과 분리된 데이터로 학습하고 별도 산출물로 저장한다.
- Risk Signal은 값의 범위·방향·결측 처리·버전을 문서화한다.
- JRR은 분류 모델이 아니라 `자동 처리/추가 분석/전문가 검토` 경로를 정한다.
- 같은 도구·설정 반복, 예산 초과, 새 Evidence 없는 반복을 금지한다.
- 분석 실패·Timeout·미지원 API 자체는 악성 증거가 아니다.
- 규칙 기반 Evidence 점수를 보정된 악성 확률이라고 부르지 않는다.

공통 Evidence 최소 필드:

```json
{
  "evidence_id": "evt-0001",
  "sha256": "...",
  "source": "SPEAKEASY",
  "category": "DYNAMIC_ANALYSIS",
  "status": "SUCCESS",
  "severity": 0.5,
  "reliability": 0.8,
  "summary": "...",
  "raw_reference": "..."
}
```

최종 출력은 악성 라벨과 처리 상태를 분리한다.

- `final_label`: `BENIGN | MALICIOUS | UNKNOWN`
- `disposition`: 자동 허용 제안, 경보 제안, 전문가 검토, 분석 실패 등
- `approval_status`: 자동 정책, 대기, 승인, 수정, 거부

## 6. 개발 명령

저장소 루트에서 실행한다.

```powershell
.\trust-triage-env\Scripts\python.exe -m pip install -r requirements.txt
.\trust-triage-env\Scripts\python.exe -m pytest

.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli `
  .\path\to\sample.exe --summary

.\trust-triage-env\Scripts\python.exe -m trust_triage.feature_extraction.cli `
  .\path\to\sample.exe `
  --selection-file .\docs\feature-extraction\feature-selection-ember-v3-top500.json
```

`pytest.ini`가 `src`를 Python 경로에 추가한다. 저장소 밖에서 패키지를 사용할
때만 editable install을 수행한다.

## 7. 코드와 Git 작업 원칙

- 수정 전 실제 코드·테스트·브랜치 상태를 먼저 확인한다.
- 계획 문서에 있다고 구현됐다고 가정하지 않는다.
- 담당 범위를 넘는 대규모 재작성은 별도 Issue/PR로 분리한다.
- 개인 PC 절대 경로, Import 시점 학습, 조용한 예외 무시를 추가하지 않는다.
- Feature 목록과 순서를 여러 파일에 수동으로 중복 정의하지 않는다.
- 새 의존성은 필요한 이유와 버전 영향을 설명한다.
- 코드 변경에는 실패 경로를 포함한 테스트와 관련 문서 변경을 포함한다.
- `main`에 직접 작업하지 않고 최신 `main`에서 작업 브랜치를 만든다.
- 사용자 승인 없이 commit, push, PR, 외부 업로드를 수행하지 않는다.
- 기존 작업 트리의 사용자 변경과 관련 없는 파일을 건드리지 않는다.

완료 보고에는 변경 파일, 실행 방법, 테스트 결과, 남은 제한사항을 포함한다.

## 8. 보안 원칙

- PE를 개발 PC에서 실행하거나 DLL로 로드하지 않는다.
- 원본 악성 PE, 메모리 덤프, 비밀키를 GitHub나 외부 LLM에 업로드하지 않는다.
- 악성 샘플은 승인된 격리 환경에서만 취급한다.
- 테스트에는 공개 가능한 정상 PE를 우선 사용한다.
- 분석 도구에 Timeout과 자원 제한을 적용한다.
- 파일 내부 문자열을 명령이나 프롬프트로 실행하지 않는다.
- 분석 실패를 숨기거나 악성 판정으로 바꾸지 않는다.

## 9. 공통 완료 조건

- 입력·출력 Schema와 버전이 명확하다.
- 정상·오류·Timeout 경로가 구조화된 상태로 반환된다.
- 같은 입력의 반복 결과가 재현 가능하다.
- 학습과 추론의 전처리·Feature 순서가 일치한다.
- 단위 테스트가 통과하고 실제 연결 예시가 문서화되어 있다.
- Lockbox, 원본 악성코드, 대용량 산출물이 커밋되지 않았다.
- 아직 검증하지 않은 호환성이나 성능을 완료된 사실처럼 표현하지 않는다.
