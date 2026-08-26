# Tiered 심층분석 계약

이 모듈은 JRR이 고위험·불확실 샘플을 심층분석으로 보냈을 때 다음 흐름을
한 번만 수행한다.

```text
JRR route
  ↓
Tier 1: CAPA
  ├─ ATT&CK 근거가 충분함 → COMPLETE
  └─ 근거 부족/상충 → Tier 2: Speakeasy
                         ├─ 정상 종료 → COMPLETE
                         └─ timeout/미지원/도구 오류 → FAILED
```

`feature/dynamic-analysis`의 Speakeasy 구현을 복사하지 않는다. 통합 시
`SpeakeasyAnalyzer` 객체를 `DeepAnalysisOrchestrator`에 주입한다.

## 사용 예시

```python
from trust_triage.deep_analysis import DeepAnalysisOrchestrator
from trust_triage.static_analysis import CapaAnalyzer

# SpeakeasyAnalyzer는 dynamic-analysis 모듈에서 주입한다.
orchestrator = DeepAnalysisOrchestrator(
    capa_analyzer=CapaAnalyzer(),
    speakeasy_analyzer=speakeasy_analyzer,
)
result = orchestrator.run(
    sample_path,
    initial_route="HIGH_RISK_UNCERTAIN",
    initial_verdict="UNKNOWN",
)
payload = result.to_dict()
```

## `deep_analysis_status`

| 상태 | 의미 |
|---|---|
| `NOT_REQUIRED` | JRR route가 심층분석 대상이 아니어서 도구를 실행하지 않음 |
| `COMPLETE` | 필요한 Tier가 정상 종료됨. 근거가 부족하면 `final_verdict=UNKNOWN`과 분석가 검토를 함께 반환할 수 있음 |
| `FAILED` | 필요한 도구가 timeout, 미지원 API, 환경 오류 등으로 완료되지 않음 |

도구 실패는 악성 Evidence로 변환하지 않는다. 실패 원인은
`tool_statuses`, `reason_codes`, `errors`에 보존하고 `ANALYSIS_FAILED`와
분석가 검토를 권고한다.

## ATT&CK Evidence 정규화

CAPA가 반환하는 원문 라벨은 `details.attack`에 그대로 보존하면서
`attack_techniques`에 정규화 결과를 추가한다.

```json
{
  "source": "CAPA",
  "category": "CAPABILITY_MATCH",
  "status": "OBSERVED",
  "details": {
    "attack": ["Defense Evasion::Process Injection"]
  },
  "attack_techniques": [
    {
      "technique_id": "T1055",
      "technique_name": "Process Injection",
      "tactics": ["Defense Evasion", "Privilege Escalation"],
      "mapping_status": "MAPPED"
    }
  ]
}
```

알 수 없는 라벨은 버리지 않고 `technique_id=null`,
`mapping_status=UNMAPPED`로 남긴다. 현재 MVP의 매핑 카탈로그는 자주 사용되는
CAPA 라벨과 Speakeasy 관찰 조합만 포함하며, 전체 ATT&CK 커버리지를 주장하지
않는다.

## Tier 진입 기준

`EvidenceSufficiencyPolicy`는 다음 점수를 사용한다.

```text
각 고유 Technique의 기여도 = severity × reliability
전체 점수 = 1 - ∏(1 - 각 Technique 기여도)
```

같은 Technique에 대한 중복 Evidence는 최대값 하나만 사용한다. 기본값은
정규화된 Technique이 1개 이상이고 전체 점수가 `0.55` 이상이면 충분한
것으로 처리한다. 이 값은 malware probability가 아니며, 실제 운영 전
calibration/evaluation 담당자가 검증해야 한다.

CAPA가 기준을 만족하면 Speakeasy를 실행하지 않는다. CAPA가 성공했지만
근거가 부족하거나 CAPA가 실패한 경우에는 Speakeasy를 한 번 시도한다.
Speakeasy까지 정상 종료했지만 근거가 부족하면 전체 분석은 `COMPLETE`이고
최종 제안은 `UNKNOWN`이며 `MANUAL_REVIEW`가 된다.

## 안전 제한

- 동일 Tier를 반복 실행하지 않는다.
- 입력 PE를 직접 실행하지 않는다. CAPA와 Speakeasy의 자체 분석 경계만 사용한다.
- timeout·도구 버전·원본 결과 참조·실패 상태는 상위 Evidence 처리에 전달한다.
- `final_verdict`는 시스템 제안이며, 악성·불확실 결과는 분석가 검토 대상이다.
