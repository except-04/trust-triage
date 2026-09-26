# 초기 모델 데모 기록

이 문서는 `tests/demo/01/demo.py`의 범위를 설명한다. 운영 대시보드는 `dashboard/`에 있으며 아래 데모의 미지원 항목을 현재 서비스의 잔여 작업으로 해석하지 않는다.

## 1. 폴더 구조

```
trust-triage/
├── tests/
│   └── demo/
│       └── 01/
│           ├── demo.py
│           └── artifacts/
│               ├── baseline_model_lightgbm_tuned_500_4way.pkl
│               ├── baseline_model_xgb_500_4way_1000cap.pkl
│               ├── feature-selection-ember-v3-top500.json
│               ├── jrr_calibrator_4way.pkl
│               └── jrr_risk_signals.pkl
├── src/
│   └── jrr/
│       └── jrr_router.py
├── pyproject.toml
├── requirements.txt
└── ...
```

---

## 2. 패키지 설치

```
# 저장소 최상위 경로(trust-triage)에서 실행
.\.venv\Scripts\Activate.ps1   # (Windows) 가상환경 켜기
pip install -e .
```

---

## 3. 실행 방법

```
cd tests/demo/01
python demo.py --path <분석할_파일_경로>
```

예시:

```
# Windows
python demo.py --path "C:\Windows\System32\notepad.exe"
```

### 인자

| 인자 | 필수 | 설명 |
|---|---|---|
| `--path <경로>` | 필수 | 분석 대상 파일 경로. 상대경로/`~` 모두 가능 (내부에서 절대경로로 변환) |
| `--quiet` | 선택 | 진행 로그(stderr) 출력을 끔 |

### 출력

- **결과 JSON → stdout**
- **진행 로그 → stderr**

출력 예시:

```json
{
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "verdict": "자동 악성",
  "analysis_status": "SUCCESS",
  "calibrated_probability": 0.9731,
  "initial_verdict": "AUTO_MALICIOUS",
  "route": "FINAL",
  "top_features": []
}
```

| 필드 | 의미 |
|---|---|
| `verdict` | `자동 정상`(AUTO_BENIGN) / `자동 악성`(AUTO_MALICIOUS) / `심층 분석`(그 외, 초기값) |
| `initial_verdict` | JRR 초기 판정. 기본값은 `HIGH_RISK_UNCERTAIN` |
| `route` | 다음 단계 처리 지시. 기본값은 `DEEP_ANALYSIS` |
| `calibrated_probability` | 보정된 악성 확률 |
| `top_features` | 이 초기 데모는 빈 목록을 반환함. 운영 Dashboard의 SHAP 연동과 별개 |

### 종료 코드

| 코드 | 의미 |
|---|---|
| `0` | 정상 완료 |
| `2` | 입력 파일 열기 실패(`InputError`) 또는 특징 추출 실패(`ExtractError`) |

추출 실패 시에도 부분 결과 JSON은 출력(`analysis_status`에 실패 사유 표기)

입력 실패 시에는 JSON 없이 에러 로그만

---

## 참고: 코드에 하드코딩된 값들

바꾸려면 `demo.py` 상단 상수를 수정해야 합니다.

```python
TAU_LOW            = 0.65   # 자동 통과 임계값
TAU_DISAGREE       = 0.3    # 모델 간 불일치 임계값
TAU_OOD            = 0.0    # OOD 임계값
TAU_DIFFICULTY     = 6.0    # 분석 난이도 임계값
EXTRACT_TIMEOUT_SEC = 30.0  # 특징 추출 타임아웃(초)
```

`TAU_HIGH`는 상수가 아니라 `jrr_calibrator_4way.pkl` 안의 `threshold` 값을 그대로 사용

---
