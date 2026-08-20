## 1. 폴더 구조

```
Project/
├── demo/
│   ├── demo.py
│   └── artifacts/
│       ├── baseline_model_lightgbm_tuned_500_v4_9120.pkl   (약 29.9MB)
│       ├── baseline_model_xgb_500.pkl                      (약 2.1MB)
│       ├── feature-selection-ember-v3-top500.json          (약 16KB)
│       └── jrr_calibrator.pkl                              (약 4KB)
└── trust-triage/
    ├── src/
    │   └── jrr/
    │       └── 10_jrr_router.py
    ├── pyproject.toml
    ├── requirements.txt
    └── ...
```

---

## 2. 패키지 설치

```
cd Project/trust-triage        # clone한 폴더
.\.venv\Scripts\Activate.ps1   # (Windows) 가상환경 켜기
pip install -e .
```

---

## 3. 실행 방법


```
python demo.py --path <분석할_파일_경로>
```

예시:

```
# Windows
python demo\demo.py --path "C:\Windows\System32\notepad.exe"
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
  "risk_score": null,
  "route": "AUTO_QUARANTINE",
  "top_features": []
}
```

| 필드 | 의미 |
|---|---|
| `verdict` | `자동 정상`(AUTO_PASS) / `자동 악성`(AUTO_QUARANTINE) / `심층 분석`(그 외, 초기값) |
| `route` | JRR 라우팅 결정. 기본값은 `MANUAL_REVIEW` |
| `calibrated_probability` | 보정된 악성 확률 |
| `risk_score`, `top_features` | 추후 추가 |

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
TAU_LOW            = 0.1    # 자동 통과 임계값
TAU_DISAGREE       = 0.3    # 모델 간 불일치 임계값
EXTRACT_TIMEOUT_SEC = 30.0  # 특징 추출 타임아웃(초)
```

`TAU_HIGH`는 상수가 아니라 `jrr_calibrator.pkl` 안의 `threshold` 값을 그대로 사용

---
