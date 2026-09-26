# 초기 모델 데모 기록 (Deprecated)

이 문서는 과거 `tests/demo/01/demo.py` 파일의 범위를 설명하던 기록입니다.
현재 백엔드-Worker 연동 통합 환경(MVP)이 완성됨에 따라 해당 단독 실행 데모 코드는 **완전히 삭제(Deprecated)** 되었습니다. 

실제 운영 대시보드와 통합 테스트는 `dashboard/` 및 `tests/dashboard/`에서 수행됩니다.

과거 모델 파일 경로 등 역사적 맥락 유지를 위해 아래 디렉토리 구조만 보존합니다.

## 1. 폴더 구조 (과거 아티팩트 보존)

```
trust-triage/
└── tests/
    └── demo/
        └── 01/
            ├── demo.py (삭제됨, 안내 문구만 보존)
            └── artifacts/ (과거 실험 모델 원본 보존)
                ├── baseline_model_lightgbm_tuned_500_4way.pkl
                ├── baseline_model_xgb_500_4way_1000cap.pkl
                ├── feature-selection-ember-v3-top500.json
                ├── jrr_calibrator_4way.pkl
                └── jrr_risk_signals.pkl
```
