# 평가 및 Lockbox 정책

> `[EVAL] 평가 및 Lockbox 정책 작성` 이슈용. DATASET_GUIDE.md 규칙을 프로젝트 전체 정책으로 공식화.

## 1. 지표 정책

- **공식 지표**: ROC-AUC(threshold 무관) + 고정 FPR(잠정 0.1%)에서의 TPR
- **금지**: Accuracy, F1 — 이 데이터의 50:50 비율이 실제 운영 환경과 다르므로 배포 성능을 예측하지 못함
- **참고용 허용**: Recall/FNR은 팀 내부 논의용으로만 병기 가능하나, 공식 보고 수치는 TPR@FPR 기준

## 2. Threshold 산출 규칙

1. Threshold는 **반드시 calibration 세트에서만** 산출
2. eval 세트에는 산출된 threshold를 **적용만** 함 (재산출 금지)
3. Lockbox(test/challenge)에는 프로젝트 종료 시점 **1회만** 적용

## 3. 데이터 분할 정책

- **시간 기반 분할만 사용** (week_id 등), 무작위/층화 재분할 금지
- train/calibration/eval 3분할 유지, calibration·eval 폭은 동일하게 (비대칭 시 시간 이동 대리지표로서의 의미 상실)
- **협회 데이터 수령 시**: 협회 데이터도 자체 시간 정보(수집일 등) 있으면 동일 원칙 적용. 없으면 Group-based Split(계열 단위)으로 대체하고 별도 정책 문서화

## 4. Lockbox 취급 규칙

- **대상**: EMBER test/challenge, (추후) 협회 데이터 자체 Lockbox
- **열람 시점**: 11주차 최종 검증 딱 1회
- **열람 담당자**: 데이터 담당(김정윤 또는 최지원) 중 1명이 대표 실행, Discord에 실행 로그 공유
- **행 삭제 금지**: 라벨 -1 포함 원본 그대로 유지, `valid_mask_*`만 별도 적용
- **challenge 세트 특이사항**: 전량 악성(label=1)이므로 ROC-AUC 계산 불가. 고정 threshold에서의 TPR(탐지율)만 유효. Win32/Win64 필터링 시 표본이 수백~수천으로 줄어들 수 있어 **점추정치 단독 보고 금지, 신뢰구간 병기**

## 5. Ablation 정책

위험 신호(Calibration, 모델 불일치, OOD, 분석 난이도, 확장안) 각각을 제거했을 때 성능 변화를 반드시 확인. 효과 없는 신호는 최종 파이프라인에서 제외.

## 6. Kill Test 기준

| 대상 | 기준 | 폐기 조건 |
|---|---|---|
| Joint Risk Router | 여러 검토예산(1/5/10/20%)에서 단순 confidence threshold보다 일관되게 우수해야 함 | 못 이기면 단순 정책으로 축소 |
| 확장안(Speakeasy 에뮬레이션) | confidence/OOD 대비 추가 오판 회수 여부 | 추가 이득 없으면 정규 범위에서 제외 |

## 7. 서비스 레벨 평가 (검토예산 정책 비교)

무작위 선별 / 낮은 Confidence 순 / 높은 OOD 순 / 모델 불일치 순 / Joint Risk Router 순, 5개 정책을 검토예산 1/5/10/20% 각각에서 비교. 지표: 회수 오판 수, Review Yield.

## 8. 재현성

- 모든 실험은 MLflow에 기록 (`dataset_source`, `feature_set`, `split_type` 태그 필수)
- Lockbox 파일 sha256은 `manifest.json` 기준으로 무결성 확인 가능해야 함

## 확정 필요 (회의 안건)

- [ ] 목표 FPR을 0.1%로 고정할지, 팀 회의에서 재검토할지
- [ ] 협회 데이터 Lockbox 분리 비율 및 시점(수령 즉시 vs 특징 스키마 확정 후)
