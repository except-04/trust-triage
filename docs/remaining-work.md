# 잔여 작업과 선택적 확장

정리일: 2026-09-26. 현재 코드·문서 기준이며 실환경 검증을 새로 실행한 기록은 아니다.

완료된 구현은 각 모듈 문서에서 설명한다. 아래 미체크 항목은 개발, 검증 또는 운영 결정이 남았다는 뜻이며 모두 기능 미구현을 뜻하지 않는다. 과거 실험 기록과 폐기된 초안은 당시 맥락을 유지한다.

## 현재 경로의 개발·검증 잔여 작업

- [ ] 실제 PE → 특징 추출 → Top-500 → 공식 모델 → SHAP 자동 E2E 회귀 테스트 ([SHAP](shap-explanation-module.md))
- [ ] 대용량 PE 처리 시간·메모리 벤치마크 ([특징 추출](feature-extraction/plan.md)). 크기 제한·timeout은 이미 구현됨.
- [ ] JRR 평가의 MLflow 필수 태그 자동 기록 ([평가 정책](docs_eval_lockbox_policy.md)). 지표 기록과 구분.
- [ ] 5개 정책 × 검토예산 1/5/10/20% 비교. 기존 3정책 라우팅 비교·ablation과 구분.
- [ ] 심층분석 이후 최종 오판 회수·비용·실패율 평가. [기존 보고서](../src/jrr/jrr_final_report.md)는 심층분석 전 라우팅 평가임.
- [ ] JRR 평가 보고 보완: 자동 정상/악성 전체 개별 건수, 구·신규 평가 수치 차이, OOD/불일치 임계값 선정 근거 ([JRR 한계](jrr_summary.md))
- [ ] Evidence 충분성 정책의 운영 전 calibration/evaluation 검증 ([심층분석](static-analysis/deep_analysis.md))

## 운영 설정·승인 확인

코드와 설정 예시의 존재만으로 실제 배포·팀 승인 완료를 판단하지 않는다.

- [ ] 실제 DB 배포 방식(RDS/EC2), AWS 네트워크 접근 범위 확인
- [ ] Worker 동시 실행 수, 증설·부하 제어 정책 확인
- [ ] S3 Lifecycle 실제 설정과 운영 보존 기간 확인 (앱 기본 보관값·정리 로직은 구현됨)
- [ ] 승인된 PE·실제 모델·분석 도구·AWS·LLM·UI 전체 E2E 검증
- [ ] 모델·인덱스·manifest의 공식 배포 패키징 절차 확정 (bundle 검증은 구현됨)
- [ ] 전체 Pipeline Freeze 및 Lockbox 실행·승인 기록 확인. 기존 보고서 존재를 1회 평가 규칙 준수로 간주하지 않음.
- [ ] 목표 FPR 공식 결정, 협회 데이터 수령 시 Lockbox 분할 정책 확정
- [ ] 팀 간 출력 계약 리뷰와 발표 시나리오 확인 (계약 코드·테스트와 별개)

## 선택적 확장 — 채택 시 구현

현재 PE MVP의 필수 기능 누락으로 집계하지 않는다. 구체적인 구현 항목은 연결된 문서에서 관리한다.

| 후보 | 현재 상태와 계획 |
|---|---|
| CAPE Sandbox, Qiling/ELF, .NET 전용 경로 | [동적 분석 확장 계획](dynamic-analysis/PLAN.md). .NET 판별만으로 전용 분석이 구현된 것은 아님. |
| Speakeasy Hook·Coverage·복수 실행 프로필 | 같은 계획서의 2.1.5절. 부분 결과 보존·오류 상태 구분은 구현됨. |
| API_GROUPS 확장·JRR/Evidence 연결 | [특징 추출 계획](feature-extraction/plan.md). 기본 3그룹 분류는 구현됨. |
| 파일명 유사도·추가 패킹 특징 | [특징 스키마](feature_schema.md). 공식 Top-500 모델과 별도의 제안. |
| MCP 서버·도구 | [인터페이스 설계](interface_spec.md)의 확장안. 범위 확정 및 구현 필요. |
| WebSocket | [서비스 구조](service_architecture.md)에서 PoC 필수 범위 제외. |

Ghidra CAPA는 동기 분석기 구현이 있으나 기본 비활성이며 현재 비동기 서비스는 활성화를 지원하지 않는다. 완전 미구현으로 분류하지 않는다.

## 과거 문서의 취급

- `docs_api_contract.md`, `docs_sqlite_schema.md`: 폐기 안내를 유지한다. 구 API·SQLite 구현을 새 잔여 과제로 만들지 않는다.
- `tests/demo/01/DEMO_SETUP.md`: 초기 데모의 기능 범위를 설명한다. 해당 데모의 빈 SHAP 필드는 운영 Dashboard의 미구현을 뜻하지 않는다.
- 과거 테스트 개수·실행 날짜는 보존하며 현재 실행 결과로 바꾸지 않는다.
- 라이브러리 업그레이드 시 재검증은 지속적인 유지보수 절차로 다룬다.
