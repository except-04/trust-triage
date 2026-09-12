# Backend 검증 기록

## 2026-09-11 — SHA-256 공유 저장과 최신 JRR 연동

원격 백엔드와 `main`의 변경을 반영한 Python 3.11 환경에서 확인했다. 공용 JRR의 `tau_low=0.65`, `tau_difficulty=6.0` 경계와 `triggered_signals` 계약을 사용한다.

| 확인 범위 | 결과 |
|---|---|
| `pytest tests/backend_api -q` | **598 통과, 2 건너뜀**. 실제 PostgreSQL 검사 49개 포함 |
| Ruff lint 및 format | `src/trust_triage/backend_api`, `src/trust_triage/storage`, `tests/backend_api` 통과 |
| OpenAPI | 명세 재생성 후 실제 앱 Schema·예시와 일치 확인 |
| `git diff --check` | 통과 |

건너뛴 2개는 PostgreSQL 전용 검사의 메모리 저장소 버전이며 PostgreSQL에서는 수행했다. TestClient의 기존 `httpx`·`anyio` 관련 deprecation 경고 2개가 있다.

- 임계값 직전·경계·직후, 모델 입력 위치에 따른 난이도 계산, 동시 발현된 위험 신호 전체와 대표 사유 보존을 확인했다.
- 신규 JRR 결과에서 신호 누락·잘못된 값·중복·자동 판정과 발현 신호의 충돌을 거부한다. 기존 기록의 누락 필드는 `null`로 조회하고 이미 저장된 초기 분석부터 재개할 수 있다.
- 신호 배열이 초기 결과 JSON·리포트에 저장되고 서비스 재시작과 전문가 검토 후에도 유지되며, 개별·목록·배치 HTTP 응답에 전달되는 것을 확인했다.
- 로컬/S3 대역에서 SHA-256 원본 공유·리포트 무결성과 보존, 실제 PostgreSQL에서 동시 접수·삭제, 이전 DB 스키마 전환을 확인했다.

모델·분석 도구는 테스트 대역을 사용했다. 실제 AWS·Streamlit·Worker·LLM을 연결한 전체 서비스 검증은 후속 통합 범위다. 저장 구조 전환은 [storage.md](storage.md), 최신 API 필드는 [api-reference.md](api-reference.md)를 참고한다.

## 2026-09-08 — 초기 백엔드 검증

2026-09-08, Python 3.11의 이 작업 폴더 전용 `trust-triage-env`에서 확인했다.

| 확인 범위 | 결과 |
|---|---|
| 외부 서비스 없는 Backend 테스트 | 403 통과. SQL 전용 검사의 메모리 버전 1개는 건너뜀 |
| 실제 PostgreSQL 저장소 계약 | 30 통과. 각 테스트의 임시 Schema만 생성·정리 |
| HTTP → PostgreSQL → 단계별 새 처리기 → 전문가 검토 | 2 통과. 초기·심층 분석만 테스트 대역 사용 |
| Ruff lint 및 format 검사 | 통과 |
| `git diff --check`, `pip check` | 통과 |
| OpenAPI 생성 | 생성된 JSON과 현재 앱 명세의 일치 확인 |
| Python wheel 빌드 | 성공. Backend SQL Schema 포함 확인 |

총 **435개 검증이 통과**했다. 테스트용 PostgreSQL은 검증 후 종료했다. TestClient의 `httpx`와 `anyio` 관련 사용 중단 예정 경고 2개가 있었으며 테스트 실패는 아니다.

업로드 형식·용량, SHA-256과 모델 Feature 규격, 재시도·점유권, 단계별 저장·재시작, 중복 요청, 검토 충돌, 공개 응답의 상태·필드, 심층 분석의 요청 식별자, 진행 중인 Worker 원본 보존을 검사했다. 원본 업로드 테스트에는 실행 코드 없는 헤더 데이터만 사용했다.

실제 팀 모델을 역직렬화하거나 실제 PE를 Feature/도구/에뮬레이터에 넣는 통합 검증, AWS S3/SQS 연결, 외부 LLM 호출은 수행하지 않았다. 이는 팀 모델 여섯 산출물, 검토한 Deep Analysis/Worker 코드, 승인된 격리 환경과 서비스 설정을 준비한 뒤 수행해야 한다. 현재 테스트가 모델의 탐지 성능이나 운영 환경의 분석 성공을 증명하지는 않는다.

현재 실행 방법과 모듈 구조는 [백엔드 구조 설명](backend-structure.md), API 사용법은 [API 안내](api-reference.md)를 참고한다.
