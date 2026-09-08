# Backend 검증 기록

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

실행 방법은 [사용 안내](usage.md), 모듈 구조는 [팀 설명용 안내](team-handoff.md)를 참고한다.
