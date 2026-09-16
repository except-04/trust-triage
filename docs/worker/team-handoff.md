# Speakeasy Worker 연결 안내

Worker는 아래 처리를 담당합니다.

`Backend에서 요청 → SQS에 대기 → Worker가 Speakeasy 분석 → PostgreSQL에 결과 저장`

- 건우: 이 브랜치의 Backend 처리기에서 심층 분석 서비스와 Worker로 이어지는 연결을 제공합니다. 같은 DB·S3 설정으로 `init-db --deep`, `serve`, `run`을 실행하고 실제 모델 산출물을 준비해주세요.
- 가영: SQS 큐 2개, 비공개 S3, PostgreSQL 연결, Worker 서버와 IAM 역할이 필요합니다. 큐 하나는 요청용이고, 다른 하나는 반복 실패한 요청을 받는 DLQ입니다.
- 상욱: Worker 실행과 오류 처리, AWS 연결 후 분석 테스트를 맡습니다.

S3 리포트는 `<prefix><sha256>/analyses/<analysis_id>/speakeasy/<tool_run_id>/report.json`에 보관하므로 Worker 역할에 해당 경로의 쓰기 권한도 필요합니다.

Worker가 끝나면 Speakeasy 단계만 완료됩니다. 이 브랜치에는 CAPA/FLOSS 이후 요청 등록과 Worker 결과 수신·증거 반영을 담당하는 Deep Analysis 서비스도 포함됩니다. Backend의 `run`이 저장된 단계에서 재개하여 전체 분석을 종료합니다. 상세 실행 절차는 [Backend 연결 안내](backend-integration.md)를 참고하세요.

회의에서는 다음처럼 설명할 수 있습니다.

> Worker 처리와 함께 CAPA/FLOSS 이후 자동 요청, Worker 결과 수신·증거 반영·전체 상태 갱신까지 연결했습니다. 로컬에서는 대역 분석기·클라우드 클라이언트와 실제 PostgreSQL로 검증했습니다. AWS와 격리 서버가 준비되면 실제 모델·분석 도구와 승인된 PE로 배포 환경을 검증해야 합니다.

[실행·AWS 설정](speakeasy-worker.md) · [건우가 연결할 함수](contracts.md)
