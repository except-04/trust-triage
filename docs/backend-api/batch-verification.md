# 배치 확장 검증 — 2026-09-09

구현 범위는 배치 요약, 초기 `HIGH_RISK_UNCERTAIN` 필터·우선 정렬, 제한을 적용한 ZIP 접수다. 상세 계약은 [API 종류와 설명](api-reference.md), 배포 전 DB 갱신 명령은 [백엔드 구조 설명](backend-structure.md)에 있다.

## 결과

| 검사 | 결과 |
|---|---|
| `pytest tests/backend_api -q` | **520 passed, 2 skipped** |
| 위 테스트 중 실제 PostgreSQL 검사 | **40 passed** |
| `ruff check src/trust_triage/backend_api tests/backend_api` | 통과 |
| `git diff --check` | 통과 |
| `export-openapi` | HTTP API 15개의 최신 명세 생성 |

전체 테스트는 Python 3.11 환경에서 수행했다. 메모리 저장소에는 적용할 수 없는 스키마 갱신·직접 SQL 제약 검사 2개만 건너뛰었으며, 실제 PostgreSQL에서는 둘 다 수행했다. 테스트 클라이언트 라이브러리의 기존 deprecation 경고 2개가 있다.

## 확인한 동작

- 작업 상태별 집계와 초기 판정별 집계를 별도로 제공한다. `SKIPPED`는 분석 실패에 포함하지 않는다.
- 배치의 대기·진행·일부 종료·전체 종료·전체 실패와 분석 작업이 없는 접수 내역을 구분한다.
- 고위험 우선 정렬과 초기 판정·상태·SHA-256·배치 필터를 페이지를 나누기 전에 적용한다.
- 시스템 최종 판정 또는 전문가 판정이 바뀌어도 초기 판정 필터가 유지된다.
- STORED·DEFLATE ZIP에서 하위 폴더와 동명 파일을 구분한다. 지원 형식·유효한 헤더를 가진 파일에만 독립 분석 번호를 발급한다.
- 잘못된 PE, 미지원 확장자·아키텍처·압축 방식·패치 데이터 기능, 암호화 파일, 중첩 ZIP, 파일별 제한 초과를 사유와 함께 기록한다.
- 경로 탈출, 절대 경로, NUL·제어 문자, 링크·특수 파일, 거짓 중앙 디렉터리 항목 수, 손상·CRC 오류, 압축률·총량·개수·시간 제한을 검사한다.
- ZIP 바이트와 멱등성 키가 같으면 최초 접수 내역을 반환한다. 입력이 전부 제외된 배치도 재시작·재전송 후 조회할 수 있다.
- DB 등록 실패 시 미등록 원본을 정리하며, 커밋 후 연결이 끊긴 경우에는 등록된 원본을 보존한다.
- 기존 DB에 `init-db`를 다시 적용해 새 열·인덱스를 추가해도 이전 접수 기록은 유지된다.
- Swagger의 요청·응답 예시가 실제 모델과 일치하고 모든 스키마 참조가 해석된다.

## 검증 환경과 범위

실제 PostgreSQL의 테스트별 임시 스키마와 로컬 임시 저장소를 사용했다. 테스트 스키마는 종료 시 삭제하며, 테스트 때문에 시작한 PostgreSQL도 종료했다. 기존 스키마 갱신 검사 역시 임시 스키마 안에서 수행했다.

입력은 실행 코드가 없는 헤더 전용 데이터와 텍스트다. 실제 악성 PE·모델·CAPA·FLOSS·Speakeasy·외부 LLM은 실행하지 않았다. 기존 모델·심층 분석 연결은 테스트 대역을 사용한다. 실제 S3·SQS 연결과 Streamlit의 API 연결은 이 검증에 포함하지 않는다. ZIP은 Python 표준 라이브러리를 사용해 새 설치 의존성이 없다.

## 재실행

연결할 **테스트 전용 DB**의 `BACKEND_TEST_DATABASE_URL`과 인증을 준비한 뒤 저장소 루트에서 실행한다. 테스트가 생성·삭제할 임시 스키마에 대한 권한이 필요하다.

```powershell
.\trust-triage-env\Scripts\python.exe -m pytest tests/backend_api -q
.\trust-triage-env\Scripts\python.exe -m ruff check src/trust_triage/backend_api tests/backend_api
.\trust-triage-env\Scripts\python.exe -m trust_triage.backend_api export-openapi
```

DB 연결 없이 검사할 때는 `pytest tests/backend_api -m "not postgres" -q`를 사용한다. 이는 실제 PostgreSQL 통합 검사를 대체하지 않는다.
