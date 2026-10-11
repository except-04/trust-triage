# PR 제목

feat: 심층 분석 큐 일원화 및 검토 완료 탭 추가, 예산 제한 해제

# PR 본문

## 변경 목적

1. **심층 분석 큐 일원화**: 긴급 대응(EMERGENCY) 탭을 제거하고 심층 분석(DEEP) 탭으로 통합하여, 분석가가 한 화면에서 초기 4대 신호(확률 불확실성, 모델 불일치, 분포 이탈, 분석 난이도) 체계로 파일을 일관되게 검토할 수 있도록 개선했습니다.
2. **검토 완료(COMPLETED) 탭 추가**: 분석가가 상세 화면에서 검토 및 최종 판정을 완료(저장)한 이력을 별도로 확인할 수 있도록 '재학습 데이터'와 '오류 항목' 사이에 신규 탭을 추가했습니다. (DB 스키마 변경 없이 기존 컬럼 활용)
3. **예산 제한 해제 및 AUTO 차감 분리**: 대시보드에서 예산 제한 인터페이스가 제거됨에 따라 백엔드 추천 목록의 예산 상한 제한을 풀고, AUTO 검토 완료 건이 수동 검토 예산을 차감하지 않도록 수정했습니다.
4. **동적 관측 텍스트 간소화**: Speakeasy 분류 이유 표기에서 혼선을 줄 수 있는 `(동적 관측—결과 미확인)` 문구를 `(동적 관측)`으로 간소화했습니다.

---

## 주요 변경 사항

### 1. 대시보드 UI (`dashboard/app.py`, `dashboard/api_client.py`)
- **탭 구성 재배치**:
  - `심층 분석 (DEEP)` | `자동 처리 (AUTO)` | `재학습 데이터 (RETRAIN)` | `검토 완료 (COMPLETED)` | `오류 항목 (ERROR)`
- **심층 분석 큐 신호 일원화 (`format_deep_queue_item`)**:
  - 긴급 대응으로 분류되었던 항목들도 발생 원인 신호에 맞춰 `확률 불확실성`, `모델 불일치`, `분포 이탈`, `분석 난이도` 중 하나로 일원화 표기
- **검토 완료 탭 구현**:
  - `search_analyses(reviewed_only=True)` 연동
  - 20건 단위 서버 사이드 페이징 및 판정 결과 내역(`초기 판정 -> 최종 판정`) 표시
  - 행 선택 시 상세 결과 보기 지원
- **예산 UI 정리**:
  - 불필요한 예산 수치 설정/초과 대기열 영역 제거

### 2. 백엔드 API & 저장소 (`src/trust_triage/backend_api/`)
- **검토 완료 조회 필터 (`GET /analyses`)**:
  - `reviewed_only: bool = False` 쿼리 파라미터 추가
  - `repository.list_analyses`에 `analyst_final_verdict IS NOT NULL` 조건 추가 (DB 마이그레이션 불필요)
- **예산 계산 분리 (`repository.get_analyst_budget`)**:
  - `today_total_manual`(수동 검토 완료)과 `today_total_completed`(전체 완료)를 분리하여 AUTO 완료가 수동 검토 잔여 예산을 차감하지 않도록 처리
- **추천 제한 제거 (`service.get_priority_recommendations`)**:
  - 긴급/심층 추천 목록의 인덱스 슬라이싱 제한을 제거하여 대상 건 전량 추천 반환

### 3. 테스트 코드 검증
- `tests/dashboard/test_analyst_review.py`: `search_analyses(reviewed_only=True)` 테스트 추가
- `tests/backend_api/test_app.py`: `GET /analyses?reviewed_only=true` 파라미터 테스트 추가
- `tests/backend_api/test_analyst_priority.py`: 예산 비제한 및 AUTO 차감 분리 검증
- `tests/backend_api/test_emergency_queue.py`: Speakeasy 분류 이유 텍스트 간소화 반영
- **전체 826개 테스트 통과 완료 (0 failed)**

---

## 데이터베이스 영향도
- **DB 스키마 변경: 0건 (None)**
- `api_analyses.analyst_final_verdict` 및 `review_revision` 기존 컬럼을 그대로 조회하므로 테이블 변경이나 추가 마이그레이션이 발생하지 않습니다.
