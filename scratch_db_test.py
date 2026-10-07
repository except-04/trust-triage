import os
import sys
import uuid
import json
import hashlib
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# 모듈 경로 추가 (가상환경이 비활성화되어 있거나 PYTHONPATH가 없어도 실행되도록 보장)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

test_db_url = os.environ.get("MIGRATION_TEST_DB_URL")
if not test_db_url:
    print("MIGRATION_TEST_DB_URL 환경변수가 설정되어 있지 않습니다.")
    print("실제 운영 DB와의 격리를 위해, 반드시 마이그레이션 테스트용 DB/복사본 주소를 지정해주세요.")
    sys.exit(1)

# 서비스 생성을 위해 BACKEND_DATABASE_URL 덮어쓰기
os.environ["BACKEND_DATABASE_URL"] = test_db_url

from trust_triage.backend_api.config import BackendConfig
from trust_triage.backend_api.runtime import create_service
from trust_triage.backend_api.schemas import ReviewRequest
from psycopg.rows import dict_row

config = BackendConfig.from_env()
svc = create_service(config)

print("=== 철저한 DB 마이그레이션 격리 검증 스크립트 ===")

# 1. 기존 리뷰 데이터 전체 상태 저장 (마이그레이션 전 컬럼만)
print("\n-> 기존 전체 리뷰 데이터 상태 기록 중...")
pre_reviews_state = {}
# 마이그레이션 전에는 review_queue, review_policy가 없을 수 있으므로 공통 컬럼만 조회
with svc.repository._connection() as conn, conn.cursor(row_factory=dict_row) as cur:
    cur.execute("SELECT review_id, analysis_id, reviewer_id, review_status, analyst_notes, analyst_final_verdict, revision, reviewed_at FROM api_reviews")
    for row in cur.fetchall():
        pre_reviews_state[row["review_id"]] = row

pre_review_count = len(pre_reviews_state)
print(f"마이그레이션 전 총 리뷰 개수: {pre_review_count}")

# 2. init-db 2회 실행 (멱등성)
print("\n-> 1차 init-db 실행 중...")
svc.repository.initialize()
print("-> 2차 init-db 실행 중 (멱등성 검증)...")
svc.repository.initialize()

# 3. 보존 검증 (전수 비교)
print("\n-> 기존 리뷰 전수 보존 검증 중...")
post_reviews_state = {}
with svc.repository._connection() as conn, conn.cursor(row_factory=dict_row) as cur:
    # 초기화 후에는 신규 컬럼 포함해 조회 가능
    cur.execute("SELECT review_id, analysis_id, reviewer_id, review_status, review_queue, review_policy, analyst_notes, analyst_final_verdict, revision, reviewed_at FROM api_reviews")
    for row in cur.fetchall():
        post_reviews_state[row["review_id"]] = row

assert len(post_reviews_state) == pre_review_count, "마이그레이션 후 리뷰 개수가 다릅니다!"
for rid, pre_data in pre_reviews_state.items():
    assert rid in post_reviews_state, f"리뷰 {rid}가 삭제되었습니다!"
    post_data = post_reviews_state[rid]
    for k, v in pre_data.items():
        assert post_data[k] == v, f"리뷰 {rid}의 {k} 필드가 변경되었습니다! (전: {v}, 후: {post_data[k]})"

print("[SUCCESS] 기존 모든 리뷰 데이터 무결성 검증 완료")

# 4. Budget 전체 검증 및 복원
print("\n-> Budget 상세 로직 및 복원 검증 중...")
orig_budget = svc.get_budget_config()
orig_dict = orig_budget if isinstance(orig_budget, dict) else orig_budget.model_dump()

test_budget = {
    "daily_budget": 9999,
    "emergency_budget": 100,
    "deep_budget": 100,
    "fp_budget": 100,
    "is_unlimited": False
}

try:
    svc.set_budget(test_budget)
    updated_budget = svc.get_budget_config()
    updated_dict = updated_budget if isinstance(updated_budget, dict) else updated_budget.model_dump()
    
    for k, v in test_budget.items():
        assert updated_dict[k] == v, f"Budget {k} 설정 실패 (예상: {v}, 실제: {updated_dict[k]})"
    print("[SUCCESS] 예산 설정 및 상세 필드 검증 완료")
finally:
    restore_budget = {
        "daily_budget": orig_dict["daily_budget"],
        "emergency_budget": orig_dict["emergency_budget"],
        "deep_budget": orig_dict["deep_budget"],
        "fp_budget": orig_dict["fp_budget"],
        "is_unlimited": orig_dict["is_unlimited"]
    }
    svc.set_budget(restore_budget)
    restored_dict = svc.get_budget_config()
    restored_dict = restored_dict if isinstance(restored_dict, dict) else restored_dict.model_dump()
    for k, v in restore_budget.items():
        assert restored_dict[k] == v, f"Budget {k} 복원 실패"
    print("[SUCCESS] 예산 원상 복구 및 검증 완료")


# 5. 더미 데이터 생성 및 추천/저장 큐 정밀 검증
print("\n-> 더미 분석건 생성 및 추천/저장 큐 검증 중...")
dummy_uuid = uuid.uuid4().hex
dummy_id = f"test_analysis_{dummy_uuid[:8]}"
dummy_sha256 = hashlib.sha256(dummy_uuid.encode()).hexdigest()
dummy_loc = f"dummy_loc_{dummy_uuid[:8]}"

try:
    # A. 유효한 판정 결과 생성 (HIGH_RISK_UNCERTAIN)
    # 현재 정책상 ood_score가 0 미만이어야 OOD 신호와 모순되지 않음
    initial_res = {
        "prediction": {"lgbm_raw_probability": 0.6, "xgb_raw_probability": 0.6, "calibrated_probability": 0.6},
        "risk_signals": {"disagreement": 0.0, "ood_score": -0.9, "difficulty_score": 0.0},
        "triggered_signals": ["OOD"],
        "initial_verdict": "HIGH_RISK_UNCERTAIN"
    }
    
    svc.repository.register([
        {"analysis_id": dummy_id, "sha256": dummy_sha256, "file_location": dummy_loc, "filename": "dummy.exe", "size_bytes": 1024}
    ])
    
    with svc.repository._connection() as conn:
        conn.execute("""
            UPDATE api_analyses 
            SET status = 'QUEUED',
                phase = 'WAITING_DEEP',
                initial_result = %s::jsonb
            WHERE analysis_id = %s
        """, (json.dumps(initial_res), dummy_id))
        
    # Pydantic 응답 모델 검증을 위해 임포트
    from trust_triage.backend_api.schemas import PriorityRecommendationResponse

    # B. 예산에 따른 추천/대기 개수 검증 (DEEP 큐 예산 0)
    svc.set_budget({"daily_budget": 999999, "emergency_budget": 99999, "deep_budget": 0, "fp_budget": 99999, "is_unlimited": False})
    recs = svc.get_priority_recommendations()
    PriorityRecommendationResponse.model_validate(recs) # 응답 모델 검증
    recs_dict = recs if isinstance(recs, dict) else recs.model_dump()
    assert dummy_id in [r["analysis_id"] for r in recs_dict["deep_waiting"]], "DEEP 예산이 0일 때 waiting에 포함되지 않았습니다."
    assert dummy_id not in [r["analysis_id"] for r in recs_dict["deep_recommendations"]], "DEEP 예산이 0인데 recommendations에 포함되었습니다."

    # 예산 할당 후 추천 큐 편입 검증 (기존 대기열보다 확실히 많게 부여)
    svc.set_budget({"daily_budget": 999999, "emergency_budget": 99999, "deep_budget": 99999, "fp_budget": 99999, "is_unlimited": False})
    recs = svc.get_priority_recommendations()
    PriorityRecommendationResponse.model_validate(recs) # 응답 모델 검증
    recs_dict = recs if isinstance(recs, dict) else recs.model_dump()
    assert dummy_id in [r["analysis_id"] for r in recs_dict["deep_recommendations"]], "DEEP 예산이 넉넉할 때 recommendations에 포함되지 않았습니다."
    assert dummy_id not in [r["analysis_id"] for r in recs_dict["deep_waiting"]], "DEEP 예산이 넉넉한데 waiting에 포함되었습니다."

    pre_budget_state = svc.get_budget_config()
    pre_budget_dict = pre_budget_state if isinstance(pre_budget_state, dict) else pre_budget_state.model_dump()
    pre_completed = pre_budget_dict["today_completed_count"]

    # C-1. PENDING (보류) 상태 저장
    with svc.repository._connection() as conn:
        conn.execute("""
            UPDATE api_analyses 
            SET status = 'COMPLETED',
                phase = 'DONE',
                completed_at = clock_timestamp(),
                final_assessment = '{}'::jsonb
            WHERE analysis_id = %s
        """, (dummy_id,))

    req_pending = ReviewRequest(
        analyst_final_verdict=None, 
        analyst_notes="Need more time (PENDING)", 
        reviewer_id="test_user", 
        expected_revision=0
    )
    svc.review(dummy_id, req_pending)

    # 검증 1: 보류 저장으로 추천/대기 대상에 남고 상태가 '검토 중'인지
    recs_after_pending = svc.get_priority_recommendations()
    PriorityRecommendationResponse.model_validate(recs_after_pending)
    recs_after_pending_dict = recs_after_pending if isinstance(recs_after_pending, dict) else recs_after_pending.model_dump()
    
    pending_item = next((r for r in recs_after_pending_dict["deep_recommendations"] if r["analysis_id"] == dummy_id), None)
    assert pending_item is not None, "보류 상태일 때 추천 목록에서 제외되었습니다!"
    assert pending_item["review_status"] == "검토 중", (
        f"후보 응답 상태 불일치: 예상='검토 중', 실제={pending_item['review_status']!r}"
    )

    # 검증 2: 보류 저장은 오늘 완료량에 영향을 주지 않음
    pending_budget_state = svc.get_budget_config()
    pending_budget_dict = pending_budget_state if isinstance(pending_budget_state, dict) else pending_budget_state.model_dump()
    assert pending_budget_dict["today_completed_count"] == pre_completed, "보류 리뷰 저장 시 완료량이 비정상적으로 증가했습니다!"

    # 검증 3: 예산 부족 시 보류 건도 대기 목록으로 밀려남
    svc.set_budget({"daily_budget": 999999, "emergency_budget": 99999, "deep_budget": 0, "fp_budget": 99999, "is_unlimited": False})
    recs_no_budget = svc.get_priority_recommendations()
    recs_no_budget_dict = recs_no_budget if isinstance(recs_no_budget, dict) else recs_no_budget.model_dump()
    assert dummy_id in [r["analysis_id"] for r in recs_no_budget_dict["deep_waiting"]], "예산 부족 시 보류 건이 waiting 큐에 나타나지 않았습니다."
    
    # 예산 넉넉히 원복
    svc.set_budget({"daily_budget": 999999, "emergency_budget": 99999, "deep_budget": 99999, "fp_budget": 99999, "is_unlimited": False})

    # 검증 6-1: revision 충돌 검사
    from trust_triage.backend_api.errors import BackendError
    try:
        req_conflict = ReviewRequest(analyst_final_verdict="MALICIOUS", analyst_notes="conflict", reviewer_id="test_user", expected_revision=0)
        svc.review(dummy_id, req_conflict)
        assert False, "잘못된 expected_revision에도 리뷰가 덮어씌워졌습니다 (충돌 무시)."
    except BackendError as e:
        assert "newer" in e.message or "already exists" in e.message or e.code == "STALE_REVISION", f"충돌 검사 오류 메시지가 예상과 다릅니다. (실제: {e.code} / {e.message})"

    # C-2. 최종 완료(COMPLETED) 저장 (revision 1)
    req = ReviewRequest(
        analyst_final_verdict="MALICIOUS", 
        analyst_notes="Test migration deep queue", 
        reviewer_id="test_user", 
        expected_revision=1
    )
    svc.review(dummy_id, req)
    
    # D. 완료 후 검증
    # 리뷰가 정확히 저장되었는지 확인
    reviews_after = svc.reviews(dummy_id)
    r_items = reviews_after["items"] if isinstance(reviews_after, dict) else reviews_after.items
    assert len(r_items) >= 1, "리뷰 저장 실패"
    completed_review = next((r for r in r_items if r.analyst_final_verdict == "MALICIOUS"), None)
    assert completed_review is not None, "MALICIOUS 판정의 리뷰가 없습니다."
    assert completed_review.analyst_notes == "Test migration deep queue", "리뷰 메모 불일치"
    with svc.repository._connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT review_queue FROM api_reviews WHERE analysis_id = %s AND review_status = 'COMPLETED'", (dummy_id,))
        saved_q = cur.fetchone()["review_queue"]
        assert saved_q == "DEEP", "DB에 저장된 리뷰 큐가 DEEP이 아닙니다."
    
    # 큐 추천 목록에서 제외되었는지 확인
    recs_after = svc.get_priority_recommendations()
    recs_after_dict = recs_after if isinstance(recs_after, dict) else recs_after.model_dump()
    assert dummy_id not in [r["analysis_id"] for r in recs_after_dict["deep_recommendations"]], "리뷰 완료 후에도 큐 추천에 남아있습니다."
    assert dummy_id not in [r["analysis_id"] for r in recs_after_dict["deep_waiting"]], "리뷰 완료 후에도 큐 대기에 남아있습니다."
    
    # 오늘 완료량(today_completed_count) 증가 확인
    post_budget_state = svc.get_budget_config()
    post_budget_dict = post_budget_state if isinstance(post_budget_state, dict) else post_budget_state.model_dump()
    post_completed = post_budget_dict["today_completed_count"]
    assert post_completed == pre_completed + 1, f"리뷰 저장 후 완료량이 증가하지 않았습니다. (이전: {pre_completed}, 이후: {post_completed})"
    
    print("[SUCCESS] 예산 연동 큐 배정, 리뷰 저장 및 완료 반영 검증 완료")

finally:
    try:
        # 안전하게 예산 원복
        svc.set_budget(restore_budget)
    finally:
        # 더미 데이터 클린업: 정확한 ID만 매칭하여 삭제
        with svc.repository._connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT request_id FROM api_analyses WHERE analysis_id = %s", (dummy_id,))
            req_row = cur.fetchone()
            
            conn.execute("DELETE FROM api_reviews WHERE analysis_id = %s", (dummy_id,))
            conn.execute("DELETE FROM api_analysis_artifacts WHERE analysis_id = %s", (dummy_id,))
            conn.execute("DELETE FROM api_analyses WHERE analysis_id = %s", (dummy_id,))
            conn.execute("DELETE FROM api_sample_objects WHERE sha256 = %s AND file_location = %s", (dummy_sha256, dummy_loc))
            
            if req_row:
                # 방금 만든 배치(request_id)만 정확히 삭제
                conn.execute("DELETE FROM api_batches WHERE request_id = %s", (req_row["request_id"],))
                
        print("[SUCCESS] 정확한 식별자를 이용한 테스트 데이터 완벽 정리 완료")

print("\n[SUCCESS] 지적해주신 모든 문제점을 보완한 검증이 성공적으로 완료되었습니다!")
