import subprocess

msg = """feat: 개선된 검토 상태 및 UI 텍스트 업데이트

- PriorityRecommendationItem의 검토 상태(review_status) 표시를 직관적으로 개선 (None -> '검토 필요', '검토 보류' -> '검토 중')
- 대시보드의 '판정 수정' 버튼 및 팝업 타이틀을 문맥에 맞게 '판정 검토'로 변경
- 판정을 번복하지 않고 기존 모델 판정 그대로 저장(승인)할 수 있도록 프론트엔드 검증(validation) 로직 제거
- 500 에러를 방지하기 위해 schemas.py의 review_status를 Optional로 수정
- 변경된 텍스트('검토 중')에 맞춰 통합 테스트 및 검증 스크립트(scratch_db_test.py) 업데이트"""

subprocess.run(["git", "add", "."])
subprocess.run(["git", "commit", "-m", msg])
subprocess.run(["git", "push"])
