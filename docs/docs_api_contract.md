# API 입출력 계약 초안

> `[API] 입출력 계약 초안 작성` 이슈용. 파일/해시 입력, 대시보드/API/Alert 출력 구조 확정.

## 엔드포인트 목록

| 메서드 | 경로 | 용도 |
|---|---|---|
| POST | `/analyze/file` | 파일 업로드 분석 |
| POST | `/analyze/hash` | 해시 조회 분석 |
| GET | `/queue/pending` | 검토 대기 목록 |
| GET | `/queue/completed` | 검토 완료 목록 |
| POST | `/review/{file_id}/verdict` | 분석가 최종 판단 제출 |
| GET | `/queue/stats` | Review Yield 등 통계 |

## 1. `POST /analyze/file`

**요청**: `multipart/form-data`, 필드 `file` (실행 파일)

**응답**:
```json
{
  "file_id": "sample_00417",
  "verdict": "악성",
  "calibrated_probability": 0.58,
  "risk_score": 0.91,
  "route": "분석가_검토",
  "priority_rank": 1,
  "top_features": [
    {"name": "section_entropy_max", "contribution": 0.31, "direction": "악성"},
    {"name": "api_registry_group", "contribution": 0.20, "direction": "악성"}
  ],
  "recommended_action": "심층분석 권고"
}
```

## 2. `POST /analyze/hash`

**요청**:
```json
{ "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85" }
```

**응답**: `/analyze/file`과 동일 스키마. **캐시에 없는 해시면 404**:
```json
{ "error": "not_found", "message": "해당 해시의 특징 데이터가 없습니다." }
```

## 3. `GET /queue/pending`

**응답**:
```json
{
  "count": 42,
  "items": [
    { "file_id": "...", "priority_rank": 1, "risk_score": 0.91, "model_verdict": "악성", "top_features": [...] }
  ]
}
```

## 4. `GET /queue/completed`

**응답**:
```json
{
  "count": 12,
  "items": [
    {
      "file_id": "...",
      "model_verdict": "정상",
      "analyst_final_verdict": "악성 확인",
      "match": false,
      "notes": "...",
      "reviewed_by": "analyst_1",
      "reviewed_at": "2026-08-05T14:00:00"
    }
  ]
}
```
`match`: `true`=모델과 일치, `false`=불일치, `null`=판단 보류라 비교 불가

## 5. `POST /review/{file_id}/verdict`

**요청**:
```json
{
  "analyst_verdict": "악성 확인",
  "notes": "레지스트리 자동실행 등록 확인",
  "reviewer_id": "analyst_1"
}
```

**응답**:
```json
{ "status": "success", "file_id": "sample_00417", "reviewed_at": "2026-08-05T14:00:00" }
```

## 6. `GET /queue/stats`

**응답**:
```json
{ "total_reviewed": 40, "review_yield": 0.62 }
```

## Alert 출력 (Slack Webhook)

API 엔드포인트가 아니라, `risk_score`가 임계값(팀 확정 필요, 잠정 0.9) 초과 시 `/analyze/*` 처리 직후 `BackgroundTasks`로 발송.

```json
{
  "text": "⚠️ 고위험 파일 발견\n파일: sample_00417\n위험도: 0.91\n주요 근거: section_entropy_max, api_registry_group"
}
```

## 확정 필요 (회의 안건)

- [ ] Alert 발동 risk_score 임계값
- [ ] `/analyze/hash` 캐시 미스 시 즉시 특징 추출 시도할지, 404만 반환할지
- [ ] 인증/권한 체계 필요 여부 (PoC 범위에서는 생략 가능성 높음, 명시적으로 결정)
