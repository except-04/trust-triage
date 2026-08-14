# SQLite 스키마 설계

> `[INFRA] SQLite 스키마 설계` 이슈용. 검토 이력 관리 + 해시 조회 두 가지 용도.

## 왜 필요한가

1. **해시 조회**: 원본 PE 없이도 "이 해시값 특징 있어요?"로 조회 가능하게
2. **검토 큐 상태 관리**: 대시보드 새로고침해도 대기/완료 상태 유지

## 테이블 설계

### 1. `feature_cache` — 해시 조회용

```sql
CREATE TABLE feature_cache (
    sha256 TEXT PRIMARY KEY,
    features_json TEXT NOT NULL,   -- 추출된 특징 (feature_schema.md 스키마 기준 JSON)
    source TEXT NOT NULL,          -- 'user_upload' | 'ember_dataset' | 'association_dataset'
    extracted_at TEXT NOT NULL     -- ISO 8601
);
```

### 2. `analysis_records` — 판정·라우팅·검토 큐 통합

```sql
CREATE TABLE analysis_records (
    file_id TEXT PRIMARY KEY,
    sha256 TEXT REFERENCES feature_cache(sha256),
    model_verdict TEXT NOT NULL,          -- '정상' | '악성'
    calibrated_probability REAL NOT NULL,
    risk_score REAL,
    route TEXT NOT NULL,                  -- '자동_정상' | '자동_악성' | '심층분석' | '분석가_검토'
    priority_rank INTEGER,                -- 검토 큐 내 순위 (해당 시)
    top_features_json TEXT,               -- SHAP 근거 (상위 5개, {name, contribution, direction})
    review_status TEXT DEFAULT 'N/A',     -- 'N/A' | '대기중' | '완료'
    analyst_final_verdict TEXT,
    analyst_notes TEXT,
    reviewed_by TEXT,
    reviewed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_review_status ON analysis_records(review_status);
CREATE INDEX idx_risk_score ON analysis_records(risk_score DESC);
```

### 3. `emulation_results` — 확장안(Speakeasy) 결과 (선택 확장안 구현 시 사용)

```sql
CREATE TABLE emulation_results (
    file_id TEXT PRIMARY KEY REFERENCES analysis_records(file_id),
    malicious_behavior_flags TEXT,   -- JSON 배열, 예: ["process_injection", "registry_persistence"]
    sensitive_file_access_flags TEXT, -- JSON 배열
    raw_api_calls_json TEXT,
    analyzed_at TEXT NOT NULL
);
```

## 사용 예시

```python
import sqlite3, json
from datetime import datetime

conn = sqlite3.connect("trust_edr.db")
conn.execute("PRAGMA foreign_keys = ON")

# 해시 조회
def lookup_by_hash(sha256):
    row = conn.execute(
        "SELECT features_json FROM feature_cache WHERE sha256 = ?", (sha256,)
    ).fetchone()
    return json.loads(row[0]) if row else None

# 검토 큐 대기 목록
def get_pending_queue():
    return conn.execute(
        "SELECT * FROM analysis_records WHERE review_status = '대기중' ORDER BY priority_rank"
    ).fetchall()
```

## 담당

INFRA 라벨 — 서비스 통합 담당(최지원)이 API 개발과 함께 진행 권장 (같은 코드에서 바로 씀).
