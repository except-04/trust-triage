-- Worker 단계 전용 테이블. 전체 Analysis/전문가 검토 상태는 이 테이블이 관리하지 않는다.
CREATE TABLE IF NOT EXISTS speakeasy_jobs (
    analysis_id varchar(128) PRIMARY KEY,
    sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    file_location text NOT NULL,
    requested_at timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'QUEUED'
        CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    dispatch_pending boolean NOT NULL DEFAULT false,
    dispatched_at timestamptz,
    lease_token uuid,
    lease_until timestamptz,
    result jsonb,
    last_error jsonb,
    started_at timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (status = 'RUNNING' AND lease_token IS NOT NULL AND lease_until IS NOT NULL)
        OR (status <> 'RUNNING' AND lease_token IS NULL AND lease_until IS NULL)
    ),
    CHECK ((status IN ('COMPLETED', 'FAILED')) = (result IS NOT NULL)),
    CHECK (result IS NULL OR (result->>'status' = status) IS TRUE),
    CHECK (result IS NULL OR (
        result->>'analysis_id' = analysis_id
        AND result->>'sha256' = sha256
        AND result->>'tool' = 'SPEAKEASY'
    ) IS TRUE)
);

CREATE INDEX IF NOT EXISTS speakeasy_jobs_pending_idx
    ON speakeasy_jobs (created_at) WHERE dispatch_pending AND status = 'QUEUED';
