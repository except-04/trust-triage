-- Full deep-analysis lifecycle; speakeasy_jobs continues to own its tool stage only.
CREATE TABLE IF NOT EXISTS deep_analysis_runs (
    analysis_id varchar(128) PRIMARY KEY,
    sha256 char(64) NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    file_location text NOT NULL,
    initial_route varchar(128) NOT NULL CHECK (initial_route ~ '^[A-Z][A-Z0-9_]{0,127}$'),
    initial_verdict text NOT NULL CHECK (initial_verdict IN ('BENIGN', 'MALICIOUS', 'UNKNOWN')),
    requested_at timestamptz NOT NULL,
    config_fingerprint varchar(256) NOT NULL CHECK (length(config_fingerprint) > 0),
    phase text NOT NULL DEFAULT 'STATIC'
        CHECK (phase IN ('STATIC', 'WAITING_SPEAKEASY', 'FINALIZING',
                         'COMPLETED', 'FAILED', 'NOT_REQUIRED')),
    checkpoint jsonb,
    result jsonb,
    last_error jsonb CHECK (last_error IS NULL OR jsonb_typeof(last_error) = 'object'),
    cancellation jsonb CHECK (cancellation IS NULL OR jsonb_typeof(cancellation) = 'object'),
    next_retry_at timestamptz,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    lease_token uuid,
    lease_until timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((lease_token IS NULL) = (lease_until IS NULL)),
    CHECK (phase NOT IN ('COMPLETED', 'FAILED', 'NOT_REQUIRED') OR lease_token IS NULL),
    CHECK (phase NOT IN ('COMPLETED', 'FAILED', 'NOT_REQUIRED') OR next_retry_at IS NULL),
    CHECK ((phase IN ('COMPLETED', 'FAILED', 'NOT_REQUIRED')) = (result IS NOT NULL)),
    CHECK ((phase IN ('COMPLETED', 'FAILED', 'NOT_REQUIRED')) = (completed_at IS NOT NULL)),
    CHECK (phase <> 'STATIC' OR checkpoint IS NULL),
    CHECK (phase NOT IN ('WAITING_SPEAKEASY', 'FINALIZING') OR checkpoint IS NOT NULL),
    CHECK (checkpoint IS NULL OR (
        jsonb_typeof(checkpoint) = 'object'
        AND checkpoint->>'schema_version' = 'deep-checkpoint-v1'
        AND jsonb_typeof(checkpoint->'static') = 'object'
        AND checkpoint->'static'->>'sha256' = sha256
        AND checkpoint->'static'->>'initial_route' = initial_route
        AND checkpoint->'static'->>'initial_verdict' = initial_verdict
        AND checkpoint->'static'->>'config_fingerprint' = config_fingerprint
    ) IS TRUE),
    CHECK (checkpoint IS NULL OR (
        checkpoint ? 'worker_result'
        AND (
            checkpoint->'worker_result' = 'null'::jsonb
            OR (
                jsonb_typeof(checkpoint->'worker_result') = 'object'
                AND checkpoint->'worker_result'->>'schema_version' = 'speakeasy-result-v1'
                AND checkpoint->'worker_result'->>'analysis_id' = analysis_id
                AND checkpoint->'worker_result'->>'sha256' = sha256
                AND checkpoint->'worker_result'->>'tool' = 'SPEAKEASY'
            )
        )
    ) IS TRUE),
    CHECK (phase <> 'WAITING_SPEAKEASY' OR
           (checkpoint->'worker_result' = 'null'::jsonb) IS TRUE),
    CHECK (result IS NULL OR (
        jsonb_typeof(result) = 'object'
        AND result->>'sha256' = sha256
        AND result->>'initial_route' = initial_route
        AND result->>'initial_verdict' = initial_verdict
        AND result->>'deep_analysis_status' =
            CASE phase WHEN 'COMPLETED' THEN 'COMPLETE' ELSE phase END
    ) IS TRUE)
);

-- Existing installations receive the durable parent-cancellation field in place.
ALTER TABLE deep_analysis_runs ADD COLUMN IF NOT EXISTS cancellation jsonb;

CREATE INDEX IF NOT EXISTS deep_analysis_runs_pending_idx
    ON deep_analysis_runs (updated_at, analysis_id)
    WHERE phase IN ('STATIC', 'WAITING_SPEAKEASY', 'FINALIZING');
