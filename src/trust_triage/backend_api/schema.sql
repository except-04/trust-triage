-- The API owns these tables. Deep-analysis and Worker schemas remain independent.
CREATE TABLE IF NOT EXISTS api_batches (
    request_id uuid PRIMARY KEY,
    batch_id text UNIQUE,
    request_kind text NOT NULL CHECK (request_kind IN ('SINGLE', 'BATCH')),
    idempotency_key text UNIQUE,
    input_fingerprint text NOT NULL CHECK (input_fingerprint ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((request_kind = 'SINGLE' AND batch_id IS NULL)
        OR (request_kind = 'BATCH' AND batch_id IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS api_analyses (
    analysis_id text PRIMARY KEY,
    request_id uuid NOT NULL REFERENCES api_batches(request_id),
    batch_id text REFERENCES api_batches(batch_id),
    batch_position integer NOT NULL CHECK (batch_position >= 0),
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    file_location text NOT NULL UNIQUE CHECK (length(file_location) BETWEEN 1 AND 4096),
    filename text NOT NULL CHECK (length(filename) BETWEEN 1 AND 512),
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    status text NOT NULL DEFAULT 'QUEUED'
        CHECK (status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED')),
    current_stage text NOT NULL DEFAULT 'UPLOAD' CHECK (current_stage IN (
        'UPLOAD', 'INITIAL_ANALYSIS', 'JRR', 'CAPA_FLOSS', 'SPEAKEASY', 'LLM', 'FINAL_ASSESSMENT'
    )),
    phase text NOT NULL DEFAULT 'INITIAL'
        CHECK (phase IN ('INITIAL', 'WAITING_DEEP', 'FINALIZING', 'DONE')),
    initial_result jsonb,
    deep_result jsonb,
    final_assessment jsonb,
    error jsonb,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    lease_token uuid,
    lease_until timestamptz,
    next_retry_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    duplicate_of text REFERENCES api_analyses(analysis_id),
    review_revision integer NOT NULL DEFAULT 0 CHECK (review_revision >= 0),
    analyst_final_verdict text CHECK (analyst_final_verdict IN ('BENIGN', 'MALICIOUS')),
    storage_deleted_at timestamptz,
    UNIQUE (request_id, batch_position),
    CHECK (duplicate_of IS DISTINCT FROM analysis_id),
    CHECK ((lease_token IS NULL) = (lease_until IS NULL)),
    CHECK ((phase = 'DONE') = (status IN ('COMPLETED', 'FAILED'))),
    CHECK (phase NOT IN ('WAITING_DEEP', 'FINALIZING') OR initial_result IS NOT NULL),
    CHECK ((status IN ('COMPLETED', 'FAILED')) = (final_assessment IS NOT NULL)),
    CHECK ((status IN ('COMPLETED', 'FAILED')) = (completed_at IS NOT NULL)),
    CHECK (status NOT IN ('COMPLETED', 'FAILED')
        OR (lease_token IS NULL AND lease_until IS NULL AND next_retry_at IS NULL)),
    CHECK (status <> 'COMPLETED' OR (error IS NULL AND initial_result IS NOT NULL)),
    CHECK (status <> 'FAILED' OR error IS NOT NULL),
    CHECK (storage_deleted_at IS NULL OR status IN ('COMPLETED', 'FAILED')),
    CHECK (review_revision > 0 OR analyst_final_verdict IS NULL),
    CHECK (initial_result IS NULL OR (
        jsonb_typeof(initial_result) = 'object'
        AND octet_length(initial_result::text) <= 8388608
        AND (NOT (initial_result ? 'analysis_id')
            OR (initial_result ->> 'analysis_id') IS NOT DISTINCT FROM analysis_id)
        AND (NOT (initial_result ? 'sha256')
            OR (initial_result ->> 'sha256') IS NOT DISTINCT FROM sha256)
    )),
    CHECK (deep_result IS NULL OR (
        jsonb_typeof(deep_result) = 'object'
        AND octet_length(deep_result::text) <= 8388608
        AND (NOT (deep_result ? 'analysis_id')
            OR (deep_result ->> 'analysis_id') IS NOT DISTINCT FROM analysis_id)
        AND (NOT (deep_result ? 'sha256')
            OR (deep_result ->> 'sha256') IS NOT DISTINCT FROM sha256)
    )),
    CHECK (final_assessment IS NULL OR (
        jsonb_typeof(final_assessment) = 'object'
        AND octet_length(final_assessment::text) <= 8388608
        AND (NOT (final_assessment ? 'analysis_id')
            OR (final_assessment ->> 'analysis_id') IS NOT DISTINCT FROM analysis_id)
        AND (NOT (final_assessment ? 'sha256')
            OR (final_assessment ->> 'sha256') IS NOT DISTINCT FROM sha256)
    )),
    CHECK (error IS NULL OR (jsonb_typeof(error) = 'object' AND octet_length(error::text) <= 8388608))
);

CREATE INDEX IF NOT EXISTS api_analyses_sha256_idx
    ON api_analyses (sha256, created_at, analysis_id);
CREATE INDEX IF NOT EXISTS api_analyses_listing_idx
    ON api_analyses (created_at DESC, analysis_id DESC);
CREATE INDEX IF NOT EXISTS api_analyses_pending_idx
    ON api_analyses (updated_at, analysis_id)
    WHERE status IN ('QUEUED', 'RUNNING');
CREATE INDEX IF NOT EXISTS api_analyses_cleanup_idx
    ON api_analyses (completed_at, analysis_id)
    WHERE status IN ('COMPLETED', 'FAILED') AND storage_deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS api_reviews (
    review_id uuid PRIMARY KEY,
    analysis_id text NOT NULL REFERENCES api_analyses(analysis_id),
    revision integer NOT NULL CHECK (revision > 0),
    analyst_final_verdict text CHECK (analyst_final_verdict IN ('BENIGN', 'MALICIOUS')),
    analyst_notes text NOT NULL CHECK (length(analyst_notes) <= 10000),
    reviewer_id text NOT NULL CHECK (length(reviewer_id) BETWEEN 1 AND 128),
    review_status text NOT NULL CHECK (review_status IN ('PENDING', 'COMPLETED')),
    reviewed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (analysis_id, revision),
    CHECK ((review_status = 'PENDING') = (analyst_final_verdict IS NULL))
);
