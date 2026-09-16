from __future__ import annotations

import json
from dataclasses import replace

import pytest

from trust_triage.speakeasy_worker.config import WorkerConfig
from trust_triage.speakeasy_worker.models import (
    InvalidJob,
    SpeakeasyJob,
    result_from_analysis,
)

from .fakes import SAMPLE, FakeAnalyzer


def test_job_uses_timezone_aware_utc_and_normalized_hash(job):
    data = job.to_dict()
    data["sha256"] = data["sha256"].upper()
    data["requested_at"] = "2026-09-07T19:00:00+09:00"
    restored = SpeakeasyJob.from_json(json.dumps(data))
    assert restored == job
    assert restored.requested_at == "2026-09-07T10:00:00+00:00"


@pytest.mark.parametrize(
    "field,value",
    [
        ("analysis_id", "../../outside"),
        ("analysis_id", "a" * 129),
        ("analysis_id", 1),
        ("sha256", "bad-hash"),
        ("sha256", "g" * 64),
        ("file_location", "C:/samples/file.exe"),
        ("file_location", "https://example.test/sample"),
        ("file_location", "s3://user:password@bucket/raw/sample"),
        ("file_location", "s3://[invalid/raw/sample"),
        ("file_location", "s3://worker-test-bucket/raw/sample?token=secret"),
        ("file_location", "s3://worker-test-bucket/raw/sample#fragment"),
        ("file_location", "s3://worker-test-bucket/raw/../sample.bin"),
        ("file_location", "s3://worker-test-bucket/raw/a b.bin"),
        ("requested_stage", "SHELL_COMMAND"),
        ("requested_at", "2026-09-07T10:00:00"),
        ("requested_at", "not-a-time"),
        ("requested_at", None),
    ],
)
def test_invalid_requests_are_rejected_before_execution(job, field, value):
    data = job.to_dict()
    data[field] = value
    with pytest.raises(InvalidJob):
        SpeakeasyJob.from_json(json.dumps(data))


@pytest.mark.parametrize(
    "body", ["[]", "null", "1", "{}", "{bad", " " * 17000, "\ud800"]
)
def test_non_contract_json_is_rejected(body):
    with pytest.raises(InvalidJob):
        SpeakeasyJob.from_json(body)


def test_unknown_and_duplicate_fields_are_rejected(job):
    data = job.to_dict()
    data["command"] = "do not execute this"
    with pytest.raises(InvalidJob):
        SpeakeasyJob.from_json(json.dumps(data))
    duplicated = job.to_json()[:-1] + ',"analysis_id":"different-id"}'
    with pytest.raises(InvalidJob):
        SpeakeasyJob.from_json(duplicated)


def test_analyzer_result_cannot_link_to_a_different_file(job, tmp_path):
    path = tmp_path / "test.bin"
    path.write_bytes(SAMPLE)
    analysis = replace(FakeAnalyzer().analyze(path), sha256="f" * 64)
    result = result_from_analysis(job, analysis)
    assert result["status"] == "FAILED"
    assert result["error"]["code"] == "RESULT_HASH_MISMATCH"


def test_nonfinite_result_is_not_serialized_as_json(job, tmp_path):
    path = tmp_path / "test.bin"
    path.write_bytes(SAMPLE)
    analysis = replace(FakeAnalyzer().analyze(path), metadata={"invalid": float("nan")})
    with pytest.raises(ValueError):
        result_from_analysis(job, analysis)


def _config_env():
    return {
        "AWS_REGION": "ap-northeast-2",
        "SQS_QUEUE_URL": "https://sqs.ap-northeast-2.amazonaws.com/123456789012/work",
        "SQS_DLQ_URL": "https://sqs.ap-northeast-2.amazonaws.com/123456789012/dead",
        "WORKER_DATABASE_URL": "postgresql://worker:never-print-this@localhost/triage",
        "WORKER_S3_BUCKET": "worker-test-bucket",
    }


def test_config_hides_database_credentials_and_has_finite_limits():
    config = WorkerConfig.from_env(_config_env())
    assert "never-print-this" not in repr(config)
    assert config.limits.job_timeout_seconds < config.limits.visibility_seconds
    assert config.analysis_timeout_seconds == 30


@pytest.mark.parametrize(
    "field,value",
    [
        ("SQS_QUEUE_URL", "http://example.test/queue"),
        ("SQS_DLQ_URL", ""),
        ("WORKER_S3_PREFIX", "raw"),
        ("WORKER_S3_PREFIX", "raw/../"),
        ("WORKER_S3_PREFIX", "raw//"),
        ("WORKER_S3_PREFIX", "raw/?query/"),
        ("WORKER_S3_PREFIX", "raw/with space/"),
        ("WORKER_POLL_SECONDS", "21"),
        ("WORKER_HEARTBEAT_SECONDS", "100"),
        ("WORKER_JOB_TIMEOUT_SECONDS", "180"),
        ("WORKER_ANALYSIS_TIMEOUT_SECONDS", "nan"),
        ("WORKER_ANALYSIS_TIMEOUT_SECONDS", "90"),
        ("WORKER_MAX_FILE_BYTES", "0"),
    ],
)
def test_invalid_config_fails_before_aws_calls(field, value):
    env = _config_env()
    env[field] = value
    with pytest.raises(ValueError):
        WorkerConfig.from_env(env)
