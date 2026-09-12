"""Artifact contracts and corruption checks with local files and an in-memory S3."""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import replace

import pytest

from trust_triage.storage import (
    ArtifactError,
    ArtifactIdentity,
    ArtifactReference,
    LocalArtifactStorage,
    S3ArtifactStorage,
)

from .test_storage import FakeS3, aws_error


@pytest.fixture(params=["local", "s3"])
def artifacts(request, tmp_path):
    if request.param == "local":
        return LocalArtifactStorage(tmp_path / "samples", max_bytes=1024)
    return S3ArtifactStorage(
        FakeS3(),
        bucket="backend-test-only",
        prefix="raw/",
        temp_root=tmp_path / "tmp",
        max_bytes=1024,
    )


@pytest.fixture
def identity():
    return ArtifactIdentity("a" * 64, "analysis-1", "CAPA", "run-1")


def test_artifacts_are_grouped_by_sample_request_tool_and_execution(
    artifacts, identity
):
    report = {"capabilities": ["synthetic only"], "status": "SUCCESS"}
    first = artifacts.put_json(
        identity, report, tool_version="test-v1", config_sha256="b" * 64
    )
    assert (
        first.identity.key == f"{'a' * 64}/analyses/analysis-1/capa/run-1/report.json"
    )
    assert first.sha256 == identity.sha256 and first.tool == "CAPA"
    assert first.tool_version == "test-v1" and first.config_sha256 == "b" * 64
    encoded = artifacts.read(first)
    assert json.loads(encoded) == report
    assert first.content_sha256 == hashlib.sha256(encoded).hexdigest()
    assert first.size_bytes == len(encoded)
    assert ArtifactReference(**first.to_dict()) == first
    second = artifacts.put_json(
        replace(identity, tool_run_id="run-2"), {"status": "TIMEOUT"}
    )
    third = artifacts.put_json(
        replace(identity, analysis_id="analysis-2"), {"status": "SUCCESS"}
    )
    assert len({ref.file_location for ref in (first, second, third)}) == 3
    assert json.loads(artifacts.read(first)) == report
    assert json.loads(artifacts.read(second))["status"] == "TIMEOUT"
    assert third.sha256 == first.sha256


def test_retries_can_verify_identical_bytes_but_cannot_overwrite_a_report(
    artifacts, identity
):
    first = artifacts.put_json(identity, {"value": 1})
    same = artifacts.put_json(identity, {"value": 1})
    assert (
        same.file_location == first.file_location
        and same.content_sha256 == first.content_sha256
    )
    with pytest.raises(ArtifactError) as error:
        artifacts.put_json(identity, {"value": 2})
    assert error.value.code == "ARTIFACT_INTEGRITY_ERROR"
    assert json.loads(artifacts.read(first)) == {"value": 1}
    if isinstance(artifacts, S3ArtifactStorage):
        assert all(
            call[1]["IfNoneMatch"] == "*"
            for call in artifacts.client.calls
            if call[0] == "put"
        )
        assert artifacts.client.body.closed


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {1, 2}])
def test_invalid_json_is_not_published(artifacts, identity, value):
    with pytest.raises(ArtifactError) as error:
        artifacts.put_json(identity, {"value": value})
    assert error.value.code == "INVALID_ARTIFACT"
    if isinstance(artifacts, S3ArtifactStorage):
        assert not artifacts.client.objects
    else:
        assert not artifacts.root.exists()


def test_report_size_limit_applies_to_json_and_streams(artifacts, identity):
    for call in (
        lambda: artifacts.put_json(identity, {"large": "x" * 1024}),
        lambda: artifacts.put_stream(identity, io.BytesIO(b"x" * 1025)),
    ):
        with pytest.raises(ArtifactError) as error:
            call()
        assert error.value.code == "ARTIFACT_TOO_LARGE"
    if isinstance(artifacts, S3ArtifactStorage):
        assert not artifacts.client.objects and not list(artifacts.temp_root.iterdir())
    else:
        assert not list(artifacts.root.rglob("report.json"))
        assert not list(artifacts.root.glob(".artifact-*"))


def test_artifact_reads_detect_tampering(artifacts, identity):
    reference = artifacts.put_json(identity, {"value": 1})
    changed = b'{"value":2}'
    if isinstance(artifacts, S3ArtifactStorage):
        artifacts.client.objects["raw/" + identity.key] = changed
    else:
        (artifacts.root / identity.key).write_bytes(changed)
    with pytest.raises(ArtifactError) as error:
        artifacts.read(reference)
    assert error.value.code == "ARTIFACT_INTEGRITY_ERROR"
    if isinstance(artifacts, S3ArtifactStorage):
        assert artifacts.client.body.closed


def test_reference_cannot_redirect_reads_to_another_store(artifacts, identity):
    reference = artifacts.put_json(identity, {"value": 1})
    forged = replace(reference, file_location=f"s3://another-bucket/raw/{identity.key}")
    with pytest.raises(ArtifactError) as error:
        artifacts.read(forged)
    assert error.value.code == "ARTIFACT_LOCATION_DENIED"


@pytest.mark.parametrize(
    "overrides",
    [
        {"sha256": "../escape"},
        {"analysis_id": "../escape"},
        {"tool": "../CAPA"},
        {"tool_run_id": "a/b"},
        {"tool_run_id": "a\\b"},
        {"name": "../../report.json"},
    ],
)
def test_untrusted_artifact_identity_cannot_form_a_storage_path(identity, overrides):
    with pytest.raises(ValueError):
        replace(identity, **overrides)


def test_reference_binds_location_to_its_sample_and_analysis(artifacts, identity):
    reference = artifacts.put_json(identity, {})
    for overrides in (
        {"sha256": "c" * 64},
        {"analysis_id": "different"},
        {"tool_run_id": "different"},
    ):
        with pytest.raises(ValueError, match="location"):
            replace(reference, **overrides)


def test_empty_tool_log_has_a_valid_checksum(artifacts, identity):
    reference = artifacts.put_stream(
        replace(identity, name="stderr.txt"), io.BytesIO(b""), media_type="text/plain"
    )
    assert (
        reference.size_bytes == 0
        and reference.content_sha256 == hashlib.sha256(b"").hexdigest()
    )
    assert artifacts.read(reference) == b""


def test_s3_artifact_errors_do_not_expose_aws_details(tmp_path, identity):
    client = FakeS3()
    store = S3ArtifactStorage(
        client, bucket="backend-test-only", prefix="raw/", temp_root=tmp_path
    )
    client.failure = aws_error("AccessDenied")
    with pytest.raises(ArtifactError) as error:
        store.put_json(identity, {})
    assert error.value.code == "ARTIFACT_ACCESS_DENIED" and not error.value.retryable
    assert "private detail" not in str(error.value)
    assert not list(tmp_path.iterdir())
