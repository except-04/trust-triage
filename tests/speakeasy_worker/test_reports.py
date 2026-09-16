from __future__ import annotations

import json
from dataclasses import replace

import pytest
from botocore.stub import ANY, Stubber

from trust_triage.speakeasy_worker.reports import ReportWriter
from trust_triage.speakeasy_worker.worker import Outcome
from trust_triage.storage import (
    ArtifactError,
    ArtifactReference,
    LocalArtifactStorage,
    S3ArtifactStorage,
)

from .test_aws import aws_client


def test_normalized_report_reference_is_saved_before_ack(
    rig, job, delivery, tmp_path, monkeypatch
):
    store = LocalArtifactStorage(tmp_path / "reports")
    rig.worker.reports = ReportWriter(store, config_sha256="a" * 64)
    acknowledge = rig.queue.acknowledge

    def verify_before_ack(message):
        result = rig.repository.get(job.analysis_id).result
        reference = ArtifactReference(**result["artifact"])
        saved = json.loads(store.read(reference))
        assert saved["report_kind"] == "normalized_worker_result"
        assert saved["result"]["analysis"]["sha256"] == job.sha256
        assert saved["result"]["behavior"] == result["behavior"]
        assert (
            reference.identity.key
            == f"{job.sha256}/analyses/{job.analysis_id}/speakeasy/{result['tool_run_id']}/report.json"
        )
        assert reference.config_sha256 == "a" * 64
        assert reference.tool_version == "test"
        assert result["artifact_error"] is None
        acknowledge(message)

    monkeypatch.setattr(rig.queue, "acknowledge", verify_before_ack)
    assert rig.worker.process(delivery) == Outcome.COMPLETED
    assert rig.worker.process(delivery) == Outcome.DUPLICATE
    assert len(list((tmp_path / "reports").rglob("report.json"))) == 1
    assert rig.analyzer.calls == 1


def test_same_sample_new_analysis_has_separate_report(rig, job, delivery, tmp_path):
    rig.worker.reports = ReportWriter(LocalArtifactStorage(tmp_path / "reports"))
    assert rig.worker.process(delivery) == Outcome.COMPLETED
    second = replace(job, analysis_id="analysis-002")
    assert (
        rig.worker.process(replace(delivery, body=second.to_json()))
        == Outcome.COMPLETED
    )
    first_ref = rig.repository.get(job.analysis_id).result["artifact"]
    second_ref = rig.repository.get(second.analysis_id).result["artifact"]
    assert first_ref["sha256"] == second_ref["sha256"]
    assert first_ref["file_location"] != second_ref["file_location"]


def test_report_retry_does_not_repeat_analysis(rig, delivery, tmp_path, monkeypatch):
    store = LocalArtifactStorage(tmp_path / "reports")
    put_json = store.put_json
    attempts = []

    def intermittent(identity, value, **metadata):
        attempts.append(identity)
        if len(attempts) < 3:
            raise ArtifactError(
                "ARTIFACT_STORAGE_ERROR", "temporary outage", retryable=True
            )
        return put_json(identity, value, **metadata)

    monkeypatch.setattr(store, "put_json", intermittent)
    rig.worker.reports = ReportWriter(store)
    assert rig.worker.process(delivery) == Outcome.COMPLETED
    assert rig.analyzer.calls == 1
    assert len(attempts) == 3
    assert len(set(attempts)) == 1


@pytest.mark.parametrize("retryable,attempts", [(False, 1), (True, 3)])
def test_report_outage_is_explicit_and_observations_stay_in_db(
    rig, job, delivery, retryable, attempts
):
    class Unavailable:
        calls = 0

        def put_json(self, *args, **kwargs):
            self.calls += 1
            raise ArtifactError(
                "ARTIFACT_STORAGE_ERROR", "Cannot archive report", retryable=retryable
            )

    storage = Unavailable()
    rig.worker.reports = ReportWriter(storage)
    assert rig.worker.process(delivery) == Outcome.COMPLETED
    result = rig.repository.get(job.analysis_id).result
    assert result["artifact"] is None
    assert result["artifact_error"]["code"] == "ARTIFACT_STORAGE_ERROR"
    assert result["analysis"]["observed_apis"] == ["CreateFileW"]
    assert storage.calls == attempts
    assert rig.analyzer.calls == 1
    assert rig.queue.acknowledged


def test_report_is_published_using_shared_s3_key_and_conditional_write(
    rig, job, delivery, tmp_path
):
    client = aws_client("s3")
    rig.worker.reports = ReportWriter(
        S3ArtifactStorage(
            client, bucket="worker-test-bucket", prefix="raw/", temp_root=tmp_path
        )
    )
    with Stubber(client) as stub:
        stub.add_response(
            "put_object",
            {},
            {
                "Bucket": "worker-test-bucket",
                "Key": ANY,
                "Body": ANY,
                "ContentLength": ANY,
                "ContentType": "application/json",
                "IfNoneMatch": "*",
                "Metadata": {"sha256": job.sha256, "content-sha256": ANY},
            },
        )
        assert rig.worker.process(delivery) == Outcome.COMPLETED
        stub.assert_no_pending_responses()
    result = rig.repository.get(job.analysis_id).result
    reference = ArtifactReference(**result["artifact"])
    assert (
        reference.file_location
        == f"s3://worker-test-bucket/raw/{reference.identity.key}"
    )
