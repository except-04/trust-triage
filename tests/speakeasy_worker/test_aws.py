from __future__ import annotations

import io
import json
from dataclasses import replace

import boto3
import pytest
from botocore.response import StreamingBody
from botocore.stub import Stubber

from trust_triage.speakeasy_worker.errors import PermanentError, RetryableError
from trust_triage.speakeasy_worker.queue import SqsQueue
from trust_triage.speakeasy_worker.storage import S3SampleStore

from .fakes import SAMPLE

QUEUE_URL = "https://sqs.ap-northeast-2.amazonaws.com/123456789012/work"
DLQ_URL = "https://sqs.ap-northeast-2.amazonaws.com/123456789012/dead"
DLQ_ARN = "arn:aws:sqs:ap-northeast-2:123456789012:dead"


def aws_client(service):
    # 실제 AWS 자격 증명을 읽지 않는다. 모든 요청은 Stubber 안에서 처리한다.
    return boto3.client(
        service,
        region_name="ap-northeast-2",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )


def test_sqs_parameters_and_receipt_handle(job):
    client = aws_client("sqs")
    queue = SqsQueue(client, QUEUE_URL)
    with Stubber(client) as stub:
        stub.add_response(
            "send_message",
            {"MessageId": "id-1"},
            {"QueueUrl": QUEUE_URL, "MessageBody": job.to_json()},
        )
        stub.add_response(
            "receive_message",
            {
                "Messages": [
                    {
                        "Body": job.to_json(),
                        "MessageId": "id-1",
                        "ReceiptHandle": "latest-receipt",
                        "Attributes": {"ApproximateReceiveCount": "2"},
                    }
                ]
            },
            {
                "QueueUrl": QUEUE_URL,
                "MaxNumberOfMessages": 1,
                "WaitTimeSeconds": 20,
                "VisibilityTimeout": 180,
                "MessageSystemAttributeNames": ["ApproximateReceiveCount"],
            },
        )
        stub.add_response(
            "change_message_visibility",
            {},
            {
                "QueueUrl": QUEUE_URL,
                "ReceiptHandle": "latest-receipt",
                "VisibilityTimeout": 180,
            },
        )
        stub.add_response(
            "delete_message",
            {},
            {"QueueUrl": QUEUE_URL, "ReceiptHandle": "latest-receipt"},
        )
        assert queue.send(job) == "id-1"
        delivery = queue.receive()
        assert delivery.receive_count == 2
        queue.defer(delivery, 180)
        queue.acknowledge(delivery)
        stub.assert_no_pending_responses()


def test_sqs_access_error_does_not_expose_service_message(job):
    client = aws_client("sqs")
    with Stubber(client) as stub:
        stub.add_client_error(
            "send_message", "AccessDenied", "sensitive-service-details", 403
        )
        with pytest.raises(RetryableError) as caught:
            SqsQueue(client, QUEUE_URL).send(job)
        assert "sensitive-service-details" not in str(caught.value)


@pytest.mark.parametrize(
    "policy,retention,valid",
    [
        ({"deadLetterTargetArn": DLQ_ARN, "maxReceiveCount": 3}, "1209600", True),
        ({}, "1209600", False),
        ({"deadLetterTargetArn": DLQ_ARN, "maxReceiveCount": 8}, "1209600", False),
        ({"deadLetterTargetArn": DLQ_ARN, "maxReceiveCount": 3}, "86400", False),
    ],
)
def test_sqs_dead_letter_configuration_is_checked(policy, retention, valid):
    client = aws_client("sqs")
    attributes = ["QueueArn", "RedrivePolicy", "FifoQueue", "MessageRetentionPeriod"]
    with Stubber(client) as stub:
        stub.add_response(
            "get_queue_attributes",
            {
                "Attributes": {
                    "QueueArn": "arn:aws:sqs:ap-northeast-2:123456789012:work",
                    "RedrivePolicy": json.dumps(policy),
                    "MessageRetentionPeriod": "345600",
                }
            },
            {"QueueUrl": QUEUE_URL, "AttributeNames": attributes},
        )
        stub.add_response(
            "get_queue_attributes",
            {"Attributes": {"QueueArn": DLQ_ARN, "MessageRetentionPeriod": retention}},
            {"QueueUrl": DLQ_URL, "AttributeNames": attributes},
        )
        queue, dlq = SqsQueue(client, QUEUE_URL), SqsQueue(client, DLQ_URL)
        if valid:
            queue.check_dead_letter_queue(dlq)
        else:
            with pytest.raises(ValueError):
                queue.check_dead_letter_queue(dlq)


def test_s3_download_is_verified_and_removed(job, tmp_path):
    client = aws_client("s3")
    body = StreamingBody(io.BytesIO(SAMPLE), len(SAMPLE))
    store = S3SampleStore(client, bucket="worker-test-bucket", temp_root=tmp_path)
    with Stubber(client) as stub:
        stub.add_response(
            "get_object",
            {"Body": body, "ContentLength": len(SAMPLE)},
            {"Bucket": "worker-test-bucket", "Key": f"raw/{job.sha256}/sample.bin"},
        )
        with store.materialize(job, lambda: None) as sample:
            assert sample.read_bytes() == SAMPLE
            assert sample.name == "sample.bin"
            assert tmp_path.resolve() in sample.parents
    assert not sample.exists()
    assert not list(tmp_path.iterdir())
    assert body._raw_stream.closed


@pytest.mark.parametrize(
    "location",
    [
        "s3://other-bucket/raw/sample.bin",
        "s3://worker-test-bucket/private/sample.bin",
        "s3://worker-test-bucket/raw-evil/sample.bin",
        "s3://worker-test-bucket/raw/unrelated-analysis/sample.bin",
        "s3://worker-test-bucket/raw/analysis-001/analyses/report.json",
    ],
)
def test_s3_outside_configured_location_is_rejected_without_request(
    job, tmp_path, location
):
    client = aws_client("s3")
    with Stubber(client):
        store = S3SampleStore(client, bucket="worker-test-bucket", temp_root=tmp_path)
        with (
            pytest.raises(PermanentError) as caught,
            store.materialize(replace(job, file_location=location), lambda: None),
        ):
            pytest.fail("should not materialize")
        assert caught.value.code == "S3_LOCATION_DENIED"


@pytest.mark.parametrize(
    "code,http_status,error_type",
    [
        ("NoSuchKey", 404, PermanentError),
        ("AccessDenied", 403, PermanentError),
        ("SlowDown", 503, RetryableError),
    ],
)
def test_s3_error_classification(job, tmp_path, code, http_status, error_type):
    client = aws_client("s3")
    with Stubber(client) as stub:
        stub.add_client_error("get_object", code, "private message", http_status)
        store = S3SampleStore(client, bucket="worker-test-bucket", temp_root=tmp_path)
        with pytest.raises(error_type) as caught, store.materialize(job, lambda: None):
            pytest.fail("should not materialize")
        assert "private message" not in str(caught.value)
    assert not list(tmp_path.iterdir())


class DownloadClient:
    def __init__(self, data=SAMPLE, declared_size=None):
        self.body = io.BytesIO(data)
        self.declared_size = len(data) if declared_size is None else declared_size

    def get_object(self, **kwargs):
        return {"Body": self.body, "ContentLength": self.declared_size}


@pytest.mark.parametrize(
    "data,declared,max_bytes,code",
    [
        (SAMPLE, len(SAMPLE), 4, "FILE_TOO_LARGE"),
        (SAMPLE, 1, 4, "FILE_TOO_LARGE"),
        (b"changed sample", len(b"changed sample"), 100, "HASH_MISMATCH"),
        (SAMPLE, len(SAMPLE) + 1, 100, "INCOMPLETE_DOWNLOAD"),
    ],
)
def test_stream_limits_and_integrity(job, tmp_path, data, declared, max_bytes, code):
    client = DownloadClient(data, declared)
    store = S3SampleStore(
        client,
        bucket="worker-test-bucket",
        temp_root=tmp_path,
        max_file_bytes=max_bytes,
    )
    with (
        pytest.raises((PermanentError, RetryableError)) as caught,
        store.materialize(job, lambda: None),
    ):
        pytest.fail("should not materialize")
    assert caught.value.code == code
    assert client.body.closed
    assert not list(tmp_path.iterdir())


def test_download_deadline_closes_stream(job, tmp_path, monkeypatch):
    client = DownloadClient()
    store = S3SampleStore(client, bucket="worker-test-bucket", temp_root=tmp_path)
    times = iter([0, 61])
    monkeypatch.setattr(
        "trust_triage.speakeasy_worker.storage.time.monotonic", lambda: next(times)
    )
    with pytest.raises(RetryableError) as caught, store.materialize(job, lambda: None):
        pytest.fail("should not materialize")
    assert caught.value.code == "DOWNLOAD_TIMEOUT"
    assert client.body.closed


def test_caller_failure_is_not_mislabeled_as_s3_error(job, tmp_path):
    store = S3SampleStore(
        DownloadClient(), bucket="worker-test-bucket", temp_root=tmp_path
    )
    with (
        pytest.raises(OSError, match="caller failure"),
        store.materialize(job, lambda: None),
    ):
        raise OSError("caller failure")
    assert not list(tmp_path.iterdir())


def test_previous_backend_path_still_downloads(job, tmp_path):
    legacy = replace(
        job, file_location=f"s3://worker-test-bucket/raw/{job.analysis_id}/sample.bin"
    )
    store = S3SampleStore(
        DownloadClient(), bucket="worker-test-bucket", temp_root=tmp_path
    )
    with store.materialize(legacy, lambda: None) as sample:
        assert sample.read_bytes() == SAMPLE
    assert not sample.exists()


def test_download_timeout_after_final_read_is_not_accepted(job, tmp_path, monkeypatch):
    client = DownloadClient()
    store = S3SampleStore(client, bucket="worker-test-bucket", temp_root=tmp_path)
    times = iter([0, 0, 1, 1, 61])
    monkeypatch.setattr(
        "trust_triage.speakeasy_worker.storage.time.monotonic", lambda: next(times)
    )
    with pytest.raises(RetryableError) as caught, store.materialize(job, lambda: None):
        pytest.fail("a late EOF must not bypass the download deadline")
    assert caught.value.code == "DOWNLOAD_TIMEOUT"
    assert client.body.closed
