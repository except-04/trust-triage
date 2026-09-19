"""AWS SQS Standard Queue 연결. 메시지 수신만으로 작업을 삭제하지 않는다."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from botocore.exceptions import BotoCoreError, ClientError

from .errors import RetryableError
from .models import SpeakeasyJob


@dataclass(frozen=True)
class Delivery:
    body: str
    message_id: str
    receipt_handle: str
    receive_count: int = 1


class JobQueue(Protocol):
    def send(self, job: SpeakeasyJob) -> str: ...
    def receive(self) -> Delivery | None: ...
    def acknowledge(self, delivery: Delivery) -> None: ...
    def defer(self, delivery: Delivery, seconds: int) -> None: ...


class SqsQueue:
    def __init__(
        self,
        client: Any,
        queue_url: str,
        *,
        wait_seconds: int = 20,
        visibility_seconds: int = 180,
    ) -> None:
        if not queue_url:
            raise ValueError("SQS queue URL is required")
        if not 0 <= wait_seconds <= 20 or not 1 <= visibility_seconds <= 43200:
            raise ValueError("invalid SQS polling or visibility timeout")
        self.client = client
        self.queue_url = queue_url
        self.wait_seconds = wait_seconds
        self.visibility_seconds = visibility_seconds

    def _call(self, operation: str, **kwargs: Any) -> Any:
        try:
            return getattr(self.client, operation)(QueueUrl=self.queue_url, **kwargs)
        except (BotoCoreError, ClientError) as exc:
            raise RetryableError("SQS_ERROR", f"SQS {operation} failed") from exc

    def send(self, job: SpeakeasyJob) -> str:
        response = self._call("send_message", MessageBody=job.to_json())
        return response["MessageId"]

    def receive(self) -> Delivery | None:
        response = self._call(
            "receive_message",
            MaxNumberOfMessages=1,
            WaitTimeSeconds=self.wait_seconds,
            VisibilityTimeout=self.visibility_seconds,
            MessageSystemAttributeNames=["ApproximateReceiveCount"],
        )
        messages = response.get("Messages", [])
        if not messages:
            return None
        message = messages[0]
        return Delivery(
            body=message["Body"],
            message_id=message["MessageId"],
            receipt_handle=message["ReceiptHandle"],
            receive_count=max(
                1,
                int(message.get("Attributes", {}).get("ApproximateReceiveCount", "1")),
            ),
        )

    def acknowledge(self, delivery: Delivery) -> None:
        self._call("delete_message", ReceiptHandle=delivery.receipt_handle)

    def defer(self, delivery: Delivery, seconds: int) -> None:
        if not 0 <= seconds <= 43200:
            raise ValueError("visibility timeout must be between 0 and 43200 seconds")
        self._call(
            "change_message_visibility",
            ReceiptHandle=delivery.receipt_handle,
            VisibilityTimeout=seconds,
        )

    def attributes(self) -> dict[str, str]:
        return self._call(
            "get_queue_attributes",
            AttributeNames=[
                "QueueArn",
                "RedrivePolicy",
                "MessageRetentionPeriod",
            ],
        )["Attributes"]

    def check_dead_letter_queue(
        self, dlq: SqsQueue, *, max_receive_count: int = 3
    ) -> None:
        """AWS 설정 누락 때문에 무한 재시도하는 배포를 시작 전에 막는다."""

        if self.queue_url == dlq.queue_url:
            raise ValueError("SQS_QUEUE_URL and SQS_DLQ_URL must be different")
        source, target = self.attributes(), dlq.attributes()
        try:
            source_arn, target_arn = source["QueueArn"], target["QueueArn"]
        except KeyError as exc:
            raise ValueError("SQS queue attributes must include QueueArn") from exc
        # FifoQueue는 FIFO 전용 속성이다. 큐 이름의 필수 접미사를 ARN에서 확인한다.
        if source_arn.endswith(".fifo") or target_arn.endswith(".fifo"):
            raise ValueError("Worker requires Standard queues, not FIFO queues")
        try:
            policy = json.loads(source.get("RedrivePolicy", "{}"))
            matched = (
                policy["deadLetterTargetArn"] == target_arn
                and int(policy["maxReceiveCount"]) == max_receive_count
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(
                "Configure the source SQS queue's DLQ redrive policy"
            ) from exc
        if not matched:
            raise ValueError(
                "SQS redrive policy must match SQS_DLQ_URL and WORKER_MAX_RECEIVES"
            )
        if int(target.get("MessageRetentionPeriod", 0)) <= int(
            source.get("MessageRetentionPeriod", 0)
        ):
            raise ValueError(
                "DLQ retention must be longer than the source queue retention"
            )
