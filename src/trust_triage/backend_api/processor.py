"""DB의 대기 작업을 한 단계씩 처리한다. 재시작하면 저장된 다음 단계에서 이어간다."""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from trust_triage.storage.artifacts import ArtifactError, ArtifactIdentity

from .config import BackendConfig
from .deep_gateway import DeepGateway, current_deep_stage, validate_snapshot
from .errors import BackendError
from .repository import AnalysisRecord, AnalysisRepository
from .schemas import FinalAssessment, InitialResult
from .service import stored_sample
from .storage import SampleStorage

LOGGER = logging.getLogger(__name__)


class LeaseLost(RuntimeError):
    """다른 처리자가 이어받았으므로 현재 처리자는 더 이상 결과를 기록하지 않는다."""


class _Lease:
    def __init__(self, repository, analysis_id, token, config):
        self.repository, self.analysis_id, self.token, self.config = (
            repository,
            analysis_id,
            token,
            config,
        )
        self.stop, self.lost = threading.Event(), threading.Event()
        self.deadline = time.monotonic() + config.operation_timeout_seconds
        self.thread = threading.Thread(target=self._heartbeat, daemon=True)

    def _heartbeat(self):
        while not self.stop.wait(self.config.heartbeat_seconds):
            try:
                # Stop renewing an over-budget operation, but keep timeout
                # distinct from fencing loss: check() records PROCESSING_TIMEOUT
                # and consumes the retry budget while the token is still valid.
                if time.monotonic() >= self.deadline:
                    return
                if not self.repository.renew(
                    self.analysis_id, self.token, self.config.lease_seconds
                ):
                    self.lost.set()
                    return
            except Exception:  # noqa: BLE001 - uncertainty means ownership is lost
                self.lost.set()
                return

    def check(self):
        if self.lost.is_set():
            raise LeaseLost("Analysis ownership expired")
        if time.monotonic() >= self.deadline:
            raise BackendError(
                "PROCESSING_TIMEOUT",
                "분석 단계 제한 시간을 초과했습니다.",
                stage="PROCESSOR",
                retryable=True,
            )

    def saved(self, value):
        if not value:
            raise LeaseLost("Analysis checkpoint was not accepted")

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(timeout=1)


def assess(record: AnalysisRecord, *, failure: bool = False) -> dict[str, Any]:
    """최종 자동판정 규칙은 팀 확정 전이므로 심층분석 대상은 전문가에게 보낸다."""
    initial = record.initial_result or {}
    verdict = initial.get("initial_verdict")
    if failure:
        value = FinalAssessment(
            final_verdict="UNCERTAIN",
            disposition="ANALYSIS_FAILED",
            requires_human_review=True,
            reason="분석을 완료하지 못했습니다. 실패를 악성 증거로 사용하지 않고 전문가 검토로 넘깁니다.",
        )
    elif verdict == "AUTO_BENIGN" and initial.get("xai_status") != "FAILED":
        value = FinalAssessment(
            final_verdict="BENIGN",
            disposition="AUTO_ALLOW_RECOMMENDED",
            requires_human_review=False,
            reason="초기 JRR이 자동 정상 처리 경로를 선택했습니다.",
        )
    elif verdict == "AUTO_MALICIOUS":
        value = FinalAssessment(
            final_verdict="MALICIOUS",
            disposition="ALERT_RECOMMENDED",
            requires_human_review=True,
            reason="초기 JRR이 악성 경보를 제안했습니다. 전문가가 증거를 확인해야 합니다.",
        )
    else:
        value = FinalAssessment(
            final_verdict="UNCERTAIN",
            disposition="MANUAL_REVIEW",
            requires_human_review=True,
            reason="누적 증거와 LLM 해석을 전문가에게 제공합니다. 최종 자동 재판정 정책은 팀 합의 후 교체합니다.",
        )
    return value.model_dump(mode="json")


class BackendProcessor:
    def __init__(
        self,
        repository: AnalysisRepository,
        storage: SampleStorage,
        initial,
        deep: DeepGateway,
        config: BackendConfig,
    ):
        self.repository, self.storage, self.initial, self.deep, self.config = (
            repository,
            storage,
            initial,
            deep,
            config,
        )
        self.artifacts = storage.artifact_store(max_bytes=config.max_artifact_bytes)

    def _checkpoint(self, record, token, tool, value, save, *, check=None):
        """Publish complete bytes, then commit reference and state together."""
        try:
            reference = self.artifacts.put_json(
                ArtifactIdentity(record.sha256, record.analysis_id, tool, token),
                value,
            )
        except ArtifactError as exc:
            raise BackendError(
                exc.code, exc.message, stage="STORAGE", retryable=exc.retryable
            ) from exc
        if check is not None:
            check()
        with self.repository.sample_transaction([record.sha256]) as transaction:
            if check is not None:
                check()
            if not transaction.record_artifact(reference, token) or not save(
                transaction
            ):
                raise LeaseLost("Artifact/checkpoint ownership expired")
        return True

    def resume(self, analysis_id: str) -> AnalysisRecord:
        claim = self.repository.claim(analysis_id, self.config.lease_seconds)
        record, token = claim.record, claim.token
        if token is None:
            return record
        with _Lease(self.repository, analysis_id, token, self.config) as lease:
            try:
                if record.phase == "INITIAL":
                    with self.storage.materialize(
                        stored_sample(record), lease.check
                    ) as path:
                        value = self.initial.analyze(
                            path, sha256=record.sha256, check=lease.check
                        )
                    value = InitialResult.model_validate(value).model_dump(mode="json")
                    if (
                        (value["route"] == "DEEP_ANALYSIS")
                        != (value["initial_verdict"] == "HIGH_RISK_UNCERTAIN")
                        or value["triggered_signals"] is None
                        or (
                            value["initial_verdict"] != "HIGH_RISK_UNCERTAIN"
                            and value["triggered_signals"]
                        )
                    ):
                        raise BackendError(
                            "INITIAL_RESULT_INVALID",
                            "초기 JRR 판정·처리 경로 또는 발현 신호가 올바르지 않습니다.",
                            stage="JRR",
                        )
                    lease.check()
                    lease.saved(
                        self._checkpoint(
                            record,
                            token,
                            "INITIAL_ANALYSIS",
                            value,
                            lambda transaction: transaction.save_initial(
                                analysis_id,
                                token,
                                value,
                                value["route"] == "DEEP_ANALYSIS",
                            ),
                            check=lease.check,
                        )
                    )
                elif record.phase == "WAITING_DEEP":
                    created = datetime.fromisoformat(record.created_at)
                    value = None
                    if (
                        datetime.now(timezone.utc) - created
                    ).total_seconds() >= self.config.deep_wait_seconds:
                        existing = self.deep.get(analysis_id)
                        if existing is not None:
                            value = validate_snapshot(existing, record)
                        if value is None or value["status"] not in {
                            "COMPLETED",
                            "FAILED",
                        }:
                            raise BackendError(
                                "DEEP_WAIT_TIMEOUT",
                                "심층 분석 전체 대기 시간을 초과했습니다.",
                                stage="SPEAKEASY",
                            )
                    if value is None:
                        value = validate_snapshot(self.deep.advance(record), record)
                    lease.check()

                    def save_deep(transaction):
                        return transaction.save_deep(
                            analysis_id,
                            token,
                            value,
                            finished=value["status"] in {"COMPLETED", "FAILED"},
                            current_stage=current_deep_stage(value),
                        )

                    lease.saved(
                        self._checkpoint(
                            record,
                            token,
                            "DEEP_ANALYSIS",
                            value,
                            save_deep,
                            check=lease.check,
                        )
                        if value["status"] in {"COMPLETED", "FAILED"}
                        else save_deep(self.repository)
                    )
                elif record.phase == "FINALIZING":
                    failed = (record.deep_result or {}).get("status") == "FAILED"
                    error = (
                        BackendError(
                            "DEEP_ANALYSIS_FAILED",
                            "심층 분석이 실패하여 전문가 검토가 필요합니다.",
                            stage="FINAL_ASSESSMENT",
                        ).to_dict()
                        if failed
                        else None
                    )
                    lease.check()
                    assessment = assess(record, failure=failed)
                    lease.saved(
                        self._checkpoint(
                            record,
                            token,
                            "FINAL_ASSESSMENT",
                            {"final_assessment": assessment, "error": error},
                            lambda transaction: transaction.finish(
                                analysis_id,
                                token,
                                assessment,
                                error=error,
                            ),
                            check=lease.check,
                        )
                    )
                    return self.repository.get(analysis_id)
                else:
                    raise BackendError(
                        "INVALID_PROCESSING_PHASE",
                        "저장된 분석 단계가 올바르지 않습니다.",
                        stage="PROCESSOR",
                    )
                self.repository.release(
                    analysis_id,
                    token,
                    next_retry_at=datetime.now(timezone.utc)
                    + timedelta(seconds=self.config.poll_seconds),
                )
            except LeaseLost:
                LOGGER.warning("analysis_lease_lost analysis_id=%s", analysis_id)
            except Exception as exc:  # noqa: BLE001 - durable task boundary with redacted errors
                error = (
                    exc
                    if isinstance(exc, BackendError)
                    else BackendError(
                        "PROCESSING_FAILED",
                        "분석 처리 중 오류가 발생했습니다.",
                        stage=record.current_stage,
                    )
                )
                retry_count = int((record.error or {}).get("retry_count", 0)) + 1
                try:
                    if error.retryable and retry_count < self.config.max_attempts:
                        payload = {**error.to_dict(), "retry_count": retry_count}
                        self.repository.release(
                            analysis_id,
                            token,
                            payload,
                            datetime.now(timezone.utc)
                            + timedelta(seconds=self.config.retry_delay_seconds),
                        )
                    else:
                        assessment, failure = (
                            assess(record, failure=True),
                            error.to_dict(),
                        )

                        def finish_failure(transaction):
                            return transaction.finish(
                                analysis_id, token, assessment, error=failure
                            )

                        try:
                            self._checkpoint(
                                record,
                                token,
                                "FINAL_ASSESSMENT",
                                {"final_assessment": assessment, "error": failure},
                                finish_failure,
                            )
                        except BackendError as artifact_error:
                            if not isinstance(artifact_error.__cause__, ArtifactError):
                                raise
                            # Even when artifact storage is down, preserve the
                            # original failure and final UNKNOWN recommendation.
                            LOGGER.warning(
                                "failure_artifact_unavailable analysis_id=%s",
                                analysis_id,
                            )
                            finish_failure(self.repository)
                        except LeaseLost:
                            LOGGER.warning(
                                "analysis_lease_lost analysis_id=%s", analysis_id
                            )
                except BackendError:
                    # 연결 복구 후 lease 만료로 재개한다. DB 오류 본문에 DSN은 남기지 않는다.
                    LOGGER.warning(
                        "analysis_checkpoint_deferred analysis_id=%s", analysis_id
                    )
        return self.repository.get(analysis_id)

    def resume_ready(
        self, limit: int = 10, *, should_stop=None
    ) -> list[AnalysisRecord]:
        values = []
        for analysis_id in self.repository.pending_ids(limit):
            if should_stop is not None and should_stop():
                break
            values.append(self.resume(analysis_id))
        return values
