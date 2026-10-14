"""Best-effort Discord embeds; no network or durable state in the analysis path."""

from __future__ import annotations

import json
import logging
import math
import ntpath
import queue
import re
import threading
import unicodedata
from collections import Counter, OrderedDict
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .config import BackendConfig

LOGGER = logging.getLogger(__name__)
HTTP_TIMEOUT_SECONDS = 2.0
BUFFER_SIZE = 128
BATCH_HISTORY_SIZE = 1024
# One HTTP attempt per event, zero retries (including 429/5xx/timeouts).
# A timeout may mean Discord accepted the message; never blindly replay it.
EVENTS = {
    "RISK_ALERT": ("초기 위험 판정", 0xE67E22),
    "ANALYSIS_COMPLETED": ("분석 완료", 0x2ECC71),
    "ANALYSIS_FAILED": ("분석 실패", 0xE74C3C),
    "BATCH_SUMMARY": ("배치 분석 완료", 0x2ECC71),
}
INITIAL_VERDICTS = {"AUTO_BENIGN", "AUTO_MALICIOUS", "HIGH_RISK_UNCERTAIN"}
FINAL_VERDICTS = {"MALICIOUS", "SUSPICIOUS", "BENIGN", "INCONCLUSIVE"}
SIGNALS = {"OOD", "DISAGREEMENT", "DIFFICULTY", "UNCERTAIN_PROBABILITY"}
# Never echo arbitrary BackendError.code/stage, even if it looks like an enum.
ERROR_CODES = {
    "PROCESSING_FAILED", "PROCESSING_TIMEOUT", "DEEP_ANALYSIS_FAILED",
    "DEEP_WAIT_TIMEOUT", "INITIAL_RESULT_INVALID", "INVALID_PROCESSING_PHASE",
    "DATABASE_ERROR", "MODEL_DEPENDENCY_MISSING", "MODEL_LOADING_FAILED",
    "FEATURE_EXTRACTION_FAILED", "INFERENCE_FAILED", "XAI_FAILED",
    "ARTIFACT_UNAVAILABLE", "SAMPLE_NOT_FOUND",
    # Explicit codes emitted by initial_analysis.py, initial_worker.py and
    # model_bundle.py. Do not accept arbitrary *_FAILED or *_INVALID strings.
    "MODEL_NOT_CONFIGURED", "MODEL_ARTIFACT_MISSING", "MODEL_SCHEMA_MISMATCH",
    "MODEL_LOAD_FAILED", "FEATURE_EXTRACTION_TIMEOUT", "SAMPLE_HASH_MISMATCH",
    "FEATURE_SCHEMA_MISMATCH", "FEATURE_NONFINITE",
    "MODEL_INFERENCE_FAILED", "MODEL_OUTPUT_INVALID",
    "CALIBRATION_FAILED", "CALIBRATION_OUTPUT_INVALID",
    "RISK_SIGNALS_FAILED", "RISK_OUTPUT_INVALID",
    "INITIAL_JRR_FAILED", "JRR_OUTPUT_INVALID",
    "INITIAL_ANALYSIS_FAILED", "INITIAL_ANALYSIS_START_FAILED",
    "INITIAL_ANALYSIS_TIMEOUT", "INITIAL_ANALYSIS_PROCESS_EXITED",
    "INITIAL_ANALYSIS_PROTOCOL_ERROR",
}
STAGES = {
    "UPLOAD", "INITIAL_ANALYSIS", "JRR", "CAPA_FLOSS", "SPEAKEASY", "LLM",
    "FINAL_ASSESSMENT", "PROCESSOR", "STORAGE", "MODEL_LOADING",
    "FEATURE_EXTRACTION", "INFERENCE", "XAI",
    "MODEL_INFERENCE", "CALIBRATION", "RISK_SIGNALS", "INITIAL_JRR",
}
WEBHOOK_PATTERN = re.compile(
    r"https://(?:discord\.com|canary\.discord\.com|ptb\.discord\.com)"
    r"/api/(?:v10/)?webhooks/[0-9]+/[A-Za-z0-9_-]+"
)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class DiscordNotifier:
    """Bounded, volatile delivery buffer with one lazy daemon sender per processor.

    emit() owns the exception boundary, including formatting and thread startup.
    Do not invoke it inside a DB transaction. No API receives unfiltered records.
    """

    def __init__(self, config: BackendConfig):
        value = config.discord_webhook_url.strip()
        self._url = value if WEBHOOK_PATTERN.fullmatch(value) else ""
        self._secrets = tuple(
            secret for secret in (
                value, value.rsplit("/", 1)[-1], config.api_token,
                config.reviewer_token, config.database_url,
            ) if secret
        )
        self._buffer = queue.Queue(maxsize=BUFFER_SIZE)
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._thread = None
        self._summarized_batches = OrderedDict()
        if value and not self._url:
            LOGGER.warning("discord_notifications_disabled_invalid_configuration")

    @property
    def enabled(self):
        return bool(self._url) and not self._stopped.is_set()

    def _text(self, value, *, filename=False, limit=128):
        text = unicodedata.normalize("NFKC", str(value))
        for secret in self._secrets:
            text = text.replace(secret, "[비공개]")
        text = re.sub(r"[A-Za-z][A-Za-z0-9+.-]*://\S+", "[비공개]", text)
        text = re.sub(
            r"(?i)(?:api[_-]?key|token|password|secret)\s*[:=]\s*\S+",
            "[비공개]", text,
        )
        if filename:
            text = ntpath.basename(text)
        # Strip opaque credentials, controls, mentions and Markdown/link syntax.
        text = re.sub(r"[A-Za-z0-9_-]{24,}", "[비공개]", text)
        text = "".join(
            char if (char.isalnum() or char in " ._-") else " "
            for char in text
        )
        return " ".join(text.split())[:limit] or "확인 불가"

    def finished(self, record, repository, *, assessment=None, error=None):
        """Called only after a terminal commit; notification reads cannot fail a job."""
        if not self.enabled:
            return
        try:
            if error is not None:
                self.emit("ANALYSIS_FAILED", record, error=error)
            elif record.batch_id is None:
                self.emit("ANALYSIS_COMPLETED", record, assessment=assessment)
            if record.batch_id is not None:
                batch = repository.batch_record(record.batch_id)
                if batch is not None:
                    self.emit("BATCH_SUMMARY", batch)
        except Exception:  # noqa: BLE001 - never expose DB/notification error details
            LOGGER.warning("discord_notification_completion_failed")

    def _batch_payload(self, batch):
        rows = batch.analyses
        if batch.batch_id is None or not rows or not all(row.terminal for row in rows):
            return None
        counts = Counter(row.status for row in rows)
        verdicts = Counter(
            (row.final_assessment or {}).get("final_verdict")
            for row in rows if row.status == "COMPLETED"
        )
        skipped = sum(
            entry.status == "SKIPPED" for entry in batch.input_report.entries
        ) if batch.input_report is not None else 0
        identity = batch.batch_id
        safe_id = (
            identity if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identity)
            and not any(secret in identity for secret in self._secrets)
            else "확인 불가"
        )
        values = [
            ("배치 ID", safe_id), ("분석 대상 파일 수", len(rows)),
            ("정상 완료", counts["COMPLETED"]), ("분석 실패", counts["FAILED"]),
            ("SKIPPED", skipped),
        ]
        values.extend(
            (verdict, verdicts[verdict])
            for verdict in ("MALICIOUS", "SUSPICIOUS", "BENIGN", "INCONCLUSIVE")
        )
        title, color = EVENTS["BATCH_SUMMARY"]
        return {
            "allowed_mentions": {"parse": [], "users": [], "roles": []},
            "embeds": [{
                "title": title, "color": color,
                "description": (
                    "배치의 모든 분석이 종료되었습니다. 최종 시스템 판정은 정상 완료 건만 "
                    "집계하며 분석가의 확정 판정과 별도입니다. 분석 실패는 악성 증거가 아닙니다."
                ),
                "fields": [
                    {"name": name, "value": str(value), "inline": False}
                    for name, value in values
                ],
                "footer": {"text": "BATCH_SUMMARY"},
            }],
        }

    def _payload(self, event, record, *, initial=None, assessment=None, error=None):
        if event == "ANALYSIS_STARTED":
            return None
        if event == "ANALYSIS_COMPLETED" and record.batch_id is not None:
            return None
        if event == "BATCH_SUMMARY":
            return self._batch_payload(record)
        title, color = EVENTS[event]
        initial = initial if initial is not None else record.initial_result or {}
        verdict = initial.get("initial_verdict")
        if event == "RISK_ALERT" and verdict not in {
            "HIGH_RISK_UNCERTAIN", "AUTO_MALICIOUS",
        }:
            return None
        fields = []

        def field(name, value):
            fields.append({"name": name, "value": str(value), "inline": False})

        # The database validates IDs. Keep their useful full UUID, but never echo
        # unexpected user-supplied values or known credentials.
        identity = record.analysis_id
        field("분석 ID", identity if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identity)
              and not any(secret in identity for secret in self._secrets)
              else "확인 불가")
        field("파일명", self._text(record.filename, filename=True))
        description = ""
        if event == "RISK_ALERT":
            field("초기 JRR 판정", verdict)
            probability = (initial.get("prediction") or {}).get("calibrated_probability")
            valid = (isinstance(probability, (int, float))
                     and not isinstance(probability, bool)
                     and math.isfinite(probability) and 0 <= probability <= 1)
            field("보정 확률", f"{probability:.2%}" if valid else "확인 불가")
            signals = initial.get("triggered_signals")
            signal_text = (
                ", ".join(signal for signal in signals if signal in SIGNALS) or "없음"
                if isinstance(signals, list) else "기록 없음"
            )
            field("발현 위험 신호", signal_text)
            description = (
                "심층 분석 대상입니다. 초기 위험 신호이며 확정된 악성 판정이 아닙니다."
                if verdict == "HIGH_RISK_UNCERTAIN" else
                "악성 경보 및 전문가 검토 대상입니다. 분석가가 확정한 악성 판정이 아닙니다."
            )
        elif event == "ANALYSIS_COMPLETED":
            assessment = assessment if assessment is not None else record.final_assessment or {}
            field("상태", "COMPLETED")
            field("초기 JRR 판정", verdict if verdict in INITIAL_VERDICTS else "확인 불가")
            final = assessment.get("final_verdict")
            field("최종 시스템 판정", final if final in FINAL_VERDICTS else "확인 불가")
            review = assessment.get("requires_human_review")
            if isinstance(review, bool):
                field("전문가 검토 필요", "예" if review else "아니요")
            description = "시스템 분석이 완료되었습니다. 분석가의 확정 판정과는 별도입니다."
        else:
            error = error if error is not None else record.error or {}
            stage, code = error.get("stage"), error.get("code")
            field("상태", "FAILED")
            field("실패 단계", stage if stage in STAGES else "확인 불가")
            field("오류 코드", code if code in ERROR_CODES else "ANALYSIS_ERROR")
            description = "분석이 최종 실패했습니다. 실패는 악성 판정의 증거가 아닙니다."
        return {
            "allowed_mentions": {"parse": [], "users": [], "roles": []},
            "embeds": [{
                "title": title, "color": color, "description": description,
                "fields": fields, "footer": {"text": event},
            }],
        }

    def emit(self, event, record, **values):
        """Non-blocking best effort. Never propagate a notification exception."""
        if not self.enabled:
            return
        try:
            payload = self._payload(event, record, **values)
            if payload is None:
                return
            data = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
            with self._lock:
                if self._stopped.is_set():
                    return
                if event == "BATCH_SUMMARY" and record.batch_id in self._summarized_batches:
                    return
                if self._thread is None:
                    thread = threading.Thread(
                        target=self._run, name="discord-notifications", daemon=True,
                    )
                    thread.start()
                    self._thread = thread
                self._buffer.put_nowait(data)
                if event == "BATCH_SUMMARY":
                    # Record enqueue, not HTTP success: delivery is never retried.
                    self._summarized_batches[record.batch_id] = None
                    if len(self._summarized_batches) > BATCH_HISTORY_SIZE:
                        self._summarized_batches.popitem(last=False)
        except queue.Full:
            LOGGER.warning("discord_notification_buffer_full")
        except Exception:  # noqa: BLE001 - URL and exception text must never escape
            LOGGER.warning("discord_notification_enqueue_failed")

    def _send(self, data):
        # Disable redirects/proxies so the credential and payload cannot be
        # forwarded to an unexpected endpoint. Never read/log response bodies.
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        request = Request(
            self._url + "?wait=true", data=data, method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "TRUST-Triage/1.0",
            },
        )
        try:
            with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                if not 200 <= response.status < 300:
                    LOGGER.warning("discord_notification_http_failed")
        except HTTPError as error:
            error.close()
            LOGGER.warning("discord_notification_http_failed")

    def _run(self):
        while not self._stopped.is_set() or not self._buffer.empty():
            try:
                data = self._buffer.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                self._send(data)
            except Exception:  # noqa: BLE001 - includes timeout, TLS and DNS failures
                LOGGER.warning("discord_notification_delivery_failed")
            finally:
                self._buffer.task_done()

    def close(self):
        """Allow a brief drain, but never hold up processor shutdown for HTTP."""
        with self._lock:
            self._stopped.set()
            thread = self._thread
        if thread is not None:
            thread.join(timeout=0.2)

