"""All HTTP is mocked; reuse the existing detached repository and analysis fakes."""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.error import HTTPError
from urllib.parse import urlunsplit
from uuid import uuid4

import pytest

from trust_triage.backend_api import notifications as module
from trust_triage.backend_api.config import BackendConfig
from trust_triage.backend_api.errors import BackendError
from trust_triage.backend_api.notifications import DiscordNotifier
from trust_triage.backend_api.processor import BackendProcessor
from trust_triage.backend_api.repository import AnalysisRecord
from trust_triage.storage.artifacts import ArtifactError

from .test_service_processor import (  # noqa: F401 - pytest fixture registration
    deep_snapshot,
    harness,
    initial_result,
    next_step,
    submit,
)


def drain(notifier):
    deadline = time.monotonic() + 3
    while notifier._buffer.unfinished_tasks and time.monotonic() < deadline:
        time.sleep(0.005)
    assert notifier._buffer.unfinished_tasks == 0


@pytest.fixture
def http(monkeypatch):
    # Synthetic, per-test credentials only. Every opener is intercepted before
    # any notifier is constructed; no actual Discord/AWS/service is contacted.
    token = "test_" + uuid4().hex
    url = urlunsplit(("https", "discord.com", "/api/webhooks/0/" + token, "", ""))
    response = Mock(status=200)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    opener = Mock()
    opener.open.return_value = response
    factory = Mock(return_value=opener)
    monkeypatch.setattr(module, "build_opener", factory)
    monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
    return SimpleNamespace(url=url, token=token, opener=opener, factory=factory)


@pytest.fixture
def notifier(http):
    value = DiscordNotifier(BackendConfig(discord_webhook_url=http.url))
    yield value
    drain(value)
    value.close()


@pytest.fixture
def row():
    return AnalysisRecord(
        analysis_id="analysis-123", sha256="a" * 64, filename="sample.exe",
        file_location="private/location", size_bytes=128, status="RUNNING",
        phase="INITIAL", attempt_count=1,
    )


def payloads(http):
    return [json.loads(call.args[0].data) for call in http.opener.open.call_args_list]


def events(http):
    return [p["embeds"][0]["footer"]["text"] for p in payloads(http)]


def fields(payload):
    return {f["name"]: f["value"] for f in payload["embeds"][0]["fields"]}


@pytest.fixture
def connected(harness, http):
    harness.processor.notifications.close()
    harness.config = replace(harness.config, discord_webhook_url=http.url)
    harness.processor = BackendProcessor(
        harness.repository, harness.storage, harness.initial, harness.deep, harness.config,
    )
    yield harness
    drain(harness.processor.notifications)
    harness.processor.close()


@pytest.mark.parametrize("value", [None, "", "   "])
def test_unconfigured_is_disabled(http, monkeypatch, row, value):
    if value is not None:
        monkeypatch.setenv("DISCORD_WEBHOOK_URL", value)
    notifier = DiscordNotifier(BackendConfig.from_env())
    notifier.emit("ANALYSIS_STARTED", row)
    notifier.close()
    assert not notifier.enabled and notifier._thread is None
    http.factory.assert_not_called()


def test_configuration_and_notifier_repr_hide_secrets(http, monkeypatch):
    monkeypatch.setenv("DISCORD_WEBHOOK_URL", " " + http.url + " ")
    config = BackendConfig.from_env()
    assert config.discord_webhook_url == http.url
    assert http.url not in repr(config) and http.token not in repr(config)
    notifier = DiscordNotifier(config)
    assert http.url not in repr(notifier) and http.token not in repr(notifier)
    notifier.close()


@pytest.mark.parametrize("url", [
    "http://discord.com/api/webhooks/0/test",
    "https://untrusted.invalid/api/webhooks/0/test",
    "https://discord.com.evil.invalid/api/webhooks/0/test",
    "https://discord.com/api/webhooks/0/test?redirect=1",
])
def test_invalid_endpoint_disables_without_raising_or_leaking(http, row, caplog, url):
    notifier = DiscordNotifier(BackendConfig(discord_webhook_url=url))
    notifier.emit("ANALYSIS_STARTED", row)
    assert not notifier.enabled and url not in caplog.text
    http.factory.assert_not_called()


def test_start_payload_and_transport(notifier, http, row):
    notifier.emit("ANALYSIS_STARTED", row)
    drain(notifier)
    payload = payloads(http)[0]
    assert fields(payload) == {
        "분석 ID": "analysis-123", "파일명": "sample.exe",
        "SHA-256 (앞 12자리)": "a" * 12, "상태": "RUNNING",
    }
    assert payload["embeds"][0]["color"] == 0x3498DB
    assert payload["allowed_mentions"] == {"parse": [], "users": [], "roles": []}
    call = http.opener.open.call_args
    assert call.kwargs == {"timeout": 2.0}
    assert call.args[0].get_method() == "POST"
    assert call.args[0].full_url.endswith("?wait=true")
    assert http.factory.call_args.args[0].proxies == {}
    assert isinstance(http.factory.call_args.args[1], module._NoRedirect)
    assert module._NoRedirect().redirect_request(None, None, 302, "", {}, "") is None


@pytest.mark.parametrize("verdict,phrase,probability", [
    ("HIGH_RISK_UNCERTAIN", "심층 분석 대상", "70.00%"),
    ("AUTO_MALICIOUS", "악성 경보 및 전문가 검토 대상", "99.00%"),
    ("AUTO_BENIGN", None, None),
])
def test_initial_risk_payload(notifier, http, row, verdict, phrase, probability):
    notifier.emit("RISK_ALERT", row, initial=initial_result(verdict))
    drain(notifier)
    if phrase is None:
        assert payloads(http) == []
        return
    payload = payloads(http)[0]
    embed = payload["embeds"][0]
    assert phrase in embed["description"] and "아닙니다" in embed["description"]
    assert embed["color"] == 0xE67E22
    assert fields(payload)["초기 JRR 판정"] == verdict
    assert fields(payload)["보정 확률"] == probability
    assert fields(payload)["발현 위험 신호"] == (
        "UNCERTAIN_PROBABILITY" if verdict == "HIGH_RISK_UNCERTAIN" else "없음"
    )


@pytest.mark.parametrize("verdict", sorted(module.FINAL_VERDICTS))
@pytest.mark.parametrize("review", [True, False, None])
def test_complete_payload_supports_four_system_verdicts(notifier, http, row, verdict, review):
    assessment = {"final_verdict": verdict}
    if review is not None:
        assessment["requires_human_review"] = review
    row = replace(row, analyst_final_verdict="BENIGN")
    notifier.emit("ANALYSIS_COMPLETED", row, assessment=assessment)
    drain(notifier)
    payload = payloads(http)[0]
    assert fields(payload)["최종 시스템 판정"] == verdict
    assert payload["embeds"][0]["color"] == 0x2ECC71
    if review is None:
        assert "전문가 검토 필요" not in fields(payload)
    else:
        assert fields(payload)["전문가 검토 필요"] == ("예" if review else "아니요")


def test_failure_omits_private_data_and_verdict(notifier, http, row):
    row = replace(row, final_assessment={"final_verdict": "MALICIOUS"})
    notifier.emit("ANALYSIS_FAILED", row, error={
        "stage": "MODEL_LOADING", "code": "PROCESSING_FAILED",
        "message": http.url + " private stack API_KEY=private",
        "traceback": "private trace",
    })
    drain(notifier)
    payload = payloads(http)[0]
    assert fields(payload)["실패 단계"] == "MODEL_LOADING"
    assert fields(payload)["오류 코드"] == "PROCESSING_FAILED"
    assert payload["embeds"][0]["color"] == 0xE74C3C
    assert "악성 판정의 증거가 아닙니다" in payload["embeds"][0]["description"]
    assert "MALICIOUS" not in json.dumps(payload)
    assert "private" not in json.dumps(payload)


def test_untrusted_strings_and_known_secrets_are_filtered(http, row, caplog):
    secret = "private-api-credential"
    notifier = DiscordNotifier(BackendConfig(
        discord_webhook_url=http.url, api_token=secret * 2,
    ))
    filenames = [
        r"C:\private\folder\sample.exe",
        "../../private/sample.exe",
        "@everyone @here <@123> <@&123> [link](https://private.invalid/key)\n\u202e.exe",
        http.url, http.token, secret * 2 + ".exe", "A" * 3000,
    ]
    try:
        for filename in filenames:
            notifier.emit("ANALYSIS_STARTED", replace(row, filename=filename))
        notifier.emit("ANALYSIS_FAILED", row, error={
            "code": http.token, "stage": http.url, "message": "private stack",
        })
        drain(notifier)
        serialized = json.dumps(payloads(http), ensure_ascii=False)
        for forbidden in [http.url, http.token, secret, "@", "\u202e", "private",
                          row.file_location, row.sha256]:
            assert forbidden not in serialized
        for payload in payloads(http):
            assert len(fields(payload)["파일명"]) <= 128
        assert fields(payloads(http)[-1])["오류 코드"] == "ANALYSIS_ERROR"
        assert fields(payloads(http)[-1])["실패 단계"] == "확인 불가"
        assert not caplog.text
    finally:
        notifier.close()


@pytest.mark.parametrize("kind", ["timeout", "oserror", "http429", "http500", "http302"])
def test_delivery_failure_is_redacted_and_never_retried(notifier, http, row, caplog, kind):
    if kind.startswith("http"):
        error = HTTPError(http.url, int(kind[4:]), http.token, {}, None)
    else:
        error = TimeoutError(http.url) if kind == "timeout" else OSError(http.token)
    http.opener.open.side_effect = error
    notifier.emit("ANALYSIS_STARTED", row)
    drain(notifier)
    assert http.opener.open.call_count == 1
    assert "discord_notification_" in caplog.text
    assert http.url not in caplog.text and http.token not in caplog.text


def test_formatting_and_thread_start_failure_do_not_escape(notifier, http, row, monkeypatch):
    notifier.emit("UNKNOWN_EVENT", row)
    monkeypatch.setattr(module.threading.Thread, "start", Mock(side_effect=RuntimeError(http.url)))
    notifier.emit("ANALYSIS_STARTED", row)
    assert notifier._thread is None
    assert notifier._buffer.empty()
    http.opener.open.assert_not_called()


def test_slow_network_buffer_limit_and_close_do_not_block(notifier, http, row, caplog):
    entered, release = threading.Event(), threading.Event()

    def slow_open(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        raise TimeoutError("synthetic")

    http.opener.open.side_effect = slow_open
    try:
        notifier.emit("ANALYSIS_STARTED", row)
        assert entered.wait(1)
        for _ in range(module.BUFFER_SIZE + 5):
            notifier.emit("ANALYSIS_STARTED", row)
        assert notifier._buffer.qsize() == module.BUFFER_SIZE
        assert "discord_notification_buffer_full" in caplog.text
        started = time.monotonic()
        notifier.close()
        assert time.monotonic() - started < 1
        notifier.emit("ANALYSIS_STARTED", row)
        assert notifier._buffer.qsize() == module.BUFFER_SIZE
    finally:
        release.set()
        drain(notifier)


@pytest.mark.parametrize("verdict,expected", [
    ("AUTO_BENIGN", ["ANALYSIS_STARTED", "ANALYSIS_COMPLETED"]),
    ("AUTO_MALICIOUS", ["ANALYSIS_STARTED", "RISK_ALERT", "ANALYSIS_COMPLETED"]),
    ("HIGH_RISK_UNCERTAIN", ["ANALYSIS_STARTED", "RISK_ALERT"]),
])
def test_processor_notifications_are_after_commits(connected, http, monkeypatch, verdict, expected):
    h = connected
    h.initial.value = initial_result(verdict)
    accepted = submit(h)
    assert payloads(http) == []  # Upload acceptance does not mean analysis started.
    transaction = h.repository.sample_transaction
    active = False

    @contextmanager
    def tracked_transaction(hashes):
        nonlocal active
        with transaction(hashes) as tx:
            active = True
            try:
                yield tx
            finally:
                active = False

    monkeypatch.setattr(h.repository, "sample_transaction", tracked_transaction)
    emit = h.processor.notifications.emit

    def inspect(event, record, **kwargs):
        assert not active
        saved = h.repository.get(record.analysis_id)
        if event == "ANALYSIS_STARTED":
            assert saved.status == "RUNNING" and saved.attempt_count == 1
        elif event == "RISK_ALERT":
            assert saved.initial_result == kwargs["initial"]
        elif event == "ANALYSIS_COMPLETED":
            assert saved.status == "COMPLETED"
            assert saved.final_assessment == kwargs["assessment"]
        emit(event, record, **kwargs)

    monkeypatch.setattr(h.processor.notifications, "emit", inspect)
    h.processor.resume(accepted.analysis_id)
    drain(h.processor.notifications)
    assert events(http) == expected


@pytest.mark.parametrize("verdict", sorted(module.FINAL_VERDICTS))
def test_deep_completion_uses_persisted_system_verdict(connected, http, verdict):
    h = connected
    h.initial.value = initial_result("HIGH_RISK_UNCERTAIN")

    def snapshot(record):
        value = deep_snapshot(record)
        value["result"]["llm_interpretation"] = {"status": "SUCCESS"}
        value["result"]["final_verdict"] = verdict
        return value

    h.deep.outcomes.append(snapshot)
    accepted = submit(h)
    h.processor.resume(accepted.analysis_id)
    final = next_step(h, accepted.analysis_id)
    drain(h.processor.notifications)
    assert final.status == "COMPLETED"
    assert final.final_assessment["final_verdict"] == verdict
    assert fields(payloads(http)[-1])["최종 시스템 판정"] == verdict
    assert events(http) == ["ANALYSIS_STARTED", "RISK_ALERT", "ANALYSIS_COMPLETED"]


@pytest.mark.parametrize("failure", ["initial", "deep", "exhausted"])
def test_final_failed_only_after_persisted_finish(connected, http, monkeypatch, failure):
    h = connected
    if failure == "deep":
        h.initial.value = initial_result("HIGH_RISK_UNCERTAIN")
        h.deep.outcomes.append(lambda record: deep_snapshot(record, status="FAILED"))
    else:
        h.initial.outcomes.extend([
            BackendError("PROCESSING_FAILED", "private", stage="INITIAL_ANALYSIS",
                         retryable=failure == "exhausted")
        ] * h.config.max_attempts)
    emit = h.processor.notifications.emit

    def inspect(event, record, **values):
        if event == "ANALYSIS_FAILED":
            assert h.repository.get(record.analysis_id).status == "FAILED"
        emit(event, record, **values)

    monkeypatch.setattr(h.processor.notifications, "emit", inspect)
    accepted = submit(h)
    final = h.processor.resume(accepted.analysis_id)
    for _ in range(3):
        if final.terminal:
            break
        drain(h.processor.notifications)
        assert "ANALYSIS_FAILED" not in events(http)
        final = next_step(h, accepted.analysis_id, seconds=3)
    drain(h.processor.notifications)
    assert final.status == "FAILED"
    assert events(http).count("ANALYSIS_FAILED") == 1
    assert "ANALYSIS_COMPLETED" not in events(http)


def restart(h):
    drain(h.processor.notifications)
    h.processor.close()
    h.processor = BackendProcessor(
        h.repository, h.storage, h.initial, h.deep, h.config,
    )


def test_retry_and_restart_do_not_repeat_start(connected, http):
    h = connected
    h.initial.outcomes.append(BackendError("PROCESSING_TIMEOUT", "private", retryable=True))
    accepted = submit(h)
    assert h.processor.resume(accepted.analysis_id).status == "RUNNING"
    drain(h.processor.notifications)
    assert events(http) == ["ANALYSIS_STARTED"]
    restart(h)
    assert next_step(h, accepted.analysis_id, seconds=3).status == "COMPLETED"
    drain(h.processor.notifications)
    assert events(http) == ["ANALYSIS_STARTED", "ANALYSIS_COMPLETED"]


def test_resume_waiting_deep_finalizing_and_terminal_do_not_replay(connected, http, monkeypatch):
    h = connected
    h.initial.value = initial_result("HIGH_RISK_UNCERTAIN")
    h.deep.outcomes.append(lambda row: deep_snapshot(row, status="RUNNING", phase="WAITING"))
    accepted = submit(h)
    h.processor.resume(accepted.analysis_id)
    restart(h)
    next_step(h, accepted.analysis_id)
    drain(h.processor.notifications)
    assert events(http) == ["ANALYSIS_STARTED", "RISK_ALERT"]
    # Simulate a process stopping after the deep checkpoint, before finalize.
    with monkeypatch.context() as m:
        m.setattr(h.processor, "_finalize_now", lambda *args: h.repository.get(args[0]))
        finalizing = next_step(h, accepted.analysis_id)
        assert finalizing.phase == "FINALIZING"
    restart(h)
    h.clock.advance(h.config.lease_seconds + 1)
    assert h.processor.resume(accepted.analysis_id).status == "COMPLETED"
    restart(h)
    h.processor.resume(accepted.analysis_id)
    drain(h.processor.notifications)
    assert events(http) == ["ANALYSIS_STARTED", "RISK_ALERT", "ANALYSIS_COMPLETED"]


def test_unsuccessful_claim_never_notifies(connected, http):
    h = connected
    accepted = submit(h)
    h.repository.claim(accepted.analysis_id, h.config.lease_seconds)
    h.processor.resume(accepted.analysis_id)
    assert payloads(http) == []
    assert h.initial.calls == []


@pytest.mark.parametrize("operation", ["save_initial", "finish"])
def test_storage_failure_does_not_emit_success(connected, http, operation):
    h = connected
    h.initial.value = initial_result("AUTO_MALICIOUS")
    h.repository.failures[operation] = 1
    accepted = submit(h)
    row = h.processor.resume(accepted.analysis_id)
    drain(h.processor.notifications)
    expected = ["ANALYSIS_STARTED"] + (["RISK_ALERT"] if operation == "finish" else [])
    assert events(http) == expected
    assert row.status == "RUNNING"
    restart(h)
    final = next_step(h, accepted.analysis_id, seconds=3)
    drain(h.processor.notifications)
    assert final.status == "COMPLETED"
    assert events(http) == ["ANALYSIS_STARTED", "RISK_ALERT", "ANALYSIS_COMPLETED"]


def test_commit_rollback_does_not_emit_risk_alert(connected, http, monkeypatch):
    h = connected
    h.initial.value = initial_result("AUTO_MALICIOUS")
    accepted = submit(h)
    transaction = h.repository.sample_transaction

    @contextmanager
    def failed_commit(hashes):
        with transaction(hashes) as tx:
            yield tx
            raise BackendError("DATABASE_ERROR", "private commit error", retryable=True)

    monkeypatch.setattr(h.repository, "sample_transaction", failed_commit)
    row = h.processor.resume(accepted.analysis_id)
    drain(h.processor.notifications)
    assert row.initial_result is None
    assert events(http) == ["ANALYSIS_STARTED"]


@pytest.mark.parametrize("accepted", [False, True])
def test_failure_artifact_fallback_notifies_only_if_finish_accepted(connected, http, monkeypatch, accepted):
    h = connected
    h.initial.outcomes.append(BackendError("PROCESSING_FAILED", "private"))
    monkeypatch.setattr(h.processor.artifacts, "put_json", Mock(
        side_effect=ArtifactError("ARTIFACT_UNAVAILABLE", "private", retryable=True),
    ))
    if not accepted:
        monkeypatch.setattr(h.repository, "finish", Mock(return_value=False))
    submitted = submit(h)
    row = h.processor.resume(submitted.analysis_id)
    drain(h.processor.notifications)
    assert (row.status == "FAILED") is accepted
    assert ("ANALYSIS_FAILED" in events(http)) is accepted


def test_final_failure_save_error_does_not_notify(connected, http):
    h = connected
    h.initial.outcomes.append(BackendError("PROCESSING_FAILED", "private"))
    h.repository.failures["finish"] = 1
    accepted = submit(h)
    assert h.processor.resume(accepted.analysis_id).status == "RUNNING"
    drain(h.processor.notifications)
    assert events(http) == ["ANALYSIS_STARTED"]


@pytest.mark.parametrize("operation", ["save_initial", "finish"])
def test_fenced_checkpoint_does_not_emit_success(connected, http, monkeypatch, operation):
    h = connected
    h.initial.value = initial_result("AUTO_MALICIOUS")
    monkeypatch.setattr(h.repository, operation, Mock(return_value=False))
    accepted = submit(h)
    h.processor.resume(accepted.analysis_id)
    drain(h.processor.notifications)
    assert events(http) == ["ANALYSIS_STARTED"] + (["RISK_ALERT"] if operation == "finish" else [])


@pytest.mark.parametrize("error_type", [TimeoutError, OSError])
def test_http_failures_never_change_analysis_or_retry(connected, http, error_type):
    h = connected
    h.initial.value = initial_result("AUTO_MALICIOUS")
    http.opener.open.side_effect = error_type(http.url)
    accepted = submit(h)
    row = h.processor.resume(accepted.analysis_id)
    drain(h.processor.notifications)
    assert row.status == "COMPLETED" and row.error is None
    assert row.attempt_count == 1
    assert h.repository.calls["release"] == 0
    assert http.opener.open.call_count == 3


def test_blocked_http_does_not_delay_analysis(connected, http):
    entered, release = threading.Event(), threading.Event()
    h = connected

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        raise TimeoutError("synthetic")

    http.opener.open.side_effect = blocked
    try:
        accepted = submit(h)
        row = h.processor.resume(accepted.analysis_id)
        assert entered.wait(1)
        assert row.status == "COMPLETED"
        assert not release.is_set()
    finally:
        release.set()
        drain(h.processor.notifications)



@pytest.mark.parametrize("failed", [False, True])
def test_terminal_commit_rollback_never_notifies(connected, http, monkeypatch, failed):
    h = connected
    accepted = submit(h)
    claim = h.repository.claim(accepted.analysis_id, h.config.lease_seconds)
    h.repository.save_initial(
        accepted.analysis_id, claim.token, initial_result("AUTO_BENIGN"), False,
    )
    h.repository.release(accepted.analysis_id, claim.token)
    if failed:
        h.repository.rows[accepted.analysis_id] = replace(
            h.repository.rows[accepted.analysis_id], deep_result={"status": "FAILED"},
        )
    transaction = h.repository.sample_transaction

    @contextmanager
    def reject_commit(hashes):
        with transaction(hashes) as tx:
            yield tx
            raise BackendError("DATABASE_ERROR", "private", retryable=True)

    monkeypatch.setattr(h.repository, "sample_transaction", reject_commit)
    row = h.processor.resume(accepted.analysis_id)
    drain(h.processor.notifications)
    assert row.status == "RUNNING"
    assert row.final_assessment is None
    assert events(http) == []


def test_notification_format_failure_never_changes_analysis(connected, http, monkeypatch, caplog):
    h = connected
    monkeypatch.setattr(
        h.processor.notifications, "_payload", Mock(side_effect=ValueError(http.url)),
    )
    accepted = submit(h)
    row = h.processor.resume(accepted.analysis_id)
    assert row.status == "COMPLETED" and row.attempt_count == 1
    assert h.repository.calls["release"] == 0
    assert http.url not in caplog.text
    assert events(http) == []

