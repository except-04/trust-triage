"""통합 업로드(PE/ZIP) 접수의 중간 저장 동작 테스트.

여러 ZIP은 파일당 한 번씩 순차 접수된다. 뒤 요청이 실패하거나 스크립트가
중간에 끊겨도, 이미 백엔드가 받아 준 배치는 프론트 상태에 남아 있어야 한다.
남지 않으면 batch_id 를 잃어버려 폴링할 방법이 없어진다.
"""

from __future__ import annotations

import pytest

from api_client import ApiError


def pe_desc(name="sample.exe"):
    return {"filename": name, "size": 128, "content": b"MZ", "kind": "PE"}


def zip_desc(name):
    return {"filename": name, "size": 256, "content": b"PK", "kind": "ZIP"}


def other_desc(name="notes.txt"):
    return {"filename": name, "size": 10, "content": b"hi", "kind": "OTHER"}


def receipt(batch_id, accepted=(), skipped=()):
    """백엔드 접수 응답(202) 모양."""
    entries, analyses = [], []
    for analysis_id, filename in accepted:
        entries.append(
            {
                "analysis_id": analysis_id,
                "status": "ACCEPTED",
                "filename": filename,
                "sha256": "a" * 64,
                "size_bytes": 256,
            }
        )
        analyses.append({"analysis_id": analysis_id, "status": "QUEUED"})
    for filename, reason in skipped:
        entries.append(
            {
                "status": "SKIPPED",
                "filename": filename,
                "size_bytes": 12,
                "reason_code": "NOT_A_PE",
                "reason": reason,
            }
        )
    return {"batch_id": batch_id, "analyses": analyses, "entries": entries}


def completed_result(analysis_id):
    return {
        "analysis_id": analysis_id,
        "status": "COMPLETED",
        "initial_verdict": "AUTO_BENIGN",
        "route": "STATIC_ONLY",
        "prediction": {
            "lgbm_raw_probability": 0.1,
            "calibrated_probability": 0.08,
        },
        "risk_signals": {
            "disagreement": 0.01,
            "ood_score": 1.2,
            "difficulty_score": 2,
        },
    }


class Recorder:
    """접수 진행 중 session_state 가 어떻게 쌓이는지 단계별로 기록한다."""

    def __init__(self, app):
        self.app = app
        self.steps = []

    def __call__(self, partial_receipt):
        promoted = self.app.commit_receipt(partial_receipt)
        state = self.app.st.session_state
        self.steps.append(
            {
                "promoted": promoted,
                "batch_ids": list(state.get("batch_ids") or []),
                "analyses": len(state.get("batch_results") or []),
                "errors": len((state.get("intake_receipt") or {}).get("errors", [])),
            }
        )
        return promoted


# --- 여러 ZIP 전건 성공 -------------------------------------------------


def test_each_zip_receipt_is_stored_before_the_next_request(app, monkeypatch):
    zips = [zip_desc("a.zip"), zip_desc("b.zip"), zip_desc("c.zip")]
    responses = {
        "a.zip": receipt("B1", accepted=[("A1", "one.exe")]),
        "b.zip": receipt("B2", accepted=[("A2", "two.exe")]),
        "c.zip": receipt("B3", accepted=[("A3", "three.exe")]),
    }
    monkeypatch.setattr(
        app.api_client, "upload_zip", lambda name, content: responses[name]
    )

    recorder = Recorder(app)
    result = app.submit_batch(zips, on_progress=recorder)

    # 요청 하나가 끝날 때마다 저장됐는지 — 마지막에 몰아서 저장하면 실패한다
    assert [step["batch_ids"] for step in recorder.steps] == [
        ["B1"],
        ["B1", "B2"],
        ["B1", "B2", "B3"],
    ]
    assert [step["analyses"] for step in recorder.steps] == [1, 2, 3]
    assert result["batch_ids"] == ["B1", "B2", "B3"]
    assert result["errors"] == []


def test_pe_batch_is_stored_before_zip_requests_start(app, monkeypatch):
    calls = []

    def upload_batch(payload):
        calls.append("pe")
        return receipt("B-PE", accepted=[("A0", "sample.exe")])

    def upload_zip(name, content):
        # ZIP 요청이 시작되는 시점에 PE 접수 결과가 이미 저장돼 있어야 한다
        calls.append(("zip", list(app.st.session_state.get("batch_ids") or [])))
        return receipt("B1", accepted=[("A1", "one.exe")])

    monkeypatch.setattr(app.api_client, "upload_batch", upload_batch)
    monkeypatch.setattr(app.api_client, "upload_zip", upload_zip)

    app.submit_batch([pe_desc(), zip_desc("a.zip")], on_progress=app.commit_receipt)

    assert calls == ["pe", ("zip", ["B-PE"])]


# --- 중간 실패 ----------------------------------------------------------


def test_zip_failure_keeps_earlier_and_later_batches(app, monkeypatch):
    def upload_zip(name, content):
        if name == "b.zip":
            raise ApiError("ZIP_TOO_LARGE", "ZIP 용량 초과", http_status=413)
        return receipt(
            {"a.zip": "B1", "c.zip": "B3"}[name],
            accepted=[({"a.zip": "A1", "c.zip": "A3"}[name], name)],
        )

    monkeypatch.setattr(app.api_client, "upload_zip", upload_zip)

    recorder = Recorder(app)
    result = app.submit_batch(
        [zip_desc("a.zip"), zip_desc("b.zip"), zip_desc("c.zip")],
        on_progress=recorder,
    )

    # 실패한 요청 하나 때문에 성공한 접수가 사라지면 안 된다
    assert result["batch_ids"] == ["B1", "B3"]
    assert [e["filename"] for e in result["errors"]] == ["b.zip"]
    assert app.st.session_state["batch_ids"] == ["B1", "B3"]
    assert len(app.st.session_state["batch_results"]) == 2
    # 실패 사유도 그 자리에서 저장된다
    assert recorder.steps[1]["errors"] == 1
    assert recorder.steps[1]["batch_ids"] == ["B1"]


def test_unexpected_exception_still_leaves_earlier_batch_pollable(app, monkeypatch):
    """ApiError 가 아닌 예외로 스크립트가 끊겨도 앞선 접수는 남아야 한다."""

    def upload_zip(name, content):
        if name == "b.zip":
            raise RuntimeError("연결이 끊겼습니다")
        return receipt("B1", accepted=[("A1", "one.exe")])

    monkeypatch.setattr(app.api_client, "upload_zip", upload_zip)

    with pytest.raises(RuntimeError):
        app.submit_batch(
            [zip_desc("a.zip"), zip_desc("b.zip")], on_progress=app.commit_receipt
        )

    state = app.st.session_state
    assert state["batch_ids"] == ["B1"]
    assert app.batch_id_list(state["batch_data"]) == ["B1"]
    # 결과 화면/폴링으로 넘어갈 수 있는 상태여야 한다
    assert state["analysis_result"]["analysis_id"] == "A1"
    assert app.pending_analyses(state["batch_data"])


def test_first_zip_failure_does_not_block_later_zip(app, monkeypatch):
    def upload_zip(name, content):
        if name == "a.zip":
            raise ApiError("ZIP_INVALID", "ZIP 을 열 수 없습니다")
        return receipt("B2", accepted=[("A2", "two.exe")])

    monkeypatch.setattr(app.api_client, "upload_zip", upload_zip)

    result = app.submit_batch(
        [zip_desc("a.zip"), zip_desc("b.zip")], on_progress=app.commit_receipt
    )

    assert result["batch_ids"] == ["B2"]
    assert app.st.session_state["analysis_result"]["analysis_id"] == "A2"


# --- 부분 성공 / analyses == [] -----------------------------------------


def test_all_skipped_zip_is_not_promoted_and_does_not_crash(app, monkeypatch):
    monkeypatch.setattr(
        app.api_client,
        "upload_zip",
        lambda name, content: receipt(
            "B1", skipped=[("readme.txt", "PE 가 아닙니다")]
        ),
    )

    recorder = Recorder(app)
    result = app.submit_batch([zip_desc("a.zip")], on_progress=recorder)

    assert result["analyses"] == []
    assert recorder.steps[0]["promoted"] is False
    # 결과 화면으로 넘기지 않는다 — 폴링할 대상이 없다
    assert "batch_data" not in app.st.session_state
    assert app.st.session_state["analysis_result"] is None
    # 제외 사유는 남는다
    assert app.st.session_state["intake_receipt"]["skipped"][0]["source"] == "a.zip"


def test_empty_zip_then_accepted_zip_recovers(app, monkeypatch):
    def upload_zip(name, content):
        if name == "a.zip":
            return receipt("B1", skipped=[("readme.txt", "PE 가 아닙니다")])
        return receipt("B2", accepted=[("A2", "two.exe")])

    monkeypatch.setattr(app.api_client, "upload_zip", upload_zip)

    recorder = Recorder(app)
    result = app.submit_batch(
        [zip_desc("a.zip"), zip_desc("b.zip")], on_progress=recorder
    )

    assert [step["promoted"] for step in recorder.steps] == [False, True]
    assert result["batch_ids"] == ["B1", "B2"]
    assert len(result["skipped"]) == 1
    assert app.st.session_state["analysis_result"]["analysis_id"] == "A2"


def test_unsupported_files_are_recorded_without_any_request(app, monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("요청을 보내면 안 된다")

    monkeypatch.setattr(app.api_client, "upload_zip", fail)
    monkeypatch.setattr(app.api_client, "upload_batch", fail)

    result = app.submit_batch([other_desc()], on_progress=app.commit_receipt)

    assert result["batch_ids"] == []
    assert result["analyses"] == []
    assert app.st.session_state["intake_receipt"]["skipped"][0]["filename"] == (
        "notes.txt"
    )


def test_empty_analyses_are_safe_for_summary_helpers(app):
    """중간 단계의 analyses == [] 가 집계 경로에서 터지지 않아야 한다."""
    empty = {"batch_ids": ["B1"], "analyses": [], "skipped": [], "errors": []}

    assert app.derive_batch_summary([])["total"] == 0
    assert app.pending_analyses(empty) == []
    assert app.group_batch_analyses([]) == {
        "needs_review": [],
        "auto_malicious": [],
        "auto_benign": [],
        "failed": [],
    }
    assert app.poll_status_counts([])["QUEUED"] == 0
    assert app.batch_id_list(empty) == ["B1"]
    assert app.commit_receipt(empty) is False


def test_selected_analysis_is_not_reset_by_later_receipts(app, monkeypatch):
    def upload_zip(name, content):
        return receipt(
            {"a.zip": "B1", "b.zip": "B2"}[name],
            accepted=[({"a.zip": "A1", "b.zip": "A2"}[name], name)],
        )

    monkeypatch.setattr(app.api_client, "upload_zip", upload_zip)

    app.submit_batch(
        [zip_desc("a.zip"), zip_desc("b.zip")], on_progress=app.commit_receipt
    )

    # 먼저 접수된 건이 계속 선택돼 있어야 한다(화면이 뒤 배치로 튀지 않게)
    assert app.st.session_state["selected_analysis_id"] == "A1"
    assert len(app.st.session_state["batch_results"]) == 2


# --- 부분 성공 상태에서의 폴링 -----------------------------------------


def test_polling_updates_reachable_batch_when_another_batch_fails(app, monkeypatch):
    def upload_zip(name, content):
        return receipt(
            {"a.zip": "B1", "b.zip": "B2"}[name],
            accepted=[({"a.zip": "A1", "b.zip": "A2"}[name], name)],
        )

    monkeypatch.setattr(app.api_client, "upload_zip", upload_zip)
    app.submit_batch(
        [zip_desc("a.zip"), zip_desc("b.zip")], on_progress=app.commit_receipt
    )
    batch_data = app.st.session_state["batch_data"]

    def get_batch(batch_id):
        if batch_id == "B1":
            raise ApiError("BATCH_NOT_FOUND", "조회 실패", http_status=503)
        return {"batch_id": "B2", "analyses": [completed_result("A2")]}

    monkeypatch.setattr(app.api_client, "get_batch", get_batch)

    still_running = app.refresh_batch(batch_data)

    by_id = {a["analysis_id"]: a for a in batch_data["analyses"]}
    # 조회된 배치는 정상 갱신
    assert by_id["A2"]["status"] == "COMPLETED"
    assert by_id["A2"]["initial_verdict"] == "AUTO_BENIGN"
    # 조회 실패한 배치는 진행 중으로 남긴다(상태를 추측하지 않는다)
    assert by_id["A1"]["status"] == "QUEUED"
    assert still_running is True
