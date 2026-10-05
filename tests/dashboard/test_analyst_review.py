"""분석가 판정 수정 (PATCH /analyses/{id}/verdict).

백엔드는 initial_verdict / final_verdict 를 바꾸지 않고 analyst_final_verdict 와
review_revision 만 갱신한다. 그래서 그룹 이동, 표의 수정 여부 열, Final Verdict
배지는 전부 프론트가 이 두 값으로 정한다. 그 규칙과 팝업의 저장 흐름을 본다.
"""

from __future__ import annotations

import pytest

import api_client
from api_client import ApiError


def analysis(
    analysis_id="A1",
    verdict="AUTO_BENIGN",
    status="COMPLETED",
    analyst=None,
    revision=0,
    approval=None,
    **overrides,
):
    """to_view() 를 거친 배치 결과 항목."""
    item = {
        "analysis_id": analysis_id,
        "filename": f"{analysis_id}.exe",
        "sha256": "ab" * 32,
        "file_size": 1024,
        "status": status,
        "initial_verdict": verdict,
        "route": "DEEP_ANALYSIS" if verdict == "HIGH_RISK_UNCERTAIN" else "FINAL",
        "reason": "test",
        "final_verdict": {"AUTO_BENIGN": "BENIGN", "AUTO_MALICIOUS": "MALICIOUS"}.get(verdict),
        "final_assessment": None,
        "calibrated_probability": 0.5,
        "raw_probability": 0.5,
        "disagreement": 0.1,
        "ood_score": 0.2,
        "difficulty_score": 1.0,
        "top_features": [],
        "deep_analysis_status": dict.fromkeys(
            ("capa", "floss", "speakeasy"),
            "COMPLETED" if verdict == "HIGH_RISK_UNCERTAIN" else "NOT_REQUIRED",
        ),
        "analyst_final_verdict": analyst,
        "approval_status": approval,
        "review_revision": revision,
    }
    item.update(overrides)
    return item


# ---- 그룹 규칙 ---------------------------------------------------------------


@pytest.mark.parametrize(
    "verdict,analyst,revision,expected",
    [
        # 수정 전에는 시스템 초기 판정을 따른다
        ("HIGH_RISK_UNCERTAIN", None, 0, "needs_review"),
        ("AUTO_MALICIOUS", None, 0, "auto_malicious"),
        ("AUTO_BENIGN", None, 0, "auto_benign"),
        # 수정 후에는 분석가 판정을 따른다
        ("HIGH_RISK_UNCERTAIN", "MALICIOUS", 1, "auto_malicious"),
        ("AUTO_MALICIOUS", "BENIGN", 1, "auto_benign"),
        ("AUTO_BENIGN", "MALICIOUS", 2, "auto_malicious"),
        # 보류(null) 저장은 Needs Review 로 간다
        ("AUTO_BENIGN", None, 1, "needs_review"),
        ("AUTO_MALICIOUS", None, 3, "needs_review"),
    ],
)
def test_group_follows_analyst_verdict_once_reviewed(app, verdict, analyst, revision, expected):
    item = analysis(verdict=verdict, analyst=analyst, revision=revision)
    assert app.triage_group_key(item) == expected


def test_failed_analysis_stays_failed_even_with_review(app):
    item = analysis(status="FAILED", analyst="BENIGN", revision=1)
    assert app.triage_group_key(item) == "failed"


def test_group_counts_and_summary_move_with_the_review(app):
    analyses = [
        analysis("A1", "HIGH_RISK_UNCERTAIN", analyst="MALICIOUS", revision=1),
        analysis("A2", "AUTO_MALICIOUS"),
        analysis("A3", "AUTO_BENIGN", analyst=None, revision=1),
    ]
    groups = app.group_batch_analyses(analyses)
    assert [a["analysis_id"] for a in groups["needs_review"]] == ["A3"]
    assert [a["analysis_id"] for a in groups["auto_malicious"]] == ["A1", "A2"]
    assert groups["auto_benign"] == []

    summary = app.derive_batch_summary(analyses)
    assert summary["high_risk_uncertain"] == 1
    assert summary["auto_malicious"] == 2
    assert summary["auto_benign"] == 0


# ---- 표: 수정 여부 열과 NOT RUN -----------------------------------------------


@pytest.mark.parametrize(
    "item,expected",
    [
        (analysis(), "-"),
        (analysis(analyst="MALICIOUS", revision=1), "수정됨 · 원래 AUTO BENIGN"),
        (analysis("A1", "HIGH_RISK_UNCERTAIN", analyst="BENIGN", revision=1), "수정됨 · 원래 NEEDS REVIEW"),
        # 저장은 했지만 원래 그룹으로 돌아온 경우
        (analysis(analyst="BENIGN", revision=2), "확인됨"),
    ],
)
def test_review_mark(app, item, expected):
    assert app.review_mark(item) == expected


@pytest.mark.parametrize("group_key", ["needs_review", "auto_malicious", "auto_benign"])
def test_every_review_group_table_has_the_review_column(app, group_key):
    rows = app.batch_group_rows(group_key, [analysis(analyst="MALICIOUS", revision=1)])
    assert app.REVIEW_COLUMN in rows[0]
    assert rows[0][app.REVIEW_COLUMN] == "수정됨 · 원래 AUTO BENIGN"


def test_auto_verdict_moved_to_needs_review_shows_not_run(app):
    moved = analysis(verdict="AUTO_BENIGN", analyst=None, revision=1)
    assert app.deep_analysis_status_text(moved) == "NOT RUN"
    # 원래 검토 대상은 기존처럼 도구 상태를 요약한다
    assert app.deep_analysis_status_text(analysis(verdict="HIGH_RISK_UNCERTAIN")) == "COMPLETED"


# ---- 상세 화면: Final Verdict 배지와 버튼 상태 ----------------------------------


@pytest.mark.parametrize(
    "item,label,badge_text",
    [
        (analysis(), "Final Verdict", "정상 (Benign)"),
        (analysis(analyst="MALICIOUS", revision=1, approval="MODIFIED"), "Final Verdict · 수정됨", "악성 (Malicious)"),
        (analysis(analyst="BENIGN", revision=1, approval="APPROVED"), "Final Verdict · 분석가 승인", "정상 (Benign)"),
        (analysis(analyst=None, revision=1, approval="PENDING"), "Final Verdict · 분석가 보류", "판정 보류 (Uncertain)"),
    ],
)
def test_final_verdict_cell(app, item, label, badge_text):
    got_label, badge = app.final_verdict_cell(item)
    assert got_label == label
    assert badge_text in badge


@pytest.mark.parametrize(
    "item",
    [
        analysis(status="RUNNING"),
        analysis(status="FAILED"),
        analysis(verdict=None, status="COMPLETED"),
    ],
)
def test_review_is_blocked_for_unfinished_failed_or_ungrouped(app, item):
    assert app.review_blocker(item) is not None


def test_review_is_blocked_while_the_batch_is_still_polling(app):
    done, running = analysis("A1"), analysis("A2", status="RUNNING")
    app.st.session_state.batch_data = {"analyses": [done, running]}
    assert app.review_blocker(done) is not None
    app.st.session_state.batch_data = {"analyses": [done]}
    assert app.review_blocker(done) is None


def test_to_view_carries_review_fields(app):
    full = {
        "status": "COMPLETED",
        "analyst_final_verdict": "MALICIOUS",
        "approval_status": "MODIFIED",
        "review_revision": 2,
    }
    view = app.to_view(full, {"analysis_id": "A1"})
    assert view["analyst_final_verdict"] == "MALICIOUS"
    assert view["approval_status"] == "MODIFIED"
    assert view["review_revision"] == 2


def test_entry_view_starts_unreviewed(app):
    view = app.entry_view({"analysis_id": "A1"}, "QUEUED")
    assert view["review_revision"] == 0
    assert view["analyst_final_verdict"] is None


# ---- 저장 후 갱신 -------------------------------------------------------------


def test_refresh_updates_batch_and_detail_but_keeps_loaded_details(app, monkeypatch):
    item = analysis("A1", "HIGH_RISK_UNCERTAIN", capa={"capabilities": ["kept"]})
    app.st.session_state.batch_data = {"analyses": [item, analysis("A2")]}
    app.st.session_state.analysis_result = item
    monkeypatch.setattr(
        api_client,
        "get_result",
        lambda analysis_id: {
            "analysis_id": analysis_id,
            "analyst_final_verdict": "BENIGN",
            "approval_status": "MODIFIED",
            "review_revision": 1,
            "final_verdict": "UNCERTAIN",
            "final_assessment": None,
        },
    )

    updated = app.refresh_review_fields("A1")

    assert updated["review_revision"] == 1
    assert updated["capa"] == {"capabilities": ["kept"]}
    stored = app.st.session_state.batch_data["analyses"][0]
    assert stored["analyst_final_verdict"] == "BENIGN"
    assert app.st.session_state.analysis_result["review_revision"] == 1
    assert app.st.session_state.batch_data["analyses"][1]["review_revision"] == 0


def test_history_rows_chain_previous_group_and_show_newest_first(app):
    items = [
        {"analyst_final_verdict": "MALICIOUS", "reviewer_id": "a", "analyst_notes": "", "reviewed_at": None},
        {"analyst_final_verdict": None, "reviewer_id": "b", "analyst_notes": "n", "reviewed_at": None},
    ]
    rows = app.review_history_rows(items, analysis(verdict="AUTO_BENIGN"))
    assert [row["Change"] for row in rows] == [
        "AUTO MALICIOUS → NEEDS REVIEW",
        "AUTO BENIGN → AUTO MALICIOUS",
    ]


# ---- 팝업 저장 흐름 -----------------------------------------------------------


@pytest.fixture
def dialog(app, monkeypatch):
    """팝업 위젯을 조종할 수 있게 하고, 호출 내용을 모아 돌려준다."""
    state = {"choice": "auto_malicious", "notes": "", "reviewer": "HongGildong", "click": True}
    seen = {"errors": [], "warnings": [], "buttons": [], "saves": [], "radio_keys": []}

    def radio(*args, **kwargs):
        seen["radio_keys"].append(kwargs.get("key"))
        return state["choice"]

    monkeypatch.setattr(app.st, "radio", radio, raising=False)
    monkeypatch.setattr(app.st, "text_area", lambda *a, **k: state["notes"], raising=False)
    monkeypatch.setattr(app.st, "text_input", lambda *a, **k: state["reviewer"], raising=False)
    monkeypatch.setattr(app.st, "error", lambda msg, *a, **k: seen["errors"].append(msg), raising=False)
    monkeypatch.setattr(app.st, "warning", lambda msg, *a, **k: seen["warnings"].append(msg), raising=False)

    def button(label, *args, **kwargs):
        seen["buttons"].append((label, kwargs))
        return state["click"] and not kwargs.get("disabled")

    monkeypatch.setattr(app.st, "button", button, raising=False)
    monkeypatch.setattr(api_client, "list_reviews", lambda analysis_id: {"items": []})
    monkeypatch.setattr(
        api_client,
        "get_result",
        lambda analysis_id: {"analyst_final_verdict": "MALICIOUS", "review_revision": 1},
    )

    def save(analysis_id, verdict, reviewer, expected_revision, notes=""):
        # 실제 PATCH 응답 형태: 저장된 판정과 새 revision 을 돌려준다
        seen["saves"].append((analysis_id, verdict, reviewer, expected_revision, notes))
        return {
            "analysis_id": analysis_id,
            "revision": expected_revision + 1,
            "analyst_final_verdict": verdict,
            "analyst_notes": notes,
            "reviewer_id": reviewer,
            "reviewed_at": "2026-10-05T00:00:00+00:00",
        }

    monkeypatch.setattr(api_client, "save_review", save)
    item = analysis("A1", "AUTO_BENIGN")
    app.st.session_state.batch_data = {"analyses": [item]}
    app.st.session_state.analysis_result = item
    return state, seen


def test_dialog_saves_mapped_verdict_and_reruns(app, dialog, rerun_signal):
    state, seen = dialog
    app.st.session_state.batch_group = "auto_benign"

    with pytest.raises(rerun_signal):
        app.review_dialog("A1")

    assert seen["saves"] == [("A1", "MALICIOUS", "HongGildong", 0, "")]
    assert app.st.session_state.reviewer_id == "HongGildong"
    # 특정 그룹을 보고 있었으면 옮겨 간 그룹으로 따라간다
    assert app.st.session_state.pending_batch_group == "auto_malicious"
    assert app.st.session_state.analysis_result["review_revision"] == 1


def test_dialog_sends_the_current_revision(app, dialog, rerun_signal):
    """이미 수정된 건은 화면이 들고 있는 review_revision 을 그대로 보내야 409가 나지 않는다."""
    state, seen = dialog
    item = analysis("A1", "AUTO_BENIGN", analyst="MALICIOUS", revision=2, approval="MODIFIED")
    app.st.session_state.batch_data = {"analyses": [item]}
    app.st.session_state.analysis_result = item
    state["choice"] = "needs_review"

    with pytest.raises(rerun_signal):
        app.review_dialog("A1")

    assert seen["saves"] == [("A1", None, "HongGildong", 2, "")]


@pytest.mark.parametrize("notes", ["", "메모만 남기기"])
def test_dialog_disables_save_for_the_current_verdict(app, dialog, notes):
    state, seen = dialog
    state["choice"], state["notes"] = "auto_benign", notes

    app.review_dialog("A1")

    save_buttons = [kw for label, kw in seen["buttons"] if label == "저장"]
    assert save_buttons and save_buttons[0]["disabled"] is True
    assert seen["saves"] == []


def test_dialog_rejects_invalid_reviewer_without_calling_backend(app, dialog):
    state, seen = dialog
    state["reviewer"] = "홍길동"

    app.review_dialog("A1")

    assert seen["saves"] == []
    assert any("검토자명" in message for message in seen["errors"])


def test_save_keeps_patch_result_when_refetch_fails(app, dialog, monkeypatch, rerun_signal):
    """저장은 됐는데 재조회가 실패해도 화면은 서버에 저장된 판정·revision 을 보여야 한다.

    완료된 건은 폴링이 다시 조회하지 않으므로, 여기서 옛 값이 남으면 화면이 계속
    틀린 판정을 보여 주고 다음 저장은 자기 자신과 충돌(409)한다.
    """
    state, seen = dialog

    def unavailable(analysis_id):
        raise ApiError("SERVICE_UNAVAILABLE", "temporary", http_status=503)

    monkeypatch.setattr(api_client, "get_result", unavailable)

    with pytest.raises(rerun_signal):
        app.review_dialog("A1")

    for view in (app.st.session_state.analysis_result, app.st.session_state.batch_data["analyses"][0]):
        assert view["analyst_final_verdict"] == "MALICIOUS"
        assert view["review_revision"] == 1
        assert view["approval_status"] == "MODIFIED"
        assert app.triage_group_key(view) == "auto_malicious"
    assert "저장했습니다" in app.st.session_state.review_notice


def test_dialog_conflict_redraws_with_latest_verdict(app, dialog, monkeypatch, rerun_signal):
    """충돌하면 최신 판정을 받아 와서 팝업을 다시 그리고, 이전 선택은 버린다.

    다시 그리지 않으면 화면에는 이전 판정이 남은 채 revision 만 새 값이 되어,
    한 번 더 저장하면 다른 검토자의 변경을 확인 없이 덮어쓴다.
    """
    state, seen = dialog

    def conflict(*args, **kwargs):
        raise ApiError("REVIEW_CONFLICT", "conflict", http_status=409)

    monkeypatch.setattr(api_client, "save_review", conflict)
    monkeypatch.setattr(
        api_client,
        "list_reviews",
        lambda analysis_id: {"items": [{"reviewer_id": "OtherAnalyst", "analyst_final_verdict": "MALICIOUS"}]},
    )

    with pytest.raises(rerun_signal):
        app.review_dialog("A1")

    assert app.st.session_state.analysis_result["review_revision"] == 1
    assert "OtherAnalyst" in app.st.session_state.review_conflict["A1"]

    # 다시 그린 팝업: 경고가 보이고, 선택 위젯은 최신 revision 의 새 위젯이며,
    # 최신 판정(AUTO MALICIOUS)과 같은 선택이면 저장할 수 없다.
    seen["buttons"].clear()
    app.review_dialog("A1")

    assert any("먼저 수정되었습니다" in message for message in seen["warnings"])
    assert seen["radio_keys"][0] != seen["radio_keys"][-1]
    assert seen["radio_keys"][-1].endswith("_1")
    save_buttons = [kw for label, kw in seen["buttons"] if label == "저장"]
    assert save_buttons[-1]["disabled"] is True
    assert seen["saves"] == []


def test_opening_dialog_refreshes_review_state_once(app, monkeypatch):
    """완료된 건은 자동 재조회가 없으므로, 팝업을 여는 순간 최신 판정을 한 번 받아 온다.

    그러지 않으면 '현재 판정'은 옛 값인데 수정 이력(매번 서버 조회)에는 다른 검토자의
    새 저장이 보여 서로 어긋난다.
    """
    item = analysis("A1", "AUTO_BENIGN")
    app.st.session_state.batch_data = {"analyses": [item]}
    app.st.session_state.analysis_result = item
    app.st.session_state.review_conflict = {"A1": "stale warning"}
    seen = {}
    monkeypatch.setattr(
        api_client,
        "get_result",
        lambda analysis_id: {"analyst_final_verdict": "MALICIOUS", "review_revision": 3,
                             "approval_status": "MODIFIED", "final_verdict": "BENIGN"},
    )
    monkeypatch.setattr(app, "review_dialog", lambda analysis_id: seen.setdefault("opened", app.review_target(analysis_id)))

    app.open_review_dialog("A1")

    opened = seen["opened"]
    assert opened["review_revision"] == 3
    assert app.triage_group_key(opened) == "auto_malicious"
    assert app.st.session_state.batch_data["analyses"][0]["review_revision"] == 3
    # 이전에 열었을 때의 충돌 안내는 새로 열면 지운다
    assert "A1" not in app.st.session_state.review_conflict


def test_opening_dialog_still_works_when_refresh_fails(app, monkeypatch):
    item = analysis("A1", "AUTO_BENIGN")
    app.st.session_state.analysis_result = item
    opened = []

    def unavailable(analysis_id):
        raise ApiError("SERVICE_UNAVAILABLE", "temporary", http_status=503)

    monkeypatch.setattr(api_client, "get_result", unavailable)
    monkeypatch.setattr(app, "review_dialog", opened.append)

    app.open_review_dialog("A1")

    assert opened == ["A1"]
    assert app.st.session_state.analysis_result["review_revision"] == 0


# ---- api_client ----------------------------------------------------------------


class _Response:
    status_code = 200

    def json(self):
        return {"ok": True}


@pytest.mark.parametrize("token,expected_key", [("", None), ("reviewer-secret", "reviewer-secret")])
def test_save_review_request(monkeypatch, token, expected_key):
    calls = []
    monkeypatch.setattr(api_client, "REVIEWER_TOKEN", token)
    monkeypatch.setattr(
        api_client.requests,
        "request",
        lambda method, url, **kwargs: calls.append((method, url, kwargs)) or _Response(),
    )

    api_client.save_review("A1", None, "HongGildong", 3, "memo")

    method, url, kwargs = calls[0]
    assert method == "PATCH"
    assert url.endswith("/analyses/A1/verdict")
    assert kwargs["json"] == {
        "analyst_final_verdict": None,
        "analyst_notes": "memo",
        "reviewer_id": "HongGildong",
        "expected_revision": 3,
    }
    assert kwargs["headers"].get("X-Reviewer-Key") == expected_key


def test_list_reviews_request(monkeypatch):
    calls = []
    monkeypatch.setattr(
        api_client.requests,
        "request",
        lambda method, url, **kwargs: calls.append((method, url)) or _Response(),
    )
    api_client.list_reviews("A1")
    assert calls == [("GET", f"{api_client.BASE_URL}/analyses/A1/reviews")]
