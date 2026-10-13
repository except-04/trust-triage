"""분석가 판정 수정 (PATCH /analyses/{id}/verdict).

백엔드는 initial_verdict / final_verdict 를 바꾸지 않고 analyst_final_verdict 와
review_revision 만 갱신한다. 그래서 그룹 이동, 표의 수정 여부 열, Final Verdict
배지는 전부 프론트가 이 두 값으로 정한다. 그 규칙과 팝업의 저장 흐름을 본다.
"""

from __future__ import annotations

import api_client
import pytest
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
        "final_verdict": {"AUTO_BENIGN": "BENIGN", "AUTO_MALICIOUS": "MALICIOUS"}.get(
            verdict
        ),
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
        # 완료된 최종 판정이 없는 이전 결과는 초기 경로로 보완한다
        ("HIGH_RISK_UNCERTAIN", None, 0, "inconclusive"),
        ("AUTO_MALICIOUS", None, 0, "auto_malicious"),
        ("AUTO_BENIGN", None, 0, "auto_benign"),
        # 수정 후에는 분석가 판정을 따른다
        ("HIGH_RISK_UNCERTAIN", "MALICIOUS", 1, "auto_malicious"),
        ("AUTO_MALICIOUS", "BENIGN", 1, "auto_benign"),
        ("AUTO_BENIGN", "MALICIOUS", 2, "auto_malicious"),
        # 보류(null) 저장은 시스템 판정을 유지한다
        ("AUTO_BENIGN", None, 1, "auto_benign"),
        ("AUTO_MALICIOUS", None, 3, "auto_malicious"),
    ],
)
def test_group_follows_analyst_verdict_once_reviewed(
    app, verdict, analyst, revision, expected
):
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
    assert groups["needs_review"] == []
    assert [a["analysis_id"] for a in groups["auto_malicious"]] == ["A1", "A2"]
    assert [a["analysis_id"] for a in groups["auto_benign"]] == ["A3"]

    summary = app.derive_batch_summary(analyses)
    assert summary["high_risk_uncertain"] == 0
    assert summary["auto_malicious"] == 2
    assert summary["auto_benign"] == 1


# ---- 표: 수정 여부 열과 NOT RUN -----------------------------------------------


@pytest.mark.parametrize(
    "item,expected",
    [
        (analysis(), "-"),
        (analysis(analyst="MALICIOUS", revision=1), "수정됨 · 원래 BENIGN"),
        (
            analysis("A1", "HIGH_RISK_UNCERTAIN", analyst="BENIGN", revision=1),
            "수정됨 · 원래 INCONCLUSIVE",
        ),
        # 저장은 했지만 원래 그룹으로 돌아온 경우
        (analysis(analyst="BENIGN", revision=2), "확인됨"),
    ],
)
def test_review_mark(app, item, expected):
    assert app.review_mark(item) == expected


@pytest.mark.parametrize(
    "group_key", ["needs_review", "inconclusive", "auto_malicious", "auto_benign"]
)
def test_every_review_group_table_has_the_review_column(app, group_key):
    rows = app.batch_group_rows(group_key, [analysis(analyst="MALICIOUS", revision=1)])
    assert app.REVIEW_COLUMN in rows[0]
    assert rows[0][app.REVIEW_COLUMN] == "수정됨 · 원래 BENIGN"


def test_held_auto_verdict_keeps_deep_analysis_not_run(app):
    moved = analysis(verdict="AUTO_BENIGN", analyst=None, revision=1)
    assert app.deep_analysis_status_text(moved) == "NOT RUN"
    # 원래 검토 대상은 기존처럼 도구 상태를 요약한다
    assert (
        app.deep_analysis_status_text(analysis(verdict="HIGH_RISK_UNCERTAIN"))
        == "COMPLETED"
    )


# ---- 상세 화면: Final Verdict 배지와 버튼 상태 ----------------------------------


@pytest.mark.parametrize(
    "item,label,badge_text",
    [
        (analysis(), "Final Verdict", "BENIGN"),
        (
            analysis(analyst="MALICIOUS", revision=1, approval="MODIFIED"),
            "Final Verdict · 수정됨",
            "MALICIOUS",
        ),
        (
            analysis(analyst="BENIGN", revision=1, approval="APPROVED"),
            "Final Verdict · 분석가 승인",
            "BENIGN",
        ),
        (
            analysis(analyst=None, revision=1, approval="PENDING"),
            "Final Verdict · REVIEW PENDING",
            "BENIGN",
        ),
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
        {
            "analyst_final_verdict": "MALICIOUS",
            "reviewer_id": "a",
            "analyst_notes": "",
            "reviewed_at": None,
        },
        {
            "analyst_final_verdict": None,
            "reviewer_id": "b",
            "analyst_notes": "n",
            "reviewed_at": None,
        },
        {
            "analyst_final_verdict": "BENIGN",
            "reviewer_id": "c",
            "analyst_notes": "",
            "reviewed_at": None,
        },
    ]
    rows = app.review_history_rows(items, analysis(verdict="AUTO_BENIGN"))
    assert [row["Change"] for row in rows] == [
        "BENIGN → BENIGN",
        "MALICIOUS → REVIEW PENDING",
        "BENIGN → MALICIOUS",
    ]


# ---- 팝업 저장 흐름 -----------------------------------------------------------


@pytest.fixture
def dialog(app, monkeypatch):
    """팝업 위젯을 조종할 수 있게 하고, 호출 내용을 모아 돌려준다."""
    state = {
        "choice": "auto_malicious",
        "notes": "",
        "reviewer": "HongGildong",
        "click": True,
    }
    seen = {"errors": [], "warnings": [], "buttons": [], "saves": [], "radio_keys": []}

    def radio(*args, **kwargs):
        seen["radio_keys"].append(kwargs.get("key"))
        return state["choice"]

    monkeypatch.setattr(app.st, "radio", radio, raising=False)
    monkeypatch.setattr(
        app.st, "text_area", lambda *a, **k: state["notes"], raising=False
    )
    monkeypatch.setattr(
        app.st, "text_input", lambda *a, **k: state["reviewer"], raising=False
    )
    monkeypatch.setattr(
        app.st, "error", lambda msg, *a, **k: seen["errors"].append(msg), raising=False
    )
    monkeypatch.setattr(
        app.st,
        "warning",
        lambda msg, *a, **k: seen["warnings"].append(msg),
        raising=False,
    )

    def button(label, *args, **kwargs):
        seen["buttons"].append((label, kwargs))
        return state["click"] and not kwargs.get("disabled")

    monkeypatch.setattr(app.st, "button", button, raising=False)
    monkeypatch.setattr(api_client, "list_reviews", lambda analysis_id: {"items": []})
    monkeypatch.setattr(
        api_client,
        "get_result",
        lambda analysis_id: {
            "analyst_final_verdict": "MALICIOUS",
            "review_revision": 1,
        },
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
    item = analysis(
        "A1", "AUTO_BENIGN", analyst="MALICIOUS", revision=2, approval="MODIFIED"
    )
    app.st.session_state.batch_data = {"analyses": [item]}
    app.st.session_state.analysis_result = item
    state["choice"] = "needs_review"

    with pytest.raises(rerun_signal):
        app.review_dialog("A1")

    assert seen["saves"] == [("A1", None, "HongGildong", 2, "")]


@pytest.mark.parametrize("notes", ["", "메모만 남기기"])
def test_dialog_saves_the_current_verdict(app, dialog, notes, monkeypatch, rerun_signal):
    state, seen = dialog
    state["choice"], state["notes"] = "auto_benign", notes

    monkeypatch.setattr(
        api_client,
        "get_result",
        lambda analysis_id: {"analyst_final_verdict": "BENIGN", "review_revision": 1},
    )

    with pytest.raises(rerun_signal):
        app.review_dialog("A1")

    save_buttons = [kw for label, kw in seen["buttons"] if label == "저장"]
    assert save_buttons and not save_buttons[0].get("disabled", False)
    assert seen["saves"] == [("A1", "BENIGN", "HongGildong", 0, notes)]
    assert app.st.session_state.analysis_result["analyst_final_verdict"] == "BENIGN"
    assert app.st.session_state.analysis_result["review_revision"] == 1


@pytest.mark.parametrize("system_verdict", ["BENIGN", "MALICIOUS"])
def test_reopening_held_review_and_saving_notes_keeps_pending(
    app, dialog, monkeypatch, rerun_signal, system_verdict
):
    state, seen = dialog
    item = analysis(verdict=f"AUTO_{system_verdict}", revision=1, approval="PENDING")
    app.st.session_state.batch_data = {"analyses": [item]}
    app.st.session_state.analysis_result = item
    state["notes"] = "추가 확인 필요"
    monkeypatch.setattr(
        app.st, "radio", lambda *args, **kwargs: kwargs["options"][kwargs["index"]]
    )
    monkeypatch.setattr(
        api_client,
        "get_result",
        lambda analysis_id: {
            **item,
            "review_revision": 2 if seen["saves"] else 1,
        },
    )

    with pytest.raises(rerun_signal):
        app.open_review_dialog("A1")

    assert seen["saves"] == [("A1", None, "HongGildong", 1, "추가 확인 필요")]
    updated = app.st.session_state.analysis_result
    assert updated["analyst_final_verdict"] is None
    assert updated["approval_status"] == "PENDING"
    assert updated["review_revision"] == 2
    assert updated["final_verdict"] == system_verdict


def test_dialog_rejects_invalid_reviewer_without_calling_backend(app, dialog):
    state, seen = dialog
    state["reviewer"] = "홍길동"

    app.review_dialog("A1")

    assert seen["saves"] == []
    assert any("검토자명" in message for message in seen["errors"])


def test_save_keeps_patch_result_when_refetch_fails(
    app, dialog, monkeypatch, rerun_signal
):
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

    for view in (
        app.st.session_state.analysis_result,
        app.st.session_state.batch_data["analyses"][0],
    ):
        assert view["analyst_final_verdict"] == "MALICIOUS"
        assert view["review_revision"] == 1
        assert view["approval_status"] == "MODIFIED"
        assert app.triage_group_key(view) == "auto_malicious"
    assert "저장했습니다" in app.st.session_state.review_notice


def test_dialog_conflict_redraws_with_latest_verdict(
    app, dialog, monkeypatch, rerun_signal
):
    """충돌하면 최신 판정을 받아 와서 팝업을 다시 그리고, 이전 선택은 버린다.

    다시 그리지 않으면 화면에는 이전 판정이 남은 채 revision 만 새 값이 되어,
    한 번 더 저장하면 다른 검토자의 변경을 확인 없이 덮어쓴다.
    """
    state, seen = dialog

    def conflict(*args, **kwargs):
        raise ApiError("REVIEW_CONFLICT", "conflict", http_status=409)

    save_review = api_client.save_review
    monkeypatch.setattr(api_client, "save_review", conflict)
    monkeypatch.setattr(
        api_client,
        "list_reviews",
        lambda analysis_id: {
            "items": [
                {"reviewer_id": "OtherAnalyst", "analyst_final_verdict": "MALICIOUS"}
            ]
        },
    )

    with pytest.raises(rerun_signal):
        app.review_dialog("A1")

    assert app.st.session_state.analysis_result["review_revision"] == 1
    assert "OtherAnalyst" in app.st.session_state.review_conflict["A1"]

    # 다시 그린 팝업: 경고가 보이고, 선택 위젯은 최신 revision 의 새 위젯이며,
    # 사용자가 다시 누르기 전에는 저장하지 않으며 같은 판정도 저장 가능하다.
    seen["buttons"].clear()
    state["click"] = False
    app.review_dialog("A1")

    assert any("먼저 수정되었습니다" in message for message in seen["warnings"])
    assert seen["radio_keys"][0] != seen["radio_keys"][-1]
    assert seen["radio_keys"][-1].endswith("_1")
    save_buttons = [kw for label, kw in seen["buttons"] if label == "저장"]
    assert not save_buttons[-1].get("disabled", False)
    assert seen["saves"] == []

    # 최신 판정을 확인한 뒤 다시 저장하면 갱신된 revision을 사용한다.
    monkeypatch.setattr(api_client, "save_review", save_review)
    monkeypatch.setattr(
        api_client,
        "get_result",
        lambda analysis_id: {"analyst_final_verdict": "MALICIOUS", "review_revision": 2},
    )
    state["click"] = True
    with pytest.raises(rerun_signal):
        app.review_dialog("A1")

    assert seen["saves"] == [("A1", "MALICIOUS", "HongGildong", 1, "")]
    assert app.st.session_state.analysis_result["review_revision"] == 2
    assert "A1" not in app.st.session_state.review_conflict


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
        lambda analysis_id: {
            "analyst_final_verdict": "MALICIOUS",
            "review_revision": 3,
            "approval_status": "MODIFIED",
            "final_verdict": "BENIGN",
        },
    )
    monkeypatch.setattr(
        app,
        "review_dialog",
        lambda analysis_id: seen.setdefault("opened", app.review_target(analysis_id)),
    )

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


@pytest.mark.parametrize(
    "token,expected_key", [("", None), ("reviewer-secret", "reviewer-secret")]
)
def test_save_review_request(monkeypatch, token, expected_key):
    calls = []
    monkeypatch.setattr(api_client, "REVIEWER_TOKEN", token)
    monkeypatch.setattr(
        api_client.requests,
        "request",
        lambda method, url, **kwargs: (
            calls.append((method, url, kwargs)) or _Response()
        ),
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


def test_search_analyses_reviewed_only(monkeypatch):
    calls = []
    monkeypatch.setattr(
        api_client.requests,
        "request",
        lambda method, url, **kwargs: (
            calls.append((method, url, kwargs)) or _Response()
        ),
    )
    api_client.search_analyses(reviewed_only=True)
    assert len(calls) == 1
    method, url, kwargs = calls[0]
    assert method == "GET"
    assert url.endswith("/analyses")
    assert kwargs["params"]["reviewed_only"] is True


def test_format_deep_queue_item_preserves_evidence(app):
    item = {
        "analysis_id": "A1",
        "filename": "malware.exe",
        "queue_name": "EMERGENCY",
        "queue_reason": "CAPA: 데이터 파괴 (정적 규칙 일치)",
        "triggered_signals": ["UNCERTAIN_PROBABILITY"],
        "calibrated_probability": 0.52,
    }
    formatted = app.format_deep_queue_item(item)
    assert formatted["queue_name"] == "DEEP"
    assert formatted["queue_reason"] == "CAPA: 데이터 파괴 (정적 규칙 일치)"
    assert formatted["priority_reason"] == "확률 불확실성"
    assert formatted["score_policy"] == "uncertainty-v2"
    assert abs(formatted["priority_score"] - (1.0 - 2.0 * abs(0.52 - 0.5))) < 1e-6


def test_sort_deep_queue_items_by_four_signals(app):
    items = [
        {
            "analysis_id": "D1",
            "score_policy": "difficulty-v2",
            "priority_score": 10.0,
            "created_at": "2026-10-12T10:00:00",
        },
        {
            "analysis_id": "U1",
            "score_policy": "uncertainty-v2",
            "priority_score": 0.8,
            "created_at": "2026-10-12T10:00:00",
        },
        {
            "analysis_id": "U2",
            "score_policy": "uncertainty-v2",
            "priority_score": 0.95,
            "created_at": "2026-10-12T10:00:00",
        },
        {
            "analysis_id": "DIS1",
            "score_policy": "disagreement-v2",
            "priority_score": 0.4,
            "created_at": "2026-10-12T10:00:00",
        },
        {
            "analysis_id": "OOD1",
            "score_policy": "ood-v2",
            "priority_score": 0.3,
            "created_at": "2026-10-12T10:00:00",
        },
        {
            "analysis_id": "EX1",
            "score_policy": "exception-v2",
            "priority_score": 0.0,
            "created_at": "2026-10-12T10:00:00",
        },
    ]
    sorted_items = app.sort_deep_queue_items(items)
    expected_order = ["U2", "U1", "DIS1", "OOD1", "D1", "EX1"]
    assert [x["analysis_id"] for x in sorted_items] == expected_order
    assert [x["rank"] for x in sorted_items] == [1, 2, 3, 4, 5, 6]


def test_format_deep_queue_item_uses_actual_risk_signal_score(app):
    # EMERGENCY에서 DEEP으로 통합 시, 단순 악성 확률(0.85)이 아니라 실제 위험 신호 점수(0.35)가 반영되는지 검증
    dis_item = {
        "analysis_id": "DIS_EM",
        "queue_name": "EMERGENCY",
        "queue_reason": "CAPA: 데이터 파괴 (정적 규칙 일치)",
        "triggered_signals": ["DISAGREEMENT"],
        "calibrated_probability": 0.85,
        "priority_score": 0.85,  # 백엔드가 EMERGENCY에 부여했던 악성 확률
        "deep_priority_score": 0.35,  # 모델 불일치 실제 신호 강도
    }
    formatted = app.format_deep_queue_item(dis_item)
    assert formatted["score_policy"] == "disagreement-v2"
    assert formatted["priority_score"] == 0.35  # 악성 확률이 아닌 실제 불일치 점수

    ood_item = {
        "analysis_id": "OOD_EM",
        "queue_name": "EMERGENCY",
        "queue_reason": "SPEAKEASY: 랜섬웨어 암호화 (동적 관측)",
        "triggered_signals": ["OOD"],
        "calibrated_probability": 0.90,
        "priority_score": 0.90,
        "deep_priority_score": 0.65,
    }
    formatted_ood = app.format_deep_queue_item(ood_item)
    assert formatted_ood["score_policy"] == "ood-v2"
    assert formatted_ood["priority_score"] == 0.65


def test_sort_deep_queue_items_fifo_on_tie(app):
    # 점수가 같을 때 파일 생성 시각 기준 오래된 파일 순(FIFO)으로 정렬되는지 검증
    items = [
        {
            "analysis_id": "NEW",
            "score_policy": "disagreement-v2",
            "priority_score": 0.5,
            "created_at": "2026-10-12T11:00:00Z",
        },
        {
            "analysis_id": "OLD",
            "score_policy": "disagreement-v2",
            "priority_score": 0.5,
            "created_at": "2026-10-12T09:00:00Z",
        },
    ]
    sorted_items = app.sort_deep_queue_items(items)
    assert [x["analysis_id"] for x in sorted_items] == ["OLD", "NEW"]
    assert [x["rank"] for x in sorted_items] == [1, 2]


def test_backend_output_to_frontend_conversion_regression(app):
    """백엔드 산출값(AUTO_MALICIOUS, prob=0.99, triggered_signals=[], CAPA OBSERVED T1485)이
    프론트엔드 format_deep_queue_item 변환 시 exception-v2 및 priority_score=0.0으로
    올바르게 처리되는지 검증하는 회귀 테스트."""
    from tests.backend_api.fake_repository import MemoryAnalysisRepository
    from trust_triage.backend_api.repository import AnalysisRecord

    repo = MemoryAnalysisRepository()
    record = AnalysisRecord(
        analysis_id="cand-auto-em",
        sha256="4" * 64,
        file_location="loc-em",
        filename="wiper.exe",
        size_bytes=2048,
        initial_result={
            "initial_verdict": "AUTO_MALICIOUS",
            "prediction": {"calibrated_probability": 0.99},
            "triggered_signals": [],
            "risk_signals": {},
        },
        deep_result={
            "evidence": [
                {
                    "source": "CAPA",
                    "status": "OBSERVED",
                    "attack_techniques": [
                        {"technique_id": "T1485", "technique_name": "Data Destruction"}
                    ],
                }
            ]
        },
        created_at="2026-10-12T10:00:00Z",
    )
    repo.rows["cand-auto-em"] = record
    recs = repo.get_priority_recommendations()
    em_cand = next(c for c in recs if c["analysis_id"] == "cand-auto-em")

    # 1. 백엔드 산출값 검증
    assert em_cand["queue_name"] == "EMERGENCY"
    assert em_cand["score_policy"] == "emergency-v1"
    assert em_cand["priority_score"] == 0.99
    assert em_cand["deep_priority_score"] == 0.0  # 4대 위험 신호가 없으므로 0.0
    assert "CAPA: 데이터 파괴" in em_cand["queue_reason"]

    # 2. 프론트엔드 변환 검증 (EMERGENCY -> DEEP, 긴급 대응 최우선 정책 유지)
    formatted = app.format_deep_queue_item(em_cand)
    assert formatted["queue_name"] == "DEEP"
    assert formatted["score_policy"] == "emergency-v1"
    assert formatted["priority_reason"] == em_cand["priority_reason"]
    assert formatted["priority_score"] == 0.99
    assert formatted["queue_reason"] == em_cand["queue_reason"]  # 고위험 Evidence 보존

    # 3. 정렬 시 일반 위험 신호(확률 불확실성 등)보다 긴급 대응이 최우선(0순위) 배치 검증
    u_item = {
        "analysis_id": "U_NON_EM",
        "score_policy": "uncertainty-v2",
        "priority_score": 0.95,
        "created_at": "2026-10-12T08:00:00Z",
    }
    sorted_items = app.sort_deep_queue_items([u_item, formatted])
    assert sorted_items[0]["analysis_id"] == "cand-auto-em"
    assert sorted_items[1]["analysis_id"] == "U_NON_EM"


def test_exception_items_fifo_ordering(app):
    """예외 정책(exception-v2) 항목 간에는 생성 시각 기준 FIFO 정렬이 유지되는지 검증."""
    # EX_OLD: 09:00 생성
    item_old = {
        "analysis_id": "EX_OLD",
        "queue_name": "DEEP",
        "score_policy": "exception-v2",
        "priority_reason": "신호 미감지",
        "priority_score": 0.0,
        "calibrated_probability": 0.70,
        "created_at": "2026-10-12T09:00:00Z",
    }
    # EX_NEW: 11:00 생성
    item_new = {
        "analysis_id": "EX_NEW",
        "queue_name": "DEEP",
        "score_policy": "exception-v2",
        "priority_reason": "신호 미감지",
        "priority_score": 0.0,
        "calibrated_probability": 0.90,
        "created_at": "2026-10-12T11:00:00Z",
    }
    # 정렬 시 생성 시각이 빠른 EX_OLD가 1위, EX_NEW가 2위여야 함 (FIFO 보장)
    sorted_items = app.sort_deep_queue_items([item_new, item_old])
    assert [x["analysis_id"] for x in sorted_items] == ["EX_OLD", "EX_NEW"]
    assert [x["rank"] for x in sorted_items] == [1, 2]


def test_emergency_items_top_priority_over_all_risk_signals(app):
    """긴급 대응 건(EMERGENCY)이 4대 일반 위험 신호 항목들보다 최우선(0순위)으로 정렬되는지 검증."""
    em_item = {
        "analysis_id": "EM1",
        "queue_name": "EMERGENCY",
        "queue_reason": "CAPA: 데이터 파괴 (정적 규칙 일치)",
        "triggered_signals": [],
        "calibrated_probability": 0.99,
        "priority_score": 0.99,
        "created_at": "2026-10-12T12:00:00Z",
    }
    em_formatted = app.format_deep_queue_item(em_item)

    u_item = {
        "analysis_id": "U1",
        "score_policy": "uncertainty-v2",
        "priority_score": 0.99,
        "created_at": "2026-10-12T08:00:00Z",
    }
    dis_item = {
        "analysis_id": "DIS1",
        "score_policy": "disagreement-v2",
        "priority_score": 0.50,
        "created_at": "2026-10-12T08:00:00Z",
    }
    ex_item = {
        "analysis_id": "EX1",
        "score_policy": "exception-v2",
        "priority_score": 0.0,
        "created_at": "2026-10-12T08:00:00Z",
    }

    # U1, DIS1, EX1이 더 먼저 생성되었더라도 긴급 건(EM1)이 최상단(1위)에 위치해야 함
    sorted_items = app.sort_deep_queue_items([ex_item, dis_item, u_item, em_formatted])
    assert [x["analysis_id"] for x in sorted_items] == ["EM1", "U1", "DIS1", "EX1"]
    assert [x["rank"] for x in sorted_items] == [1, 2, 3, 4]


def test_emergency_items_severity_level_ordering(app):
    """긴급 항목 간 위험도(emergency_level) 정렬 검증:
    데이터 파괴(T1485, 레벨 1, 확률 0.70)가 서비스 중단(T1489, 레벨 2, 확률 0.99)보다
    악성 확률이 낮더라도 우선순위가 높아야 한다."""
    t1485_item = {
        "analysis_id": "EM_DESTRUCT_T1485",
        "queue_name": "EMERGENCY",
        "queue_reason": "CAPA: 데이터 파괴 (T1485)",
        "emergency_level": 1,
        "emergency_obs_level": 2,
        "calibrated_probability": 0.70,
        "priority_score": 0.70,
        "created_at": "2026-10-12T10:00:00Z",
    }
    t1489_item = {
        "analysis_id": "EM_STOP_T1489",
        "queue_name": "EMERGENCY",
        "queue_reason": "CAPA: 서비스 중단 (T1489)",
        "emergency_level": 2,
        "emergency_obs_level": 2,
        "calibrated_probability": 0.99,
        "priority_score": 0.99,
        "created_at": "2026-10-12T10:00:00Z",
    }

    # 1. format_deep_queue_item 후 정렬 검증
    formatted_1485 = app.format_deep_queue_item(t1485_item)
    formatted_1489 = app.format_deep_queue_item(t1489_item)
    sorted_items = app.sort_deep_queue_items([formatted_1489, formatted_1485])

    assert sorted_items[0]["analysis_id"] == "EM_DESTRUCT_T1485"
    assert sorted_items[1]["analysis_id"] == "EM_STOP_T1489"
    assert [x["rank"] for x in sorted_items] == [1, 2]

    # 2. emergency_level이 누락된 raw item이라도 queue_reason 기반 폴백 추론으로 순서 유지
    raw_1485 = {
        "analysis_id": "RAW_T1485",
        "queue_name": "EMERGENCY",
        "queue_reason": "CAPA: 데이터 파괴 (T1485)",
        "priority_score": 0.70,
        "created_at": "2026-10-12T10:00:00Z",
    }
    raw_1489 = {
        "analysis_id": "RAW_T1489",
        "queue_name": "EMERGENCY",
        "queue_reason": "CAPA: 서비스 중단 (T1489)",
        "priority_score": 0.99,
        "created_at": "2026-10-12T10:00:00Z",
    }
    sorted_raw = app.sort_deep_queue_items([raw_1489, raw_1485])
    assert sorted_raw[0]["analysis_id"] == "RAW_T1485"
    assert sorted_raw[1]["analysis_id"] == "RAW_T1489"


def test_emergency_items_observation_level_ordering(app):
    """긴급 항목 간 동일 위험도일 때 관측 수준(emergency_obs_level) 정렬 검증:
    Speakeasy 동적 관측(obs_level 1, 확률 0.70)이 CAPA 정적 규칙(obs_level 2, 확률 0.99)보다
    악성 확률이 낮더라도 우선순위가 높아야 한다."""
    dynamic_item = {
        "analysis_id": "EM_SPEAKEASY_DYN",
        "queue_name": "EMERGENCY",
        "queue_reason": "SPEAKEASY: 랜섬웨어 암호화 (T1486)",
        "emergency_level": 1,
        "emergency_obs_level": 1,
        "calibrated_probability": 0.70,
        "priority_score": 0.70,
        "created_at": "2026-10-12T10:00:00Z",
    }
    static_item = {
        "analysis_id": "EM_CAPA_STATIC",
        "queue_name": "EMERGENCY",
        "queue_reason": "CAPA: 랜섬웨어 암호화 (T1486)",
        "emergency_level": 1,
        "emergency_obs_level": 2,
        "calibrated_probability": 0.99,
        "priority_score": 0.99,
        "created_at": "2026-10-12T10:00:00Z",
    }

    sorted_items = app.sort_deep_queue_items([static_item, dynamic_item])
    assert sorted_items[0]["analysis_id"] == "EM_SPEAKEASY_DYN"
    assert sorted_items[1]["analysis_id"] == "EM_CAPA_STATIC"


def test_emergency_end_to_end_severity_ordering(app):
    """백엔드 레포지토리부터 프론트엔드 포맷 및 정렬까지 End-to-End 검증:
    T1485(레벨 1, prob=0.70) vs T1489(레벨 2, prob=0.99) 조합에서
    백엔드 추천과 프론트엔드 심층 분석 큐 정렬 모두 T1485가 1위를 유지해야 함."""
    from tests.backend_api.fake_repository import MemoryAnalysisRepository
    from trust_triage.backend_api.repository import AnalysisRecord

    repo = MemoryAnalysisRepository()
    # T1489 (서비스 중단, 위험도 2, 높은 악성 확률 0.99)
    repo.rows["cand-t1489"] = AnalysisRecord(
        analysis_id="cand-t1489",
        sha256="8" * 64,
        file_location="loc-8",
        filename="service_stop.exe",
        size_bytes=1024,
        initial_result={
            "initial_verdict": "AUTO_MALICIOUS",
            "prediction": {"calibrated_probability": 0.99},
            "triggered_signals": [],
            "risk_signals": {},
        },
        deep_result={
            "evidence": [
                {
                    "source": "CAPA",
                    "status": "OBSERVED",
                    "attack_techniques": [
                        {"technique_id": "T1489", "technique_name": "Service Stop"}
                    ],
                }
            ]
        },
        created_at="2026-10-12T10:00:00Z",
    )
    # T1485 (데이터 파괴, 위험도 1, 상대적으로 낮은 악성 확률 0.70)
    repo.rows["cand-t1485"] = AnalysisRecord(
        analysis_id="cand-t1485",
        sha256="5" * 64,
        file_location="loc-5",
        filename="data_destruct.exe",
        size_bytes=1024,
        initial_result={
            "initial_verdict": "AUTO_MALICIOUS",
            "prediction": {"calibrated_probability": 0.70},
            "triggered_signals": [],
            "risk_signals": {},
        },
        deep_result={
            "evidence": [
                {
                    "source": "CAPA",
                    "status": "OBSERVED",
                    "attack_techniques": [
                        {"technique_id": "T1485", "technique_name": "Data Destruction"}
                    ],
                }
            ]
        },
        created_at="2026-10-12T10:00:00Z",
    )

    # 1. 백엔드 추천 목록 정렬 검증
    recs = repo.get_priority_recommendations()
    em_recs = [c for c in recs if c["queue_name"] == "EMERGENCY"]
    assert em_recs[0]["analysis_id"] == "cand-t1485"
    assert em_recs[0]["emergency_level"] == 1
    assert em_recs[1]["analysis_id"] == "cand-t1489"
    assert em_recs[1]["emergency_level"] == 2

    # 2. 프론트엔드 포맷 및 DEEP 큐 정렬 검증
    formatted_items = [app.format_deep_queue_item(c) for c in em_recs]
    sorted_frontend = app.sort_deep_queue_items(formatted_items)
    assert sorted_frontend[0]["analysis_id"] == "cand-t1485"
    assert sorted_frontend[1]["analysis_id"] == "cand-t1489"
    assert sorted_frontend[0]["rank"] == 1
    assert sorted_frontend[1]["rank"] == 2


def test_emergency_items_with_different_risk_signals_sorted_by_calibrated_probability(app):
    """같은 위험도·관측 수준에서 서로 다른 위험 신호가 있더라도,
    format_deep_queue_item에 의해 priority_score가 신호 점수로 바뀌었을 때
    sort_deep_queue_items는 악성 확률(calibrated_probability) 내림차순으로 정렬하는지 검증."""
    # Item A: 불일치 신호(deep_priority_score=0.90), 악성 확률 0.70
    item_a = {
        "analysis_id": "EM_DISAGREE_LOW_PROB",
        "queue_name": "EMERGENCY",
        "queue_reason": "SPEAKEASY: 데이터 파괴 (T1485)",
        "emergency_level": 1,
        "emergency_obs_level": 1,
        "triggered_signals": ["DISAGREEMENT"],
        "calibrated_probability": 0.70,
        "priority_score": 0.70,
        "deep_priority_score": 0.90,
        "created_at": "2026-10-12T10:00:00Z",
    }
    # Item B: 불확실성 신호(deep_priority_score=0.10), 악성 확률 0.95
    item_b = {
        "analysis_id": "EM_UNCERTAIN_HIGH_PROB",
        "queue_name": "EMERGENCY",
        "queue_reason": "SPEAKEASY: 랜섬웨어 암호화 (T1486)",
        "emergency_level": 1,
        "emergency_obs_level": 1,
        "triggered_signals": ["UNCERTAIN_PROBABILITY"],
        "calibrated_probability": 0.95,
        "priority_score": 0.95,
        "deep_priority_score": 0.10,
        "created_at": "2026-10-12T10:00:00Z",
    }

    formatted_a = app.format_deep_queue_item(item_a)
    formatted_b = app.format_deep_queue_item(item_b)

    # format 후 priority_score는 각각 0.90과 0.10으로 위험 신호 점수가 반영됨
    assert formatted_a["priority_score"] == 0.90
    assert formatted_b["priority_score"] == 0.10

    # 하지만 긴급 항목 정렬 시에는 신호 점수가 아니라 calibrated_probability(0.95 > 0.70)를 기준으로 Item B가 1위여야 함
    sorted_items = app.sort_deep_queue_items([formatted_a, formatted_b])
    assert sorted_items[0]["analysis_id"] == "EM_UNCERTAIN_HIGH_PROB"
    assert sorted_items[1]["analysis_id"] == "EM_DISAGREE_LOW_PROB"
    assert sorted_items[0]["rank"] == 1
    assert sorted_items[1]["rank"] == 2


def test_emergency_items_fifo_on_calibrated_probability_tie(app):
    """같은 위험도·관측 수준·악성 확률일 때 created_at 오름차순(FIFO) 및 analysis_id 순서 고정 검증."""
    item_old = {
        "analysis_id": "EM_TIE_OLD",
        "queue_name": "EMERGENCY",
        "queue_reason": "CAPA: 데이터 파괴 (T1485)",
        "emergency_level": 1,
        "emergency_obs_level": 2,
        "calibrated_probability": 0.85,
        "created_at": "2026-10-12T08:00:00Z",
    }
    item_new = {
        "analysis_id": "EM_TIE_NEW",
        "queue_name": "EMERGENCY",
        "queue_reason": "CAPA: 데이터 파괴 (T1485)",
        "emergency_level": 1,
        "emergency_obs_level": 2,
        "calibrated_probability": 0.85,
        "created_at": "2026-10-12T12:00:00Z",
    }
    # 같은 시각 동점 시 analysis_id 알파벳 순 (A1 vs B1)
    item_id_a = {
        "analysis_id": "EM_TIE_A1",
        "queue_name": "EMERGENCY",
        "queue_reason": "CAPA: 데이터 파괴 (T1485)",
        "emergency_level": 1,
        "emergency_obs_level": 2,
        "calibrated_probability": 0.85,
        "created_at": "2026-10-12T12:00:00Z",
    }

    sorted_items = app.sort_deep_queue_items([item_new, item_id_a, item_old])
    # 08:00(OLD)이 1위, 12:00 동점 중에는 ID 순으로 EM_TIE_A1이 2위, EM_TIE_NEW가 3위
    assert [x["analysis_id"] for x in sorted_items] == ["EM_TIE_OLD", "EM_TIE_A1", "EM_TIE_NEW"]
    assert [x["rank"] for x in sorted_items] == [1, 2, 3]


def test_emergency_items_missing_or_invalid_probability_sorted_to_back(app):
    """악성 확률이 누락되거나 유효하지 않은 항목은 같은 위험도·관측 수준에서 뒤로 가는지 검증."""
    item_valid = {
        "analysis_id": "EM_VALID_PROB",
        "queue_name": "EMERGENCY",
        "queue_reason": "CAPA: 데이터 파괴 (T1485)",
        "emergency_level": 1,
        "emergency_obs_level": 2,
        "calibrated_probability": 0.50,
        "created_at": "2026-10-12T10:00:00Z",
    }
    item_missing = {
        "analysis_id": "EM_MISSING_PROB",
        "queue_name": "EMERGENCY",
        "queue_reason": "CAPA: 데이터 파괴 (T1485)",
        "emergency_level": 1,
        "emergency_obs_level": 2,
        "calibrated_probability": None,
        "created_at": "2026-10-12T09:00:00Z",
    }
    item_invalid = {
        "analysis_id": "EM_INVALID_PROB",
        "queue_name": "EMERGENCY",
        "queue_reason": "CAPA: 데이터 파괴 (T1485)",
        "emergency_level": 1,
        "emergency_obs_level": 2,
        "calibrated_probability": "not_a_number",
        "created_at": "2026-10-12T09:00:00Z",
    }

    sorted_items = app.sort_deep_queue_items([item_missing, item_invalid, item_valid])
    assert sorted_items[0]["analysis_id"] == "EM_VALID_PROB"
    # 확률 누락/유효하지 않은 항목들은 뒤로 밀려남
    assert {sorted_items[1]["analysis_id"], sorted_items[2]["analysis_id"]} == {
        "EM_MISSING_PROB",
        "EM_INVALID_PROB",
    }


