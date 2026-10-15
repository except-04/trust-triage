"""File representatives with independent queue membership and full analysis history."""
from datetime import datetime


def timestamp(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return value.timestamp() if value else 0


def representative_key(item):
    policy = item.get("score_policy")
    order = {"uncertainty-v2": 0, "disagreement-v2": 1, "ood-v2": 2,
             "difficulty-v2": 3, "fail-closed-v1": 4, "jrr-inconsistent-v1": 5}
    if item["queue_name"] == "ERROR":
        priority = (0, 0, 0, 0)
    elif item["queue_name"] == "EMERGENCY":
        priority = (0, item.get("emergency_level") or 99,
                    item.get("emergency_obs_level") or 99, -(item.get("priority_score") or 0))
    else:
        score = item.get("calibrated_probability") if policy == "uncertainty-v2" else item.get("priority_score")
        priority = (1, order.get(policy, 99), 0, -(score or 0))
    return (*priority, -timestamp(item.get("created_at")), item["analysis_id"])


def group_candidates(candidates, history):
    groups = {}
    other = []
    for item in candidates:
        queue = item["queue_name"]
        if queue not in {"DEEP", "EMERGENCY", "ERROR"}:
            other.append(item)
            continue
        key = ("DEEP" if queue == "EMERGENCY" else queue, item["sha256"])
        groups.setdefault(key, []).append(item)
    for (_, sha), members in groups.items():
        representative = dict(min(members, key=representative_key))
        records = sorted(history.get(sha, []), key=lambda r: (-timestamp(r.get("created_at")), r["analysis_id"]))
        representative.update(
            analysis_count=len(records),
            failure_count=sum(r.get("status") == "FAILED" for r in records),
            jrr_error_count=sum(bool(r.get("jrr_error")) or r.get("reason_code") == "JRR_RESULT_INCONSISTENT" for r in records),
            analysis_history=records,
        )
        other.append(representative)
    # AUTO retains its previous latest-per-file behavior.
    result, seen = [], set()
    for item in other:
        if item["queue_name"] == "AUTO":
            if item["sha256"] in seen:
                continue
            seen.add(item["sha256"])
        if "analysis_history" not in item:
            records = sorted(history.get(item["sha256"], []),
                             key=lambda r: (-timestamp(r.get("created_at")), r["analysis_id"]))
            item = dict(item, analysis_history=records, analysis_count=len(records),
                        failure_count=sum(r.get("status") == "FAILED" for r in records),
                        jrr_error_count=sum(bool(r.get("jrr_error")) or r.get("reason_code") == "JRR_RESULT_INCONSISTENT" for r in records))
        result.append(item)
    return result
