"""Deterministic, detached persistence for HTTP/processor tests without PostgreSQL."""

from __future__ import annotations

import json
import threading
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from trust_triage.backend_api.errors import BackendError
from trust_triage.backend_api.repository import (
    AnalysisRecord,
    BatchRecord,
    Claim,
    json_object,
    registration_input,
    validate_listing,
    validate_review,
)
from trust_triage.storage.artifacts import ArtifactReference


def _copy(value):
    return json.loads(json.dumps(value, allow_nan=False))


class MemoryAnalysisRepository:
    def __init__(self):
        self.rows = {}
        self.batches = {}
        self.input_reports = {}
        self.idempotency = {}
        self.leases = {}
        self.retries = {}
        self.reviews = {}
        self.sample_objects = {}
        self.artifacts = {}
        self.calls = Counter()
        self.failures = Counter()
        self.now = datetime.now(timezone.utc)
        self._lock = threading.RLock()

    def _fault(self, operation):
        self.calls[operation] += 1
        if self.failures[operation] > 0:
            self.failures[operation] -= 1
            raise BackendError(
                "DATABASE_ERROR",
                "Synthetic temporary storage failure",
                http_status=503,
                retryable=True,
            )

    def _tick(self):
        self.now += timedelta(microseconds=1)
        return self.now.isoformat()

    def advance(self, seconds):
        self.now += timedelta(seconds=seconds)

    def get_budget_config(self):
        self._fault("get_budget_config")
        daily_budget = getattr(self, "daily_budget", 100)
        emergency_budget = getattr(self, "emergency_budget", 0)
        deep_budget = getattr(self, "deep_budget", 100)
        fp_budget = getattr(self, "fp_budget", 0)
        is_unlimited = getattr(self, "is_unlimited", False)

        today_completed = 0
        today_em = 0
        today_deep = 0
        today_fp = 0
        today_auto = 0
        today_unknown = 0

        from datetime import datetime
        from zoneinfo import ZoneInfo

        now_seoul = self.now.astimezone(ZoneInfo("Asia/Seoul"))
        completed_first_times = {}
        for rev_item in self.reviews.values():
            rev_list = rev_item if isinstance(rev_item, list) else [rev_item]
            for review in rev_list:
                if review.get("review_status") == "COMPLETED":
                    rev_time = datetime.fromisoformat(review["reviewed_at"])
                    rev_time_seoul = rev_time.astimezone(ZoneInfo("Asia/Seoul"))
                    a_id = review.get("analysis_id")
                    if (
                        a_id not in completed_first_times
                        or rev_time_seoul < completed_first_times[a_id]["time"]
                    ):
                        completed_first_times[a_id] = {
                            "time": rev_time_seoul,
                            "queue": review.get("review_queue", "UNKNOWN"),
                        }

        for a_id, info in completed_first_times.items():
            if info["time"].date() == now_seoul.date():
                q = info["queue"]
                if q == "EMERGENCY":
                    today_em += 1
                elif q == "DEEP":
                    today_deep += 1
                elif q == "FP":
                    today_fp += 1
                elif q == "AUTO":
                    today_auto += 1
                else:
                    today_unknown += 1

        today_total_manual = today_em + today_deep + today_fp + today_unknown

        return {
            "daily_budget": daily_budget,
            "emergency_budget": emergency_budget,
            "deep_budget": deep_budget,
            "fp_budget": fp_budget,
            "is_unlimited": is_unlimited,
            "today_completed_count": today_total_manual,
            "today_completed_emergency": today_em,
            "today_completed_deep": today_deep,
            "remaining_budget": max(daily_budget - today_total_manual, 0),
            "remaining_emergency": max(emergency_budget - today_em, 0),
            "remaining_deep": max(deep_budget - today_deep, 0),
            "updated_at": self.now.isoformat(),
        }

    def set_budget_config(self, config):
        self._fault("set_budget_config")
        self.daily_budget = config.get("daily_budget", 100)
        self.emergency_budget = config.get("emergency_budget", 0)
        self.deep_budget = config.get("deep_budget", 100)
        self.fp_budget = config.get("fp_budget", 0)
        self.is_unlimited = config.get("is_unlimited", False)

    def set_daily_budget(self, budget, em=0, deep=0, fp=0, is_unlimited=False):
        self._fault("set_daily_budget")
        self.daily_budget = budget
        self.emergency_budget = em
        self.deep_budget = deep
        self.fp_budget = fp
        self.is_unlimited = is_unlimited

    def _determine_queue(
        self, prob_float, initial_verdict, triggered_signals, risk_signals, deep_result
    ):
        # We copy exactly the logic from repository.py
        if prob_float < 0.0:
            return {
                "queue_name": "ERROR",
                "queue_reason": "비정상/누락된 악성 확률 값",
                "priority_score": -1.0,
                "score_policy": "error-v1",
                "priority_reason": "오류 상태로 점수 산정 불가",
                "selection_reason": "확률 값 오류 검토 필요",
            }

        is_emergency = False
        emergency_reason = ""
        evidence = deep_result.get("evidence", []) if deep_result else []

        emergency_level = None
        emergency_obs_level = 99
        emergency_category = ""

        from trust_triage.backend_api.repository import evaluate_emergency_evidence

        em_eval = evaluate_emergency_evidence(evidence)
        if em_eval is not None:
            is_emergency = True
            emergency_level = em_eval["emergency_level"]
            emergency_obs_level = em_eval["emergency_obs_level"]
            emergency_category = em_eval["emergency_category"]
            emergency_reason = em_eval["emergency_reason"]

        is_auto = initial_verdict in ["AUTO_BENIGN", "AUTO_MALICIOUS"]
        auto_reason = "자동 판정 기준 충족 (추가 수집 경로 없음)" if is_auto else ""

        is_deep = False
        deep_reasons = []
        deep_priority_score = prob_float
        deep_score_policy = "probability-v1"
        deep_priority_reason = "단순 악성 확률순"
        deep_queue_reason = ""

        raw_ood = float(risk_signals.get("ood_score", 0))
        disagreement = float(risk_signals.get("disagreement", 0))
        difficulty = float(risk_signals.get("difficulty_score", 0))

        has_uncertainty = "UNCERTAIN_PROBABILITY" in triggered_signals
        has_disagreement = "DISAGREEMENT" in triggered_signals
        has_ood = "OOD" in triggered_signals
        has_difficulty = "DIFFICULTY" in triggered_signals

        if has_uncertainty or has_disagreement or has_ood or has_difficulty:
            is_deep = True
            if has_uncertainty:
                deep_reasons.append("JRR 확률 보류 구간")
            if has_disagreement:
                deep_reasons.append(f"모델 간 확률 차이 {disagreement * 100:.2f}%p")
            if has_ood:
                deep_reasons.append("학습 분포에서 벗어남")
            if has_difficulty:
                deep_reasons.append(f"PE 구조 경고 점수 {int(difficulty)}")

            if has_uncertainty:
                deep_priority_score = 1.0 - 2.0 * abs(prob_float - 0.5)
                deep_score_policy = "uncertainty-v2"
                deep_priority_reason = "확률 불확실성"
                deep_queue_reason = "JRR 확률 보류 구간"
            elif has_disagreement:
                deep_priority_score = disagreement
                deep_score_policy = "disagreement-v2"
                deep_priority_reason = "모델 불일치"
                deep_queue_reason = f"모델 간 확률 차이 {disagreement * 100:.2f}%p"
            elif has_ood:
                deep_priority_score = max(0.0, -raw_ood)
                deep_score_policy = "ood-v2"
                deep_priority_reason = "분포 이탈"
                deep_queue_reason = "학습 분포에서 벗어남"
            elif has_difficulty:
                deep_priority_score = difficulty
                deep_score_policy = "difficulty-v2"
                deep_priority_reason = "분석 난이도"
                deep_queue_reason = f"PE 구조 경고 점수 {int(difficulty)}"
        elif initial_verdict == "HIGH_RISK_UNCERTAIN":
            is_deep = True
            deep_priority_score = 0.0
            deep_score_policy = "exception-v2"
            deep_priority_reason = "예외 처리"
            deep_queue_reason = "위험 신호 없는 불확실 파일"

        queue_name = "UNKNOWN"
        queue_reason = ""
        priority_score = -1.0
        score_policy = "none"
        priority_reason = ""
        selection_reason = ""

        if is_emergency:
            queue_name = "EMERGENCY"
            queue_reason = emergency_reason
            priority_score = prob_float
            score_policy = "emergency-v1"
            priority_reason = emergency_category
            selection_reason = f"긴급 대응: {emergency_reason}"
        elif is_deep:
            queue_name = "DEEP"
            queue_reason = deep_queue_reason
            priority_score = deep_priority_score
            score_policy = deep_score_policy
            priority_reason = deep_priority_reason
            selection_reason = f"심층 분석 필요 ({priority_reason})"
        elif is_auto:
            queue_name = "AUTO"
            queue_reason = auto_reason
            priority_score = prob_float
            score_policy = "probability-v1"
            priority_reason = "자동 처리 대상"
            selection_reason = "자동 분류"

        return {
            "queue_name": queue_name,
            "queue_reason": queue_reason,
            "priority_score": priority_score,
            "score_policy": score_policy,
            "priority_reason": priority_reason,
            "selection_reason": selection_reason,
            "_emergency_level": emergency_level if emergency_level is not None else 99,
            "_emergency_obs_level": emergency_obs_level
            if emergency_level is not None
            else 99,
        }

    def get_priority_recommendations(self):
        self._fault("get_priority_recommendations")
        candidates = []
        seen_sha256 = set()

        # Determine completed sha256
        completed_hashes = set()
        for a_id, row in self.rows.items():
            completed = any(
                r.get("analysis_id") == a_id and r.get("review_status") == "COMPLETED"
                for rev_list in self.reviews.values() 
                for r in (rev_list if isinstance(rev_list, list) else [rev_list])
            )
            if completed:
                completed_hashes.add(row.sha256)

        # Sort rows by created_at DESC first to pick the most recent analysis_id for a hash
        sorted_rows = sorted(
            self.rows.values(),
            key=lambda r: (r.created_at, r.analysis_id),
            reverse=True,
        )

        for record in sorted_rows:
            if record.sha256 in seen_sha256:
                continue
            if record.sha256 in completed_hashes:
                continue

            if record.initial_result is None:
                continue

            completed = any(
                r.get("analysis_id") == record.analysis_id
                and r.get("review_status") == "COMPLETED"
                for rev_list in self.reviews.values()
                for r in (rev_list if isinstance(rev_list, list) else [rev_list])
            )
            if completed:
                continue

            is_pending = any(
                r.get("analysis_id") == record.analysis_id
                and r.get("review_status") == "PENDING"
                for rev_list in self.reviews.values()
                for r in (rev_list if isinstance(rev_list, list) else [rev_list])
            )

            seen_sha256.add(record.sha256)

            initial_result = record.initial_result
            deep_result = record.deep_result or {}

            initial_verdict = initial_result.get("initial_verdict")
            triggered_signals = initial_result.get("triggered_signals") or []
            risk_signals = initial_result.get("risk_signals") or {}

            pred = record.initial_result.get("prediction", {})
            prob = pred.get("calibrated_probability")
            try:
                if prob is None or prob == "":
                    raise ValueError()
                prob_float = float(prob)
                import math

                if (
                    math.isnan(prob_float)
                    or math.isinf(prob_float)
                    or prob_float < 0.0
                    or prob_float > 1.0
                ):
                    raise ValueError()
            except (ValueError, TypeError):
                prob_float = -1.0

            q = self._determine_queue(
                prob_float,
                initial_verdict,
                triggered_signals,
                risk_signals,
                deep_result,
            )
            if q["queue_name"] == "UNKNOWN":
                continue

            candidates.append(
                {
                    "analysis_id": record.analysis_id,
                    "filename": record.filename,
                    "sha256": record.sha256,
                    "calibrated_probability": prob_float if prob_float >= 0.0 else None,
                    "priority_score": q["priority_score"],
                    "score_policy": q["score_policy"],
                    "queue_name": q["queue_name"],
                    "queue_reason": q["queue_reason"],
                    "priority_reason": q["priority_reason"],
                    "selection_reason": q["selection_reason"],
                    "_emergency_level": q.get("_emergency_level", 99),
                    "_emergency_obs_level": q.get("_emergency_obs_level", 99),
                    "initial_verdict": record.initial_result.get("initial_verdict"),
                    "triggered_signals": record.initial_result.get("triggered_signals"),
                    "review_status": "검토 중" if is_pending else "검토 필요",
                    "created_at": record.created_at,
                }
            )

        def policy_rank(policy):
            order = {
                "uncertainty-v2": 0,
                "disagreement-v2": 1,
                "ood-v2": 2,
                "difficulty-v2": 3,
                "exception-v2": 4,
                "probability-v1": 5,
                "error-v1": 99,
            }
            return order.get(policy, 99)

        def get_sort_key(x):
            created_dt = x["created_at"]
            if isinstance(created_dt, str):
                from datetime import datetime

                created_dt = datetime.fromisoformat(created_dt)

            if x["queue_name"] == "AUTO":
                return (
                    x["queue_name"],
                    0,
                    0,
                    0.0,
                    -created_dt.timestamp(),
                    x["analysis_id"],
                )
            elif x["queue_name"] == "EMERGENCY":
                return (
                    x["queue_name"],
                    x.get("_emergency_level", 99),
                    x.get("_emergency_obs_level", 99),
                    -x["priority_score"],
                    created_dt.timestamp(),
                    x["analysis_id"],
                )
            else:
                return (
                    x["queue_name"],
                    policy_rank(x["score_policy"]),
                    0,
                    -x["priority_score"],
                    created_dt.timestamp(),
                    x["analysis_id"],
                )

        candidates.sort(key=get_sort_key)

        for i, c in enumerate(candidates):
            c["rank"] = i + 1
            c.pop("_emergency_level", None)
            c.pop("_emergency_obs_level", None)
        return candidates

    def initialize(self):
        self._fault("initialize")

    def check(self):
        self._fault("check")

    @contextmanager
    def sample_transaction(self, sha256s):
        with self._lock:
            names = (
                "rows",
                "batches",
                "input_reports",
                "idempotency",
                "reviews",
                "sample_objects",
                "artifacts",
                "leases",
                "retries",
            )
            snapshot = {name: deepcopy(getattr(self, name)) for name in names}
            try:
                yield self
            except BaseException:
                for name, value in snapshot.items():
                    setattr(self, name, value)
                raise

    def register(self, analyses, *, batch_id=None, idempotency_key=None):
        return self._register(
            analyses, batch_id=batch_id, idempotency_key=idempotency_key
        ).analyses

    def register_batch(self, analyses, *, batch_id, input_report, idempotency_key=None):
        return self._register(
            analyses,
            batch_id=batch_id,
            input_report=input_report,
            idempotency_key=idempotency_key,
        )

    def _register(
        self, analyses, *, batch_id=None, idempotency_key=None, input_report=None
    ):
        self._fault("register")
        inputs, fingerprint, kind = registration_input(
            analyses, batch_id, idempotency_key, input_report
        )
        with self._lock:
            previous = (
                self.idempotency.get(idempotency_key)
                if idempotency_key is not None
                else None
            )
            if previous is not None:
                if previous[:2] != (fingerprint, kind):
                    raise BackendError(
                        "IDEMPOTENCY_CONFLICT",
                        "Idempotency key was already used for a different request",
                        http_status=409,
                    )
                report = self.input_reports.get(previous[3])
                return BatchRecord(
                    previous[3],
                    [self.get(key) for key in previous[2]],
                    report.model_copy(deep=True) if report else None,
                )
            if (batch_id is not None and batch_id in self.batches) or any(
                item["analysis_id"] in self.rows for item in inputs
            ):
                raise BackendError(
                    "REGISTRATION_CONFLICT",
                    "Analysis registration conflicts with existing input",
                    http_status=409,
                )
            for item in inputs:
                existing = self.sample_objects.get(item["file_location"])
                if existing is not None and existing[:2] != (
                    item["sha256"],
                    item["size_bytes"],
                ):
                    raise BackendError(
                        "STORAGE_IDENTITY_CONFLICT",
                        "Storage identifies different bytes",
                        http_status=409,
                    )
            ids = []
            for item in inputs:
                self.sample_objects[item["file_location"]] = (
                    item["sha256"],
                    item["size_bytes"],
                    None,
                )
                duplicate = next(
                    (
                        row.analysis_id
                        for row in self.rows.values()
                        if row.sha256 == item["sha256"]
                    ),
                    None,
                )
                stamp = self._tick()
                record = AnalysisRecord(
                    **item,
                    batch_id=batch_id,
                    duplicate_of=duplicate,
                    created_at=stamp,
                    updated_at=stamp,
                )
                self.rows[record.analysis_id] = record
                ids.append(record.analysis_id)
            if batch_id is not None:
                self.batches[batch_id] = ids
                self.input_reports[batch_id] = (
                    input_report.model_copy(deep=True) if input_report else None
                )
            if idempotency_key is not None:
                self.idempotency[idempotency_key] = (fingerprint, kind, ids, batch_id)
            return BatchRecord(
                batch_id,
                [self.get(key) for key in ids],
                input_report.model_copy(deep=True) if input_report else None,
            )

    def get(self, analysis_id):
        self._fault("get")
        with self._lock:
            row = self.rows.get(analysis_id)
            if row is None:
                return None
            lease = self.leases.get(analysis_id)
            return replace(
                row,
                claimed=bool(lease and lease[1] > self.now),
                initial_result=_copy(row.initial_result),
                deep_result=_copy(row.deep_result),
                final_assessment=_copy(row.final_assessment),
                error=_copy(row.error),
            )

    def list_analyses(
        self,
        limit=20,
        offset=0,
        status=None,
        sha256=None,
        *,
        batch_id=None,
        verdict=None,
        overturned_only=False,
        sort="newest",
    ):
        self._fault("list_analyses")
        validate_listing(batch_id, verdict, sort)
        with self._lock:
            if batch_id is not None and batch_id not in self.batches:
                raise BackendError(
                    "BATCH_NOT_FOUND", "Batch was not found", http_status=404
                )
            records = sorted(
                (
                    row
                    for row in self.rows.values()
                    if (status is None or row.status == status)
                    and (sha256 is None or row.sha256 == sha256)
                    and (batch_id is None or row.batch_id == batch_id)
                    and (
                        verdict is None
                        or (row.initial_result or {}).get("initial_verdict") == verdict
                    )
                    and (
                        not overturned_only
                        or (
                            row.analyst_final_verdict is not None
                            and (
                                (
                                    (row.initial_result or {}).get("initial_verdict")
                                    in ("BENIGN", "AUTO_BENIGN")
                                    and row.analyst_final_verdict == "MALICIOUS"
                                )
                                or (
                                    (row.initial_result or {}).get("initial_verdict")
                                    in (
                                        "MALICIOUS",
                                        "AUTO_MALICIOUS",
                                        "HIGH_RISK_UNCERTAIN",
                                    )
                                    and row.analyst_final_verdict == "BENIGN"
                                )
                            )
                        )
                    )
                ),
                key=lambda row: (row.created_at, row.analysis_id),
                reverse=True,
            )
            if sort == "high_risk_first":
                priorities = {
                    "HIGH_RISK_UNCERTAIN": 0,
                    "AUTO_MALICIOUS": 1,
                    "AUTO_BENIGN": 2,
                }
                records.sort(
                    key=lambda row: (
                        4
                        if row.status == "FAILED"
                        else priorities.get(
                            (row.initial_result or {}).get("initial_verdict"), 3
                        )
                    )
                )
            elif sort == "input_order":
                positions = {
                    key: index for index, key in enumerate(self.batches[batch_id])
                }
                records.sort(key=lambda row: positions[row.analysis_id])
            return [
                self.get(row.analysis_id) for row in records[offset : offset + limit]
            ], len(records)

    def get_batch(self, batch_id):
        result = self.batch_record(batch_id)
        return None if result is None else result.analyses

    def batch_record(self, batch_id):
        self._fault("get_batch")
        with self._lock:
            ids = self.batches.get(batch_id)
            report = self.input_reports.get(batch_id)
            return (
                None
                if ids is None
                else BatchRecord(
                    batch_id,
                    [self.get(key) for key in ids],
                    report.model_copy(deep=True) if report else None,
                )
            )

    def _ready(self, row):
        lease = self.leases.get(row.analysis_id)
        retry = self.retries.get(row.analysis_id)
        return (
            not row.terminal
            and (not lease or lease[1] <= self.now)
            and (retry is None or retry <= self.now)
        )

    def pending_ids(self, limit=10):
        self._fault("pending_ids")
        with self._lock:
            return [
                row.analysis_id
                for row in sorted(
                    self.rows.values(),
                    key=lambda row: (
                        row.phase == "WAITING_DEEP",
                        row.updated_at,
                        row.analysis_id,
                    ),
                )
                if self._ready(row)
            ][:limit]

    def claim(self, analysis_id, lease_seconds):
        self._fault("claim")
        with self._lock:
            row = self.get(analysis_id)
            if row is None:
                raise BackendError(
                    "ANALYSIS_NOT_FOUND", "Analysis was not found", http_status=404
                )
            if not self._ready(row):
                return Claim(row)
            token = str(uuid4())
            self.leases[analysis_id] = (
                token,
                self.now + timedelta(seconds=lease_seconds),
            )
            self.rows[analysis_id] = replace(
                row,
                status="RUNNING",
                current_stage="INITIAL_ANALYSIS"
                if row.phase == "INITIAL"
                else row.current_stage,
                attempt_count=row.attempt_count + 1,
                updated_at=self._tick(),
            )
            return Claim(self.get(analysis_id), token)

    def _owns(self, analysis_id, token):
        row = self.rows.get(analysis_id)
        lease = self.leases.get(analysis_id)
        return bool(
            row
            and not row.terminal
            and lease
            and lease[0] == token
            and lease[1] > self.now
        )

    def renew(self, analysis_id, token, lease_seconds):
        self._fault("renew")
        with self._lock:
            if not self._owns(analysis_id, token):
                return False
            self.leases[analysis_id] = (
                token,
                self.now + timedelta(seconds=lease_seconds),
            )
            self.rows[analysis_id] = replace(
                self.rows[analysis_id], updated_at=self._tick()
            )
            return True

    def release(self, analysis_id, token, error=None, next_retry_at=None):
        self._fault("release")
        with self._lock:
            if not self._owns(analysis_id, token):
                return False
            retry = (
                datetime.fromisoformat(next_retry_at.replace("Z", "+00:00"))
                if isinstance(next_retry_at, str)
                else next_retry_at
            )
            if retry is not None and (
                not isinstance(retry, datetime) or retry.tzinfo is None
            ):
                raise ValueError("Timezone-aware next_retry_at required")
            payload = json_object(error) if error is not None else None
            self.rows[analysis_id] = replace(
                self.rows[analysis_id], error=payload, updated_at=self._tick()
            )
            self.leases.pop(analysis_id, None)
            self.retries[analysis_id] = retry
            return True

    @staticmethod
    def _identity(row, payload):
        if any(
            key in payload and payload[key] != getattr(row, key)
            for key in ("sha256", "analysis_id")
        ):
            raise BackendError(
                "INVALID_PERSISTED_STATE",
                "Analysis state failed persistence validation",
                http_status=422,
            )

    def save_initial(self, analysis_id, token, result, needs_deep):
        self._fault("save_initial")
        payload = json_object(result)
        with self._lock:
            if (
                not self._owns(analysis_id, token)
                or self.rows[analysis_id].phase != "INITIAL"
            ):
                return False
            row = self.rows[analysis_id]
            self._identity(row, payload)
            self.rows[analysis_id] = replace(
                row,
                initial_result=payload,
                phase="WAITING_DEEP" if needs_deep else "FINALIZING",
                current_stage="CAPA_FLOSS" if needs_deep else "FINAL_ASSESSMENT",
                error=None,
                updated_at=self._tick(),
            )
            self.retries.pop(analysis_id, None)
            return True

    def save_deep(self, analysis_id, token, snapshot, *, finished, current_stage):
        self._fault("save_deep")
        payload = json_object(snapshot)
        with self._lock:
            if (
                not self._owns(analysis_id, token)
                or self.rows[analysis_id].phase != "WAITING_DEEP"
            ):
                return False
            row = self.rows[analysis_id]
            self._identity(row, payload)
            self.rows[analysis_id] = replace(
                row,
                deep_result=payload,
                phase="FINALIZING" if finished else "WAITING_DEEP",
                current_stage="FINAL_ASSESSMENT" if finished else current_stage,
                error=None,
                updated_at=self._tick(),
            )
            self.retries.pop(analysis_id, None)
            return True

    def finish(self, analysis_id, token, final_assessment, *, error=None):
        self._fault("finish")
        payload = json_object(final_assessment)
        failure = json_object(error) if error is not None else None
        with self._lock:
            if not self._owns(analysis_id, token):
                return False
            row = self.rows[analysis_id]
            if failure is None and row.phase != "FINALIZING":
                return False
            self._identity(row, payload)
            stamp = self._tick()
            status = "FAILED" if failure is not None else "COMPLETED"
            self.rows[analysis_id] = replace(
                row,
                final_assessment=payload,
                error=failure,
                phase="DONE",
                status=status,
                current_stage="FINAL_ASSESSMENT",
                updated_at=stamp,
                completed_at=stamp,
            )
            self.leases.pop(analysis_id, None)
            self.retries.pop(analysis_id, None)
            return True

    def cleanup_candidates(self, before_datetime, limit=10, *, after=None):
        self._fault("cleanup_candidates")
        with self._lock:
            return [
                self.get(row.analysis_id)
                for row in sorted(
                    self.rows.values(),
                    key=lambda row: (row.completed_at or "", row.analysis_id),
                )
                if row.terminal
                and row.storage_deleted_at is None
                and datetime.fromisoformat(row.completed_at) < before_datetime
                and (
                    after is None
                    or (datetime.fromisoformat(row.completed_at), row.analysis_id)
                    > after
                )
            ][:limit]

    def location_records(self, location):
        self._fault("location_records")
        with self._lock:
            return [
                self.get(row.analysis_id)
                for row in sorted(self.rows.values(), key=lambda row: row.analysis_id)
                if row.file_location == location and row.storage_deleted_at is None
            ]

    def mark_sample_deleted(self, location):
        self._fault("mark_sample_deleted")
        with self._lock:
            references = self.location_records(location)
            if any(not row.terminal for row in references):
                raise BackendError(
                    "SAMPLE_IN_USE",
                    "Sample is still used by an analysis",
                    http_status=409,
                )
            stamp = self._tick()
            for row in references:
                self.rows[row.analysis_id] = replace(row, storage_deleted_at=stamp)
            if location in self.sample_objects:
                sha256, size, deleted = self.sample_objects[location]
                self.sample_objects[location] = (sha256, size, deleted or stamp)
            return [row.analysis_id for row in references]

    def location_referenced(self, location):
        self._fault("location_referenced")
        return any(
            row.file_location == location and row.storage_deleted_at is None
            for row in self.rows.values()
        )

    def record_artifact(self, reference, token):
        self._fault("record_artifact")
        reference = ArtifactReference(**reference.to_dict())
        with self._lock:
            if not self._owns(reference.analysis_id, token):
                return False
            row = self.rows[reference.analysis_id]
            if row.sha256 != reference.sha256:
                raise BackendError(
                    "ARTIFACT_IDENTITY_CONFLICT",
                    "Artifact belongs to another sample",
                    http_status=409,
                )
            key = (
                reference.analysis_id,
                reference.tool,
                reference.tool_run_id,
                reference.name,
            )
            existing = self.artifacts.get(key)
            if existing is not None and any(
                getattr(existing, name) != value
                for name, value in reference.to_dict().items()
                if name != "created_at"
            ):
                raise BackendError(
                    "ARTIFACT_CONFLICT",
                    "Artifact reference already exists",
                    http_status=409,
                )
            self.artifacts.setdefault(key, reference)
            return True

    def list_artifacts(self, analysis_id):
        self._fault("list_artifacts")
        with self._lock:
            return sorted(
                [
                    value
                    for value in self.artifacts.values()
                    if value.analysis_id == analysis_id
                ],
                key=lambda ref: (ref.created_at, ref.tool, ref.tool_run_id, ref.name),
            )

    def save_review(
        self,
        analysis_id,
        *,
        analyst_final_verdict,
        analyst_notes,
        reviewer_id,
        expected_revision,
    ):
        self._fault("save_review")
        validate_review(
            analyst_final_verdict, analyst_notes, reviewer_id, expected_revision
        )
        with self._lock:
            row = self.rows.get(analysis_id)
            if row is None:
                raise BackendError(
                    "ANALYSIS_NOT_FOUND", "Analysis was not found", http_status=404
                )
            if not row.terminal:
                raise BackendError(
                    "ANALYSIS_NOT_FINISHED",
                    "Analysis must finish before analyst review",
                    http_status=409,
                )
            if row.review_revision != expected_revision:
                raise BackendError(
                    "REVIEW_CONFLICT",
                    "A newer analyst review already exists",
                    http_status=409,
                )
            revision, stamp = expected_revision + 1, self._tick()
            review = {
                "review_id": str(uuid4()),
                "analysis_id": analysis_id,
                "revision": revision,
                "analyst_final_verdict": analyst_final_verdict,
                "analyst_notes": analyst_notes,
                "reviewer_id": reviewer_id,
                "review_status": "PENDING"
                if analyst_final_verdict is None
                else "COMPLETED",
                "reviewed_at": stamp,
            }
            self.reviews.setdefault(analysis_id, []).append(review)
            self.rows[analysis_id] = replace(
                row,
                review_revision=revision,
                analyst_final_verdict=analyst_final_verdict,
                updated_at=stamp,
            )
            return _copy(review)

    def list_reviews(self, analysis_id):
        self._fault("list_reviews")
        return _copy(self.reviews.get(analysis_id, []))


# Short alias for application test fixtures.
MemoryRepository = MemoryAnalysisRepository
