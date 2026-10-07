"""Durable API requests, fenced processing, and append-only analyst decisions."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from copy import copy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from importlib.resources import files
from typing import Any, Protocol
from uuid import uuid4

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from trust_triage.storage.artifacts import ArtifactReference

from .errors import BackendError
from .schemas import BatchInputReport, CurrentStage, InitialVerdict

MAX_STATE_BYTES = 8 * 1024 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SELECT = "SELECT *, COALESCE(lease_until > clock_timestamp(), false) AS claimed FROM api_analyses"
_ACTIVE = "status IN ('QUEUED', 'RUNNING')"
_READY = (
    _ACTIVE + " AND (lease_until IS NULL OR lease_until <= clock_timestamp())"
    " AND (next_retry_at IS NULL OR next_retry_at <= clock_timestamp())"
)
_OWNED = (
    "analysis_id = %s AND "
    + _ACTIVE
    + " AND lease_token = %s::uuid AND lease_until > clock_timestamp()"
)


def evaluate_emergency_evidence(
    evidence: list[dict[str, Any]],
) -> dict[str, Any] | None:
    best_level = None
    best_obs_level = 99
    best_category = ""
    best_reason = ""

    for ev in evidence:
        source = ev.get("source", "").lower()
        status = ev.get("status", "").upper()
        techniques = ev.get("attack_techniques", [])

        if status != "OBSERVED":
            continue

        if source == "speakeasy":
            obs_level = 1
            act_str = "동적 관측—결과 미확인"
        elif source == "capa":
            obs_level = 2
            act_str = "정적 규칙 일치"
        else:
            continue

        for t in techniques:
            t_id = t.get("technique_id")
            if t_id:
                t_id = str(t_id).upper()
            else:
                t_id = ""

            t_name = t.get("technique_name")
            if t_name:
                t_name = str(t_name).lower()
            else:
                t_name = ""

            level = None
            cat = ""

            if (
                t_id in ["T1485", "T1561"]
                or "data destruction" in t_name
                or "disk structure wipe" in t_name
            ):
                level = 1
                cat = "데이터 파괴"
            elif (
                t_id in ["T1486"]
                or "data encrypted for impact" in t_name
                or "ransomware" in t_name
            ):
                # Normal encrypting APIs are ignored, strictly ransomware tag/id
                level = 1
                cat = "랜섬웨어 암호화"
            elif (
                t_id in ["T1490"]
                or "inhibit system recovery" in t_name
                or "delete volume shadow" in t_name
            ):
                level = 2
                cat = "복구 방해"
            elif (
                t_id in ["T1489"]
                or "service stop" in t_name
                or "stop services" in t_name
            ):
                level = 2
                cat = "서비스 중단"

            if level is not None:
                if (
                    best_level is None
                    or level < best_level
                    or (level == best_level and obs_level < best_obs_level)
                ):
                    best_level = level
                    best_obs_level = obs_level
                    best_category = cat

                    src_display = source.upper() if source else "UNKNOWN"
                    best_reason = f"{src_display}: {cat} ({act_str})"

    if best_level is not None:
        return {
            "emergency_level": best_level,
            "emergency_obs_level": best_obs_level,
            "emergency_category": best_category,
            "emergency_reason": best_reason,
        }
    return None


@dataclass(frozen=True)
class AnalysisRecord:
    analysis_id: str
    sha256: str
    file_location: str
    filename: str
    size_bytes: int
    batch_id: str | None = None
    status: str = "QUEUED"
    current_stage: str = "UPLOAD"
    phase: str = "INITIAL"
    initial_result: Mapping[str, Any] | None = None
    deep_result: Mapping[str, Any] | None = None
    final_assessment: Mapping[str, Any] | None = None
    error: Mapping[str, Any] | None = None
    attempt_count: int = 0
    created_at: str | None = None
    updated_at: str | None = None
    completed_at: str | None = None
    duplicate_of: str | None = None
    review_revision: int = 0
    analyst_final_verdict: str | None = None
    claimed: bool = False
    storage_deleted_at: str | None = None

    @property
    def terminal(self) -> bool:
        return self.status in {"COMPLETED", "FAILED"}

    def to_dict(self) -> dict[str, Any]:
        """Internal serialization; HTTP responses must exclude storage locations."""
        return asdict(self)


@dataclass(frozen=True)
class Claim:
    record: AnalysisRecord
    token: str | None = None


@dataclass(frozen=True)
class BatchRecord:
    batch_id: str | None
    analyses: list[AnalysisRecord]
    input_report: BatchInputReport | None = None


class AnalysisRepository(Protocol):
    def initialize(self) -> None: ...
    def check(self) -> None: ...
    def sample_transaction(self, sha256s: list[str]): ...
    def register(
        self,
        analyses: list[dict[str, Any]],
        *,
        batch_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> list[AnalysisRecord]: ...
    def register_batch(
        self,
        analyses,
        *,
        batch_id: str,
        input_report: BatchInputReport,
        idempotency_key: str | None = None,
    ) -> BatchRecord: ...
    def batch_record(self, batch_id: str) -> BatchRecord | None: ...
    def get(self, analysis_id: str) -> AnalysisRecord | None: ...
    def list_analyses(
        self,
        limit: int = 20,
        offset: int = 0,
        status: str | None = None,
        sha256: str | None = None,
        *,
        batch_id: str | None = None,
        verdict: str | None = None,
        overturned_only: bool = False,
        sort: str = "newest",
    ) -> tuple[list[AnalysisRecord], int]: ...
    def get_batch(self, batch_id: str) -> list[AnalysisRecord] | None: ...
    def pending_ids(self, limit: int = 10) -> list[str]: ...
    def claim(self, analysis_id: str, lease_seconds: int) -> Claim: ...
    def renew(self, analysis_id: str, token: str, lease_seconds: int) -> bool: ...
    def release(
        self,
        analysis_id: str,
        token: str,
        error: Mapping[str, Any] | None = None,
        next_retry_at: datetime | str | None = None,
    ) -> bool: ...
    def save_initial(
        self,
        analysis_id: str,
        token: str,
        result: Mapping[str, Any],
        needs_deep: bool,
    ) -> bool: ...
    def save_deep(
        self,
        analysis_id: str,
        token: str,
        snapshot: Mapping[str, Any],
        *,
        finished: bool,
        current_stage: str,
    ) -> bool: ...
    def finish(
        self,
        analysis_id: str,
        token: str,
        final_assessment: Mapping[str, Any],
        *,
        error: Mapping[str, Any] | None = None,
    ) -> bool: ...
    def cleanup_candidates(
        self,
        before_datetime: datetime,
        limit: int = 10,
        *,
        after: tuple[datetime, str] | None = None,
    ) -> list[AnalysisRecord]: ...
    def mark_sample_deleted(self, location: str) -> list[str]: ...
    def location_records(self, location: str) -> list[AnalysisRecord]: ...
    def location_referenced(self, location: str) -> bool: ...
    def record_artifact(self, reference: ArtifactReference, token: str) -> bool: ...
    def list_artifacts(self, analysis_id: str) -> list[ArtifactReference]: ...
    def save_review(
        self,
        analysis_id: str,
        *,
        analyst_final_verdict: str | None,
        analyst_notes: str,
        reviewer_id: str,
        expected_revision: int,
    ) -> dict[str, Any]: ...
    def list_reviews(self, analysis_id: str) -> list[dict[str, Any]]: ...


class PostgresAnalysisRepository:
    def get_budget_config(self) -> dict[str, Any]:
        with self._connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT daily_budget, emergency_budget, deep_budget, fp_budget, is_unlimited, updated_at FROM api_budget_config WHERE id = 1"
            )
            row = cur.fetchone()
            if not row:
                cur.execute(
                    "INSERT INTO api_budget_config (id, daily_budget, emergency_budget, deep_budget, fp_budget, is_unlimited) VALUES (1, 100, 0, 100, 0, FALSE) RETURNING daily_budget, emergency_budget, deep_budget, fp_budget, is_unlimited, updated_at"
                )
                row = cur.fetchone()
                conn.commit()

            daily_budget = row["daily_budget"]
            emergency_budget = row["emergency_budget"]
            deep_budget = row["deep_budget"]
            fp_budget = row["fp_budget"]
            is_unlimited = row["is_unlimited"]
            updated_at = row["updated_at"]

            # Calculate completed tasks today using Seoul time boundary (KST UTC+9)
            # Find the *first* completed review per analysis_id, then count those that happened today.
            # "min(review_queue)처럼 문자열 최솟값으로 큐를 선택하지 말고, 최초 완료 기록에 연결된 큐를 집계해주세요."
            cur.execute("""
                WITH first_reviews AS (
                    SELECT 
                        a.sha256,
                        r.review_queue,
                        r.reviewed_at,
                        ROW_NUMBER() OVER(PARTITION BY a.sha256 ORDER BY r.reviewed_at ASC) as rn
                    FROM api_reviews r
                    JOIN api_analyses a ON r.analysis_id = a.analysis_id
                    WHERE r.review_status = 'COMPLETED'
                )
                SELECT review_queue, COUNT(*) as cnt
                FROM first_reviews
                WHERE rn = 1
                  AND reviewed_at AT TIME ZONE 'Asia/Seoul' >= (CURRENT_TIMESTAMP AT TIME ZONE 'Asia/Seoul')::date
                GROUP BY review_queue
            """)
            counts = cur.fetchall()

            today_em = 0
            today_deep = 0
            today_auto = 0
            today_fp = 0
            today_unknown = 0

            for c in counts:
                q = c["review_queue"]
                if q == "EMERGENCY":
                    today_em = c["cnt"]
                elif q == "DEEP":
                    today_deep = c["cnt"]
                elif q == "FP":
                    today_fp = c["cnt"]
                elif q == "AUTO":
                    today_auto = c["cnt"]
                else:
                    today_unknown += c["cnt"]

            today_total = today_em + today_deep + today_fp + today_unknown + today_auto
            # Note: AUTO doesn't cost budget, so maybe we only subtract manual reviews.
            # But "과거 리뷰의 큐 정보가 없는 경우도 전체 완료량에서 조용히 빠지지 않도록"
            # So today_total_manual = today_em + today_deep + today_fp + today_unknown
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
                "today_completed_fp": today_fp,
                "remaining_budget": max(daily_budget - today_total_manual, 0),
                "remaining_emergency": max(emergency_budget - today_em, 0),
                "remaining_deep": max(deep_budget - today_deep, 0),
                "remaining_fp": max(fp_budget - today_fp, 0),
                "updated_at": updated_at,
            }

    def set_budget_config(self, config: dict[str, Any]) -> None:
        if (
            not config.get("is_unlimited", False)
            and config["emergency_budget"] + config["deep_budget"] + config["fp_budget"]
            > config["daily_budget"]
        ):
            raise ValueError("Queue budgets exceed total daily budget")
        with self._connection() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO api_budget_config (id, daily_budget, emergency_budget, deep_budget, fp_budget, is_unlimited, updated_at)
                VALUES (1, %(daily_budget)s, %(emergency_budget)s, %(deep_budget)s, %(fp_budget)s, %(is_unlimited)s, clock_timestamp())
                ON CONFLICT (id) DO UPDATE SET 
                    daily_budget = EXCLUDED.daily_budget,
                    emergency_budget = EXCLUDED.emergency_budget,
                    deep_budget = EXCLUDED.deep_budget,
                    fp_budget = EXCLUDED.fp_budget,
                    is_unlimited = EXCLUDED.is_unlimited,
                    updated_at = clock_timestamp()
            """,
                config,
            )

    def _determine_queue(
        self, prob_float, initial_verdict, triggered_signals, risk_signals, deep_result
    ) -> dict[str, Any]:
        # Handle ERROR state for invalid probability
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

    def get_priority_recommendations(self) -> list[dict[str, Any]]:
        with self._connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute("""
                SELECT
                    a.analysis_id,
                    a.filename,
                    a.sha256,
                    a.initial_result,
                    a.deep_result,
                    a.created_at,
                    a.final_assessment
                FROM api_analyses a
                WHERE a.initial_result IS NOT NULL
                AND a.review_revision = 0
                AND NOT EXISTS (
                    SELECT 1 FROM api_reviews r 
                    WHERE r.analysis_id = a.analysis_id AND r.review_status IN ('PENDING', 'COMPLETED')
                )
                AND NOT EXISTS (
                    SELECT 1 FROM api_reviews r2 
                    JOIN api_analyses a2 ON r2.analysis_id = a2.analysis_id
                    WHERE a2.sha256 = a.sha256 AND r2.review_status = 'COMPLETED'
                )
                ORDER BY a.created_at DESC
            """)
            rows = cur.fetchall()

            candidates = []
            seen_sha256 = set()
            for row in rows:
                if row["sha256"] in seen_sha256:
                    continue
                seen_sha256.add(row["sha256"])

                initial_result = row["initial_result"]
                deep_result = row.get("deep_result") or {}

                initial_verdict = initial_result.get("initial_verdict")
                triggered_signals = initial_result.get("triggered_signals") or []
                risk_signals = initial_result.get("risk_signals") or {}

                prob = initial_result.get("prediction", {}).get(
                    "calibrated_probability"
                )
                try:
                    import math

                    if prob is None or prob == "":
                        raise ValueError()
                    prob_float = float(prob)
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
                        "analysis_id": row["analysis_id"],
                        "filename": row["filename"],
                        "sha256": row["sha256"],
                        "queue_name": q["queue_name"],
                        "queue_reason": q["queue_reason"],
                        "calibrated_probability": prob_float
                        if prob_float >= 0.0
                        else None,
                        "priority_score": q["priority_score"],
                        "score_policy": q["score_policy"],
                        "priority_reason": q["priority_reason"],
                        "selection_reason": q["selection_reason"],
                        "_emergency_level": q.get("_emergency_level", 99),
                        "_emergency_obs_level": q.get("_emergency_obs_level", 99),
                        "initial_verdict": initial_verdict,
                        "triggered_signals": triggered_signals,
                        "review_status": "PENDING",
                        "created_at": row["created_at"],
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
                if x["queue_name"] == "AUTO":
                    return (
                        x["queue_name"],
                        0,
                        0,
                        0.0,
                        -x["created_at"].timestamp(),
                        x["analysis_id"],
                    )
                elif x["queue_name"] == "EMERGENCY":
                    # For EMERGENCY:
                    # Risk Level -> Observation Level -> -Calibrated Probability -> created_at -> analysis_id
                    # We inject this by overriding policy rank to be emergency_level, and priority score handling.
                    # To keep it in the same tuple format:
                    return (
                        x["queue_name"],
                        x.get("_emergency_level", 99),
                        x.get("_emergency_obs_level", 99),
                        -x["priority_score"],
                        x["created_at"].timestamp(),
                        x["analysis_id"],
                    )
                else:
                    return (
                        x["queue_name"],
                        policy_rank(x["score_policy"]),
                        0,  # placeholder for emergency_obs_level
                        -x["priority_score"],
                        x["created_at"].timestamp(),
                        x["analysis_id"],
                    )

            candidates.sort(key=get_sort_key)
            for i, c in enumerate(candidates):
                c["rank"] = i + 1
                c.pop("_emergency_level", None)
                c.pop("_emergency_obs_level", None)
            return candidates

    """One bounded transaction per call; no network details enter public errors."""

    def __init__(
        self, dsn: str, *, connect_timeout: int = 5, statement_timeout_ms: int = 10000
    ):
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError("A PostgreSQL connection string is required")
        _positive_int(connect_timeout, "connect_timeout")
        _positive_int(statement_timeout_ms, "statement_timeout_ms")
        try:
            existing = conninfo_to_dict(dsn).get("options", "")
        except psycopg.Error as exc:
            raise ValueError("Invalid PostgreSQL connection string") from exc
        self._dsn = dsn
        self._connect_timeout = connect_timeout
        self._bound_connection = None
        self._options = (
            f"{existing} -c statement_timeout={statement_timeout_ms}".strip()
        )

    @contextmanager
    def _connection(self) -> Iterator[Any]:
        if self._bound_connection is not None:
            yield self._bound_connection
            return
        try:
            with psycopg.connect(
                self._dsn,
                connect_timeout=self._connect_timeout,
                options=self._options,
                row_factory=dict_row,
            ) as connection:
                yield connection
        except psycopg.errors.UniqueViolation as exc:
            raise BackendError(
                "REGISTRATION_CONFLICT",
                "An analysis, batch, or storage location is already registered",
                http_status=409,
            ) from exc
        except psycopg.errors.CheckViolation as exc:
            raise BackendError(
                "INVALID_PERSISTED_STATE",
                "Analysis state failed persistence validation",
                http_status=422,
            ) from exc
        except psycopg.Error as exc:
            raise BackendError(
                "DATABASE_ERROR",
                "Analysis storage is temporarily unavailable",
                http_status=503,
                retryable=True,
            ) from exc

    def initialize(self) -> None:
        schema = files(__package__).joinpath("schema.sql").read_text(encoding="utf-8")
        with self._connection() as connection:
            connection.execute(schema)

    def check(self) -> None:
        with self._connection() as connection:
            for table in (
                "api_batches",
                "api_analyses",
                "api_reviews",
                "api_sample_objects",
                "api_analysis_artifacts",
            ):
                # These table names are constants, never user input.
                connection.execute(f"SELECT * FROM {table} LIMIT 0")
            connection.execute("SELECT input_report FROM api_batches LIMIT 0")

    @contextmanager
    def sample_transaction(self, sha256s: list[str]):
        """Serialize publish/register/delete for shared bytes across API processes.

        The yielded repository uses this transaction. Do not use it after exit.
        Input streams are staged and validated before entering this scope.
        """
        hashes = sorted(set(sha256s))
        for value in hashes:
            _hash(value)
        with self._connection() as connection:
            _lock_samples(connection, hashes)
            scoped = copy(self)
            scoped._bound_connection = connection
            yield scoped

    def register(
        self,
        analyses: list[dict[str, Any]],
        *,
        batch_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> list[AnalysisRecord]:
        return self._register(
            analyses, batch_id=batch_id, idempotency_key=idempotency_key
        ).analyses

    def register_batch(
        self, analyses, *, batch_id, input_report, idempotency_key=None
    ) -> BatchRecord:
        return self._register(
            analyses,
            batch_id=batch_id,
            input_report=input_report,
            idempotency_key=idempotency_key,
        )

    def _register(
        self, analyses, *, batch_id=None, idempotency_key=None, input_report=None
    ) -> BatchRecord:
        inputs, fingerprint, kind = registration_input(
            analyses, batch_id, idempotency_key, input_report
        )
        request_id = str(uuid4())
        with self._connection() as connection:
            # Acquire before the idempotency row, in the same order as intake/GC.
            _lock_samples(connection, sorted({item["sha256"] for item in inputs}))
            row = connection.execute(
                """INSERT INTO api_batches
                   (request_id, batch_id, request_kind, idempotency_key, input_fingerprint, input_report)
                   VALUES (%s::uuid, %s, %s, %s, %s, %s)
                   ON CONFLICT (idempotency_key) DO NOTHING RETURNING request_id""",
                (
                    request_id,
                    batch_id,
                    kind,
                    idempotency_key,
                    fingerprint,
                    Jsonb(input_report.model_dump(mode="json"))
                    if input_report
                    else None,
                ),
            ).fetchone()
            if row is None:
                previous = connection.execute(
                    "SELECT request_id, request_kind, input_fingerprint, batch_id, input_report FROM api_batches WHERE idempotency_key = %s",
                    (idempotency_key,),
                ).fetchone()
                if (
                    previous is None
                    or previous["request_kind"] != kind
                    or previous["input_fingerprint"] != fingerprint
                ):
                    raise BackendError(
                        "IDEMPOTENCY_CONFLICT",
                        "Idempotency key was already used for a different request",
                        http_status=409,
                    )
                records = [
                    _record(item)
                    for item in connection.execute(
                        _SELECT + " WHERE request_id = %s ORDER BY batch_position",
                        (previous["request_id"],),
                    ).fetchall()
                ]
                return BatchRecord(
                    previous["batch_id"],
                    records,
                    BatchInputReport.model_validate(previous["input_report"])
                    if previous["input_report"]
                    else None,
                )

            for position, item in enumerate(inputs):
                stored = connection.execute(
                    """INSERT INTO api_sample_objects (file_location, sha256, size_bytes)
                       VALUES (%s, %s, %s) ON CONFLICT (file_location) DO UPDATE
                       SET storage_deleted_at = NULL
                       WHERE api_sample_objects.sha256 = EXCLUDED.sha256
                         AND api_sample_objects.size_bytes = EXCLUDED.size_bytes
                       RETURNING file_location""",
                    (item["file_location"], item["sha256"], item["size_bytes"]),
                ).fetchone()
                if stored is None:
                    raise BackendError(
                        "STORAGE_IDENTITY_CONFLICT",
                        "Storage location belongs to different sample bytes",
                        http_status=409,
                    )
                duplicate = connection.execute(
                    "SELECT analysis_id FROM api_analyses WHERE sha256 = %s ORDER BY created_at, analysis_id LIMIT 1",
                    (item["sha256"],),
                ).fetchone()
                connection.execute(
                    """INSERT INTO api_analyses
                       (analysis_id, request_id, batch_id, batch_position, sha256,
                        file_location, filename, size_bytes, duplicate_of)
                       VALUES (%s, %s::uuid, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        item["analysis_id"],
                        request_id,
                        batch_id,
                        position,
                        item["sha256"],
                        item["file_location"],
                        item["filename"],
                        item["size_bytes"],
                        duplicate["analysis_id"] if duplicate else None,
                    ),
                )
            records = [
                _record(item)
                for item in connection.execute(
                    _SELECT + " WHERE request_id = %s::uuid ORDER BY batch_position",
                    (request_id,),
                ).fetchall()
            ]
            return BatchRecord(
                batch_id,
                records,
                input_report.model_copy(deep=True) if input_report else None,
            )

    def get(self, analysis_id: str) -> AnalysisRecord | None:
        with self._connection() as connection:
            row = connection.execute(
                _SELECT + " WHERE analysis_id = %s", (analysis_id,)
            ).fetchone()
            return _record(row) if row else None

    def list_analyses(
        self,
        limit: int = 20,
        offset: int = 0,
        status: str | None = None,
        sha256: str | None = None,
        *,
        batch_id: str | None = None,
        verdict: str | None = None,
        overturned_only: bool = False,
        sort: str = "newest",
    ) -> tuple[list[AnalysisRecord], int]:
        _limit(limit)
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise ValueError("offset must be a nonnegative integer")
        validate_listing(batch_id, verdict, sort)
        conditions, params = [], []
        if status is not None:
            if status not in {"QUEUED", "RUNNING", "COMPLETED", "FAILED"}:
                raise ValueError("Unknown analysis status")
            conditions.append("status = %s")
            params.append(status)
        if sha256 is not None:
            _hash(sha256)
            conditions.append("sha256 = %s")
            params.append(sha256)
        if batch_id is not None:
            conditions.append("batch_id = %s")
            params.append(batch_id)
        if verdict is not None:
            conditions.append("initial_result ->> 'initial_verdict' = %s")
            params.append(verdict)
        if overturned_only:
            conditions.append(
                "("
                "  analyst_final_verdict IS NOT NULL AND ("
                "    (initial_result->>'initial_verdict' LIKE '%%BENIGN' AND analyst_final_verdict = 'MALICIOUS') OR"
                "    (initial_result->>'initial_verdict' LIKE '%%MALICIOUS' AND analyst_final_verdict = 'BENIGN')"
                "  )"
                ")"
            )
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        with self._connection() as connection:
            # One MVCC snapshot keeps count and page consistent under concurrent writes.
            connection.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            if (
                batch_id is not None
                and connection.execute(
                    "SELECT 1 FROM api_batches WHERE batch_id = %s", (batch_id,)
                ).fetchone()
                is None
            ):
                raise BackendError(
                    "BATCH_NOT_FOUND",
                    "해당 일괄 분석을 찾을 수 없습니다.",
                    http_status=404,
                )
            total = connection.execute(
                "SELECT count(*) AS total FROM api_analyses" + where, params
            ).fetchone()["total"]
            rows = connection.execute(
                _SELECT
                + where
                + " ORDER BY "
                + _LIST_ORDER[sort]
                + " LIMIT %s OFFSET %s",
                (*params, limit, offset),
            ).fetchall()
            return [_record(row) for row in rows], total

    def get_batch(self, batch_id: str) -> list[AnalysisRecord] | None:
        result = self.batch_record(batch_id)
        return None if result is None else result.analyses

    def batch_record(self, batch_id: str) -> BatchRecord | None:
        _identifier(batch_id, "batch_id")
        with self._connection() as connection:
            connection.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
            )
            batch = connection.execute(
                "SELECT request_id, input_report FROM api_batches WHERE batch_id = %s",
                (batch_id,),
            ).fetchone()
            if batch is None:
                return None
            records = [
                _record(row)
                for row in connection.execute(
                    _SELECT + " WHERE request_id = %s ORDER BY batch_position",
                    (batch["request_id"],),
                ).fetchall()
            ]
            return BatchRecord(
                batch_id,
                records,
                BatchInputReport.model_validate(batch["input_report"])
                if batch["input_report"]
                else None,
            )

    def pending_ids(self, limit: int = 10) -> list[str]:
        _limit(limit)
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT analysis_id FROM api_analyses WHERE "
                + _READY
                # 가벼운 INITIAL/FINALIZING 단계를 CAPA/FLOSS가 도는 WAITING_DEEP보다
                # 먼저 처리해 이미 판정된 건이 심층 분석 뒤에 줄 서지 않게 한다.
                + " ORDER BY (phase = 'WAITING_DEEP'), updated_at, analysis_id LIMIT %s",
                (limit,),
            ).fetchall()
            return [row["analysis_id"] for row in rows]

    def claim(self, analysis_id: str, lease_seconds: int) -> Claim:
        _lease(lease_seconds)
        token = str(uuid4())
        with self._connection() as connection:
            row = connection.execute(
                """UPDATE api_analyses SET lease_token = %s::uuid,
                   lease_until = clock_timestamp() + make_interval(secs => %s),
                   status = 'RUNNING',
                   current_stage = CASE WHEN phase = 'INITIAL' THEN 'INITIAL_ANALYSIS' ELSE current_stage END,
                   attempt_count = attempt_count + 1, updated_at = clock_timestamp()
                   WHERE analysis_id = %s AND """
                + _READY
                + " RETURNING *, true AS claimed",
                (token, lease_seconds, analysis_id),
            ).fetchone()
            if row:
                return Claim(_record(row), token)
            row = connection.execute(
                _SELECT + " WHERE analysis_id = %s", (analysis_id,)
            ).fetchone()
            if row is None:
                raise BackendError(
                    "ANALYSIS_NOT_FOUND", "Analysis was not found", http_status=404
                )
            return Claim(_record(row))

    def renew(self, analysis_id: str, token: str, lease_seconds: int) -> bool:
        _lease(lease_seconds)
        with self._connection() as connection:
            return (
                connection.execute(
                    """UPDATE api_analyses SET lease_until = clock_timestamp() + make_interval(secs => %s),
                   updated_at = clock_timestamp() WHERE """
                    + _OWNED,
                    (lease_seconds, analysis_id, token),
                ).rowcount
                == 1
            )

    def release(
        self,
        analysis_id: str,
        token: str,
        error: Mapping[str, Any] | None = None,
        next_retry_at: datetime | str | None = None,
    ) -> bool:
        payload = json_object(error) if error is not None else None
        retry = _aware_datetime(next_retry_at) if next_retry_at is not None else None
        with self._connection() as connection:
            return (
                connection.execute(
                    """UPDATE api_analyses SET lease_token = NULL, lease_until = NULL,
                   error = %s, next_retry_at = %s, updated_at = clock_timestamp() WHERE """
                    + _OWNED,
                    (
                        Jsonb(payload) if payload is not None else None,
                        retry,
                        analysis_id,
                        token,
                    ),
                ).rowcount
                == 1
            )

    def save_initial(
        self,
        analysis_id: str,
        token: str,
        result: Mapping[str, Any],
        needs_deep: bool,
    ) -> bool:
        if not isinstance(needs_deep, bool):
            raise TypeError("needs_deep must be boolean")
        payload = json_object(result)
        phase = "WAITING_DEEP" if needs_deep else "FINALIZING"
        stage = "CAPA_FLOSS" if needs_deep else "FINAL_ASSESSMENT"
        with self._connection() as connection:
            return (
                connection.execute(
                    """UPDATE api_analyses SET initial_result = %s, phase = %s, current_stage = %s,
                   error = NULL, next_retry_at = NULL, updated_at = clock_timestamp()
                   WHERE """
                    + _OWNED
                    + " AND phase = 'INITIAL'",
                    (Jsonb(payload), phase, stage, analysis_id, token),
                ).rowcount
                == 1
            )

    def save_deep(
        self,
        analysis_id: str,
        token: str,
        snapshot: Mapping[str, Any],
        *,
        finished: bool,
        current_stage: str,
    ) -> bool:
        if not isinstance(finished, bool):
            raise TypeError("finished must be boolean")
        current_stage = CurrentStage(current_stage).value
        payload = json_object(snapshot)
        phase = "FINALIZING" if finished else "WAITING_DEEP"
        stage = "FINAL_ASSESSMENT" if finished else current_stage
        with self._connection() as connection:
            return (
                connection.execute(
                    """UPDATE api_analyses SET deep_result = %s, phase = %s, current_stage = %s,
                   error = NULL, next_retry_at = NULL, updated_at = clock_timestamp()
                   WHERE """
                    + _OWNED
                    + " AND phase = 'WAITING_DEEP'",
                    (Jsonb(payload), phase, stage, analysis_id, token),
                ).rowcount
                == 1
            )

    def finish(
        self,
        analysis_id: str,
        token: str,
        final_assessment: Mapping[str, Any],
        *,
        error: Mapping[str, Any] | None = None,
    ) -> bool:
        result = json_object(final_assessment)
        failure = json_object(error) if error is not None else None
        status = "FAILED" if failure is not None else "COMPLETED"
        with self._connection() as connection:
            return (
                connection.execute(
                    """UPDATE api_analyses SET final_assessment = %s, error = %s,
                   status = %s, phase = 'DONE', current_stage = 'FINAL_ASSESSMENT',
                   lease_token = NULL, lease_until = NULL, next_retry_at = NULL,
                   completed_at = clock_timestamp(), updated_at = clock_timestamp()
                   WHERE """
                    + _OWNED
                    + " AND (%s OR phase = 'FINALIZING')",
                    (
                        Jsonb(result),
                        Jsonb(failure) if failure is not None else None,
                        status,
                        analysis_id,
                        token,
                        failure is not None,
                    ),
                ).rowcount
                == 1
            )

    def cleanup_candidates(
        self,
        before_datetime: datetime,
        limit: int = 10,
        *,
        after: tuple[datetime, str] | None = None,
    ) -> list[AnalysisRecord]:
        before = _aware_datetime(before_datetime)
        _limit(limit)
        if after is not None:
            if (
                not isinstance(after, tuple)
                or len(after) != 2
                or not isinstance(after[1], str)
                or not after[1]
            ):
                raise ValueError("cleanup cursor must contain datetime and analysis_id")
            cursor_time = _aware_datetime(after[0])
            cursor_id = after[1]
        else:
            cursor_time = None
            cursor_id = None
        cursor_clause = (
            " AND (completed_at, analysis_id) > (%s, %s)" if after is not None else ""
        )
        parameters = (
            (before, cursor_time, cursor_id, limit)
            if after is not None
            else (before, limit)
        )
        with self._connection() as connection:
            return [
                _record(row)
                for row in connection.execute(
                    _SELECT
                    + " WHERE status IN ('COMPLETED', 'FAILED') AND storage_deleted_at IS NULL"
                    " AND completed_at < %s"
                    + cursor_clause
                    + " ORDER BY completed_at, analysis_id LIMIT %s",
                    parameters,
                ).fetchall()
            ]

    def location_records(self, location: str) -> list[AnalysisRecord]:
        with self._connection() as connection:
            return [
                _record(row)
                for row in connection.execute(
                    _SELECT
                    + " WHERE file_location = %s AND storage_deleted_at IS NULL ORDER BY analysis_id",
                    (location,),
                ).fetchall()
            ]

    def mark_sample_deleted(self, location: str) -> list[str]:
        with self._connection() as connection:
            sample = connection.execute(
                "SELECT sha256 FROM api_sample_objects WHERE file_location = %s",
                (location,),
            ).fetchone()
            if sample is None:
                return []
            _lock_samples(connection, [sample["sha256"]])
            active = connection.execute(
                "SELECT EXISTS (SELECT 1 FROM api_analyses WHERE file_location = %s "
                "AND storage_deleted_at IS NULL AND status IN ('QUEUED', 'RUNNING')) AS found",
                (location,),
            ).fetchone()["found"]
            if active:
                raise BackendError(
                    "SAMPLE_IN_USE",
                    "Sample is still used by an analysis",
                    http_status=409,
                )
            rows = connection.execute(
                "UPDATE api_analyses SET storage_deleted_at = clock_timestamp() "
                "WHERE file_location = %s AND storage_deleted_at IS NULL RETURNING analysis_id",
                (location,),
            ).fetchall()
            connection.execute(
                "UPDATE api_sample_objects SET storage_deleted_at = COALESCE(storage_deleted_at, clock_timestamp()) "
                "WHERE file_location = %s",
                (location,),
            )
            return sorted(row["analysis_id"] for row in rows)

    def location_referenced(self, location: str) -> bool:
        with self._connection() as connection:
            return connection.execute(
                "SELECT EXISTS (SELECT 1 FROM api_analyses WHERE file_location = %s AND storage_deleted_at IS NULL) AS found",
                (location,),
            ).fetchone()["found"]

    def record_artifact(self, reference: ArtifactReference, token: str) -> bool:
        # Revalidate even if a caller hands us an object constructed elsewhere.
        reference = ArtifactReference(**reference.to_dict())
        with self._connection() as connection:
            row = connection.execute(
                "SELECT sha256 FROM api_analyses WHERE " + _OWNED + " FOR UPDATE",
                (reference.analysis_id, token),
            ).fetchone()
            if row is None:
                return False
            if row["sha256"] != reference.sha256:
                raise BackendError(
                    "ARTIFACT_IDENTITY_CONFLICT",
                    "Artifact belongs to another sample",
                    http_status=409,
                )
            payload = reference.to_dict()
            connection.execute(
                """INSERT INTO api_analysis_artifacts
                (sha256, analysis_id, tool, tool_run_id, name, file_location, content_sha256,
                 size_bytes, created_at, media_type, tool_version, config_sha256, schema_version)
                VALUES (%(sha256)s, %(analysis_id)s, %(tool)s, %(tool_run_id)s, %(name)s,
                    %(file_location)s, %(content_sha256)s, %(size_bytes)s, %(created_at)s::timestamptz,
                    %(media_type)s, %(tool_version)s, %(config_sha256)s, %(schema_version)s)
                ON CONFLICT (analysis_id, tool, tool_run_id, name) DO NOTHING""",
                payload,
            )
            existing = connection.execute(
                "SELECT * FROM api_analysis_artifacts WHERE analysis_id = %s AND tool = %s AND tool_run_id = %s AND name = %s",
                (
                    reference.analysis_id,
                    reference.tool,
                    reference.tool_run_id,
                    reference.name,
                ),
            ).fetchone()
            if any(
                existing[key] != value
                for key, value in payload.items()
                if key != "created_at"
            ):
                raise BackendError(
                    "ARTIFACT_CONFLICT",
                    "An immutable artifact reference already exists",
                    http_status=409,
                )
            return True

    def list_artifacts(self, analysis_id: str) -> list[ArtifactReference]:
        with self._connection() as connection:
            return [
                ArtifactReference(**{**row, "created_at": _iso(row["created_at"])})
                for row in connection.execute(
                    "SELECT * FROM api_analysis_artifacts WHERE analysis_id = %s ORDER BY created_at, tool, tool_run_id, name",
                    (analysis_id,),
                ).fetchall()
            ]

    def save_review(
        self,
        analysis_id: str,
        *,
        analyst_final_verdict: str | None,
        analyst_notes: str,
        reviewer_id: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        validate_review(
            analyst_final_verdict, analyst_notes, reviewer_id, expected_revision
        )
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT analysis_id, status, review_revision, initial_result, deep_result FROM api_analyses WHERE sha256 = (SELECT sha256 FROM api_analyses WHERE analysis_id = %s) FOR UPDATE",
                (analysis_id,),
            ).fetchall()
            row = next((r for r in rows if r["analysis_id"] == analysis_id), None)
            if row is None:
                raise BackendError(
                    "ANALYSIS_NOT_FOUND", "Analysis was not found", http_status=404
                )
            if row["status"] not in {"COMPLETED", "FAILED"}:
                raise BackendError(
                    "ANALYSIS_NOT_FINISHED",
                    "Analysis must finish before analyst review",
                    http_status=409,
                )
            if row["review_revision"] != expected_revision:
                raise BackendError(
                    "REVIEW_CONFLICT",
                    "A newer analyst review already exists",
                    http_status=409,
                )

            initial_result = row["initial_result"] or {}
            deep_result = row["deep_result"] or {}
            initial_verdict = initial_result.get("initial_verdict")
            triggered_signals = initial_result.get("triggered_signals") or []
            risk_signals = initial_result.get("risk_signals") or {}
            prob = initial_result.get("prediction", {}).get("calibrated_probability")
            try:
                prob_float = float(prob) if prob is not None and prob != "" else -1.0
            except (ValueError, TypeError):
                prob_float = -1.0

            q = self._determine_queue(
                prob_float,
                initial_verdict,
                triggered_signals,
                risk_signals,
                deep_result,
            )
            queue_name = q["queue_name"]
            score_policy = q["score_policy"]

            revision = expected_revision + 1
            review = connection.execute(
                """INSERT INTO api_reviews
                   (review_id, analysis_id, revision, analyst_final_verdict, analyst_notes, reviewer_id, review_status, review_queue, review_policy)
                   VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING *""",
                (
                    str(uuid4()),
                    analysis_id,
                    revision,
                    analyst_final_verdict,
                    analyst_notes,
                    reviewer_id,
                    "PENDING" if analyst_final_verdict is None else "COMPLETED",
                    queue_name,
                    score_policy,
                ),
            ).fetchone()
            connection.execute(
                """UPDATE api_analyses SET review_revision = %s, analyst_final_verdict = %s,
                   updated_at = clock_timestamp() WHERE analysis_id = %s""",
                (revision, analyst_final_verdict, analysis_id),
            )
            return _review(review)

    def list_reviews(self, analysis_id: str) -> list[dict[str, Any]]:
        with self._connection() as connection:
            return [
                _review(row)
                for row in connection.execute(
                    "SELECT * FROM api_reviews WHERE analysis_id = %s ORDER BY revision",
                    (analysis_id,),
                ).fetchall()
            ]


def _lock_samples(connection, hashes):
    for sample_hash in hashes:
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (sample_hash,)
        )


def registration_input(analyses, batch_id, idempotency_key, input_report=None):
    """Validate before DB access; IDs/locations intentionally do not define replay identity."""
    minimum = 0 if batch_id is not None and input_report is not None else 1
    if not isinstance(analyses, list) or not minimum <= len(analyses) <= 100:
        raise ValueError("invalid number of registered analyses")
    if batch_id is None and len(analyses) != 1:
        raise ValueError("multiple analyses require a batch_id")
    if batch_id is not None:
        _identifier(batch_id, "batch_id")
    if idempotency_key is not None and (
        not isinstance(idempotency_key, str)
        or not 1 <= len(idempotency_key) <= 200
        or any(ord(char) < 33 or ord(char) > 126 for char in idempotency_key)
    ):
        raise ValueError(
            "idempotency_key must contain 1-200 printable ASCII characters"
        )
    normalized = []
    for value in analyses:
        if not isinstance(value, Mapping) or set(value) != {
            "analysis_id",
            "sha256",
            "file_location",
            "filename",
            "size_bytes",
        }:
            raise ValueError("analysis input has missing or unknown fields")
        item = dict(value)
        _identifier(item["analysis_id"], "analysis_id")
        _hash(item["sha256"])
        for name, maximum in (("file_location", 4096), ("filename", 512)):
            if (
                not isinstance(item[name], str)
                or not 1 <= len(item[name]) <= maximum
                or "\x00" in item[name]
            ):
                raise ValueError(
                    f"{name} must be nonempty text within its length limit"
                )
        size = item["size_bytes"]
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or not 0 <= size <= 2**63 - 1
        ):
            raise ValueError("size_bytes must be a nonnegative 64-bit integer")
        normalized.append(item)
    if len({item["analysis_id"] for item in normalized}) != len(normalized):
        raise ValueError("analysis IDs must be unique within a request")
    locations = {}
    for item in normalized:
        identity = (item["sha256"], item["size_bytes"])
        if locations.setdefault(item["file_location"], identity) != identity:
            raise ValueError("shared storage locations must identify identical bytes")
    kind = "BATCH" if batch_id is not None else "SINGLE"
    identity = {
        "kind": kind,
        "inputs": [
            {name: item[name] for name in ("sha256", "size_bytes", "filename")}
            for item in normalized
        ],
    }
    if input_report is not None:
        if batch_id is None or not isinstance(input_report, BatchInputReport):
            raise ValueError("input reports require a batch and a validated report")
        report = BatchInputReport.model_validate(input_report.model_dump(mode="json"))
        accepted = [entry for entry in report.entries if entry.status == "ACCEPTED"]
        if not report.entries or len(accepted) != len(normalized):
            raise ValueError("input report must account for every accepted analysis")
        for entry, item in zip(accepted, normalized):
            if (entry.analysis_id, entry.sha256, entry.size_bytes) != (
                item["analysis_id"],
                item["sha256"],
                item["size_bytes"],
            ):
                raise ValueError(
                    "input report identity does not match registered analyses"
                )
        if report.source_type == "ZIP":
            # Archive bytes bind ALL entries, including encrypted/unsupported ones.
            # Admission limits may change between retries; they do not change input identity.
            identity = {
                "kind": kind,
                "archive": {
                    name: getattr(report, name)
                    for name in (
                        "archive_filename",
                        "archive_sha256",
                        "archive_size_bytes",
                    )
                },
            }
        elif any(entry.status == "SKIPPED" for entry in report.entries):
            if any(
                entry.sha256 is None or entry.size_bytes is None
                for entry in report.entries
            ):
                raise ValueError("direct batch entries require content hashes")
            identity["all_inputs"] = [
                {
                    name: getattr(entry, name)
                    for name in ("filename", "sha256", "size_bytes")
                }
                for entry in report.entries
            ]
    encoded = json.dumps(
        identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return normalized, hashlib.sha256(encoded.encode("utf-8")).hexdigest(), kind


_LIST_ORDER = {
    "newest": "created_at DESC, analysis_id DESC",
    "input_order": "batch_position, analysis_id",
    "high_risk_first": """CASE WHEN status = 'FAILED' THEN 4
        WHEN initial_result ->> 'initial_verdict' = 'HIGH_RISK_UNCERTAIN' THEN 0
        WHEN initial_result ->> 'initial_verdict' = 'AUTO_MALICIOUS' THEN 1
        WHEN initial_result ->> 'initial_verdict' = 'AUTO_BENIGN' THEN 2
        ELSE 3 END, created_at DESC, analysis_id DESC""",
}


def validate_listing(batch_id, verdict, sort):
    if batch_id is not None:
        _identifier(batch_id, "batch_id")
    if verdict is not None and verdict not in {item.value for item in InitialVerdict}:
        raise ValueError("unknown initial verdict")
    if sort not in _LIST_ORDER or (sort == "input_order" and batch_id is None):
        raise ValueError("invalid result sort order")


def json_object(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("Analysis state must be a JSON object")
    try:
        encoded = json.dumps(dict(value), ensure_ascii=False, allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_STATE_BYTES:
            raise ValueError("Analysis state exceeds the 8 MiB limit")
        return json.loads(encoded)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError(
            "Analysis state must be finite JSON within the 8 MiB limit"
        ) from exc


def validate_review(verdict, notes, reviewer, revision):
    if verdict is not None and verdict not in {"BENIGN", "MALICIOUS"}:
        raise ValueError("Analyst verdict must be BENIGN, MALICIOUS, or null")
    if not isinstance(notes, str) or len(notes) > 10000 or "\x00" in notes:
        raise ValueError("Analyst notes must be text of at most 10000 characters")
    if (
        not isinstance(reviewer, str)
        or not reviewer.strip()
        or len(reviewer) > 128
        or "\x00" in reviewer
    ):
        raise ValueError("reviewer_id must be nonempty text of at most 128 characters")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
        raise ValueError("expected_revision must be a nonnegative integer")


def _positive_int(value, name):
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _limit(value):
    _positive_int(value, "limit")
    if value > 100:
        raise ValueError("limit must not exceed 100")


def _lease(value):
    _positive_int(value, "lease_seconds")
    if value > 43200:
        raise ValueError("lease_seconds must not exceed 43200")


def _identifier(value, name):
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name} must be an identifier of 1-128 characters")


def _hash(value):
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError("sha256 must be 64 lowercase hexadecimal characters")


def _aware_datetime(value):
    parsed = (
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        if isinstance(value, str)
        else value
    )
    if (
        not isinstance(parsed, datetime)
        or parsed.tzinfo is None
        or parsed.utcoffset() is None
    ):
        raise ValueError("A timezone-aware timestamp is required")
    return parsed.astimezone(timezone.utc)


def _iso(value):
    return _aware_datetime(value).isoformat() if value is not None else None


def _record(row):
    keys = AnalysisRecord.__dataclass_fields__
    payload = {name: row[name] for name in keys}
    for name in ("created_at", "updated_at", "completed_at", "storage_deleted_at"):
        payload[name] = _iso(payload[name])
    return AnalysisRecord(**payload)


def _review(row):
    return {
        "review_id": str(row["review_id"]),
        "analysis_id": row["analysis_id"],
        "revision": row["revision"],
        "analyst_final_verdict": row["analyst_final_verdict"],
        "analyst_notes": row["analyst_notes"],
        "reviewer_id": row["reviewer_id"],
        "review_status": row["review_status"],
        "reviewed_at": _iso(row["reviewed_at"]),
    }
