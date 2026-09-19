"""Harmless service doubles; persisted state is detached via JSON like PostgreSQL."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from speakeasy_worker.fakes import (
    SAMPLE,
    SAMPLE_SHA256,
    FakeSamples,
    MemoryQueue,
)
from speakeasy_worker.fakes import (
    MemoryRepository as WorkerMemoryRepository,
)

from trust_triage.attack_mapping import normalize_attack_labels
from trust_triage.deep_analysis import (
    DeepAnalysisOrchestrator,
    Evidence,
    EvidenceStatus,
    LLMInterpretation,
    LLMInterpretationStatus,
)
from trust_triage.deep_analysis.service import DeepAnalysisService, DeepServiceLimits
from trust_triage.deep_analysis.service_models import (
    DeepAnalysisClaim,
    DeepAnalysisPhase,
    DeepAnalysisRecord,
    DeepAnalysisRequest,
)
from trust_triage.dynamic_analysis import DynamicAnalysisResult, DynamicAnalysisStatus
from trust_triage.speakeasy_worker.errors import RetryableError
from trust_triage.speakeasy_worker.models import (
    JobConflict,
    JobStatus,
    result_from_analysis,
)
from trust_triage.speakeasy_worker.publisher import JobPublisher


def detached(value):
    return json.loads(json.dumps(value, allow_nan=False))


class MemoryDeepRepository:
    def __init__(self):
        self.rows = {}
        self.leases = {}
        self.now = 1000
        self.failures = Counter()
        self.calls = Counter()
        self.on_save = None

    def initialize(self):
        pass

    def check(self):
        pass

    def _fault(self, operation):
        self.calls[operation] += 1
        if self.failures[operation] > 0:
            self.failures[operation] -= 1
            raise RetryableError(
                "DATABASE_ERROR", "Synthetic transient persistence failure"
            )

    def register(self, request, config_fingerprint):
        self._fault("register")
        if request.analysis_id not in self.rows:
            self.rows[request.analysis_id] = DeepAnalysisRecord(
                request, config_fingerprint
            )
        row = self.rows[request.analysis_id]
        if (
            not row.request.same_input(request)
            or row.config_fingerprint != config_fingerprint
        ):
            raise JobConflict("different input or configuration")
        return self.get(request.analysis_id)

    def get(self, analysis_id):
        self._fault("get")
        row = self.rows.get(analysis_id)
        if row is None:
            return None
        lease = self.leases.get(analysis_id)
        return replace(
            row,
            checkpoint=detached(row.checkpoint),
            result=detached(row.result),
            last_error=detached(row.last_error),
            claimed=bool(lease and lease[1] > self.now),
        )

    def pending_ids(self, limit=10):
        return [
            key
            for key, row in self.rows.items()
            if not row.phase.terminal and not self.get(key).claimed and self._ready(row)
        ][:limit]

    @staticmethod
    def _ready(row):
        next_retry_at = (row.last_error or {}).get("next_retry_at")
        return not next_retry_at or datetime.now(
            timezone.utc
        ) >= datetime.fromisoformat(next_retry_at)

    def claim(self, analysis_id, lease_seconds):
        self._fault("claim")
        row = self.get(analysis_id)
        if row is None:
            raise ValueError("unknown analysis")
        if row.phase.terminal or row.claimed or not self._ready(row):
            return DeepAnalysisClaim(row)
        token = str(uuid4())
        self.leases[analysis_id] = (token, self.now + lease_seconds)
        self.rows[analysis_id] = replace(row, attempts=row.attempts + 1)
        return DeepAnalysisClaim(self.get(analysis_id), token)

    def owns(self, analysis_id, token):
        lease = self.leases.get(analysis_id)
        return bool(
            lease
            and lease[0] == token
            and lease[1] > self.now
            and not self.rows[analysis_id].phase.terminal
        )

    def renew(self, analysis_id, token, lease_seconds):
        self._fault("renew")
        if not self.owns(analysis_id, token):
            return False
        self.leases[analysis_id] = (token, self.now + lease_seconds)
        return True

    def save_checkpoint(self, analysis_id, token, checkpoint, phase):
        self._fault("save_checkpoint")
        if not self.owns(analysis_id, token):
            return False
        row = self.rows[analysis_id]
        if row.phase is DeepAnalysisPhase.FINALIZING and phase is not row.phase:
            return False
        self.rows[analysis_id] = replace(
            row,
            phase=phase,
            checkpoint=detached(checkpoint),
            last_error=None,
        )
        if self.on_save:
            self.on_save(self.get(analysis_id))
        return True

    def finish(self, analysis_id, token, result):
        self._fault("finish")
        if not self.owns(analysis_id, token):
            return False
        status = result["deep_analysis_status"]
        phase = DeepAnalysisPhase("COMPLETED" if status == "COMPLETE" else status)
        self.rows[analysis_id] = replace(
            self.rows[analysis_id],
            phase=phase,
            result=detached(result),
            last_error=None,
        )
        self.leases.pop(analysis_id, None)
        return True

    def release(self, analysis_id, token, error=None):
        self._fault("release")
        if not self.owns(analysis_id, token):
            return False
        row = self.rows[analysis_id]
        self.rows[analysis_id] = replace(
            row,
            last_error=detached(error),
        )
        self.leases.pop(analysis_id, None)
        return True

    def retry_due(self, analysis_id):
        row = self.rows[analysis_id]
        self.rows[analysis_id] = replace(
            row,
            last_error={
                **(row.last_error or {}),
                "next_retry_at": "2000-01-01T00:00:00+00:00",
            },
        )


class StaticResult:
    def __init__(self, source, *, sufficient=False, status="SUCCESS"):
        self.source, self.status = source, status
        self.sha256 = SAMPLE_SHA256
        self.evidence = Evidence(
            evidence_id=f"{source.lower()}-saved-evidence",
            sha256=self.sha256,
            source=source,
            category="CAPABILITY_MATCH" if source == "CAPA" else "OBFUSCATED_STRING",
            severity=0.7 if sufficient else 0.2,
            reliability=0.8 if source == "CAPA" else 0.55,
            summary="Synthetic static observation from harmless test bytes",
            status=EvidenceStatus.OBSERVED,
            details={"string": "https://example.invalid/fixture"},
            attack_techniques=normalize_attack_labels(("Process Injection",))
            if sufficient
            else (),
        )

    def to_evidence(self, *, reliability=0.8, max_strings=64):
        del max_strings
        return (
            (replace(self.evidence, reliability=reliability),)
            if self.status == "SUCCESS"
            else ()
        )

    def to_dict(self):
        return {
            "sha256": self.sha256,
            "source": self.source,
            "status": self.status,
            "summary": self.evidence.summary,
            "errors": [],
        }


class StaticAnalyzer:
    def __init__(self, source, *, sufficient=False):
        self.result = StaticResult(source, sufficient=sufficient)
        self.calls = 0
        self.callback = None

    def analyze(self, path):
        assert path.read_bytes() == SAMPLE
        self.calls += 1
        if self.callback:
            self.callback()
        return self.result


class FakeInterpreter:
    def __init__(self):
        self.calls = 0
        self.inputs = []

    def interpret(self, evidence, *, sha256, initial_verdict):
        assert sha256 == SAMPLE_SHA256
        assert initial_verdict == "UNKNOWN"
        self.calls += 1
        self.inputs.append(tuple(evidence))
        return LLMInterpretation(
            status=LLMInterpretationStatus.SUCCESS,
            verdict="MALICIOUS",
            confidence=0.9,
            supporting_evidence_ids=tuple(item.evidence_id for item in evidence),
            attack_techniques=("T1055",),
            summary="Synthetic interpretation",
            manual_review_required=True,
            model="fake-model",
        )


def dynamic_result(status=DynamicAnalysisStatus.SUCCESS):
    return DynamicAnalysisResult(
        evidence_id="worker-observation",
        sha256=SAMPLE_SHA256,
        source="SPEAKEASY",
        category="DYNAMIC_ANALYSIS",
        status=status,
        summary="Synthetic emulation observation",
        observed_apis=("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"),
        events={"api_calls": ({"api_name": "CreateRemoteThread"},)},
        errors=()
        if status is DynamicAnalysisStatus.SUCCESS
        else ("Synthetic tool failure",),
        tool_version="fake-speakeasy",
        started_at="2026-09-08T00:00:00+00:00",
        completed_at="2026-09-08T00:00:01+00:00",
    )


class FakeDynamicAnalyzer:
    def __init__(self):
        self.calls = 0

    def analyze(self, path):
        assert path.read_bytes() == SAMPLE
        self.calls += 1
        return dynamic_result()


def complete_worker(repository, request, result=None):
    claim = repository.claim(request.worker_job, 180)
    assert claim.token
    payload = result or result_from_analysis(request.worker_job, dynamic_result())
    assert repository.finish(request.analysis_id, claim.token, payload)
    assert repository.get(request.analysis_id).status in {
        JobStatus.COMPLETED,
        JobStatus.FAILED,
    }
    return payload


class ServiceHarness:
    def __init__(
        self, root: Path, *, sufficient=False, repository=None, worker_repository=None
    ):
        self.request = DeepAnalysisRequest(
            "deep-service-test",
            SAMPLE_SHA256,
            "s3://test-bucket/samples/harmless.bin",
            "DEEP_ANALYSIS",
        )
        self.repository = repository or MemoryDeepRepository()
        self.worker_repository = worker_repository or WorkerMemoryRepository()
        self.queue = MemoryQueue()
        self.samples = FakeSamples(root)
        self.capa = StaticAnalyzer("CAPA", sufficient=sufficient)
        self.floss = StaticAnalyzer("FLOSS")
        self.llm = FakeInterpreter()
        self.service = self.restart()

    def restart(self, *, config=None, limits=None):
        self.service = DeepAnalysisService(
            repository=self.repository,
            publisher=JobPublisher(self.worker_repository, self.queue),
            samples=self.samples,
            orchestrator=DeepAnalysisOrchestrator(
                capa_analyzer=self.capa,
                floss_analyzer=self.floss,
                llm_interpreter=self.llm,
                config=config,
            ),
            limits=limits or DeepServiceLimits(),
        )
        return self.service

    @property
    def calls(self):
        return self.capa.calls, self.floss.calls, self.llm.calls, self.samples.calls
