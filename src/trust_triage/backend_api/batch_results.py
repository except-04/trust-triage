"""Batch receipts and progress views; initial verdicts stay separate from job status."""

from collections import Counter

from . import views
from .repository import AnalysisRecord, BatchRecord, validate_listing
from .schemas import (
    BatchAccepted,
    BatchInputEntry,
    BatchResponse,
    BatchStatus,
    BatchSummary,
)


def _receipt(batch: BatchRecord) -> dict:
    report = batch.input_report
    # Requests registered before the receipt migration contain accepted jobs only.
    entries = (
        report.entries
        if report is not None
        else [
            BatchInputEntry(
                input_index=index,
                filename=row.filename,
                status="ACCEPTED",
                analysis_id=row.analysis_id,
                sha256=row.sha256,
                size_bytes=row.size_bytes,
            )
            for index, row in enumerate(batch.analyses)
        ]
    )
    accepted = sum(entry.status == "ACCEPTED" for entry in entries)
    return {
        "input_count": len(entries),
        "accepted_count": accepted,
        "skipped_count": len(entries) - accepted,
        "entries": entries,
        "archive_file_count": len(entries)
        if report and report.source_type == "ZIP"
        else None,
    }


def accepted(batch: BatchRecord) -> BatchAccepted:
    return BatchAccepted(
        batch_id=batch.batch_id,
        total_count=len(batch.analyses),
        analyses=[views.accepted(row) for row in batch.analyses],
        **_receipt(batch),
    )


def priority(row: AnalysisRecord) -> int:
    if row.status == "FAILED":
        return 4
    return {"HIGH_RISK_UNCERTAIN": 0, "AUTO_MALICIOUS": 1, "AUTO_BENIGN": 2}.get(
        (row.initial_result or {}).get("initial_verdict"), 3
    )


def ordered(rows: list[AnalysisRecord], sort: str) -> list[AnalysisRecord]:
    if sort == "input_order":
        return list(rows)
    result = sorted(
        rows, key=lambda row: (row.created_at, row.analysis_id), reverse=True
    )
    if sort == "high_risk_first":
        result.sort(key=priority)
    return result


def _status(summary: BatchSummary) -> BatchStatus:
    active = summary.queued + summary.running
    finished = summary.completed + summary.failed
    if not active:
        return (
            BatchStatus.FAILED
            if summary.total and summary.failed == summary.total
            else BatchStatus.COMPLETED
        )
    if finished:
        return BatchStatus.PARTIALLY_COMPLETED
    return BatchStatus.RUNNING if summary.running else BatchStatus.QUEUED


def response(batch: BatchRecord, *, sort: str = "high_risk_first") -> BatchResponse:
    validate_listing(batch.batch_id, None, sort)
    counts = Counter(row.status for row in batch.analyses)
    verdicts = Counter(
        (row.initial_result or {}).get("initial_verdict") for row in batch.analyses
    )
    summary = BatchSummary(
        total=len(batch.analyses),
        queued=counts["QUEUED"],
        running=counts["RUNNING"],
        completed=counts["COMPLETED"],
        failed=counts["FAILED"],
        auto_benign=verdicts["AUTO_BENIGN"],
        auto_malicious=verdicts["AUTO_MALICIOUS"],
        high_risk_uncertain=verdicts["HIGH_RISK_UNCERTAIN"],
        unclassified=sum(
            count
            for verdict, count in verdicts.items()
            if verdict not in {"AUTO_BENIGN", "AUTO_MALICIOUS", "HIGH_RISK_UNCERTAIN"}
        ),
    )
    return BatchResponse(
        batch_id=batch.batch_id,
        total_count=summary.total,
        finished_count=summary.completed + summary.failed,
        status_counts={
            state: counts[state]
            for state in ("QUEUED", "RUNNING", "COMPLETED", "FAILED")
        },
        status=_status(summary),
        summary=summary,
        analyses=[views.analysis(row) for row in ordered(batch.analyses, sort)],
        **_receipt(batch),
    )
