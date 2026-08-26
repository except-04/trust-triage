"""Convert CAPA and Speakeasy outputs into one Evidence contract."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from ..attack_mapping import (
    normalize_attack_labels,
    technique_display_name,
)
from ..evidence import Evidence, EvidenceStatus


_INJECTION_APIS = {
    "createremotethread",
    "createremotethreadex",
    "ntcreatethreadex",
    "rtlcreateuserthread",
    "queueuserapc",
    "setthreadcontext",
}
_INJECTION_MEMORY_APIS = {
    "virtualallocex",
    "ntallocatevirtualmemory",
    "writeprocessmemory",
    "ntwritevirtualmemory",
}
_SERVICE_APIS = {"createservicea", "createservicew", "openscmanagera", "openscmanagerw"}


def normalize_capa_result(
    result: Any,
    *,
    reliability: float = 0.8,
) -> tuple[Evidence, ...]:
    """Return normalized CAPA evidence, excluding tool failures."""

    if _status_value(result) != "SUCCESS":
        return ()

    to_evidence = getattr(result, "to_evidence", None)
    if not callable(to_evidence):
        return ()
    return tuple(to_evidence(reliability=reliability))


def normalize_speakeasy_result(
    result: Any,
    *,
    sha256: str | None = None,
    reliability: float = 0.75,
) -> tuple[Evidence, ...]:
    """Normalize the dynamic branch's Speakeasy result without importing it.

    The dynamic branch exposes a dataclass with ``to_dict()``.  Accepting a
    mapping as well keeps this boundary usable when the result arrives over
    an API or a queue.  A timeout or unsupported API never becomes malicious
    evidence; only observations from a successful run are converted.
    """

    payload = _payload(result)
    if _status_value(payload) != "SUCCESS":
        return ()

    sample_sha256 = str(payload.get("sha256") or sha256 or "")
    base_id = str(payload.get("evidence_id") or f"speakeasy-{sample_sha256[:16] or 'unknown'}")
    observed_apis = _strings(payload.get("observed_apis"))
    behaviors = _strings(payload.get("behaviors"))
    events = payload.get("events")
    techniques = _observed_techniques(observed_apis, behaviors)
    tool_status = str(payload.get("status") or "SUCCESS")

    evidence: list[Evidence] = []
    for index, technique in enumerate(techniques, start=1):
        evidence.append(
            Evidence(
                evidence_id=f"evt-{base_id}-attack-{index:04d}",
                sha256=sample_sha256,
                source="SPEAKEASY",
                category="ATTACK_TECHNIQUE",
                severity=0.85,
                reliability=reliability,
                summary=(
                    "Speakeasy observed ATT&CK candidate: "
                    f"{technique_display_name(technique)}"
                ),
                status=EvidenceStatus.OBSERVED,
                raw_reference=str(payload.get("raw_reference") or ""),
                details={
                    "tool_status": tool_status,
                    "observed_apis": list(observed_apis),
                    "behaviors": list(behaviors),
                    "event_categories": _event_categories(events),
                    "attack_techniques": [technique.to_dict()],
                },
                attack_techniques=(technique,),
            )
        )

    # Preserve useful successful observations even when they do not yet map
    # to an ATT&CK technique.  The sufficiency policy deliberately ignores
    # this low-weight item and therefore will not overstate generic behavior.
    if not techniques and (observed_apis or behaviors):
        evidence.append(
            Evidence(
                evidence_id=f"evt-{base_id}-behavior-0001",
                sha256=sample_sha256,
                source="SPEAKEASY",
                category="BEHAVIOR_OBSERVED",
                severity=0.35,
                reliability=min(reliability, 0.65),
                summary=(
                    f"Speakeasy observed {len(observed_apis)} API(s) and "
                    f"{len(behaviors)} behavior group(s)."
                ),
                status=EvidenceStatus.OBSERVED,
                raw_reference=str(payload.get("raw_reference") or ""),
                details={
                    "tool_status": tool_status,
                    "observed_apis": list(observed_apis),
                    "behaviors": list(behaviors),
                    "event_categories": _event_categories(events),
                },
            )
        )
    return tuple(evidence)


def _observed_techniques(
    observed_apis: Sequence[str],
    behaviors: Sequence[str],
) -> tuple[Any, ...]:
    labels: list[str] = list(behaviors)
    api_names = {_api_basename(api) for api in observed_apis}

    # A single generic API is not enough to assert injection.  A thread
    # creation API is a strong direct signal; memory allocation plus writing
    # into another process is treated as a candidate combination.
    if api_names & _INJECTION_APIS or len(api_names & _INJECTION_MEMORY_APIS) >= 2:
        labels.append("Process Injection")
    if api_names & _SERVICE_APIS:
        labels.append("Create Service")

    return tuple(
        technique
        for technique in normalize_attack_labels(labels)
        if technique.technique_id is not None
    )


def _payload(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        converted = to_dict()
        if isinstance(converted, Mapping):
            return dict(converted)
    return {
        name: getattr(value, name)
        for name in (
            "evidence_id",
            "sha256",
            "status",
            "source",
            "raw_reference",
            "observed_apis",
            "behaviors",
            "events",
        )
        if hasattr(value, name)
    }


def _status_value(value: Any) -> str:
    if isinstance(value, Mapping):
        status = value.get("status")
    else:
        status = getattr(value, "status", None)
    if hasattr(status, "value"):
        status = status.value
    return str(status or "").upper()


def _strings(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return tuple(str(item) for item in value if str(item).strip())
    return (str(value),)


def _api_basename(value: str) -> str:
    normalized = value.casefold().split("!")[-1].split(".")[-1]
    return re.sub(r"[^a-z0-9]", "", normalized)


def _event_categories(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return []
    return sorted(str(key) for key in value)
