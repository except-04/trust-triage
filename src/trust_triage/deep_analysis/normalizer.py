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
_INJECTION_ALLOCATION_APIS = {
    "virtualallocex",
    "ntallocatevirtualmemory",
}
_INJECTION_WRITE_APIS = {
    "writeprocessmemory",
    "ntwritevirtualmemory",
}
_SERVICE_CREATION_APIS = {"createservicea", "createservicew"}
_OBSERVATION_FIELDS = (
    "api_name", "path", "file_path", "src_path", "dst_path", "destination",
    "host", "ip", "port", "url", "key", "ret_val", "retval", "return_value",
    "event", "query", "response", "server", "proto", "method", "type",
    "pid", "entry_point",
)
_OBSERVATION_CATEGORIES = (
    "network_events", "file_access", "dropped_files", "registry_access",
    "api_calls", "process_events",
)


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


def normalize_floss_result(
    result: Any,
    *,
    reliability: float = 0.55,
    max_strings: int = 64,
) -> tuple[Evidence, ...]:
    """Normalize the static branch's FLOSS result without importing it.

    FLOSS is owned by ``feature/static-analysis``. Keeping this boundary
    duck-typed lets the deep-analysis branch accept the implementation from
    that branch without copying its subprocess or parser code.
    """

    if _status_value(result) != "SUCCESS":
        return ()
    to_evidence = getattr(result, "to_evidence", None)
    if not callable(to_evidence):
        return ()
    return tuple(
        to_evidence(
            reliability=reliability,
            max_strings=max_strings,
        )
    )


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
    base_id = str(
        payload.get("evidence_id") or f"speakeasy-{sample_sha256[:16] or 'unknown'}"
    )
    observed_apis = _strings(payload.get("observed_apis"))
    behaviors = _strings(payload.get("behaviors"))
    events = payload.get("events")
    metadata = payload.get("metadata")
    event_counts = metadata.get("event_counts") if isinstance(metadata, Mapping) else None
    events_truncated = (
        metadata.get("events_truncated") is True
        if isinstance(metadata, Mapping)
        else False
    )
    techniques = _observed_techniques(observed_apis, behaviors, events, metadata)
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
                    "observations": _bounded_observations(events),
                    "event_counts": event_counts if isinstance(event_counts, Mapping) else {},
                    "events_truncated": events_truncated,
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
                    "observations": _bounded_observations(events),
                    "event_counts": event_counts if isinstance(event_counts, Mapping) else {},
                    "events_truncated": events_truncated,
                },
            )
        )
    return tuple(evidence)


def _observed_techniques(
    observed_apis: Sequence[str],
    behaviors: Sequence[str],
    events: Any = None,
    metadata: Any = None,
) -> tuple[Any, ...]:
    labels: list[str] = list(behaviors)
    api_names = {_api_basename(api) for api in observed_apis}

    # A single generic API is not enough to assert injection.  A thread
    # creation API is a strong direct signal; memory allocation plus writing
    # into another process is treated as a candidate combination.
    if api_names & _INJECTION_APIS or (
        api_names & _INJECTION_ALLOCATION_APIS
        and api_names & _INJECTION_WRITE_APIS
    ):
        labels.append("Process Injection")
    if _successful_service_creation(api_names, events, metadata):
        labels.append("Create Service")

    return tuple(
        technique
        for technique in normalize_attack_labels(labels)
        if technique.technique_id is not None
    )


def _successful_service_creation(
    api_names: set[str], events: Any, metadata: Any = None
) -> bool:
    if not api_names & _SERVICE_CREATION_APIS:
        return False
    if isinstance(metadata, Mapping) and metadata.get("events_truncated") is True:
        # The remaining events may omit a failed call. A compact return-value
        # record from the full pre-truncation input is the only positive basis.
        summary = metadata.get("service_creation_calls")
        calls = summary.get("calls") if isinstance(summary, Mapping) else None
        return isinstance(calls, list) and any(
            isinstance(call, Mapping) and _explicit_call_success(call)
            for call in calls
        )
    if not isinstance(events, Mapping):
        return True
    api_calls = events.get("api_calls")
    if not isinstance(api_calls, Sequence) or isinstance(
        api_calls, (str, bytes, bytearray)
    ):
        return True
    matching_calls = [
        call
        for call in api_calls
        if isinstance(call, Mapping)
        and _api_basename(str(call.get("api_name") or "")) in _SERVICE_CREATION_APIS
    ]
    if not matching_calls:
        return True
    return any(not _explicit_call_failure(call) for call in matching_calls)


def _explicit_call_success(call: Mapping[str, Any]) -> bool:
    for name in ("ret_val", "retval", "return_value", "return"):
        if name not in call:
            continue
        value = call[name]
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        if isinstance(value, str):
            normalized = value.strip().casefold()
            if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", normalized):
                return int(normalized, 16 if normalized.startswith("0x") else 10) != 0
        return False
    return False


def _explicit_call_failure(call: Mapping[str, Any]) -> bool:
    for name in ("ret_val", "retval", "return_value", "return"):
        if name not in call:
            continue
        value = call[name]
        if value is None or value is False or value == 0:
            return True
        if isinstance(value, str):
            normalized = value.strip().casefold()
            if normalized in {"", "false", "none", "null"}:
                return True
            if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", normalized):
                return int(normalized, 16 if normalized.startswith("0x") else 10) == 0
        return False
    return False


def _bounded_observations(events: Any) -> list[dict[str, Any]]:
    """Keep a small allowlisted sample of actual dynamic observations."""

    if not isinstance(events, Mapping):
        return []
    rows: dict[str, list[tuple[Mapping[str, Any], dict[str, Any]]]] = {}
    for category in _OBSERVATION_CATEGORIES:
        values = events.get(category)
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
            continue
        if category != "network_events":
            rows[category] = [
                (event, {"event_index": index})
                for index, event in enumerate(values[:8])
                if isinstance(event, Mapping)
            ]
            continue
        network_rows: list[tuple[Mapping[str, Any], dict[str, Any]]] = []
        for event_index, event in enumerate(values):
            if not isinstance(event, Mapping):
                continue
            nested = {
                kind: items
                for kind in ("dns", "traffic")
                if isinstance((items := event.get(kind)), Sequence)
                and not isinstance(items, (str, bytes, bytearray))
            }
            if not nested:
                network_rows.append((event, {"event_index": event_index}))
            else:
                entry_point = event.get("entry_point")
                for item_index in range(8):
                    for kind, items in nested.items():
                        if item_index < len(items) and isinstance(items[item_index], Mapping):
                            location = {
                                "event_index": event_index,
                                "kind": kind,
                                "item_index": item_index,
                            }
                            if isinstance(entry_point, (int, str)):
                                location["entry_point"] = str(entry_point)[:32]
                            network_rows.append(
                                (
                                    items[item_index],
                                    location,
                                )
                            )
                        if len(network_rows) >= 8:
                            break
                    if len(network_rows) >= 8:
                        break
            if len(network_rows) >= 8:
                break
        rows[category] = network_rows[:8]
    observations: list[dict[str, Any]] = []
    # Rotate through categories so many API calls cannot hide file/network data.
    for index in range(8):
        for category in _OBSERVATION_CATEGORIES:
            category_rows = rows.get(category, ())
            if index >= len(category_rows):
                continue
            event, location = category_rows[index]
            observation: dict[str, Any] = {"category": category, **location}
            for field in _OBSERVATION_FIELDS:
                value = event.get(field)
                if isinstance(value, (str, int, float, bool)):
                    observation[field] = str(value)[:160]
            args = event.get("args")
            if isinstance(args, Sequence) and not isinstance(
                args, (str, bytes, bytearray)
            ):
                pairs = []
                for arg_index, argument in enumerate(args[:4]):
                    if isinstance(argument, Mapping):
                        name, value = argument.get("name"), argument.get("value")
                        if isinstance(name, str) and isinstance(value, (str, int, float, bool)):
                            pairs.append(f"{name[:40]}={str(value)[:120]}")
                    elif isinstance(argument, (str, int, float, bool)):
                        pairs.append(f"arg[{arg_index}]={str(argument)[:120]}")
                if pairs:
                    observation["arguments"] = "; ".join(pairs)[:400]
            if len(observation) > 2:
                observations.append(observation)
                if len(observations) == 8:
                    return observations
    return observations


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
