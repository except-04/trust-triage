"""Bounded CreateService return values shared by adapter and Worker compaction."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_SERVICE_CREATION_APIS = {"createservicea", "createservicew"}
_MAX_SERVICE_CALL_SUMMARY = 256


class ServiceCallAccumulator:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.total = 0

    def observe(self, event: Mapping[str, Any], event_index: int) -> None:
        name = re.sub(
            r"[^a-z0-9]",
            "",
            str(event.get("api_name") or "").casefold().split("!")[-1].split(".")[-1],
        )
        if name not in _SERVICE_CREATION_APIS:
            return
        self.total += 1
        if len(self.calls) >= _MAX_SERVICE_CALL_SUMMARY:
            return
        item: dict[str, Any] = {"api_name": name, "event_index": event_index}
        for field in ("ret_val", "retval", "return_value", "return"):
            if field not in event:
                continue
            value = event[field]
            if isinstance(value, (str, int, bool)) or value is None:
                if isinstance(value, str) and len(value) > 64:
                    item["return_truncated"] = True
                else:
                    item[field] = value
            break
        self.calls.append(item)

    def to_dict(self) -> dict[str, Any]:
        return {
            "calls": list(self.calls),
            "total": self.total,
            "complete": self.total <= _MAX_SERVICE_CALL_SUMMARY,
        }


def service_creation_calls(events: Mapping[str, Any]) -> dict[str, Any]:
    """Summarize all available API calls before the Worker shortens events."""

    accumulator = ServiceCallAccumulator()
    for index, event in enumerate(events.get("api_calls", ())):
        if isinstance(event, Mapping):
            accumulator.observe(event, index)
    return accumulator.to_dict()
