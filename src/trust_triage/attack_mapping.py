"""Conservative CAPA/Speakeasy-to-MITRE ATT&CK label normalization."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from .evidence import AttackTechnique


_TECHNIQUE_ID_PATTERN = re.compile(
    r"(?<![A-Z0-9])T\d{4}(?:\.\d{3})?(?!\d)",
    re.IGNORECASE,
)

_TECHNIQUE_CATALOG: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1027": ("Obfuscated Files or Information", ("Defense Evasion",)),
    "T1053": ("Scheduled Task/Job", ("Execution", "Persistence")),
    "T1053.005": (
        "Scheduled Task/Job: Scheduled Task",
        ("Execution", "Persistence"),
    ),
    "T1055": ("Process Injection", ("Defense Evasion", "Privilege Escalation")),
    "T1055.012": (
        "Process Hollowing",
        ("Defense Evasion", "Privilege Escalation"),
    ),
    "T1059": ("Command and Scripting Interpreter", ("Execution",)),
    "T1059.001": ("PowerShell", ("Execution",)),
    "T1112": ("Modify Registry", ("Defense Evasion",)),
    "T1543": (
        "Create or Modify System Process",
        ("Persistence", "Privilege Escalation"),
    ),
    "T1543.003": (
        "Create or Modify System Process: Windows Service",
        ("Persistence", "Privilege Escalation"),
    ),
    "T1547.001": (
        "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        ("Persistence", "Privilege Escalation"),
    ),
    "T1620": ("Reflective Code Loading", ("Defense Evasion",)),
}

_LABEL_ALIASES: tuple[tuple[str, str], ...] = (
    ("process hollowing", "T1055.012"),
    ("process injection", "T1055"),
    ("create remote thread", "T1055"),
    ("create or modify system process", "T1543"),
    ("create service", "T1543.003"),
    ("windows service", "T1543.003"),
    ("registry run keys", "T1547.001"),
    ("startup folder", "T1547.001"),
    ("modify registry", "T1112"),
    ("scheduled task job", "T1053"),
    ("scheduled task", "T1053.005"),
    ("powershell", "T1059.001"),
    ("command and scripting interpreter", "T1059"),
    ("reflective code loading", "T1620"),
    ("obfuscated files or information", "T1027"),
)


def normalize_attack_label(label: Any) -> AttackTechnique:
    """Normalize one label without dropping unknown values."""

    raw_label = "" if label is None else str(label).strip()
    if not raw_label:
        return AttackTechnique(
            technique_id=None,
            technique_name="",
            source_label=raw_label,
            mapping_status="UNMAPPED",
        )

    id_match = _TECHNIQUE_ID_PATTERN.search(raw_label.upper())
    if id_match is not None:
        technique_id = id_match.group(0).upper()
        return _technique_from_id(
            technique_id,
            source_label=raw_label,
            fallback_name=_display_name(raw_label, technique_id),
        )

    normalized = _normalize_for_match(raw_label)
    for alias, technique_id in _LABEL_ALIASES:
        if _normalize_for_match(alias) in normalized:
            return _technique_from_id(
                technique_id,
                source_label=raw_label,
                fallback_name=_display_name(raw_label, technique_id),
            )

    return AttackTechnique(
        technique_id=None,
        technique_name=_display_name(raw_label, None),
        source_label=raw_label,
        mapping_status="UNMAPPED",
    )


def normalize_attack_labels(labels: Iterable[Any] | None) -> tuple[AttackTechnique, ...]:
    """Normalize labels and de-duplicate repeated technique references."""

    if labels is None:
        return ()

    normalized: list[AttackTechnique] = []
    seen: set[str] = set()
    for label in labels:
        technique = normalize_attack_label(label)
        key = (
            technique.technique_id
            or _normalize_for_match(technique.source_label)
            or technique.technique_name
        )
        if key in seen:
            continue
        seen.add(key)
        normalized.append(technique)
    return tuple(normalized)


def technique_display_name(technique: AttackTechnique) -> str:
    """Return the analyst-facing ``[Txxxx] Name`` label."""

    if technique.technique_id:
        return f"[{technique.technique_id}] {technique.technique_name}"
    return technique.technique_name or technique.source_label


def _technique_from_id(
    technique_id: str,
    *,
    source_label: str,
    fallback_name: str,
) -> AttackTechnique:
    catalog_entry = _TECHNIQUE_CATALOG.get(technique_id)
    if catalog_entry is None:
        return AttackTechnique(
            technique_id=technique_id,
            technique_name=fallback_name,
            source_label=source_label,
            mapping_status="ID_ONLY",
        )

    technique_name, tactics = catalog_entry
    return AttackTechnique(
        technique_id=technique_id,
        technique_name=technique_name,
        tactics=tactics,
        source_label=source_label,
        mapping_status="MAPPED",
    )


def _display_name(label: str, technique_id: str | None) -> str:
    if technique_id is not None:
        catalog_entry = _TECHNIQUE_CATALOG.get(technique_id)
        if catalog_entry is not None:
            return catalog_entry[0]

    parts = [part.strip() for part in re.split(r"::|:|/|\\", label)]
    return next((part for part in reversed(parts) if part), label)


def _normalize_for_match(value: str) -> str:
    lowered = value.casefold().replace("_", " ")
    return " ".join(re.findall(r"[a-z0-9]+", lowered))
