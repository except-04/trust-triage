"""PE Import Table의 API를 사람이 이해하기 쉬운 그룹으로 분류한다.

이 모듈의 결과는 EMBER v3의 2568차원 모델 입력을 대체하지 않는다.
원본 PE에 선언된 Import를 읽어서 설명, Evidence, JRR 위험 신호로 활용하기
위한 별도 메타데이터다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

import pefile


API_GROUPS_SCHEMA_VERSION = "api-groups-mvp-v1"

# API 이름은 대소문자를 구분하지 않고 비교한다.
# 목록은 팀에서 제안한 초기 MVP 목록이며, 이후 근거를 확인해 확장할 수 있다.
DEFAULT_API_GROUPS: dict[str, tuple[str, ...]] = {
    "registry": (
        "RegSetValueExW",
        "RegSetValueExA",
        "RegCreateKeyExW",
        "RegCreateKeyExA",
        "RegDeleteKeyW",
        "RegOpenKeyExW",
    ),
    "injection": (
        "WriteProcessMemory",
        "CreateRemoteThread",
        "VirtualAllocEx",
        "SetWindowsHookExW",
        "NtUnmapViewOfSection",
    ),
    "network": (
        "InternetOpenA",
        "InternetOpenUrlA",
        "send",
        "recv",
        "WSAStartup",
        "connect",
        "URLDownloadToFileA",
    ),
}


def _decode_import_name(value: bytes | str | None) -> str:
    """pefile이 반환한 DLL/API 이름을 안전한 문자열로 변환한다."""

    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip()
    return str(value).strip()


def _normalize_name(value: str) -> str:
    """API 이름 비교를 위해 대소문자 차이를 제거한다."""

    return value.casefold()


@dataclass(frozen=True)
class ApiGroupMatch:
    """하나의 API 그룹에서 발견된 Import 정보를 표현한다."""

    matched: bool
    match_count: int
    apis: tuple[str, ...]
    dlls: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """JSON 출력에 사용할 사전으로 변환한다."""

        return {
            "matched": self.matched,
            "match_count": self.match_count,
            "apis": list(self.apis),
            "dlls": list(self.dlls),
        }


@dataclass(frozen=True)
class ApiGroupReport:
    """PE Import Table을 API 그룹별로 분류한 전체 결과."""

    schema_version: str
    source: str
    named_import_count: int
    ordinal_import_count: int
    groups: dict[str, ApiGroupMatch]

    def to_dict(self) -> dict[str, object]:
        """JSON 출력에 사용할 사전으로 변환한다."""

        return {
            "schema_version": self.schema_version,
            "source": self.source,
            "named_import_count": self.named_import_count,
            "ordinal_import_count": self.ordinal_import_count,
            "groups": {
                name: match.to_dict() for name, match in self.groups.items()
            },
        }


def _prepare_groups(
    groups: Mapping[str, Iterable[str]],
) -> dict[str, dict[str, str]]:
    """사용자 설정을 비교용 정규화 목록으로 변환한다."""

    prepared: dict[str, dict[str, str]] = {}
    for group_name, api_names in groups.items():
        if not group_name.strip():
            raise ValueError("API group name must not be empty")

        normalized: dict[str, str] = {}
        for api_name in api_names:
            display_name = str(api_name).strip()
            if display_name:
                normalized[_normalize_name(display_name)] = display_name
        prepared[group_name] = normalized
    return prepared


def classify_imports(
    pe: pefile.PE,
    *,
    groups: Mapping[str, Iterable[str]] = DEFAULT_API_GROUPS,
) -> ApiGroupReport:
    """PE의 정적 Import Table을 API 그룹별로 분류한다.

    Import Table에 이름이 기록된 정적 Import만 확인한다. 동적으로 로드되는
    API, 난독화된 API, ordinal만 있는 Import는 정확한 함수명을 알 수 없으므로
    API 그룹 매칭 대상에서 제외하고 별도로 개수를 기록한다.
    """

    prepared_groups = _prepare_groups(groups)
    matched_pairs: dict[str, list[tuple[str, str]]] = {
        group_name: [] for group_name in prepared_groups
    }
    seen_pairs: dict[str, set[tuple[str, str]]] = {
        group_name: set() for group_name in prepared_groups
    }

    named_import_count = 0
    ordinal_import_count = 0
    import_entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []

    for import_entry in import_entries:
        dll_name = _decode_import_name(getattr(import_entry, "dll", None))
        for imported in getattr(import_entry, "imports", []) or []:
            api_name = _decode_import_name(getattr(imported, "name", None))
            if not api_name:
                ordinal_import_count += 1
                continue

            named_import_count += 1
            normalized_api_name = _normalize_name(api_name)
            for group_name, api_names in prepared_groups.items():
                if normalized_api_name not in api_names:
                    continue

                pair = (dll_name, api_name)
                if pair not in seen_pairs[group_name]:
                    seen_pairs[group_name].add(pair)
                    matched_pairs[group_name].append(pair)

    group_results: dict[str, ApiGroupMatch] = {}
    for group_name, pairs in matched_pairs.items():
        api_names = tuple(dict.fromkeys(api_name for _, api_name in pairs))
        dll_names = tuple(dict.fromkeys(dll_name for dll_name, _ in pairs))
        group_results[group_name] = ApiGroupMatch(
            matched=bool(pairs),
            match_count=len(pairs),
            apis=api_names,
            dlls=dll_names,
        )

    return ApiGroupReport(
        schema_version=API_GROUPS_SCHEMA_VERSION,
        source="PE_IMPORT_TABLE",
        named_import_count=named_import_count,
        ordinal_import_count=ordinal_import_count,
        groups=group_results,
    )
