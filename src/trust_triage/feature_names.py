"""SHAP feature 이름을 사람이 읽을 수 있는 라벨로 옮긴다.

SHAP 결과의 ``feature_name`` 은 ``그룹명[그룹 내 위치]`` 형식의 raw 식별자다
(``ember_v3._build_schema`` 가 만들고 selection manifest 를 거쳐 그대로 전달된다).
thrember 는 원소별 이름을 제공하지 않으므로, 여기서는 고정된 thrember 커밋의
``features.py`` 가 벡터를 조립하는 순서(``process_raw_features`` 의 ``hstack``)를
정적 표로 옮겨 라벨을 만든다.

표는 아래 커밋과 Schema 버전에 종속된다. 다른 Schema 버전이 들어오면 라벨을
추측하지 않고 raw 이름을 그대로 돌려준다 — 그룹 차원이 같아도 원소 순서가
달라졌을 수 있기 때문이다.

feature hashing 을 거친 원소(section 이름별 통계, import/export 이름, Rich
header 쌍)는 한 bucket 에 여러 원본이 섞이므로 원래 이름을 복원할 수 없다.
이들은 "Import API hash bucket #k" 처럼 그룹 수준으로만 표기한다. EMBER 의
import 특징을 API 이름으로 되돌린 것처럼 보이게 하면 안 된다 — API 이름 근거는
``feature_extraction.api_groups`` 가 별도로 담당한다.

이 모듈은 thrember 도, ``trust_triage.explanation``(lightgbm/shap 를 import 시점에
불러온다)도 import 하지 않는다. 백엔드 API 프로세스가 무거운 의존성 없이 라벨만
붙일 수 있도록 패키지 최상위에 둔다. 표가 pin 커밋과 같은지는
``tests/test_feature_names.py`` 가 설치된 thrember 의 파일을 직접 읽어 대조한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Literal

# 이 표가 유효한 thrember 커밋과 Feature Schema 버전. 둘 다 requirements.txt /
# docs/feature-extraction/ember-v3-schema.json 과 같아야 한다.
THREMBER_COMMIT = "0ef753e81d98bf209f71b03cd331dfc190b5b54d"
SCHEMA_VERSION = "ember2024-v3-pe-873e612248d4"

FeatureKind = Literal["exact", "hashed", "unknown"]

_FEATURE_NAME = re.compile(r"^(?P<group>[^\[\]]+)\[(?P<index>\d+)\]$")


@dataclass(frozen=True)
class ResolvedFeature:
    """raw feature 이름 하나에 대한 표시 정보."""

    feature_name: str
    display_name: str
    kind: FeatureKind
    group: str | None = None


# --- thrember features.py 의 리스트를 그대로 옮긴 것 ---------------------------
# HeaderFileInfo.__init__ (COFF Characteristics 비트, 이 순서로 one-hot)
IMAGE_CHARACTERISTICS = (
    "RELOCS_STRIPPED",
    "EXECUTABLE_IMAGE",
    "LINE_NUMS_STRIPPED",
    "LOCAL_SYMS_STRIPPED",
    "AGGRESIVE_WS_TRIM",
    "LARGE_ADDRESS_AWARE",
    "16BIT_MACHINE",
    "BYTES_REVERSED_LO",
    "32BIT_MACHINE",
    "DEBUG_STRIPPED",
    "REMOVABLE_RUN_FROM_SWAP",
    "NET_RUN_FROM_SWAP",
    "SYSTEM",
    "DLL",
    "UP_SYSTEM_ONLY",
    "BYTES_REVERSED_HI",
)

# HeaderFileInfo.__init__ (OPTIONAL_HEADER DllCharacteristics 비트)
DLL_CHARACTERISTICS = (
    "HIGH_ENTROPY_VA",
    "DYNAMIC_BASE",
    "FORCE_INTEGRITY",
    "NX_COMPAT",
    "NO_ISOLATION",
    "NO_SEH",
    "NO_BIND",
    "APPCONTAINER",
    "WDM_DRIVER",
    "GUARD_CF",
    "TERMINAL_SERVER_AWARE",
)

# HeaderFileInfo.__init__ (DOS 헤더 필드)
DOS_MEMBERS = (
    "e_magic",
    "e_cblp",
    "e_cp",
    "e_crlc",
    "e_cparhdr",
    "e_minalloc",
    "e_maxalloc",
    "e_ss",
    "e_sp",
    "e_csum",
    "e_ip",
    "e_cs",
    "e_lfarlc",
    "e_ovno",
    "e_oemid",
    "e_oeminfo",
    "e_lfanew",
)

# DataDirectories.__init__ (_name_order). 마지막 RESERVED 는 thrember 루프가
# 건너뛰므로 값이 항상 0 이다.
DATA_DIRECTORY_NAMES = (
    "EXPORT",
    "IMPORT",
    "RESOURCE",
    "EXCEPTION",
    "SECURITY",
    "BASERELOC",
    "DEBUG",
    "COPYRIGHT",
    "GLOBALPTR",
    "TLS",
    "LOAD_CONFIG",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT",
    "COM_DESCRIPTOR",
    "RESERVED",
)

# StringExtractor: regex_idxs = enumerate(sorted(self._regexes)) 이므로 정렬 순서
STRING_PATTERNS = (
    ".click(",
    "/EmbeddedFile",
    "/FlateDecode",
    "/URI",
    "/bin/",
    "/dev/",
    "/proc/",
    "/tmp/",
    "/usr/",
    "<script",
    "Invoke-Command",
    "Invoke-Expression",
    "Start-process",
    "base64",
    "base64string",
    "btc_wallet",
    "cache",
    "certificate",
    "clipboard",
    "command",
    "connect",
    "cookie",
    "create",
    "crypt",
    "debug",
    "decode",
    "delete",
    "desktop",
    "directory",
    "disk",
    "dos_msg",
    "download",
    "email_addr",
    "encode",
    "enum",
    "environment",
    "exit",
    "file",
    "file_path",
    "ftp",
    "get",
    "hidden",
    "hostname",
    "html",
    "http",
    "http://",
    "https://",
    "install",
    "internet",
    "ipv4_addr",
    "ipv6_addr",
    "javascript",
    "keyboard",
    "mac_addr",
    "memory",
    "module",
    "mutex",
    "onlick",
    "password",
    "post",
    "powershell",
    "privilege",
    "process",
    "registry_key",
    "remote",
    "resource",
    "security",
    "service",
    "shell",
    "snapshot",
    "system",
    "thread",
    "token",
    "url",
    "useragent",
    "wallet",
    "window",
)

# PEFormatWarnings: thrember/pefile_warnings.txt 의 줄 순서 = one-hot 위치.
# "..." 로 끝나면 접두 일치, "..." 로 시작하면 접미 일치로 정규화한 패턴이다.
PEFILE_WARNINGS = (
    "AddressOfEntryPoint lies outside the sections' boundaries...",
    "Bad RVA in relocation data...",
    "Byte 0x...",
    "Corrupt header...",
    "Damaged Import Table information...",
    "Don't know how to parse LOAD_CONFIG information for non-PE32...",
    "Error, too many imported symbols...",
    "Error parsing a resource directory data entry...",
    "Error parsing export directory at RVA...",
    "Error parsing resource of type RT_STRING at...",
    "Error parsing StringFileInfo/VarFileInfo struct...",
    "Error parsing the Delay import directory...",
    "Error parsing the Delay import directory at RVA...",
    "Error parsing the import directory at RVA...",
    "Error parsing the import directory. Invalid Import data at RVA...",
    "Error parsing the import table. Entries go beyond bounds...",
    "Error parsing the import table. AddressOfData overlaps with THUNK_DATA for THUNK at RVA...",
    "Error parsing the import table. Invalid data at RVA...",
    "Error parsing the resources directory. Excessively nested table depth...",
    "Error parsing the resources directory. The directory contains...",
    "Error parsing the resources directory. The file contains at least...",
    "Error parsing the resources directory. Entry...",
    "Error parsing the resources directory, attempting to read entry name. Entry names overlap...",
    "Error parsing the resources directory, attempting to read entry name. Can't read unicode string at offset...",
    "Error parsing the version information, attempting to read OffsetToData with RVA...",
    "Error parsing the version information, attempting to read VS_VERSION_INFO string...",
    "Error parsing the version information, attempting to read VarFileInfo Var string...",
    "Error parsing the version information, attempting to read StringFileInfo string...",
    "Error parsing the version information, attempting to read StringTable string...",
    "Error parsing the version information, attempting to read StringTable Key string...",
    "Error parsing the version information, to read StringTable Value string...",
    "Excessive number of imports...",
    "Export directory contains more than 10 repeated entries...",
    "Failed parsing FunctionEntry of UNWIND_INFO at...",
    "Failed rendering pascal string, attempting to read from RVA 0x...",
    "Failed rendering unicode string, attempting to read from RVA 0x...",
    "Failed to process directory...",
    "FunctionEntry of UNWIND_INFO at...",
    "If SectionAlignment...",
    "If FileAlignment > 0x200 it should be a power of 2. Value...",
    "Imported symbols contain entries typical of packed executables...",
    "Invalid bdd dynamic relocation...",
    "Invalid bdd info...",
    "Invalid debug information...",
    "Invalid function override header...",
    "Invalid function override info...",
    "Invalid IMAGE_DYNAMIC_RELOCATION_TABLE information...",
    "Invalid LOAD_CONFIG information...",
    "Invalid relocation information. Can't read...",
    "Invalid relocation information. SizeOfBlock too large...",
    "Invalid relocation information. VirtualAddress outside...",
    "Invalid resources directory. Can't read...",
    "Invalid resources directory. Can't parse directory data at RVA...",
    "Invalid TLS information. Can't read...",
    "Invalid type 0x...",
    "Invalid VS_VERSION_INFO block...",
    "No parsing available for IMAGE_DYNAMIC_RELOCATION_TABLE...",
    "Overlapping offsets in relocation data...",
    "Possibly corrupt file. AddressOfEntryPoint lies outside the file...",
    "Relocating image but PE does not have (or pefile cannot parse) a DIRECTORY_ENTRY_BASERELOC...",
    "Resource size...",
    "Rich Header is malformed...",
    "Rich Header is not in Microsoft format, possibly malformed...",
    "RVA AddressOfFunctions in the export directory points to an invalid...",
    "RVA AddressOfNames in the export directory points to an invalid...",
    "RVA of IMAGE_BOUND_IMPORT_DESCRIPTOR points...",
    "SizeOfHeaders is smaller than AddressOfEntryPoint...",
    "Suspicious flags set for section...",
    "Suspicious NumberOfRvaAndSizes in the Optional Header...",
    "Suspicious value found parsing section...",
    "The Bound Imports directory exists but can't be parsed...",
    "Too many warnings parsing section. Aborting...",
    "Too many errors parsing the Delay import directory...",
    "Too many errors parsing the import directory...",
    "Too many sections...",
    "Unknown UNWIND_CODE at...",
    "Unsupported version of UNWIND_INFO...",
    "...Contents are null-bytes.",
    "...No data in the file (is this corkami's virtsectblXP?).",
    "...PointerToRawData points beyond the end of the file.",
    "...PointerToRawData should normally be a multiple of FileAlignment, this might imply the file is trying to confuse tools which parse this incorrectly.",
    "...SizeOfRawData is larger than file.",
    "...VirtualSize is extremely large > 256MiB",
    "...VirtualAddress is beyond 0x10000000",
    "...symbol entries. Assuming corrupt.",
    "...ordinal entries. Assuming corrupt.",
    "...Assuming corrupt.",
)

# HeaderFileInfo.process_raw_features 의 스칼라 30개 (hstack 순서)
_HEADER_SCALARS = (
    "COFF Timestamp",
    "Number Of Sections",
    "Number Of Symbols",
    "Size Of Optional Header",
    "Pointer To Symbol Table",
    "Machine Type (categorical code)",
    "Subsystem (categorical code)",
    "Major Image Version",
    "Minor Image Version",
    "Major Linker Version",
    "Minor Linker Version",
    "Major OS Version",
    "Minor OS Version",
    "Major Subsystem Version",
    "Minor Subsystem Version",
    "Size Of Code",
    "Size Of Headers",
    "Size Of Image",
    "Size Of Initialized Data",
    "Size Of Uninitialized Data",
    "Size Of Stack Reserve",
    "Size Of Stack Commit",
    "Size Of Heap Reserve",
    "Size Of Heap Commit",
    "Address Of Entry Point",
    "Base Of Code",
    "Image Base",
    "Section Alignment",
    "Checksum",
    "Number Of RVAs And Sizes",
)

# SectionInfo.process_raw_features 의 general 11개. min 계열은 리스트에 0 이
# 항상 들어 있어 값이 0 으로 고정된다.
_SECTION_GENERAL = (
    "Section Count",
    "Zero-Size Section Count",
    "Unnamed Section Count",
    "Read/Execute Section Count",
    "Writable Section Count",
    "Max Section/Overlay Entropy",
    "Min Section/Overlay Entropy (always 0)",
    "Max Section/Overlay Size Ratio",
    "Min Section/Overlay Size Ratio (always 0)",
    "Max Section Virtual Size Ratio",
    "Min Section Virtual Size Ratio (always 0)",
)

_GENERAL = (
    "File Size (bytes)",
    "File Byte Entropy",
    "Is Parsed PE",
    "First Byte Value",
    "Second Byte Value",
    "Third Byte Value",
    "Fourth Byte Value",
)

# AuthenticodeSignature.process_raw_features 순서
_AUTHENTICODE = (
    "Certificate Count",
    "Self-Signed Certificate",
    "Empty Program Name",
    "No Countersigner",
    "Signature Parse Error",
    "Certificate Chain Max Depth",
    "Latest Signing Time",
    "Signing Time Difference",
)


def _warning_label(pattern: str) -> str:
    # 정규화 패턴의 "..." 자리표시만 떼어 낸다. 문구 자체는 pefile 원문이다.
    text = pattern[3:] if pattern.startswith("...") else pattern[:-3]
    return f"PE Warning: {text.strip()}"


# 그룹별 레이아웃: (원소 수, 종류, 그룹 내 위치 -> 라벨). 합이 thrember 그룹 차원과
# 같아야 하며, 그 검증은 _LAYOUT 조립 직후에 한다.
_Segment = tuple[int, FeatureKind, Callable[[int], str]]


def _fixed(labels: tuple[str, ...], kind: FeatureKind = "exact") -> _Segment:
    return (len(labels), kind, lambda i: labels[i])


def _bucket(count: int, label: str) -> _Segment:
    return (count, "hashed", lambda i: f"{label} hash bucket #{i}")


def _data_directory_label(i: int) -> str:
    name = DATA_DIRECTORY_NAMES[i // 2]
    label = f"{name.title().replace('_', ' ')} Directory "
    label += "Size" if i % 2 == 0 else "Virtual Address"
    if name == "RESERVED":
        label += " (always 0)"
    return label


_LAYOUT: dict[str, tuple[_Segment, ...]] = {
    "general": (_fixed(_GENERAL),),
    "histogram": ((256, "exact", lambda i: f"Byte 0x{i:02X} Frequency"),),
    # ByteEntropyHistogram: (16 entropy bins x 16 byte nibbles).flatten()
    "byteentropy": (
        (
            256,
            "exact",
            lambda i: f"Byte-Entropy Bin (entropy {i // 16}/16, byte nibble 0x{i % 16:X})",
        ),
    ),
    # StringExtractor.process_raw_features hstack 순서 (docstring 의 5+96+76 과
    # 달리 실제는 3 + 96 + 1 + 77 = 177)
    "strings": (
        _fixed(("String Count", "Average String Length", "Printable Character Count")),
        (96, "exact", lambda i: f"Printable Char {chr(0x20 + i)!r} Share"),
        _fixed(("String Character Entropy",)),
        (
            len(STRING_PATTERNS),
            "exact",
            lambda i: f"String Pattern Count: {STRING_PATTERNS[i]}",
        ),
    ),
    "header": (
        _fixed(_HEADER_SCALARS),
        (
            len(IMAGE_CHARACTERISTICS),
            "exact",
            lambda i: f"File Characteristic Flag: {IMAGE_CHARACTERISTICS[i]}",
        ),
        (
            len(DLL_CHARACTERISTICS),
            "exact",
            lambda i: f"DLL Characteristic Flag: {DLL_CHARACTERISTICS[i]}",
        ),
        (len(DOS_MEMBERS), "exact", lambda i: f"DOS Header {DOS_MEMBERS[i]}"),
    ),
    "section": (
        _fixed(_SECTION_GENERAL),
        _bucket(50, "Section size"),
        _bucket(50, "Section virtual size"),
        _bucket(50, "Section entropy"),
        _bucket(50, "Section characteristics"),
        _bucket(10, "Entry-point section name"),
        _fixed(("Overlay Size", "Overlay Size Ratio", "Overlay Entropy")),
    ),
    "imports": (
        _fixed(("Imported Function Count", "Imported Library Count")),
        _bucket(256, "Import library"),
        _bucket(1024, "Import API"),
    ),
    "exports": (
        # thrember 는 export 개수가 아니라 해시 벡터 길이(항상 128)를 넣는다.
        _fixed(("Export Hash Vector Length (0 or 128)",)),
        _bucket(128, "Export name"),
    ),
    "datadirectories": (
        (2 * len(DATA_DIRECTORY_NAMES), "exact", _data_directory_label),
        _fixed(("Has Relocations", "Has Dynamic Relocations")),
    ),
    "richheader": (
        _fixed(("Rich Header Entry Count",)),
        _bucket(32, "Rich header entry"),
    ),
    "authenticode": (_fixed(_AUTHENTICODE),),
    "pefilewarnings": (
        (len(PEFILE_WARNINGS), "exact", lambda i: _warning_label(PEFILE_WARNINGS[i])),
        _fixed(("PE Warning Count",)),
    ),
}

# ember-v3-schema.json 의 그룹 차원. 표가 어긋나면 import 시점에 바로 실패한다.
GROUP_DIMENSIONS: dict[str, int] = {
    "general": 7,
    "histogram": 256,
    "byteentropy": 256,
    "strings": 177,
    "header": 74,
    "section": 224,
    "imports": 1282,
    "exports": 129,
    "datadirectories": 34,
    "richheader": 33,
    "authenticode": 8,
    "pefilewarnings": 88,
}

for _group, _segments in _LAYOUT.items():
    _total = sum(count for count, _, _ in _segments)
    if _total != GROUP_DIMENSIONS[_group]:
        raise AssertionError(
            f"feature_names layout for {_group!r} has {_total} elements, "
            f"schema says {GROUP_DIMENSIONS[_group]}"
        )


def _lookup(group: str, index: int) -> tuple[str, FeatureKind] | None:
    segments = _LAYOUT.get(group)
    if segments is None:
        return None
    for count, kind, label in segments:
        if index < count:
            return label(index), kind
        index -= count
    return None


def resolve(feature_name: str, *, schema_version: str | None) -> ResolvedFeature:
    """raw feature 이름을 표시 정보로 옮긴다.

    Schema 버전이 이 표의 것과 다르거나, 이름 형식이 맞지 않거나, 그룹/범위를
    모르면 ``kind="unknown"`` 에 raw 이름을 그대로 ``display_name`` 으로 돌려준다.
    호출자가 별도 fallback 을 쓰지 않아도 되게 하기 위해서다.
    """

    match = _FEATURE_NAME.fullmatch(feature_name or "")
    if match is None:
        return ResolvedFeature(feature_name, feature_name, "unknown")

    group = match.group("group")
    if schema_version != SCHEMA_VERSION:
        return ResolvedFeature(feature_name, feature_name, "unknown", group)

    found = _lookup(group, int(match.group("index")))
    if found is None:
        return ResolvedFeature(feature_name, feature_name, "unknown", group)

    label, kind = found
    return ResolvedFeature(feature_name, label, kind, group)


def display_name(feature_name: str, *, schema_version: str | None) -> str:
    return resolve(feature_name, schema_version=schema_version).display_name
