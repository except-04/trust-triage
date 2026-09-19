"""SHAP feature 이름 → 표시용 라벨.

라벨 표는 고정된 thrember 커밋의 features.py 조립 순서를 옮긴 것이다. 관심사는
세 가지다: (1) 표가 pin 커밋의 실제 파일과 같은가, (2) 해시 특성을 특정 이름으로
복원하지 않는가, (3) 모르는 것은 추측하지 않고 raw 이름으로 돌아가는가.

thrember 는 import 하지 않는다 — 이 venv 에서는 signify 버전 차이로 import 자체가
실패하며, 그 문제는 이 작업 범위가 아니다. 대신 설치 위치를 find_spec 으로 찾아
파일을 직접 읽어 대조한다.
"""

from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path

import pytest

from trust_triage import feature_names as fn


REPO = Path(__file__).parents[1]
SCHEMA_JSON = REPO / "docs" / "feature-extraction" / "ember-v3-schema.json"
MANIFEST_JSON = (
    REPO / "docs" / "feature-extraction" / "feature-selection-ember-v3-top500.json"
)
V = fn.SCHEMA_VERSION


def _thrember_dir() -> Path | None:
    """설치된 thrember 패키지 디렉터리. 모듈을 실행하지 않고 위치만 찾는다."""
    spec = importlib.util.find_spec("thrember")
    if spec is None or not spec.submodule_search_locations:
        return None
    return Path(next(iter(spec.submodule_search_locations)))


def _thrember_lists(features_py: Path) -> dict[str, list[str]]:
    """features.py 를 AST 로 읽어 __init__ 의 리스트/dict 키를 뽑는다."""
    tree = ast.parse(features_py.read_text(encoding="utf-8"))
    found: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        init = next(
            (n for n in node.body if isinstance(n, ast.FunctionDef) and n.name == "__init__"),
            None,
        )
        if init is None:
            continue
        for stmt in init.body:
            if not isinstance(stmt, ast.Assign) or not isinstance(
                stmt.targets[0], ast.Attribute
            ):
                continue
            name = stmt.targets[0].attr
            if isinstance(stmt.value, ast.List):
                found[name] = [ast.literal_eval(e) for e in stmt.value.elts]
            elif isinstance(stmt.value, ast.Dict) and name == "_regexes":
                found[name] = [ast.literal_eval(k) for k in stmt.value.keys]
    return found


# --- 1. 요청된 5개 feature 의 고정 회귀 ---------------------------------------


@pytest.mark.parametrize(
    "name,label,kind",
    [
        ("header[43]", "File Characteristic Flag: DLL", "exact"),
        ("pefilewarnings[67]", "PE Warning: Suspicious flags set for section", "exact"),
        ("header[9]", "Major Linker Version", "exact"),
        ("section[3]", "Read/Execute Section Count", "exact"),
        ("datadirectories[12]", "Debug Directory Size", "exact"),
    ],
)
def test_reviewed_features_resolve_to_verified_labels(name, label, kind):
    resolved = fn.resolve(name, schema_version=V)
    assert resolved.display_name == label
    assert resolved.kind == kind
    assert resolved.feature_name == name  # raw 식별자는 건드리지 않는다


def test_reviewed_features_sit_at_the_verified_global_and_selected_indices():
    """분석에서 확인한 global(2568) / Top500 위치가 체크인된 manifest 와 같다."""
    manifest = json.loads(MANIFEST_JSON.read_text(encoding="utf-8"))
    names, sources = manifest["feature_names"], manifest["source_indices"]
    expected = {
        "header[43]": (739, 233),
        "pefilewarnings[67]": (2547, 497),
        "header[9]": (705, 209),
        "section[3]": (773, 243),
        "datadirectories[12]": (2417, 437),
    }
    for name, (global_index, selected_index) in expected.items():
        assert names[selected_index] == name
        assert sources[selected_index] == global_index


# --- 2. 표 vs 체크인된 Schema / pin 된 thrember ----------------------------------


def test_group_dimensions_match_the_checked_in_schema():
    schema = json.loads(SCHEMA_JSON.read_text(encoding="utf-8"))
    assert schema["schema_version"] == V
    assert {g["name"]: g["dimension"] for g in schema["groups"]} == fn.GROUP_DIMENSIONS
    assert [g["name"] for g in schema["groups"]] == list(fn.GROUP_DIMENSIONS)


def test_every_top500_feature_gets_a_label_without_guessing():
    manifest = json.loads(MANIFEST_JSON.read_text(encoding="utf-8"))
    assert manifest["source_schema_version"] == V
    kinds = {}
    for name in manifest["feature_names"]:
        resolved = fn.resolve(name, schema_version=V)
        kinds[resolved.kind] = kinds.get(resolved.kind, 0) + 1
        assert resolved.display_name  # 비어 있지 않다
        if resolved.kind == "hashed":
            assert "hash bucket #" in resolved.display_name
        else:
            assert resolved.display_name != name
    assert "unknown" not in kinds
    # docs/feature_schema.md 의 블록별 개수: 해시 197 / 나머지 303
    assert kinds == {"exact": 303, "hashed": 197}


def test_every_index_of_every_group_is_covered_exactly_once():
    for group, dimension in fn.GROUP_DIMENSIONS.items():
        labels = [fn.resolve(f"{group}[{i}]", schema_version=V) for i in range(dimension)]
        assert all(r.kind != "unknown" for r in labels)
        assert len({r.display_name for r in labels}) == dimension  # 라벨 충돌 없음
        assert fn.resolve(f"{group}[{dimension}]", schema_version=V).kind == "unknown"


def test_pinned_commit_matches_requirements_and_extractor_constant():
    requirements = (REPO / "requirements.txt").read_text(encoding="utf-8")
    assert f"EMBER2024.git@{fn.THREMBER_COMMIT}" in requirements
    source = (
        REPO / "src" / "trust_triage" / "feature_extraction" / "ember_v3.py"
    ).read_text(encoding="utf-8")
    assert f'"{fn.THREMBER_COMMIT}"' in source


def test_tables_match_the_installed_thrember_files():
    """설치된 thrember 의 리스트·경고 파일과 정적 표가 원소 단위로 같다."""
    location = _thrember_dir()
    if location is None or not (location / "features.py").exists():
        pytest.skip("thrember is not installed")

    lists = _thrember_lists(location / "features.py")
    assert tuple(lists["_image_characteristics"]) == fn.IMAGE_CHARACTERISTICS
    assert tuple(lists["_dll_characteristics"]) == fn.DLL_CHARACTERISTICS
    assert tuple(lists["_dos_members"]) == fn.DOS_MEMBERS
    assert tuple(lists["_name_order"]) == fn.DATA_DIRECTORY_NAMES
    # StringExtractor: regex_idxs = enumerate(sorted(self._regexes))
    assert tuple(sorted(lists["_regexes"])) == fn.STRING_PATTERNS

    warnings_file = location / "pefile_warnings.txt"
    lines = [line.strip() for line in warnings_file.read_text(encoding="utf-8").splitlines()]
    assert tuple(line for line in lines if line) == fn.PEFILE_WARNINGS
    assert len(fn.PEFILE_WARNINGS) == 87


# --- 3. pefilewarnings: one-hot 이라 정확히 복원한다 ------------------------------


def test_pefile_warning_labels_come_from_the_line_order_not_a_hash():
    assert fn.PEFILE_WARNINGS[67] == "Suspicious flags set for section..."
    assert fn.resolve("pefilewarnings[0]", schema_version=V).display_name == (
        "PE Warning: AddressOfEntryPoint lies outside the sections' boundaries"
    )
    # 접미 일치 패턴은 앞의 "..." 를 뗀다
    assert fn.resolve("pefilewarnings[86]", schema_version=V).display_name == (
        "PE Warning: Assuming corrupt."
    )
    assert fn.resolve("pefilewarnings[87]", schema_version=V).display_name == (
        "PE Warning Count"
    )


# --- 4. 해시 특성은 그룹 수준으로만 --------------------------------------------


@pytest.mark.parametrize(
    "name,label",
    [
        ("section[11]", "Section size hash bucket #0"),
        ("section[60]", "Section size hash bucket #49"),
        ("section[61]", "Section virtual size hash bucket #0"),
        ("section[111]", "Section entropy hash bucket #0"),
        ("section[161]", "Section characteristics hash bucket #0"),
        ("section[211]", "Entry-point section name hash bucket #0"),
        ("imports[2]", "Import library hash bucket #0"),
        ("imports[258]", "Import API hash bucket #0"),
        ("imports[1281]", "Import API hash bucket #1023"),
        ("exports[1]", "Export name hash bucket #0"),
        ("richheader[1]", "Rich header entry hash bucket #0"),
    ],
)
def test_hashed_features_are_named_by_bucket_only(name, label):
    resolved = fn.resolve(name, schema_version=V)
    assert resolved.kind == "hashed"
    assert resolved.display_name == label


def test_hashed_labels_never_mention_a_concrete_api_or_section_name():
    for group, dimension in fn.GROUP_DIMENSIONS.items():
        for i in range(dimension):
            resolved = fn.resolve(f"{group}[{i}]", schema_version=V)
            if resolved.kind == "hashed":
                assert ".dll" not in resolved.display_name.lower()
                assert ".text" not in resolved.display_name.lower()


# --- 5. 레이아웃 경계 (hstack 순서) ---------------------------------------------


@pytest.mark.parametrize(
    "name,label",
    [
        ("header[0]", "COFF Timestamp"),
        ("header[29]", "Number Of RVAs And Sizes"),
        ("header[30]", "File Characteristic Flag: RELOCS_STRIPPED"),
        ("header[45]", "File Characteristic Flag: BYTES_REVERSED_HI"),
        ("header[46]", "DLL Characteristic Flag: HIGH_ENTROPY_VA"),
        ("header[56]", "DLL Characteristic Flag: TERMINAL_SERVER_AWARE"),
        ("header[57]", "DOS Header e_magic"),
        ("header[73]", "DOS Header e_lfanew"),
        ("section[0]", "Section Count"),
        ("section[10]", "Min Section Virtual Size Ratio (always 0)"),
        ("section[221]", "Overlay Size"),
        ("section[223]", "Overlay Entropy"),
        ("imports[0]", "Imported Function Count"),
        ("imports[1]", "Imported Library Count"),
        ("exports[0]", "Export Hash Vector Length (0 or 128)"),
        ("datadirectories[0]", "Export Directory Size"),
        ("datadirectories[1]", "Export Directory Virtual Address"),
        ("datadirectories[13]", "Debug Directory Virtual Address"),
        ("datadirectories[30]", "Reserved Directory Size (always 0)"),
        ("datadirectories[32]", "Has Relocations"),
        ("datadirectories[33]", "Has Dynamic Relocations"),
        ("richheader[0]", "Rich Header Entry Count"),
        ("strings[0]", "String Count"),
        ("strings[2]", "Printable Character Count"),
        ("strings[3]", "Printable Char ' ' Share"),
        ("strings[98]", "Printable Char '\\x7f' Share"),
        ("strings[99]", "String Character Entropy"),
        ("strings[100]", "String Pattern Count: .click("),
        ("strings[176]", "String Pattern Count: window"),
        ("general[0]", "File Size (bytes)"),
        ("general[6]", "Fourth Byte Value"),
        ("histogram[255]", "Byte 0xFF Frequency"),
        ("byteentropy[0]", "Byte-Entropy Bin (entropy 0/16, byte nibble 0x0)"),
        ("byteentropy[255]", "Byte-Entropy Bin (entropy 15/16, byte nibble 0xF)"),
        ("authenticode[0]", "Certificate Count"),
        ("authenticode[7]", "Signing Time Difference"),
    ],
)
def test_segment_boundaries_follow_the_hstack_order(name, label):
    assert fn.resolve(name, schema_version=V).display_name == label


# --- 6. fallback: 추측하지 않는다 ---------------------------------------------


@pytest.mark.parametrize("version", [None, "", "synthetic-v1", "ember2024-v3-pe-000000000000"])
def test_other_schema_versions_fall_back_to_the_raw_name(version):
    resolved = fn.resolve("header[9]", schema_version=version)
    assert resolved.kind == "unknown"
    assert resolved.display_name == "header[9]"
    assert fn.display_name("header[9]", schema_version=version) == "header[9]"


@pytest.mark.parametrize(
    "name", ["header[74]", "foo[0]", "header", "header[]", "header[-1]", "", "f[2]"]
)
def test_unknown_names_fall_back_to_the_raw_name(name):
    resolved = fn.resolve(name, schema_version=V)
    assert resolved.kind == "unknown"
    assert resolved.display_name == name


def test_module_has_no_heavy_imports():
    """백엔드가 top-level 로 import 하므로 thrember/lightgbm/shap 를 끌어오면 안 된다."""
    source = (REPO / "src" / "trust_triage" / "feature_names.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= {"__future__", "re", "dataclasses", "typing"}
