#!/usr/bin/env python3
"""
3단계 — 메타데이터 추출. 벡터 행 순서와 동일한 순서로 각 레코드의
sha256 / week_id / file_type / family / label 을 뽑아 저장하고,
그로부터 arch(Win32/Win64/OTHER) 인덱스를 파생시킨다.

메타데이터는 pandas pickle(.pkl)로 저장한다. parquet(pyarrow/fastparquet)은
네이티브 DLL을 요구해 스마트 앱 제어 등 애플리케이션 제어 정책이 걸린
Windows에서 로딩이 차단될 수 있어, 추가 네이티브 의존성이 없는 pickle을 쓴다.

왜 필요한가
-----------
`read_vectorized_features()`는 X, y만 돌려줄 뿐 week_id와 file_type을 주지
않는다. 그런데 이후 단계에서 반드시 필요하다:
  * 4단계 시간 분할 — `week_id` 기준으로 train/calibration/eval을 나눈다.
    EMBER2024는 IID가 아니라 시간축 설계이므로 무작위 분할이 금지된다.
  * challenge 필터 / .NET 제외 — `file_type`으로 Win32/Win64만 남긴다.
  * 지표 분해 — arch(=file_type)별로 성능을 나눠 본다. Win32:Win64가 3:1이라
    집계 지표는 사실상 Win32 성능만 반영한다.

어떻게 만드는가
---------------
벡터화 시 행 순서는 gather_feature_paths()가 반환한 파일 순서
(sorted(os.listdir()) 기반) x 각 파일의 줄 순서로 결정된다. 멀티프로세싱을
쓰지만 irow로 위치를 지정해 쓰므로 순서가 섞이지 않는다. 따라서 같은 함수를
import해서 파일 순서를 재현하고, 각 파일을 한 줄씩 읽으며 스칼라 필드만
추출한다.

성능: 레코드 전체를 json.loads 하면 거대한 특징 dict까지 파싱해 44GB train에서
수십 분~시간이 걸린다. 여기서는 필요한 스칼라 5개만 정규식으로 뽑고, 하나라도
놓친 줄만 json.loads로 폴백한다.

주의: thrember.read_metadata()는 쓰지 않는다. challenge 부분에 버그가 있어
      challenge 자리에 test 레코드를 넣어 반환하며, 전체 레코드를 dict 리스트로
      RAM에 올려 32GB로는 돌지 않는다.

검증 게이트 (⭐)
----------------
subset마다 다음을 확인하고, 하나라도 어긋나면 즉시 중단한다:
  * len(meta) == .dat 행 수
  * (meta.label == y).all()
이 두 assert가 통과해야 벡터 행 ↔ 메타데이터 대응이 보장된다. 실패하면 이후
시간 분할과 challenge 필터가 통째로 무의미하므로 여기서 멈춘다.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (  # noqa: E402
    ARCH_NAMES, ARCH_OTHER, ARCH_WIN32, ARCH_WIN64, Layout, Timer,
    add_root_arg, gather_paths, get_dim, open_dat, setup_logging,
    write_json,
)

# 스칼라 top-level 필드만 뽑는 정규식 (거대한 특징 dict를 파싱하지 않기 위함).
RE_SHA256 = re.compile(rb'"sha256"\s*:\s*"([^"]*)"')
RE_WEEK = re.compile(rb'"week_id"\s*:\s*(-?\d+)')
RE_FILE_TYPE = re.compile(rb'"file_type"\s*:\s*"([^"]*)"')
RE_FAMILY = re.compile(rb'"family"\s*:\s*(?:"([^"]*)"|null)')
RE_LABEL = re.compile(rb'"label"\s*:\s*(-?\d+)')


def arch_from_file_type(value: str) -> int:
    if "Win32" in value:
        return ARCH_WIN32
    if "Win64" in value:
        return ARCH_WIN64
    return ARCH_OTHER


def _parse_line_json(line: bytes) -> dict:
    """정규식이 놓친 줄만 여기로 온다 (느린 경로)."""
    try:
        return json.loads(line)
    except Exception:
        return {}


def extract_meta_file(path: Path) -> tuple[list, Counter]:
    """
    파일 한 개에서 (sha256, week_id, file_type, family, label) 행들을 뽑는다.
    반환: (rows, raw_file_type_counter). rows는 튜플의 리스트.
    """
    rows: list = []
    raw = Counter()
    with open(path, "rb") as f:
        for line in f:
            if not line.strip():
                continue

            m_sha = RE_SHA256.search(line)
            m_wk = RE_WEEK.search(line)
            m_ft = RE_FILE_TYPE.search(line)
            m_lb = RE_LABEL.search(line)
            m_fam = RE_FAMILY.search(line)

            # 필수 필드(week_id / file_type / label)를 놓쳤으면 json 폴백.
            if m_wk is None or m_ft is None or m_lb is None:
                rec = _parse_line_json(line)
                sha = str(rec.get("sha256", "")) if rec else ""
                wk = rec.get("week_id", -1)
                ft = str(rec.get("file_type", "")) if rec else ""
                fam = rec.get("family")
                lb = rec.get("label", -1)
                week = int(wk) if wk is not None else -1
                label = int(lb) if lb is not None else -1
                family = None if fam is None else str(fam)
            else:
                sha = m_sha.group(1).decode("utf-8", "replace") if m_sha else ""
                ft = m_ft.group(1).decode("utf-8", "replace")
                week = int(m_wk.group(1))
                label = int(m_lb.group(1))
                # family: "..." 이면 group(1), null 이면 None, 아예 없으면 None
                family = (m_fam.group(1).decode("utf-8", "replace")
                          if (m_fam and m_fam.group(1) is not None) else None)

            raw[ft] += 1
            rows.append((sha, week, ft, family, label))
    return rows, raw


def build_subset(layout: Layout, subset: str, dim: int, log):
    """
    subset의 메타데이터를 추출해 (DataFrame, arch, info)를 만든다.
    행 순서 정합성(len, label==y)을 검증하고, 실패 시 예외를 던진다.
    """
    import pandas as pd

    paths = gather_paths(layout.dataset, subset)
    if not paths:
        raise FileNotFoundError(f"{subset} 에 해당하는 .jsonl이 없습니다.")

    log.info("%s: 대상 파일 %d개 (레코드 스캔)", subset, len(paths))

    all_rows: list = []
    per_file: list[dict] = []
    raw_types: Counter = Counter()

    for p in paths:
        start = len(all_rows)
        rows, raw = extract_meta_file(p)
        all_rows.extend(rows)
        raw_types.update(raw)
        n = len(all_rows) - start
        per_file.append({"file": p.name, "n_rows": n})
        log.info("  %-45s %9d행", p.name, n)

    meta = pd.DataFrame(
        all_rows, columns=["sha256", "week_id", "file_type", "family", "label"]
    )
    # dtype 정리: week_id/label은 정수, file_type/sha256/family는 문자열/None.
    meta["week_id"] = meta["week_id"].astype(np.int32)
    meta["label"] = meta["label"].astype(np.int32)

    arch = np.array(
        [arch_from_file_type(ft) for ft in meta["file_type"].tolist()],
        dtype=np.int8,
    )

    # --- ⭐ 정합성 게이트 -------------------------------------------------
    _, y, n_dat = open_dat(layout, subset, dim)
    if len(meta) != n_dat:
        raise ValueError(
            f"{subset}: 메타데이터 행 수({len(meta)})와 .dat 행 수({n_dat})가 "
            f"다릅니다. 벡터화 이후 dataset의 .jsonl이 바뀌었거나 gather 순서가 "
            f"어긋났습니다. 02단계를 --force로 다시 실행하세요."
        )
    y_arr = np.asarray(y, dtype=np.int64)
    if not (meta["label"].to_numpy(dtype=np.int64) == y_arr).all():
        n_mismatch = int((meta["label"].to_numpy(dtype=np.int64) != y_arr).sum())
        raise ValueError(
            f"{subset}: 메타데이터 label과 y_{subset}가 {n_mismatch}행에서 "
            f"불일치합니다 — 행 순서 매핑 실패. jsonl 나열 순서를 thrember "
            f"gather_feature_paths와 대조해 맞춘 뒤 재시도하세요."
        )
    log.info("  ✅ 정합성 통과: len=%d, label==y 전부 일치", n_dat)

    counts = {ARCH_NAMES.get(int(a), str(a)): int((arch == a).sum())
              for a in np.unique(arch)}
    week_min = int(meta["week_id"].min())
    week_max = int(meta["week_id"].max())
    log.info("%s: 총 %d행 / arch %s / week_id 범위 %d–%d",
             subset, len(meta), counts, week_min, week_max)

    info = {
        "n_rows": int(len(meta)),
        "arch_counts": counts,
        "raw_file_type_counts": dict(raw_types),
        "week_id_min": week_min,
        "week_id_max": week_max,
        "n_family_null": int(meta["family"].isna().sum()),
        "files": per_file,
    }
    return meta, arch, info


def main() -> int:
    ap = argparse.ArgumentParser(
        description="메타데이터(week_id/file_type/...) 추출 + arch 인덱스 생성"
    )
    add_root_arg(ap)
    ap.add_argument("--force", action="store_true", help="이미 있어도 다시 생성")
    ap.add_argument("--subsets", default="train,test,challenge",
                    help="처리할 subset (쉼표 구분)")
    args = ap.parse_args()

    layout = Layout(args.root)
    layout.mkdirs()
    log = setup_logging("03_build_index", layout.logs)

    if layout.is_done("build_index") and not args.force:
        log.info("이미 완료되었습니다 (--force로 재생성).")
        return 0

    try:
        import pandas  # noqa: F401
    except ImportError:
        log.error("pandas가 필요합니다: pip install pandas")
        return 1

    dim = get_dim()
    report: dict = {"feature_dim": dim, "subsets": {}}
    subsets = [s.strip() for s in args.subsets.split(",") if s.strip()]

    for subset in subsets:
        with Timer(log, f"메타데이터 추출 ({subset})"):
            try:
                meta, arch, info = build_subset(layout, subset, dim, log)
            except FileNotFoundError as exc:
                log.error("%s 건너뜀: %s", subset, exc)
                continue

            meta.to_pickle(layout.meta_path(subset))
            np.save(layout.arch_path(subset), arch)
            report["subsets"][subset] = info
            log.info("저장: %s", layout.meta_path(subset))
            log.info("저장: %s", layout.arch_path(subset))

    write_json(layout.reports / "meta_index_report.json", report)

    ch = report["subsets"].get("challenge")
    if ch:
        log.info("challenge의 실제 file_type 분포: %s", ch["raw_file_type_counts"])
        log.info("→ Win32/Win64만 평가하려면 5단계 challenge 필터를 적용하세요.")

    tr = report["subsets"].get("train")
    if tr:
        log.info("train week_id 범위: %d–%d (시간 분할 기준)",
                 tr["week_id_min"], tr["week_id_max"])
        if tr["week_id_min"] != 0 or tr["week_id_max"] != 51:
            log.warning("train week_id 범위가 0–51과 다릅니다 — 분할 경계를 재확인하세요.")

    layout.mark_done("build_index")
    log.info("다음 단계: python 04_split_qc.py --root %s", args.root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
