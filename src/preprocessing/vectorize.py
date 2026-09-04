#!/usr/bin/env python3
"""
2단계 — 원본 .jsonl을 특징 벡터(.dat)로 변환하고 무결성을 검증한다.

thrember.create_vectorized_features()는 dataset 디렉터리 안의 .jsonl 중
파일명에 train/test/challenge가 들어간 것을 전부 긁어서 처리한다.
Win32/Win64만 내려받았다면 자동으로 그것만 벡터화된다 (별도 필터 인자 없음).

산출물 (dataset/ 안):
  X_train.dat      약 21.4GB  (2,080,000 x 2568 float32)
  X_test.dat       약  4.9GB  (  480,000 x 2568 float32)
  X_challenge.dat  약   65MB  (    6,315 x 2568 float32)
  y_*.dat          int32

무결성 검증
-----------
create_vectorized_features()는 memmap을 전체 크기로 미리 할당한 뒤 채우기
때문에, 중간에 죽어도 파일 크기는 정상으로 보인다. 따라서 크기 검사만으로는
중단을 잡을 수 없다. 대신 '전부 0인 행'을 찾는다. 바이트 히스토그램 256차원이
정규화되어 합이 1이므로, 정상적으로 채워진 행은 절대 전부 0일 수 없다.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (  # noqa: E402
    DEFAULT_CHUNK, Layout, Timer, add_root_arg, fmt_bytes, get_dim,
    iter_chunks, open_dat, setup_logging, write_json,
)


def scan_zero_rows(X, n: int, chunk: int, log) -> np.ndarray:
    """전부 0인 행의 인덱스를 찾는다 (벡터화 중단 탐지용)."""
    bad = []
    for s, e in iter_chunks(n, chunk):
        block = np.asarray(X[s:e])
        zero = ~block.any(axis=1)
        if zero.any():
            bad.extend((s + np.flatnonzero(zero)).tolist())
        if (s // chunk) % 20 == 0:
            log.info("    ...%d / %d 행 검사 (%.1f%%)", e, n, 100.0 * e / n)
    return np.array(bad, dtype=np.int64)


def main() -> int:
    ap = argparse.ArgumentParser(description="EMBER2024 벡터화 + 무결성 검증")
    add_root_arg(ap)
    ap.add_argument("--force", action="store_true", help="이미 .dat이 있어도 다시 벡터화")
    ap.add_argument("--chunk", type=int, default=DEFAULT_CHUNK,
                    help=f"검증 시 청크 행 수 (기본 {DEFAULT_CHUNK})")
    ap.add_argument("--skip-zero-check", action="store_true",
                    help="0행 검사를 건너뜀 (약 26GB 순차 읽기를 절약)")
    args = ap.parse_args()

    layout = Layout(args.root)
    layout.mkdirs()
    log = setup_logging("vectorize", layout.logs)

    try:
        import thrember  # noqa: F401
        from thrember.model import create_vectorized_features
    except ImportError:
        log.error("thrember를 import할 수 없습니다. pip install . 을 먼저 수행하세요.")
        return 1

    jsonl = sorted(layout.dataset.glob("*.jsonl"))
    if not jsonl:
        log.error("%s 안에 .jsonl이 없습니다. download.py를 먼저 실행하세요.",
                  layout.dataset)
        return 1
    log.info("입력 .jsonl 파일 %d개", len(jsonl))

    # --- 벡터화 ----------------------------------------------------------
    already = all((layout.dataset / f"X_{s}.dat").is_file()
                  for s in ("train", "test", "challenge"))

    if already and not args.force:
        log.info("이미 .dat 파일이 존재합니다. 벡터화를 건너뜁니다 (--force로 재실행).")
    else:
        log.warning("벡터화는 수 시간이 걸립니다. 중단 시 --force로 처음부터 다시 해야 합니다.")
        with Timer(log, "create_vectorized_features (label_type='label')"):
            # label_type="label" = 악성/정상 이진 라벨. 라벨 없는 샘플은 -1이 된다.
            create_vectorized_features(str(layout.dataset), label_type="label")

    # --- 검증 ------------------------------------------------------------
    dim = get_dim()
    log.info("특징 차원(thrember 기준): %d", dim)

    report: dict = {"feature_dim": dim, "subsets": {}}
    ok = True

    for subset in ("train", "test", "challenge"):
        x_path, y_path = layout.dat(subset)
        if not x_path.is_file():
            log.error("%s 없음", x_path.name)
            ok = False
            continue

        try:
            X, y, n = open_dat(layout, subset, dim)
        except ValueError as exc:
            log.error("%s 검증 실패: %s", subset, exc)
            ok = False
            continue

        y_arr = np.array(y)
        info = {
            "n_rows": int(n),
            "X_bytes": x_path.stat().st_size,
            "y_bytes": y_path.stat().st_size,
            "X_size_human": fmt_bytes(x_path.stat().st_size),
            "unique_labels": sorted(int(v) for v in np.unique(y_arr)),
        }
        log.info("%-10s %9d행  %10s  라벨값=%s",
                 subset, n, fmt_bytes(info["X_bytes"]), info["unique_labels"])

        if not args.skip_zero_check:
            with Timer(log, f"0행 검사 ({subset})"):
                zero_idx = scan_zero_rows(X, n, args.chunk, log)
            info["n_all_zero_rows"] = int(zero_idx.size)
            if zero_idx.size:
                ok = False
                log.error(
                    "%s: 전부 0인 행이 %d개 있습니다. 벡터화가 완료되지 않았을 "
                    "가능성이 높습니다. --force로 재실행하세요.",
                    subset, zero_idx.size,
                )
                np.save(layout.reports / f"zero_rows_{subset}.npy", zero_idx)
            else:
                log.info("%s: 0행 없음 — 정상", subset)

        del X, y
        report["subsets"][subset] = info

    write_json(layout.reports / "vectorize_report.json", report)
    log.info("검증 리포트: %s", layout.reports / "vectorize_report.json")

    if not ok:
        log.error("무결성 검증에 실패했습니다. 다음 단계로 진행하지 마세요.")
        return 1

    layout.mark_done("vectorize", {"feature_dim": dim})
    log.info("다음 단계: python build_index.py --root %s", args.root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
