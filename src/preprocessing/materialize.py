#!/usr/bin/env python3
"""
5단계 — 인덱스를 적용해 최종 .npy 파일을 만든다.

메모리 전략
-----------
np.lib.format.open_memmap()으로 출력 파일을 미리 만들고 청크 단위로 채운다.
청크 하나가 20000행 x 2568차원 x 4바이트 = 약 205MB이므로 RAM 사용량은
1GB를 넘지 않는다. 21GB짜리 배열을 만들면서도 32GB 환경에서 여유롭다.

인덱스는 4단계의 시간 분할 결과로, np.where가 오름차순으로 돌려주므로 소스
memmap 읽기가 거의 순차 접근이 된다 (무작위 순서면 21GB에 대한 랜덤 I/O가
되어 훨씬 느리다).

포맷
----
parquet이 아니라 .npy를 쓴다. 2568개 dense float 컬럼은 parquet에 최악의
입력이고, 무엇보다 읽을 때 전체 materialize가 강제되어 32GB에서 다시 터진다.
.npy는 np.load(..., mmap_mode='r')로 lazy 로딩이 된다.

dtype은 float32를 유지한다. float16으로 낮추면 표현 가능 최대값이 65504라서
general.size(원시 파일 크기), SectionInfo의 size/vsize, AddressOfEntryPoint 등
원시 정수값 특징이 대량으로 inf가 된다. 용량 절감보다 손실이 훨씬 크다.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
from numpy.lib.format import open_memmap

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (  # noqa: E402
    DEFAULT_CHUNK, DEV_SPLITS, Layout, Timer, add_root_arg, fmt_bytes, get_dim,
    iter_chunks, load_y, open_dat, setup_logging, write_json,
)

LOCKBOX_SUBSETS = ("test", "challenge")


def ensure_writable(path: Path) -> None:
    """06단계에서 0o444로 봉인된 파일을 다시 쓰기 전에 권한을 푼다."""
    import os
    import stat
    if path.exists() and not os.access(path, os.W_OK):
        path.chmod(path.stat().st_mode | stat.S_IWUSR)


def npy_shape(path: Path) -> tuple | None:
    """
    .npy의 shape만 헤더에서 읽는다 (없으면 None).

    데이터는 건드리지 않으므로 21GB 파일에도 비용이 없다. memmap을 열고
    바로 닫는 이유는, Windows에서 열린 매핑이 남아 있으면 같은 경로를
    open_memmap(mode="w+")으로 다시 만들 때 실패하기 때문이다.
    """
    if not path.is_file():
        return None
    arr = np.load(path, mmap_mode="r")
    shape = tuple(int(v) for v in arr.shape)
    del arr
    return shape


def copy_rows(X_src, idx: np.ndarray, out_path: Path, dim: int,
              chunk: int, log) -> None:
    """소스 memmap에서 idx가 가리키는 행만 골라 새 .npy로 복사한다."""
    n = int(idx.size)
    out = open_memmap(out_path, mode="w+", dtype=np.float32, shape=(n, dim))
    try:
        for s, e in iter_chunks(n, chunk):
            out[s:e] = X_src[idx[s:e]]
            if (s // chunk) % 20 == 0:
                log.info("    ...%d / %d 행 (%.1f%%)", e, n, 100.0 * e / n)
        out.flush()
    finally:
        del out


def copy_all(X_src, n: int, out_path: Path, dim: int, chunk: int, log) -> None:
    """전체를 그대로 복사한다 (lockbox용, 필터링 없음)."""
    out = open_memmap(out_path, mode="w+", dtype=np.float32, shape=(n, dim))
    try:
        for s, e in iter_chunks(n, chunk):
            out[s:e] = X_src[s:e]
            if (s // chunk) % 20 == 0:
                log.info("    ...%d / %d 행 (%.1f%%)", e, n, 100.0 * e / n)
        out.flush()
    finally:
        del out


def verify_sample(X_src, idx: np.ndarray, out_path: Path, rng, n_check: int, log) -> bool:
    """
    무작위 표본 행을 골라 원본과 산출물이 정확히 일치하는지 확인한다.
    '인덱스만 남겨도 X를 복원할 수 있다'를 실제로 보증하기 위한 검사.
    """
    arr = np.load(out_path, mmap_mode="r")
    n = int(idx.size)
    if n == 0:
        return True
    picks = rng.choice(n, size=min(n_check, n), replace=False)
    for p in np.sort(picks):
        # NaN이 포함된 행도 정확히 비교하기 위해 바이트 단위로 대조한다
        # (np.array_equal은 NaN != NaN 때문에 오탐이 난다)
        a = np.ascontiguousarray(arr[p]).tobytes()
        b = np.ascontiguousarray(X_src[idx[p]]).tobytes()
        if a != b:
            log.error("검증 실패: %s의 %d번째 행이 원본과 다릅니다.", out_path.name, p)
            return False
    del arr
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description="최종 .npy 산출물 생성")
    add_root_arg(ap)
    ap.add_argument("--chunk", type=int, default=DEFAULT_CHUNK)
    ap.add_argument("--force", action="store_true", help="이미 있는 산출물도 덮어씀")
    ap.add_argument("--verify", action="store_true",
                    help="무작위 표본으로 원본과의 일치를 검증")
    ap.add_argument("--verify-n", type=int, default=200,
                    help="검증할 표본 행 수 (기본 200)")
    ap.add_argument("--skip-lockbox", action="store_true",
                    help="lockbox(test/challenge) 복사를 건너뜀")
    args = ap.parse_args()

    layout = Layout(args.root)
    layout.mkdirs()
    log = setup_logging("materialize", layout.logs)

    dim = get_dim()
    rng = np.random.default_rng(0)
    manifest_rows: dict = {}

    # ------------------------------------------------------------------
    # 개발용 3분할
    # ------------------------------------------------------------------
    X_train, _, n_train = open_dat(layout, "train", dim)
    y_train = load_y(layout, "train")
    arch_train = np.load(layout.arch_path("train"))

    for split in DEV_SPLITS:
        idx_path = layout.split_idx_path(split)
        if not idx_path.is_file():
            log.error("%s 없음 — split_qc.py를 먼저 실행하세요. "
                      "(분할 경계를 바꿨다면 04를 --force로 다시 돌려야 "
                      "idx_%s.npy가 생깁니다.)", idx_path, split)
            return 1
        idx = np.load(idx_path)

        x_out = layout.dev / f"X_{split}.npy"
        y_out = layout.dev / f"y_{split}.npy"
        a_out = layout.dev / f"arch_{split}.npy"

        # y와 arch는 작으니 항상 새로 쓴다
        np.save(y_out, y_train[idx].astype(np.int32))
        np.save(a_out, arch_train[idx].astype(np.int8))

        # 이미 있는 파일이 지금의 인덱스와 맞는지 shape로 확인한다.
        # 분할 경계를 바꾼 뒤(예: train 0–39 → tr 0–33 + val 34–39) 그냥
        # 재실행하면, 예전 기준으로 만든 X_tr.npy가 "이미 존재"로 스킵되어
        # 인덱스와 어긋난 채 남는다. 조용한 불일치는 --force를 깜빡한 사람의
        # 실수가 아니라 파이프라인의 결함이므로, 행 수가 다르면 경고와 함께
        # 무조건 다시 만든다.
        want = (int(idx.size), dim)
        have = npy_shape(x_out)
        stale = have is not None and have != want

        if have is not None and not args.force and not stale:
            log.info("스킵: %s (이미 존재, shape %s 일치 — --force로 덮어쓰기)",
                     x_out.name, have)
        else:
            if stale:
                log.warning("%s의 shape가 %s인데 현재 인덱스는 %s입니다 — "
                            "분할 경계가 바뀐 산출물이므로 다시 만듭니다.",
                            x_out.name, have, want)
            est = idx.size * dim * 4
            log.info("%s: %d행 → 예상 %s", x_out.name, idx.size, fmt_bytes(est))
            with Timer(log, f"X_{split}.npy 생성"):
                copy_rows(X_train, idx, x_out, dim, args.chunk, log)

        if args.verify:
            with Timer(log, f"X_{split}.npy 표본 검증"):
                if not verify_sample(X_train, idx, x_out, rng, args.verify_n, log):
                    return 1
            log.info("  검증 통과 — 인덱스만으로 복원 가능함이 확인되었습니다.")

        manifest_rows[f"X_{split}"] = {
            "path": str(x_out), "shape": [int(idx.size), dim], "dtype": "float32",
        }

    del X_train

    # ------------------------------------------------------------------
    # Lockbox — 필터링 없이 원본 그대로
    # ------------------------------------------------------------------
    if not args.skip_lockbox:
        for subset in LOCKBOX_SUBSETS:
            try:
                X_src, y_src, n = open_dat(layout, subset, dim)
            except FileNotFoundError:
                log.warning("%s 없음 — 건너뜀", subset)
                continue

            x_out = layout.lockbox / f"X_{subset}.npy"
            y_out = layout.lockbox / f"y_{subset}.npy"
            a_out = layout.lockbox / f"arch_{subset}.npy"
            m_out = layout.lockbox / f"valid_mask_{subset}.npy"

            for p in (x_out, y_out, a_out, m_out):
                ensure_writable(p)

            np.save(y_out, np.array(y_src, dtype=np.int32))
            arch_path = layout.arch_path(subset)
            if arch_path.is_file():
                np.save(a_out, np.load(arch_path))
            mask_path = layout.valid_mask_path(subset)
            if mask_path.is_file():
                np.save(m_out, np.load(mask_path))

            if x_out.is_file() and not args.force:
                log.info("스킵: %s (이미 존재)", x_out.name)
            else:
                log.info("%s: %d행 → 예상 %s (필터링 없이 전체 복사)",
                         x_out.name, n, fmt_bytes(n * dim * 4))
                with Timer(log, f"X_{subset}.npy 생성"):
                    copy_all(X_src, n, x_out, dim, args.chunk, log)

            manifest_rows[f"X_{subset}"] = {
                "path": str(x_out), "shape": [int(n), dim], "dtype": "float32",
                "lockbox": True,
            }
            del X_src, y_src

    write_json(layout.reports / "materialize_report.json", manifest_rows)

    log.info("")
    log.info("=== 산출물 ===")
    for d in (layout.dev, layout.lockbox):
        for p in sorted(d.glob("*.npy")):
            log.info("  %-28s %10s", p.name, fmt_bytes(p.stat().st_size))

    layout.mark_done("materialize")
    log.info("다음 단계: python manifest.py --root %s", args.root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
