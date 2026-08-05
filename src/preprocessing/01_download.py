#!/usr/bin/env python3
"""
1단계 — EMBER2024에서 Win32 / Win64 (+ challenge) 원본 특징을 내려받고,
challenge 셋의 파일 타입(arch) 인덱스를 생성한다.

주의사항
--------
* thrember의 download_dataset()은 file_type을 한 번에 하나만 받는다.
  file_type="PE"는 .NET까지 포함하므로 쓰면 안 된다.
* split="all"을 쓰면 challenge까지 자동으로 받는데, challenge는 파일 타입 구분이
  없는 단일 zip이라 Win32/Win64 두 번 호출 시 중복 다운로드가 발생한다.
  그래서 (file_type, split) 조합을 명시적으로 4번 + challenge 1번 호출한다.
* download_dataset()은 내부에서 os.chdir()을 호출하므로 반환 후 CWD를 복원한다.

challenge 필터링 정책
--------------------
challenge 셋 6,315개에는 Win32/Win64 외에 .NET / APK / ELF / PDF가 섞여 있다
(논문 Table 3 기준 Win32 3,225 + Win64 814 = 4,039개만 대상).
thrember는 비PE 파일도 동일한 2568차원으로 벡터화하므로, 필터링을 빠뜨려도
차원 검증은 통과하고 오염이 조용히 넘어간다.

이 스크립트는 원본 .jsonl을 **수정하지 않는다**. 대신 벡터화 행 순서와 동일한
순서로 arch 배열을 만들어 index/에 저장한다:
  - out/index/arch_challenge.npy   : 행별 ARCH_* 코드 (int8)
  - out/index/idx_challenge_win.npy: Win32/Win64 행 인덱스만 (int64)
원본을 물리적으로 잘라내면 gather_feature_paths()가 원본과 필터본을 모두
집어 행이 중복되고, 재현성 추적도 끊어진다.

Windows 참고
-----------
* 콘솔 인코딩(cp949)에서 로그의 ▶/■ 기호가 UnicodeEncodeError를 일으키므로
  stdout을 UTF-8로 재설정한다.
* .jsonl을 열 때 encoding="utf-8"을 명시한다. Windows 기본값은 cp949라
  UnicodeDecodeError가 난다.
* HuggingFace 캐시가 심볼릭 링크 대신 복사로 동작해(개발자 모드 미설정 시)
  데이터셋 용량만큼 별도 공간을 더 쓴다. 두 드라이브를 모두 점검한다.

예상 용량: Win32 train 23.7GB + Win64 train 12.9GB + test 4.9/2.5GB
           + challenge 126MB = 약 44GB (+ HF 캐시 사본)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (  # noqa: E402
    ARCH_NAMES,
    ARCH_OTHER,
    ARCH_WIN32,
    ARCH_WIN64,
    Layout,
    add_root_arg,
    fmt_bytes,
    fmt_duration,
    setup_logging,
    write_json,
)

# (file_type, split) 조합. challenge는 별도 처리.
COMBOS = [
    ("Win32", "train"),
    ("Win64", "train"),
    ("Win32", "test"),
    ("Win64", "test"),
]

# challenge .jsonl 레코드에서 파일 타입이 담겼을 만한 키 후보.
# 실제 스키마가 바뀌면 --arch-key로 직접 지정할 수 있다.
ARCH_KEY_CANDIDATES = ("file_type", "filetype", "fileType", "type", "format")

# 파일 타입 문자열 -> ARCH_* 코드
ARCH_VALUE_MAP = {
    "win32": ARCH_WIN32,
    "pe32": ARCH_WIN32,
    "win64": ARCH_WIN64,
    "pe64": ARCH_WIN64,
    "pe32+": ARCH_WIN64,
}


# --------------------------------------------------------------------------
# 플랫폼 준비
# --------------------------------------------------------------------------

def enable_utf8_console() -> None:
    """
    Windows 콘솔(cp949)에서 ▶ / ■ 같은 기호를 찍다 죽는 것을 막는다.
    common.py의 Timer와 로그 포맷이 비ASCII를 쓰므로 로깅 설정보다 먼저 호출한다.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def hf_cache_dir() -> Path:
    """huggingface_hub이 실제로 쓰는 캐시 경로를 추정한다."""
    for var in ("HF_HUB_CACHE", "HUGGINGFACE_HUB_CACHE"):
        v = os.environ.get(var)
        if v:
            return Path(v).expanduser()
    hf_home = os.environ.get("HF_HOME")
    if hf_home:
        return Path(hf_home).expanduser() / "hub"
    return Path.home() / ".cache" / "huggingface" / "hub"


def free_bytes(path: Path) -> int:
    """존재하는 가장 가까운 상위 경로 기준으로 여유 공간을 잰다."""
    p = path
    while not p.exists() and p != p.parent:
        p = p.parent
    return shutil.disk_usage(p).free


def same_volume(a: Path, b: Path) -> bool:
    try:
        return os.path.splitdrive(str(a.resolve()))[0].lower() == \
               os.path.splitdrive(str(b.resolve()))[0].lower()
    except Exception:
        return False


def preflight(log, layout: Layout, min_free_gb: int, strict: bool) -> bool:
    """
    다운로드 전 환경 점검. 문제가 있으면 False.
    20시간 받다가 디스크 부족으로 죽는 상황을 막는 것이 목적이다.
    """
    ok = True
    is_win = os.name == "nt"

    cache = hf_cache_dir()
    need = min_free_gb * 1024 ** 3

    ds_free = free_bytes(layout.dataset)
    cache_free = free_bytes(cache)
    shared = same_volume(layout.dataset, cache)

    log.info("데이터셋 경로: %s (여유 %s)", layout.dataset, fmt_bytes(ds_free))
    log.info("HF 캐시 경로 : %s (여유 %s)", cache, fmt_bytes(cache_free))

    if shared:
        # 같은 드라이브면 원본 + 캐시 사본이 함께 쌓인다.
        if ds_free < need * 2:
            log.error("데이터셋과 HF 캐시가 같은 드라이브인데 여유 공간이 %s뿐입니다. "
                      "최소 %dGB 필요합니다.", fmt_bytes(ds_free), min_free_gb * 2)
            log.error("  HF_HOME 환경변수로 캐시를 다른 드라이브로 옮기는 것을 권합니다.")
            ok = False
    else:
        if ds_free < need:
            log.error("데이터셋 드라이브 여유 공간 부족: %s (최소 %dGB)",
                      fmt_bytes(ds_free), min_free_gb)
            ok = False
        if cache_free < need:
            log.error("HF 캐시 드라이브 여유 공간 부족: %s (최소 %dGB)",
                      fmt_bytes(cache_free), min_free_gb)
            ok = False

    if is_win:
        # 1) 심볼릭 링크. 개발자 모드가 꺼져 있으면 캐시가 복사로 동작한다.
        os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
        log.info("Windows: HF 캐시가 심볼릭 링크 대신 복사로 동작하면 "
                 "데이터셋 용량만큼 추가 공간이 필요합니다.")

        # 2) MAX_PATH 260자 제한
        probe = len(str(layout.dataset)) + 80  # 데이터셋 파일명 여유분
        if probe > 240:
            msg = (f"작업 루트 경로가 깁니다({len(str(layout.dataset))}자). "
                   f"Windows MAX_PATH(260) 문제가 날 수 있습니다.")
            if strict:
                log.error(msg + " 짧은 경로(예: D:\\ember)로 --root를 지정하세요.")
                ok = False
            else:
                log.warning(msg + " 짧은 경로 사용을 권합니다.")

        # 3) 실시간 검사
        log.info("Windows: Defender 실시간 검사가 켜져 있으면 압축 해제가 크게 "
                 "느려집니다. 작업 폴더를 검사 예외로 등록하는 것을 권합니다.")
        log.info('  Add-MpPreference -ExclusionPath "%s"', layout.root)

    return ok


@contextmanager
def timed(log, label: str):
    """
    common.py의 Timer는 __exit__에서 예외 여부를 보지 않아 실패해도 '완료'를
    찍는다. 여기서는 실패를 실패로 기록한다.
    """
    t0 = time.time()
    log.info("[>] %s 시작", label)
    try:
        yield
    except BaseException as exc:
        log.error("[X] %s 실패 (%s): %s: %s", label, fmt_duration(time.time() - t0),
                  type(exc).__name__, exc)
        raise
    else:
        log.info("[=] %s 완료 (%s)", label, fmt_duration(time.time() - t0))


# --------------------------------------------------------------------------
# 다운로드
# --------------------------------------------------------------------------

def dir_stats(path: Path) -> tuple[int, int]:
    """(파일 수, 총 바이트). 하위 디렉터리까지 포함한다."""
    n = 0
    total = 0
    for f in path.rglob("*"):
        if f.is_file():
            n += 1
            total += f.stat().st_size
    return n, total


def download_one(log, thrember, layout: Layout, cwd: str, retries: int,
                 split: str, file_type: str | None) -> bool:
    label = f"{file_type or '-'} / {split}"
    kwargs = {"split": split}
    if file_type is not None:
        kwargs["file_type"] = file_type

    for attempt in range(1, retries + 1):
        try:
            with timed(log, f"다운로드 {label} (시도 {attempt}/{retries})"):
                thrember.download_dataset(str(layout.dataset), **kwargs)
            return True
        except KeyboardInterrupt:
            raise
        except Exception:
            log.exception("다운로드 중 예외 (%s)", label)
            if attempt == retries:
                return False
            wait = min(60 * attempt, 300)
            log.info("%d초 후 재시도합니다.", wait)
            time.sleep(wait)
        finally:
            # download_dataset이 chdir하므로 성공/실패 무관하게 복원.
            # Windows에서는 CWD가 잡힌 디렉터리를 지우거나 이름을 바꿀 수 없다.
            os.chdir(cwd)
    return False


# --------------------------------------------------------------------------
# challenge 파일 타입 인덱싱
# --------------------------------------------------------------------------

def challenge_paths(log, layout: Layout) -> list[Path]:
    """
    벡터화 시 사용될 것과 동일한 순서로 challenge .jsonl 경로를 얻는다.
    행 순서가 어긋나면 arch 인덱스가 통째로 무의미해지므로 thrember의
    gather_feature_paths를 우선 사용한다.
    """
    try:
        from common import gather_paths
        paths = [Path(p) for p in gather_paths(layout.dataset, "challenge")]
        if paths:
            return paths
        log.warning("gather_feature_paths가 challenge 파일을 반환하지 않았습니다.")
    except Exception:
        log.warning("gather_feature_paths 사용 실패. 파일명 기준으로 대체합니다.",
                    exc_info=True)

    return sorted(p for p in layout.dataset.rglob("*.jsonl")
                  if "challenge" in p.name.lower())


def detect_arch_key(log, path: Path, override: str | None) -> str | None:
    """첫 레코드에서 파일 타입 필드명을 찾는다."""
    if override:
        return override

    with open(path, "r", encoding="utf-8") as f:
        line = f.readline()
    if not line.strip():
        return None

    rec = json.loads(line)
    for key in ARCH_KEY_CANDIDATES:
        if key in rec:
            log.info("파일 타입 필드 감지: %r (예시값 %r)", key, rec[key])
            return key

    log.error("파일 타입 필드를 찾지 못했습니다. 레코드의 최상위 키:")
    log.error("  %s", sorted(rec.keys()))
    log.error("  --arch-key <필드명> 으로 직접 지정하세요.")
    return None


def to_arch(value) -> int:
    if not isinstance(value, str):
        return ARCH_OTHER
    return ARCH_VALUE_MAP.get(value.strip().lower(), ARCH_OTHER)


def build_challenge_arch(log, layout: Layout, arch_key: str | None) -> dict | None:
    """
    challenge 셋의 행별 arch 배열과 Win32/Win64 인덱스를 만든다.
    반환값은 리포트 dict. 실패 시 None.
    """
    paths = challenge_paths(log, layout)
    if not paths:
        log.error("challenge .jsonl을 찾지 못했습니다. 다운로드를 확인하세요.")
        return None

    log.info("challenge 파일 %d개: %s", len(paths), [p.name for p in paths])

    key = detect_arch_key(log, paths[0], arch_key)
    if key is None:
        return None

    arch_list: list[int] = []
    raw_counts: dict[str, int] = {}
    per_file: list[dict] = []
    n_missing = 0
    n_bad_json = 0
    labels: dict[str, int] = {}

    for path in paths:
        start = len(arch_list)
        # encoding 명시 필수: Windows 기본값(cp949)이면 여기서 죽는다.
        with open(path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    n_bad_json += 1
                    log.warning("JSON 파싱 실패: %s:%d — OTHER로 처리", path.name, lineno)
                    arch_list.append(ARCH_OTHER)
                    continue

                val = rec.get(key)
                if val is None:
                    n_missing += 1
                raw = str(val)
                raw_counts[raw] = raw_counts.get(raw, 0) + 1
                arch_list.append(to_arch(val))

                if "label" in rec:
                    lk = str(rec["label"])
                    labels[lk] = labels.get(lk, 0) + 1

        per_file.append({"file": path.name, "n_rows": len(arch_list) - start})

    arch = np.asarray(arch_list, dtype=np.int8)
    win_idx = np.flatnonzero((arch == ARCH_WIN32) | (arch == ARCH_WIN64)).astype(np.int64)

    layout.index.mkdir(parents=True, exist_ok=True)
    np.save(layout.arch_path("challenge"), arch)
    np.save(layout.split_idx_path("challenge_win"), win_idx)

    counts = {ARCH_NAMES[a]: int((arch == a).sum())
              for a in (ARCH_WIN32, ARCH_WIN64, ARCH_OTHER)}

    log.info("challenge 총 %d행 — Win32 %d / Win64 %d / OTHER %d",
             arch.size, counts["Win32"], counts["Win64"], counts["OTHER"])
    log.info("Win32+Win64 유효 행: %d (%.1f%%)",
             win_idx.size, 100.0 * win_idx.size / max(arch.size, 1))
    log.info("원본 파일 타입 분포: %s", dict(sorted(raw_counts.items())))
    if labels:
        log.info("라벨 분포: %s (challenge는 전량 악성이어야 정상)", labels)
    if n_missing:
        log.warning("파일 타입 필드가 없는 레코드 %d개 → OTHER 처리", n_missing)

    report = {
        "source_files": per_file,
        "arch_key": key,
        "n_rows": int(arch.size),
        "counts": counts,
        "n_win": int(win_idx.size),
        "raw_file_type_counts": raw_counts,
        "label_counts": labels or None,
        "n_missing_arch_field": n_missing,
        "n_bad_json": n_bad_json,
        "arch_npy": str(layout.arch_path("challenge")),
        "win_index_npy": str(layout.split_idx_path("challenge_win")),
        "note": ("행 순서는 gather_feature_paths() 반환 순서 x 각 파일의 줄 순서. "
                 "02_vectorize 이후 X_challenge.dat의 행 수가 n_rows와 같은지 "
                 "반드시 검증할 것."),
    }
    write_json(layout.reports / "challenge_filetype_report.json", report)

    # 논문 Table 3 기준값과 대조 (경고만)
    if arch.size and abs(arch.size - 6315) > 50:
        log.warning("challenge 행 수 %d — 논문 기준 6,315와 차이가 큽니다.", arch.size)
    if counts["OTHER"] == 0:
        log.warning("OTHER가 0입니다. 파일 타입 파싱이 잘못됐을 가능성이 큽니다.")

    return report


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> int:
    enable_utf8_console()

    ap = argparse.ArgumentParser(description="EMBER2024 Win32/Win64 다운로드")
    add_root_arg(ap)
    ap.add_argument("--force", action="store_true", help="완료 마커를 무시하고 재다운로드")
    ap.add_argument("--skip-challenge", action="store_true",
                    help="challenge 셋을 받지 않음 (권장하지 않음)")
    ap.add_argument("--retries", type=int, default=3, help="다운로드 재시도 횟수")
    ap.add_argument("--min-free-gb", type=int, default=60,
                    help="드라이브별 최소 여유 공간(GB)")
    ap.add_argument("--skip-preflight", action="store_true",
                    help="환경 점검을 건너뜀")
    ap.add_argument("--strict-preflight", action="store_true",
                    help="경고도 실패로 처리")
    ap.add_argument("--arch-key", default=None,
                    help="challenge .jsonl의 파일 타입 필드명 (자동 감지 실패 시)")
    args = ap.parse_args()

    layout = Layout(args.root)
    layout.mkdirs()
    log = setup_logging("01_download", layout.logs)

    log.info("작업 루트: %s", layout.root)
    log.info("플랫폼: %s / Python %s", sys.platform, sys.version.split()[0])

    try:
        import thrember
    except ImportError:
        log.error("thrember를 import할 수 없습니다.")
        log.error("  git clone https://github.com/FutureComputing4AI/EMBER2024.git")
        log.error("  cd EMBER2024 && pip install .")
        return 1

    if not args.skip_preflight:
        if not preflight(log, layout, args.min_free_gb, args.strict_preflight):
            log.error("환경 점검 실패. 문제를 해결한 뒤 다시 실행하세요 "
                      "(무시하려면 --skip-preflight).")
            return 1

    failures: list[str] = []
    cwd = os.getcwd()

    try:
        for file_type, split in COMBOS:
            key = f"download_{file_type}_{split}"
            if layout.is_done(key) and not args.force:
                log.info("스킵: %s / %s (이미 완료)", file_type, split)
                continue

            before_n, before_b = dir_stats(layout.dataset)
            ok = download_one(log, thrember, layout, cwd, args.retries,
                              split=split, file_type=file_type)
            after_n, after_b = dir_stats(layout.dataset)

            if not ok:
                failures.append(f"{file_type}/{split}")
                continue

            if after_n == before_n:
                log.warning("%s / %s: 새로 생긴 파일이 없습니다. 이미 받았거나 "
                            "다운로드가 비어 있습니다.", file_type, split)

            # 마커에 실측치를 남겨 다음 실행에서 무결성을 대조할 수 있게 한다.
            layout.mark_done(key, {
                "file_type": file_type,
                "split": split,
                "files_added": after_n - before_n,
                "bytes_added": after_b - before_b,
                "dataset_files_total": after_n,
                "dataset_bytes_total": after_b,
            })

        if not args.skip_challenge:
            key = "download_challenge"
            if layout.is_done(key) and not args.force:
                log.info("스킵: challenge (이미 완료)")
            else:
                before_n, before_b = dir_stats(layout.dataset)
                ok = download_one(log, thrember, layout, cwd, args.retries,
                                  split="challenge", file_type=None)
                after_n, after_b = dir_stats(layout.dataset)
                if ok:
                    layout.mark_done(key, {
                        "split": "challenge",
                        "files_added": after_n - before_n,
                        "bytes_added": after_b - before_b,
                    })
                else:
                    failures.append("challenge")
        else:
            log.warning("challenge를 건너뜁니다. create_vectorized_features()가 "
                        "challenge 파일을 찾지 못해 실패할 수 있습니다.")
    except KeyboardInterrupt:
        log.warning("사용자가 중단했습니다. 완료된 항목은 마커에 남아 있으므로 "
                    "다시 실행하면 이어서 진행됩니다.")
        return 130
    finally:
        os.chdir(cwd)

    # ---- challenge 파일 타입 인덱싱 -------------------------------------
    if not args.skip_challenge and "challenge" not in failures:
        key = "arch_challenge"
        if layout.is_done(key) and not args.force:
            log.info("스킵: challenge arch 인덱싱 (이미 완료)")
        else:
            try:
                with timed(log, "challenge 파일 타입 인덱싱"):
                    report = build_challenge_arch(log, layout, args.arch_key)
                if report is None:
                    failures.append("arch_challenge")
                else:
                    layout.mark_done(key, {
                        "n_rows": report["n_rows"],
                        "n_win": report["n_win"],
                        "counts": report["counts"],
                        "arch_key": report["arch_key"],
                    })
            except Exception:
                log.exception("challenge arch 인덱싱 실패")
                failures.append("arch_challenge")

    # ---- 요약 -----------------------------------------------------------
    jsonl = sorted(layout.dataset.rglob("*.jsonl"))
    n_files, n_bytes = dir_stats(layout.dataset)
    log.info("내려받은 .jsonl 파일 수: %d", len(jsonl))
    log.info("dataset 디렉터리: 파일 %d개 / %s", n_files, fmt_bytes(n_bytes))

    n_win32 = sum(1 for p in jsonl if "Win32" in p.name)
    n_win64 = sum(1 for p in jsonl if "Win64" in p.name)
    n_other = len(jsonl) - n_win32 - n_win64
    log.info("  Win32: %d개 / Win64: %d개 / 기타(challenge 등): %d개",
             n_win32, n_win64, n_other)

    if n_other == 0 and not args.skip_challenge:
        log.warning("challenge 파일로 보이는 .jsonl이 없습니다. 확인이 필요합니다.")
        failures.append("challenge_missing")

    if failures:
        log.error("실패 항목: %s", ", ".join(failures))
        log.error("동일 명령을 다시 실행하면 완료된 항목은 건너뜁니다.")
        return 1

    log.info("다음 단계: python 02_vectorize.py --root %s", args.root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
