"""
EMBER2024 Win32/Win64 데이터 준비 파이프라인 - 공통 유틸리티

모든 단계 스크립트가 공유하는 경로 레이아웃, memmap 헬퍼, 로깅을 제공한다.
32GB RAM 환경을 가정하므로 X 행렬은 절대 통째로 RAM에 올리지 않는다.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
from pathlib import Path

import numpy as np

# --------------------------------------------------------------------------
# 상수
# --------------------------------------------------------------------------

# 분할은 week_id 기반 결정론적 시간 분할이라 시드가 필요 없다. 이 값은 이후
# 모델 학습 등 다른 단계에서 재현성이 필요할 때 참조하라고 남겨둔 것뿐이다.
SEED = 42

SUBSETS = ("train", "test", "challenge")

# arch 인덱스 인코딩
ARCH_WIN32 = 0
ARCH_WIN64 = 1
ARCH_OTHER = 2  # challenge 셋에 섞여 있는 APK / ELF / PDF / .NET
ARCH_NAMES = {ARCH_WIN32: "Win32", ARCH_WIN64: "Win64", ARCH_OTHER: "OTHER"}

# 라벨 인코딩 (thrember 기준)
LABEL_UNKNOWN = -1
LABEL_BENIGN = 0
LABEL_MALICIOUS = 1

# 시간 기반 분할 경계 (week_id 기준).
# EMBER2024는 IID가 아니라 시간축 설계이므로 무작위 분할이 금지된다.
# train 원본은 week_id 0–51(52주). 이를 시간 순서대로 4분할한다:
#   idx_tr    : weeks  0–33  (약 65%, 모델 파라미터 적합 전용)
#   idx_val   : weeks 34–39  (약 12%, 하이퍼파라미터/모델 선택 전용)
#   idx_calib : weeks 40–45  (약 12%, 임계값·확률 보정 전용)
#   idx_eval  : weeks 46–51  (약 12%, 시간 이동 후 성능 확인용)
#
# 왜 validation을 따로 두는가
# --------------------------
# 초기 설계는 train(0–39) / calib(40–45) / eval(46–51)의 3분할이라 validation이
# 없었다. 그러면 모델 선택(하이퍼파라미터 탐색, early stopping)을 할 곳이 없어
# calibration이나 eval이 그 역할까지 겸하게 된다. 그 순간
#   * calib에서 모델을 고르면 → 그 모델의 임계값을 같은 데이터로 정하게 되어
#     목표 FPR이 낙관적으로 추정된다(임계값 과적합).
#   * eval에서 모델을 고르면 → eval이 더 이상 '시간 이동 후 성능'의 정직한
#     추정치가 아니게 되고, 사실상 test를 미리 소모한 셈이 된다.
# 그래서 train의 뒤쪽 6주를 떼어 validation으로 만든다. 모델 선택은 val에서
# 끝내고, calib는 확정된 단일 모델의 임계값만 만지고, eval은 읽기만 한다.
#
# val / calib / eval의 폭을 각 6주로 동일하게 두는 대칭성이 비율보다 중요하다.
# 폭이 같아야 "val→calib 6주 이동", "calib→eval 6주 이동"에서 관측한 성능 저하를
# 서로 비교할 수 있고, eval의 저하폭이 test에서 겪을 저하의 대리 지표가 된다.
# 비율은 경계의 결과로 받아들이고, 6:2:2를 맞추려 주차를 쪼개지 않는다.
WEEK_TRAIN_END = 33     # idx_tr    = week <= 33
WEEK_VAL_START = 34     # idx_val   = 34 <= week <= 39
WEEK_VAL_END = 39
WEEK_CALIB_START = 40   # idx_calib = 40 <= week <= 45
WEEK_CALIB_END = 45
WEEK_EVAL_START = 46    # idx_eval  = week >= 46
WEEK_MAX = 51           # train 원본의 마지막 주차 (사전 검증용)

# 개발용 분할 이름. 시간 순서대로 나열한다 (04/05/06단계가 이 순서로 순회한다).
DEV_SPLITS = ("tr", "val", "calib", "eval")

# 각 분할의 주차 구간 [시작, 끝] (양끝 포함). 경계 로직의 단일 진실 공급원.
SPLIT_WEEKS = {
    "tr": (0, WEEK_TRAIN_END),
    "val": (WEEK_VAL_START, WEEK_VAL_END),
    "calib": (WEEK_CALIB_START, WEEK_CALIB_END),
    "eval": (WEEK_EVAL_START, WEEK_MAX),
}

# 메타데이터에 담는 필드.
#   sha256    : 식별자 / 중복 검사
#   week_id   : 시간 분할 기준 (필수)
#   file_type : challenge 필터 / .NET 제외 (필수)
#   family    : 사후 오분석용 (분할에는 쓰지 않음, 정상 파일은 null)
#   label     : 벡터 행 순서 정합성 검증용
META_FIELDS = ("sha256", "week_id", "file_type", "family", "label")

# 분할에 쓰는 유효 file_type (이 외 .NET / APK / ELF / PDF 등은 PE 학습에서 제외)
PE_FILE_TYPES = ("Win32", "Win64")

# 청크 크기(행 단위). 20000행 x 2568차원 x 4바이트 = 약 205MB
DEFAULT_CHUNK = 20_000


# --------------------------------------------------------------------------
# 분할 계약 (split contract)
# --------------------------------------------------------------------------
#
# 데이터 분할은 파일을 나누는 일이 아니라 "각 조각을 무엇에 쓰고 무엇에 쓰지
# 않을지"를 약속하는 일이다. 약속이 문서 밖(사람 머릿속)에만 있으면 몇 주 뒤에
# 반드시 깨진다. 그래서 계약을 코드 상수로 두고 06단계가 manifest.json에
# 그대로 박아 넣는다. 분할을 바꾸면 계약도 같이 바뀌어 산출물에 남는다.

SPLIT_CONTRACT_RATIONALE = (
    "초기 3분할(train 0–39 / calib 40–45 / eval 46–51)에는 validation이 없어서 "
    "모델 선택을 할 곳이 없었고, calibration과 eval이 그 역할까지 겸해야 했다. "
    "calib에서 모델을 고르면 같은 데이터로 임계값까지 정하게 되어 목표 FPR이 "
    "낙관적으로 추정되고, eval에서 고르면 eval이 시간 이동 성능의 정직한 추정치가 "
    "아니게 된다. train의 뒤쪽 6주(34–39)를 validation으로 분리해 각 조각에 "
    "역할을 하나씩만 준다."
)

SPLIT_CONTRACT_ORDER = [
    "1) tr에서 학습한다 (fit).",
    "2) val에서 하이퍼파라미터를 고르고 early stopping을 걸고 모델을 확정한다.",
    "3) 모델을 확정한 뒤에야 calib에서 목표 FPR 임계값과 확률 보정을 산출한다.",
    "4) eval에서 (2)(3)의 결과가 6주 시간 이동 후에도 유지되는지 확인만 한다.",
    "5) 모든 결정이 끝난 뒤 lockbox(test/challenge)를 단 한 번 연다.",
]


def split_contract() -> dict:
    """
    각 분할의 용도/허용/금지를 기계가 읽을 수 있는 형태로 돌려준다.
    06단계가 manifest.json의 "split_contract" 항목으로 기록한다.
    """
    def weeks(name: str) -> str:
        lo, hi = SPLIT_WEEKS[name]
        return f"{lo} <= week <= {hi}"

    return {
        "rationale": SPLIT_CONTRACT_RATIONALE,
        "order_of_use": SPLIT_CONTRACT_ORDER,
        "splits": {
            "tr": {
                "weeks": list(SPLIT_WEEKS["tr"]),
                "week_rule": weeks("tr"),
                "files": ["out/dev/X_tr.npy", "out/dev/y_tr.npy",
                          "out/dev/arch_tr.npy"],
                "role": "모델 파라미터 적합(fit) 전용",
                "allowed": [
                    "model.fit() / booster 학습",
                    "특징 전처리 통계(median, scaler 등) 산출 — 반드시 여기서만",
                    "횟수 제한 없이 반복 사용",
                ],
                "forbidden": [
                    "성능 보고 (train 성능은 진단용일 뿐 결과가 아니다)",
                ],
                "touch_budget": "무제한",
            },
            "val": {
                "weeks": list(SPLIT_WEEKS["val"]),
                "week_rule": weeks("val"),
                "files": ["out/dev/X_val.npy", "out/dev/y_val.npy",
                          "out/dev/arch_val.npy"],
                "role": "하이퍼파라미터 탐색 / early stopping / 모델 선택 전용",
                "allowed": [
                    "하이퍼파라미터 탐색과 비교",
                    "LightGBM early stopping의 valid_sets",
                    "특징 선택, 임베딩/아키텍처 후보 비교",
                    "반복 사용 (단, 과적합은 val에 쌓인다는 점을 감안)",
                ],
                "forbidden": [
                    "운영 임계값 산출 (그것은 calib의 역할)",
                    "최종 성능 보고 (여러 번 들여다본 데이터는 낙관 편향된다)",
                    "학습에 포함 (val을 tr에 합쳐 재학습하면 계약이 깨진다)",
                ],
                "touch_budget": "반복 허용",
            },
            "calib": {
                "weeks": list(SPLIT_WEEKS["calib"]),
                "week_rule": weeks("calib"),
                "files": ["out/dev/X_calib.npy", "out/dev/y_calib.npy",
                          "out/dev/arch_calib.npy"],
                "role": "확정된 단일 모델의 임계값·확률 보정 전용",
                "allowed": [
                    "목표 FPR(예: 1e-3)에서의 임계값 산출",
                    "확률 보정 (Platt / isotonic)",
                    "arch(Win32/Win64)별 임계값 분리 산출",
                ],
                "forbidden": [
                    "모델 선택이나 하이퍼파라미터 비교 (val에서 끝냈어야 한다)",
                    "학습에 포함",
                ],
                "touch_budget": "모델 확정 후 1회",
            },
            "eval": {
                "weeks": list(SPLIT_WEEKS["eval"]),
                "week_rule": weeks("eval"),
                "files": ["out/dev/X_eval.npy", "out/dev/y_eval.npy",
                          "out/dev/arch_eval.npy"],
                "role": "시간 이동 후 성능 확인 (읽기 전용 진단)",
                "allowed": [
                    "calib에서 정한 임계값이 6주 뒤에도 유지되는지 확인",
                    "ROC-AUC 및 고정 FPR에서의 TPR을 arch별로 분해해 보고",
                ],
                "forbidden": [
                    "eval 결과를 보고 모델/임계값/특징을 되돌려 바꾸기 "
                    "(되먹임하는 순간 eval은 두 번째 validation이 된다)",
                    "학습에 포함",
                ],
                "touch_budget": "가급적 1회, 되먹임 금지",
            },
            "lockbox(test/challenge)": {
                "weeks": None,
                "week_rule": "train과 별개의 원본 subset (시간 분할 대상 아님)",
                "files": ["out/lockbox/X_test.npy", "out/lockbox/X_challenge.npy"],
                "role": "최종 보고용 1회성 평가",
                "allowed": [
                    "모든 결정이 끝난 뒤 단 한 번의 최종 평가",
                    "valid_mask_*.npy를 적용해 라벨 -1 행 제외",
                ],
                "forbidden": [
                    "개발 중 열람",
                    "결과를 보고 모델을 수정한 뒤 재평가",
                ],
                "touch_budget": "1회",
            },
        },
    }


# --------------------------------------------------------------------------
# 로깅
# --------------------------------------------------------------------------

def enable_utf8_console() -> None:
    """
    Windows 콘솔(cp949 등)에서 로그의 ▶ / ■ / ✖ 같은 비ASCII 기호를 찍다
    UnicodeEncodeError로 로그가 유실되는 것을 막는다.

    common.Timer가 ▶/■/✖를 쓰므로 Timer를 사용하는 모든 단계(02~06)에서
    필요하다. 로깅 오류는 치명적이지 않지만(파이썬 logging이 삼킨다),
    콘솔에 '--- Logging error ---' 트레이스백이 쏟아지고 해당 로그 줄이
    사라진다. stdout/stderr를 UTF-8로 재설정해 두면 모두 해결된다.

    - reconfigure()는 Python 3.7+의 TextIOWrapper에만 있다. 없거나 실패하면
      조용히 넘어간다(예: stdout이 리다이렉트된 특수 스트림).
    - errors="replace"로 두어, 재설정이 불가능한 극단적 상황에서도 최소한
      크래시는 나지 않게 한다.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def setup_logging(name: str, log_dir: Path | None = None) -> logging.Logger:
    # 핸들러를 만들기 전에 콘솔 인코딩부터 UTF-8로 맞춘다.
    # 01_download 외의 단계들도 Timer의 ▶/■/✖를 콘솔에 찍기 때문에,
    # 여기서 한 번 처리해 두면 모든 단계가 Windows에서 안전해진다.
    enable_utf8_console()

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-7s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_dir / f"{name}.log", encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


class Timer:
    """
    with 블록의 소요 시간을 측정하고 로깅한다.

    - time.monotonic()을 쓴다. time.time()은 NTP 보정이나 시스템 시계 변경에
      영향을 받아 수 시간짜리 단계에서 음수/과대 측정이 나올 수 있다.
    - 블록이 예외로 끝나면 "완료"가 아니라 "실패"로 기록한다.
    - 종료 후 timer.elapsed(초)로 값을 다시 꺼내 쓸 수 있다.
    """

    def __init__(self, logger: logging.Logger, label: str):
        self.logger = logger
        self.label = label
        self.t0: float | None = None
        self.elapsed: float = 0.0

    def __enter__(self) -> "Timer":
        self.t0 = time.monotonic()
        self.elapsed = 0.0
        self.logger.info("▶ %s 시작", self.label)
        return self

    def peek(self) -> float:
        """블록 안에서 현재까지의 경과 시간(초)을 확인한다."""
        if self.t0 is None:
            return self.elapsed
        return time.monotonic() - self.t0

    def __exit__(self, exc_type, exc, tb) -> bool:
        self.elapsed = self.peek()
        self.t0 = None
        if exc_type is None:
            self.logger.info("■ %s 완료 (%s)", self.label, fmt_duration(self.elapsed))
        else:
            self.logger.error(
                "✖ %s 실패 (%s) — %s: %s",
                self.label, fmt_duration(self.elapsed), exc_type.__name__, exc,
            )
        return False  # 예외는 그대로 위로 전파시킨다


def fmt_duration(sec: float) -> str:
    """
    초를 사람이 읽는 문자열로 바꾼다.

    1초 미만은 "0초"로 뭉개지 않고 ms로 표시하고, 음수도 int() 절단 때문에
    "-1시간 59분 55초" 같은 값이 나오지 않도록 부호를 먼저 분리한다.
    """
    try:
        sec = float(sec)
    except (TypeError, ValueError):
        return "N/A"
    if sec != sec:  # NaN
        return "N/A"

    sign = "-" if sec < 0 else ""
    sec = abs(sec)

    if sec < 1:
        return f"{sign}{sec * 1000:.0f}ms"

    h, rem = divmod(int(sec), 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{sign}{h}시간 {m}분 {s}초"
    if m:
        return f"{sign}{m}분 {s}초"
    return f"{sign}{s}초"


def fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"


# --------------------------------------------------------------------------
# 디렉터리 레이아웃
# --------------------------------------------------------------------------

class Layout:
    """
    작업 루트 아래의 표준 디렉터리 구조.

    <root>/
      dataset/            원본 .jsonl + thrember가 만든 .dat (44GB + 26GB)
      out/
        dev/              X_tr / X_val / X_calib / X_eval  (개발용, 자유 사용)
        lockbox/          X_test / X_challenge     (봉인, 읽기 전용)
        index/            분할 인덱스, arch 인덱스, valid 마스크 (수 MB)
        reports/          QC 리포트, manifest, README
      .state/             단계별 완료 마커 (재실행 시 스킵용)
      logs/
    """

    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve()
        self.dataset = self.root / "dataset"
        self.out = self.root / "out"
        self.dev = self.out / "dev"
        self.lockbox = self.out / "lockbox"
        self.index = self.out / "index"
        self.reports = self.out / "reports"
        self.state = self.root / ".state"
        self.logs = self.root / "logs"

    def mkdirs(self) -> None:
        for d in (
            self.dataset, self.out, self.dev, self.lockbox,
            self.index, self.reports, self.state, self.logs,
        ):
            d.mkdir(parents=True, exist_ok=True)

    # --- 단계 완료 마커 -------------------------------------------------

    def marker(self, name: str) -> Path:
        return self.state / f"{name}.done"

    def is_done(self, name: str) -> bool:
        return self.marker(name).exists()

    def mark_done(self, name: str, payload: dict | None = None) -> None:
        self.state.mkdir(parents=True, exist_ok=True)
        body = {"completed_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        if payload:
            body.update(payload)
        self.marker(name).write_text(
            json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    # --- 파일 경로 ------------------------------------------------------

    def dat(self, subset: str) -> tuple[Path, Path]:
        return (self.dataset / f"X_{subset}.dat", self.dataset / f"y_{subset}.dat")

    def arch_path(self, subset: str) -> Path:
        return self.index / f"arch_{subset}.npy"

    def split_idx_path(self, split: str) -> Path:
        return self.index / f"idx_{split}.npy"

    def valid_mask_path(self, subset: str) -> Path:
        return self.index / f"valid_mask_{subset}.npy"

    def meta_path(self, subset: str) -> Path:
        """
        벡터 행 순서와 동일한 순서의 메타데이터. 03단계 산출물.

        저장 포맷은 pandas pickle(.pkl)이다. parquet(pyarrow/fastparquet)은
        네이티브 DLL을 요구해 스마트 앱 제어 등 애플리케이션 제어 정책이 걸린
        Windows에서 로딩이 차단될 수 있다. pickle은 pandas만 있으면 되므로
        추가 네이티브 의존성 없이 어디서나 동작한다.
        """
        return self.index / f"meta_{subset}.pkl"


def add_root_arg(parser) -> None:
    """모든 단계 스크립트가 공유하는 --root 인자."""
    parser.add_argument(
        "--root",
        default="./ember2024_work",
        help="작업 루트 디렉터리 (기본값: ./ember2024_work)",
    )


# --------------------------------------------------------------------------
# thrember 연동
# --------------------------------------------------------------------------

_DIM_CACHE: int | None = None


def get_dim() -> int:
    """
    특징 벡터 차원을 thrember에서 직접 가져온다 (하드코딩 금지).
    현재 feature version 3 기준 2568.
    """
    global _DIM_CACHE
    if _DIM_CACHE is None:
        from thrember.features import PEFeatureExtractor
        _DIM_CACHE = int(PEFeatureExtractor().dim)
    return _DIM_CACHE


def gather_paths(dataset_dir: Path, subset: str) -> list[Path]:
    """
    thrember의 gather_feature_paths를 그대로 재사용한다.

    직접 구현하면 정렬 규칙이 미묘하게 어긋나 행 순서가 틀어질 수 있으므로
    반드시 원본 함수를 import해서 쓴다. 벡터화 시 행 순서가 이 함수의
    반환 순서 x 각 파일의 줄 순서로 결정되기 때문이다.
    """
    from thrember.model import gather_feature_paths
    return list(gather_feature_paths(dataset_dir, subset))


# --------------------------------------------------------------------------
# memmap 헬퍼
# --------------------------------------------------------------------------

def open_dat(layout: Layout, subset: str, dim: int | None = None):
    """
    thrember가 만든 .dat을 읽기 전용 memmap으로 연다.

    thrember.read_vectorized_features()는 내부에서 np.array(X)를 호출해
    21GB를 통째로 RAM에 복사하므로 32GB 환경에서는 사용할 수 없다.
    여기서는 파일 크기로부터 행 수를 역산해 lazy memmap을 만든다.

    Returns: (X, y, nrows)
    """
    if dim is None:
        dim = get_dim()

    x_path, y_path = layout.dat(subset)
    if not x_path.is_file():
        raise FileNotFoundError(f"{x_path} 없음 — vectorize.py를 먼저 실행하세요.")
    if not y_path.is_file():
        raise FileNotFoundError(f"{y_path} 없음 — vectorize.py를 먼저 실행하세요.")

    x_bytes = x_path.stat().st_size
    y_bytes = y_path.stat().st_size
    row_bytes = dim * 4  # float32

    if x_bytes % row_bytes != 0:
        raise ValueError(
            f"{x_path.name} 크기({x_bytes})가 행 크기({row_bytes})로 나누어떨어지지 "
            f"않습니다. 벡터화가 중단되었거나 dim({dim})이 잘못되었습니다."
        )
    n = x_bytes // row_bytes

    if y_bytes // 4 != n:
        raise ValueError(
            f"X({n}행)와 y({y_bytes // 4}행)의 행 수가 다릅니다. "
            f"벡터화를 다시 수행해야 합니다."
        )

    X = np.memmap(x_path, dtype=np.float32, mode="r", shape=(n, dim))
    y = np.memmap(y_path, dtype=np.int32, mode="r", shape=(n,))
    return X, y, n


def load_y(layout: Layout, subset: str) -> np.ndarray:
    """y만 RAM으로 복사한다 (208만 x int32 = 8MB, 안전)."""
    _, y_path = layout.dat(subset)
    y = np.memmap(y_path, dtype=np.int32, mode="r")
    return np.array(y)


def iter_chunks(n: int, chunk: int = DEFAULT_CHUNK):
    """[0, n)을 chunk 크기로 잘라 (start, stop)을 순회한다."""
    for s in range(0, n, chunk):
        yield s, min(s + chunk, n)


def load_meta(layout: Layout, subset: str):
    """
    03단계가 만든 메타데이터(pandas pickle)를 DataFrame으로 읽는다.

    컬럼: sha256, week_id, file_type, family, label. 행 순서는 벡터화(.dat)와
    동일하므로 X_*.dat / y_*.dat / arch_*.npy 와 그대로 대응된다.
    """
    import pandas as pd  # 지역 import: 메타데이터를 쓰는 단계에서만 pandas 요구

    path = layout.meta_path(subset)
    if not path.is_file():
        raise FileNotFoundError(
            f"{path} 없음 — build_index.py(메타데이터 추출)를 먼저 실행하세요."
        )
    return pd.read_pickle(path)


# --------------------------------------------------------------------------
# 해시 / JSON
# --------------------------------------------------------------------------

def sha256_file(path: Path, buf_size: int = 8 << 20) -> str:
    """대용량 파일도 안전하게 스트리밍 해시."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(buf_size)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, ensure_ascii=False, indent=2, default=_json_default),
        encoding="utf-8",
    )


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _json_default(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    if isinstance(o, Path):
        return str(o)
    raise TypeError(f"직렬화 불가: {type(o)}")


# --------------------------------------------------------------------------
# 통계 헬퍼
# --------------------------------------------------------------------------

def label_stats(y: np.ndarray, arch: np.ndarray | None = None) -> dict:
    """
    라벨 분포를 집계한다.

    np.bincount는 음수를 받지 못하므로 -1을 먼저 분리해서 센다.
    """
    y = np.asarray(y)
    n = int(y.size)
    n_unknown = int((y == LABEL_UNKNOWN).sum())
    labeled = y[y >= 0]
    counts = np.bincount(labeled, minlength=2) if labeled.size else np.zeros(2, int)

    out = {
        "n_total": n,
        "n_unknown(-1)": n_unknown,
        "n_labeled": int(labeled.size),
        "n_benign(0)": int(counts[0]),
        "n_malicious(1)": int(counts[1]),
        "malicious_ratio": (
            float(counts[1] / labeled.size) if labeled.size else None
        ),
        "unique_label_values": sorted(int(v) for v in np.unique(y)),
    }

    if arch is not None:
        arch = np.asarray(arch)
        per_arch = {}
        for a in np.unique(arch):
            m = arch == a
            ya = y[m]
            la = ya[ya >= 0]
            ca = np.bincount(la, minlength=2) if la.size else np.zeros(2, int)
            per_arch[ARCH_NAMES.get(int(a), f"ARCH_{int(a)}")] = {
                "n_total": int(m.sum()),
                "n_unknown(-1)": int((ya == LABEL_UNKNOWN).sum()),
                "n_benign(0)": int(ca[0]),
                "n_malicious(1)": int(ca[1]),
                "malicious_ratio": float(ca[1] / la.size) if la.size else None,
            }
        out["per_arch"] = per_arch

    return out


def env_versions() -> dict:
    """재현성을 위해 기록해 둘 버전 정보."""
    import platform
    info = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "numpy": np.__version__,
    }
    for mod in ("pefile", "sklearn", "thrember", "lightgbm", "pandas"):
        try:
            m = __import__(mod)
            info[mod] = getattr(m, "__version__", "unknown")
        except Exception:
            info[mod] = "not installed"
    return info


def thrember_commit(repo_dir: str | Path | None) -> str | None:
    """thrember 저장소의 git 커밋 해시 (인덱스 공유 시 재현성 확인용)."""
    if repo_dir is None:
        return None
    import subprocess
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=15,
        )
        return out.stdout.strip() or None
    except Exception:
        return None
