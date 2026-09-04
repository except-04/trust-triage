"""모델 학습용 4분할 NumPy artifact 계약 검증."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import numpy as np

EXPECTED_FEATURE_DIM = 2568
EXPECTED_ROWS = {"tr": 2_720_000, "val": 480_000, "calib": 480_000, "eval": 480_000}
SPLITS = tuple(EXPECTED_ROWS)


class DataContractError(ValueError):
    """4분할 artifact가 학습 데이터 계약을 위반했음을 나타낸다."""


@dataclass(frozen=True)
class SplitData:
    """검증이 끝난 한 split의 X/y와 원본 경로."""

    X: np.ndarray
    y: np.ndarray
    x_path: Path
    y_path: Path


def validate_four_way_contract(
    data_dir: str | Path,
    *,
    expected_rows: Mapping[str, int] = EXPECTED_ROWS,
    expected_feature_dim: int = EXPECTED_FEATURE_DIM,
) -> dict[str, SplitData]:
    """train/validation/calibration/eval artifact를 fallback 없이 검증한다."""

    root = Path(data_dir).expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"data directory does not exist: {root}")
    if tuple(expected_rows) != SPLITS:
        raise DataContractError(f"expected split keys and order must be {SPLITS}")

    paths: list[Path] = []
    loaded: dict[str, SplitData] = {}
    for split in SPLITS:
        x_path = (root / f"X_{split}.npy").resolve()
        y_path = (root / f"y_{split}.npy").resolve()
        for path in (x_path, y_path):
            if not path.is_file():
                raise FileNotFoundError(f"required {split} artifact does not exist: {path}")
            paths.append(path)

        X = np.load(x_path, mmap_mode="r", allow_pickle=False)
        y = np.load(y_path, mmap_mode="r", allow_pickle=False)
        expected_n = int(expected_rows[split])
        if X.ndim >= 1 and y.ndim >= 1 and X.shape[0] != y.shape[0]:
            raise DataContractError(f"{split} X/y row mismatch: X={X.shape[0]}, y={y.shape[0]}")
        if X.ndim != 2 or X.shape[1] != expected_feature_dim:
            raise DataContractError(
                f"X_{split} must have shape ({expected_n}, {expected_feature_dim}); got {X.shape}"
            )
        if X.shape[0] != expected_n:
            raise DataContractError(f"X_{split} row count must be {expected_n}; got {X.shape[0]}")
        if y.ndim != 1 or y.shape[0] != expected_n:
            raise DataContractError(f"y_{split} must have shape ({expected_n},); got {y.shape}")
        labels = np.unique(y)
        if not np.all(np.isin(labels, np.array([0, 1]))):
            raise DataContractError(
                f"y_{split} contains labels outside binary contract: {labels.tolist()}"
            )
        loaded[split] = SplitData(X=X, y=y, x_path=x_path, y_path=y_path)

    if len(set(paths)) != len(paths):
        raise DataContractError("split X/y paths must all be distinct")
    return loaded


def load_top_indices(path: str | Path, *, expected_count: int = 500) -> np.ndarray:
    """기존 규칙대로 Top-N 원본 index를 오름차순으로 반환한다."""

    artifact = Path(path).expanduser().resolve()
    if not artifact.is_file():
        raise FileNotFoundError(f"top-feature index artifact does not exist: {artifact}")
    indices = np.load(artifact, allow_pickle=False)
    if indices.shape != (expected_count,) or not np.issubdtype(indices.dtype, np.integer):
        raise DataContractError(
            f"top-feature indices must be an integer array with shape ({expected_count},)"
        )
    indices = np.sort(indices.astype(np.int64, copy=False))
    if len(np.unique(indices)) != expected_count:
        raise DataContractError("top-feature indices must be unique")
    if indices[0] < 0 or indices[-1] >= EXPECTED_FEATURE_DIM:
        raise DataContractError("top-feature index is outside [0, 2568)")
    return indices


def require_new_output(path: str | Path) -> Path:
    """기존 artifact를 덮어쓰지 않는 새 출력 경로를 검증한다."""

    output = Path(path).expanduser().resolve()
    if output.exists():
        raise FileExistsError(f"refusing to overwrite existing artifact: {output}")
    if not output.parent.is_dir():
        raise FileNotFoundError(f"output parent directory does not exist: {output.parent}")
    return output
