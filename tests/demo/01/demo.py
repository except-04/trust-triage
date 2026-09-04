import argparse
import json
import logging
import pathlib
import sys
import hashlib
import joblib
import numpy as np
import importlib.util

from trust_triage.feature_extraction import (
    EmberV3Extractor,
    ExtractionStatus,
    FeatureSelector
)

log = logging.getLogger("demo")
ROOT = pathlib.Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent / "trust-triage"
ARTIFACTS = ROOT / "artifacts"
SELECTION_JSON = ARTIFACTS / "feature-selection-ember-v3-top500.json"
LGB_PATH = ARTIFACTS / "baseline_model_lightgbm_tuned_500_v4_9120.pkl"
XGB_PATH = ARTIFACTS / "baseline_model_xgb_500.pkl"
CALIB_PATH = ARTIFACTS / "jrr_calibrator.pkl"
JRR_ROUTER_PATH = REPO_ROOT / "src" / "jrr" / "jrr_router.py"

TAU_LOW = 0.1
TAU_DISAGREE = 0.3
EXTRACT_TIMEOUT_SEC = 30.0

class InputError(Exception):
    """입력 파일이 파이프라인에 진입할 수 없음"""
class ExtractError(Exception):
    """추출 실패"""

    def __init__(self, result):
        super().__init__(f"extraction failed: {result.status.value}")
        self.result = result

def new_response(info: dict) -> dict:
    return {
        "sha256": info["sha256"],
        "verdict": "심층 분석",
        "analysis_status": None,
        "calibrated_probability": None,
        "risk_score": None,
        "route": "MANUAL_REVIEW",
        "top_features": []
    }

# 인자 파싱 준비 함수
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog = "demo",
        description = "demo until JRR",
        allow_abbrev = False
    )

    p.add_argument("--path", type = pathlib.Path, required = True, help = "분석 대상 경로")
    p.add_argument("--quiet", action = "store_true", help = "진행 로그 출력을 끄는 옵션")

    return p

# 로그 세팅 함수
def setup_logging(quiet:bool) -> None:
    if quiet is True:
        level = logging.ERROR
    else:
        level = logging.INFO

    logging.basicConfig(
        stream = sys.stderr,
        level = level,
        format = "[%(levelname)s] %(message)s"
    )

# 최종 딕셔너리를 json으로 바꿔서 stdout에 출력하는 함수
def emit(response: dict) -> None:
    json.dump(response, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")

# 입력 파일 사전검사 함수
# 경로에 문제가 없는지, 읽기 권한이 있는지 + sha256 계산
def prepare_input(path: pathlib.Path) -> dict:
    try:
        with open(path, "rb") as f:
            sha256 = hashlib.file_digest(f, "sha256").hexdigest()
    except OSError as e:
        raise InputError(f"can't open the file: {e}") from e

    return {
        "sha256": sha256
    }

# extractor, selector 세팅 함수
def prepare_extract() -> tuple:
    extractor = EmberV3Extractor()
    selector = FeatureSelector.from_json_file(extractor.schema, SELECTION_JSON)

    return extractor, selector
    
# 특징 추출 함수
def extract(extractor, selector, path: pathlib.Path) -> tuple:
    result = extractor.extract_with_timeout(path, EXTRACT_TIMEOUT_SEC)

    if result.status is not ExtractionStatus.SUCCESS:
        raise ExtractError(result)

    x = result.to_model_input(selector)

    return x, result

# 모델 로드 함수
def load_models_predict() -> tuple:
    lgb = joblib.load(LGB_PATH)
    xgb = joblib.load(XGB_PATH)

    return lgb, xgb

# 예측
def predict(lgb, xgb, x: np.ndarray) -> tuple:
    X = x.reshape(1, -1)
    p_lgb_raw = float(lgb.predict_proba(X)[:, 1][0])
    p_xgb_raw = float(xgb.predict_proba(X)[:, 1][0])

    return p_lgb_raw, p_xgb_raw

# 모델 로드 함수
def load_models_calib() -> tuple:
    p = joblib.load(CALIB_PATH)
    calib = p["model"]
    tau_high = p["threshold"]

    return calib, tau_high

# JRR signal 계산
def signals(calib, p_lgb_raw: float, p_xgb_raw: float) -> tuple:
    p_calib = float(calib.predict([p_lgb_raw])[0])
    disagreement = abs(p_lgb_raw - p_xgb_raw)

    return p_calib, disagreement

# jrr_router.py를 일반적인 방법으로 import 할 수 없어 사용
def load_router_class(router_path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("jrr_router", router_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.JointRiskRouter

# 라우터 준비 함수
def prepare_route(tau_high: float):
    JointRiskRouter = load_router_class(JRR_ROUTER_PATH)
    return JointRiskRouter(tau_low = TAU_LOW, tau_high = tau_high, tau_disagree = TAU_DISAGREE)

# JRR 라우팅
def route(router, p_calib: float, disagreement: float) -> dict:
    return router.route_sample(p_calib, disagreement)

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    setup_logging(quiet = args.quiet)

    # 절대경로화
    path = args.path.expanduser().resolve()
    log.info("target: %s", path)

    response = None

    try:
        # 경로에 문제 있는지 검사 + sha256 계산
        info = prepare_input(path)
        log.info("sha256: %s\n", info["sha256"])

        response = new_response(info)

        # extractor, selector 준비
        extractor, selector = prepare_extract()
        log.info("extractor ready")
        log.info("selector ready: %d features", selector.feature_count)

        # 특징 추출
        x, result = extract(extractor, selector, path)
        response["analysis_status"] = result.status.name
        log.info("features: %s, %s, nonzero = %d\n", x.shape, x.dtype, int(np.count_nonzero(x)))

        # 모델 로드
        lgb, xgb = load_models_predict()
        log.info("predict models: %s / %s", type(lgb).__name__, type(xgb).__name__)

        # 예측
        p_lgb_raw, p_xgb_raw = predict(lgb, xgb, x)
        log.info("p_lgb_raw = %.4f p_xgb_raw = %.4f\n", p_lgb_raw, p_xgb_raw)

        # 모델 로드
        calib, TAU_HIGH = load_models_calib()
        log.info("calib model: %s", type(calib).__name__)

        # JRR signal 계산
        p_calib, disagreement = signals(calib, p_lgb_raw, p_xgb_raw)
        response["calibrated_probability"] = p_calib
        log.info("p_calib = %.4f", p_calib)
        log.info("disagreement = %.4f\n", disagreement)

        # 라우팅
        router = prepare_route(TAU_HIGH)
        routed = route(router, p_calib, disagreement)
        response["route"] = routed["decision"]
        log.info("router ready (tau_high = %.4f, tau_low = %.4f, tau_disagreement = %.4f)", TAU_HIGH, TAU_LOW, TAU_DISAGREE)
        log.info("route: %s", routed["decision"])
        log.info("reason: %s\n", routed["reason"])

        if response["route"] == "AUTO_PASS":
            response["verdict"] = "자동 정상"
        elif response["route"] == "AUTO_QUARANTINE":
            response["verdict"] = "자동 악성"
        else:
            response["verdict"] = "심층 분석"

    except InputError as e:
        log.error("%s", e)
        return 2

    except ExtractError as e:
        log.error("%s", e)
        response["analysis_status"] = e.result.status.name
        emit(response)
        return 2

    emit(response)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())