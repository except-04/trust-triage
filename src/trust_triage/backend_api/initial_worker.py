"""Reuse trusted models while each untrusted PE gets a disposable extractor.

Only bounded JSON feature/result messages cross the process boundary. Model
files remain in the inference child, which is replaced on timeout or failure.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any
from uuid import uuid4

from .errors import BackendError
from .initial_analysis import (
    InitialAnalysisConfig,
    _build_explainer,
    _explain,
    _failure,
    _predict_initial,
    _stop_process,
    _xai_failure,
)
from .model_bundle import ModelBundle

LOGGER = logging.getLogger(__name__)
MAX_MESSAGE_BYTES = 2 * 1024 * 1024
_DISCONNECTED = object()


def _send(connection: Any, kind: str, job_id: str, payload: dict) -> None:
    data = json.dumps(
        {"kind": kind, "job_id": job_id, "payload": payload}, allow_nan=False
    ).encode("utf-8")
    if len(data) > MAX_MESSAGE_BYTES:
        raise ValueError("Initial-analysis IPC message exceeds its limit")
    connection.send_bytes(data)


def _receive(connection: Any) -> dict:
    message = json.loads(connection.recv_bytes(MAX_MESSAGE_BYTES))
    if (
        not isinstance(message, dict)
        or set(message) != {"kind", "job_id", "payload"}
        or not isinstance(message["kind"], str)
        or not isinstance(message["job_id"], str)
        or not isinstance(message["payload"], dict)
    ):
        raise ValueError("Invalid initial-analysis IPC message")
    return message


def _send_error(connection: Any, exc: Exception, job_id: str, stage: str) -> None:
    if isinstance(exc, BackendError):
        error = exc
    elif isinstance(exc, ImportError):
        error = _failure(
            "MODEL_DEPENDENCY_MISSING",
            "Initial-analysis dependencies are unavailable.",
            stage,
            http_status=503,
        )
    else:
        error = _failure("INITIAL_ANALYSIS_FAILED", "Initial analysis failed.", stage)
    _send(
        connection,
        "error",
        job_id,
        {**error.to_dict(), "http_status": error.http_status},
    )


def _extract_entry(
    max_file_size: int, path: Path, job_id: str, connection: Any
) -> None:
    try:
        import numpy as np

        from trust_triage.feature_extraction import EmberV3Extractor

        result = EmberV3Extractor(
            max_file_size_bytes=max_file_size, verify_source=True
        ).extract(path)
        if not np.all(np.isfinite(np.asarray(result.features, dtype=np.float32))):
            raise _failure(
                "FEATURE_NONFINITE",
                "The current feature/model contract rejects NaN or infinite inputs; no values were imputed.",
                "FEATURE_EXTRACTION",
            )
        # The inference process needs numeric features and bounded diagnostics,
        # never raw PE bytes, import lists, or extractor implementation metadata.
        payload = replace(result, api_groups=None, metadata={}).to_dict()
        _send(connection, "features", job_id, payload)
    except Exception as exc:  # noqa: BLE001 - redact native parser failures.
        _send_error(connection, exc, job_id, "FEATURE_EXTRACTION")
    finally:
        connection.close()


def _model_entry(config: InitialAnalysisConfig, connection: Any) -> None:
    try:
        from trust_triage.feature_extraction import (
            EmberV3Extractor,
            ExtractionStatus,
            FeatureExtractionResult,
        )

        # Construct the verified source schema without opening a sample.
        schema = EmberV3Extractor(
            max_file_size_bytes=config.max_file_size_bytes, verify_source=True
        ).schema
        bundle = ModelBundle.load(config.artifacts, schema)
        _send(connection, "ready", "", {})
        explainer = None
        while True:
            message = _receive(connection)
            job_id, payload = message["job_id"], message["payload"]
            if message["kind"] != "analyze":
                raise ValueError("Unexpected initial-analysis request")
            try:
                feature_data = dict(payload["features"])
                feature_data.pop("api_groups", None)
                feature_data["status"] = ExtractionStatus(feature_data["status"])
                result = FeatureExtractionResult(**feature_data)
                initial, vector = _predict_initial(result, bundle, payload["sha256"])
                _send(connection, "initial", job_id, initial)
            except Exception as exc:  # noqa: BLE001 - retire possibly dirty native state.
                _send_error(connection, exc, job_id, "MODEL_INFERENCE")
                break
            try:
                if explainer is None:
                    explainer = _build_explainer(bundle)
                features = _explain(
                    bundle, vector, config.shap_top_k, explainer=explainer
                )
                xai = {
                    "top_features": features,
                    "xai_status": "SUCCESS",
                    "xai_error": None,
                }
            except BackendError as exc:
                xai = {
                    "top_features": [],
                    "xai_status": "FAILED",
                    "xai_error": exc.to_dict(),
                }
            except ImportError:
                xai = _xai_failure(
                    "XAI_DEPENDENCY_MISSING",
                    "SHAP dependencies are unavailable; the initial model/JRR decision is preserved.",
                )
            except Exception:  # noqa: BLE001 - preserve prediction on optional SHAP failure.
                xai = _xai_failure(
                    "XAI_FAILED",
                    "SHAP explanation failed; the initial model/JRR decision is preserved.",
                )
            _send(connection, "xai", job_id, xai)
            if xai["xai_status"] != "SUCCESS":
                break
    except (EOFError, OSError):
        pass
    except Exception as exc:  # noqa: BLE001 - sanitize startup/protocol errors.
        _send_error(connection, exc, "", "MODEL_LOADING")
    finally:
        connection.close()


class _Channel:
    """A partial native pipe read/write cannot block the supervising deadline."""

    def __init__(self, connection: Any) -> None:
        self.connection = connection
        self.messages: queue.Queue = queue.Queue(maxsize=8)
        self.stop = threading.Event()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.writer: threading.Thread | None = None
        self.reader.start()

    def _publish(self, message: Any) -> None:
        while not self.stop.is_set():
            try:
                self.messages.put(message, timeout=0.05)
                return
            except queue.Full:
                continue

    def _read(self) -> None:
        try:
            while not self.stop.is_set():
                self._publish(_receive(self.connection))
        except Exception:  # noqa: BLE001 - a malformed child message means the channel is unusable.
            self._publish(_DISCONNECTED)

    def get(self) -> Any:
        try:
            return self.messages.get(timeout=0.05)
        except queue.Empty:
            return None

    def send(
        self, kind: str, job_id: str, payload: dict, check: Callable[[], None]
    ) -> None:
        done, failures = threading.Event(), []

        def write() -> None:
            try:
                _send(self.connection, kind, job_id, payload)
            except (OSError, ValueError, TypeError) as exc:
                failures.append(exc)
            finally:
                done.set()

        self.writer = threading.Thread(target=write, daemon=True)
        self.writer.start()
        while not done.wait(0.05):
            check()
        check()
        if failures:
            raise _failure(
                "INITIAL_ANALYSIS_PROCESS_EXITED",
                "Initial analysis ended without a result.",
                "MODEL_INFERENCE",
            ) from failures[0]

    def close(self) -> None:
        self.stop.set()
        self.connection.close()
        self.reader.join(timeout=0.5)
        if self.writer is not None:
            self.writer.join(timeout=0.5)


class ReusableInitialAnalysis:
    """One serial inference child per backend runner; no model lives in the API."""

    def __init__(
        self,
        config: InitialAnalysisConfig,
        context: Any,
        clock: Callable[[], float],
        *,
        model_target: Any = _model_entry,
        extraction_target: Any = _extract_entry,
    ) -> None:
        self.config, self.context, self.clock = config, context, clock
        self.model_target, self.extraction_target = model_target, extraction_target
        self.process = self.channel = self.signature = None
        self.jobs = 0
        self.lock = threading.Lock()

    def _artifact_signature(self) -> tuple:
        paths = self.config.artifacts.validated_paths()
        signature = []
        try:
            for name, path in sorted(paths.items()):
                stat = path.stat()
                signature.append(
                    (
                        name,
                        str(path),
                        stat.st_dev,
                        stat.st_ino,
                        stat.st_size,
                        stat.st_mtime_ns,
                        stat.st_ctime_ns,
                    )
                )
        except OSError as exc:
            raise _failure(
                "MODEL_ARTIFACT_MISSING",
                "A configured initial-analysis artifact is missing.",
                "MODEL_LOADING",
                http_status=503,
            ) from exc
        return (
            self.config.max_file_size_bytes,
            self.config.shap_top_k,
            tuple(signature),
        )

    def _spawn(self, target: Any, args: tuple, *, duplex: bool, stage: str) -> tuple:
        parent, child = self.context.Pipe(duplex=duplex)
        process = self.context.Process(target=target, args=(*args, child))
        process.daemon = True
        try:
            process.start()
        except (OSError, RuntimeError) as exc:
            parent.close()
            child.close()
            process.close()
            raise _failure(
                "INITIAL_ANALYSIS_START_FAILED",
                "The initial-analysis worker could not start.",
                stage,
            ) from exc
        child.close()
        return process, _Channel(parent)

    def _check(self, deadline: float, stage: str, check: Any) -> None:
        if check is not None:
            check()
        if self.clock() >= deadline:
            code = (
                "FEATURE_EXTRACTION_TIMEOUT"
                if stage == "FEATURE_EXTRACTION"
                else "INITIAL_ANALYSIS_TIMEOUT"
            )
            raise _failure(
                code,
                "Initial analysis exceeded its stage time limit.",
                stage,
                http_status=504,
            )

    def _next(
        self, channel: _Channel, job_id: str, deadline: float, stage: str, check: Any
    ) -> dict:
        while True:
            self._check(deadline, stage, check)
            message = channel.get()
            if message is None:
                continue
            if message is _DISCONNECTED:
                raise _failure(
                    "INITIAL_ANALYSIS_PROCESS_EXITED",
                    "Initial analysis ended without a result.",
                    stage,
                )
            if message["job_id"] != job_id:
                raise _failure(
                    "INITIAL_ANALYSIS_PROTOCOL_ERROR",
                    "Initial-analysis response identity did not match.",
                    stage,
                )
            if message["kind"] not in {"ready", "features", "initial", "xai", "error"}:
                raise _failure(
                    "INITIAL_ANALYSIS_PROTOCOL_ERROR",
                    "Initial-analysis response type was invalid.",
                    stage,
                )
            if message["kind"] == "error":
                payload = message["payload"]
                if not isinstance(payload.get("code"), str) or not isinstance(
                    payload.get("message"), str
                ):
                    raise _failure(
                        "INITIAL_ANALYSIS_PROTOCOL_ERROR",
                        "Initial-analysis error response was invalid.",
                        stage,
                    )
                raise BackendError(
                    payload["code"],
                    payload["message"],
                    stage=payload.get("stage"),
                    http_status=payload.get("http_status", 500),
                    retryable=payload.get("retryable", False),
                )
            return message

    def _discard(self) -> None:
        process, channel = self.process, self.channel
        self.process = self.channel = self.signature = None
        self.jobs = 0
        try:
            if process is not None:
                _stop_process(process)
        finally:
            if channel is not None:
                channel.close()

    def close(self) -> None:
        with self.lock:
            self._discard()

    def _prepare(self, signature: tuple, check: Any) -> bool:
        if (
            self.process is not None
            and self.process.is_alive()
            and self.signature == signature
        ):
            return True
        self._discard()
        self.process, self.channel = self._spawn(
            self.model_target, (self.config,), duplex=True, stage="MODEL_LOADING"
        )
        try:
            message = self._next(
                self.channel,
                "",
                self.clock() + self.config.inference_timeout_seconds,
                "MODEL_LOADING",
                check,
            )
            if message["kind"] != "ready":
                raise _failure(
                    "INITIAL_ANALYSIS_PROTOCOL_ERROR",
                    "Initial-analysis worker was not ready.",
                    "MODEL_LOADING",
                )
            self.signature = signature
            return False
        except BaseException:
            self._discard()
            raise

    def _extract(self, path: Path, job_id: str, check: Any) -> dict:
        deadline = self.clock() + self.config.extraction_timeout_seconds
        process, channel = self._spawn(
            self.extraction_target,
            (self.config.max_file_size_bytes, path, job_id),
            duplex=False,
            stage="FEATURE_EXTRACTION",
        )
        try:
            message = self._next(channel, job_id, deadline, "FEATURE_EXTRACTION", check)
            if message["kind"] != "features":
                raise _failure(
                    "INITIAL_ANALYSIS_PROTOCOL_ERROR",
                    "Initial-analysis features were unavailable.",
                    "FEATURE_EXTRACTION",
                )
            return message["payload"]
        finally:
            try:
                _stop_process(process)
            finally:
                channel.close()

    def _timing(self, sha256: str, stage: str, started: float, reused: bool) -> None:
        LOGGER.info(
            "initial_analysis_timing sha256=%s stage=%s elapsed_ms=%.3f model_reused=%s model_worker_pid=%s",
            sha256,
            stage,
            max(0.0, self.clock() - started) * 1000,
            reused,
            getattr(self.process, "pid", None),
        )

    def _infer(
        self, features: dict, sha256: str, job_id: str, check: Any, reused: bool
    ) -> dict:
        stage, started = "MODEL_INFERENCE", self.clock()
        deadline = started + self.config.inference_timeout_seconds
        initial = None
        try:
            self.channel.send(
                "analyze",
                job_id,
                {"features": features, "sha256": sha256},
                lambda: self._check(deadline, stage, check),
            )
            while True:
                try:
                    message = self._next(self.channel, job_id, deadline, stage, check)
                except BackendError as exc:
                    if initial is None or exc.code not in {
                        "INITIAL_ANALYSIS_TIMEOUT",
                        "INITIAL_ANALYSIS_PROCESS_EXITED",
                    }:
                        raise
                    return {
                        **initial,
                        **_xai_failure(
                            "XAI_TIMEOUT"
                            if exc.code == "INITIAL_ANALYSIS_TIMEOUT"
                            else "XAI_PROCESS_EXITED",
                            "SHAP explanation did not complete; the initial model/JRR decision is preserved.",
                        ),
                    }
                if message["kind"] == "initial" and initial is None:
                    initial = message["payload"]
                    self._timing(sha256, stage, started, reused)
                    stage, started = "XAI", self.clock()
                    deadline = started + self.config.xai_timeout_seconds
                elif message["kind"] == "xai" and initial is not None:
                    return {**initial, **message["payload"]}
                else:
                    raise _failure(
                        "INITIAL_ANALYSIS_PROTOCOL_ERROR",
                        "Unexpected initial-analysis response.",
                        stage,
                    )
        except BaseException:
            self._discard()
            raise
        finally:
            self._timing(sha256, stage, started, reused)
            # An XAI timeout returns a preserved prediction, so cleanup must
            # also cover returns instead of relying only on exception handling.
            if initial is not None and stage == "XAI" and self.clock() >= deadline:
                self._discard()

    def analyze(self, path: Path, *, sha256: str, check: Any = None) -> dict:
        with self.lock:
            if check is not None:
                check()
            started, reused = self.clock(), False
            try:
                reused = self._prepare(self._artifact_signature(), check)
            finally:
                self._timing(sha256, "MODEL_LOADING", started, reused)
            job_id, started = uuid4().hex, self.clock()
            try:
                features = self._extract(path, job_id, check)
            finally:
                self._timing(sha256, "FEATURE_EXTRACTION", started, reused)
            output = self._infer(features, sha256, job_id, check, reused)
            if output["xai_status"] != "SUCCESS":
                self._discard()
            elif self.process is not None:
                self.jobs += 1
                if self.jobs >= self.config.model_worker_max_jobs:
                    self._discard()
            return output
