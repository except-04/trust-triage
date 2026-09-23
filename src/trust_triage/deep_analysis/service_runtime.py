"""실제 CAPA/FLOSS, PostgreSQL, SQS, S3와 기존 LLM 해석기를 조립한다."""

from __future__ import annotations

import math
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

import boto3
from botocore.config import Config

from ..speakeasy_worker.config import WorkerConfig
from ..speakeasy_worker.repository import PostgresJobRepository
from ..speakeasy_worker.runtime import create_publisher
from ..speakeasy_worker.storage import S3SampleStore
from ..static_analysis import CapaAnalyzer, CapaConfig, FlossAnalyzer, FlossConfig
from ..storage import S3ArtifactStorage
from .checkpoints import MAX_CHECKPOINT_BYTES
from .llm_interpreter import MonoGPTClaudeInterpreter, MonoGPTConfig
from .orchestrator import DeepAnalysisOrchestrator
from .service import DeepAnalysisService, DeepServiceLimits
from .service_repository import PostgresDeepAnalysisRepository


def _number(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be a finite positive number") from exc
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a finite positive number")
    return value


def _integer(name: str, default: int) -> int:
    value = _number(name, default)
    if not value.is_integer():
        raise ValueError(f"{name} must be an integer")
    return int(value)


def _limits_from_env() -> DeepServiceLimits:
    return DeepServiceLimits(
        lease_seconds=_integer("DEEP_LEASE_SECONDS", 600),
        heartbeat_seconds=_number("DEEP_HEARTBEAT_SECONDS", 30),
        operation_timeout_seconds=_number("DEEP_OPERATION_TIMEOUT_SECONDS", 480),
        speakeasy_wait_seconds=_number("DEEP_SPEAKEASY_WAIT_SECONDS", 86400),
        max_transient_failures=_integer("DEEP_MAX_TRANSIENT_FAILURES", 3),
        retry_delay_seconds=_integer("DEEP_RETRY_DELAY_SECONDS", 30),
    )


def _optional_path(name: str) -> Path | None:
    value = os.getenv(name, "").strip()
    return Path(value) if value else None


@dataclass
class DeepAnalysisRuntime:
    service: DeepAnalysisService
    repository: PostgresDeepAnalysisRepository
    worker_repository: PostgresJobRepository

    def check(self) -> None:
        self.repository.check()
        self.worker_repository.check()
        self.service.publisher.queue.attributes()
        for name, analyzer in (
            ("CAPA", self.service.orchestrator.capa_analyzer),
            ("FLOSS", self.service.orchestrator.floss_analyzer),
        ):
            executable = str(analyzer.config.executable)
            if shutil.which(executable) is None and not Path(executable).is_file():
                raise ValueError(
                    f"{name} executable was not found; configure {name}_EXECUTABLE"
                )
        config = self.service.orchestrator.capa_analyzer.config
        for name in ("rules_path", "signatures_path"):
            path = getattr(config, name)
            if path is not None and not path.exists():
                raise ValueError(f"Configured CAPA {name} was not found")


def create_deep_analysis_runtime(
    config: WorkerConfig | None = None,
) -> DeepAnalysisRuntime:
    config = config or WorkerConfig.from_env()
    limits = _limits_from_env()
    capa_timeout = _number("DEEP_CAPA_TIMEOUT_SECONDS", 120)
    floss_timeout = _number("DEEP_FLOSS_TIMEOUT_SECONDS", 120)
    llm_config = MonoGPTConfig.from_env(load_env_file=False)
    if not math.isfinite(llm_config.timeout_seconds):
        raise ValueError("MONOGPT_TIMEOUT_SECONDS must be finite")
    total_timeout = config.download_timeout_seconds + capa_timeout + floss_timeout
    if llm_config.is_configured:
        total_timeout += llm_config.timeout_seconds
    if total_timeout >= limits.operation_timeout_seconds:
        raise ValueError(
            "DEEP_OPERATION_TIMEOUT_SECONDS must exceed download, static tool and LLM timeouts combined"
        )
    capa_executable = os.getenv("CAPA_EXECUTABLE", "capa").strip()
    floss_executable = os.getenv("FLOSS_EXECUTABLE", "floss").strip()
    if not capa_executable or not floss_executable:
        raise ValueError("CAPA_EXECUTABLE and FLOSS_EXECUTABLE must not be empty")
    orchestrator = DeepAnalysisOrchestrator(
        capa_analyzer=CapaAnalyzer(
            CapaConfig(
                executable=capa_executable,
                timeout_seconds=capa_timeout,
                rules_path=_optional_path("CAPA_RULES_PATH"),
                signatures_path=_optional_path("CAPA_SIGNATURES_PATH"),
                rules_version=os.getenv("CAPA_RULES_VERSION") or None,
            )
        ),
        floss_analyzer=FlossAnalyzer(
            FlossConfig(
                executable=floss_executable,
                timeout_seconds=floss_timeout,
            )
        ),
        llm_interpreter=MonoGPTClaudeInterpreter(llm_config),
    )
    publisher = create_publisher(config)
    repository = PostgresDeepAnalysisRepository(config.database_url)
    s3 = boto3.client(
        "s3",
        region_name=config.region,
        config=Config(
            connect_timeout=3,
            read_timeout=10,
            retries={"mode": "standard", "total_max_attempts": 1},
        ),
    )
    service = DeepAnalysisService(
        repository=repository,
        publisher=publisher,
        orchestrator=orchestrator,
        artifact_storage=S3ArtifactStorage(
            s3,
            bucket=config.s3_bucket,
            prefix=config.s3_prefix,
            temp_root=Path(config.temp_root) / "deep-analysis-artifacts",
            max_bytes=MAX_CHECKPOINT_BYTES,
            download_timeout_seconds=config.download_timeout_seconds,
        ),
        limits=limits,
        samples=S3SampleStore(
            s3,
            bucket=config.s3_bucket,
            prefix=config.s3_prefix,
            temp_root=Path(config.temp_root) / "deep-analysis",
            max_file_bytes=config.max_file_bytes,
            download_timeout_seconds=config.download_timeout_seconds,
        ),
    )
    return DeepAnalysisRuntime(service, repository, publisher.repository)


def create_deep_analysis_service(
    config: WorkerConfig | None = None,
) -> DeepAnalysisService:
    """환경변수 설정 후 Backend에서 재사용할 서비스 인스턴스를 만든다."""

    return create_deep_analysis_runtime(config).service
