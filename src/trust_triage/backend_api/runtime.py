"""실제 PostgreSQL·저장소·분석 모듈을 조립한다. import만으로 접속하지 않는다."""

from __future__ import annotations

import importlib.util
import os

from .config import BackendConfig, _integer, _positive
from .deep_gateway import ExistingDeepGateway
from .errors import BackendError
from .initial_analysis import InitialAnalysisConfig, InitialAnalysisService
from .model_bundle import ModelBundleConfig
from .processor import BackendProcessor
from .repository import PostgresAnalysisRepository
from .service import BackendService
from .storage import LocalSampleStorage, S3SampleStorage


def initial_config(config: BackendConfig) -> InitialAnalysisConfig:
    artifacts = ModelBundleConfig(
        **{
            name: os.getenv(f"BACKEND_{name.upper()}") or None
            for name in ModelBundleConfig.__dataclass_fields__
        }
    )
    value = InitialAnalysisConfig(
        artifacts=artifacts,
        extraction_timeout_seconds=_positive("BACKEND_EXTRACTION_TIMEOUT_SECONDS", 30),
        inference_timeout_seconds=_positive("BACKEND_INFERENCE_TIMEOUT_SECONDS", 120),
        xai_timeout_seconds=_positive("BACKEND_XAI_TIMEOUT_SECONDS", 30),
        shap_top_k=_integer("BACKEND_SHAP_TOP_K", 5),
        max_file_size_bytes=config.max_file_bytes,
    )
    total = (
        config.download_timeout_seconds
        + value.extraction_timeout_seconds
        + 2 * value.inference_timeout_seconds
        + value.xai_timeout_seconds
    )
    if total >= config.operation_timeout_seconds:
        raise ValueError(
            "BACKEND_OPERATION_TIMEOUT_SECONDS must exceed download, model loading, extraction, inference and XAI timeouts combined"
        )
    return value


def create_service(config: BackendConfig | None = None) -> BackendService:
    config = config or BackendConfig.from_env()
    if not config.database_url:
        raise BackendError(
            "DATABASE_NOT_CONFIGURED",
            "BACKEND_DATABASE_URL을 설정해주세요.",
            http_status=503,
        )
    repository = PostgresAnalysisRepository(config.database_url)
    if config.storage_mode == "local":
        storage = LocalSampleStorage(
            config.storage_root, max_file_bytes=config.max_file_bytes
        )
    else:
        import boto3
        from botocore.config import Config

        client = boto3.client(
            "s3",
            region_name=config.aws_region,
            config=Config(
                connect_timeout=3,
                read_timeout=10,
                retries={"mode": "standard", "total_max_attempts": 1},
            ),
        )
        storage = S3SampleStorage(
            client,
            bucket=config.s3_bucket,
            prefix=config.s3_prefix,
            temp_root=config.temp_root,
            max_file_bytes=config.max_file_bytes,
            download_timeout_seconds=config.download_timeout_seconds,
        )
    gateway = ExistingDeepGateway(config)
    return BackendService(repository, storage, config, cleanup_guard=gateway.can_delete)


def create_processor(service: BackendService) -> BackendProcessor:
    return BackendProcessor(
        service.repository,
        service.storage,
        InitialAnalysisService(initial_config(service.config)),
        ExistingDeepGateway(service.config),
        service.config,
    )


def check(
    service: BackendService, *, analysis: bool = False, deep: bool = False
) -> dict:
    service.repository.check()
    service.storage.check()
    if analysis:
        initial_config(service.config).artifacts.validated_paths()
        for name in (
            "numpy",
            "pefile",
            "thrember",
            "lightgbm",
            "xgboost",
            "sklearn",
            "joblib",
            "shap",
        ):
            if importlib.util.find_spec(name) is None:
                raise BackendError(
                    "MODEL_DEPENDENCY_MISSING",
                    "requirements-backend-analysis.txt의 분석 의존성을 설치해주세요.",
                    http_status=503,
                    stage="MODEL_LOADING",
                )
    if deep:
        ExistingDeepGateway(service.config).check()
    return {
        "status": "ready",
        "analysis_files_and_dependencies_checked": analysis,
        "deep_checked": deep,
    }
