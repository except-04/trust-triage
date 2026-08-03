"""EMBER2024 Feature Version 3 추출 인터페이스."""

from .api_groups import (
    API_GROUPS_SCHEMA_VERSION,
    DEFAULT_API_GROUPS,
    ApiImportMatch,
    ApiGroupMatch,
    ApiGroupReport,
    OrdinalImport,
    classify_imports,
)
from .ember_v3 import EmberV3Extractor, extract_file
from .result import ExtractionStatus, FeatureExtractionResult
from .schema import FeatureGroup, FeatureSchema

__all__ = [
    "EmberV3Extractor",
    "API_GROUPS_SCHEMA_VERSION",
    "ApiImportMatch",
    "ApiGroupMatch",
    "ApiGroupReport",
    "DEFAULT_API_GROUPS",
    "OrdinalImport",
    "ExtractionStatus",
    "FeatureGroup",
    "FeatureSchema",
    "FeatureExtractionResult",
    "classify_imports",
    "extract_file",
]
