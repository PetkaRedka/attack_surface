"""attack-surface: построение поверхности атаки на базе trailmark."""

from attack_surface._call_graph import CallGraphBuilder
from attack_surface._extractor import EntryPointExtractor
from attack_surface._graph import generate_attack_surface_graph
from attack_surface._logger import Logger
from attack_surface._models import (
    ENTRY_POINT_DISPLAY_NAMES,
    EntryPointInfo,
    EntryPointType,
    ExternalSource,
    ScanResult,
    display_name,
)
from attack_surface._report import generate_html_report

__all__ = [
    "ENTRY_POINT_DISPLAY_NAMES",
    "CallGraphBuilder",
    "EntryPointExtractor",
    "EntryPointInfo",
    "EntryPointType",
    "ExternalSource",
    "Logger",
    "ScanResult",
    "display_name",
    "generate_attack_surface_graph",
    "generate_html_report",
]
__version__ = "0.1.0"
