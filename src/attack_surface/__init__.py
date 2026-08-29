"""attack-surface: построение поверхности атаки на базе trailmark."""

from attack_surface._attack_surface import AttackChain, ReachabilityResult, compute_attack_surface
from attack_surface._call_graph import CallGraphBuilder
from attack_surface._extractor import EntryPointExtractor
from attack_surface._graph import generate_attack_surface_graph
from attack_surface._interface_llm import (
    InterfaceAnalyzerLLM,
    InterfaceBatchAnalyzerLLM,
    InterfaceDescriptor,
)
from attack_surface._link_llm import LinkValidatorLLM
from attack_surface._linker import CrossRepoEdge, CrossRepoLinker
from attack_surface._logger import Logger
from attack_surface._models import (
    ENTRY_POINT_DISPLAY_NAMES,
    EntryPointInfo,
    EntryPointType,
    ExternalSource,
    ScanResult,
    display_name,
)
from attack_surface._project_config import (
    LinkConfig,
    LinkType,
    ProjectConfig,
    RepoConfig,
    load_project_config,
)
from attack_surface._project_graph import build_project_graph_model, generate_project_graph
from attack_surface._project_pipeline import ProjectScanResult, ProjectScanner, RepoScanResult
from attack_surface._report import generate_html_report
from attack_surface._threagile import (
    build_threagile_model,
    dump_threagile,
    load_threagile,
    save_threagile,
)

__all__ = [
    "ENTRY_POINT_DISPLAY_NAMES",
    "AttackChain",
    "CallGraphBuilder",
    "CrossRepoEdge",
    "CrossRepoLinker",
    "EntryPointExtractor",
    "EntryPointInfo",
    "EntryPointType",
    "ExternalSource",
    "InterfaceAnalyzerLLM",
    "InterfaceBatchAnalyzerLLM",
    "InterfaceDescriptor",
    "LinkConfig",
    "LinkType",
    "LinkValidatorLLM",
    "Logger",
    "ProjectConfig",
    "ProjectScanResult",
    "ProjectScanner",
    "ReachabilityResult",
    "RepoConfig",
    "RepoScanResult",
    "ScanResult",
    "build_project_graph_model",
    "build_threagile_model",
    "compute_attack_surface",
    "display_name",
    "dump_threagile",
    "generate_attack_surface_graph",
    "generate_html_report",
    "generate_project_graph",
    "load_project_config",
    "load_threagile",
    "save_threagile",
]
__version__ = "0.1.0"
