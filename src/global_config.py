import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import loguru
import yaml

from backends.csa import ClangBackend
from backends.factory import AnalysisBackendFactory
from targets.compiledb import CompileDBTarget
from targets.factory import TargetFactory
from targets.linux import Linux
from targets.v8 import V8

logger = loguru.logger


def _compiledb_target(config: "GlobalConfig") -> CompileDBTarget:
    options = dict(config.get("target_options") or {})
    if "repo_dir" not in options or "setup" not in options:
        raise ValueError("compiledb target needs `target_options.repo_dir` and `target_options.setup`")
    options.setdefault("llvm_bin", str(Path(config.get("LLVM_dir")) / "build" / "bin"))
    options.setdefault("jobs", config.get("analysis_jobs", 8))
    return CompileDBTarget(**options)


# target_type -> constructor. Add new target kinds here.
TARGET_BUILDERS = {
    "linux": lambda config: Linux(
        config.get("linux_dir"), incremental=config.get("linux_incremental", False)
    ),
    "v8": lambda config: V8(config.get("v8_dir")),
    "compiledb": _compiledb_target,
}


class GlobalConfig:
    """Singleton class to manage global configuration settings."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(GlobalConfig, cls).__new__(cls, *args, **kwargs)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        self._config: Dict[str, Any] = {}
        self._keys: Dict[str, Any] = {}

    def setup(self, config_path: str = "config.yaml"):
        if self._initialized:
            logger.warning("GlobalConfig is already initialized.")
            return

        self._load_config(config_path)

        keys_path = self.get("key_file", "llm_keys.yaml")
        self._load_keys(keys_path)
        self._initialized = True
        self._keys["model"] = self.get("model")

        self._init_logger()

        # Init the target and backend
        target_type = self.get("target_type", "linux")
        if target_type not in TARGET_BUILDERS:
            raise ValueError(
                f"Unknown target_type '{target_type}'. "
                f"Known: {', '.join(sorted(TARGET_BUILDERS))}"
            )
        self._config["target"] = TARGET_BUILDERS[target_type](self)

        plugin_build = self.get("plugin_build", "standalone")
        if target_type == "v8" and plugin_build != "legacy":
            # The V8 analysis path hardcodes the in-tree plugin location.
            logger.warning("V8 target: forcing plugin_build=legacy")
            plugin_build = "legacy"
        self._config["backend"] = ClangBackend(
            self.get("LLVM_dir"),
            plugin_build=plugin_build,
            plugin_cache_dir=self.get("plugin_cache_dir", "tmp/plugin-cache"),
            plugin_opt_level=self.get("plugin_opt_level", "-O1"),
            plugin_pch=self.get("plugin_pch", True),
            max_parallel_plugin_builds=self.get("max_parallel_plugin_builds", 4),
            plugin_cache=self.get("plugin_cache", True),
            plugin_preamble=self.get("plugin_preamble", True),
            analysis_jobs=self.get("analysis_jobs", 8),
            analysis_timeout=self.get("analysis_timeout", 600),
            max_loop=self.get("max_loop", 4),
            validation_scoring=self.get("validation_scoring", "strict"),
        )
        logger.info(
            f"Target: {self._config['target']}; plugin_build={plugin_build}; "
            f"validation_scoring={self.get('validation_scoring', 'strict')}"
        )

    def _init_logger(self):
        """Initialize the logger."""
        log_dir = Path("logs")
        if not log_dir.exists():
            log_dir.mkdir()

        result_name = Path(self.get("result_dir")).stem
        time_stamp = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())
        logger.add(
            f"{log_dir}/{result_name}-{time_stamp}.log",
            rotation="1 day",
            retention="7 days",
            level="DEBUG",
        )

    def _load_config(self, path: str):
        try:
            with open(path, "r") as f:
                self._config = yaml.safe_load(f) or {}
        except FileNotFoundError:
            logger.error(f"Config file '{path}' not found.")
            exit(-1)

    def _load_keys(self, path: str):
        try:
            with open(path, "r") as f:
                self._keys = yaml.safe_load(f) or {}
        except FileNotFoundError:
            logger.error(f"Keys file '{path}' not found.")
            exit(-1)

    def get_key_config(self) -> Dict[str, Any]:
        """Get the keys configuration."""
        return self._keys

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self._config.get(key, default)

    @property
    def target(self) -> Optional[TargetFactory]:
        """Get the target."""
        return self._config.get("target")

    @property
    def backend(self) -> Optional[AnalysisBackendFactory]:
        """Get the backend."""
        return self._config.get("backend")

    @property
    def result_dir(self) -> Optional[Path]:
        """Get the result directory."""
        return Path(self.get("result_dir"))

    @property
    def scan_timeout(self) -> Optional[int]:
        """Get the scan timeout."""
        return self.get("scan_timeout", 600)

    @property
    def scan_commit(self) -> Optional[str]:
        """Get the scan commit."""
        return self.get("scan_commit", "main")

    @property
    def max_fp_reports_for_refinement(self) -> int:
        """Get the maximum number of false positive reports to use for refinement."""
        return self.get("max_fp_reports_for_refinement", 5)

    @property
    def max_fp_reports_for_batch(self) -> int:
        """Get the maximum number of false positive reports to use for batch refinement."""
        return self.get("max_fp_reports_for_batch", 5)

    @property
    def group_scan_targets(self) -> List[str]:
        """Get the default scan targets for group scanning."""
        return self.get("group_scan_targets", ["drivers/"])

    @property
    def group_scan_timeout(self) -> int:
        """Get the timeout for group scanning in seconds."""
        return self.get("group_scan_timeout", 3600)  # 60 minutes for large groups

    @property
    def group_scan_jobs(self) -> int:
        """Get the number of parallel jobs for group scanning."""
        return self.get("group_scan_jobs", 32)

    @property
    def project_description(self) -> str:
        """How prompts name the analyzed project ("a patch to <this>")."""
        project = self.get("project") or {}
        if project.get("description"):
            return project["description"]
        target_type = self.get("target_type", "linux")
        if target_type == "linux":
            return "the Linux kernel"
        if target_type == "v8":
            return "the V8 JavaScript engine"
        name = (self.get("target_options") or {}).get("name", "the target project")
        return f"{name}, a C project"

    @property
    def project_feasibility(self) -> str:
        """Name of the NULL-feasibility guidance for triage (prompt_template/knowledge/feasibility-<name>.md)."""
        project = self.get("project") or {}
        if project.get("feasibility"):
            return project["feasibility"]
        return "linux" if self.get("target_type", "linux") == "linux" else "generic"

    @property
    def min_reports_for_triage(self) -> int:
        """Fewer scan reports than this skips triage (kernel default: 5)."""
        return self.get("min_reports_for_triage", 5)

    @property
    def perfect_report_threshold(self) -> int:
        """A scan with at most this many reports counts as "perfect" (kernel default: 10)."""
        return self.get("perfect_report_threshold", 10)

    @property
    def jobs(self) -> int:
        """Get the number of parallel jobs."""
        return self.get("jobs", 32)


global_config = GlobalConfig()
