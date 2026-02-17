import logging
from pathlib import Path

DEFAULT_CONFIG_PATH = Path(__file__).with_name("config.yaml")
LOGGER = logging.getLogger(__name__)

# New nested structure defaults
_DEFAULT_CONFIG = {
    "policy": {
        "deployment_stage": "assess",
        "deploy_action": "detect",
        "report_action_candidates": ["no_action", "none", "monitor"],
        "prevalence_threshold": 25,
    },
    "rollout": {
        "host_groups": [],
        "priority_platforms": [],
    },
    "safety": {
        "excluded_platforms": [],
        "excluded_domains": [],
    },
}

# Still track valid top-level keys
ACTIVE_CONFIG_KEYS = tuple(_DEFAULT_CONFIG.keys())

try:
    from dotenv import dotenv_values
except ImportError:  # pragma: no cover
    dotenv_values = None

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def load_dotenv(path: Path) -> dict:
    if not path.exists():
        return {}
    if dotenv_values is None:
        raise RuntimeError(
            "python-dotenv is required to load .env files. Install with: uv pip install python-dotenv"
        )
    values = dotenv_values(path)
    return {k: str(v) for k, v in values.items() if v is not None}


def resolve_env_file_path(raw_path: str) -> Path:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate

    cwd_path = Path.cwd() / candidate
    if cwd_path.exists():
        return cwd_path

    script_dir = Path(__file__).resolve().parent
    script_path = script_dir / candidate
    if script_path.exists():
        return script_path

    repo_path = script_dir.parent / candidate
    if repo_path.exists():
        return repo_path

    default_env = Path.cwd() / ".env"
    if default_env.exists():
        return default_env

    script_env = script_dir / ".env"
    if script_env.exists():
        return script_env

    return cwd_path


def load_simple_yaml(path: Path) -> dict:
    # Start with defaults
    config = _DEFAULT_CONFIG.copy()

    if not path.exists():
        return config
    if yaml is None:
        raise RuntimeError(
            "PyYAML is required for config.yaml. Install with: uv pip install pyyaml"
        )

    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(loaded, dict):
        raise RuntimeError(f"Config file must be a YAML mapping: {path}")

    # Warn on unknown top-level keys
    unknown_keys = sorted(str(k) for k in loaded.keys() if k not in ACTIVE_CONFIG_KEYS)
    if unknown_keys:
        LOGGER.warning(
            "Unknown config keys ignored: %s",
            ", ".join(unknown_keys),
        )

    # Shallow merge of top-level sections (policy, rollout, safety)
    # We trust the user provides the correct structure within these sections
    # or that main.py's safe accessors handle missing nested keys.
    for key in ACTIVE_CONFIG_KEYS:
        if key in loaded and isinstance(loaded[key], dict):
            # We could do a deep merge here if we wanted to be very robust,
            # but for now, let's just accept the user's section if it exists,
            # possibly merging with default keys if missing?
            # Simplest is to update the section dictionary with user provided one.
            # But if user omits a default key inside a section, it might be missing.
            # Let's do a simple 1-level merge.
            default_section = _DEFAULT_CONFIG[key].copy()
            user_section = loaded[key]
            default_section.update(user_section)
            config[key] = default_section

    return config
