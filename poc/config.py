"""Configuration objects and .env handling.

Everything here is stdlib-only and Python 3.9 compatible: no ``X | Y`` unions,
no ``dict[str, int]`` builtin generics at runtime.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import urlsplit

DEFAULT_CMD = "id>/out/p1"
MAX_CMD = 14
DEFAULT_FLAG = "FLAG{php2shell_lab_synthetic_flag_redacted}"


class ConfigError(ValueError):
    """Invalid CLI/configuration value."""


def project_root() -> Path:
    """Repository root (the directory that contains ``poc/``)."""
    return Path(__file__).resolve().parent.parent


def parse_env_file(path: Path) -> Dict[str, str]:
    """Parse a tiny KEY=VALUE file, ignoring comments and blank lines."""
    values: Dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def _env_int(env: Dict[str, str], key: str, default: int) -> int:
    raw = env.get(key)
    if raw is None or raw == "":
        return default
    try:
        return int(raw, 0)
    except ValueError as exc:
        raise ConfigError("{} must be an integer, got {!r}".format(key, raw)) from exc


@dataclass(frozen=True)
class TargetConfig:
    """A validated HTTP target URL."""

    url: str
    timeout: float = 30.0
    allow_public: bool = False

    def __post_init__(self) -> None:
        parts = urlsplit(self.url)
        if parts.scheme not in ("http", "https"):
            raise ConfigError("target URL must start with http:// or https://")
        if not parts.hostname:
            raise ConfigError("target URL has no host")
        if parts.username or parts.password:
            raise ConfigError("credentials in the target URL are not supported")
        try:
            port = parts.port
        except ValueError as exc:
            raise ConfigError("invalid port in target URL") from exc
        if port is not None and not (1 <= port <= 65535):
            raise ConfigError("target port out of range")
        if self.timeout <= 0:
            raise ConfigError("timeout must be positive")

    @property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def port(self) -> int:
        return urlsplit(self.url).port or (443 if self.scheme == "https" else 80)

    @property
    def path(self) -> str:
        parts = urlsplit(self.url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        return path

    @property
    def host_header(self) -> str:
        host = self.host
        if ":" in host and not host.startswith("["):
            host = "[" + host + "]"
        default = 443 if self.scheme == "https" else 80
        if self.port != default:
            return "{}:{}".format(host, self.port)
        return host


@dataclass
class ExploitConfig:
    """Knobs that map 1:1 to the reference exploit."""

    cmd: str = DEFAULT_CMD
    profile: str = "bookworm"
    huge_mb: int = 12
    retries: int = 3
    proof_file: Optional[Path] = None
    fetch: str = ""
    zif_offset: Optional[int] = None
    dtor_offset: Optional[int] = None
    htdata_offset: Optional[int] = None
    pre_rotate: bool = True
    retry_rotate: bool = True
    verbose: bool = True

    def validate(self) -> None:
        length = len(self.cmd.encode("utf-8"))
        if length == 0:
            raise ConfigError("command must not be empty")
        if length > MAX_CMD:
            raise ConfigError(
                "command is {} bytes; the 167-byte carrier allows at most {} "
                "(chain longer commands through 'sh</out/c')".format(length, MAX_CMD)
            )
        if not (9 <= self.huge_mb <= 64):
            raise ConfigError("huge-mb must be between 9 and 64 (lab memory_limit is 8M)")
        if not (1 <= self.retries <= 10):
            raise ConfigError("retries must be between 1 and 10")
        for name, value in (
            ("zif-offset", self.zif_offset),
            ("dtor-offset", self.dtor_offset),
            ("htdata-offset", self.htdata_offset),
        ):
            if value is not None and value < 0:
                raise ConfigError("{} must be non-negative".format(name))


@dataclass(frozen=True)
class LabConfig:
    """Paths, images and ports used by the Docker lab."""

    root: Path
    compose_file: Path
    env_file: Path
    vuln_container: str = "php2shell-vuln"
    patched_container: str = "php2shell-patched"
    vuln_port: int = 8088
    patched_port: int = 8089
    vuln_image: str = "php:8.4.26-apache"
    patched_image: str = "php:8.4.27-apache"
    platform: str = "linux/amd64"
    synthetic_flag: str = DEFAULT_FLAG

    @property
    def runtime_dir(self) -> Path:
        return self.root / "runtime"

    @property
    def vuln_out(self) -> Path:
        return self.runtime_dir / "out"

    @property
    def patched_out(self) -> Path:
        return self.runtime_dir / "patched" / "out"

    @property
    def flag_file(self) -> Path:
        return self.runtime_dir / "f"

    @property
    def results_dir(self) -> Path:
        return self.root / "results"

    @property
    def vuln_url(self) -> str:
        return "http://127.0.0.1:{}/index.php".format(self.vuln_port)

    @property
    def patched_url(self) -> str:
        return "http://127.0.0.1:{}/index.php".format(self.patched_port)

    @classmethod
    def from_env(cls, root: Optional[Path] = None) -> "LabConfig":
        root = (root or project_root()).resolve()
        file_env = parse_env_file(root / ".env")

        def get(key: str, default: str) -> str:
            # Process environment wins over .env, matching docker compose.
            return os.environ.get(key) or file_env.get(key) or default

        return cls(
            root=root,
            compose_file=root / "docker" / "compose.yml",
            env_file=root / ".env",
            vuln_container=get("VULN_CONTAINER", "php2shell-vuln"),
            patched_container=get("PATCHED_CONTAINER", "php2shell-patched"),
            vuln_port=_env_int(
                {"VULN_PORT": get("VULN_PORT", "8088")}, "VULN_PORT", 8088
            ),
            patched_port=_env_int(
                {"PATCHED_PORT": get("PATCHED_PORT", "8089")}, "PATCHED_PORT", 8089
            ),
            vuln_image=get("VULN_IMAGE", "php:8.4.26-apache"),
            patched_image=get("PATCHED_IMAGE", "php:8.4.27-apache"),
            platform=get("PLATFORM", "linux/amd64"),
        )


def parse_offsets(text: str) -> Tuple[int, int]:
    """Parse two hex offsets from CLI text ``zif,dtor`` (open to extension)."""
    try:
        left, right = text.split(",", 1)
        return int(left, 0), int(right, 0)
    except ValueError as exc:
        raise ConfigError("offsets must look like 0x465370,0x65eb60") from exc
