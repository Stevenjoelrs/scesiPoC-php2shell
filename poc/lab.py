"""Docker lab helpers: runtime directories, container state, health."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .config import LabConfig

DOCKER = os.environ.get("DOCKER", "docker")


class LabError(RuntimeError):
    """The Docker lab is not available or not in the expected state."""


def ensure_runtime(config: LabConfig, flag_text: Optional[str] = None) -> Path:
    """Create runtime dirs, the synthetic flag, and writable /out mounts."""
    for directory in (config.vuln_out, config.patched_out):
        directory.mkdir(parents=True, exist_ok=True)
        try:
            # Docker Desktop cannot chown bind mounts from inside the container.
            os.chmod(directory, 0o777)
        except OSError:
            pass
    flag = config.flag_file
    if not flag.exists():
        flag.write_text((flag_text or config.synthetic_flag) + "\n", encoding="utf-8")
    try:
        os.chmod(flag, 0o644)
    except OSError:
        pass
    return flag


def _run(command: Sequence[str], timeout: int = 60) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
        )
    except FileNotFoundError as exc:
        raise LabError("{} not found in PATH".format(command[0])) from exc
    except subprocess.SubprocessError as exc:
        raise LabError("command failed: {}".format(exc)) from exc


def compose(
    config: LabConfig,
    args: Sequence[str],
    profile: bool = False,
    timeout: int = 300,
) -> subprocess.CompletedProcess:
    command = [
        DOCKER,
        "compose",
        "--env-file",
        str(config.env_file),
        "-f",
        str(config.compose_file),
    ]
    if profile:
        command += ["--profile", "patched"]
    command += list(args)
    result = _run(command, timeout=timeout)
    if result.returncode != 0:
        raise LabError(result.stderr.strip() or "docker compose failed")
    return result


def container_state(container: str) -> str:
    result = _run(
        [DOCKER, "inspect", "-f", "{{.State.Status}}", container],
        timeout=20,
    )
    if result.returncode != 0:
        return "missing"
    return result.stdout.strip() or "unknown"


def container_health(container: str) -> str:
    template = "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}"
    result = _run([DOCKER, "inspect", "-f", template, container], timeout=20)
    if result.returncode != 0:
        return "missing"
    return result.stdout.strip() or "unknown"


def wait_healthy(containers: Sequence[str], timeout: float = 60.0) -> Dict[str, str]:
    deadline = time.monotonic() + timeout
    states: Dict[str, str] = {}
    while True:
        states = {name: container_health(name) for name in containers}
        if all(state == "healthy" for state in states.values()):
            return states
        bad = {name: state for name, state in states.items() if state in ("unhealthy", "exited")}
        if bad:
            raise LabError("containers not healthy: {}".format(bad))
        if time.monotonic() >= deadline:
            raise LabError("timed out waiting for healthy containers: {}".format(states))
        time.sleep(0.5)


def exec_in(container: str, argv: Sequence[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return _run([DOCKER, "exec", container] + list(argv), timeout=timeout)


def php_version(container: str) -> str:
    result = exec_in(container, ["php", "-r", "echo PHP_VERSION;"])
    if result.returncode != 0:
        return "unknown"
    return result.stdout.strip()


def php_ini(container: str, key: str) -> str:
    script = 'echo ini_get("{}");'.format(key.replace('"', ""))
    result = exec_in(container, ["php", "-r", script])
    if result.returncode != 0:
        return "unknown"
    return result.stdout.strip()


def docker_server_version() -> str:
    result = _run([DOCKER, "version", "--format", "{{.Server.Version}}"], timeout=20)
    if result.returncode != 0:
        raise LabError(result.stderr.strip() or "docker daemon unavailable")
    return result.stdout.strip()


_ARCH_ALIASES = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}


def normalize_platform(value: str) -> str:
    """Normalise ``linux/x86_64`` and ``linux/amd64`` to the same string."""
    os_type, _, arch = value.strip().partition("/")
    return "{}/{}".format(os_type, _ARCH_ALIASES.get(arch, arch))


def docker_platform() -> str:
    """Return the daemon platform as ``ostype/arch`` (e.g. ``linux/amd64``)."""
    result = _run(
        [DOCKER, "info", "--format", "{{.OSType}}/{{.Architecture}}"],
        timeout=30,
    )
    if result.returncode != 0:
        raise LabError(result.stderr.strip() or "cannot read docker platform")
    return normalize_platform(result.stdout.strip())


def compose_version() -> str:
    """Return the Docker Compose v2 version, or raise if only v1 is present."""
    result = _run([DOCKER, "compose", "version", "--short"], timeout=20)
    if result.returncode != 0:
        raise LabError(
            result.stderr.strip()
            or "docker compose v2 is required (the 'docker compose' plugin)"
        )
    return result.stdout.strip().splitlines()[0] if result.stdout.strip() else "unknown"


def selinux_enforcing() -> bool:
    """Best-effort host SELinux check (always False outside Linux)."""
    try:
        return Path("/sys/fs/selinux/enforce").read_text(encoding="utf-8").strip() == "1"
    except OSError:
        return False


def container_image(container: str) -> str:
    result = _run([DOCKER, "inspect", "-f", "{{.Config.Image}}", container], timeout=20)
    if result.returncode != 0:
        return "unknown"
    return result.stdout.strip()


def container_ports(container: str) -> List[str]:
    result = _run(
        [DOCKER, "inspect", "-f", "{{json .NetworkSettings.Ports}}", container],
        timeout=20,
    )
    if result.returncode != 0:
        return []
    return [result.stdout.strip()]
