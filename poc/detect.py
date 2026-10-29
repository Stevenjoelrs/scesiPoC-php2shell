"""Detection helpers: version banner and leak-probe verdicts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .config import TargetConfig
from .http import HttpClient

VULNERABLE = "vulnerable"
PATCHED = "patched"
UNKNOWN = "unknown"
INCONCLUSIVE = "inconclusive"

_VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")

# Branches fixed on 2026-10-22 (PHP changelog): the same two GHSAs are fixed
# by "Avoid state corruption via bailout" in each supported branch.
_FIXED = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}


def parse_php_version(value: str) -> Optional[Tuple[int, int, int]]:
    match = _VERSION_RE.search(value or "")
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def version_text(version: Optional[Tuple[int, int, int]]) -> str:
    if not version:
        return "unknown"
    return "{}.{}.{}".format(*version)


def assess_version(version: Optional[Tuple[int, int, int]]) -> str:
    if version is None:
        return UNKNOWN
    fixed = _FIXED.get((version[0], version[1]))
    if fixed is None:
        return UNKNOWN
    return VULNERABLE if version < fixed else PATCHED


def probe_verdict(version_verdict: str, probe_success: bool, cookie_len: int) -> str:
    """Combine the banner with the behavioural stage-1 result."""
    if probe_success and cookie_len >= 1000:
        return VULNERABLE
    if version_verdict == PATCHED and not probe_success:
        return PATCHED
    if version_verdict == VULNERABLE and not probe_success:
        return INCONCLUSIVE
    return version_verdict


@dataclass
class Detection:
    url: str
    status_code: int = 0
    powered_by: str = ""
    server: str = ""
    version: Optional[Tuple[int, int, int]] = None
    verdict: str = UNKNOWN
    detail: str = ""
    probe: Optional[Dict[str, object]] = None

    def to_dict(self) -> Dict[str, object]:
        payload = {
            "url": self.url,
            "status_code": self.status_code,
            "powered_by": self.powered_by,
            "server": self.server,
            "version": version_text(self.version),
            "verdict": self.verdict,
            "detail": self.detail,
        }
        if self.probe is not None:
            payload["probe"] = self.probe
        return payload


def detect(client: HttpClient, target: TargetConfig) -> Detection:
    response = client.get(target.path)
    powered_by = response.header("x-powered-by")
    server = response.header("server")
    version = parse_php_version(powered_by)
    verdict = assess_version(version)
    detail = ""
    if version is None:
        detail = "no X-Powered-By PHP version (expose_php may be Off)"
    return Detection(
        url=target.url,
        status_code=response.status,
        powered_by=powered_by,
        server=server,
        version=version,
        verdict=verdict,
        detail=detail,
    )
