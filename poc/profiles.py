"""Heap-calibration profiles.

A profile bundles the build-specific constants that are *not* derivable from
ELF symbols: the heap-grooming counts, the fake-reference padding layout, and
the chunk-relative offset of the 167-byte carrier string.

The JSON files under ``profiles/`` are the source of truth; this module only
validates and loads them.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import project_root

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class ProfileError(ValueError):
    """Invalid or unknown profile."""


def _as_int(data: Dict[str, Any], key: str) -> int:
    if key not in data:
        raise ProfileError("profile is missing {!r}".format(key))
    value = data[key]
    if isinstance(value, bool):
        raise ProfileError("{} must be an integer".format(key))
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise ProfileError("{} must be an integer".format(key)) from exc
    raise ProfileError("{} must be an integer".format(key))


def _as_bool(data: Dict[str, Any], key: str, default: bool = False) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ProfileError("{} must be a boolean".format(key))
    return value


@dataclass(frozen=True)
class Profile:
    name: str
    php_version: str
    image: str
    description: str
    zif_offset: int
    dtor_offset: int
    htdata_offset: int
    stage1_n: int
    stage2_t: int
    stage2_v: int
    stage3_pads: Tuple[Tuple[int, int], ...]
    stage3_carrier: bool
    stage3_cookie: bool

    def with_offsets(
        self,
        zif_offset: Optional[int] = None,
        dtor_offset: Optional[int] = None,
        htdata_offset: Optional[int] = None,
    ) -> "Profile":
        return replace(
            self,
            zif_offset=self.zif_offset if zif_offset is None else zif_offset,
            dtor_offset=self.dtor_offset if dtor_offset is None else dtor_offset,
            htdata_offset=self.htdata_offset if htdata_offset is None else htdata_offset,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "php_version": self.php_version,
            "image": self.image,
            "description": self.description,
            "zif_offset": "0x{:x}".format(self.zif_offset),
            "dtor_offset": "0x{:x}".format(self.dtor_offset),
            "htdata_offset": "0x{:x}".format(self.htdata_offset),
            "stage1_n": self.stage1_n,
            "stage2_t": self.stage2_t,
            "stage2_v": self.stage2_v,
            "stage3_pads": [list(pair) for pair in self.stage3_pads],
            "stage3_carrier": self.stage3_carrier,
            "stage3_cookie": self.stage3_cookie,
        }

    def fingerprint(self) -> str:
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def summary(self) -> str:
        return (
            "{} php={} zif=0x{:x} dtor=0x{:x} htdata=0x{:x} "
            "stage1_n={} stage2_t={} stage2_v={}".format(
                self.name,
                self.php_version,
                self.zif_offset,
                self.dtor_offset,
                self.htdata_offset,
                self.stage1_n,
                self.stage2_t,
                self.stage2_v,
            )
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Profile":
        name = data.get("name")
        if not isinstance(name, str) or not _NAME_RE.match(name):
            raise ProfileError("invalid profile name: {!r}".format(name))

        pads_raw = data.get("stage3_pads")
        if not isinstance(pads_raw, list) or not pads_raw:
            raise ProfileError("stage3_pads must be a non-empty list")
        pads: List[Tuple[int, int]] = []
        for entry in pads_raw:
            if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                raise ProfileError("each stage3_pads entry must be [name_len, value_len]")
            name_len, value_len = entry
            if not isinstance(name_len, int) or not isinstance(value_len, int):
                raise ProfileError("stage3_pads values must be integers")
            if name_len < 0 or value_len < 0 or name_len > 64 or value_len > 4096:
                raise ProfileError("stage3_pads entry out of range")
            pads.append((name_len, value_len))

        profile = cls(
            name=name,
            php_version=str(data.get("php_version", "")),
            image=str(data.get("image", "")),
            description=str(data.get("description", "")),
            zif_offset=_as_int(data, "zif_offset"),
            dtor_offset=_as_int(data, "dtor_offset"),
            htdata_offset=_as_int(data, "htdata_offset"),
            stage1_n=_as_int(data, "stage1_n"),
            stage2_t=_as_int(data, "stage2_t"),
            stage2_v=_as_int(data, "stage2_v"),
            stage3_pads=tuple(pads),
            stage3_carrier=_as_bool(data, "stage3_carrier"),
            stage3_cookie=_as_bool(data, "stage3_cookie"),
        )
        profile.validate()
        return profile

    def validate(self) -> None:
        if self.zif_offset <= 0 or self.dtor_offset <= 0 or self.htdata_offset <= 0:
            raise ProfileError("offsets must be positive")
        if not (1 <= self.stage1_n <= 100000):
            raise ProfileError("stage1_n out of range")
        if not (0 <= self.stage2_t <= 982):
            raise ProfileError("stage2_t out of range (0..982)")
        if not (0 <= self.stage2_v <= 4096):
            raise ProfileError("stage2_v out of range")


def profiles_dir(root: Optional[Path] = None) -> Path:
    return (root or project_root()) / "profiles"


def profile_path(name_or_path: str, root: Optional[Path] = None) -> Path:
    candidate = Path(name_or_path)
    if candidate.suffix == ".json" or os.sep in name_or_path:
        return candidate
    return profiles_dir(root) / "{}.json".format(name_or_path)


def load_profile(name_or_path: str, root: Optional[Path] = None) -> Profile:
    path = profile_path(name_or_path, root)
    if not path.is_file():
        available = ", ".join(list_profiles(root)) or "none"
        raise ProfileError(
            "profile {!r} not found ({}); available: {}".format(name_or_path, path, available)
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ProfileError("cannot read profile {}: {}".format(path, exc)) from exc
    if not isinstance(data, dict):
        raise ProfileError("profile {} must be a JSON object".format(path))
    return Profile.from_dict(data)


def list_profiles(root: Optional[Path] = None) -> List[str]:
    directory = profiles_dir(root)
    if not directory.is_dir():
        return []
    return sorted(path.stem for path in directory.glob("*.json"))


def merge_offsets(
    profile: Profile,
    zif_offset: Optional[int],
    dtor_offset: Optional[int],
    htdata_offset: Optional[int],
) -> Profile:
    return profile.with_offsets(zif_offset, dtor_offset, htdata_offset)
