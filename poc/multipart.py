"""Multipart/form-data builder matching the reference request shapes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence, Union

_BAD_CHARS = ("\r", "\n", '"')


@dataclass(frozen=True)
class Part:
    name: str
    data: bytes
    filename: Optional[str] = None
    content_type: str = "application/octet-stream"


def field(name: str, data: Union[bytes, str]) -> Part:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return Part(name=name, data=data)


def file_part(name: str, filename: str, data: Union[bytes, str]) -> Part:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return Part(name=name, data=data, filename=filename)


def _check_token(value: str, what: str) -> None:
    if not value:
        raise ValueError("empty {}".format(what))
    for bad in _BAD_CHARS:
        if bad in value:
            raise ValueError("{} contains {!r}".format(what, bad))


def build_multipart(parts: Sequence[Part], boundary: bytes) -> bytes:
    if not boundary or len(boundary) > 70:
        raise ValueError("boundary must be 1..70 bytes")
    if b"\r" in boundary or b"\n" in boundary:
        raise ValueError("boundary must not contain CR/LF")

    out = bytearray()
    for part in parts:
        _check_token(part.name, "field name")
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + part.name.encode("utf-8") + b'"'
        if part.filename is not None:
            _check_token(part.filename, "filename")
            out += b'; filename="' + part.filename.encode("utf-8") + b'"'
            out += b"\r\nContent-Type: " + part.content_type.encode("ascii")
        out += b"\r\n\r\n" + part.data + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def session_parts(session_id: bytes, progress: bytes = b"pwn") -> List[Part]:
    """The session bootstrap fields used by every stage."""
    return [
        field("PHPSESSID", session_id),
        field("PHP_SESSION_UPLOAD_PROGRESS", progress),
    ]
