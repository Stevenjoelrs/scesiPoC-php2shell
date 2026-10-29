"""Minimal HTTP/1.1 client for the exploit.

Two details matter:

* The target aborts the worker while a large upload is in flight. Reading the
  response concurrently with the upload keeps a Set-Cookie header that would
  otherwise be lost to the RST.
* The client connects to a pinned IP returned by the scope guard, but sends the
  original Host header, so validation and connection use the same address.
"""

from __future__ import annotations

import gzip
import re
import socket
import ssl
import threading
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .config import TargetConfig


@dataclass(frozen=True)
class HttpResponse:
    status: int
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    set_cookies: Tuple[str, ...] = ()
    body: bytes = b""
    raw: bytes = b""

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def cookie(self, name: str) -> Optional[str]:
        prefix = name + "="
        for value in self.set_cookies:
            if value.startswith(prefix):
                return value[len(prefix) :].split(";", 1)[0]
        return None


def _dechunk(data: bytes) -> bytes:
    out = bytearray()
    pos = 0
    while True:
        end = data.find(b"\r\n", pos)
        if end < 0:
            break
        size_text = data[pos:end].split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            break
        pos = end + 2
        if size == 0:
            break
        out += data[pos : pos + size]
        pos += size + 2
        if pos > len(data):
            break
    return bytes(out)


def parse_response(raw: bytes) -> HttpResponse:
    if not raw:
        return HttpResponse(status=0, reason="", raw=raw)
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        return HttpResponse(status=0, reason="", raw=raw)

    lines = head.split(b"\r\n")
    match = re.match(rb"HTTP/1\.[01]\s+(\d{3})\s*(.*)", lines[0])
    if not match:
        return HttpResponse(status=0, reason="", raw=raw)
    status = int(match.group(1))
    reason = match.group(2).decode("latin1", "replace")

    headers: Dict[str, str] = {}
    cookies: List[str] = []
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        key = name.decode("latin1").strip().lower()
        val = value.decode("latin1").strip()
        if key == "set-cookie":
            cookies.append(val)
        if key in headers:
            headers[key] += ", " + val
        else:
            headers[key] = val

    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = _dechunk(body)
    if headers.get("content-encoding", "").lower() == "gzip":
        try:
            body = gzip.decompress(body)
        except OSError:
            pass
    if "content-length" in headers:
        try:
            length = int(headers["content-length"])
            if 0 <= length <= len(body):
                body = body[:length]
        except ValueError:
            pass

    return HttpResponse(
        status=status,
        reason=reason,
        headers=headers,
        set_cookies=tuple(cookies),
        body=body,
        raw=raw,
    )


class HttpClient:
    def __init__(
        self,
        target: TargetConfig,
        address: Optional[str] = None,
        log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.target = target
        self.address = address or target.host
        self._log = log or (lambda _msg: None)

    def _connect(self) -> socket.socket:
        last: Optional[OSError] = None
        for _ in range(10):
            try:
                sock = socket.create_connection(
                    (self.address, self.target.port), timeout=self.target.timeout
                )
                if self.target.scheme == "https":
                    context = ssl.create_default_context()
                    sock = context.wrap_socket(sock, server_hostname=self.target.host)
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return sock
            except OSError as exc:
                last = exc
                threading.Event().wait(0.3)
        assert last is not None
        raise last

    def _request(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        content_type: Optional[str] = None,
        read_cap: int = 1 << 20,
        timeout: Optional[float] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> HttpResponse:
        lines = [
            "{} {} HTTP/1.1".format(method, path),
            "Host: {}".format(self.target.host_header),
        ]
        for key, value in (extra_headers or {}).items():
            if "\r" in key or "\n" in key or "\r" in value or "\n" in value:
                raise ValueError("header injection attempt")
            lines.append("{}: {}".format(key, value))
        if content_type:
            lines.append("Content-Type: {}".format(content_type))
        lines.append("Content-Length: {}".format(len(body)))
        lines.append("Connection: close")
        header = ("\r\n".join(lines) + "\r\n\r\n").encode("latin1")

        sock = self._connect()
        sock.settimeout(timeout or self.target.timeout)
        data = bytearray()

        def reader() -> None:
            try:
                while len(data) < read_cap:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except OSError:
                pass

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        try:
            try:
                sock.sendall(header)
                view = memoryview(body)
                for offset in range(0, len(body), 262144):
                    sock.sendall(view[offset : offset + 262144])
            except OSError as exc:
                # The worker may die while the upload is still in flight.
                self._log("[.] send interrupted: {}".format(exc))
            thread.join(timeout=(timeout or self.target.timeout) + 1.0)
        finally:
            sock.close()
        return parse_response(bytes(data))

    def post(
        self,
        body: bytes,
        boundary: bytes,
        read_cap: int = 1 << 20,
        timeout: Optional[float] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> HttpResponse:
        return self._request(
            "POST",
            self.target.path,
            body=body,
            content_type="multipart/form-data; boundary={}".format(boundary.decode("ascii")),
            read_cap=read_cap,
            timeout=timeout,
            extra_headers=extra_headers,
        )

    def get(self, path: str, read_cap: int = 1 << 20) -> HttpResponse:
        return self._request("GET", path, read_cap=read_cap)
