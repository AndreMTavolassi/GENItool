"""Bounded HTTP GET requests to one origin, with verified TLS and no redirects."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import math
import ssl
import time
from typing import Mapping
import urllib.error
import urllib.parse
import urllib.request


class HttpRequestError(RuntimeError):
    """A request did not produce a usable HTTP response."""


def url_origin(url: str) -> tuple[str, str, int]:
    if any(ord(character) < 32 or ord(character) == 127 for character in url):
        raise ValueError("A URL contém caracteres de controle.")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Informe uma URL HTTP(S) com hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credenciais na URL não são permitidas; use cabeçalhos.")
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    if port < 1:
        raise ValueError("A porta HTTP deve estar entre 1 e 65535.")
    return parsed.scheme, parsed.hostname.lower(), port


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


@dataclass(frozen=True)
class HTTPResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    truncated: bool = False

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


class HttpClient:
    """A sequential client bound to one origin.

    ``timeout`` limits socket operations. An elapsed-body check also interrupts
    streaming bodies; this is not a hard wall-clock bound on DNS/header parsing.
    """

    def __init__(
        self,
        headers: Mapping[str, str] | None = None,
        timeout: float = 10,
        rate: float = 5,
        max_body_bytes: int = 1_048_576,
        origin: str | None = None,
    ):
        if timeout <= 0 or rate <= 0 or max_body_bytes <= 0 or not math.isfinite(timeout) or not math.isfinite(rate):
            raise ValueError("Timeout, taxa e limite de corpo devem ser positivos.")
        self.headers = {"User-Agent": "GENItool/0.1", "Accept-Encoding": "identity"}
        for key, value in (headers or {}).items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError("Nomes e valores de cabeçalhos devem ser texto.")
            if any(ord(c) < 32 or ord(c) == 127 for c in key + value):
                raise ValueError("Cabeçalho com caracteres de controle.")
            if key.lower() in {"host", "proxy-authorization", "proxy-connection"}:
                raise ValueError("Cabeçalho de roteamento/proxy não permitido.")
            self.headers[key] = value
        self.timeout = timeout
        self.interval = 1.0 / rate
        self.max_body_bytes = max_body_bytes
        self._origin = url_origin(origin) if origin else None
        self._next_request = 0.0
        self._opener = urllib.request.build_opener(
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def get(self, url: str) -> HTTPResponse:
        origin = url_origin(url)
        if self._origin is None:
            self._origin = origin
        elif origin != self._origin:
            raise ValueError("A requisição sairia da origem autorizada.")
        delay = self._next_request - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        self._next_request = time.monotonic() + self.interval
        request = urllib.request.Request(url, headers=self.headers, method="GET")
        deadline = time.monotonic() + self.timeout
        try:
            try:
                response = self._opener.open(request, timeout=self.timeout)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                chunks: list[bytes] = []
                size = 0
                while size <= self.max_body_bytes:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("HTTP request deadline exceeded")
                    chunk = response.read1(min(65_536, self.max_body_bytes + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                body = b"".join(chunks)
                return HTTPResponse(
                    url=url,
                    status_code=response.code,
                    headers={key.lower(): value for key, value in response.headers.items()},
                    body=body[: self.max_body_bytes],
                    truncated=len(body) > self.max_body_bytes,
                )
        except (OSError, urllib.error.URLError, TimeoutError, ValueError, http.client.HTTPException) as error:
            # Do not interpolate request/response objects: they can contain secrets.
            reason = "timeout" if isinstance(error, TimeoutError) else type(error).__name__
            raise HttpRequestError(f"Falha HTTP ({reason}); verifique rede e TLS.") from error
