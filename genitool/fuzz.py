"""Path discovery with wildcard calibration and repeat-request validation."""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
import re
import secrets
import urllib.parse

from .http_client import HTTPResponse, HttpClient, HttpRequestError, url_origin
from .models import StageResult


def _safe_path(value: str) -> str | None:
    """Accept relative path components, including ordinary encoded filenames."""
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None
    value = value.strip()
    if not value or value.startswith("#") or len(value) > 2048:
        return None
    decoded = value
    for _ in range(8):
        if any(ord(c) < 32 or ord(c) == 127 for c in decoded):
            return None
        try:
            parsed = urllib.parse.urlsplit(decoded)
        except ValueError:
            return None
        if (
            decoded.startswith(("/", "\\"))
            or "\\" in decoded
            or parsed.scheme
            or parsed.netloc
            or parsed.query
            or parsed.fragment
            or "?" in decoded
            or "#" in decoded
            or any(segment in {".", ".."} for segment in decoded.split("/"))
        ):
            return None
        try:
            next_decoded = urllib.parse.unquote(decoded, errors="strict")
        except UnicodeError:
            return None
        if next_decoded == decoded:
            if re.search(r"%(?![0-9a-fA-F]{2})", decoded):
                return None
            return urllib.parse.quote(decoded, safe="/-._~")
        decoded = next_decoded
    return None


def _normalized(response: HTTPResponse) -> tuple[int, str, bytes]:
    parsed = urllib.parse.urlsplit(response.url)
    body = response.body
    # Wildcard pages often echo the requested absolute URL, path or random token.
    replacements = {
        response.url,
        parsed.path,
        urllib.parse.unquote(parsed.path),
        parsed.path.rsplit("/", 1)[-1],
    }
    for value in sorted(replacements, key=len, reverse=True):
        if value and value != "/":
            body = body.replace(value.encode("utf-8"), b"<requested-path>")
    location = response.headers.get("location", "")
    for value in sorted(replacements, key=len, reverse=True):
        if value and value != "/":
            location = location.replace(value, "<requested-path>")
    return response.status_code, location, body


def _similar(first: HTTPResponse, second: HTTPResponse) -> bool:
    # Conservatively compare the complete captured bodies, not a common HTML
    # prefix or a broad similarity percentage that can hide real endpoints.
    if first.truncated or second.truncated:
        return False
    return _normalized(first) == _normalized(second)


def _load_paths(wordlist: Path, max_paths: int) -> tuple[list[str], list[str]]:
    paths: list[str] = []
    seen: set[str] = set()
    invalid = 0
    bounded = False
    with Path(wordlist).open("r", encoding="utf-8", errors="strict") as handle:
        for _ in range(max_paths * 20 + 100):
            line = handle.readline(4097)
            if not line:
                break
            if len(line) > 4096:
                invalid += 1
                # Never consume an arbitrarily long line or allocate its entire contents.
                bounded = True
                break
            candidate = _safe_path(line.rstrip("\r\n"))
            if candidate is None:
                if line.strip() and not line.lstrip().startswith("#"):
                    invalid += 1
                continue
            if candidate not in seen:
                paths.append(candidate)
                seen.add(candidate)
            if len(paths) == max_paths:
                bounded = True
                break
        else:
            bounded = True
    notes: list[str] = []
    if invalid:
        notes.append(f"{invalid} entrada(s) inválida(s) da wordlist ignorada(s).")
    if bounded:
        notes.append(f"Leitura da wordlist limitada a {max_paths} caminhos e linhas de até 4096 caracteres.")
    return paths, notes


def fuzz_paths(
    url: str,
    wordlist: Path,
    headers: dict[str, str],
    timeout: float,
    rate: float,
    max_paths: int,
) -> StageResult:
    result = StageResult("fuzzing", "completed")
    try:
        url_origin(url)
        parsed = urllib.parse.urlsplit(url)
        if parsed.query or parsed.fragment:
            raise ValueError("A URL base do fuzzing não pode conter query ou fragmento.")
        if max_paths <= 0 or not math.isfinite(rate) or not math.isfinite(timeout):
            raise ValueError("Limites e taxa devem ser positivos e finitos.")
        base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") + "/", "", ""))
        paths, notes = _load_paths(wordlist, max_paths)
        result.notes.extend(notes)
        client = HttpClient(headers, timeout=timeout, rate=rate, origin=base)
    except (OSError, UnicodeError, ValueError) as error:
        return StageResult("fuzzing", "error", notes=[f"Configuração inválida: {error}"])
    if not paths:
        result.status = "skipped"
        result.notes.append("Wordlist sem caminhos relativos válidos.")
        return result

    baselines: list[HTTPResponse] = []
    try:
        for _ in range(2):
            baselines.append(client.get(base + "genitool-absent-" + secrets.token_hex(12)))
    except HttpRequestError as error:
        return StageResult("fuzzing", "error", notes=result.notes + [f"Calibração de caminhos inexistentes falhou: {error}"])
    if any(response.status_code >= 500 or response.status_code == 429 for response in baselines):
        return StageResult("fuzzing", "error", notes=result.notes + ["Calibração recebeu erro do servidor ou limitação HTTP 429; fuzzing interrompido."])
    wildcard = _similar(baselines[0], baselines[1])
    if wildcard and baselines[0].status_code not in {404, 410}:
        result.notes.append("Resposta genérica/catch-all detectada; respostas equivalentes à calibração serão descartadas.")
    elif not wildcard and any(response.status_code not in {404, 410} for response in baselines):
        result.status = "partial"
        result.notes.append("Calibração de caminhos inexistentes retornou respostas diferentes de 404/410 e instáveis; confirme manualmente os caminhos encontrados.")

    suppressed = 0
    errors = 0
    requests = 2
    for path in paths:
        candidate_url = base + path
        try:
            requests += 1
            first = client.get(candidate_url)
            if first.status_code == 429:
                result.status = "partial"
                result.notes.append("HTTP 429 recebido; requisições interrompidas para respeitar o limite do servidor.")
                break
            if first.status_code in {404, 410}:
                continue
            if wildcard and all(_similar(first, baseline) for baseline in baselines):
                suppressed += 1
                continue
            entry = {
                "url": candidate_url,
                "status_code": first.status_code,
                "length": len(first.body),
                "sha256": hashlib.sha256(first.body).hexdigest(),
                "truncated": first.truncated,
                "location": first.headers.get("location", ""),
                "validation": "unverified",
                "reproducible": False,
            }
            try:
                requests += 1
                second = client.get(candidate_url)
                stable = _similar(first, second)
                entry["reproducible"] = stable
                entry["validation"] = (
                    "unverified"
                    if first.truncated or second.truncated
                    else "authentication_required"
                    if stable and first.status_code in {401, 403}
                    else "reproducible" if stable else "unstable"
                )
                entry["recheck_status_code"] = second.status_code
                entry["recheck_truncated"] = second.truncated
                if first.truncated or second.truncated:
                    result.status = "partial"
                if second.status_code == 429:
                    result.status = "partial"
                    result.notes.append("HTTP 429 na validação; requisições interrompidas.")
                    result.data.append(entry)
                    break
            except HttpRequestError:
                errors += 1
                result.status = "partial"
                entry["validation"] = "unverified"
            if first.status_code >= 500:
                result.status = "partial"
            result.data.append(entry)
        except HttpRequestError:
            errors += 1
            result.status = "partial"
    if errors:
        if not result.data and errors == len(paths):
            result.status = "error"
        result.notes.append(f"{errors} requisição(ões) falharam; resultados incompletos.")
    if suppressed:
        result.notes.append(f"{suppressed} resposta(s) equivalentes ao catch-all descartada(s).")
    if not result.data:
        result.notes.append("Nenhum caminho distinto foi validado na wordlist e nos limites informados.")
    result.notes.append(f"{requests} requisição(ões); limite máximo: {2 + 2 * max_paths}. Redirecionamentos não são seguidos.")
    return result
