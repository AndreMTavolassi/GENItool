"""Bounded NVD enrichment. A fingerprint match is not proof of vulnerability."""

from __future__ import annotations

import json
import math
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, unquote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .models import StageResult

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESULTS = 20
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_RETRY_WAIT = 30.0
_COMPONENT = re.compile(r"^[A-Za-z0-9._~+*?\-]+$")
_EXACT_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~\-]{0,99}$")
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


# A fixed endpoint must not redirect the NVD API key to another service.
urlopen = build_opener(_NoRedirect()).open


def _version(value: Any) -> str | None:
    value = str(value or "").strip()
    if _EXACT_VERSION.fullmatch(value) and any(char.isdigit() for char in value):
        return value
    return None


def normalize_cpe(value: str) -> str | None:
    """Convert simple, versioned Nmap CPE URIs to CPE 2.3 names.

    Complex escaped/packed CPEs are deliberately skipped rather than guessed.
    Wildcards in the version cannot establish a version-specific query.
    """
    if not isinstance(value, str) or len(value) > 1024:
        return None
    if value.startswith("cpe:/"):
        fields = value[5:].split(":")
        if not 4 <= len(fields) <= 7:
            return None
        if len(fields) > 5 and fields[5].startswith("~"):
            # URI packed edition syntax needs structured unbinding, not padding.
            return None
        fields = [unquote(field) or "*" for field in fields]
        fields += ["*"] * (11 - len(fields))
    elif value.startswith("cpe:2.3:"):
        fields = value[8:].split(":")
        if len(fields) != 11:
            return None
    else:
        return None
    if fields[0] not in {"a", "o", "h"} or not _version(fields[3]):
        return None
    if any(not _COMPONENT.fullmatch(field) for field in fields):
        return None
    if any(field == "-" or "*" in field or "?" in field for field in fields[1:3]):
        return None
    return "cpe:2.3:" + ":".join(fields)


def _technology_cpe(cpe: str, version: str | None) -> str:
    """Bind a detector's version only to its own wildcard application CPE.

    A service fingerprint may carry additional OS or library CPEs; its service
    version must never be copied to those. This helper is only used for the
    individual technology records emitted by Wappalyzer.
    """
    if not version:
        return cpe
    if cpe.startswith("cpe:2.3:"):
        prefix = "cpe:2.3:"
        fields = cpe[len(prefix):].split(":")
        valid_length = len(fields) == 11
    elif cpe.startswith("cpe:/"):
        prefix = "cpe:/"
        fields = cpe[len(prefix):].split(":")
        valid_length = 4 <= len(fields) <= 7
    else:
        return cpe
    if valid_length and fields[0] == "a" and fields[3] == "*":
        fields[3] = version
        return prefix + ":".join(fields)
    return cpe


def _queries(services: list[dict], technologies: list[dict]) -> list[dict]:
    queries: list[dict] = []
    seen: set[tuple[str, str]] = set()
    records = [(item, False) for item in services] + [(item, True) for item in technologies]
    for item, is_technology in records:
        if not isinstance(item, dict):
            continue
        product = str(item.get("product") or item.get("name") or "").strip()
        version = _version(item.get("version"))
        cpes = item.get("cpes") or []
        if isinstance(cpes, str):
            cpes = [cpes]
        if not isinstance(cpes, (list, tuple)):
            cpes = []
        candidates = [normalize_cpe(_technology_cpe(cpe, version) if is_technology else cpe)
                      for cpe in cpes if isinstance(cpe, str)]
        versioned_cpes = [cpe for cpe in candidates if cpe]
        if versioned_cpes:
            for cpe in versioned_cpes:
                cpe_fields = cpe.split(":")
                key = ("cpeName", cpe)
                if key not in seen:
                    seen.add(key)
                    queries.append({"parameter": key[0], "value": key[1],
                                    "product": product or cpe_fields[4],
                                    "version": cpe_fields[5], "basis": "CPE exato com versão"})
        elif product and len(product) <= 200 and version:
            if any(ord(char) < 32 for char in product):
                continue
            key = ("keywordSearch", f"{product} {version}")
            if key not in seen:
                seen.add(key)
                queries.append({"parameter": key[0], "value": key[1],
                                "product": product, "version": version,
                                "basis": "palavra-chave e versão; correspondência não verificada"})
    # Precise CPE matches consume the query budget before broad keyword matches.
    return sorted(queries, key=lambda query: query["parameter"] != "cpeName")


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        wait = float(value)
    except (ValueError, TypeError):
        try:
            until = parsedate_to_datetime(value)
            if until.tzinfo is None:
                until = until.replace(tzinfo=timezone.utc)
            wait = (until - datetime.now(timezone.utc)).total_seconds()
        except (ValueError, TypeError, OverflowError):
            return None
    return max(0.0, wait) if math.isfinite(wait) else None


def _metric(cve: dict) -> tuple[float | None, str]:
    metrics = cve.get("metrics", {})
    for family in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(family, []) if isinstance(metrics, dict) else []
        if not isinstance(entries, list):
            continue
        for entry in sorted(entries, key=lambda entry: entry.get("type") != "Primary"
                            if isinstance(entry, dict) else True):
            if not isinstance(entry, dict):
                continue
            data = entry.get("cvssData", {})
            if not isinstance(data, dict):
                continue
            score = data.get("baseScore")
            if isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 10:
                severity = str(data.get("baseSeverity") or entry.get("baseSeverity") or "não informada")
                return float(score), severity
    return None, "não informada"


def _entries(payload: dict, query: dict) -> list[dict]:
    findings = []
    for entry in payload["vulnerabilities"][:MAX_RESULTS]:
        if not isinstance(entry, dict) or not isinstance(entry.get("cve"), dict):
            continue
        cve = entry["cve"]
        identifier = str(cve.get("id", ""))
        if not _CVE_ID.fullmatch(identifier) or cve.get("vulnStatus") == "Rejected":
            continue
        descriptions = cve.get("descriptions", [])
        descriptions = [item for item in descriptions if isinstance(item, dict)] if isinstance(descriptions, list) else []
        description = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
        if not description and descriptions:
            description = descriptions[0].get("value", "")
        score, severity = _metric(cve)
        findings.append({"id": identifier, "description": str(description)[:4000],
                         "cvss": score, "severity": severity,
                         "url": f"https://nvd.nist.gov/vuln/detail/{identifier}",
                         "matched_product": query["product"], "matched_version": query["version"],
                         "match_basis": query["basis"], "status": "candidate"})
    return findings


def lookup_cves(services: list[dict], technologies: list[dict], timeout: float,
                max_queries: int = 10, api_key: str | None = None) -> StageResult:
    """Query only observed, versioned fingerprints with at most one bounded retry.

    NVD requests carry only the NVD key, never target authentication. Results are
    capped at the first 20 per fingerprint and always labelled candidates.
    """
    result = StageResult("cves", "completed")
    result.notes.append("CVEs são candidatas: confirme produto, versão, configuração e condições de exploração manualmente.")
    if not math.isfinite(timeout) or timeout <= 0 or not isinstance(max_queries, int) or not 0 <= max_queries <= 100:
        result.status = "error"
        result.notes.append("Timeout ou limite de consultas NVD inválido.")
        return result
    queries = _queries(services, technologies)
    if not queries or max_queries == 0:
        result.status = "skipped"
        result.notes.append("Sem fingerprints com versão exata para consultar a NVD." if not queries else "Consulta NVD desativada pelo limite zero.")
        return result
    if len(queries) > max_queries:
        result.notes.append(f"Limite NVD: consultados {max_queries} de {len(queries)} fingerprints; cobertura incompleta.")
        result.status = "partial"
    headers = {"User-Agent": "GENItool/0.1 (authorized-security-assessment)", "Accept": "application/json"}
    if api_key:
        if any(ord(char) < 32 or ord(char) == 127 for char in api_key):
            result.status = "error"
            result.notes.append("Chave NVD inválida; nenhum segredo foi registrado.")
            return result
        headers["apiKey"] = api_key
    interval = 0.7 if api_key else 6.1
    last_request: float | None = None
    successful = 0
    failures = 0
    stop_queries = False
    seen: set[tuple[str, str, str]] = set()
    for query in queries[:max_queries]:
        params = {query["parameter"]: query["value"], "resultsPerPage": MAX_RESULTS, "startIndex": 0, "noRejected": ""}
        request = Request(NVD_ENDPOINT + "?" + urlencode(params), headers=headers)
        payload = None
        for attempt in range(2):
            if last_request is not None:
                delay = interval - (time.monotonic() - last_request)
                if delay > 0:
                    time.sleep(delay)
            last_request = time.monotonic()
            try:
                with urlopen(request, timeout=timeout) as response:
                    raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ValueError("Resposta NVD excedeu o limite de tamanho")
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
                    raise ValueError("Formato NVD inválido")
                break
            except HTTPError as exc:
                wait = _retry_after(exc.headers.get("Retry-After") if exc.headers else None)
                can_retry = exc.code in {429, 503} and attempt == 0 and (wait is None or wait <= MAX_RETRY_WAIT)
                exc.close()
                if can_retry:
                    time.sleep(max(interval, wait or 0.0))
                    continue
                result.notes.append(f"Falha NVD HTTP {exc.code} ao consultar {query['product']} {query['version']}; consulta não concluída.")
                if wait is not None and wait > MAX_RETRY_WAIT:
                    result.notes.append("Retry-After excede a espera máxima; a consulta foi interrompida sem ignorar o limite remoto.")
                if exc.code == 429 or (wait is not None and wait > MAX_RETRY_WAIT):
                    stop_queries = True
                    result.notes.append("Consultas restantes interrompidas para respeitar o limite da NVD.")
                break
            except (URLError, TimeoutError, OSError, ValueError, UnicodeError):
                # Exception messages can contain URLs or credentials. Keep the diagnostic fixed.
                result.notes.append(f"Falha de rede ou resposta inválida da NVD para {query['product']} {query['version']}.")
                break
        if payload is None or not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            failures += 1
            if stop_queries:
                break
            continue
        successful += 1
        total = payload.get("totalResults", len(payload["vulnerabilities"]))
        if isinstance(total, int) and total > MAX_RESULTS:
            result.status = "partial"
            result.notes.append(f"NVD retornou {total} resultados para {query['product']} {query['version']}; relatório limitado aos primeiros {MAX_RESULTS}.")
        for finding in _entries(payload, query):
            key = (finding["id"], finding["matched_product"], finding["matched_version"])
            if key not in seen:
                seen.add(key)
                result.data.append(finding)
    if failures:
        result.status = "partial" if successful else "error"
    result.notes.append(f"Consultas NVD concluídas: {successful}; falhas: {failures}.")
    return result
