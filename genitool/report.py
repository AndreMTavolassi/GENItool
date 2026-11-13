"""Render a self-contained, plain UTF-8 evidence report.

Only explicitly selected options and evidence fields are rendered. Request
headers, cookies, and API keys are deliberately excluded from the report.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any
import unicodedata
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_ANSI = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[@-_])"
)
_SENSITIVE_KEY = re.compile(
    r"authorization|cookie|password|passwd|secret|token|api.?key|headers?",
    re.IGNORECASE,
)
_HEADER_VALUE = re.compile(
    r"\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*[:=][^\r\n]*",
    re.IGNORECASE,
)
_OPTIONS = (
    "ports", "timeout", "http_timeout", "rate", "max_paths", "max_queries", "max_cve_queries", "wordlist",
    "skip_nmap", "skip_fuzz", "skip_technologies", "skip_cves",
    "no_nmap", "no_fuzz", "no_technologies", "no_cves", "auth_enabled", "authenticated_headers_supplied",
)
_TITLES = {
    "nmap": "NMAP — PORTAS E SERVIÇOS",
    "technologies": "WAPPALYZER — TECNOLOGIAS",
    "wappalyzer": "WAPPALYZER — TECNOLOGIAS",
    "fuzzing": "FUZZING — CAMINHOS HTTP",
    "cves": "CVEs — POSSÍVEIS CORRESPONDÊNCIAS",
}
_STATUSES = {
    "completed": "concluído", "partial": "parcial", "skipped": "ignorado",
    "error": "erro", "failed": "falhou",
}


def _redacted(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): "[redigido]" if _SENSITIVE_KEY.search(str(key)) else _redacted(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redacted(item) for item in value]
    return value


def clean(value: Any) -> str:
    """Flatten untrusted text and strip terminal controls, including bidi marks."""
    if value is None or value == "":
        return "não informado"
    if isinstance(value, (Mapping, list, tuple)):
        value = json.dumps(_redacted(value), ensure_ascii=False, default=str)
    text = _ANSI.sub("", str(value))
    text = _HEADER_VALUE.sub("[cabeçalho redigido]", text)
    text = "".join(
        " " if unicodedata.category(char) in {"Cc", "Cf", "Cs"} else char
        for char in text
    )
    return " ".join(text.split())


def _url(value: Any) -> str:
    """Keep evidence URLs usable without reproducing embedded credentials."""
    if not isinstance(value, str):
        return clean(value)
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"}:
            return clean(value)
        netloc = parsed.netloc.rsplit("@", 1)[-1]
        query = urlencode([
            (key, "[redigido]" if _SENSITIVE_KEY.search(key) else item)
            for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        ])
        return clean(urlunsplit((parsed.scheme, netloc, parsed.path, query, "")))
    except ValueError:
        return "[URL inválida]"


def _get(stage: Any, key: str, default: Any) -> Any:
    if isinstance(stage, Mapping):
        return stage.get(key, default)
    return getattr(stage, key, default)


def _fields(item: Mapping[str, Any], fields: tuple[tuple[str, str], ...]) -> list[str]:
    lines = []
    for key, label in fields:
        value = item.get(key)
        if value is not None and value != "" and value != []:
            lines.append(f"    {label}: {_url(value) if key == 'url' else clean(value)}")
    return lines


def _evidence(name: str, item: Any, index: int) -> list[str]:
    if not isinstance(item, Mapping):
        return [f"  [{index}] {clean(item)}"]
    if name == "nmap":
        lines = [
            f"  [{index}] {clean(item.get('host'))}:{clean(item.get('port'))}"
            f"/{clean(item.get('protocol', 'tcp'))} — {clean(item.get('service'))}"
        ]
        return lines + _fields(item, (
            ("product", "Produto"), ("version", "Versão observada"), ("cpes", "CPEs"),
        ))
    if name in {"technologies", "wappalyzer"}:
        lines = [f"  [{index}] {clean(item.get('name'))}"]
        return lines + _fields(item, (
            ("version", "Versão observada"), ("confidence", "Confiança do detector"),
            ("cpes", "CPEs"), ("source", "Fonte"),
        ))
    if name == "fuzzing":
        lines = [f"  [{index}] {_url(item.get('url'))}"]
        return lines + _fields(item, (
            ("status_code", "HTTP"), ("length", "Bytes capturados"),
            ("validation", "Validação"), ("recheck_status_code", "HTTP na revalidação"),
            ("truncated", "Corpo capturado truncado"), ("sha256", "SHA256 do corpo capturado"),
        ))
    if name == "cves":
        lines = [f"  [{index}] {clean(item.get('id'))} — CANDIDATA, SEM CONFIRMAÇÃO"]
        return lines + _fields(item, (
            ("matched_product", "Produto consultado"),
            ("matched_version", "Versão consultada"),
            ("match_basis", "Base da correspondência"),
            ("cvss", "CVSS publicado"), ("severity", "Severidade publicada"),
            ("description", "Descrição"), ("url", "Referência"),
        ))
    lines = [f"  [{index}]"]
    for key, value in item.items():
        if not _SENSITIVE_KEY.search(str(key)):
            lines.append(f"    {clean(key)}: {clean(value)}")
    return lines


def render_report(report: dict) -> str:
    """Produce deterministic report text; a stage failure remains visible."""
    lines = [
        "GENItool — RELATÓRIO DE RECONHECIMENTO",
        "=" * 72,
        f"Versão: {clean(report.get('version'))}",
        f"Alvo: {_url(report.get('target'))}",
        f"Início: {clean(report.get('started_at'))}",
        f"Fim: {clean(report.get('finished_at'))}",
        "",
        "ESCOPO E INTERPRETAÇÃO",
        "Os registros abaixo são evidências de reconhecimento em um alvo autorizado.",
        "Uma resposta reproduzível confirma a observação HTTP, não uma vulnerabilidade.",
        "Versões e tecnologias são inferências dos detectores e podem estar incorretas.",
        "CVEs são candidatas: valide versão afetada, configuração e correções aplicadas.",
        "A consulta não executa exploração nem comprova que o alvo seja vulnerável.",
        "SHA256 permite conferir integridade; não é assinatura nem prova de autoria.",
    ]
    options = report.get("options", {})
    if isinstance(options, Mapping):
        selected = [(key, options[key]) for key in _OPTIONS if key in options]
        if selected:
            lines.extend(["", "PARÂMETROS"])
            lines.extend(f"  {key}: {clean(value)}" for key, value in selected)
    stages = report.get("stages", [])
    if not isinstance(stages, (list, tuple)):
        stages = []
    lines.extend(["", "RESUMO DAS ETAPAS"])
    if not stages:
        lines.append("  Nenhuma etapa registrada.")
    for stage in stages:
        name = clean(_get(stage, "name", "etapa"))
        status = clean(_get(stage, "status", "não informado"))
        data = _get(stage, "data", [])
        count = len(data) if isinstance(data, (list, tuple)) else 0
        lines.append(f"  {name}: {_STATUSES.get(status, status)}; registros: {count}")
    for stage in stages:
        name = clean(_get(stage, "name", "etapa"))
        status = clean(_get(stage, "status", "não informado"))
        lines.extend(["", _TITLES.get(name, name.upper()), "-" * 72])
        lines.append(f"Estado: {_STATUSES.get(status, status)}")
        notes = _get(stage, "notes", [])
        if isinstance(notes, str):
            notes = [notes]
        if isinstance(notes, (list, tuple)):
            lines.extend(f"Nota: {clean(note)}" for note in notes)
        data = _get(stage, "data", [])
        if isinstance(data, (list, tuple)) and data:
            for index, item in enumerate(data, start=1):
                lines.extend(_evidence(name, item, index))
        else:
            lines.append("Nenhuma evidência registrada nesta etapa.")
            lines.append("A ausência de registros não comprova ausência de vulnerabilidades.")
    return "\n".join(lines) + "\n"
