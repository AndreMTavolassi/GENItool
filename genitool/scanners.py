"""Bounded Nmap discovery and static Wappalyzer fingerprints."""

from __future__ import annotations

import ipaddress
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from .models import StageResult


_ENGINE = Path(__file__).with_name("wappalyzer.cjs")


class _SnapshotParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, list[str]] = {}
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "meta":
            name = attributes.get("name") or attributes.get("property")
            content = attributes.get("content")
            if name and content:
                self.meta.setdefault(name.lower(), []).append(content)
        if tag == "script" and attributes.get("src"):
            self.scripts.append(attributes["src"])


def _valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(
            len(host) <= 253
            and all(
                re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
                for label in host.rstrip(".").split(".")
            )
        )


def _valid_ports(ports: str) -> bool:
    if not isinstance(ports, str) or not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", ports):
        return False
    for item in ports.split(","):
        numbers = [int(number) for number in item.split("-")]
        if not all(1 <= number <= 65535 for number in numbers):
            return False
        if len(numbers) == 2 and numbers[0] > numbers[1]:
            return False
    return True


def parse_nmap_xml(xml: str) -> list[dict]:
    """Read only open ports from Nmap's machine-readable output."""
    if "<!ENTITY" in xml.upper():
        raise ValueError("XML com entidades não é aceito")
    root = ET.fromstring(xml)
    if root.tag != "nmaprun":
        raise ValueError("A saída não é um documento Nmap")
    services = []
    for host in root.findall("host"):
        addresses = host.findall("address")
        address = next(
            (item.get("addr", "") for item in addresses if item.get("addrtype") in {"ipv4", "ipv6"}),
            "",
        )
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            attributes = service.attrib if service is not None else {}
            cpes = [item.text for item in service.findall("cpe") if item.text] if service is not None else []
            services.append({
                "host": address,
                "port": int(port.attrib["portid"]),
                "protocol": port.get("protocol", "tcp"),
                "service": attributes.get("name", ""),
                "product": attributes.get("product", ""),
                "version": attributes.get("version", ""),
                "cpes": cpes,
                "tunnel": attributes.get("tunnel", ""),
                "evidence": "Nmap -sV; identificação de serviço, sem exploração",
            })
    return services


def scan_nmap(host: str, ports: str, timeout: int) -> StageResult:
    if not _valid_host(host) or not _valid_ports(ports) or timeout <= 0:
        return StageResult("nmap", "error", notes=["Alvo, portas ou timeout inválidos."])
    executable = shutil.which("nmap")
    if not executable:
        return StageResult("nmap", "skipped", notes=["Nmap ausente; instale o binário nmap e coloque-o no PATH."])
    command = [executable, "-sT", "-sV", "--version-light", "-Pn", "-p", ports, "-oX", "-"]
    try:
        if ipaddress.ip_address(host).version == 6:
            command.append("-6")
    except ValueError:
        pass
    command.append(host)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return StageResult("nmap", "error", notes=["Nmap excedeu o timeout; resultados incompletos foram descartados."])
    except OSError:
        return StageResult("nmap", "error", notes=["Não foi possível executar o Nmap."])
    if result.returncode:
        return StageResult("nmap", "error", notes=[f"Nmap terminou com código {result.returncode}; verifique a instalação e o alvo."])
    try:
        services = parse_nmap_xml(result.stdout)
    except (ET.ParseError, ValueError, KeyError, TypeError):
        return StageResult("nmap", "error", notes=["A saída XML do Nmap é inválida."])
    return StageResult("nmap", "completed", services, ["Somente portas TCP solicitadas; -sT -sV --version-light -Pn."])


def _engine_check(timeout: int = 10) -> bool:
    node = shutil.which("node")
    if not node:
        return False
    try:
        result = subprocess.run([node, str(_ENGINE), "--check"], capture_output=True, text=True, timeout=timeout, check=False)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def dependency_status() -> dict[str, bool]:
    return {"nmap": bool(shutil.which("nmap")), "node": bool(shutil.which("node")), "wappalyzer": _engine_check()}


def scan_technologies(url: str, headers: dict[str, str], timeout: int) -> StageResult:
    """Run Wappalyzer's actual engine on one TLS-verified HTTP snapshot.

    Browser JavaScript is deliberately not executed. Fingerprint data belongs to
    the optional installed Wappalyzer package, not to an invented local detector.
    """
    if not _engine_check(min(timeout, 10)):
        return StageResult("wappalyzer", "skipped", notes=[
            "Engine Wappalyzer indisponível. Instale Node.js e execute npm install --ignore-scripts na raiz do projeto.",
            "O pacote opcional usa assinaturas históricas Wappalyzer 6.10.66; npm wappalyzer 7 não contém o engine.",
        ])
    from .http_client import HttpClient, HttpRequestError

    try:
        response = HttpClient(headers=headers, timeout=timeout, rate=5, max_body_bytes=1048576, origin=url).get(url)
    except HttpRequestError:
        return StageResult("wappalyzer", "error", notes=["Falha ao obter a página para análise Wappalyzer."])
    encoding = "utf-8"
    match = re.search(r"charset\s*=\s*[\"']?([a-zA-Z0-9_-]+)", response.headers.get("content-type", ""), re.I)
    if match:
        encoding = match.group(1)
    try:
        body = response.body.decode(encoding, errors="replace") if isinstance(response.body, bytes) else response.body
    except LookupError:
        body = response.body.decode("utf-8", errors="replace")
    parser = _SnapshotParser()
    parser.feed(body)
    payload = {"url": url, "html": body, "headers": dict(response.headers), "meta": parser.meta, "scriptSrc": parser.scripts}
    try:
        result = subprocess.run(
            [shutil.which("node"), str(_ENGINE)],
            input=json.dumps(payload), capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return StageResult("wappalyzer", "error", notes=["A análise Wappalyzer excedeu o timeout."])
    except OSError:
        return StageResult("wappalyzer", "error", notes=["Não foi possível iniciar o engine Wappalyzer."])
    if result.returncode:
        return StageResult("wappalyzer", "error", notes=["Engine Wappalyzer falhou; verifique a instalação opcional."])
    try:
        data = json.loads(result.stdout)
        if not isinstance(data, dict) or not isinstance(data.get("technologies"), list):
            raise ValueError
        technologies = []
        for item in data["technologies"]:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise ValueError
            cpe = item.get("cpe")
            technologies.append({
                "name": item["name"], "version": item.get("version") or "",
                "cpes": [cpe] if isinstance(cpe, str) and cpe else [],
                "confidence": item.get("confidence", 0),
                "source": "Wappalyzer 6.10.66 (análise estática)",
            })
    except (ValueError, TypeError, KeyError):
        return StageResult("wappalyzer", "error", notes=["A saída JSON do engine Wappalyzer é inválida."])
    notes = [
        "Assinaturas históricas Wappalyzer 6.10.66; somente HTML e cabeçalhos, sem executar JavaScript.",
        f"Resposta HTTP {response.status_code}; fingerprint é evidência, não confirmação de vulnerabilidade.",
    ]
    partial = response.truncated or not 200 <= response.status_code < 300
    if response.truncated:
        notes.append("HTML limitado a 1 MiB; parte da página não foi analisada.")
    return StageResult("wappalyzer", "partial" if partial else "completed", technologies, notes)
