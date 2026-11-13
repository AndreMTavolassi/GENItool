"""Command line orchestration. Target credentials never enter subprocess argv."""

import argparse
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from . import __version__
from .models import StageResult

DEFAULT_PORTS = "21,22,25,53,80,110,135,139,143,443,445,465,587,993,995,1433,1521,3306,3389,5432,5900,6379,8000,8080,8443,9200,27017"
DEFAULT_WORDLIST = Path(__file__).parent / "data" / "paths.txt"


def normalize_target(value: str) -> tuple[str, str]:
    if not value or re.search(r"[\s\x00-\x1f\x7f\\]", value):
        raise ValueError("Alvo inválido: informe uma URL HTTP(S), hostname ou IP único.")
    if "://" not in value and "/" in value:
        raise ValueError("CIDRs não são aceitos; para caminhos base, informe a URL HTTP(S) completa.")
    parsed = urlsplit(value if "://" in value else "https://" + value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("O alvo deve usar HTTP ou HTTPS.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Use --headers-file ou variáveis de ambiente para autenticação.")
    if parsed.query or parsed.fragment:
        raise ValueError("Informe uma URL base sem query string nem fragmento.")
    host = parsed.hostname
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Porta inválida na URL.") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Porta fora do intervalo 1–65535.")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
        if len(host) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        ):
            raise ValueError("Hostname inválido; listas, CIDRs e opções Nmap não são aceitos.")
    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority += f":{port}"
    return urlunsplit((parsed.scheme, authority, parsed.path or "/", "", "")), host


def validate_ports(value: str) -> str:
    if not value or len(value) > 4096:
        raise argparse.ArgumentTypeError("Informe portas ou intervalos separados por vírgula.")
    for item in value.split(","):
        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", item):
            raise argparse.ArgumentTypeError("Portas inválidas; exemplo: 22,80,443,8000-8100.")
        bounds = [int(part) for part in item.split("-")]
        if not all(1 <= n <= 65535 for n in bounds) or bounds[-1] < bounds[0]:
            raise argparse.ArgumentTypeError("Portas devem estar entre 1 e 65535, em ordem crescente.")
    return value


def positive_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("O valor deve ser finito e maior que zero.")
    return number


def bounded_int(value: str) -> int:
    number = int(value)
    if not 1 <= number <= 10000:
        raise argparse.ArgumentTypeError("Use um inteiro entre 1 e 10000.")
    return number


def cve_query_limit(value: str) -> int:
    number = int(value)
    if not 1 <= number <= 100:
        raise argparse.ArgumentTypeError("Use entre 1 e 100 consultas de CVEs.")
    return number


def load_headers(path: Path | None) -> dict[str, str]:
    headers = {}
    if path:
        if path.stat().st_size > 65536:
            raise ValueError("Arquivo de headers excede 64 KiB.")
        headers = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(headers, dict):
            raise ValueError("O arquivo de headers deve conter um objeto JSON.")
    headers = dict(headers)
    for variable, name in (("GENITOOL_TOKEN", "Authorization"), ("GENITOOL_COOKIE", "Cookie")):
        secret = os.environ.get(variable)
        if secret:
            headers = {k: v for k, v in headers.items() if k.lower() != name.lower()}
            headers[name] = ("Bearer " if variable == "GENITOOL_TOKEN" else "") + secret
    seen = set()
    blocked = {"host", "proxy-authorization", "connection", "content-length", "transfer-encoding", "upgrade", "proxy-connection"}
    for name, value in headers.items():
        if not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ValueError("Nome inválido no arquivo de headers.")
        if name.lower() in blocked or name.lower() in seen:
            raise ValueError("Header duplicado ou incompatível com o escopo HTTP.")
        if not isinstance(value, str) or re.search(r"[\x00-\x1f\x7f]", value):
            raise ValueError("Os valores dos headers devem ser strings sem controles.")
        value.encode("latin-1")
        seen.add(name.lower())
    return headers


def redact(text: str, headers: dict[str, str], api_key: str | None = None) -> str:
    secrets = set(headers.values())
    for name, value in headers.items():
        if name.lower() == "authorization" and " " in value:
            secrets.add(value.split(" ", 1)[1])
        if name.lower() == "cookie":
            secrets.update(part.strip().split("=", 1)[1] for part in value.split(";") if "=" in part)
    if api_key:
        secrets.add(api_key)
    for secret in sorted(secrets, key=len, reverse=True):
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_report(path: Path, content: str) -> None:
    atomic_write(path, content)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    atomic_write(Path(str(path) + ".sha256"), f"{digest}  {path.name}\n")


def verify_report(path: Path) -> bool:
    checksum = Path(str(path) + ".sha256").read_text(encoding="utf-8").strip()
    expected, separator, name = checksum.partition("  ")
    if not separator or name != path.name or not re.fullmatch(r"[0-9a-f]{64}", expected):
        return False
    return hashlib.sha256(path.read_bytes()).hexdigest() == expected


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="GENItool — reconhecimento e evidências em TXT para pentestes autorizados.")
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="Verificar dependências locais sem acessar alvos.")
    verify = commands.add_parser("verify", help="Verificar integridade SHA-256 de um relatório.")
    verify.add_argument("report", type=Path)
    scan = commands.add_parser("scan", help="Executar as etapas e gravar um TXT.")
    scan.add_argument("target", help="URL base, hostname ou IP único dentro do escopo autorizado.")
    scan.add_argument("-o", "--output", type=Path)
    scan.add_argument("--ports", type=validate_ports, default=None)
    scan.add_argument("--wordlist", type=Path, default=DEFAULT_WORDLIST)
    scan.add_argument("--max-paths", type=bounded_int, default=100)
    scan.add_argument("--rate", type=positive_float, default=5, help="Máximo de requisições HTTP por segundo no fuzzing (padrão: 5).")
    scan.add_argument("--timeout", type=positive_float, default=10, help="Timeout de operações de socket HTTP em segundos (padrão: 10).")
    scan.add_argument("--scan-timeout", type=bounded_int, default=120, help="Timeout de cada processo externo em segundos.")
    scan.add_argument("--max-cve-queries", type=cve_query_limit, default=5)
    scan.add_argument("--headers-file", type=Path, help="Objeto JSON com headers; valores nunca entram no relatório.")
    for name in ("nmap", "wappalyzer", "fuzz", "cves"):
        scan.add_argument(f"--skip-{name}", action="store_true")
    return root


def run_scan(args: argparse.Namespace) -> int:
    from .cves import lookup_cves
    from .fuzz import fuzz_paths
    from .report import render_report
    from .scanners import scan_nmap, scan_technologies

    target, host = normalize_target(args.target)
    headers = load_headers(args.headers_file)
    api_key = os.environ.get("NVD_API_KEY")
    if api_key and re.search(r"[\x00-\x1f\x7f]", api_key):
        raise ValueError("NVD_API_KEY contém caracteres inválidos.")
    if not args.skip_fuzz and not args.wordlist.is_file():
        raise ValueError("Wordlist não encontrada.")
    now = datetime.now(timezone.utc)
    output = args.output or Path("reports") / f"{host.replace(':', '_')}_{now.strftime('%Y%m%dT%H%M%S%fZ')}.txt"
    if output.suffix.lower() != ".txt":
        raise ValueError("O relatório deve usar a extensão .txt.")
    if output.resolve() in {args.wordlist.resolve(), args.headers_file.resolve() if args.headers_file else None}:
        raise ValueError("A saída deve ser diferente dos arquivos de entrada.")
    ports = args.ports or DEFAULT_PORTS
    if args.ports is None and urlsplit(target).port is not None:
        ports = ",".join(dict.fromkeys([*ports.split(","), str(urlsplit(target).port)]))
    stages = []
    report = {"version": __version__, "target": target, "started_at": now.isoformat(), "stages": stages,
              "options": {"ports": ports, "max_paths": args.max_paths, "rate": args.rate, "http_timeout": args.timeout,
                          "authenticated_headers_supplied": bool(headers), "max_cve_queries": args.max_cve_queries}}
    interrupted = False
    active_stage = "inicialização"
    try:
        tasks = [
            ("nmap", args.skip_nmap, lambda: scan_nmap(host, ports, args.scan_timeout)),
            ("wappalyzer", args.skip_wappalyzer, lambda: scan_technologies(target, headers, args.scan_timeout)),
            ("fuzzing", args.skip_fuzz, lambda: fuzz_paths(target, args.wordlist, headers, args.timeout, args.rate, args.max_paths)),
        ]
        for name, skip, action in tasks:
            active_stage = name
            print(f"[{name}] {'ignorado por opção' if skip else 'executando...'}", file=sys.stderr)
            if skip:
                stages.append(StageResult(name, "skipped", notes=["Desativado pelo usuário."]))
                continue
            try:
                stages.append(action())
            except Exception as exc:
                stages.append(StageResult(name, "error", notes=[f"Falha interna da etapa: {type(exc).__name__}."]))
        active_stage = "cves"
        print("[cves] " + ("ignorado por opção" if args.skip_cves else "consultando NVD quando há versões..."), file=sys.stderr)
        if args.skip_cves:
            stages.append(StageResult("cves", "skipped", notes=["Desativado pelo usuário."]))
        else:
            services = next((stage.data for stage in stages if stage.name == "nmap"), [])
            technologies = next((stage.data for stage in stages if stage.name == "wappalyzer"), [])
            try:
                stages.append(lookup_cves(services, technologies, args.timeout, args.max_cve_queries, api_key))
            except Exception as exc:
                stages.append(StageResult("cves", "error", notes=[f"Falha interna da consulta: {type(exc).__name__}."]))
    except KeyboardInterrupt:
        interrupted = True
        stages.append(StageResult(active_stage, "error", notes=["Interrompido pelo usuário; resultados parciais preservados."]))
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    content = redact(render_report(report), headers, api_key)
    save_report(output, content)
    print(f"Relatório: {output}\nIntegridade: {output}.sha256")
    if interrupted:
        return 130
    # Explicitly disabled stages and absent fingerprints are normal; unavailable requested tools are incomplete.
    requested = {"nmap": not args.skip_nmap, "wappalyzer": not args.skip_wappalyzer,
                 "fuzzing": not args.skip_fuzz, "cves": not args.skip_cves}
    incomplete = any(stage.status in {"error", "partial"} or
                     (stage.status == "skipped" and requested.get(stage.name, False) and stage.name != "cves")
                     for stage in stages)
    return 1 if incomplete else 0


def main(argv: list[str] | None = None) -> int:
    arg_parser = parser()
    args = arg_parser.parse_args(argv)
    try:
        if args.command == "verify":
            valid = verify_report(args.report)
            print("Integridade SHA-256 verificada." if valid else "FALHA: relatório ou checksum foi alterado.")
            return 0 if valid else 1
        if args.command == "doctor":
            from .scanners import dependency_status
            print(f"GENItool {__version__} | Python {sys.version.split()[0]}")
            statuses = dependency_status()
            for name, available in statuses.items():
                print(f"{name}: {'disponível' if available else 'ausente'}")
            print("Fuzzing HTTP e consulta NVD: biblioteca padrão do Python.")
            return 0 if all(statuses.values()) else 1
        return run_scan(args)
    except (ValueError, OSError, UnicodeError) as exc:
        # Exception messages can contain raw input or credentials; diagnostics deliberately omit them.
        if isinstance(exc, ValueError) and not isinstance(exc, (json.JSONDecodeError, UnicodeError)):
            print(f"Erro: {exc}", file=sys.stderr)
        else:
            print(f"Erro de configuração/arquivo ({type(exc).__name__}); verifique os caminhos e o formato dos arquivos.", file=sys.stderr)
        return 2

