#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Recon & Security Audit Suite v2.5
================================

- Subdominios (subfinder)
- HTTP 200 / HTTP‑Headers (curl)
- Puertos abiertos (nmap –sS -p- o filtro)
- TLS / Certificado (sslscan)
- Huella dactilar (web_fingerprint)
- CMS (web_wpscan)
- Reportes: TXT + JSON
"""

import os
import sys
import re
import json
import socket
import time
import random
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple, Dict, Any

# ---------- UI / CONSTANTES ----------
C_BOLD   = '\033[1m'
C_RESET  = '\033[0m'
C_PRIMARY   = '\033[38;5;39m'   # Azul Cyber
C_SECONDARY = '\033[38;5;81m'   # Cían Neón
C_MUTED     = '\033[38;5;240m' # Gris Oscuro
C_SUCCESS   = '\033[38;5;82m'   # Verde Menta
C_WARN      = '\033[38;5;214m'  # Naranja
C_DANGER    = '\033[38;5;196m'  # Rojo
C_WHITE     = '\033[38;5;255m'  # Blanco

LOG_FILE    = "resultados_recon.txt"
JSON_LOG    = "resultados_recon.json"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0"
]

# ---------- HELPERS ----------
def clear_screen() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header() -> None:
    clear_screen()
    print(f"{C_MUTED}┌────────────────────────────────────────────────────────┐{C_RESET}")
    print(f"{C_MUTED}│{C_RESET} {C_PRIMARY}{C_BOLD}        NETRECON & SECURITY SUITE v2.5         {C_RESET}{C_MUTED}│{C_RESET}")
    print(f"{C_MUTED}└────────────────────────────────────────────────────────┘{C_RESET}\n")

def log_txt(msg: str) -> None:
    """Escribe en pantalla y en el fichero TXT sin ANSI."""
    clean = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', msg)
    print(msg)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(clean + "\n")
    except Exception:
        pass

def log_json(entry: Dict[str, Any]) -> None:
    """Agrega un registro a un array en el fichero JSON."""
    if not os.path.exists(JSON_LOG):
        data = []
    else:
        with open(JSON_LOG, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
    data.append(entry)
    with open(JSON_LOG, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

# ---------- TOOL CALLS ----------
# (Los siguientes wrappers llaman a los *tool* definidos en la plataforma)
def run_subfinder(domain: str) -> List[str]:
    """Devuelve la lista de subdominios encontrados."""
    result = subfinder({"target_domain": domain})
    return result.get("subdomains", [])

def run_nmap_scan(target: str, ports: str = "-p-", scan_type: str = "-sS -A") -> Dict[str, Any]:
    """Ejecuta nmap y devuelve el JSON de resultados."""
    return nmap_scan({"target": target, "scan_type": scan_type, "ports": ports})

def run_sslscan(host: str) -> Dict[str, Any]:
    """Ejecuta sslscan y devuelve el JSON de resultados."""
    return sslscan({"target_domain": host})

def run_web_fingerprint(host: str) -> Dict[str, Any]:
    """Devuelve la huella de la web."""
    return web_fingerprint({"host": host})

def run_web_wpscan(host: str) -> Dict[str, Any]:
    """Devuelve la información de CMS (si es WordPress)."""
    return web_wpscan({"host": host})

# ---------- RECON FUNCIONES ----------
def resolve_ip(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return ""

def http_status(url: str, timeout: int = 4) -> Tuple[int, Dict[str, str]]:
    """Devuelve el código HTTP y las cabeceras."""
    import urllib.request, urllib.error
    try:
        req = urllib.request.Request(url, headers=get_random_headers())
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = dict(resp.info())
            return resp.status, headers
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception:
        return 0, {}

def get_random_headers(extra: dict = None) -> dict:
    h = {"User-Agent": random.choice(USER_AGENTS)}
    if extra:
        h.update(extra)
    return h

# ---------- MAIN SCAN ----------
def run_full_scan(target: str, port_filter: str = "-p-", json_output: bool = True) -> None:
    """Ejecución completa de todas las etapas."""
    log_txt(f"\n{C_WARN}[+] Iniciando escaneo completo en {target}{C_RESET}\n")
    start = datetime.now()
    results: Dict[str, Any] = {"target": target, "timestamp": start.isoformat()}

    # 1. IP & CDN
    ip = resolve_ip(target)
    results["ip"] = ip
    log_txt(f"  IP Resuelta: {ip}")

    # 2. Subdominios (subfinder)
    log_txt("\n  • Enumerando subdominios con subfinder…")
    subdomains = run_subfinder(target)
    results["subdomains"] = subdomains
    log_txt(f"    Subdominios encontrados: {len(subdomains)}")

    # 3. HTTP 200 + headers
    log_txt("\n  • Verificando HTTP 200 y extrayendo cabeceras…")
    http_ok = []
    http_err = []
    for sub in subdomains:
        url = f"https://{sub}"
        status, headers = http_status(url)
        if status == 200:
            http_ok.append({"subdomain": sub, "url": url, "headers": headers})
        else:
            http_err.append({"subdomain": sub, "url": url, "status": status})
    results["http_ok"] = http_ok
    results["http_err"] = http_err
    log_txt(f"    HTTP 200: {len(http_ok)} | No 200: {len(http_err)}")

    # 4. Puertos abiertos (nmap)
    log_txt("\n  • Escaneando puertos abiertos con nmap…")
    nmap_res = run_nmap_scan(target, ports=port_filter, scan_type="-sS -A")
    results["nmap"] = nmap_res
    open_ports = []
    for host in nmap_res.get("hosts", []):
        for port in host.get("ports", []):
            if port.get("state") == "open":
                open_ports.append({"port": port["portid"], "service": port.get("service", {}).get("name")})
    results["open_ports"] = open_ports
    log_txt(f"    Puertos abiertos: {len(open_ports)}")

    # 5. TLS / Certificado (sslscan)
    log_txt("\n  • Auditoría SSL/TLS con sslscan…")
    ssl_res = run_sslscan(target)
    results["sslscan"] = ssl_res
    # Extraer CN y expiración
    cert = ssl_res.get("certificates", [{}])[0]
    cn = cert.get("subject", {}).get("CN", "N/A")
    exp = cert.get("validity", {}).get("notAfter", "N/A")
    results["tls_cert"] = {"CN": cn, "expires": exp}
    log_txt(f"    CN: {cn} | Expira: {exp}")

    # 6. Huella dactilar (web_fingerprint)
    log_txt("\n  • Fingerprint de la web…")
    fp_res = run_web_fingerprint(target)
    results["fingerprint"] = fp_res
    log_txt(f"    Server: {fp_res.get('server', 'N/A')}")

    # 7. CMS detection (web_wpscan)
    log_txt("\n  • Detección de CMS (WordPress) …")
    wp_res = run_web_wpscan(target)
    results["cms"] = wp_res
    if wp_res.get("found"):
        log_txt(f"    CMS detectado: WordPress (versión {wp_res.get('version')})")
    else:
        log_txt("    CMS no detectado.")

    # 8. Resumen en TXT
    log_txt("\n  • Generando resumen en TXT…")
    log_txt(f"=== Resumen para {target} ===")
    log_txt(f"IP: {ip}")
    log_txt(f"Subdominios activos: {len(subdomains)}")
    log_txt(f"HTTP 200: {len(http_ok)}")
    log_txt(f"Puertos abiertos: {len(open_ports)}")
    log_txt(f"TLS CN: {cn} | Expira: {exp}")
    log_txt(f"Server: {fp_res.get('server', 'N/A')}")
    if wp_res.get("found"):
        log_txt(f"CMS: WordPress {wp_res.get('version')}")
    else:
        log_txt("CMS: No detectado")

    # 9. JSON opcional
    if json_output:
        log_txt("\n  • Escribiendo reporte JSON…")
        log_json(results)

    end = datetime.now()
    duration = (end - start).total_seconds()
    log_txt(f"\n{C_SUCCESS}[✔] Escaneo completo en {duration:.1f}s{C_RESET}\n")

# ---------- INTERFAZ ----------
def main() -> None:
    while True:
        print_header()
        print(f"{C_PRIMARY}1.{C_RESET} {C_WHITE}Escaneo completo (subdominios, puertos, TLS, CMS) …{C_RESET}")
        print(f"{C_PRIMARY}2.{C_RESET} {C_WHITE}Salir{C_RESET}\n")

        try:
            opt = input(f"{C_WHITE}Selecciona una opción [1-2]: {C_RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{C_WARN}[!] Salida detectada. Cerrando…{C_RESET}\n")
            break

        if opt == "1":
            target = input(f"\n{C_WHITE}Introduce el dominio a escanear: {C_RESET}").strip()
            if not target:
                continue
            # ¿Filtro de puertos?
            fp = input(f"\n{C_WHITE}Filtrar puertos (ej. 80,443,8080) o dejar vacío para todos: {C_RESET}").strip()
            port_filter = f"-p{fp}" if fp else "-p-"
            run_full_scan(target, port_filter=port_filter)
            input(f"\n{C_MUTED}Presiona Enter para continuar…{C_RESET}")
        elif opt == "2":
            print(f"\n{C_SUCCESS}Saliendo de la herramienta…{C_RESET}\n")
            sys.exit(0)

if __name__ == "__main__":
    main()
