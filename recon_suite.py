#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Recon & Security Audit Suite v2.3 (Optimized Single-File Architecture)
Multi-threaded reconnaissance tool with headers audit, sensitive files discovery,
user-agent rotation, log exporter, and GitHub auto-updater.
"""

import socket
import ssl
import sys
import os
import re
import time
import random
import json
import subprocess
import urllib.request
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Paleta de Colores Cyber Security / Terminal Profesional
C_BOLD = '\033[1m'
C_RESET = '\033[0m'
C_PRIMARY = '\033[38;5;39m'     # Azul Cyber
C_SECONDARY = '\033[38;5;81m'   # Cían Neón
C_MUTED = '\033[38;5;240m'       # Gris Oscuro / Bordes
C_SUCCESS = '\033[38;5;82m'     # Verde Menta
C_WARN = '\033[38;5;214m'        # Naranja
C_DANGER = '\033[38;5;196m'      # Rojo Alerta
C_WHITE = '\033[38;5;255m'       # Blanco Alto Contraste

LOG_FILE = "resultados_recon.txt"
JSON_LOG_FILE = "resultados_recon.json"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0"
]

def get_random_headers(extra_headers=None):
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    if extra_headers:
        headers.update(extra_headers)
    return headers

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    clear_screen()
    print(f"{C_MUTED}┌────────────────────────────────────────────────────────┐{C_RESET}")
    print(f"{C_MUTED}│{C_RESET} {C_PRIMARY}{C_BOLD}        NETRECON & SECURITY SUITE v2.3         {C_RESET}{C_MUTED}│{C_RESET}")
    print(f"{C_MUTED}└────────────────────────────────────────────────────────┘{C_RESET}\n")

def log_result(text):
    """Guarda en pantalla y en el archivo txt de salida sin colores ANSI."""
    clean_text = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(clean_text + "\n")
    except Exception:
        pass

def start_log_session(module_name):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = f"\n==================================================\n[MÓDULO: {module_name}] - {timestamp}\n=================================================="
    log_result(header)

def update_script():
    """Descarga la última versión desde GitHub y reinicia la herramienta."""
    print_header()
    print(f"{C_SECONDARY}{C_BOLD}--- ACTUALIZADOR AUTOMÁTICO DE GITHUB ---{C_RESET}\n")
    print(f"{C_WARN}[+] Comprobando repositorio Git local...{C_RESET}")

    if not os.path.exists(".git"):
        print(f"\n{C_DANGER}[!] Este directorio no parece estar inicializado como repositorio Git.{C_RESET}")
        print(f"{C_MUTED}Para usar el actualizador, clona el repositorio directamente con 'git clone'.{C_RESET}")
        return

    try:
        print(f"{C_PRIMARY}[+] Conectando con GitHub y descargando actualizaciones...{C_RESET}\n")
        result = subprocess.run(["git", "pull", "origin", "main"], capture_output=True, text=True)
        output = result.stdout + result.stderr
        print(f"{C_WHITE}{output}{C_RESET}")

        if "Already up to date" in output or "Ya está actualizado" in output:
            print(f"{C_SUCCESS}[✔] El script ya se encuentra en la última versión.{C_RESET}")
        elif "Fast-forward" in output or "files changed" in output or "Unpacking objects" in output:
            print(f"\n{C_SUCCESS}{C_BOLD}[✔] ¡Script actualizado correctamente desde GitHub!{C_RESET}")
            print(f"{C_WARN}[i] Reiniciando la herramienta para aplicar los cambios...{C_RESET}")
            time.sleep(2)
            os.execv(sys.executable, [sys.executable] + sys.argv)
        else:
            print(f"{C_WARN}[!] Respuesta del sistema Git procesada.{C_RESET}")

    except FileNotFoundError:
        print(f"{C_DANGER}[!] Git no está instalado en este sistema. Instálalo usando: apt install git{C_RESET}")
    except Exception as e:
        print(f"{C_DANGER}[!] Ocurrió un error inesperado durante la actualización: {e}{C_RESET}")

# --- MÓDULOS DE ESCANEO ---

def check_ip_and_cdn(target):
    start_log_session(f"IP & CDN Scanner ({target})")
    print(f"\n{C_WARN}[+] Analizando IP y Protección CDN para: {target}{C_RESET}\n")
    log_result(f"[+] Analizando IP y Protección CDN para: {target}")
    
    try:
        ip = socket.gethostbyname(target)
        msg_ip = f"IP Resuelta: {ip}"
        print(f"{C_WHITE}IP Resuelta:{C_RESET} {C_SECONDARY}{ip}{C_RESET}")
        log_result(msg_ip)
        
        cdn_detected = "Ninguno / Servidor Directo"
        try:
            req = urllib.request.Request(f"http://{target}", headers=get_random_headers())
            with urllib.request.urlopen(req, timeout=5) as response:
                headers = dict(response.info())
                server = headers.get('Server', '').lower()
                via = headers.get('Via', '').lower()
                
                if 'cloudflare' in server or 'cf-ray' in headers:
                    cdn_detected = "Cloudflare"
                elif 'cloudfront' in via or 'x-amz-cf-id' in headers:
                    cdn_detected = "Amazon CloudFront"
                elif 'gws' in server or 'google' in via:
                    cdn_detected = "Google Cloud CDN / GFE"
                elif 'imperva' in server or 'incapsula' in headers:
                    cdn_detected = "Imperva / Incapsula"
        except Exception:
            pass

        msg_cdn = f"Infraestructura / CDN: {cdn_detected}"
        print(f"{C_WHITE}Infraestructura / CDN:{C_RESET} {C_PRIMARY}{C_BOLD}{cdn_detected}{C_RESET}")
        log_result(msg_cdn)
    except socket.gaierror:
        err = f"[!] No se pudo resolver el dominio {target}."
        print(f"{C_DANGER}{err}{C_RESET}")
        log_result(err)

def scan_subdomain(target_domain, sub):
    full_domain = f"{sub}.{target_domain}"
    try:
        ip = socket.gethostbyname(full_domain)
        return (full_domain, ip)
    except socket.gaierror:
        return None

def brute_force_subdomains(target_domain):
    start_log_session(f"Descubrimiento de Subdominios ({target_domain})")
    print(f"\n{C_WARN}[+] Descubriendo subdominios activos para: {target_domain}{C_RESET}\n")
    log_result(f"[+] Descubrimiento de subdominios para: {target_domain}")
    
    wordlist = [
        "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
        "smtp", "secure", "vpn", "api", "dev", "staging", "test", "portal",
        "admin", "app", "dashboard", "cdn", "cloud", "shop", "store", "m",
        "forum", "news", "static", "img", "images", "assets", "status", "vps"
    ]
    
    found_subdomains = []
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        results = executor.map(lambda sub: scan_subdomain(target_domain, sub), wordlist)
        for res in results:
            if res:
                found_subdomains.append(res)

    if found_subdomains:
        msg = f"[✔] Subdominios Activos Encontrados ({len(found_subdomains)}):"
        print(f"{C_SUCCESS}{msg}{C_RESET}\n")
        log_result(msg)
        for sub, ip in found_subdomains:
            item = f"  - {sub} -> {ip}"
            print(f" {C_WHITE}{sub}{C_RESET} -> {C_SECONDARY}{ip}{C_RESET}")
            log_result(item)
    else:
        msg = "[i] No se encontraron subdominios activos con la lista interna."
        print(f"{C_MUTED}{msg}{C_RESET}")
        log_result(msg)

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return port
    except Exception:
        pass
    return None

def run_port_scan(target):
    start_log_session(f"Escáner de Puertos ({target})")
    print(f"\n{C_WARN}[+] Escaneando puertos abiertos en: {target}{C_RESET}\n")
    log_result(f"[+] Escaneando puertos abiertos en: {target}")
    try:
        ip = socket.gethostbyname(target)
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080, 8443]
        open_ports = []

        with ThreadPoolExecutor(max_workers=25) as executor:
            results = executor.map(lambda p: scan_port(ip, p), common_ports)
            for port in results:
                if port:
                    open_ports.append(port)

        if open_ports:
            msg = f"[✔] Puertos Abiertos Detectados: {open_ports}"
            print(f"{C_SUCCESS}[✔] Puertos Abiertos Detectados:{C_RESET} {C_SECONDARY}{open_ports}{C_RESET}")
            log_result(msg)
        else:
            msg = "[i] No se encontraron puertos abiertos comunes."
            print(f"{C_MUTED}{msg}{C_RESET}")
            log_result(msg)
    except socket.gaierror:
        err = "[!] Error de resolución de nombre de dominio."
        print(f"{C_DANGER}{err}{C_RESET}")
        log_result(err)

def validate_security_headers(target):
    """Comprueba la presencia de cabeceras de seguridad HTTP clave."""
    start_log_session(f"Auditoría Cabeceras HTTP ({target})")
    print(f"\n{C_WARN}[+] Auditando Cabeceras de Seguridad en: {target}{C_RESET}\n")
    log_result(f"[+] Auditando Cabeceras de Seguridad en: {target}")
    
    url = f"https://{target}" if not target.startswith("http") else target
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]
    
    try:
        req = urllib.request.Request(url, headers=get_random_headers())
        with urllib.request.urlopen(req, timeout=5) as response:
            headers = dict(response.info())
            
            for s_header in security_headers:
                found = False
                for h_key in headers:
                    if h_key.lower() == s_header.lower():
                        found = True
                        val = headers[h_key]
                        msg = f"  [✔] {s_header}: {val}"
                        print(f" {C_SUCCESS}[✔]{C_RESET} {C_WHITE}{s_header}:{C_RESET} {C_SECONDARY}{val}{C_RESET}")
                        log_result(msg)
                        break
                if not found:
                    msg = f"  [!] {s_header}: Ausente / No Configurada"
                    print(f" {C_DANGER}[!]{C_RESET} {C_WHITE}{s_header}:{C_RESET} {C_MUTED}Ausente / No Configurada{C_RESET}")
                    log_result(msg)
    except Exception as err:
        msg = f"[!] Falló la conexión HTTP/HTTPS: {err}"
        print(f"{C_DANGER}{msg}{C_RESET}")
        log_result(msg)

def scan_sensitive_files(target):
    """Escanera rutas y archivos sensibles comunes."""
    start_log_session(f"Búsqueda de Archivos Sensibles ({target})")
    print(f"\n{C_WARN}[+] Buscando archivos sensibles/exposiciones en: {target}{C_RESET}\n")
    log_result(f"[+] Buscando archivos sensibles en: {target}")

    base_url = f"http://{target}" if not target.startswith("http") else target
    paths = [
        "/.env", "/.git/HEAD", "/robots.txt", "/sitemap.xml",
        "/config.php.bak", "/.htaccess", "/server-status", "/api/v1"
    ]

    def check_path(path):
        url = f"{base_url.rstrip('/')}{path}"
        try:
            req = urllib.request.Request(url, headers=get_random_headers())
            with urllib.request.urlopen(req, timeout=4) as resp:
                if resp.status == 200:
                    return (path, resp.status)
        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                return (path, e.code)
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(check_path, paths)
        found = False
        for res in results:
            if res:
                found = True
                path, status = res
                if status == 200:
                    msg = f"  [EXPOSED] {path} -> HTTP {status} OK"
                    print(f" {C_SUCCESS}[EXPOSED]{C_RESET} {C_WHITE}{path}{C_RESET} -> {C_SUCCESS}200 OK{C_RESET}")
                else:
                    msg = f"  [PROTECTED] {path} -> HTTP {status}"
                    print(f" {C_WARN}[PROTECTED]{C_RESET} {C_WHITE}{path}{C_RESET} -> {C_WARN}{status}{C_RESET}")
                log_result(msg)
        if not found:
            msg = "[i] No se detectaron archivos sensibles expuestos en las rutas comunes."
            print(f"{C_MUTED}{msg}{C_RESET}")
            log_result(msg)

def check_ssl_tls(target):
    start_log_session(f"Auditoría SSL/TLS ({target})")
    print(f"\n{C_WARN}[+] Auditando SSL/TLS en: {target}{C_RESET}\n")
    log_result(f"[+] Auditando SSL/TLS en: {target}")
    
    hostname = target.replace("https://", "").replace("http://", "").split('/')[0]
    
    protocols = [
        ("TLS 1.0", getattr(ssl, "PROTOCOL_TLSv1", None)),
        ("TLS 1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None)),
        ("TLS 1.2", getattr(ssl, "PROTOCOL_TLSv1_2", None)),
        ("TLS 1.3", getattr(ssl, "PROTOCOL_TLS", None))
    ]

    for name, proto in protocols:
        if proto is None:
            continue
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    msg = f"Protocolo Activo ({name}): {version}"
                    print(f" {C_WHITE}Protocolo Activo ({name}):{C_RESET} {C_SUCCESS}{version}{C_RESET}")
                    log_result(msg)
                    break
        except Exception:
            msg = f"{name}: No soportado / Rechazado"
            print(f" {C_WHITE}{name}:{C_RESET} {C_MUTED}No soportado / Rechazado{C_RESET}")
            log_result(msg)

# --- NAVEGACIÓN Y SUBMENÚS ---

def sub_domain_recon():
    while True:
        print_header()
        print(f"{C_SECONDARY}{C_BOLD}--- SUBMENÚ: ESCÁNER DE DOMINIOS & IP ---{C_RESET}")
        print(f"{C_PRIMARY}1.{C_RESET} {C_WHITE}Obtener IP y Detección de CDN{C_RESET}")
        print(f"{C_PRIMARY}2.{C_RESET} {C_WHITE}Descubrimiento de Subdominios{C_RESET}")
        print(f"{C_PRIMARY}3.{C_RESET} {C_WHITE}Escáner de Puertos Abiertos{C_RESET}")
        print(f"{C_PRIMARY}4.{C_RESET} {C_WHITE}Auditoría de Cabeceras de Seguridad HTTP{C_RESET}")
        print(f"{C_PRIMARY}5.{C_RESET} {C_WHITE}Búsqueda de Archivos Sensibles (.env, .git, etc.){C_RESET}")
        print(f"{C_PRIMARY}6.{C_RESET} {C_WHITE}Auditoría SSL / TLS{C_RESET}")
        print(f"{C_DANGER}0. Volver al Menú Principal{C_RESET}\n")
        
        try:
            opt = input(f"{C_WHITE}Selecciona una opción [0-6]: {C_RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if opt == "1":
            target = input(f"\n{C_WHITE}Ingresa el Dominio u Host: {C_RESET}").strip()
            if target: check_ip_and_cdn(target)
            input(f"\n{C_MUTED}Presiona Enter para continuar en este submenú...{C_RESET}")
        elif opt == "2":
            target = input(f"\n{C_WHITE}Ingresa el Dominio Base: {C_RESET}").strip()
            if target: brute_force_subdomains(target)
            input(f"\n{C_MUTED}Presiona Enter para continuar en este submenú...{C_RESET}")
        elif opt == "3":
            target = input(f"\n{C_WHITE}Ingresa el Dominio u Host: {C_RESET}").strip()
            if target: run_port_scan(target)
            input(f"\n{C_MUTED}Presiona Enter para continuar en este submenú...{C_RESET}")
        elif opt == "4":
            target = input(f"\n{C_WHITE}Ingresa el Dominio u Host: {C_RESET}").strip()
            if target: validate_security_headers(target)
            input(f"\n{C_MUTED}Presiona Enter para continuar en este submenú...{C_RESET}")
        elif opt == "5":
            target = input(f"\n{C_WHITE}Ingresa el Dominio u Host: {C_RESET}").strip()
            if target: scan_sensitive_files(target)
            input(f"\n{C_MUTED}Presiona Enter para continuar en este submenú...{C_RESET}")
        elif opt == "6":
            target = input(f"\n{C_WHITE}Ingresa el Dominio u Host: {C_RESET}").strip()
            if target: check_ssl_tls(target)
            input(f"\n{C_MUTED}Presiona Enter para continuar en este submenú...{C_RESET}")
        elif opt == "0":
            break

def sub_gov_recon():
    gov_databases = {
        "argentina": ["argentina.gob.ar", "afip.gob.ar", "anses.gob.ar", "pami.org.ar"],
        "mexico": ["gob.mx", "sat.gob.mx", "imss.gob.mx", "sep.gob.mx"],
        "bolivia": ["gob.bo", "impuestos.gob.bo", "aduana.gob.bo", "seprec.gob.bo"],
        "colombia": ["gov.co", "dian.gov.co", "sisben.gov.co"],
        "peru": ["gob.pe", "sunat.gob.pe", "reniec.gob.pe", "essalud.gob.pe"],
        "chile": ["gob.cl", "sii.cl", "registrocivil.cl", "servel.cl"],
        "ecuador": ["gob.ec", "sri.gob.ec", "registrocivil.gob.ec"],
        "espana": ["gob.es", "agenciatributaria.gob.es", "seg-social.es"]
    }
    
    while True:
        print_header()
        print(f"{C_SECONDARY}{C_BOLD}--- SUBMENÚ: ESCÁNER DE PÁGINAS GUBERNAMENTALES ---{C_RESET}")
        print(f"{C_PRIMARY}1.{C_RESET} {C_WHITE}Argentina (.gob.ar){C_RESET}")
        print(f"{C_PRIMARY}2.{C_RESET} {C_WHITE}México (.gob.mx){C_RESET}")
        print(f"{C_PRIMARY}3.{C_RESET} {C_WHITE}Bolivia (.gob.bo){C_RESET}")
        print(f"{C_PRIMARY}4.{C_RESET} {C_WHITE}Colombia (.gov.co){C_RESET}")
        print(f"{C_PRIMARY}5.{C_RESET} {C_WHITE}Perú (.gob.pe){C_RESET}")
        print(f"{C_PRIMARY}6.{C_RESET} {C_WHITE}Chile (.gob.cl / .cl){C_RESET}")
        print(f"{C_PRIMARY}7.{C_RESET} {C_WHITE}Ecuador (.gob.ec){C_RESET}")
        print(f"{C_PRIMARY}8.{C_RESET} {C_WHITE}España (.gob.es){C_RESET}")
        print(f"{C_DANGER}0. Volver al Menú Principal{C_RESET}\n")

        try:
            opt = input(f"{C_WHITE}Selecciona el país a escanear [0-8]: {C_RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            break

        country_map = {
            "1": "argentina", "2": "mexico", "3": "bolivia", "4": "colombia",
            "5": "peru", "6": "chile", "7": "ecuador", "8": "espana"
        }
        
        if opt in country_map:
            country = country_map[opt]
            domains = gov_databases[country]
            start_log_session(f"Escáner Gubernamental ({country.capitalize()})")
            print(f"\n{C_WARN}[+] Escaneando sitios gubernamentales de {country.capitalize()}...{C_RESET}\n")
            log_result(f"[+] Escaneando sitios gubernamentales de {country.capitalize()}...")
            
            for dom in domains:
                try:
                    ip = socket.gethostbyname(dom)
                    msg = f"  [ONLINE] {dom} -> {ip}"
                    print(f" {C_SUCCESS}[ONLINE]{C_RESET} {C_WHITE}{dom}{C_RESET} -> {C_SECONDARY}{ip}{C_RESET}")
                    log_result(msg)
                except socket.gaierror:
                    msg = f"  [OFFLINE] {dom}"
                    print(f" {C_DANGER}[OFFLINE]{C_RESET} {C_WHITE}{dom}{C_RESET}")
                    log_result(msg)
            input(f"\n{C_MUTED}Presiona Enter para continuar en este submenú...{C_RESET}")
        elif opt == "0":
            break

# --- MENÚ PRINCIPAL ---

def main_menu():
    while True:
        print_header()
        print(f"{C_PRIMARY}1.{C_RESET} {C_WHITE}Escáner de Dominio, IP, Subdominios,
