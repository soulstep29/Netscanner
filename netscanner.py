#!/usr/bin/env python3
"""
NetScanner - Herramienta de análisis de red local
Uso: python3 netscanner.py
Requiere: nmap instalado en el sistema + python-nmap, scapy (opcional)
"""

import socket
import threading
import subprocess
import json
import os
import sys
import time
import ipaddress
import platform
import struct
import datetime
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed

# Dependencias opcionales
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# ─────────────────────────────────────────────
# COLORES ANSI (estilo terminal)
# ─────────────────────────────────────────────
class Colors:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"
    BG_RED  = "\033[41m"

C = Colors()

BANNER = f"""
{C.GREEN}{C.BOLD}
 ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
 ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
 ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.RESET}{C.DIM}           Herramienta de análisis de red - Laboratorio/LAN
           [Solo uso autorizado] v2.0 - Github: github.com/soulstep29
{C.RESET}"""

# ─────────────────────────────────────────────
# HISTORIAL DE ESCANEOS
# ─────────────────────────────────────────────
scan_history = []

def add_to_history(scan_type, target, result_summary):
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "type": scan_type,
        "target": target,
        "summary": result_summary
    }
    scan_history.append(entry)

# ─────────────────────────────────────────────
# UTILIDADES GENERALES
# ─────────────────────────────────────────────
def clear():
    os.system("cls" if platform.system() == "Windows" else "clear")

def print_header(title):
    width = 60
    print(f"\n{C.CYAN}{'─'*width}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  {title}{C.RESET}")
    print(f"{C.CYAN}{'─'*width}{C.RESET}\n")

def print_ok(msg):    print(f"{C.GREEN}  [+]{C.RESET} {msg}")
def print_warn(msg):  print(f"{C.YELLOW}  [!]{C.RESET} {msg}")
def print_err(msg):   print(f"{C.RED}  [-]{C.RESET} {msg}")
def print_info(msg):  print(f"{C.BLUE}  [*]{C.RESET} {msg}")

def input_prompt(msg):
    return input(f"\n{C.YELLOW}  >{C.RESET} {msg}: ").strip()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def get_network_range(ip):
    """Deduce el rango /24 a partir de la IP local"""
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "N/A"

# ─────────────────────────────────────────────
#  ESCANEO DE HOSTS
# ─────────────────────────────────────────────
def ping_host(ip, timeout=1):
    """Ping individual a un host"""
    param = "-n" if platform.system() == "Windows" else "-c"
    cmd = ["ping", param, "1", "-W", str(timeout), str(ip)]
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False

def ping_sweep(network_range, silent=False, max_threads=100):
    """Escaneo de hosts activos en la red"""
    print_header("PING SWEEP / ESCANEO DE HOSTS")
    print_info(f"Red objetivo: {C.BOLD}{network_range}{C.RESET}")
    print_info(f"Hilos simultáneos: {max_threads}\n")

    try:
        net = ipaddress.ip_network(network_range, strict=False)
    except ValueError:
        print_err("Rango de red inválido.")
        return []

    hosts = list(net.hosts())
    active = []
    lock = threading.Lock()
    done = [0]

    def check(ip):
        ip_str = str(ip)
        if ping_host(ip_str):
            hostname = resolve_hostname(ip_str)
            with lock:
                active.append({"ip": ip_str, "hostname": hostname})
                done[0] += 1
                if not silent:
                    print_ok(f"{ip_str:<18} {C.DIM}→{C.RESET} {hostname}")
        else:
            with lock:
                done[0] += 1

    print_info(f"Escaneando {len(hosts)} hosts...")
    t_start = time.time()

    with ThreadPoolExecutor(max_workers=max_threads) as ex:
        ex.map(check, hosts)

    elapsed = time.time() - t_start
    print(f"\n{C.GREEN}  Hosts activos: {len(active)} / {len(hosts)}{C.RESET}  ({elapsed:.1f}s)")
    add_to_history("ping_sweep", network_range, f"{len(active)} hosts activos")
    return active

# ─────────────────────────────────────────────
#  ESCANEO DE PUERTOS 
# ─────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    512: "rexec", 514: "rsh", 515: "LPD", 587: "SMTPS", 631: "IPP",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL",
    1521: "Oracle", 2049: "NFS", 2375: "Docker", 3306: "MySQL",
    3389: "RDP", 4444: "Metasploit", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 6443: "K8s API", 7070: "RealServer", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "Jupyter", 9200: "Elasticsearch",
    9090: "Prometheus", 27017: "MongoDB"
}

def scan_port(ip, port, timeout=0.5):
    """Intenta conectar a un puerto TCP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def grab_banner(ip, port, timeout=2):
    """Intenta capturar el banner del servicio"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        # Enviar petición básica según el puerto
        if port in [80, 8080, 8443]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 21:
            pass  # FTP manda banner solo
        else:
            sock.send(b"\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:100]  # Truncar
    except:
        return ""

def port_scan(ip, mode="common", grab=False, silent=False):
    """Escaneo de puertos en un host"""
    print_header(f"ESCANEO DE PUERTOS — {ip}")

    if mode == "common":
        ports = list(COMMON_PORTS.keys())
        print_info(f"Modo: {C.YELLOW}Puertos comunes{C.RESET} ({len(ports)} puertos)")
    elif mode == "fast":
        ports = list(range(1, 1025))
        print_info(f"Modo: {C.YELLOW}Rápido{C.RESET} (1-1024)")
    else:
        ports = list(range(1, 65536))
        print_info(f"Modo: {C.RED}Completo{C.RESET} (1-65535) — puede tardar varios minutos")

    open_ports = []
    lock = threading.Lock()

    def check_port(port):
        if scan_port(ip, port):
            service = COMMON_PORTS.get(port, "?")
            banner = grab_banner(ip, port) if grab else ""
            with lock:
                open_ports.append({"port": port, "service": service, "banner": banner})
                if not silent:
                    banner_str = f" {C.DIM}│ {banner[:60]}{C.RESET}" if banner else ""
                    print_ok(f":{C.BOLD}{port:<6}{C.RESET} {C.CYAN}{service:<15}{C.RESET}{banner_str}")

    print_info("Escaneando...\n")
    t_start = time.time()

    with ThreadPoolExecutor(max_workers=200) as ex:
        ex.map(check_port, ports)

    elapsed = time.time() - t_start
    open_ports.sort(key=lambda x: x["port"])
    print(f"\n{C.GREEN}  Puertos abiertos: {len(open_ports)}{C.RESET}  ({elapsed:.1f}s)")
    add_to_history("port_scan", ip, f"{len(open_ports)} puertos abiertos - modo {mode}")
    return open_ports

# ─────────────────────────────────────────────
#  ESCANEO CON NMAP 
# ─────────────────────────────────────────────
def nmap_scan(target, scan_type="basic"):
    """Escaneo con nmap via python-nmap"""
    print_header(f"ESCANEO NMAP — {target}")

    if not NMAP_AVAILABLE:
        print_err("python-nmap no está instalado. Ejecuta: pip install python-nmap")
        return {}

    nm = nmap.PortScanner()
    results = {}

    try:
        if scan_type == "basic":
            print_info("Escaneo básico: puertos comunes + versiones")
            nm.scan(hosts=target, arguments="-sV --open -T4 --top-ports 100")
        elif scan_type == "os":
            print_info("Detección de SO (requiere root/sudo)")
            nm.scan(hosts=target, arguments="-O -sV --open -T4")
        elif scan_type == "vuln":
            print_info("Scripts de vulnerabilidades (requiere root/sudo)")
            nm.scan(hosts=target, arguments="-sV --script=vuln -T4")
        elif scan_type == "full":
            print_info("Escaneo completo: todos los puertos + versiones")
            nm.scan(hosts=target, arguments="-sV -p- --open -T4")

        for host in nm.all_hosts():
            print(f"\n{C.BOLD}  Host: {host} ({nm[host].hostname()}){C.RESET}")
            print(f"  Estado: {C.GREEN}{nm[host].state()}{C.RESET}")

            # Detección de SO
            if "osmatch" in nm[host]:
                for os_match in nm[host]["osmatch"][:2]:
                    print(f"  OS: {C.MAGENTA}{os_match['name']}{C.RESET} ({os_match['accuracy']}% confianza)")

            for proto in nm[host].all_protocols():
                ports_data = nm[host][proto]
                print(f"\n  {C.CYAN}Protocolo: {proto.upper()}{C.RESET}")
                print(f"  {'Puerto':<10}{'Estado':<12}{'Servicio':<20}{'Versión'}")
                print(f"  {'─'*65}")
                for port in sorted(ports_data.keys()):
                    info = ports_data[port]
                    state   = info.get("state", "?")
                    service = info.get("name", "?")
                    version = f"{info.get('product','')} {info.get('version','')} {info.get('extrainfo','')}".strip()
                    color = C.GREEN if state == "open" else C.RED
                    print(f"  {C.BOLD}{port:<10}{C.RESET}{color}{state:<12}{C.RESET}{service:<20}{C.DIM}{version}{C.RESET}")
                    results[port] = {"state": state, "service": service, "version": version}

        add_to_history(f"nmap_{scan_type}", target, f"{len(results)} puertos encontrados")
    except Exception as e:
        print_err(f"Error en nmap: {e}")
        print_warn("Algunos modos requieren ejecutar con sudo.")

    return results

# ─────────────────────────────────────────────
#  INFO DE DISPOSITIVOS / RED LOCAL
# ─────────────────────────────────────────────
def get_device_info():
    """Información sobre el dispositivo actual"""
    print_header("INFORMACIÓN DEL DISPOSITIVO")

    local_ip = get_local_ip()
    hostname  = socket.gethostname()
    net_range = get_network_range(local_ip)

    try:
        public_ip = socket.gethostbyname("api.ipify.org")
    except:
        public_ip = "N/A (sin acceso externo)"

    print_ok(f"Hostname:     {C.BOLD}{hostname}{C.RESET}")
    print_ok(f"IP local:     {C.BOLD}{local_ip}{C.RESET}")
    print_ok(f"Rango /24:    {C.BOLD}{net_range}{C.RESET}")
    print_ok(f"Sistema:      {C.BOLD}{platform.system()} {platform.release()}{C.RESET}")
    print_ok(f"Python:       {C.BOLD}{sys.version.split()[0]}{C.RESET}")
    print_ok(f"nmap lib:     {C.BOLD}{'Disponible' if NMAP_AVAILABLE else 'No instalado'}{C.RESET}")

    # Interfaces de red (Linux/Mac)
    if platform.system() != "Windows":
        try:
            result = subprocess.run(["ip", "addr"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"\n{C.CYAN}  Interfaces de red:{C.RESET}")
                for line in result.stdout.split("\n"):
                    if "inet " in line and "127.0.0.1" not in line:
                        print(f"  {C.DIM}{line.strip()}{C.RESET}")
        except:
            pass

    return local_ip, net_range

def basic_network_info():
    """Pruebas básicas de red"""
    print_header("DIAGNÓSTICO DE RED BÁSICO")

    targets = [
        ("Gateway/Router", "192.168.1.1"),
        ("DNS Google",     "8.8.8.8"),
        ("DNS Cloudflare", "1.1.1.1"),
        ("Internet",       "google.com"),
    ]

    for name, target in targets:
        try:
            ip = socket.gethostbyname(target)
            alive = ping_host(ip, timeout=2)
            status = f"{C.GREEN}ONLINE{C.RESET}" if alive else f"{C.RED}OFFLINE{C.RESET}"
            print_ok(f"{name:<20} {ip:<18} {status}")
        except:
            print_err(f"{name:<20} No resoluble")

    # Velocidad DNS
    print(f"\n{C.CYAN}  Test de resolución DNS:{C.RESET}")
    domains = ["google.com", "github.com", "cloudflare.com"]
    for d in domains:
        t0 = time.time()
        try:
            socket.gethostbyname(d)
            ms = (time.time() - t0) * 1000
            print_ok(f"{d:<25} {ms:.1f} ms")
        except:
            print_err(f"{d:<25} Fallo")

# ─────────────────────────────────────────────
#  EXPORTAR RESULTADOS
# ─────────────────────────────────────────────
def export_results(data, filename_base="scan_result", fmt="json"):
    """Exporta resultados a TXT o JSON"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{filename_base}_{timestamp}.{fmt}"

    try:
        if fmt == "json":
            with open(filename, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            with open(filename, "w") as f:
                f.write(f"NetScanner - Exportación {timestamp}\n")
                f.write("="*50 + "\n\n")
                if isinstance(data, list):
                    for item in data:
                        f.write(str(item) + "\n")
                else:
                    f.write(str(data))

        print_ok(f"Resultados exportados a: {C.BOLD}{filename}{C.RESET}")
        return filename
    except Exception as e:
        print_err(f"Error al exportar: {e}")
        return None

# ─────────────────────────────────────────────
#  HISTORIAL
# ─────────────────────────────────────────────
def show_history():
    print_header("HISTORIAL DE ESCANEOS")
    if not scan_history:
        print_warn("Sin escaneos en esta sesión.")
        return

    for i, entry in enumerate(scan_history, 1):
        ts = entry["timestamp"][:19].replace("T", " ")
        print(f"  {C.DIM}[{i}]{C.RESET} {C.CYAN}{ts}{C.RESET}  "
              f"{C.YELLOW}{entry['type']:<20}{C.RESET}  "
              f"{entry['target']:<20}  {C.DIM}{entry['summary']}{C.RESET}")

# ─────────────────────────────────────────────
#  ESCANEO DE RED EXTERNA (AUTORIZADA)
# ─────────────────────────────────────────────
def scan_external_range():
    print_header("ESCANEO DE RED EXTERNA (AUTORIZADA)")
    print(f"{C.BG_RED}{C.WHITE}  ADVERTENCIA LEGAL  {C.RESET}")
    print(f"{C.RED}  Solo usar en redes para las que tienes autorización explícita.{C.RESET}")
    print(f"{C.RED}  El escaneo no autorizado es ilegal en la mayoría de jurisdicciones.{C.RESET}\n")

    confirm = input_prompt("Confirma que tienes autorización (escribe 'SI TENGO AUTORIZACIÓN')")
    if confirm != "SI TENGO AUTORIZACIÓN":
        print_warn("Operación cancelada.")
        return

    target = input_prompt("Introduce la IP/rango objetivo (ej: 10.0.0.0/24 o 192.168.2.50)")
    if not target:
        return

    print_info("¿Qué tipo de escaneo quieres?")
    print("  [1] Ping sweep (hosts activos)")
    print("  [2] Puertos comunes")
    print("  [3] Nmap básico")

    opt = input_prompt("Opción")
    if opt == "1":
        ping_sweep(target)
    elif opt == "2":
        port_scan(target, mode="common")
    elif opt == "3":
        nmap_scan(target, scan_type="basic")
    else:
        print_warn("Opción no válida.")

# ─────────────────────────────────────────────
# MENÚ PRINCIPAL
# ─────────────────────────────────────────────
def main_menu():
    local_ip = get_local_ip()
    net_range = get_network_range(local_ip)

    while True:
        clear()
        print(BANNER)
        print(f"  {C.DIM}IP local: {C.BOLD}{local_ip}{C.RESET}  │  "
              f"{C.DIM}Red: {C.BOLD}{net_range}{C.RESET}  │  "
              f"{C.DIM}Sesión: {len(scan_history)} escaneos{C.RESET}\n")

        print(f"{C.CYAN}ESCANEO{C.RESET}")
        print(f"  {C.BOLD}1.{C.RESET} Escaneo de hosts (ping sweep)")
        print(f"  {C.BOLD}2.{C.RESET} Escaneo de puertos TCP")
        print(f"  {C.BOLD}3.{C.RESET} Escaneo con Nmap")
        print(f"  {C.BOLD}4.{C.RESET} Captura de banners de servicios")

        print(f"\n{C.CYAN}SISTEMA{C.RESET}")
        print(f"  {C.BOLD}5.{C.RESET} Información del sistema")
        print(f"  {C.BOLD}6.{C.RESET} Diagnóstico básico de red")
        print(f"  {C.BOLD}7.{C.RESET} Escaneo de puertos comunes")

        print(f"\n{C.CYAN}AVANZADO{C.RESET}")
        print(f"  {C.BOLD}8.{C.RESET} Detección de sistema operativo")
        print(f"  {C.BOLD}9.{C.RESET} Escaneo de red objetivo")

        print(f"\n{C.CYAN}UTILIDADES{C.RESET}")
        print(f"  {C.BOLD}H.{C.RESET} Historial de escaneos")
        print(f"  {C.BOLD}E.{C.RESET} Exportar último resultado")
        print(f"  {C.BOLD}Q.{C.RESET} Salir")
        choice = input_prompt("Selecciona opción").upper()
        last_result = None

        if choice == "1":
            target = input_prompt(f"Red a escanear [{net_range}]") or net_range
            last_result = ping_sweep(target)

        elif choice == "2":
            target = input_prompt("IP del objetivo")
            if not target:
                continue
            print(f"\n  Modo: [1] Puertos comunes  [2] Rápido (1-1024)  [3] Completo (1-65535)")
            mode_map = {"1": "common", "2": "fast", "3": "full"}
            m = input_prompt("Modo [1/2/3]")
            grab = input_prompt("¿Banner grabbing? [s/N]").lower() == "s"
            last_result = port_scan(target, mode=mode_map.get(m, "common"), grab=grab)

        elif choice == "3":
            target = input_prompt("IP/rango nmap objetivo")
            if not target:
                continue
            print(f"\n  Tipo: [1] Básico  [2] Con OS  [3] Vuln scripts  [4] Completo")
            type_map = {"1": "basic", "2": "os", "3": "vuln", "4": "full"}
            t = input_prompt("Tipo [1/2/3/4]")
            last_result = nmap_scan(target, scan_type=type_map.get(t, "basic"))

        elif choice == "4":
            target = input_prompt("IP objetivo para banner grabbing")
            if not target:
                continue
            last_result = port_scan(target, mode="common", grab=True)

        elif choice == "5":
            local_ip, net_range = get_device_info()

        elif choice == "6":
            basic_network_info()

        elif choice == "7":
            target = input_prompt(f"IP a comprobar [{local_ip}]") or local_ip
            last_result = port_scan(target, mode="common")

        elif choice == "8":
            target = input_prompt("IP objetivo (requiere sudo/root)")
            if target:
                last_result = nmap_scan(target, scan_type="os")

        elif choice == "9":
            scan_external_range()

        elif choice == "H":
            show_history()

        elif choice == "E":
            if last_result:
                fmt = input_prompt("Formato [json/txt]").lower()
                fmt = fmt if fmt in ("json", "txt") else "json"
                export_results(last_result, fmt=fmt)
            else:
                print_warn("No hay resultados recientes para exportar.")

        elif choice == "Q":
            print(f"\n{C.GREEN}  Hasta luego. Recuerda: solo escaneo autorizado.{C.RESET}\n")
            sys.exit(0)

        else:
            print_warn("Opción no válida.")

        input(f"\n{C.DIM}  [Enter para continuar...]{C.RESET}")

# ─────────────────────────────────────────────
# PUNTO DE ENTRADA
# ─────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}  Interrumpido por el usuario. Saliendo...{C.RESET}\n")
        sys.exit(0)
