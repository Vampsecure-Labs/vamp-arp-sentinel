# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp-arp-sentinel.

Pruebas de extremo a extremo sobre ARPSentinel con inyección de paquetes
mock: se inyectan secuencias de paquetes ARP y se verifican el estado final
de la tabla, las alertas generadas y la exportación JSON.
Mínimo 5 tests de integración.

NOTA: Scapy se mockea en conftest.py. Los paquetes se inyectan directamente
llamando a sentinel._process() con mocks.
"""

import sys
import json
from pathlib import Path


# Los mocks de Scapy y los imports principales están en conftest.py.
sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_arp_sentinel import ARPSentinel, ScopeValidator, dump_json_output
from tests.conftest import crear_paquete_arp_mock


# ─────────────────────────────────────────────────────────────────────────────
# 1. Integración: fase de aprendizaje y sellado
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_aprendizaje_y_sellado(scope_sin_restriccion):
    """
    Inyectar 5 IPs distintas → tabla aprende las 5.
    Sellar → inyectar una IP nueva → no debe añadirse.
    """
    sentinel = ARPSentinel(iface="eth_test", learn_time=5,
                           scope=scope_sin_restriccion)

    # Fase aprendizaje: 5 IPs distintas
    for i in range(1, 6):
        pkt = crear_paquete_arp_mock(
            op=2,
            psrc=f"192.168.1.{i}",
            hwsrc=f"aa:bb:cc:dd:ee:{i:02x}",
        )
        sentinel._process(pkt)

    assert len(sentinel._table) == 5, (
        f"Se esperaban 5 entradas en la tabla, hay {len(sentinel._table)}"
    )

    # Sellar la tabla
    sentinel._locked = True

    # Inyectar una IP nueva → no debe ser aprendida
    pkt_nueva = crear_paquete_arp_mock(op=2, psrc="192.168.1.99",
                                        hwsrc="ff:ff:ff:ff:ff:99")
    sentinel._process(pkt_nueva)
    assert "192.168.1.99" not in sentinel._table, (
        "Una IP nueva no debe añadirse a la tabla cuando está sellada"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Integración: detección de ARP spoofing sobre tabla aprendida
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_deteccion_spoofing_completa(scope_sin_restriccion):
    """
    Aprender 3 IPs, sellar y luego inyectar spoofing para 2 de ellas.
    Deben generarse 2 alertas con los campos correctos.
    """
    sentinel = ARPSentinel(iface="eth_test", learn_time=5,
                           scope=scope_sin_restriccion)

    macs_legitimas = {
        "10.0.0.1": "aa:bb:cc:dd:ee:01",
        "10.0.0.2": "aa:bb:cc:dd:ee:02",
        "10.0.0.3": "aa:bb:cc:dd:ee:03",
    }
    for ip, mac in macs_legitimas.items():
        pkt = crear_paquete_arp_mock(op=2, psrc=ip, hwsrc=mac)
        sentinel._process(pkt)

    sentinel._locked = True

    # Spoofing sobre dos IPs
    sentinel._process(
        crear_paquete_arp_mock(op=2, psrc="10.0.0.1", hwsrc="11:11:11:11:11:11")
    )
    sentinel._process(
        crear_paquete_arp_mock(op=2, psrc="10.0.0.2", hwsrc="22:22:22:22:22:22")
    )

    assert len(sentinel._alerts) == 2

    ips_alertadas = {a["ip"] for a in sentinel._alerts}
    assert "10.0.0.1" in ips_alertadas
    assert "10.0.0.2" in ips_alertadas

    # Verificar estructura de la alerta
    for alerta in sentinel._alerts:
        assert "ts" in alerta
        assert "ip" in alerta
        assert "orig_mac" in alerta
        assert "new_mac" in alerta


# ─────────────────────────────────────────────────────────────────────────────
# 3. Integración: scope restringe IPs fuera de la subred
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_scope_filtra_ips_externas():
    """
    Con scope 192.168.1.0/24, paquetes de 10.x.x.x y 172.x.x.x
    no deben modificar la tabla ni generar alertas.
    """
    scope = ScopeValidator(subnet="192.168.1.0/24")
    sentinel = ARPSentinel(iface="eth_test", learn_time=5, scope=scope)

    ips_externas = ["10.0.0.5", "172.16.0.10", "8.8.8.8", "1.1.1.1"]
    for ip in ips_externas:
        pkt = crear_paquete_arp_mock(op=2, psrc=ip, hwsrc="de:ad:be:ef:00:01")
        sentinel._process(pkt)

    assert len(sentinel._table) == 0, (
        "No debe haber entradas de IPs fuera del scope"
    )
    assert len(sentinel._alerts) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 4. Integración: dump_json_output con alertas reales de sentinel
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_json_export_de_alertas_reales(tmp_path, scope_sin_restriccion):
    """
    Simular spoofing completo y exportar a JSON.
    Verificar que el fichero tiene las alertas con los datos correctos.
    """
    sentinel = ARPSentinel(iface="eth_test", learn_time=5,
                           scope=scope_sin_restriccion)

    # Aprender 1 IP
    sentinel._process(
        crear_paquete_arp_mock(op=2, psrc="192.168.0.1", hwsrc="ab:cd:ef:00:00:01")
    )
    # Sellar y hacer spoofing
    sentinel._locked = True
    sentinel._process(
        crear_paquete_arp_mock(op=2, psrc="192.168.0.1", hwsrc="ff:ff:ff:ff:ff:01")
    )

    salida = tmp_path / "exportado.json"
    dump_json_output(
        str(salida),
        arp_alerts=sentinel._alerts,
        iface="eth_test",
    )

    datos = json.loads(salida.read_text(encoding="utf-8"))
    assert datos["summary"]["total"] == 1
    assert datos["summary"]["arp_spoofing"] == 1
    hallazgo = datos["findings"][0]
    assert hallazgo["ip"] == "192.168.0.1"
    assert hallazgo["orig_mac"] == "ab:cd:ef:00:00:01"
    assert hallazgo["new_mac"] == "ff:ff:ff:ff:ff:01"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Integración: múltiples spoofings de la misma IP
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_multiples_spoofings_misma_ip(scope_sin_restriccion):
    """
    Un atacante que cambia de MAC varias veces para la misma IP debe
    generar múltiples alertas (una por cada cambio de MAC).
    """
    sentinel = ARPSentinel(iface="eth_test", learn_time=5,
                           scope=scope_sin_restriccion)

    # Aprender la IP legítima
    sentinel._process(
        crear_paquete_arp_mock(op=2, psrc="10.10.10.1", hwsrc="00:00:00:00:00:01")
    )
    sentinel._locked = True

    # El mismo atacante usa 3 MACs diferentes
    for i in range(2, 5):
        mac_falsa = f"ff:ff:ff:ff:ff:{i:02x}"
        sentinel._process(
            crear_paquete_arp_mock(op=2, psrc="10.10.10.1", hwsrc=mac_falsa)
        )

    # Tres cambios de MAC → tres alertas (o al menos ≥ 1 por cada ciclo)
    # La implementación añade una alerta por cada paquete con MAC diferente a la REGISTRADA
    assert len(sentinel._alerts) >= 3, (
        f"Se esperaban al menos 3 alertas, hay {len(sentinel._alerts)}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 6. Integración: ScopeValidator con fichero múltiples subredes
# ─────────────────────────────────────────────────────────────────────────────

def test_integracion_scope_fichero_multiples_subredes(tmp_path):
    """
    ARPSentinel con scope cargado desde fichero que contiene dos subredes.
    IPs de ambas subredes se aprenden; IPs externas no.
    """
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(
        "# subredes autorizadas\n"
        "192.168.10.0/24\n"
        "172.20.0.0/16\n",
        encoding="utf-8",
    )
    scope = ScopeValidator(scope_file=str(scope_file))
    sentinel = ARPSentinel(iface="eth_test", learn_time=5, scope=scope)

    # IPs autorizadas (de ambas subredes)
    sentinel._process(
        crear_paquete_arp_mock(op=2, psrc="192.168.10.5", hwsrc="11:11:11:11:11:01")
    )
    sentinel._process(
        crear_paquete_arp_mock(op=2, psrc="172.20.1.1", hwsrc="22:22:22:22:22:01")
    )
    # IP no autorizada
    sentinel._process(
        crear_paquete_arp_mock(op=2, psrc="10.0.0.1", hwsrc="33:33:33:33:33:01")
    )

    assert "192.168.10.5" in sentinel._table
    assert "172.20.1.1" in sentinel._table
    assert "10.0.0.1" not in sentinel._table
