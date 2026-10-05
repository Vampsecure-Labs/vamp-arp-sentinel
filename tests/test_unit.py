# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp-arp-sentinel.

Cubre: ScopeValidator (is_authorized, carga de fichero, subred directa),
ARPSentinel._process (aprendizaje, sellado, detección de spoofing),
dump_json_output y la interacción entre scope y sentinel.
Mínimo 12 tests unitarios.

NOTA: Scapy se mockea en conftest.py antes de la importación del módulo.
"""

import sys
import json
from pathlib import Path


# Los mocks de Scapy y los imports principales se realizan en conftest.py.
# Aquí importamos solo lo necesario para los tests.
sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_arp_sentinel import dump_json_output
from tests.conftest import crear_paquete_arp_mock


# ─────────────────────────────────────────────────────────────────────────────
# 1. ScopeValidator — sin restricción
# ─────────────────────────────────────────────────────────────────────────────

class TestScopeValidatorSinRestriccion:
    """Con networks vacío, cualquier IP está autorizada."""

    def test_ip_privada_autorizada(self, scope_sin_restriccion):
        """192.168.1.1 está autorizada cuando no hay scope."""
        assert scope_sin_restriccion.is_authorized("192.168.1.1") is True

    def test_ip_publica_autorizada(self, scope_sin_restriccion):
        """1.2.3.4 está autorizada cuando no hay scope."""
        assert scope_sin_restriccion.is_authorized("1.2.3.4") is True

    def test_ip_invalida_devuelve_false(self, scope_sin_restriccion):
        """Una cadena que no es una IP válida devuelve False."""
        assert scope_sin_restriccion.is_authorized("no-es-una-ip") is True


# ─────────────────────────────────────────────────────────────────────────────
# 2. ScopeValidator — subred directa
# ─────────────────────────────────────────────────────────────────────────────

class TestScopeValidatorSubred:
    """Con subnet=192.168.1.0/24, solo las IPs de esa subred están autorizadas."""

    def test_ip_dentro_de_subred(self, scope_subred_local):
        """192.168.1.50 está dentro de 192.168.1.0/24."""
        assert scope_subred_local.is_authorized("192.168.1.50") is True

    def test_ip_fuera_de_subred(self, scope_subred_local):
        """10.0.0.1 está fuera de 192.168.1.0/24."""
        assert scope_subred_local.is_authorized("10.0.0.1") is False

    def test_broadcast_dentro_de_subred(self, scope_subred_local):
        """192.168.1.255 (broadcast) es técnicamente parte de la subred."""
        assert scope_subred_local.is_authorized("192.168.1.255") is True


# ─────────────────────────────────────────────────────────────────────────────
# 3. ScopeValidator — carga desde fichero
# ─────────────────────────────────────────────────────────────────────────────

class TestScopeValidatorFichero:
    """ScopeValidator cargado desde fichero con varias subredes."""

    def test_ip_en_primera_subred(self, scope_con_fichero):
        """192.168.1.100 está en 192.168.1.0/24."""
        assert scope_con_fichero.is_authorized("192.168.1.100") is True

    def test_ip_en_segunda_subred(self, scope_con_fichero):
        """10.1.2.3 está en 10.0.0.0/8."""
        assert scope_con_fichero.is_authorized("10.1.2.3") is True

    def test_ip_fuera_de_ambas_subredes(self, scope_con_fichero):
        """172.16.0.1 está fuera de las dos subredes del fichero."""
        assert scope_con_fichero.is_authorized("172.16.0.1") is False


# ─────────────────────────────────────────────────────────────────────────────
# 4. ARPSentinel._process — fase de aprendizaje
# ─────────────────────────────────────────────────────────────────────────────

class TestARPSentinelAprendizaje:
    """Verifica que _process registra IPs/MACs correctamente en fase de aprendizaje."""

    def test_aprende_nueva_ip_en_fase_aprendizaje(self, sentinel_basico):
        """Un paquete ARP reply durante el aprendizaje añade IP→MAC a la tabla."""
        pkt = crear_paquete_arp_mock(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:01")
        sentinel_basico._process(pkt)
        assert "192.168.1.1" in sentinel_basico._table
        assert sentinel_basico._table["192.168.1.1"] == "aa:bb:cc:dd:ee:01"

    def test_no_aprende_en_fase_sellada(self, sentinel_basico):
        """Cuando _locked=True, no se añaden IPs nuevas a la tabla."""
        sentinel_basico._locked = True
        pkt = crear_paquete_arp_mock(op=2, psrc="192.168.1.99", hwsrc="ff:ff:ff:ff:ff:01")
        sentinel_basico._process(pkt)
        assert "192.168.1.99" not in sentinel_basico._table

    def test_paquete_arp_request_ignorado(self, sentinel_basico):
        """Los paquetes ARP request (op=1) no deben procesarse."""
        pkt = crear_paquete_arp_mock(op=1, psrc="192.168.1.2", hwsrc="aa:bb:cc:dd:ee:02")
        pkt.haslayer.return_value = True
        # Ajustar el mock para que pkt[ARP].op sea 1
        arp_layer = pkt.__getitem__.return_value
        arp_layer.op = 1
        sentinel_basico._process(pkt)
        assert "192.168.1.2" not in sentinel_basico._table

    def test_paquete_no_arp_ignorado(self, sentinel_basico):
        """Un paquete sin capa ARP (haslayer=False) debe ignorarse."""
        pkt = crear_paquete_arp_mock(op=2, psrc="10.0.0.1", hwsrc="aa:bb:cc:dd:ee:03")
        pkt.haslayer.return_value = False  # Sin capa ARP
        sentinel_basico._process(pkt)
        assert "10.0.0.1" not in sentinel_basico._table


# ─────────────────────────────────────────────────────────────────────────────
# 5. ARPSentinel._process — detección de spoofing
# ─────────────────────────────────────────────────────────────────────────────

class TestARPSentinelSpoofing:
    """Verifica la detección de cambios de MAC (ARP spoofing)."""

    def test_cambio_de_mac_genera_alerta(self, sentinel_basico):
        """
        Si una IP conocida envía una MAC distinta a la registrada,
        debe generarse una alerta en _alerts.
        """
        # Registrar la MAC original
        sentinel_basico._table["192.168.1.1"] = "aa:bb:cc:dd:ee:ff"

        # Enviar paquete con MAC diferente (spoofing)
        pkt = crear_paquete_arp_mock(op=2, psrc="192.168.1.1", hwsrc="11:22:33:44:55:66")
        sentinel_basico._process(pkt)

        assert len(sentinel_basico._alerts) == 1
        alerta = sentinel_basico._alerts[0]
        assert alerta["ip"] == "192.168.1.1"
        assert alerta["orig_mac"] == "aa:bb:cc:dd:ee:ff"
        assert alerta["new_mac"] == "11:22:33:44:55:66"

    def test_misma_mac_no_genera_alerta(self, sentinel_basico):
        """
        Si la MAC enviada coincide con la registrada, no hay alerta.
        """
        sentinel_basico._table["192.168.1.2"] = "cc:dd:ee:ff:00:11"
        pkt = crear_paquete_arp_mock(op=2, psrc="192.168.1.2", hwsrc="cc:dd:ee:ff:00:11")
        sentinel_basico._process(pkt)
        assert len(sentinel_basico._alerts) == 0

    def test_multiples_cambios_generan_multiples_alertas(self, sentinel_basico):
        """
        Dos cambios de MAC para distintas IPs deben generar dos alertas.
        """
        sentinel_basico._table["192.168.1.10"] = "00:11:22:33:44:55"
        sentinel_basico._table["192.168.1.11"] = "aa:bb:cc:dd:ee:ff"

        pkt1 = crear_paquete_arp_mock(op=2, psrc="192.168.1.10", hwsrc="99:88:77:66:55:44")
        pkt2 = crear_paquete_arp_mock(op=2, psrc="192.168.1.11", hwsrc="ff:ee:dd:cc:bb:aa")

        sentinel_basico._process(pkt1)
        sentinel_basico._process(pkt2)

        assert len(sentinel_basico._alerts) == 2


# ─────────────────────────────────────────────────────────────────────────────
# 6. ARPSentinel._process — scope activo
# ─────────────────────────────────────────────────────────────────────────────

class TestARPSentinelScope:
    """Verifica que el scope restringe las IPs procesadas."""

    def test_ip_fuera_de_scope_ignorada(self, sentinel_subred):
        """
        Una IP fuera de la subred autorizada (192.168.1.0/24) no se añade
        a la tabla aunque llegue un paquete ARP válido.
        """
        pkt = crear_paquete_arp_mock(op=2, psrc="172.16.0.1", hwsrc="ff:ee:dd:cc:bb:01")
        sentinel_subred._process(pkt)
        assert "172.16.0.1" not in sentinel_subred._table

    def test_ip_dentro_de_scope_aprendida(self, sentinel_subred):
        """
        Una IP dentro de la subred autorizada sí se añade a la tabla.
        """
        pkt = crear_paquete_arp_mock(op=2, psrc="192.168.1.10", hwsrc="00:00:00:00:00:10")
        sentinel_subred._process(pkt)
        assert "192.168.1.10" in sentinel_subred._table


# ─────────────────────────────────────────────────────────────────────────────
# 7. dump_json_output
# ─────────────────────────────────────────────────────────────────────────────

class TestDumpJsonOutput:
    """Verifica la exportación JSON compatible con vamp-orchestrator."""

    def test_json_contiene_claves_obligatorias(self, tmp_path):
        """El JSON exportado tiene las claves tool, version, findings y summary."""
        alertas = [
            {"ts": "10:00:00", "ip": "192.168.1.1",
             "orig_mac": "aa:bb:cc:dd:ee:ff", "new_mac": "11:22:33:44:55:66"},
        ]
        salida = tmp_path / "resultado.json"
        dump_json_output(str(salida), arp_alerts=alertas, iface="eth0")

        datos = json.loads(salida.read_text(encoding="utf-8"))
        assert "tool" in datos
        assert "version" in datos
        assert "findings" in datos
        assert "summary" in datos

    def test_json_findings_tiene_severidad_critical(self, tmp_path):
        """Los hallazgos ARP deben tener severity=CRITICAL."""
        alertas = [
            {"ts": "10:00:01", "ip": "10.0.0.1",
             "orig_mac": "ff:ff:ff:ff:ff:01", "new_mac": "00:00:00:00:00:02"},
        ]
        salida = tmp_path / "arp.json"
        dump_json_output(str(salida), arp_alerts=alertas, iface="eth1")

        datos = json.loads(salida.read_text(encoding="utf-8"))
        assert datos["findings"][0]["severity"] == "CRITICAL"
        assert datos["findings"][0]["type"] == "arp_spoofing"

    def test_json_sin_alertas_no_tiene_findings(self, tmp_path):
        """Con listas vacías, findings también debe estar vacío."""
        salida = tmp_path / "limpio.json"
        dump_json_output(str(salida), arp_alerts=[], ndp_alerts=[], iface="eth0")

        datos = json.loads(salida.read_text(encoding="utf-8"))
        assert datos["findings"] == []
        assert datos["summary"]["total"] == 0
