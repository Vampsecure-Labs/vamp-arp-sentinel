# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidas para los tests de vamp-arp-sentinel.

Proporciona mocks de Scapy, helpers de paquetes ARP y configuraciones
de ScopeValidator para test_unit.py y test_integration.py.

NOTA: Scapy se simula con MagicMock antes de importar el módulo para evitar
la dependencia de privilegios root y la librería real de captura de paquetes.
"""

import sys
from unittest.mock import MagicMock

import pytest

# ── Mock de Scapy (debe ejecutarse ANTES de importar el módulo) ───────────────
# El módulo intenta `from scapy.all import ARP, ...` al cargar.
# Creamos mocks para todos los sub-módulos necesarios.

_mock_scapy = MagicMock()
_mock_scapy_all = MagicMock()
_mock_scapy_layers = MagicMock()
_mock_scapy_layers_inet6 = MagicMock()

# ARP como clase mock accesible
_ARP_cls = MagicMock()
_mock_scapy_all.ARP = _ARP_cls

sys.modules.setdefault("scapy", _mock_scapy)
sys.modules.setdefault("scapy.all", _mock_scapy_all)
sys.modules.setdefault("scapy.layers", _mock_scapy_layers)
sys.modules.setdefault("scapy.layers.inet6", _mock_scapy_layers_inet6)

# Importar el módulo DESPUÉS de instalar los mocks
sys.path.insert(0, str(__file__.rsplit("/tests/", 1)[0]))

from vamp_arp_sentinel import ARPSentinel, ScopeValidator


# ── Helper: crear paquete ARP mock ────────────────────────────────────────────

def crear_paquete_arp_mock(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff"):
    """
    Crea un paquete ARP simulado con MagicMock.

    Parámetros
    ----------
    op    : int   — Operación ARP (1=request, 2=reply)
    psrc  : str   — IP origen
    hwsrc : str   — MAC origen

    Retorna
    -------
    MagicMock que simula el comportamiento de un paquete Scapy.
    """
    pkt = MagicMock()
    pkt.haslayer.return_value = True

    # Simular acceso pkt[ARP].op, pkt[ARP].psrc, pkt[ARP].hwsrc
    arp_layer = MagicMock()
    arp_layer.op = op
    arp_layer.psrc = psrc
    arp_layer.hwsrc = hwsrc
    pkt.__getitem__ = MagicMock(return_value=arp_layer)

    return pkt


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def scope_sin_restriccion():
    """ScopeValidator sin redes definidas → todo está autorizado."""
    return ScopeValidator()


@pytest.fixture
def scope_subred_local():
    """ScopeValidator restringido a 192.168.1.0/24."""
    return ScopeValidator(subnet="192.168.1.0/24")


@pytest.fixture
def scope_con_fichero(tmp_path):
    """ScopeValidator cargado desde un fichero con dos subredes."""
    fichero = tmp_path / "scope.txt"
    fichero.write_text(
        "# Redes autorizadas para el test\n"
        "192.168.1.0/24\n"
        "10.0.0.0/8\n",
        encoding="utf-8",
    )
    return ScopeValidator(scope_file=str(fichero))


@pytest.fixture
def sentinel_basico(scope_sin_restriccion):
    """ARPSentinel mínimo sin Scapy real (iface ficticia)."""
    return ARPSentinel(
        iface="eth0_test",
        learn_time=5,
        scope=scope_sin_restriccion,
    )


@pytest.fixture
def sentinel_subred(scope_subred_local):
    """ARPSentinel restringido a 192.168.1.0/24."""
    return ARPSentinel(
        iface="eth0_test",
        learn_time=5,
        scope=scope_subred_local,
    )
