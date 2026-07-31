# vamp-arp-sentinel

**VampSecure Labs — Security Research Division**  
Detector de ARP spoofing en tiempo real con modo laboratorio de envenenamiento.

---

## Descripción

Herramienta Blue/Red Team para la detección y demostración de ataques ARP spoofing en
redes locales. Combina un monitor pasivo que aprende la tabla IP→MAC legítima con un
módulo de ataque controlado para uso en entornos de laboratorio.

Utiliza Scapy para captura y fabricación de paquetes ARP, con interfaz Rich Live que
actualiza la tabla de estado en tiempo real sin limpiar el terminal.

## Módulos

### Sentinel (modo defensa)
Captura paquetes ARP-Reply durante una fase de aprendizaje configurable y después alerta
cuando detecta cambios en la tabla IP→MAC. Soporte para scope CIDR para limitar la
vigilancia a subredes autorizadas.

### Attacker (modo laboratorio)
Envía ARP-Reply falsificados de forma periódica para demostrar el envenenamiento de caché
ARP en un entorno controlado. **Solo para uso en laboratorios propios.**

## Requisitos

- Python 3.9+
- Permisos de root / `CAP_NET_RAW` (necesario para captura Scapy)
- Dependencias: `scapy>=2.5.0`, `rich>=13.7.0`

## Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

```bash
# Iniciar sentinel en interfaz eth0 (aprendizaje 60s)
sudo python3 vamp_arp_sentinel.py sentinel --iface eth0

# Sentinel con scope restringido a subred específica
sudo python3 vamp_arp_sentinel.py sentinel --iface eth0 --subnet 192.168.1.0/24 --learn-time 30

# Sentinel con fichero de scope (lista de CIDRs)
sudo python3 vamp_arp_sentinel.py sentinel --iface eth0 --scope scope.txt

# Laboratorio de envenenamiento ARP (SOLO entorno de test)
sudo python3 vamp_arp_sentinel.py attacker --target-ip 192.168.1.100 --fake-ip 192.168.1.1 --iface eth0
```

## Opciones sentinel

| Opción | Descripción |
|--------|-------------|
| `--iface` | Interfaz de red a monitorizar |
| `--learn-time` | Segundos en fase de aprendizaje (por defecto: 60) |
| `--subnet` | CIDR de subred autorizada |
| `--scope` | Fichero con lista de CIDRs autorizados |

## Opciones attacker

| Opción | Descripción |
|--------|-------------|
| `--target-ip` | IP víctima a envenenar |
| `--fake-ip` | IP que se suplanta (p.ej. gateway) |
| `--iface` | Interfaz de red |
| `--interval` | Intervalo entre paquetes en segundos (por defecto: 2) |

## Aviso legal

**Uso exclusivo en redes de tu propiedad o con autorización escrita del propietario.**  
El módulo attacker activa envenenamiento de caché ARP real. Su uso en redes sin autorización
puede constituir un delito. VampSecure Studios no se responsabiliza del uso indebido.

---

© VampSecure Studios — VampSecure Labs Security Research Division  
Licencia: MIT
