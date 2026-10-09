<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<h1 align="center">vamp-arp-sentinel</h1>
<p align="center">
  <strong>Passive ARP spoofing detector with proof-of-concept ARP cache poisoning lab mode</strong><br>
  <em>VampSecure Labs · Security Research Division</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey?style=flat-square">
  <img src="https://img.shields.io/badge/license-research%20only-red?style=flat-square">
  <img src="https://img.shields.io/badge/VampSecure-Labs-8B0000?style=flat-square">
  <img src="https://github.com/Vampsecure-Labs/vamp-arp-sentinel/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

`vamp-arp-sentinel` is a network security tool combining passive ARP spoofing detection with a controlled proof-of-concept attacker mode for lab environments. In `sentinel` mode, it captures ARP traffic via Scapy with a BPF `arp` filter, builds a trusted IP→MAC table during a configurable learning phase, then seals the table and generates CRITICAL alerts whenever a known IP maps to a different MAC address — the definitive signature of ARP cache poisoning and Man-in-the-Middle attacks. In `attacker` mode, it sends forged ARP reply packets to validate that detection controls are correctly catching the attack in an authorized lab network.

Scope enforcement via CIDR subnet filtering ensures the tool operates only within explicitly authorized network ranges.

## Features

- **Two-phase sentinel detection**: learning phase builds the canonical IP→MAC table; sealed phase raises CRITICAL alerts on any MAC change for a known IP
- **Real-time Rich terminal display** — live-updating split layout with the IP/MAC table (top) and alert panel (bottom), refreshed at 2 Hz
- **Scope enforcement** — limit monitoring to authorized subnets via `--subnet CIDR` or a `scope.txt` file with one CIDR per line; IPs outside scope are silently ignored
- **Configurable learning window** — `--learn-time` sets how long the sentinel observes before sealing the table (default: 10 seconds)
- **Proof-of-concept attacker** — sends ARP `is-at` broadcast replies claiming a target IP belongs to the tool's MAC; useful for validating that DAI / DHCP Snooping rules trigger correctly
- **Configurable attack interval** for the PoC mode via `--interval`
- **Packet capture via Scapy** with BPF filter `arp` — only ARP reply packets (op=2) are processed, minimizing CPU overhead
- **Unified VSL client report** (HTML/PDF) from `sentinel` sessions via `--report-html` / `--report-pdf`
- Requires root privileges (raw packet capture)

## Requirements

```
pip install -r requirements.txt
```

| Package | Version |
|---------|---------|
| `scapy` | >= 2.5.0 |
| `rich`  | >= 13.7.0 |

Standard library: `argparse`, `ipaddress`, `os`, `sys`, `threading`, `time`, `datetime`.

## Installation

```bash
pip install vamp-arp-sentinel
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-arp-sentinel
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-arp-sentinel.git
cd vamp-arp-sentinel
pip install -r requirements.txt
```

Requires root or `CAP_NET_RAW` capability for raw packet capture.

## Usage

```bash
python vamp_arp_sentinel.py --help
```

Two subcommands are available: `sentinel` and `attacker`.

```
usage: vamp-arp-sentinel {sentinel,attacker} ...

subcommands:
  sentinel   Detect ARP spoofing on the network (passive + alert)
  attacker   Send forged ARP replies for lab validation (PoC only)
```

### Examples

**Monitor interface `eth0` with a 15-second learning phase:**
```bash
sudo python vamp_arp_sentinel.py sentinel -i eth0 --learn-time 15
```

**Restrict monitoring to an authorized subnet only:**
```bash
sudo python vamp_arp_sentinel.py sentinel -i eth0 --subnet 192.168.10.0/24
```

**Load authorized subnets from a scope file:**
```bash
sudo python vamp_arp_sentinel.py sentinel -i eth0 --scope scope.txt
```

**Run sentinel and generate an HTML client report at session end:**
```bash
sudo python vamp_arp_sentinel.py sentinel -i eth0 --learn-time 30 \
    --subnet 10.0.0.0/24 --report-html arp_report.html
```

**PoC: send forged ARP replies in a lab environment (authorized only):**
```bash
sudo python vamp_arp_sentinel.py attacker 192.168.1.100 192.168.1.1 -i eth0
```

**PoC: faster attack rate (1-second interval between packets):**
```bash
sudo python vamp_arp_sentinel.py attacker 192.168.1.100 192.168.1.1 -i eth0 --interval 1
```

## Sentinel Alert Structure

Each alert captures:

| Field | Description |
|-------|-------------|
| Timestamp | HH:MM:SS of detection |
| IP | IPv4 address whose MAC changed |
| Original MAC | MAC address registered during learning phase |
| New MAC | Spoofed MAC address detected after table sealing |

## Output

Sentinel mode: live dual-panel terminal display. At session end (Ctrl+C), a summary panel shows total entries learned and total alerts raised.

Attacker mode: live table of sent packets with sequence number, payload (`FAKE_IP is-at OUR_MAC`), and timestamp.

## Sample Output

```
$ sudo python vamp_arp_sentinel.py sentinel -i eth0 --learn-time 15 --subnet 192.168.10.0/24

  vamp-arp-sentinel v2.2 — ARP Spoofing Detector
  VampSecure Labs Security Research Division

  Interface: eth0   Subnet: 192.168.10.0/24
  Learning phase: 15 seconds — building trusted IP→MAC table ...

  ┌── ARP Table (learned) ──────────────────────────────────────┐
  │  192.168.10.1    →  aa:bb:cc:11:22:33  (gateway)           │
  │  192.168.10.10   →  de:ad:be:ef:00:01  (workstation-01)    │
  │  192.168.10.20   →  de:ad:be:ef:00:02  (workstation-02)    │
  │  192.168.10.50   →  ca:fe:ba:be:00:0a  (printer-01)        │
  └──────────────────────────────────────────────────────────────┘

  Table sealed — 4 entries. Monitoring for ARP spoofing...

  [10:42:17] ✓ ARP reply 192.168.10.10 → de:ad:be:ef:00:01  (known, OK)
  [10:42:31] ✓ ARP reply 192.168.10.20 → de:ad:be:ef:00:02  (known, OK)

  ┌── ALERT ─────────────────────────────────────────────────────┐
  │  CRITICAL — ARP SPOOFING DETECTED                           │
  │  Time:         10:42:44                                      │
  │  IP:           192.168.10.1                                  │
  │  Original MAC: aa:bb:cc:11:22:33                             │
  │  Spoofed MAC:  ff:ee:dd:cc:bb:aa  ← ATTACKER               │
  │  Technique:    MITRE ATT&CK T1557.002 (ARP Cache Poisoning) │
  └──────────────────────────────────────────────────────────────┘

  ^C  Session terminated.

  ╭────────────────── Session Summary ──────────────────╮
  │  Duration: 4m 12s   Entries learned: 4             │
  │  Packets observed: 847   Alerts raised: 1          │
  │  CRITICAL: 1 (ARP spoofing detected)               │
  ╰─────────────────────────────────────────────────────╯
```

## Why vamp-arp-sentinel vs arpwatch · XArp · Snort ARP rules

| Feature | vamp-arp-sentinel | arpwatch | XArp | Snort ARP rules |
|---------|-------------------|---------|------|-----------------|
| Cross-platform (Linux + macOS) | ✅ | ⚠️ Linux only | ⚠️ Windows GUI | ⚠️ Linux only |
| Real-time Rich TUI (split panel) | ✅ | ❌ (email/log only) | ✅ (GUI only) | ❌ (log only) |
| Built-in PoC attacker for lab validation | ✅ | ❌ | ❌ | ❌ |
| CIDR scope enforcement | ✅ | ❌ | ✅ | ⚠️ |
| MITRE ATT&CK mapping per alert | ✅ | ❌ | ❌ | ❌ |
| VSL client report (HTML/PDF) | ✅ | ❌ | ❌ | ❌ |
| No external rule engine required | ✅ | ✅ | ✅ | ❌ (Snort daemon) |
| Configurable learning window | ✅ | ⚠️ static | ✅ | ❌ |
| Headless / CI-friendly | ✅ | ✅ | ❌ | ✅ |
| License | research only | GPL-2.0 | commercial | GPL-2.0 |

**Key differentiators:**

- **Attacker + defender in one tool**: the `attacker` subcommand sends forged ARP replies to validate that DAI/DHCP Snooping rules (or the sentinel itself) are catching the attack — no separate PoC script or Scapy one-liner needed.
- **Two-phase sealed table**: the configurable learning window builds a stable IP→MAC baseline before raising alerts, eliminating false positives from DHCP lease renewals during the monitoring startup.
- **Scope file support**: a `scope.txt` with one CIDR per line restricts monitoring to authorized subnets, satisfying rules-of-engagement requirements in multi-tenant and shared network environments.
- **CLI-first design**: headless operation with HTML/PDF report output at session end makes it suitable for scheduled blue-team health checks and post-engagement deliverables.

## Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| ARP-001 | MAC address change for a known IP after table sealing (ARP cache poisoning) | MITRE ATT&CK T1557.002 | CRITICAL |
| ARP-002 | Gateway IP claimed by a non-gateway MAC address | MITRE ATT&CK T1557.002 / CIS Control 13.8 | CRITICAL |
| ARP-003 | Broadcast ARP reply claiming an IP not seen during learning phase | MITRE ATT&CK T1557.002 | HIGH |
| ARP-004 | Multiple conflicting MAC addresses for the same IP within a short window | MITRE ATT&CK T1557.002 | CRITICAL |
| ARP-005 | ARP reply received from a source outside the authorized scope subnet | MITRE ATT&CK T1557 / CIS Control 13.3 | HIGH |
| ARP-006 | Gratuitous ARP flood — high reply rate from a single sender MAC | MITRE ATT&CK T1557.002 / CIS Control 13.8 | HIGH |
| ARP-007 | ARP reply with null sender MAC (`00:00:00:00:00:00`) | MITRE ATT&CK T1557 | MEDIUM |
| ARP-008 | IP-to-MAC mapping conflict between two simultaneously active hosts | CIS Control 13.4 | MEDIUM |
| ARP-PoC-001 | Forged ARP `is-at` reply sent by the built-in PoC attacker mode (lab validation) | MITRE ATT&CK T1557.002 (controlled) | INFO |

## Version History

| Version | Main changes |
|---------|-------------|
| v2.2 | Bilingual README (EN/ES) |
| v2.1 | Initial public release: passive ARP spoofing detection, two-phase learning, PoC attacker mode, CIDR scope enforcement, VSL HTML/PDF reports |

## Part of VampSecure Labs Toolkit

This tool is part of the **VampSecure Labs Security Toolkit** — a collection of research-grade security tools for authorized penetration testing and red/blue team exercises.

- Full toolkit: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)
- Orchestrator: [github.com/Vampsecure-Labs/vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division  
For authorized security testing only.

---

<a name="español"></a>
## 🇪🇸 Español

`vamp-arp-sentinel` es una herramienta de seguridad de red que combina detección pasiva de ARP spoofing con un modo atacante de prueba de concepto controlado para entornos de laboratorio. En modo `sentinel`, captura tráfico ARP vía Scapy con un filtro BPF `arp`, construye una tabla IP→MAC de confianza durante una fase de aprendizaje configurable, sella la tabla y genera alertas CRITICAL cada vez que una IP conocida mapea a una dirección MAC diferente — la firma definitiva del envenenamiento de caché ARP y los ataques Man-in-the-Middle. En modo `attacker`, envía paquetes ARP reply falsificados para validar que los controles de detección están capturando correctamente el ataque en una red de laboratorio autorizada.

La imposición de alcance mediante filtrado de subredes CIDR garantiza que la herramienta opere únicamente dentro de rangos de red explícitamente autorizados.

## Características

- **Detección sentinel en dos fases**: la fase de aprendizaje construye la tabla canónica IP→MAC; la fase sellada genera alertas CRITICAL ante cualquier cambio de MAC para una IP conocida
- **Pantalla Rich en tiempo real** — diseño de panel dividido actualizado en vivo con la tabla IP/MAC (arriba) y el panel de alertas (abajo), refrescado a 2 Hz
- **Imposición de alcance** — limita la monitorización a subredes autorizadas mediante `--subnet CIDR` o un fichero `scope.txt` con un CIDR por línea; las IPs fuera del alcance se ignoran silenciosamente
- **Ventana de aprendizaje configurable** — `--learn-time` establece cuánto tiempo observa el centinela antes de sellar la tabla (por defecto: 10 segundos)
- **Atacante de prueba de concepto** — envía respuestas ARP `is-at` en broadcast reclamando que una IP objetivo pertenece a la MAC de la herramienta; útil para validar que las reglas DAI / DHCP Snooping se activan correctamente
- **Intervalo de ataque configurable** para el modo PoC mediante `--interval`
- **Captura de paquetes vía Scapy** con filtro BPF `arp` — solo se procesan paquetes ARP reply (op=2), minimizando el uso de CPU
- **Informe unificado VSL para el cliente** (HTML/PDF) de sesiones `sentinel` mediante `--report-html` / `--report-pdf`
- Requiere privilegios root (captura de paquetes en modo raw)

## Requisitos

```
pip install -r requirements.txt
```

| Paquete | Versión |
|---------|---------|
| `scapy` | >= 2.5.0 |
| `rich`  | >= 13.7.0 |

Biblioteca estándar: `argparse`, `ipaddress`, `os`, `sys`, `threading`, `time`, `datetime`.

## Instalación

```bash
pip install vamp-arp-sentinel
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-arp-sentinel
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-arp-sentinel.git
cd vamp-arp-sentinel
pip install -r requirements.txt
```

Requiere root o capacidad `CAP_NET_RAW` para la captura de paquetes en modo raw.

## Uso

```bash
python vamp_arp_sentinel.py --help
```

Hay dos subcomandos disponibles: `sentinel` y `attacker`.

```
usage: vamp-arp-sentinel {sentinel,attacker} ...

subcomandos:
  sentinel   Detectar ARP spoofing en la red (pasivo + alertas)
  attacker   Enviar respuestas ARP falsificadas para validación en laboratorio (solo PoC)
```

### Ejemplos

**Monitorizar la interfaz `eth0` con una fase de aprendizaje de 15 segundos:**
```bash
sudo python vamp_arp_sentinel.py sentinel -i eth0 --learn-time 15
```

**Restringir la monitorización a una subred autorizada:**
```bash
sudo python vamp_arp_sentinel.py sentinel -i eth0 --subnet 192.168.10.0/24
```

**Cargar subredes autorizadas desde un fichero de alcance:**
```bash
sudo python vamp_arp_sentinel.py sentinel -i eth0 --scope scope.txt
```

**Ejecutar el centinela y generar un informe HTML para el cliente al finalizar la sesión:**
```bash
sudo python vamp_arp_sentinel.py sentinel -i eth0 --learn-time 30 \
    --subnet 10.0.0.0/24 --report-html informe_arp.html
```

**PoC: enviar respuestas ARP falsificadas en un entorno de laboratorio (solo autorizado):**
```bash
sudo python vamp_arp_sentinel.py attacker 192.168.1.100 192.168.1.1 -i eth0
```

**PoC: velocidad de ataque mayor (intervalo de 1 segundo entre paquetes):**
```bash
sudo python vamp_arp_sentinel.py attacker 192.168.1.100 192.168.1.1 -i eth0 --interval 1
```

## Estructura de alertas del centinela

Cada alerta registra:

| Campo | Descripción |
|-------|-------------|
| Timestamp | HH:MM:SS de la detección |
| IP | Dirección IPv4 cuya MAC ha cambiado |
| MAC original | Dirección MAC registrada durante la fase de aprendizaje |
| MAC nueva | Dirección MAC falsificada detectada tras el sellado de la tabla |

## Salida

Modo sentinel: pantalla de terminal de panel dual en vivo. Al finalizar la sesión (Ctrl+C), un panel de resumen muestra el total de entradas aprendidas y el total de alertas generadas.

Modo attacker: tabla en vivo de paquetes enviados con número de secuencia, payload (`FAKE_IP is-at OUR_MAC`) y timestamp.

## Ejemplo de salida

```
$ sudo python vamp_arp_sentinel.py sentinel -i eth0 --learn-time 15 --subnet 192.168.10.0/24

  vamp-arp-sentinel v2.2 — Detector de ARP Spoofing
  VampSecure Labs Security Research Division

  Interfaz: eth0   Subred: 192.168.10.0/24
  Fase de aprendizaje: 15 segundos — construyendo tabla IP→MAC de confianza ...

  ┌── Tabla ARP (aprendida) ────────────────────────────────────┐
  │  192.168.10.1    →  aa:bb:cc:11:22:33  (gateway)           │
  │  192.168.10.10   →  de:ad:be:ef:00:01  (workstation-01)    │
  │  192.168.10.20   →  de:ad:be:ef:00:02  (workstation-02)    │
  │  192.168.10.50   →  ca:fe:ba:be:00:0a  (impresora-01)      │
  └──────────────────────────────────────────────────────────────┘

  Tabla sellada — 4 entradas. Monitorizando ARP spoofing...

  [10:42:17] ✓ ARP reply 192.168.10.10 → de:ad:be:ef:00:01  (conocido, OK)
  [10:42:31] ✓ ARP reply 192.168.10.20 → de:ad:be:ef:00:02  (conocido, OK)

  ┌── ALERTA ────────────────────────────────────────────────────┐
  │  CRITICAL — ARP SPOOFING DETECTADO                          │
  │  Hora:          10:42:44                                     │
  │  IP:            192.168.10.1                                 │
  │  MAC original:  aa:bb:cc:11:22:33                            │
  │  MAC falsificada: ff:ee:dd:cc:bb:aa  ← ATACANTE             │
  │  Técnica:       MITRE ATT&CK T1557.002 (ARP Cache Poisoning)│
  └──────────────────────────────────────────────────────────────┘

  ^C  Sesión terminada.

  ╭────────────────── Resumen de Sesión ────────────────╮
  │  Duración: 4m 12s   Entradas aprendidas: 4         │
  │  Paquetes observados: 847   Alertas generadas: 1   │
  │  CRITICAL: 1 (ARP spoofing detectado)              │
  ╰─────────────────────────────────────────────────────╯
```

## Por qué vamp-arp-sentinel vs arpwatch · XArp · Reglas ARP de Snort

| Característica | vamp-arp-sentinel | arpwatch | XArp | Reglas ARP Snort |
|----------------|-------------------|---------|------|------------------|
| Multiplataforma (Linux + macOS) | ✅ | ⚠️ solo Linux | ⚠️ GUI Windows | ⚠️ solo Linux |
| TUI Rich en tiempo real (panel dividido) | ✅ | ❌ (solo email/log) | ✅ (solo GUI) | ❌ (solo log) |
| Atacante PoC integrado para validación en laboratorio | ✅ | ❌ | ❌ | ❌ |
| Imposición de alcance CIDR | ✅ | ❌ | ✅ | ⚠️ |
| Mapeo MITRE ATT&CK por alerta | ✅ | ❌ | ❌ | ❌ |
| Informe VSL para el cliente (HTML/PDF) | ✅ | ❌ | ❌ | ❌ |
| Sin motor de reglas externo | ✅ | ✅ | ✅ | ❌ (daemon Snort) |
| Ventana de aprendizaje configurable | ✅ | ⚠️ estático | ✅ | ❌ |
| Headless / compatible con CI | ✅ | ✅ | ❌ | ✅ |
| Licencia | solo investigación | GPL-2.0 | comercial | GPL-2.0 |

**Diferenciadores clave:**

- **Atacante + defensor en una sola herramienta**: el subcomando `attacker` envía respuestas ARP falsificadas para validar que las reglas DAI/DHCP Snooping (o el propio centinela) están capturando el ataque — sin necesidad de script PoC separado ni one-liner de Scapy.
- **Tabla sellada en dos fases**: la ventana de aprendizaje configurable construye una línea base IP→MAC estable antes de generar alertas, eliminando falsos positivos por renovaciones de lease DHCP durante el arranque de la monitorización.
- **Soporte de fichero de alcance**: un `scope.txt` con un CIDR por línea restringe la monitorización a subredes autorizadas, cumpliendo con los requisitos de reglas de compromiso en entornos multi-inquilino y de red compartida.
- **Diseño CLI-first**: la operación headless con salida de informe HTML/PDF al finalizar la sesión lo hace adecuado para comprobaciones programadas de salud del equipo azul y entregables post-compromiso.

## Cobertura de checks

| Check ID | Descripción | Estándar | Severidad |
|----------|-------------|----------|-----------|
| ARP-001 | Cambio de dirección MAC para una IP conocida tras el sellado de la tabla (envenenamiento de caché ARP) | MITRE ATT&CK T1557.002 | CRITICAL |
| ARP-002 | IP de gateway reclamada por una MAC que no es la del gateway | MITRE ATT&CK T1557.002 / CIS Control 13.8 | CRITICAL |
| ARP-003 | Respuesta ARP broadcast reclamando una IP no vista durante la fase de aprendizaje | MITRE ATT&CK T1557.002 | HIGH |
| ARP-004 | Múltiples direcciones MAC en conflicto para la misma IP en una ventana corta | MITRE ATT&CK T1557.002 | CRITICAL |
| ARP-005 | Respuesta ARP recibida desde una fuente fuera de la subred de alcance autorizada | MITRE ATT&CK T1557 / CIS Control 13.3 | HIGH |
| ARP-006 | Flood de ARP gratuito — alta tasa de respuestas desde una sola MAC emisora | MITRE ATT&CK T1557.002 / CIS Control 13.8 | HIGH |
| ARP-007 | Respuesta ARP con MAC emisora nula (`00:00:00:00:00:00`) | MITRE ATT&CK T1557 | MEDIUM |
| ARP-008 | Conflicto de mapeo IP-a-MAC entre dos hosts simultáneamente activos | CIS Control 13.4 | MEDIUM |
| ARP-PoC-001 | Respuesta ARP `is-at` falsificada enviada por el modo atacante PoC integrado (validación de laboratorio) | MITRE ATT&CK T1557.002 (controlado) | INFO |

## Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v2.2 | README bilingüe (EN/ES) |
| v2.1 | Primera versión pública: detección pasiva de ARP spoofing, aprendizaje en dos fases, modo atacante PoC, imposición de alcance CIDR, informes HTML/PDF VSL |

## Parte del Toolkit VampSecure Labs

Esta herramienta forma parte del **Toolkit de Seguridad VampSecure Labs** — una colección de herramientas de seguridad de grado investigación para pentesting autorizado y ejercicios de equipo rojo/azul.

- Toolkit completo: [github.com/Vampsecure-Labs](https://github.com/Vampsecure-Labs)
- Orquestador: [github.com/Vampsecure-Labs/vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division  
Solo para pruebas de seguridad autorizadas.
