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
</p>

---

## Overview

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
git clone https://github.com/belky-me/vamp-arp-sentinel.git
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

## Part of VampSecure Labs Toolkit

This tool is part of the **VampSecure Labs Security Toolkit** — a collection of research-grade security tools for authorized penetration testing and red/blue team exercises.

- Full toolkit: [github.com/belky-me](https://github.com/belky-me)
- Orchestrator: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division  
For authorized security testing only.
