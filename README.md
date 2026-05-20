# SilenceX v1.0 — Security Scanner Suite

> Unified active security scanner: Nmap + Nikto + ZAP + custom modules
> Built by BennyG | DevSecOps

⚠️ **Authorized scanning only. Always have written permission before scanning any target.**

---

## Features

- 🔍 **Nmap Port Scanner** — Multiple stealth profiles (SYN, Fast, Custom)
- 🕷️ **Nikto Web Scanner** — Web vulnerability detection
- 🔒 **ZAP Web App Scanner** — OWASP spider + active scan
- 🔌 **Custom Port Scanner** — Banner grabbing on common ports
- 🛡️ **SSL/TLS Analysis** — Certificate inspection, cipher suites
- 📋 **Security Headers Audit** — Full HTTP headers security score
- 🌐 **DNS Enumeration** — A, AAAA, MX, NS, TXT records
- 🔎 **Subdomain Enumeration** — Certificate transparency via crt.sh

---

## Requirements

### System Tools
```bash
sudo pacman -S nmap nikto zaproxy   # Arch Linux
sudo apt install nmap nikto zaproxy  # Debian/Ubuntu
```

### Python Dependencies
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

```bash
source venv/bin/activate
sudo venv/bin/python silencex.py
```

> ⚠️ sudo is required for Nmap SYN stealth scans on Linux

---

## Test Targets (Legal)

- `scanme.nmap.org` — Nmap's official test server
- `testphp.vulnweb.com` — Acunetix's vulnerable test site

---

## Export

Reports can be exported as **TXT** or **JSON** from the GUI.

---

## Built With

- Python 3 + CustomTkinter
- Nmap 7.x
- Nikto v2.6
- OWASP ZAP
