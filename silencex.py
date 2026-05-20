#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║            SilenceX v1.0 — Security Scanner Suite            ║
║     Unified Scanner: Nmap + Nikto + ZAP + Custom Modules    ║
║                  Built by BennyG | DevSecOps                 ║
╚══════════════════════════════════════════════════════════════╝

Authorized scanning only. Always have written permission.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import threading
import datetime
import shutil
import json
import time
import os
import sys
import re
import socket
import ssl
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

# ─── Optional imports ────────────────────────────────────────────────────────
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


# ══════════════════════════════════════════════════════════════════════════════
#  THEME
# ══════════════════════════════════════════════════════════════════════════════

DARK_BG       = "#08090d"
PANEL_BG      = "#0e1117"
CARD_BG       = "#141820"
INPUT_BG      = "#1a1f2e"
ACCENT        = "#c026d3"  # Purple/magenta brand color
ACCENT_HOVER  = "#a020b0"
ACCENT_DIM    = "#7c1a8e"
CYAN          = "#00d4ff"
GREEN         = "#00ff41"
RED           = "#ff3b3b"
YELLOW        = "#ffd700"
ORANGE        = "#ff8c00"
TEXT          = "#e0e0e0"
TEXT_DIM      = "#5a6577"
BORDER        = "#1e2738"

VERSION = "1.0"


# ══════════════════════════════════════════════════════════════════════════════
#  TOOL DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def which(tool):
    """Check if a tool is installed."""
    return shutil.which(tool) is not None


def run_cmd(cmd, timeout=300):
    """Run a shell command and return output."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout
        )
        return result.stdout + result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "ERROR: Command timed out", 1
    except Exception as e:
        return f"ERROR: {e}", 1


# ══════════════════════════════════════════════════════════════════════════════
#  SCAN PROFILES
# ══════════════════════════════════════════════════════════════════════════════

NMAP_PROFILES = {
    "Fast Stealth (Recommended)": {
        "cmd": "-sS -T4 -Pn --open --top-ports 1000 --reason",
        "desc": "SYN-only + fast timing — stealth from scan type, speed from T4",
        "risk": "Low (SYN only, no full connect)",
    },
    "Stealth (SYN)": {
        "cmd": "-sS -T2 -Pn --open --reason",
        "desc": "SYN scan, slow timing, skip host discovery",
        "risk": "Low",
    },
    "Ghost (Ultra Stealth)": {
        "cmd": "-sS -T1 -Pn --open --randomize-hosts -f --data-length 24",
        "desc": "Fragmented packets, random order, padded data, paranoid timing",
        "risk": "Minimal",
    },
    "Quick Scan": {
        "cmd": "-sS -T4 --top-ports 100 --open",
        "desc": "Top 100 ports, aggressive timing",
        "risk": "Medium",
    },
    "Full TCP": {
        "cmd": "-sT -T3 -p- --open --reason",
        "desc": "Full connect scan, all 65535 ports",
        "risk": "High (noisy)",
    },
    "Service Detection": {
        "cmd": "-sS -sV -T3 --top-ports 1000 --open",
        "desc": "SYN scan + version detection on top 1000 ports",
        "risk": "Medium-High",
    },
    "OS Fingerprint": {
        "cmd": "-sS -O -T3 --top-ports 200 --open",
        "desc": "SYN scan + OS detection",
        "risk": "Medium",
    },
    "Vuln Scan": {
        "cmd": "-sS -sV --script=vuln -T3 --top-ports 500",
        "desc": "SYN + version + NSE vuln scripts",
        "risk": "High (active probing)",
    },
    "UDP Quick": {
        "cmd": "-sU -T4 --top-ports 50 --open",
        "desc": "UDP scan on top 50 ports",
        "risk": "Medium",
    },
    "Custom": {
        "cmd": "",
        "desc": "Enter your own Nmap flags",
        "risk": "Varies",
    },
}

NIKTO_PROFILES = {
    "Standard": {
        "cmd": "",
        "desc": "Default Nikto scan",
    },
    "Quick (No 404 guessing)": {
        "cmd": "-no404",
        "desc": "Skip 404 content guessing",
    },
    "Full + SSL": {
        "cmd": "-ssl -C all",
        "desc": "Force SSL + all CGI dirs",
    },
    "Stealth (Evasion)": {
        "cmd": "-evasion 1",
        "desc": "Random URI encoding evasion",
    },
    "Custom": {
        "cmd": "",
        "desc": "Enter your own Nikto flags",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
#  CUSTOM SCANNER MODULES
# ══════════════════════════════════════════════════════════════════════════════

class CustomScanner:
    """Custom Python-based security checks (no external tools needed)."""

    @staticmethod
    def banner_grab(target, port, callback):
        """Grab service banner from a port."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target, port))
            s.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            banner = s.recv(1024).decode("utf-8", errors="replace")
            s.close()
            return banner.strip()
        except Exception as e:
            return f"No banner: {e}"

    @staticmethod
    def ssl_analysis(domain, callback):
        """Deep SSL/TLS analysis."""
        callback("\n[CUSTOM] SSL/TLS Deep Analysis", "header")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    # Certificate details
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    callback(f"  Subject:     {subject.get('commonName', 'N/A')}", "success")
                    callback(f"  Issuer:      {issuer.get('organizationName', 'N/A')}", "info")
                    callback(f"  Valid From:  {cert.get('notBefore', 'N/A')}", "info")
                    callback(f"  Valid Until: {cert.get('notAfter', 'N/A')}", "info")
                    callback(f"  TLS Version: {ssock.version()}", "info")
                    callback(f"  Cipher:      {ssock.cipher()[0]}", "info")

                    # Check expiry
                    expiry = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.datetime.utcnow()).days
                    if days_left < 0:
                        callback(f"  ⚠ EXPIRED {abs(days_left)} days ago!", "error")
                    elif days_left < 30:
                        callback(f"  ⚠ Expires in {days_left} days!", "warning")
                    else:
                        callback(f"  ✓ Valid for {days_left} more days", "success")

                    # SANs
                    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                    if sans:
                        callback(f"  SANs ({len(sans)}):", "info")
                        for san in sans[:15]:
                            callback(f"    → {san}", "dim")

                    # TLS version check
                    tls_ver = ssock.version()
                    if "TLSv1.3" in tls_ver:
                        callback(f"  ✓ TLS 1.3 — Excellent!", "success")
                    elif "TLSv1.2" in tls_ver:
                        callback(f"  ✓ TLS 1.2 — Good", "success")
                    else:
                        callback(f"  ⚠ {tls_ver} — Outdated! Upgrade recommended", "error")

        except ssl.SSLCertVerificationError as e:
            callback(f"  ⚠ Cert verification failed: {e}", "error")
        except Exception as e:
            callback(f"  SSL analysis failed: {e}", "error")

    @staticmethod
    def security_headers(domain, callback):
        """Check HTTP security headers."""
        callback("\n[CUSTOM] Security Headers Audit", "header")
        try:
            url = f"https://{domain}"
            if HAS_REQUESTS:
                r = requests.get(url, timeout=10, verify=False,
                                 headers={"User-Agent": "SilenceX/1.0"}, allow_redirects=True)
                headers = dict(r.headers)
                status = r.status_code
            else:
                import urllib.request
                req = urllib.request.Request(url, headers={"User-Agent": "SilenceX/1.0"})
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                resp = urllib.request.urlopen(req, timeout=10, context=ctx)
                headers = dict(resp.headers)
                status = resp.status

            callback(f"  HTTP Status: {status}", "info")

            checks = {
                "Strict-Transport-Security": ("HSTS", "critical"),
                "Content-Security-Policy": ("CSP", "critical"),
                "X-Frame-Options": ("Clickjacking Protection", "high"),
                "X-Content-Type-Options": ("MIME Sniffing Protection", "medium"),
                "X-XSS-Protection": ("XSS Filter", "medium"),
                "Referrer-Policy": ("Referrer Policy", "medium"),
                "Permissions-Policy": ("Permissions Policy", "low"),
                "Cross-Origin-Opener-Policy": ("COOP", "low"),
                "Cross-Origin-Resource-Policy": ("CORP", "low"),
                "Cross-Origin-Embedder-Policy": ("COEP", "low"),
            }

            score = 0
            total = len(checks)
            for hdr, (desc, severity) in checks.items():
                val = headers.get(hdr, headers.get(hdr.lower(), ""))
                if val:
                    callback(f"  ✓ {desc}: {val[:80]}", "success")
                    score += 1
                else:
                    sev_color = "error" if severity == "critical" else "warning" if severity == "high" else "dim"
                    callback(f"  ✗ {desc}: MISSING [{severity.upper()}]", sev_color)

            grade = "A+" if score >= 9 else "A" if score >= 8 else "B" if score >= 6 else "C" if score >= 4 else "D" if score >= 2 else "F"
            callback(f"\n  Security Score: {score}/{total} — Grade: {grade}", "header")

            # Cookie analysis
            cookies = headers.get("Set-Cookie", headers.get("set-cookie", ""))
            if cookies:
                callback(f"\n  Cookie Analysis:", "section")
                if "Secure" not in cookies:
                    callback(f"    ⚠ Missing 'Secure' flag", "warning")
                if "HttpOnly" not in cookies:
                    callback(f"    ⚠ Missing 'HttpOnly' flag", "warning")
                if "SameSite" not in cookies:
                    callback(f"    ⚠ Missing 'SameSite' flag", "warning")

            # Server info leak
            server = headers.get("Server", headers.get("server", ""))
            powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
            if server:
                callback(f"\n  ⚠ Server header leaks: {server}", "warning")
            if powered:
                callback(f"  ⚠ X-Powered-By leaks: {powered}", "warning")

            # WAF detection
            waf_sigs = {
                "cloudflare": "Cloudflare", "akamai": "Akamai",
                "sucuri": "Sucuri", "imperva": "Imperva",
                "barracuda": "Barracuda", "f5 big": "F5 BIG-IP",
                "fortiweb": "FortiWeb", "wallarm": "Wallarm",
                "aws": "AWS WAF", "ddos-guard": "DDoS-Guard",
            }
            all_hdrs = json.dumps(headers).lower()
            for sig, name in waf_sigs.items():
                if sig in all_hdrs:
                    callback(f"  🛡 WAF Detected: {name}", "warning")

        except Exception as e:
            callback(f"  Headers check failed: {e}", "error")

    @staticmethod
    def port_scan(target, callback, ports=None):
        """Fast Python port scanner (no Nmap needed)."""
        callback("\n[CUSTOM] Python Port Scanner", "header")
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                     993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080,
                     8443, 8888, 9090, 9200, 27017]
        try:
            ip = socket.gethostbyname(target) if not re.match(r'^\d+\.\d+\.\d+\.\d+$', target) else target
            callback(f"  Target IP: {ip}", "info")
            callback(f"  Scanning {len(ports)} ports...\n", "info")

            open_ports = []
            start = time.time()

            def check_port(port):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.5)
                    result = s.connect_ex((ip, port))
                    s.close()
                    return port if result == 0 else None
                except Exception:
                    return None

            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(check_port, p): p for p in ports}
                for future in futures:
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        # Try banner grab
                        banner = CustomScanner.banner_grab(ip, result, callback)
                        service = {
                            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
                            443: "HTTPS", 445: "SMB", 3306: "MySQL",
                            3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
                            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
                            9200: "Elasticsearch",
                        }.get(result, "Unknown")
                        banner_short = banner[:60].replace('\n', ' ') if banner and "No banner" not in banner else ""
                        callback(f"  ✓ {result:5d}/tcp  {service:<15s}  {banner_short}", "success")

            elapsed = time.time() - start
            callback(f"\n  Found {len(open_ports)} open ports in {elapsed:.1f}s", "info")

        except Exception as e:
            callback(f"  Port scan error: {e}", "error")

    @staticmethod
    def subdomain_enum(domain, callback):
        """Subdomain enumeration via crt.sh."""
        callback("\n[CUSTOM] Subdomain Enumeration (crt.sh)", "header")
        try:
            if not HAS_REQUESTS:
                callback("  requests library not available", "error")
                return

            callback(f"  Querying certificate transparency logs...", "info")
            r = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"User-Agent": "SilenceX/1.0"}, timeout=20
            )
            if r.status_code != 200:
                callback(f"  crt.sh returned status {r.status_code}", "error")
                return

            data = r.json()
            subs = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        subs.add(name)

            subs = sorted(subs)
            callback(f"  Found {len(subs)} unique subdomains:\n", "success")
            for i, sub in enumerate(subs, 1):
                callback(f"    {i:3d}. {sub}", "success")

        except Exception as e:
            callback(f"  Subdomain enum error: {e}", "error")

    @staticmethod
    def dns_enum(domain, callback):
        """DNS enumeration."""
        callback("\n[CUSTOM] DNS Enumeration", "header")
        if not HAS_DNS:
            callback("  dnspython not installed", "error")
            return

        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                callback(f"\n  ─── {rtype} ───", "section")
                for rdata in answers:
                    if rtype == "MX":
                        callback(f"    Priority {rdata.preference} → {rdata.exchange}", "success")
                    elif rtype == "SOA":
                        callback(f"    Primary: {rdata.mname}  Admin: {rdata.rname}", "success")
                    else:
                        callback(f"    {rdata.to_text()}", "success")
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN GUI
# ══════════════════════════════════════════════════════════════════════════════

class SilenceXApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("SilenceX v1.0 — Security Scanner Suite")
        self.geometry("1200x800")
        self.minsize(1000, 650)
        self.configure(fg_color=DARK_BG)

        # Try icon
        try:
            base = sys._MEIPASS if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
            ico = os.path.join(base, "silencex.ico")
            if os.path.exists(ico):
                self.iconbitmap(ico)
        except Exception:
            pass

        self.scan_running = False
        self.results_text = ""
        self.current_process = None
        self.spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.spinner_idx = 0
        self.spinner_after_id = None

        self._detect_tools()
        self._build_ui()

    def _detect_tools(self):
        """Detect installed tools."""
        self.tools = {
            "nmap": which("nmap"),
            "nikto": which("nikto"),
            "zap-cli": which("zap-cli") or which("zaproxy") or which("zap.sh"),
        }

    # ─── UI BUILDING ─────────────────────────────────────────────────
    def _build_ui(self):
        self._build_header()
        self._build_main_area()
        self._build_statusbar()

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=0, height=65)
        header.pack(fill="x")
        header.pack_propagate(False)

        # Logo
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", padx=20)

        icon_lbl = ctk.CTkLabel(title_frame, text="🔇", font=ctk.CTkFont(size=28))
        icon_lbl.pack(side="left", padx=(0, 8))

        name_lbl = ctk.CTkLabel(
            title_frame, text="SilenceX",
            font=ctk.CTkFont(family="Consolas", size=26, weight="bold"),
            text_color=ACCENT
        )
        name_lbl.pack(side="left")

        ver_lbl = ctk.CTkLabel(
            title_frame, text=f"v{VERSION}",
            font=ctk.CTkFont(family="Consolas", size=11), text_color=TEXT_DIM
        )
        ver_lbl.pack(side="left", padx=(8, 0), pady=(8, 0))

        # Tool status
        tools_frame = ctk.CTkFrame(header, fg_color="transparent")
        tools_frame.pack(side="right", padx=20)

        for tool, installed in self.tools.items():
            color = GREEN if installed else RED
            icon = "✓" if installed else "✗"
            lbl = ctk.CTkLabel(
                tools_frame, text=f"{icon} {tool}",
                font=ctk.CTkFont(family="Consolas", size=11), text_color=color
            )
            lbl.pack(side="left", padx=8)

    def _build_main_area(self):
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=12, pady=5)

        # Left panel — controls
        left = ctk.CTkFrame(main, fg_color=PANEL_BG, corner_radius=8, width=340)
        left.pack(side="left", fill="y", padx=(0, 5))
        left.pack_propagate(False)

        self._build_left_panel(left)

        # Right panel — output
        right = ctk.CTkFrame(main, fg_color=PANEL_BG, corner_radius=8)
        right.pack(side="left", fill="both", expand=True)

        self._build_output(right)

    def _build_left_panel(self, parent):
        # ─── Target ──────────────────────────────────────────────
        sec = self._section(parent, "TARGET")

        self.target_entry = ctk.CTkEntry(
            sec, placeholder_text="domain.com or IP",
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=INPUT_BG, border_color=BORDER, text_color=TEXT,
            height=36, corner_radius=5
        )
        self.target_entry.pack(fill="x", padx=10, pady=5)
        self.target_entry.bind("<Return>", lambda e: self._start_scan())

        # Port override
        self.port_entry = ctk.CTkEntry(
            sec, placeholder_text="Ports (optional: 80,443,8080 or 1-1000)",
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=INPUT_BG, border_color=BORDER, text_color=TEXT,
            height=30, corner_radius=5
        )
        self.port_entry.pack(fill="x", padx=10, pady=(0, 5))

        # ─── Nmap ────────────────────────────────────────────────
        sec2 = self._section(parent, "NMAP PROFILE")

        self.nmap_var = ctk.StringVar(value="Fast Stealth (Recommended)")
        self.nmap_menu = ctk.CTkOptionMenu(
            sec2, variable=self.nmap_var,
            values=list(NMAP_PROFILES.keys()),
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=INPUT_BG, button_color=ACCENT_DIM,
            button_hover_color=ACCENT, dropdown_fg_color=CARD_BG,
            height=30, corner_radius=5, command=self._on_nmap_profile_change
        )
        self.nmap_menu.pack(fill="x", padx=10, pady=5)

        self.nmap_desc = ctk.CTkLabel(
            sec2, text=NMAP_PROFILES["Fast Stealth (Recommended)"]["desc"],
            font=ctk.CTkFont(family="Consolas", size=10), text_color=TEXT_DIM,
            wraplength=300, justify="left"
        )
        self.nmap_desc.pack(fill="x", padx=10)

        self.nmap_custom = ctk.CTkEntry(
            sec2, placeholder_text="Custom Nmap flags (when Custom selected)",
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=INPUT_BG, border_color=BORDER, text_color=TEXT,
            height=28, corner_radius=5
        )
        self.nmap_custom.pack(fill="x", padx=10, pady=5)

        # ─── Nikto ───────────────────────────────────────────────
        sec3 = self._section(parent, "NIKTO PROFILE")

        self.nikto_var = ctk.StringVar(value="Standard")
        self.nikto_menu = ctk.CTkOptionMenu(
            sec3, variable=self.nikto_var,
            values=list(NIKTO_PROFILES.keys()),
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=INPUT_BG, button_color=ACCENT_DIM,
            button_hover_color=ACCENT, dropdown_fg_color=CARD_BG,
            height=30, corner_radius=5
        )
        self.nikto_menu.pack(fill="x", padx=10, pady=5)

        # ─── Modules ────────────────────────────────────────────
        sec4 = self._section(parent, "SCAN MODULES")

        self.mod_vars = {}
        modules = [
            ("Nmap Scan", True),
            ("Nikto Web Scan", False),
            ("ZAP Spider + Scan", False),
            ("Custom: Port Scanner", False),
            ("Custom: SSL Analysis", True),
            ("Custom: Security Headers", True),
            ("Custom: DNS Enum", True),
            ("Custom: Subdomain Enum", True),
        ]
        for name, default in modules:
            var = ctk.BooleanVar(value=default)
            self.mod_vars[name] = var
            cb = ctk.CTkCheckBox(
                sec4, text=name, variable=var,
                font=ctk.CTkFont(family="Consolas", size=11),
                fg_color=ACCENT, hover_color=ACCENT_HOVER,
                border_color=BORDER, text_color=TEXT,
                checkbox_width=18, checkbox_height=18, corner_radius=4
            )
            cb.pack(anchor="w", padx=10, pady=2)

        # ─── Action Buttons ──────────────────────────────────────
        btn_frame = ctk.CTkFrame(parent, fg_color="transparent")
        btn_frame.pack(fill="x", padx=10, pady=10)

        self.scan_btn = ctk.CTkButton(
            btn_frame, text="🔇 START SCAN",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            fg_color=ACCENT, text_color="white", hover_color=ACCENT_HOVER,
            height=42, corner_radius=6, command=self._start_scan
        )
        self.scan_btn.pack(fill="x", pady=(0, 5))

        self.stop_btn = ctk.CTkButton(
            btn_frame, text="⬛ STOP",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            fg_color=RED, text_color="white", hover_color="#cc0000",
            height=32, corner_radius=6, command=self._stop_scan
        )
        self.stop_btn.pack(fill="x", pady=(0, 5))

        # Quick action row
        row = ctk.CTkFrame(btn_frame, fg_color="transparent")
        row.pack(fill="x")

        for text, cmd in [("Clear", self._clear), ("Export TXT", self._export_txt),
                          ("Export JSON", self._export_json)]:
            ctk.CTkButton(
                row, text=text, font=ctk.CTkFont(family="Consolas", size=10),
                fg_color=BORDER, text_color=TEXT, height=26, width=90,
                corner_radius=4, command=cmd
            ).pack(side="left", padx=2, expand=True)

    def _section(self, parent, title):
        """Create a labeled section."""
        lbl = ctk.CTkLabel(
            parent, text=f"  {title}",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=ACCENT, anchor="w"
        )
        lbl.pack(fill="x", padx=5, pady=(10, 2))

        frame = ctk.CTkFrame(parent, fg_color=CARD_BG, corner_radius=6)
        frame.pack(fill="x", padx=8, pady=(0, 5))
        return frame

    def _build_output(self, parent):
        # Tab view for different outputs
        self.tabview = ctk.CTkTabview(
            parent, fg_color=CARD_BG,
            segmented_button_selected_color=ACCENT,
            segmented_button_selected_hover_color=ACCENT_HOVER,
            segmented_button_unselected_color=PANEL_BG
        )
        self.tabview.pack(fill="both", expand=True, padx=5, pady=5)

        self.tabview.add("Live Output")
        self.tabview.add("Nmap Results")
        self.tabview.add("Nikto Results")
        self.tabview.add("Summary")

        # Live Output tab
        self.output = tk.Text(
            self.tabview.tab("Live Output"),
            bg=DARK_BG, fg=TEXT, font=("Consolas", 11),
            wrap="word", insertbackground=ACCENT,
            selectbackground="#2d1a4e", relief="flat",
            padx=12, pady=10, borderwidth=0
        )
        self.output.pack(fill="both", expand=True)

        # Tags
        self.output.tag_configure("header", foreground=ACCENT, font=("Consolas", 12, "bold"))
        self.output.tag_configure("section", foreground=CYAN, font=("Consolas", 11, "bold"))
        self.output.tag_configure("success", foreground=GREEN)
        self.output.tag_configure("error", foreground=RED)
        self.output.tag_configure("warning", foreground=YELLOW)
        self.output.tag_configure("info", foreground=CYAN)
        self.output.tag_configure("dim", foreground=TEXT_DIM)
        self.output.tag_configure("banner", foreground=ACCENT, font=("Consolas", 10, "bold"))
        self.output.configure(state="disabled")

        # Nmap tab
        self.nmap_output = tk.Text(
            self.tabview.tab("Nmap Results"),
            bg=DARK_BG, fg=GREEN, font=("Consolas", 11),
            wrap="word", relief="flat", padx=12, pady=10, borderwidth=0
        )
        self.nmap_output.pack(fill="both", expand=True)
        self.nmap_output.configure(state="disabled")

        # Nikto tab
        self.nikto_output = tk.Text(
            self.tabview.tab("Nikto Results"),
            bg=DARK_BG, fg=ORANGE, font=("Consolas", 11),
            wrap="word", relief="flat", padx=12, pady=10, borderwidth=0
        )
        self.nikto_output.pack(fill="both", expand=True)
        self.nikto_output.configure(state="disabled")

        # Summary tab
        self.summary_output = tk.Text(
            self.tabview.tab("Summary"),
            bg=DARK_BG, fg=TEXT, font=("Consolas", 11),
            wrap="word", relief="flat", padx=12, pady=10, borderwidth=0
        )
        self.summary_output.pack(fill="both", expand=True)
        self.summary_output.configure(state="disabled")

        self._show_banner()

    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=0, height=28)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        self.status_lbl = ctk.CTkLabel(
            bar, text="Ready — Configure target and modules, then START SCAN",
            font=ctk.CTkFont(family="Consolas", size=10), text_color=TEXT_DIM
        )
        self.status_lbl.pack(side="left", padx=12)

        self.progress = ctk.CTkProgressBar(
            bar, width=200, height=10, fg_color=CARD_BG, progress_color=ACCENT
        )
        self.progress.pack(side="right", padx=12, pady=8)
        self.progress.set(0)

    # ─── HELPERS ─────────────────────────────────────────────────────
    def _show_banner(self):
        banner = r"""
  ███████╗██╗██╗     ███████╗███╗   ██╗ ██████╗███████╗██╗  ██╗
  ██╔════╝██║██║     ██╔════╝████╗  ██║██╔════╝██╔════╝╚██╗██╔╝
  ███████╗██║██║     █████╗  ██╔██╗ ██║██║     █████╗   ╚███╔╝
  ╚════██║██║██║     ██╔══╝  ██║╚██╗██║██║     ██╔══╝   ██╔██╗
  ███████║██║███████╗███████╗██║ ╚████║╚██████╗███████╗██╔╝ ██╗
  ╚══════╝╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═╝
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   🔇 Security Scanner Suite v1.0  |  by BennyG  |  Authorized Use Only
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

   Engines: Nmap | Nikto | ZAP | Custom Python Modules
   Profiles: Ghost · Stealth · Quick · Full · Vuln · Custom

   ⚠ Only scan targets you have written authorization to test.

   Configure your target and modules on the left panel, then hit START.
"""
        self._append(banner, "banner")

    def _append(self, text, tag="info"):
        def _do():
            self.output.configure(state="normal")
            self.output.insert("end", text + "\n", tag)
            self.output.see("end")
            self.output.configure(state="disabled")
        self.after(0, _do)

    def _append_to(self, widget, text):
        def _do():
            widget.configure(state="normal")
            widget.insert("end", text + "\n")
            widget.see("end")
            widget.configure(state="disabled")
        self.after(0, _do)

    def _clear(self):
        for w in [self.output, self.nmap_output, self.nikto_output, self.summary_output]:
            w.configure(state="normal")
            w.delete("1.0", "end")
            w.configure(state="disabled")
        self.results_text = ""

    def _set_status(self, text):
        self.after(0, lambda: self.status_lbl.configure(text=text))

    def _set_progress(self, val):
        self.after(0, lambda: self.progress.set(val))

    def _start_spinner(self):
        """Start animated spinner in status bar."""
        if not self.scan_running:
            return
        self.spinner_idx = (self.spinner_idx + 1) % len(self.spinner_chars)
        spinner = self.spinner_chars[self.spinner_idx]
        current = self.status_lbl.cget("text")
        # Strip old spinner
        for c in self.spinner_chars:
            current = current.replace(f" {c}", "")
        self.status_lbl.configure(text=f"{current} {spinner}")
        # Also pulse the progress bar
        cur_progress = self.progress.get()
        if cur_progress < 0.95:
            self.progress.set(cur_progress + 0.002)
        self.spinner_after_id = self.after(150, self._start_spinner)

    def _stop_spinner(self):
        """Stop the spinner animation."""
        if self.spinner_after_id:
            self.after_cancel(self.spinner_after_id)
            self.spinner_after_id = None

    def _on_nmap_profile_change(self, choice):
        prof = NMAP_PROFILES.get(choice, {})
        self.nmap_desc.configure(text=f"{prof.get('desc','')} | Risk: {prof.get('risk','')}")

    # ─── EXPORT ──────────────────────────────────────────────────────
    def _export_txt(self):
        if not self.results_text:
            messagebox.showinfo("Export", "No results yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text", "*.txt")],
            initialfile=f"silencex_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if path:
            with open(path, "w") as f:
                f.write(self.results_text)
            messagebox.showinfo("Saved", f"Report saved: {path}")

    def _export_json(self):
        if not self.results_text:
            messagebox.showinfo("Export", "No results yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON", "*.json")],
            initialfile=f"silencex_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        if path:
            report = {
                "tool": "SilenceX", "version": VERSION,
                "timestamp": datetime.datetime.now().isoformat(),
                "target": self.target_entry.get().strip(),
                "nmap_profile": self.nmap_var.get(),
                "raw_output": self.results_text
            }
            with open(path, "w") as f:
                json.dump(report, f, indent=2, default=str)
            messagebox.showinfo("Saved", f"JSON saved: {path}")

    # ─── AUTO UPDATE ─────────────────────────────────────────────────
    def _auto_update(self, tool_output):
        """Detect outdated warnings in tool output and auto-update."""
        output_lower = tool_output.lower()

        # Nikto outdated
        if "out of date" in output_lower or "update available" in output_lower:
            self._callback("\n  🔄 Outdated tool detected — attempting auto-update...", "warning")

            # Try pip updates first (venv packages)
            pip_packages = ["dnspython", "python-whois", "requests", "customtkinter"]
            try:
                result, code = run_cmd(f"{sys.executable} -m pip install --upgrade {' '.join(pip_packages)} --quiet", timeout=60)
                if code == 0:
                    self._callback("  ✓ Python packages updated", "success")
            except Exception:
                pass

            # Try pacman update for system tools (nikto, nmap)
            for tool in ["nikto", "nmap"]:
                if self.tools.get(tool):
                    try:
                        result, code = run_cmd(f"pkexec pacman -S --noconfirm {tool}", timeout=120)
                        if code == 0:
                            self._callback(f"  ✓ {tool} updated via pacman", "success")
                        else:
                            self._callback(f"  ⚠ {tool} update failed — run manually: sudo pacman -S {tool}", "warning")
                    except Exception:
                        self._callback(f"  ⚠ Could not update {tool} automatically", "warning")

    # ─── SCAN EXECUTION ─────────────────────────────────────────────
    def _callback(self, text, tag="info"):
        self.results_text += text + "\n"
        self._append(text, tag)

    def _stop_scan(self):
        if self.current_process:
            try:
                self.current_process.kill()
            except Exception:
                pass
        self.scan_running = False
        self._stop_spinner()
        self._callback("\n  ⬛ Scan stopped by user.", "error")
        self._set_status("Scan stopped")
        self.scan_btn.configure(state="normal", text="🔇 START SCAN")

    def _start_scan(self):
        target = self.target_entry.get().strip()
        target = target.replace("http://", "").replace("https://", "").rstrip("/").split("/")[0]

        if not target:
            messagebox.showwarning("No Target", "Enter a domain or IP.")
            return
        if self.scan_running:
            return

        self.scan_running = True
        self.scan_btn.configure(state="disabled", text="⏳ Scanning...")
        self._clear()
        self.results_text = ""
        self._start_spinner()

        thread = threading.Thread(target=self._run_scan, args=(target,), daemon=True)
        thread.start()

    def _run_scan(self, target):
        start = time.time()
        selected = [m for m, v in self.mod_vars.items() if v.get()]
        total = len(selected)

        self._callback(f"{'═'*60}", "section")
        self._callback(f"  SilenceX v{VERSION} — Scan Report", "header")
        self._callback(f"  Target:    {target}", "header")
        self._callback(f"  Modules:   {', '.join(selected)}", "info")
        self._callback(f"  Time:      {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "info")
        self._callback(f"  Nmap:      {self.nmap_var.get()}", "info")
        self._callback(f"{'═'*60}", "section")

        for i, mod in enumerate(selected):
            if not self.scan_running:
                break
            self._set_status(f"Running: {mod} ({i+1}/{total})")
            self._set_progress(i / total)

            try:
                if mod == "Nmap Scan":
                    self._run_nmap(target)
                elif mod == "Nikto Web Scan":
                    self._run_nikto(target)
                elif mod == "ZAP Spider + Scan":
                    self._run_zap(target)
                elif mod == "Custom: Port Scanner":
                    ports = self._parse_ports()
                    CustomScanner.port_scan(target, self._callback, ports)
                elif mod == "Custom: SSL Analysis":
                    CustomScanner.ssl_analysis(target, self._callback)
                elif mod == "Custom: Security Headers":
                    CustomScanner.security_headers(target, self._callback)
                elif mod == "Custom: DNS Enum":
                    CustomScanner.dns_enum(target, self._callback)
                elif mod == "Custom: Subdomain Enum":
                    CustomScanner.subdomain_enum(target, self._callback)
            except Exception as e:
                self._callback(f"\n  [!] {mod} crashed: {e}", "error")

        elapsed = time.time() - start
        self._callback(f"\n{'═'*60}", "section")
        self._callback(f"  Scan complete in {elapsed:.1f}s — {total} modules", "header")
        self._callback(f"{'═'*60}", "section")

        # Summary
        self._generate_summary(target, selected, elapsed)

        self._set_progress(1.0)
        self._set_status(f"Complete — {elapsed:.1f}s — {total} modules")
        self.after(0, lambda: self.scan_btn.configure(state="normal", text="🔇 START SCAN"))
        self._stop_spinner()
        self.scan_running = False

    def _parse_ports(self):
        """Parse port entry field."""
        raw = self.port_entry.get().strip()
        if not raw:
            return None
        ports = []
        for part in raw.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    a, b = part.split("-")
                    ports.extend(range(int(a), int(b) + 1))
                except ValueError:
                    pass
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    pass
        return ports if ports else None

    # ─── NMAP ────────────────────────────────────────────────────────
    def _run_nmap(self, target):
        self._callback("\n[NMAP] Port & Service Scan", "header")
        if not self.tools["nmap"]:
            self._callback("  ✗ Nmap not installed! Install: sudo pacman -S nmap", "error")
            return

        profile = self.nmap_var.get()
        flags = NMAP_PROFILES[profile]["cmd"]
        if profile == "Custom":
            flags = self.nmap_custom.get().strip()
            if not flags:
                self._callback("  No custom flags provided", "error")
                return

        # Add port override
        ports_raw = self.port_entry.get().strip()
        if ports_raw and "-p" not in flags:
            flags += f" -p {ports_raw}"

        # Add XML output for parsing
        xml_file = f"/tmp/silencex_nmap_{int(time.time())}.xml"
        cmd = f"nmap {flags} -oX {xml_file} {target}"

        self._callback(f"  Profile: {profile}", "info")
        self._callback(f"  Command: {cmd}", "dim")
        self._callback(f"  Running...\n", "info")

        try:
            proc = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            self.current_process = proc

            full_output = ""
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    full_output += line + "\n"
                    self._callback(f"  {line}", "success")
                    self._append_to(self.nmap_output, line)

            proc.wait()
            self.current_process = None
            self._auto_update(full_output)

            # Parse XML for summary
            if os.path.exists(xml_file):
                self._parse_nmap_xml(xml_file)
                os.remove(xml_file)

        except Exception as e:
            self._callback(f"  Nmap error: {e}", "error")

    def _parse_nmap_xml(self, xml_file):
        """Parse Nmap XML output for structured data."""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for host in root.findall("host"):
                addr = host.find("address")
                if addr is not None:
                    self._callback(f"\n  Host: {addr.get('addr', 'unknown')}", "section")
                ports_elem = host.find("ports")
                if ports_elem:
                    for port in ports_elem.findall("port"):
                        portid = port.get("portid", "")
                        proto = port.get("protocol", "")
                        state = port.find("state")
                        service = port.find("service")
                        state_str = state.get("state", "") if state is not None else ""
                        svc_name = service.get("name", "") if service is not None else ""
                        svc_ver = service.get("version", "") if service is not None else ""
                        self._append_to(self.summary_output,
                            f"  {portid}/{proto}  {state_str:<8s}  {svc_name} {svc_ver}")
        except Exception:
            pass

    # ─── NIKTO ───────────────────────────────────────────────────────
    def _run_nikto(self, target):
        self._callback("\n[NIKTO] Web Vulnerability Scan", "header")
        if not self.tools["nikto"]:
            self._callback("  ✗ Nikto not installed! Install: sudo pacman -S nikto", "error")
            return

        profile = self.nikto_var.get()
        flags = NIKTO_PROFILES[profile]["cmd"]
        if profile == "Custom":
            flags = ""

        cmd = f"nikto -h {target} {flags}"
        self._callback(f"  Command: {cmd}", "dim")
        self._callback(f"  Running (this may take a while)...\n", "info")

        try:
            proc = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            self.current_process = proc

            full_output = ""
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    full_output += line + "\n"
                    tag = "info"
                    if "OSVDB" in line or "vulnerability" in line.lower():
                        tag = "error"
                    elif "+" in line[:3]:
                        tag = "warning"
                    self._callback(f"  {line}", tag)
                    self._append_to(self.nikto_output, line)

            proc.wait()
            self.current_process = None
            self._auto_update(full_output)

        except Exception as e:
            self._callback(f"  Nikto error: {e}", "error")

    # ─── ZAP ─────────────────────────────────────────────────────────
    def _run_zap(self, target):
        self._callback("\n[ZAP] Web Application Scanner", "header")

        zap_cmd = None
        for cmd in ["zap-cli", "zaproxy", "zap.sh"]:
            if which(cmd):
                zap_cmd = cmd
                break

        if not zap_cmd:
            self._callback("  ✗ ZAP not installed!", "error")
            self._callback("  Install: sudo pacman -S zaproxy  (AUR)", "info")
            return

        url = f"https://{target}" if not target.startswith("http") else target

        if zap_cmd == "zap-cli":
            self._callback(f"  Using zap-cli quick-scan on {url}", "info")
            cmd = f"zap-cli quick-scan -s all -r {url}"
        else:
            self._callback(f"  ZAP found but automated CLI scanning requires zap-cli", "warning")
            self._callback(f"  Install: pip install zaproxy", "info")
            return

        self._callback(f"  Command: {cmd}", "dim")
        self._callback(f"  Running...\n", "info")

        try:
            proc = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            self.current_process = proc
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    self._callback(f"  {line}", "info")
            proc.wait()
            self.current_process = None
        except Exception as e:
            self._callback(f"  ZAP error: {e}", "error")

    # ─── SUMMARY ─────────────────────────────────────────────────────
    def _generate_summary(self, target, modules, elapsed):
        summary = f"""
{'═'*50}
  SilenceX — Scan Summary
{'═'*50}
  Target:   {target}
  Modules:  {len(modules)}
  Duration: {elapsed:.1f}s
  Time:     {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Profile:  {self.nmap_var.get()}
{'═'*50}
  Modules executed:
"""
        for m in modules:
            summary += f"    ✓ {m}\n"

        summary += f"\n  Full output available in Live Output tab.\n"
        summary += f"  Use Export TXT/JSON to save report.\n"

        self._append_to(self.summary_output, summary)


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")

    app = SilenceXApp()
    app.mainloop()
