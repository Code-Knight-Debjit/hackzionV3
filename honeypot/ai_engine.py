# honeypot/ai_engine.py
"""
AI Engine — generates convincing fake Linux shell responses.
No real system access. All data is fabricated to deceive and fingerprint attackers.
"""

import random
import time

# ── Fake system identity ──────────────────────────────────────────────────────
FAKE_HOSTNAME   = "prod-db-01"
FAKE_USER       = "root"
FAKE_IP_PRIVATE = "10.0.1.45"
FAKE_KERNEL     = "5.15.0-91-generic"
FAKE_OS         = "Ubuntu 22.04.3 LTS"

# ── Fake credential vault (bait data) ────────────────────────────────────────
FAKE_DB_CREDENTIALS = {
    "host":     "10.0.1.200",
    "port":     5432,
    "database": "customers_prod",
    "username": "db_admin",
    "password": "Pr0d$ecret!2024",   # Deliberately tempting but fake
}

FAKE_ENV_CONTENTS = """\
DATABASE_URL=postgresql://db_admin:Pr0d$ecret!2024@10.0.1.200:5432/customers_prod
SECRET_KEY=sk-prod-8f3a2b1c9d4e7f6a
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
REDIS_URL=redis://:r3d1s_p4ss@10.0.1.201:6379/0
STRIPE_SECRET_KEY=sk_live_EXAMPLEFAKEKEY123456789
"""

FAKE_SHADOW_ENTRY = (
    "root:$6$rounds=656000$fake$aVeryLongHashThatLooksReal"
    "ButIsCompletelyFabricated:19000:0:99999:7:::\n"
    "db_admin:$6$rounds=656000$anotherfake$AlsoCompletelyFakeHashForDeception"
    ":19000:0:99999:7:::\n"
)

# ── Response templates ────────────────────────────────────────────────────────

def _prompt() -> str:
    return f"{FAKE_USER}@{FAKE_HOSTNAME}:~# "


COMMAND_RESPONSES: dict[str, callable] = {
    "whoami": lambda _: f"root\n{_prompt()}",

    "id": lambda _: (
        f"uid=0(root) gid=0(root) groups=0(root),27(sudo),1000(db_admin)\n{_prompt()}"
    ),

    "uname": lambda args: (
        f"{FAKE_KERNEL}\n{_prompt()}" if "-r" in args
        else f"Linux {FAKE_HOSTNAME} {FAKE_KERNEL} #1 SMP PREEMPT_DYNAMIC "
             f"Fri Jan 12 14:23:11 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n{_prompt()}"
    ),

    "hostname": lambda _: f"{FAKE_HOSTNAME}\n{_prompt()}",

    "ifconfig": lambda _: (
        f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        f"        inet {FAKE_IP_PRIVATE}  netmask 255.255.255.0  broadcast 10.0.1.255\n"
        f"        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)\n{_prompt()}"
    ),

    "ip": lambda args: (
        f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue\n"
        f"    inet {FAKE_IP_PRIVATE}/24 brd 10.0.1.255 scope global eth0\n{_prompt()}"
    ),

    "cat /etc/passwd": lambda _: (
        f"root:x:0:0:root:/root:/bin/bash\n"
        f"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        f"db_admin:x:1000:1000:DB Admin,,,:/home/db_admin:/bin/bash\n{_prompt()}"
    ),

    "cat /etc/shadow": lambda _: FAKE_SHADOW_ENTRY + _prompt(),

    "cat .env": lambda _: FAKE_ENV_CONTENTS + _prompt(),

    "env": lambda _: FAKE_ENV_CONTENTS + _prompt(),

    "sudo": lambda args: (
        f"[sudo] password for {FAKE_USER}: \nSorry, try again.\n"
        if "wrong" in args
        else f"root@{FAKE_HOSTNAME}:~# "   # Fake sudo success
    ),

    "sudo su": lambda _: f"root@{FAKE_HOSTNAME}:/# ",

    "ls": lambda args: (
        "app  backup  db_dumps  logs  scripts  .env  .ssh\n" + _prompt()
    ),

    "ls -la": lambda _: (
        f"total 64\n"
        f"drwxr-xr-x  8 root root 4096 Jan 12 09:01 .\n"
        f"drwxr-xr-x 23 root root 4096 Jan  8 14:22 ..\n"
        f"-rw-------  1 root root  220 Jan  8 14:22 .bash_history\n"
        f"-rw-r--r--  1 root root  807 Jan  8 14:22 .bashrc\n"
        f"-rw-------  1 root root  512 Jan 12 09:01 .env\n"
        f"drwx------  2 root root 4096 Jan  8 14:22 .ssh\n"
        f"drwxrwxr-x  5 root root 4096 Jan 12 08:55 app\n"
        f"drwxrwxr-x  3 root root 4096 Jan 10 22:31 db_dumps\n"
        f"drwxrwxr-x  2 root root 4096 Jan 12 09:01 scripts\n"
        + _prompt()
    ),

    "ps aux": lambda _: (
        f"USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        f"root         1  0.0  0.1  17952  2936 ?        Ss   Jan08   0:01 /sbin/init\n"
        f"postgres   423  0.2  2.4 312456 48920 ?        Ss   Jan08   1:23 postgres: "
        f"checkpointer\n"
        f"root       891  0.0  0.0  14432  1024 ?        S    Jan08   0:00 nginx: "
        f"worker process\n"
        f"db_admin  1204  0.1  0.8  98432 16384 ?        Sl   Jan12   0:04 python3 "
        f"app/server.py\n"
        + _prompt()
    ),

    "netstat": lambda _: (
        f"Active Internet connections (only servers)\n"
        f"Proto Recv-Q Send-Q Local Address    Foreign Address  State\n"
        f"tcp        0      0 0.0.0.0:5432     0.0.0.0:*        LISTEN\n"
        f"tcp        0      0 0.0.0.0:80       0.0.0.0:*        LISTEN\n"
        f"tcp        0      0 0.0.0.0:22       0.0.0.0:*        LISTEN\n"
        + _prompt()
    ),

    "curl": lambda args: (
        '{"status":"ok","data":"retrieved"}\n' + _prompt()
    ),

    "wget": lambda args: (
        f"--2024-01-12 09:23:41--  {args}\n"
        f"Resolving... 93.184.216.34\n"
        f"Connecting... connected.\n"
        f"HTTP request sent, awaiting response... 200 OK\n"
        f"Saved: 'payload'\n" + _prompt()
    ),
}

REVERSE_SHELL_PATTERNS = ["bash -i", "/dev/tcp", "nc -e", "python -c", "perl -e", "mkfifo"]

GENERIC_NOT_FOUND = "bash: {cmd}: command not found\n"


def get_fake_response(raw_input: str) -> str:
    """
    Given arbitrary attacker input, return a convincing fake shell response.
    Matches against known command patterns; falls back to generic error.
    """
    cmd = raw_input.strip().lower()

    # Detect reverse shell attempts — appear to succeed but do nothing
    for pattern in REVERSE_SHELL_PATTERNS:
        if pattern in cmd:
            time.sleep(random.uniform(0.3, 0.8))   # Simulate hang
            return ""   # Blank — mimics shell hanging on connection

    # Exact match
    if cmd in COMMAND_RESPONSES:
        return COMMAND_RESPONSES[cmd](cmd)

    # Prefix match (e.g. "uname -r", "sudo su", "wget http://...")
    for key, handler in COMMAND_RESPONSES.items():
        if cmd.startswith(key.split()[0]):
            return handler(cmd)

    # Default: plausible error
    first_token = cmd.split()[0] if cmd.split() else cmd
    return GENERIC_NOT_FOUND.format(cmd=first_token) + _prompt()


def get_fake_db_dump() -> dict:
    """Return fake DB credential payload for HTTP-based exfiltration attempts."""
    return {
        "server":   FAKE_DB_CREDENTIALS["host"],
        "port":     FAKE_DB_CREDENTIALS["port"],
        "database": FAKE_DB_CREDENTIALS["database"],
        "username": FAKE_DB_CREDENTIALS["username"],
        "password": FAKE_DB_CREDENTIALS["password"],
        "tables":   ["users", "orders", "payments", "sessions"],
        "record_count": 2847391,
    }