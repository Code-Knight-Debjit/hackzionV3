# ai_analyzer/analyzer.py
"""
Input Pipeline + LLM Analysis Orchestrator.

Accepts raw log dicts from:
  - honeypot/ai_handler.py
  - gateway/router.py event_payload
  - detection/behavior_analyzer.py ingest_event() output

Runs analysis via Llama3 (Ollama) with rule-based fallback.
Feeds results to: cvss_engine → threat_intel → profiler → database → api_client
"""

import json
import logging
import time
import re
import httpx

from ai_analyzer.cvss_engine    import compute_cvss, severity_from_score
from ai_analyzer.threat_intel   import match_threat_intel
from ai_analyzer.profiler       import update_profile, get_profile
from ai_analyzer.database       import insert_attack_log
from ai_analyzer.api_client     import send_critical_alert

logger = logging.getLogger("ai_analyzer")

# ── Ollama config ─────────────────────────────────────────────────────────────
OLLAMA_URL   = "http://ollama:11434/api/generate"
OLLAMA_MODEL = "llama3"
LLM_TIMEOUT  = 25.0   # seconds — LLM can be slow; never block the caller past this


# ── LLM severity → numeric map (for CVSS blending) ───────────────────────────
LLM_SEVERITY_SCORES = {
    "critical": 10.0,
    "high":      8.0,
    "medium":    5.0,
    "low":       2.0,
}

# ── Rule-based fallback classifier ────────────────────────────────────────────
_RULE_FALLBACK = [
    (["union select", "' or ", "1=1", "drop table", "sleep(", "benchmark("],
     "SQL Injection",        "High",     9.0,  "automated"),
    (["<script", "onerror=", "javascript:", "alert(", "onload="],
     "XSS",                  "Medium",   6.0,  "automated"),
    (["bash -i", "/dev/tcp", "nc -e", "mkfifo", "python -c", "perl -e"],
     "Remote Code Execution", "Critical", 9.5,  "manual"),
    (["../", "etc/passwd", "etc/shadow", "/proc/", "%2e%2e"],
     "Path Traversal",       "High",     7.5,  "automated"),
    (["wget", "curl", "chmod +x", ".sh", "miner"],
     "Malware Deployment",   "Critical", 9.0,  "tool-based"),
    (["CVE-", "dirtycow", "pwnkit", "pkexec", "overlayfs"],
     "Kernel Exploit",       "Critical", 9.8,  "manual"),
    (["admin", "password", "login", "passwd"],
     "Brute Force",          "Medium",   5.0,  "tool-based"),
    (["whoami", "uname", "ifconfig", "netstat", "ps aux"],
     "Reconnaissance",       "Low",      3.0,  "manual"),
]


def _rule_based_analysis(log: dict) -> dict:
    """
    Pure rule-based fallback — used when Ollama is unavailable.
    Scans the combined text of path + query + body against known signatures.
    """
    combined = " ".join([
        log.get("path", ""),
        log.get("query", ""),
        log.get("body", ""),
        log.get("request", ""),
    ]).lower()

    for patterns, attack_type, severity, _, behavior in _RULE_FALLBACK:
        if any(p in combined for p in patterns):
            return {
                "attack_type":   attack_type,
                "severity":      severity,
                "behavior":      behavior,
                "mitigation":    _default_mitigation(attack_type),
                "llm_available": False,
                "confidence":    0.75,
            }

    return {
        "attack_type":   "Generic Probe",
        "severity":      "Low",
        "behavior":      "automated",
        "mitigation":    "Monitor and rate-limit the IP. No immediate action required.",
        "llm_available": False,
        "confidence":    0.40,
    }


def _default_mitigation(attack_type: str) -> str:
    mitigations = {
        "SQL Injection":         "Use parameterized queries. Sanitize all inputs. Enable WAF SQL injection rules.",
        "XSS":                   "Encode all output. Set Content-Security-Policy headers. Sanitize HTML inputs.",
        "Remote Code Execution": "Patch immediately. Disable dangerous functions. Isolate the service.",
        "Path Traversal":        "Validate and canonicalize file paths. Use chroot jails. Restrict file permissions.",
        "Malware Deployment":    "Block outbound connections to C2 IPs. Audit cron jobs. Check for new binaries.",
        "Kernel Exploit":        "Apply kernel patches immediately. Restrict SUID binaries. Enable AppArmor/SELinux.",
        "Brute Force":           "Enable account lockout. Implement MFA. Rate-limit login endpoints.",
        "Reconnaissance":        "Block IP. Review exposed services. Reduce attack surface.",
    }
    return mitigations.get(attack_type, "Investigate and monitor. Block IP if activity continues.")


# ── LLM prompt builder ────────────────────────────────────────────────────────

def _build_prompt(log: dict) -> str:
    return f"""You are a cybersecurity analyst. Analyze this attack log and respond ONLY with valid JSON.

ATTACK LOG:
- IP: {log.get('ip', 'unknown')}
- Path: {log.get('path', '/')}
- Method: {log.get('method', 'GET')}
- Query: {log.get('query', '')}
- Body: {str(log.get('body', ''))[:400]}
- User-Agent: {log.get('user_agent', log.get('headers', {}).get('user-agent', ''))}
- Timestamp: {log.get('timestamp', log.get('ts', time.time()))}

Respond with ONLY this JSON structure, no explanation, no markdown:
{{
  "attack_type": "one of: SQL Injection, XSS, Remote Code Execution, Path Traversal, Brute Force, Credential Harvesting, Malware Deployment, Kernel Exploit, Reconnaissance, Generic Probe",
  "severity": "one of: Low, Medium, High, Critical",
  "behavior": "one of: manual, automated, tool-based",
  "mitigation": "2-3 concrete actionable steps as a single string",
  "confidence": 0.0 to 1.0
}}"""


def _parse_llm_response(raw: str) -> dict | None:
    """
    Extract JSON from LLM output robustly.
    LLMs sometimes wrap JSON in markdown — strip it.
    """
    # Strip markdown code fences if present
    raw = re.sub(r"```(?:json)?", "", raw).strip()

    # Find the first { ... } block
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        return None

    try:
        data = json.loads(match.group())
        # Validate required keys
        required = {"attack_type", "severity", "behavior", "mitigation", "confidence"}
        if not required.issubset(data.keys()):
            return None
        # Normalise severity capitalisation
        data["severity"] = data["severity"].capitalize()
        data["llm_available"] = True
        return data
    except (json.JSONDecodeError, KeyError):
        return None


async def analyze_with_llm(log: dict) -> dict:
    """
    Send log to Llama3 via Ollama and parse structured response.
    Returns rule-based result if LLM is unreachable or returns garbage.
    """
    prompt = _build_prompt(log)

    try:
        async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
            response = await client.post(OLLAMA_URL, json={
                "model":  OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
            })
            if response.status_code != 200:
                raise ValueError(f"Ollama HTTP {response.status_code}")

            raw_text = response.json().get("response", "")
            parsed   = _parse_llm_response(raw_text)

            if parsed:
                logger.info(f"LLM analysis succeeded for {log.get('ip')} → {parsed['attack_type']}")
                return parsed
            else:
                logger.warning(f"LLM returned unparseable output — using rule fallback")
                return _rule_based_analysis(log)

    except (httpx.ConnectError, httpx.TimeoutException) as e:
        logger.warning(f"Ollama unreachable ({e}) — using rule-based fallback")
        return _rule_based_analysis(log)
    except Exception as e:
        logger.error(f"LLM error: {e} — using rule-based fallback")
        return _rule_based_analysis(log)


# ── Main pipeline orchestrator ────────────────────────────────────────────────

async def run_analysis_pipeline(log: dict) -> dict:
    """
    Full pipeline:
      log → LLM/rules → CVSS → threat intel → profiler → DB → alert (if critical)

    Returns the complete structured intelligence report.
    """
    ip = log.get("ip", "unknown")
    ts = log.get("timestamp", log.get("ts", time.time()))

    # ── Step 1: LLM analysis (with rule fallback) ─────────────────────────────
    llm_result = await analyze_with_llm(log)

    # ── Step 2: CVSS scoring ──────────────────────────────────────────────────
    cvss_result = compute_cvss(
        attack_type  = llm_result["attack_type"],
        llm_severity = llm_result["severity"],
    )

    # ── Step 3: Threat intelligence matching ──────────────────────────────────
    intel_result = match_threat_intel(
        path    = log.get("path", "/"),
        query   = log.get("query", ""),
        body    = str(log.get("body", "")),
        request = log.get("request", ""),
    )

    # ── Step 4: Build complete report ─────────────────────────────────────────
    report = {
        "ip":               ip,
        "timestamp":        ts,
        "attack_type":      llm_result["attack_type"],
        "severity":         cvss_result["severity"],    # CVSS-authoritative
        "cvss_score":       cvss_result["cvss_score"],
        "behavior":         llm_result["behavior"],
        "confidence":       llm_result["confidence"],
        "mitigation":       llm_result["mitigation"],
        "llm_used":         llm_result.get("llm_available", False),
        "matched_signature":intel_result["matched_signature"],
        "mitre_technique":  intel_result["mitre_technique"],
        "pattern_type":     intel_result["pattern_type"],
        "owasp_category":   intel_result["owasp_category"],
    }

    # ── Step 5: Threat actor profiling (MongoDB upsert) ───────────────────────
    profile = await update_profile(ip=ip, report=report)
    report["attacker_profile"] = profile

    # ── Step 6: Persist full report to MongoDB ────────────────────────────────
    await insert_attack_log(report)

    # ── Step 7: Critical alert → external API ─────────────────────────────────
    if cvss_result["severity"] == "Critical":
        await send_critical_alert(report)

    logger.info(
        f"Pipeline complete | IP={ip} type={report['attack_type']} "
        f"severity={report['severity']} cvss={report['cvss_score']}"
    )
    return report