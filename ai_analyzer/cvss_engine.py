# ai_analyzer/cvss_engine.py
"""
Rule-Based CVSS Scoring Engine.

Base scores per attack type (CVSS v3.1 approximate values):
  RCE              → 9.8  (Critical)
  Kernel Exploit   → 9.8  (Critical)
  Malware Deploy   → 9.0  (Critical)
  SQL Injection     → 9.0  (Critical)
  Path Traversal   → 7.5  (High)
  Credential Harv. → 7.5  (High)
  XSS              → 6.0  (Medium)
  Brute Force      → 5.0  (Medium)
  Reconnaissance   → 3.0  (Low)
  Generic Probe    → 2.0  (Low)

Final score blends rule score and LLM-inferred severity.
"""

# ── Base CVSS scores by attack type ──────────────────────────────────────────
BASE_SCORES: dict[str, float] = {
    "Remote Code Execution":  9.8,
    "Kernel Exploit":         9.8,
    "Malware Deployment":     9.0,
    "SQL Injection":          9.0,
    "Path Traversal":         7.5,
    "Credential Harvesting":  7.5,
    "XSS":                    6.0,
    "Cross-Site Scripting":   6.0,
    "Brute Force":            5.0,
    "Privilege Escalation Probe": 7.0,
    "Reconnaissance":         3.0,
    "Generic Probe":          2.0,
    "Generic Reconnaissance": 2.0,
    "Unknown":                4.0,
}

# LLM severity label → numeric score for blending
LLM_SEVERITY_MAP: dict[str, float] = {
    "Critical": 10.0,
    "High":      8.0,
    "Medium":    5.0,
    "Low":       2.0,
}

# CVSS score → severity band
SEVERITY_BANDS = [
    (9.0,  "Critical"),
    (7.0,  "High"),
    (4.0,  "Medium"),
    (0.0,  "Low"),
]


def severity_from_score(score: float) -> str:
    """Map a numeric CVSS score to a severity label."""
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "Low"


def compute_cvss(attack_type: str, llm_severity: str) -> dict:
    """
    Compute blended CVSS score.

    Formula:
        rule_score  = BASE_SCORES[attack_type]
        llm_score   = LLM_SEVERITY_MAP[llm_severity]
        final_score = (rule_score + llm_score) / 2

    Returns:
        {
            "cvss_score": float (0.0–10.0, rounded to 1dp),
            "rule_score": float,
            "llm_score":  float,
            "severity":   str,
        }
    """
    # Normalise attack_type — handle minor LLM variations
    normalised = attack_type.strip().title()
    rule_score = BASE_SCORES.get(normalised, BASE_SCORES["Unknown"])

    # Normalise LLM severity
    llm_severity_clean = llm_severity.strip().capitalize()
    llm_score = LLM_SEVERITY_MAP.get(llm_severity_clean, 5.0)

    final_score = round((rule_score + llm_score) / 2, 1)
    # Clamp to valid CVSS range
    final_score = max(0.0, min(10.0, final_score))

    return {
        "cvss_score": final_score,
        "rule_score": rule_score,
        "llm_score":  llm_score,
        "severity":   severity_from_score(final_score),
    }