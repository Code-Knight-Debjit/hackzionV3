# detection/ml_model.py
"""
ML Classifier — rule-based attack classifier.
Acts as a drop-in placeholder for a trained ML model.
Returns structured { "attack_type": "..." } compatible with the response engine.

To upgrade: replace classify_attack() with a joblib-loaded sklearn model.
"""

from dataclasses import dataclass


# ── Attack taxonomy ───────────────────────────────────────────────────────────
@dataclass
class ClassificationResult:
    attack_type: str
    confidence:  float
    description: str

    def dict(self):
        return {
            "attack_type": self.attack_type,
            "confidence":  self.confidence,
            "description": self.description,
        }


# ── Feature rules (ordered by specificity — most specific first) ──────────────
_RULES: list[tuple[callable, ClassificationResult]] = [
    (
        lambda path, query, scenario, body, n: scenario == "rce_attempt" or any(
            x in (query + body).lower() for x in ["bash -i", "/dev/tcp", "nc -e", "mkfifo", "eval("]
        ),
        ClassificationResult("Remote Code Execution", 0.95, "Shell injection or reverse shell attempt"),
    ),
    (
        lambda path, query, scenario, body, n: scenario == "sql_injection" or any(
            x in query.lower() for x in ["union select", "' or ", "1=1", "drop table", "--"]
        ),
        ClassificationResult("SQL Injection", 0.92, "SQL injection probe via query parameters"),
    ),
    (
        lambda path, query, scenario, body, n: any(
            x in (query + body).lower() for x in ["<script", "onerror=", "javascript:", "alert("]
        ),
        ClassificationResult("Cross-Site Scripting", 0.90, "XSS payload in request"),
    ),
    (
        lambda path, query, scenario, body, n: scenario == "path_traversal" or any(
            x in path.lower() for x in ["../", "etc/passwd", "etc/shadow", "/proc/"]
        ),
        ClassificationResult("Path Traversal", 0.88, "Directory traversal attempt"),
    ),
    (
        lambda path, query, scenario, body, n: scenario in ("db_credential_exposure", "env_exposure"),
        ClassificationResult("Credential Harvesting", 0.85, "Attempting to extract credentials or env vars"),
    ),
    (
        lambda path, query, scenario, body, n: scenario in ("admin_access", "user_enumeration"),
        ClassificationResult("Privilege Escalation Probe", 0.80, "Probing admin surfaces or user lists"),
    ),
    (
        lambda path, query, scenario, body, n: n > 20,
        ClassificationResult("Automated Scanner", 0.75, "High request volume — likely automated tool"),
    ),
    (
        lambda path, query, scenario, body, n: True,   # Default
        ClassificationResult("Generic Reconnaissance", 0.50, "General scanning or probing activity"),
    ),
]


def classify_attack(
    path: str,
    query: str,
    scenario: str,
    body: str,
    event_count: int,
) -> dict:
    """
    Classify the attack type for a given event.
    Returns a dict compatible with the response engine.
    """
    for condition, result in _RULES:
        if condition(path, query, scenario, body, event_count):
            return result.dict()

    return ClassificationResult("Unknown", 0.0, "No pattern matched").dict()