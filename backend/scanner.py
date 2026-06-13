import re
from typing import Dict, List, Tuple

from backend.models import RuleMatch, ScanResponse


RULES = [
    # -----------------------------
    # Prompt Injection / Jailbreak
    # -----------------------------
    {
        "rule_id": "PI-001",
        "category": "PROMPT_INJECTION",
        "severity": "HIGH",
        "score": 75,
        "pattern": r"\b(ignore|disregard|forget)\b.*\b(previous|prior|above|earlier)\b.*\b(instructions|rules|message|prompt)\b",
        "reason": "Detected attempt to override previous instructions."
    },
    {
        "rule_id": "PI-002",
        "category": "PROMPT_INJECTION",
        "severity": "HIGH",
        "score": 80,
        "pattern": r"\b(reveal|show|print|display|leak)\b.*\b(system prompt|hidden prompt|developer message|internal instructions)\b",
        "reason": "Detected attempt to reveal hidden/system instructions."
    },
    {
        "rule_id": "PI-003",
        "category": "JAILBREAK",
        "severity": "MEDIUM",
        "score": 55,
        "pattern": r"\b(jailbreak|DAN mode|developer mode|bypass safety|bypass restrictions|unfiltered mode)\b",
        "reason": "Detected possible jailbreak or safety-bypass attempt."
    },
    {
        "rule_id": "PI-004",
        "category": "PROMPT_INJECTION",
        "severity": "MEDIUM",
        "score": 50,
        "pattern": r"\b(act as|pretend to be)\b.*\b(no rules|no restrictions|unrestricted|evil|malicious)\b",
        "reason": "Detected suspicious role-play instruction intended to bypass restrictions."
    },

    # -----------------------------
    # Secret Leakage Attempts
    # -----------------------------
    {
        "rule_id": "SL-001",
        "category": "SECRET_LEAKAGE",
        "severity": "CRITICAL",
        "score": 95,
        "pattern": r"\b(print|show|display|reveal|dump|cat)\b.*\b(\.env|environment variables|env variables|secrets|api keys|credentials)\b",
        "reason": "Detected attempt to expose environment variables or secrets."
    },
    {
        "rule_id": "SL-002",
        "category": "SECRET_LEAKAGE",
        "severity": "CRITICAL",
        "score": 100,
        "pattern": r"(-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)",
        "reason": "Detected private key material."
    },
    {
        "rule_id": "SL-003",
        "category": "SECRET_LEAKAGE",
        "severity": "CRITICAL",
        "score": 95,
        "pattern": r"\b(AKIA[0-9A-Z]{16})\b",
        "reason": "Detected possible AWS access key ID."
    },
    {
        "rule_id": "SL-004",
        "category": "SECRET_LEAKAGE",
        "severity": "HIGH",
        "score": 80,
        "pattern": r"\b(cat|type|open|read)\b.*(\.ssh/id_rsa|\.ssh/id_ed25519|private_key|id_rsa)",
        "reason": "Detected attempt to access SSH private key files."
    },

    # -----------------------------
    # Dangerous Commands in Text
    # -----------------------------
    {
        "rule_id": "DC-001",
        "category": "DESTRUCTIVE_COMMAND",
        "severity": "CRITICAL",
        "score": 100,
        "pattern": r"\brm\s+-rf\s+(/|\*|~|\\)",
        "reason": "Detected destructive recursive delete command."
    },
    {
        "rule_id": "DC-002",
        "category": "DESTRUCTIVE_COMMAND",
        "severity": "CRITICAL",
        "score": 95,
        "pattern": r"\b(del|erase|rmdir)\b.*\b(/s|/q)\b",
        "reason": "Detected potentially destructive Windows delete command."
    },
    {
        "rule_id": "DC-003",
        "category": "PRIVILEGE_ESCALATION",
        "severity": "HIGH",
        "score": 80,
        "pattern": r"\bsudo\b.*\b(chmod|chown|usermod|passwd|su|bash|sh)\b",
        "reason": "Detected privileged system modification command."
    },
    {
        "rule_id": "DC-004",
        "category": "UNSAFE_NETWORK_EXECUTION",
        "severity": "CRITICAL",
        "score": 95,
        "pattern": r"\b(curl|wget)\b.*\|\s*(bash|sh|powershell|pwsh)",
        "reason": "Detected remote script execution through shell pipe."
    },

    # -----------------------------
    # Reconnaissance / Exfiltration
    # -----------------------------
    {
        "rule_id": "RECON-001",
        "category": "SYSTEM_RECONNAISSANCE",
        "severity": "MEDIUM",
        "score": 45,
        "pattern": r"\b(whoami|hostname|uname\s+-a|ipconfig|ifconfig|netstat|systeminfo)\b",
        "reason": "Detected system reconnaissance command."
    },
    {
        "rule_id": "EXFIL-001",
        "category": "NETWORK_EXFILTRATION",
        "severity": "HIGH",
        "score": 85,
        "pattern": r"\b(send|upload|post|exfiltrate)\b.*\b(secret|token|password|credential|key|\.env)\b.*\b(http|https|ftp)\b",
        "reason": "Detected possible secret exfiltration attempt."
    },

    # -----------------------------
    # Unsafe Code Patterns
    # -----------------------------
    {
        "rule_id": "CODE-001",
        "category": "UNSAFE_CODE",
        "severity": "MEDIUM",
        "score": 50,
        "pattern": r"\beval\s*\(",
        "reason": "Detected use of eval(), which can execute untrusted code."
    },
    {
        "rule_id": "CODE-002",
        "category": "UNSAFE_CODE",
        "severity": "MEDIUM",
        "score": 50,
        "pattern": r"\bexec\s*\(",
        "reason": "Detected use of exec(), which can execute dynamic code."
    },
    {
        "rule_id": "CODE-003",
        "category": "UNSAFE_CODE",
        "severity": "MEDIUM",
        "score": 45,
        "pattern": r"verify\s*=\s*False",
        "reason": "Detected disabled TLS certificate verification."
    },
    {
        "rule_id": "CODE-004",
        "category": "UNSAFE_CODE",
        "severity": "HIGH",
        "score": 75,
        "pattern": r"shell\s*=\s*True",
        "reason": "Detected shell=True, which may enable command injection."
    }
]


def normalize_text(content: str) -> str:
    """
    Normalize text for more consistent scanning.
    """
    return content.strip()


def find_rule_matches(content: str) -> List[RuleMatch]:
    """
    Find all rule matches in the provided content.
    """
    matches: List[RuleMatch] = []

    for rule in RULES:
        regex_matches = re.finditer(rule["pattern"], content, flags=re.IGNORECASE | re.MULTILINE)

        for match in regex_matches:
            matched_text = match.group(0)

            matches.append(
                RuleMatch(
                    rule_id=rule["rule_id"],
                    category=rule["category"],
                    severity=rule["severity"],
                    score=rule["score"],
                    matched_text=matched_text,
                    reason=rule["reason"]
                )
            )

    return matches


def calculate_risk_score(matches: List[RuleMatch]) -> int:
    """
    Calculate final risk score.

    Current logic:
    - Use the highest matched rule score.
    - Add a small bonus for multiple matches.
    - Cap score at 100.

    This keeps the result simple and explainable.
    """
    if not matches:
        return 0

    highest_score = max(match.score for match in matches)
    bonus = min((len(matches) - 1) * 5, 20)

    return min(highest_score + bonus, 100)


def decide(risk_score: int, matches: List[RuleMatch]) -> str:
    """
    Convert risk score and rule categories into a decision.
    """
    critical_categories = {
        "SECRET_LEAKAGE",
        "DESTRUCTIVE_COMMAND",
        "UNSAFE_NETWORK_EXECUTION",
        "NETWORK_EXFILTRATION"
    }

    matched_categories = {match.category for match in matches}

    if risk_score >= 80:
        return "BLOCK"

    if matched_categories.intersection(critical_categories) and risk_score >= 70:
        return "BLOCK"

    if risk_score >= 50:
        return "REQUIRE_APPROVAL"

    if risk_score >= 21:
        return "WARN"

    return "ALLOW"


def scan_text(content: str, input_type: str) -> ScanResponse:
    """
    Main scanner function used by FastAPI endpoints.
    """
    normalized_content = normalize_text(content)

    matches = find_rule_matches(normalized_content)
    risk_score = calculate_risk_score(matches)
    decision = decide(risk_score, matches)

    categories = sorted(list({match.category for match in matches}))
    reasons = sorted(list({match.reason for match in matches}))

    return ScanResponse(
        input_type=input_type,
        decision=decision,
        risk_score=risk_score,
        categories=categories,
        reasons=reasons,
        matched_rules=matches
    )