import re
from typing import List, Optional

from backend.models import CommandScanResponse, RuleMatch
from backend.secret_detector import find_secret_rule_matches


COMMAND_RULES = [
    # -------------------------------------------------
    # Critical destructive commands - Linux/macOS
    # -------------------------------------------------
    {
        "rule_id": "CMD-DEST-001",
        "category": "DESTRUCTIVE_COMMAND",
        "severity": "CRITICAL",
        "score": 100,
        "pattern": r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+(/|~|\*|\.)",
        "reason": "Detected destructive recursive delete command."
    },
    {
        "rule_id": "CMD-DEST-002",
        "category": "DESTRUCTIVE_COMMAND",
        "severity": "CRITICAL",
        "score": 100,
        "pattern": r"\bmkfs(\.[a-z0-9]+)?\b",
        "reason": "Detected filesystem formatting command."
    },
    {
        "rule_id": "CMD-DEST-003",
        "category": "DESTRUCTIVE_COMMAND",
        "severity": "CRITICAL",
        "score": 100,
        "pattern": r"\bdd\s+.*\bof=/dev/(sd[a-z]|nvme\d+n\d+|zero|random)",
        "reason": "Detected dangerous disk overwrite command."
    },
    {
        "rule_id": "CMD-DEST-004",
        "category": "DESTRUCTIVE_COMMAND",
        "severity": "CRITICAL",
        "score": 100,
        "pattern": r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;:",
        "reason": "Detected fork bomb pattern."
    },

    # -------------------------------------------------
    # Critical destructive commands - Windows
    # -------------------------------------------------
    {
        "rule_id": "CMD-WIN-DEST-001",
        "category": "DESTRUCTIVE_COMMAND",
        "severity": "CRITICAL",
        "score": 100,
        "pattern": r"\b(del|erase)\b\s+.*(/s|/q).*(c:\\|%systemroot%|%userprofile%)",
        "reason": "Detected potentially destructive Windows delete command."
    },
    {
        "rule_id": "CMD-WIN-DEST-002",
        "category": "DESTRUCTIVE_COMMAND",
        "severity": "CRITICAL",
        "score": 100,
        "pattern": r"\bformat\s+[a-zA-Z]:",
        "reason": "Detected Windows drive formatting command."
    },
    {
        "rule_id": "CMD-WIN-DEST-003",
        "category": "DESTRUCTIVE_COMMAND",
        "severity": "CRITICAL",
        "score": 95,
        "pattern": r"\bRemove-Item\b.*\b(-Recurse|-r)\b.*\b(-Force|-f)\b",
        "reason": "Detected destructive PowerShell recursive force deletion."
    },

    # -------------------------------------------------
    # Remote script execution
    # -------------------------------------------------
    {
        "rule_id": "CMD-NET-001",
        "category": "UNSAFE_NETWORK_EXECUTION",
        "severity": "CRITICAL",
        "score": 95,
        "pattern": r"\b(curl|wget)\b\s+.*\|\s*(bash|sh|zsh|fish)",
        "reason": "Detected remote script execution through shell pipe."
    },
    {
        "rule_id": "CMD-NET-002",
        "category": "UNSAFE_NETWORK_EXECUTION",
        "severity": "CRITICAL",
        "score": 95,
        "pattern": r"\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b.*\|\s*(iex|Invoke-Expression)",
        "reason": "Detected remote PowerShell execution through Invoke-Expression."
    },
    {
        "rule_id": "CMD-NET-003",
        "category": "NETWORK_EXFILTRATION",
        "severity": "HIGH",
        "score": 85,
        "pattern": r"\b(curl|wget|scp|ftp|sftp|nc|netcat)\b.*\b(\.env|id_rsa|id_ed25519|secret|token|password|credentials?)\b",
        "reason": "Detected possible secret transfer over the network."
    },

    # -------------------------------------------------
    # Secret access
    # -------------------------------------------------
    {
        "rule_id": "CMD-SECRET-001",
        "category": "SECRET_LEAKAGE",
        "severity": "CRITICAL",
        "score": 95,
        "pattern": r"\b(cat|type|more|less|Get-Content)\b\s+.*(\.env|id_rsa|id_ed25519|\.aws/credentials|credentials\.json)",
        "reason": "Detected attempt to read sensitive credential files."
    },
    {
        "rule_id": "CMD-SECRET-002",
        "category": "SECRET_LEAKAGE",
        "severity": "HIGH",
        "score": 80,
        "pattern": r"\b(env|printenv|set)\b",
        "reason": "Detected command that may expose environment variables."
    },
    {
        "rule_id": "CMD-SECRET-003",
        "category": "SECRET_LEAKAGE",
        "severity": "HIGH",
        "score": 85,
        "pattern": r"\b(grep|findstr|Select-String)\b.*\b(password|secret|token|api_key|apikey|credential)\b",
        "reason": "Detected search for secrets or credentials."
    },

    # -------------------------------------------------
    # Privilege escalation and system modification
    # -------------------------------------------------
    {
        "rule_id": "CMD-PRIV-001",
        "category": "PRIVILEGE_ESCALATION",
        "severity": "HIGH",
        "score": 75,
        "pattern": r"\bsudo\b",
        "reason": "Detected privileged command execution."
    },
    {
        "rule_id": "CMD-PRIV-002",
        "category": "PRIVILEGE_ESCALATION",
        "severity": "CRITICAL",
        "score": 95,
        "pattern": r"\bchmod\s+(-R\s+)?777\b",
        "reason": "Detected insecure permission change to world-readable/writable/executable."
    },
    {
        "rule_id": "CMD-PRIV-003",
        "category": "PRIVILEGE_ESCALATION",
        "severity": "HIGH",
        "score": 85,
        "pattern": r"\b(chown|usermod|passwd|su)\b",
        "reason": "Detected user, ownership, or authentication-related system modification."
    },
    {
        "rule_id": "CMD-PRIV-004",
        "category": "SECURITY_CONTROL_DISABLE",
        "severity": "CRITICAL",
        "score": 100,
        "pattern": r"\b(systemctl\s+stop\s+(ufw|firewalld|iptables)|ufw\s+disable|Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$true)\b",
        "reason": "Detected attempt to disable security controls."
    },

    # -------------------------------------------------
    # Reconnaissance
    # -------------------------------------------------
    {
        "rule_id": "CMD-RECON-001",
        "category": "SYSTEM_RECONNAISSANCE",
        "severity": "MEDIUM",
        "score": 35,
        "pattern": r"\b(whoami|hostname|uname\s+-a|systeminfo|ipconfig|ifconfig|netstat|ss\s+-tulnp)\b",
        "reason": "Detected system reconnaissance command."
    },
    {
        "rule_id": "CMD-RECON-002",
        "category": "NETWORK_RECONNAISSANCE",
        "severity": "MEDIUM",
        "score": 45,
        "pattern": r"\b(nmap|masscan|arp-scan|traceroute|tracert)\b",
        "reason": "Detected network reconnaissance tool."
    },

    # -------------------------------------------------
    # Package installation
    # -------------------------------------------------
    {
        "rule_id": "CMD-PKG-001",
        "category": "PACKAGE_INSTALLATION",
        "severity": "LOW",
        "score": 30,
        "pattern": r"\b(pip|pip3|npm|yarn|pnpm|apt|apt-get|choco|winget|brew)\b\s+(install|add)",
        "reason": "Detected package installation command."
    },

    # -------------------------------------------------
    # Docker/container risk
    # -------------------------------------------------
    {
        "rule_id": "CMD-DOCKER-001",
        "category": "CONTAINER_ESCAPE_RISK",
        "severity": "HIGH",
        "score": 85,
        "pattern": r"\bdocker\s+run\b.*(--privileged|-v\s+/:/host|-v\s+/var/run/docker\.sock)",
        "reason": "Detected risky Docker command that may expose the host system."
    }
]


SHELL_HINTS = {
    "powershell": [r"\bInvoke-WebRequest\b", r"\bInvoke-RestMethod\b", r"\bGet-Content\b", r"\bRemove-Item\b", r"\bSet-MpPreference\b"],
    "cmd": [r"\bdir\b", r"\btype\b", r"\bdel\b", r"\brmdir\b", r"\bipconfig\b"],
    "bash": [r"\bsudo\b", r"\brm\b", r"\bchmod\b", r"\bchown\b", r"\bcurl\b", r"\bwget\b", r"\bcat\b"]
}


def normalize_command(command: str) -> str:
    """
    Normalize command input before analysis.
    """
    return command.strip()


def detect_shell(command: str) -> Optional[str]:
    """
    Best-effort shell detection based on command syntax.
    """
    for shell_name, patterns in SHELL_HINTS.items():
        for pattern in patterns:
            if re.search(pattern, command, flags=re.IGNORECASE):
                return shell_name

    return None


def has_command_chaining(command: str) -> bool:
    """
    Detect chained commands.

    Chaining is not always malicious, but it increases risk because it can hide
    multiple actions in one line.
    """
    chaining_patterns = [
        r"\s&&\s",
        r"\s\|\|\s",
        r"\s;\s",
        r"\|",
        r"`.+`",
        r"\$\(.+\)"
    ]

    return any(re.search(pattern, command) for pattern in chaining_patterns)


def find_command_matches(command: str) -> List[RuleMatch]:
    """
    Match command against command-specific rules.
    """
    matches: List[RuleMatch] = []

    for rule in COMMAND_RULES:
        regex_matches = re.finditer(rule["pattern"], command, flags=re.IGNORECASE | re.MULTILINE)

        for match in regex_matches:
            matches.append(
                RuleMatch(
                    rule_id=rule["rule_id"],
                    category=rule["category"],
                    severity=rule["severity"],
                    score=rule["score"],
                    matched_text=match.group(0),
                    reason=rule["reason"]
                )
            )

    return matches


def calculate_command_risk_score(matches: List[RuleMatch], command_chain_detected: bool) -> int:
    """
    Calculate command-specific risk score.
    """
    if not matches:
        if command_chain_detected:
            return 20
        return 0

    highest_score = max(match.score for match in matches)

    multiple_match_bonus = min((len(matches) - 1) * 5, 15)
    chain_bonus = 10 if command_chain_detected else 0

    return min(highest_score + multiple_match_bonus + chain_bonus, 100)


def decide_command(risk_score: int, matches: List[RuleMatch]) -> str:
    """
    Decide what should happen with the command.
    """
    categories = {match.category for match in matches}

    block_categories = {
        "DESTRUCTIVE_COMMAND",
        "UNSAFE_NETWORK_EXECUTION",
        "NETWORK_EXFILTRATION",
        "SECURITY_CONTROL_DISABLE"
    }

    approval_categories = {
        "PRIVILEGE_ESCALATION",
        "SECRET_LEAKAGE",
        "PACKAGE_INSTALLATION",
        "CONTAINER_ESCAPE_RISK"
    }

    if categories.intersection(block_categories):
        return "BLOCK"

    if risk_score >= 80:
        return "BLOCK"

    if categories.intersection(approval_categories):
        return "REQUIRE_APPROVAL"

    if risk_score >= 50:
        return "REQUIRE_APPROVAL"

    if risk_score >= 21:
        return "WARN"

    return "ALLOW"


def build_explanation(decision: str, risk_score: int, matches: List[RuleMatch], command_chain_detected: bool) -> str:
    """
    Generate a readable explanation for the user.
    """
    if not matches and not command_chain_detected:
        return "No risky command patterns were detected."

    explanation_parts = []

    if command_chain_detected:
        explanation_parts.append(
            "Command chaining or piping was detected, which can hide multiple actions in a single command."
        )

    for match in matches:
        explanation_parts.append(match.reason)

    return f"Decision: {decision}. Risk score: {risk_score}. " + " ".join(sorted(set(explanation_parts)))


def analyze_command(command: str) -> CommandScanResponse:
    """
    Main command analyzer.
    """
    normalized_command = normalize_command(command)
    detected_shell = detect_shell(normalized_command)
    command_chain_detected = has_command_chaining(normalized_command)

    matches = find_command_matches(normalized_command)
    matches.extend(find_secret_rule_matches(normalized_command))

    risk_score = calculate_command_risk_score(matches, command_chain_detected)
    decision = decide_command(risk_score, matches)

    categories = sorted(list({match.category for match in matches}))
    reasons = sorted(list({match.reason for match in matches}))

    explanation = build_explanation(
        decision=decision,
        risk_score=risk_score,
        matches=matches,
        command_chain_detected=command_chain_detected
    )

    return CommandScanResponse(
        input_type="command",
        command=normalized_command,
        detected_shell=detected_shell,
        command_chain_detected=command_chain_detected,
        decision=decision,
        risk_score=risk_score,
        categories=categories,
        reasons=reasons,
        matched_rules=matches,
        explanation=explanation
    )