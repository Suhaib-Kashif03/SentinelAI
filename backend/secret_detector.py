import re
from typing import List, Optional

from backend.models import RuleMatch, SecretMatch, SecretScanResponse


SECRET_PATTERNS = [
    {
        "rule_id": "SECRET-AWS-001",
        "secret_type": "AWS_ACCESS_KEY_ID",
        "severity": "CRITICAL",
        "score": 95,
        "pattern": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        "reason": "Detected possible AWS access key ID."
    },
    {
        "rule_id": "SECRET-AWS-002",
        "secret_type": "AWS_SECRET_ACCESS_KEY",
        "severity": "CRITICAL",
        "score": 95,
        "pattern": r"(?i)\b(?:aws_?secret_?access_?key|aws_secret|secret_access_key)\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "reason": "Detected possible AWS secret access key."
    },
    {
        "rule_id": "SECRET-GITHUB-001",
        "secret_type": "GITHUB_TOKEN",
        "severity": "CRITICAL",
        "score": 95,
        "pattern": r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,255}\b",
        "reason": "Detected possible GitHub token."
    },
    {
        "rule_id": "SECRET-GITHUB-002",
        "secret_type": "GITHUB_FINE_GRAINED_TOKEN",
        "severity": "CRITICAL",
        "score": 95,
        "pattern": r"\bgithub_pat_[A-Za-z0-9_]{20,}_[A-Za-z0-9_]{20,}\b",
        "reason": "Detected possible GitHub fine-grained personal access token."
    },
    {
        "rule_id": "SECRET-GOOGLE-001",
        "secret_type": "GOOGLE_API_KEY",
        "severity": "HIGH",
        "score": 85,
        "pattern": r"\bAIza[0-9A-Za-z\-_]{35}\b",
        "reason": "Detected possible Google API key."
    },
    {
        "rule_id": "SECRET-SLACK-001",
        "secret_type": "SLACK_TOKEN",
        "severity": "HIGH",
        "score": 85,
        "pattern": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        "reason": "Detected possible Slack token."
    },
    {
        "rule_id": "SECRET-JWT-001",
        "secret_type": "JWT",
        "severity": "HIGH",
        "score": 80,
        "pattern": r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        "reason": "Detected possible JSON Web Token."
    },
    {
        "rule_id": "SECRET-PRIVATEKEY-001",
        "secret_type": "PRIVATE_KEY",
        "severity": "CRITICAL",
        "score": 100,
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        "reason": "Detected private key material."
    },
    {
        "rule_id": "SECRET-OPENAI-001",
        "secret_type": "OPENAI_STYLE_API_KEY",
        "severity": "HIGH",
        "score": 85,
        "pattern": r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
        "reason": "Detected possible OpenAI-style API key."
    },
    {
        "rule_id": "SECRET-STRIPE-001",
        "secret_type": "STRIPE_SECRET_KEY",
        "severity": "HIGH",
        "score": 85,
        "pattern": r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b",
        "reason": "Detected possible Stripe secret key."
    },
    {
        "rule_id": "SECRET-DB-001",
        "secret_type": "DATABASE_URL",
        "severity": "HIGH",
        "score": 85,
        "pattern": r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^\s'\"<>]+",
        "reason": "Detected database connection URL that may contain credentials."
    },
    {
        "rule_id": "SECRET-PASSWORD-001",
        "secret_type": "PASSWORD_ASSIGNMENT",
        "severity": "HIGH",
        "score": 80,
        "pattern": r"(?i)\b(?:password|passwd|pwd|db_password|secret|api_key|apikey|access_token|auth_token)\b\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]",
        "reason": "Detected hardcoded password, token, or API key assignment."
    },
    {
        "rule_id": "SECRET-ENV-001",
        "secret_type": "ENV_SECRET_ASSIGNMENT",
        "severity": "HIGH",
        "score": 80,
        "pattern": r"(?i)\b[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_]*\s*=\s*['\"]?([A-Za-z0-9_\-./+=:@]{8,})['\"]?",
        "reason": "Detected environment-style secret assignment."
    }
]


def mask_secret(secret: str) -> str:
    """
    Mask secret values before returning them in API responses.
    This prevents SentinelAI itself from leaking secrets.
    """
    if not secret:
        return "[REDACTED]"

    if "PRIVATE KEY" in secret:
        return "-----BEGIN PRIVATE KEY-----...[REDACTED]...-----END PRIVATE KEY-----"

    if len(secret) <= 8:
        return "*" * len(secret)

    visible_prefix = secret[:4]
    visible_suffix = secret[-4:]
    hidden_length = max(len(secret) - 8, 4)

    return f"{visible_prefix}{'*' * hidden_length}{visible_suffix}"


def get_secret_value(match: re.Match) -> str:
    """
    If a regex uses capture groups, mask the captured secret value.
    Otherwise, mask the full match.
    """
    groups = [group for group in match.groups() if group]

    if groups:
        return groups[-1]

    return match.group(0)


def find_secrets(content: str) -> List[SecretMatch]:
    """
    Detect secrets in content.
    Returned matches contain only masked secret values.
    """
    secrets: List[SecretMatch] = []

    for rule in SECRET_PATTERNS:
        regex_matches = re.finditer(rule["pattern"], content, flags=re.IGNORECASE | re.MULTILINE)

        for match in regex_matches:
            secret_value = get_secret_value(match)
            masked_value = mask_secret(secret_value)

            secrets.append(
                SecretMatch(
                    rule_id=rule["rule_id"],
                    secret_type=rule["secret_type"],
                    severity=rule["severity"],
                    score=rule["score"],
                    masked_value=masked_value,
                    start_index=match.start(),
                    end_index=match.end(),
                    reason=rule["reason"]
                )
            )

    return secrets


def redact_secrets(content: str) -> str:
    """
    Replace detected secret values with masked versions.
    """
    redacted_content = content

    for rule in SECRET_PATTERNS:
        matches = list(re.finditer(rule["pattern"], redacted_content, flags=re.IGNORECASE | re.MULTILINE))

        for match in reversed(matches):
            full_match = match.group(0)
            secret_value = get_secret_value(match)
            masked_value = mask_secret(secret_value)

            if secret_value != full_match:
                redacted_match = full_match.replace(secret_value, masked_value)
            else:
                redacted_match = masked_value

            redacted_content = (
                redacted_content[:match.start()]
                + redacted_match
                + redacted_content[match.end():]
            )

    return redacted_content


def calculate_secret_risk_score(secrets: List[SecretMatch]) -> int:
    """
    Calculate risk score for detected secrets.
    """
    if not secrets:
        return 0

    highest_score = max(secret.score for secret in secrets)
    bonus = min((len(secrets) - 1) * 5, 15)

    return min(highest_score + bonus, 100)


def decide_secret_scan(risk_score: int, secrets: List[SecretMatch]) -> str:
    """
    Decide action for secret scan.
    """
    if not secrets:
        return "ALLOW"

    if risk_score >= 80:
        return "BLOCK"

    if risk_score >= 50:
        return "REQUIRE_APPROVAL"

    if risk_score >= 21:
        return "WARN"

    return "ALLOW"


def scan_secrets(content: str, input_type: str = "secrets") -> SecretScanResponse:
    """
    Main secret scanning function.
    """
    secrets = find_secrets(content)
    risk_score = calculate_secret_risk_score(secrets)
    decision = decide_secret_scan(risk_score, secrets)

    categories = ["SECRET_LEAKAGE"] if secrets else []
    reasons = sorted(list({secret.reason for secret in secrets}))
    redacted_content = redact_secrets(content)

    return SecretScanResponse(
        input_type=input_type,
        decision=decision,
        risk_score=risk_score,
        categories=categories,
        reasons=reasons,
        secrets_found=secrets,
        redacted_content=redacted_content
    )


def find_secret_rule_matches(content: str) -> List[RuleMatch]:
    """
    Convert secret detections into generic RuleMatch objects.

    This allows the normal prompt/response scanner and command analyzer
    to include secret detection results.
    """
    secrets = find_secrets(content)
    rule_matches: List[RuleMatch] = []

    for secret in secrets:
        rule_matches.append(
            RuleMatch(
                rule_id=secret.rule_id,
                category="SECRET_LEAKAGE",
                severity=secret.severity,
                score=secret.score,
                matched_text=secret.masked_value,
                reason=secret.reason
            )
        )

    return rule_matches