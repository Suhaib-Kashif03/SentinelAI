# Threat Model

## Assets

SentinelAI is designed to protect:

- API keys
- SSH private keys
- GitHub tokens
- AWS credentials
- Database URLs
- Environment variables
- Source code
- Local files
- System integrity
- Developer trust in AI-generated outputs

---

## Threat Actors

| Threat Actor | Description |
|---|---|
| Malicious prompt author | Creates prompts designed to override AI behavior |
| Compromised documentation | Contains hidden prompt injection instructions |
| Careless developer | Copies AI-generated commands without review |
| Over-permissive AI assistant | Suggests unsafe or destructive actions |
| Malicious package/script provider | Tricks users into installing or executing remote code |

---

## Threats

| Threat | Example | Impact |
|---|---|---|
| Prompt Injection | Ignore previous instructions | Model manipulation |
| Secret Leakage | Paste `.env` into prompt | Credential exposure |
| Destructive Command | `rm -rf /` | Data loss |
| Remote Script Execution | `curl URL | bash` | Malware execution |
| Unsafe Permissions | `chmod -R 777 /` | Security weakening |
| Insecure Code | `eval(user_input)` | Code execution vulnerability |
| Reconnaissance | `whoami`, `hostname`, `nmap` | Information gathering |
| Security Control Disable | `ufw disable` | Reduced protection |

---

## Trust Boundaries

```text
User Input
   ↓ trust boundary
SentinelAI Scanner
   ↓ trust boundary
Local LLM
   ↓ trust boundary
Response Scanner
   ↓ trust boundary
User / Agent Workflow
```

## Security Controls

| Control          | Purpose                                    |
| ---------------- | ------------------------------------------ |
| Prompt scanning  | Prevent prompt injection before LLM access |
| Secret detection | Prevent credential exposure                |
| Command analysis | Prevent unsafe terminal actions            |
| Policy engine    | Make decisions configurable                |
| Audit logging    | Preserve investigation evidence            |
| Redaction        | Avoid storing raw secrets                  |
| Agent simulation | Review AI-suggested commands safely        |


## Assumptions
- SentinelAI runs locally.
- The user routes AI-assisted workflows through SentinelAI.
- Commands are reviewed, not executed.
- Test secrets are fake.
- Version 1 is rule-based and explainable.

## Out of Scope
- Malware sandboxing
- Full EDR behavior monitoring
- Enterprise authentication
- Real IDE plugin enforcement
- Kernel-level command blocking
- Full DLP coverage