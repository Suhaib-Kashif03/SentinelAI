# Future Work

The following improvements can make SentinelAI more advanced and production-like.

## 1. VS Code Extension

Build a VS Code extension that sends AI-generated commands and code snippets to SentinelAI before execution.

## 2. PyCharm Plugin

Add PyCharm integration for Python-focused development workflows.

## 3. Terminal Wrapper

Create a local command wrapper that intercepts commands before execution.

Example:

```bash
sentinel run "curl http://example.com/install.sh | bash"
```

## 4. Semantic Prompt Injection Detection

Use embeddings or a small classifier to detect hidden prompt injection beyond regex patterns.

## 5. MITRE ATLAS Mapping

Map AI-related risks to MITRE ATLAS techniques.

## 6. MITRE ATT&CK Mapping

Map command behaviors such as reconnaissance, privilege escalation, and exfiltration to MITRE ATT&CK tactics.

## 7. Multi-Provider LLM Support

Add optional support for Gemini, OpenAI-compatible APIs, and local OpenAI-compatible servers.

## 8. Role-Based Policies

Add policy profiles for:

- Student mode
- Developer mode
- Enterprise mode
- SOC mode
- Strict mode

## 9. Docker Deployment

Containerize the backend and dashboard for easier deployment.

## 10. PDF/HTML Report Export

Allow users to export audit logs and evaluation reports as professional security reports.

## 11. Advanced Secret Detection

Add entropy-based secret detection and integration with tools like Gitleaks-style scanning.

## 12. Human Approval Workflow

Create an approval queue for risky commands.

## 13. Real-Time Dashboard Updates

Use WebSockets to update the dashboard as events happen.