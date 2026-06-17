# Limitations

SentinelAI is a defensive security project, but it has limitations.

## 1. Rule-Based Detection

SentinelAI mainly uses regex and rule-based detection. This is explainable and fast, but it may miss obfuscated attacks.

Example:

```bash
r''m -r''f /
```

A simple pattern may not detect all variations.

## 2. False Positives

Some legitimate security or administration commands may be flagged.

Example:

```bash
whoami
```

This can be normal, but it is also commonly used during reconnaissance.

## 3. False Negatives

A risky prompt or command may bypass detection if it does not match existing rules.

## 4. No Real IDE Plugin Yet

The IDE/terminal agent workflow is currently simulated. SentinelAI does not yet integrate directly with VS Code, PyCharm, or a real shell wrapper.

## 5. No Command Execution Control

SentinelAI reviews commands but does not enforce operating-system-level blocking.

## 6. Local LLM Limitations

The quality of /llm/secure-chat and /agent/simulate depends on the selected Ollama model.

## 7. No Advanced Semantic Detection Yet

SentinelAI does not yet use embeddings or ML-based semantic analysis for hidden prompt injection or intent detection.

## 8. Not a Replacement for EDR

SentinelAI is not an endpoint detection and response system. It is focused on AI-assisted development workflows.

## 9. Not a Complete DLP System

The secret detection engine covers many common secret types, but it is not a full enterprise data loss prevention product.