# SentinelAI Architecture

## Overview

SentinelAI is designed as a local security gateway for AI-assisted development workflows. It reviews prompts, LLM responses, generated commands, code snippets, and secrets before they are trusted or used.

## Main Components

### 1. FastAPI Backend

The backend exposes APIs for scanning prompts, responses, commands, secrets, secure LLM chat, and agent simulation.

### 2. Prompt Scanner

Detects prompt injection, jailbreak attempts, instruction override patterns, and secret leakage before a prompt reaches the model.

### 3. Response Scanner

Scans LLM output for unsafe code, leaked credentials, dangerous instructions, and suspicious command suggestions.

### 4. Command Analyzer

Evaluates terminal commands before execution. It detects destructive commands, unsafe network execution, secret file access, privilege escalation, reconnaissance, package installation, and risky Docker usage.

### 5. Secret Detector

Detects and redacts secrets such as API keys, GitHub tokens, AWS keys, JWTs, database URLs, private keys, and password assignments.

### 6. Policy Engine

Applies YAML-based decision logic. Categories are mapped to actions such as `ALLOW`, `WARN`, `REQUIRE_APPROVAL`, or `BLOCK`.

### 7. Audit Logger

Stores scan decisions in SQLite. Raw secrets are not stored directly. SentinelAI stores redacted content and SHA-256 hashes.

### 8. Ollama Connector

Sends safe prompts to a local Ollama model and returns the response for scanning.

### 9. Agent Simulator

Simulates an IDE or terminal AI agent. It extracts suggested commands from LLM responses and reviews them without executing them.

### 10. Streamlit Dashboard

Visualizes scan statistics, audit events, policy configuration, secure LLM chat results, agent simulation results, and evaluation metrics.

---

## Data Flow

```text
User Input
   ↓
Scanner / Analyzer
   ↓
Rule Matches
   ↓
Risk Score
   ↓
Policy Engine
   ↓
Final Decision
   ↓
Audit Logger
   ↓
Dashboard
```

## Secure LLM Flow

```text
User Prompt
   ↓
Prompt Scanner
   ↓
Policy Decision
   ↓
Ollama Local LLM
   ↓
Response Scanner
   ↓
Policy Decision
   ↓
Final Safe Response
```

## Agent Simulation Flow

```text
User Request
   ↓
Prompt Scanner
   ↓
Ollama Agent Response
   ↓
Command Extraction
   ↓
Command Analyzer
   ↓
Final Workflow Decision
```

## Design Principles
- Local-first operation
- Privacy-aware scanning
- No raw secret storage
- Explainable rule-based detection
- Policy-driven decisions
- Human-in-the-loop approval
- Safe simulation instead of command execution