# SentinelAI Project Summary

## Project Title

SentinelAI: Local AI Security Gateway for LLM and IDE Agent Workflows

## One-Line Description

SentinelAI is a local cybersecurity gateway that scans prompts, LLM responses, generated commands, and configuration content to prevent prompt injection, secret leakage, destructive commands, and unsafe AI-assisted development behavior.

## Problem

AI coding assistants and local LLM agents can generate unsafe outputs such as destructive commands, leaked credentials, insecure code, and risky system instructions. Developers may trust these outputs without properly reviewing their security impact.

## Solution

SentinelAI acts as a local security layer between the user and the AI assistant. It scans inputs and outputs, applies a YAML-based security policy, logs decisions, and provides a dashboard for monitoring.

## Core Features

- Prompt injection detection
- Secret leakage detection
- Command risk analysis
- Unsafe code detection
- Secure local LLM chat
- IDE/terminal agent simulation
- Audit logging
- Streamlit dashboard
- Evaluation reporting

## Skills Demonstrated

- Python backend development
- FastAPI API design
- Local LLM integration with Ollama
- Security rule engineering
- Policy-as-code
- SQLite audit logging
- Dashboard development
- Threat modeling
- Evaluation and reporting