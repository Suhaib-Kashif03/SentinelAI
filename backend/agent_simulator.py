import re
from typing import List

from backend.audit_logger import log_scan_event
from backend.command_analyzer import analyze_command
from backend.llm_connector import call_ollama
from backend.models import (
    AgentRequest,
    AgentSimulationResponse,
    CommandReview
)
from backend.policy_engine import strongest_decision
from backend.scanner import scan_text


COMMAND_LANGUAGES = {
    "bash",
    "sh",
    "shell",
    "zsh",
    "powershell",
    "ps1",
    "cmd",
    "bat",
    "batch"
}


def build_agent_prompt(user_prompt: str) -> str:
    """
    Prompt used for IDE/terminal agent simulation.
    The model may suggest commands, but SentinelAI will review them.
    """
    return f"""
You are simulating an AI coding assistant inside an IDE.

The user asked:
{user_prompt}

Give a helpful answer. If commands are useful, put each command in a separate fenced code block.
Do not execute anything. Only suggest commands.
Prefer safe commands and explain risks when commands may be dangerous.
"""


def extract_fenced_commands(text: str) -> List[str]:
    """
    Extract commands from fenced code blocks such as:

    ```bash
    pip install flask
    ```
    """
    commands: List[str] = []

    fenced_pattern = r"```(\w+)?\s*([\s\S]*?)```"
    matches = re.finditer(fenced_pattern, text, flags=re.MULTILINE)

    for match in matches:
        language = (match.group(1) or "").lower().strip()
        code = match.group(2).strip()

        if language in COMMAND_LANGUAGES:
            for line in code.splitlines():
                cleaned = line.strip()

                if cleaned and not cleaned.startswith("#"):
                    commands.append(cleaned)

    return commands


def extract_inline_commands(text: str) -> List[str]:
    """
    Best-effort extraction of inline commands from normal text.

    This catches lines like:
    $ pip install flask
    > npm install
    Run: python app.py
    """
    commands: List[str] = []

    command_starters = (
        "pip ",
        "pip3 ",
        "python ",
        "python3 ",
        "npm ",
        "yarn ",
        "pnpm ",
        "git ",
        "docker ",
        "kubectl ",
        "curl ",
        "wget ",
        "sudo ",
        "rm ",
        "cat ",
        "type ",
        "dir",
        "ls",
        "cd ",
        "uvicorn ",
        "streamlit "
    )

    for line in text.splitlines():
        cleaned = line.strip()

        if not cleaned:
            continue

        if cleaned.startswith("$ "):
            commands.append(cleaned[2:].strip())
            continue

        if cleaned.startswith("> "):
            commands.append(cleaned[2:].strip())
            continue

        lowered = cleaned.lower()

        if lowered.startswith("run:"):
            possible_command = cleaned.split(":", 1)[1].strip()
            if possible_command:
                commands.append(possible_command)
            continue

        if lowered.startswith(command_starters):
            commands.append(cleaned)

    return commands


def deduplicate_commands(commands: List[str]) -> List[str]:
    seen = set()
    unique_commands = []

    for command in commands:
        normalized = command.strip()

        if normalized and normalized not in seen:
            seen.add(normalized)
            unique_commands.append(normalized)

    return unique_commands


def extract_commands(text: str) -> List[str]:
    """
    Extract command suggestions from LLM output.
    """
    commands = []
    commands.extend(extract_fenced_commands(text))
    commands.extend(extract_inline_commands(text))

    return deduplicate_commands(commands)


def simulate_agent(request: AgentRequest) -> AgentSimulationResponse:
    """
    Simulate an IDE/terminal AI agent safely.

    No commands are executed.
    SentinelAI only reviews suggested commands.
    """

    if request.provider.lower() != "ollama":
        raise ValueError("Phase 9 currently supports only the ollama provider.")

    prompt_scan = scan_text(
        content=request.prompt,
        input_type="agent_prompt"
    )

    log_scan_event(
        original_content=request.prompt,
        scan_result=prompt_scan
    )

    if prompt_scan.decision == "BLOCK":
        return AgentSimulationResponse(
            provider=request.provider,
            model=request.model,
            final_decision="BLOCK",
            prompt_scan=prompt_scan,
            llm_response=None,
            response_scan=None,
            extracted_commands=[],
            blocked_stage="prompt",
            explanation="The agent request was blocked before reaching the LLM."
        )

    agent_prompt = build_agent_prompt(request.prompt)

    llm_response = call_ollama(
        prompt=agent_prompt,
        model=request.model
    )

    response_scan = scan_text(
        content=llm_response,
        input_type="agent_response"
    )

    log_scan_event(
        original_content=llm_response,
        scan_result=response_scan
    )

    suggested_commands = extract_commands(llm_response)

    command_reviews: List[CommandReview] = []

    for command in suggested_commands:
        analysis = analyze_command(command)

        log_scan_event(
            original_content=command,
            scan_result=analysis
        )

        command_reviews.append(
            CommandReview(
                command=command,
                analysis=analysis
            )
        )

    command_decisions = [
        review.analysis.decision
        for review in command_reviews
    ]

    decisions = [prompt_scan.decision]

    if response_scan:
        decisions.append(response_scan.decision)

    decisions.extend(command_decisions)

    final_decision = strongest_decision(decisions)

    if final_decision == "BLOCK":
        explanation = "One or more parts of the agent workflow were blocked by SentinelAI."
    elif final_decision == "REQUIRE_APPROVAL":
        explanation = "The agent workflow contains actions that require human approval."
    elif final_decision == "WARN":
        explanation = "The agent workflow is allowed with warnings."
    else:
        explanation = "The agent workflow appears safe. No risky command patterns were detected."

    return AgentSimulationResponse(
        provider=request.provider,
        model=request.model,
        final_decision=final_decision,
        prompt_scan=prompt_scan,
        llm_response=llm_response,
        response_scan=response_scan,
        extracted_commands=command_reviews,
        blocked_stage=None,
        explanation=explanation
    )