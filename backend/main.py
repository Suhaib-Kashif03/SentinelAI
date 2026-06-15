from typing import Optional

from fastapi import FastAPI, HTTPException, Query

from backend.models import (
    ScanRequest,
    ScanResponse,
    CommandScanResponse,
    SecretScanResponse,
    SecureLLMRequest,
    SecureLLMResponse,
    AgentRequest,
    AgentSimulationResponse
)
from backend.scanner import scan_text
from backend.command_analyzer import analyze_command
from backend.secret_detector import scan_secrets
from backend.policy_engine import get_policy_summary
from backend.secure_llm_service import secure_chat
from backend.llm_connector import LLMConnectionError
from backend.models import AgentRequest, AgentSimulationResponse
from backend.agent_simulator import simulate_agent
from backend.audit_logger import (
    init_db,
    log_scan_event,
    list_audit_events,
    get_audit_event,
    get_audit_stats
)


app = FastAPI(
    title="SentinelAI",
    description="Local AI Security Gateway for scanning prompts, LLM responses, code, commands, and secrets.",
    version="0.7.0"
)


@app.on_event("startup")
def startup_event():
    """
    Initialize database when API starts.
    """
    init_db()


@app.get("/")
def root():
    return {
        "project": "SentinelAI",
        "version": "0.7.0",
        "status": "running",
        "message": "Local AI Security Gateway API is active."
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.get("/policy")
def view_active_policy():
    """
    View the currently loaded SentinelAI security policy.
    """
    return get_policy_summary()


@app.get("/audit/events")
def view_audit_events(
    limit: int = Query(default=50, ge=1, le=200),
    decision: Optional[str] = Query(default=None),
    input_type: Optional[str] = Query(default=None)
):
    """
    View recent audit events.

    Optional filters:
    - decision=BLOCK
    - input_type=command
    """
    return {
        "events": list_audit_events(
            limit=limit,
            decision=decision,
            input_type=input_type
        )
    }


@app.get("/audit/events/{event_id}")
def view_single_audit_event(event_id: int):
    """
    View a single audit event by ID.
    """
    event = get_audit_event(event_id)

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="Audit event not found."
        )

    return event


@app.get("/audit/stats")
def view_audit_stats():
    """
    View audit summary statistics.
    """
    return get_audit_stats()


@app.post("/llm/secure-chat", response_model=SecureLLMResponse)
def secure_llm_chat(request: SecureLLMRequest):
    """
    Securely send a prompt to a local LLM through SentinelAI.

    Flow:
    - Scan prompt before LLM
    - Send safe prompt to Ollama
    - Scan LLM response
    - Return safe response or block
    """
    try:
        return secure_chat(request)

    except LLMConnectionError as error:
        raise HTTPException(
            status_code=503,
            detail=str(error)
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


@app.post("/scan/prompt", response_model=ScanResponse)
def scan_prompt(request: ScanRequest):
    """
    Scan a user prompt before sending it to an LLM.
    """
    result = scan_text(
        content=request.content,
        input_type="prompt"
    )

    log_scan_event(
        original_content=request.content,
        scan_result=result
    )

    return result


@app.post("/scan/response", response_model=ScanResponse)
def scan_response(request: ScanRequest):
    """
    Scan an LLM response before showing it to the user or executing suggested actions.
    """
    result = scan_text(
        content=request.content,
        input_type="response"
    )

    log_scan_event(
        original_content=request.content,
        scan_result=result
    )

    return result


@app.post("/scan/command", response_model=CommandScanResponse)
def scan_command(request: ScanRequest):
    """
    Analyze a terminal command before execution.
    """
    result = analyze_command(
        command=request.content
    )

    log_scan_event(
        original_content=request.content,
        scan_result=result
    )

    return result


@app.post("/scan/secrets", response_model=SecretScanResponse)
def scan_secret_content(request: ScanRequest):
    """
    Detect and redact secrets in text, code, configuration files, or command output.
    """
    result = scan_secrets(
        content=request.content,
        input_type="secrets"
    )

    log_scan_event(
        original_content=request.content,
        scan_result=result
    )

    return result

@app.post("/agent/simulate", response_model=AgentSimulationResponse)
def simulate_ide_terminal_agent(request: AgentRequest):
    """
    Simulate an AI IDE/terminal agent.

    The agent may suggest commands, but SentinelAI reviews them.
    Commands are not executed.
    """
    try:
        return simulate_agent(request)

    except LLMConnectionError as error:
        raise HTTPException(
            status_code=503,
            detail=str(error)
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )