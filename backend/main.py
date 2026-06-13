from fastapi import FastAPI

from backend.models import ScanRequest, ScanResponse
from backend.scanner import scan_text


app = FastAPI(
    title="SentinelAI",
    description="Local AI Security Gateway for scanning prompts, LLM responses, code, and commands.",
    version="0.1.0"
)


@app.get("/")
def root():
    return {
        "project": "SentinelAI",
        "status": "running",
        "message": "Local AI Security Gateway API is active."
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.post("/scan/prompt", response_model=ScanResponse)
def scan_prompt(request: ScanRequest):
    """
    Scan a user prompt before sending it to an LLM.
    """
    return scan_text(
        content=request.content,
        input_type="prompt"
    )


@app.post("/scan/response", response_model=ScanResponse)
def scan_response(request: ScanRequest):
    """
    Scan an LLM response before showing it to the user or executing suggested actions.
    """
    return scan_text(
        content=request.content,
        input_type="response"
    )