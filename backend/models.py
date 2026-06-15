from typing import List, Literal, Optional, Dict, Any
from pydantic import BaseModel, Field


DecisionType = Literal["ALLOW", "WARN", "REQUIRE_APPROVAL", "BLOCK"]


class ScanRequest(BaseModel):
    content: str = Field(
        ...,
        min_length=1,
        description="Text content to scan. This can be a prompt, LLM response, code block, command, or configuration snippet."
    )


class RuleMatch(BaseModel):
    rule_id: str
    category: str
    severity: str
    score: int
    matched_text: str
    reason: str


class ScanResponse(BaseModel):
    input_type: str
    decision: DecisionType
    risk_score: int
    categories: List[str]
    reasons: List[str]
    matched_rules: List[RuleMatch]


class CommandScanResponse(ScanResponse):
    command: str
    detected_shell: Optional[str] = None
    command_chain_detected: bool = False
    explanation: str


class SecretMatch(BaseModel):
    rule_id: str
    secret_type: str
    severity: str
    score: int
    masked_value: str
    start_index: int
    end_index: int
    reason: str


class SecretScanResponse(BaseModel):
    input_type: str
    decision: DecisionType
    risk_score: int
    categories: List[str]
    reasons: List[str]
    secrets_found: List[SecretMatch]
    redacted_content: str


class AuditEvent(BaseModel):
    id: int
    timestamp: str
    input_type: str
    decision: str
    risk_score: int
    categories: List[str]
    reasons: List[str]
    matched_rules: List[Dict[str, Any]]
    redacted_content: str
    content_preview: str
    content_hash: str
    command: Optional[str] = None
    detected_shell: Optional[str] = None
    command_chain_detected: bool = False


class AuditStats(BaseModel):
    total_events: int
    decisions: Dict[str, int]
    input_types: Dict[str, int]
    categories: Dict[str, int]
    high_risk_events: int
    latest_event_timestamp: Optional[str] = None


class SecureLLMRequest(BaseModel):
    prompt: str = Field(
        ...,
        min_length=1,
        description="User prompt to scan before sending to the local LLM."
    )
    model: str = Field(
        default="qwen3:8b",
        description="Ollama model name."
    )
    provider: str = Field(
        default="ollama",
        description="LLM provider. Phase 8 supports ollama."
    )


class SecureLLMResponse(BaseModel):
    provider: str
    model: str
    final_decision: DecisionType
    prompt_scan: ScanResponse
    response_scan: Optional[ScanResponse] = None
    llm_response: Optional[str] = None
    blocked_stage: Optional[str] = None
    explanation: str

class AgentRequest(BaseModel):
    prompt: str = Field(
        ...,
        min_length=1,
        description="User request for the simulated IDE/terminal agent."
    )
    model: str = Field(
        default="qwen3:8b",
        description="Ollama model name."
    )
    provider: str = Field(
        default="ollama",
        description="LLM provider. Phase 9 supports ollama."
    )


class CommandReview(BaseModel):
    command: str
    analysis: CommandScanResponse


class AgentSimulationResponse(BaseModel):
    provider: str
    model: str
    final_decision: DecisionType
    prompt_scan: ScanResponse
    llm_response: Optional[str] = None
    response_scan: Optional[ScanResponse] = None
    extracted_commands: List[CommandReview]
    blocked_stage: Optional[str] = None
    explanation: str