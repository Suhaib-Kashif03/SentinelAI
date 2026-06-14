from typing import List, Literal, Optional
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