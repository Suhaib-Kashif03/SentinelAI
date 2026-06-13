from typing import List, Literal
from pydantic import BaseModel, Field


DecisionType = Literal["ALLOW", "WARN", "REQUIRE_APPROVAL", "BLOCK"]


class ScanRequest(BaseModel):
    content: str = Field(
        ...,
        min_length=1,
        description="Text content to scan. This can be a prompt, LLM response, code block, or command suggestion."
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