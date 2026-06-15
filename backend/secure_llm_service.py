from backend.audit_logger import log_scan_event
from backend.llm_connector import call_ollama
from backend.models import SecureLLMRequest, SecureLLMResponse
from backend.scanner import scan_text


def secure_chat(request: SecureLLMRequest) -> SecureLLMResponse:
    """
    Secure LLM flow:

    1. Scan prompt.
    2. Block if prompt is unsafe.
    3. Send safe prompt to Ollama.
    4. Scan LLM response.
    5. Block unsafe response if needed.
    6. Log all security decisions.
    """

    if request.provider.lower() != "ollama":
        raise ValueError("Phase 8 currently supports only the ollama provider.")

    prompt_scan = scan_text(
        content=request.prompt,
        input_type="llm_prompt"
    )

    log_scan_event(
        original_content=request.prompt,
        scan_result=prompt_scan
    )

    if prompt_scan.decision == "BLOCK":
        return SecureLLMResponse(
            provider=request.provider,
            model=request.model,
            final_decision="BLOCK",
            prompt_scan=prompt_scan,
            response_scan=None,
            llm_response=None,
            blocked_stage="prompt",
            explanation="The user prompt was blocked before being sent to the local LLM."
        )

    llm_response = call_ollama(
        prompt=request.prompt,
        model=request.model
    )

    response_scan = scan_text(
        content=llm_response,
        input_type="llm_response"
    )

    log_scan_event(
        original_content=llm_response,
        scan_result=response_scan
    )

    if response_scan.decision == "BLOCK":
        return SecureLLMResponse(
            provider=request.provider,
            model=request.model,
            final_decision="BLOCK",
            prompt_scan=prompt_scan,
            response_scan=response_scan,
            llm_response=None,
            blocked_stage="response",
            explanation="The LLM response was blocked because SentinelAI detected unsafe content."
        )

    if response_scan.decision == "REQUIRE_APPROVAL":
        return SecureLLMResponse(
            provider=request.provider,
            model=request.model,
            final_decision="REQUIRE_APPROVAL",
            prompt_scan=prompt_scan,
            response_scan=response_scan,
            llm_response=llm_response,
            blocked_stage=None,
            explanation="The LLM response requires human approval before use."
        )

    if response_scan.decision == "WARN":
        return SecureLLMResponse(
            provider=request.provider,
            model=request.model,
            final_decision="WARN",
            prompt_scan=prompt_scan,
            response_scan=response_scan,
            llm_response=llm_response,
            blocked_stage=None,
            explanation="The LLM response was returned with a warning."
        )

    return SecureLLMResponse(
        provider=request.provider,
        model=request.model,
        final_decision="ALLOW",
        prompt_scan=prompt_scan,
        response_scan=response_scan,
        llm_response=llm_response,
        blocked_stage=None,
        explanation="The prompt and LLM response passed SentinelAI security checks."
    )