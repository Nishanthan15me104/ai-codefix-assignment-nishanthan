import json
import logging
from fastapi import APIRouter
# CRITICAL FIX: Changing to direct absolute import to resolve persistent 
# module-loading conflicts and NameErrors.
from app.models import FixRequest, FixResponse, TokenUsage 
from app.llm_service import run_inference, MODEL_NAME

# Initialize logging for this module
logger = logging.getLogger(__name__)

# Create an APIRouter instance
router = APIRouter()

@router.post("/local_fix", response_model=FixResponse)
async def local_fix(request: FixRequest):
    """Analyzes vulnerable code and returns a secure fix, diff, and explanation."""
    
    # Run the core inference logic
    parsed_result, input_tokens, output_tokens, latency_ms = run_inference(
        request.language, 
        request.cwe, 
        request.code
    )
    
    # 1. Log metrics (Mandatory Requirement C)
    log_entry = {
        "model": MODEL_NAME,
        "language": request.language,
        "cwe": request.cwe,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "latency_ms": f"{latency_ms:.2f}ms",
        "status": "Success"
    }
    logger.info(f"Remediation Log: {json.dumps(log_entry)}")

    # 2. Return the structured response
    # Reference TokenUsage and FixResponse directly from the imported namespace
    return FixResponse(
        fixed_code=parsed_result["fixed_code"],
        diff=parsed_result["diff"],
        explanation=parsed_result["explanation"],
        model_used=MODEL_NAME,
        token_usage=TokenUsage(input_tokens=input_tokens, output_tokens=output_tokens),
        latency_ms=latency_ms
    )