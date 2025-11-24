from pydantic import BaseModel

class FixRequest(BaseModel):
    """Input schema for the /local_fix endpoint."""
    language: str
    cwe: str
    code: str

class TokenUsage(BaseModel):
    """Schema for token count metrics."""
    input_tokens: int
    output_tokens: int

class FixResponse(BaseModel):
    """Output schema for the /local_fix endpoint, used across the application."""
    fixed_code: str
    diff: str
    explanation: str
    model_used: str
    token_usage: TokenUsage
    latency_ms: float