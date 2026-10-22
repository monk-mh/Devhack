"""
PrivacyShield AI — FastAPI Backend Server
Problem Statement: DEVHOST 2026 - PS 2.2

Exposes endpoints for context-aware data privacy scanning, dynamic policy enforcement,
and downstream LLM reasoning simulation.
"""

from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from privacy_engine import scan_and_sanitize, simulate_llm_response, surrogate_store

# ──────────────────────────────────────────────────────────────────────────────
# APPLICATION INITIALIZATION
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Context-Aware Data Privacy Guard API",
    description="Intelligent privacy protection engine with dynamic contextual policies (PASS, MASK, PSEUDONYMIZE, REDACT).",
    version="2.2.0"
)

# Enable CORS for cross-origin frontend support
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────────────────────
# REQUEST & RESPONSE SCHEMAS
# ──────────────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    text: str = Field(..., description="Raw input text to scan and sanitize")

class TelemetryItem(BaseModel):
    entity_type: str
    value: str
    start: int
    end: int
    risk_tier: str
    action: str
    category: str
    replacement: str
    reason: str

class StatsModel(BaseModel):
    total: int
    pass_count: int = Field(alias="pass")
    mask: int
    pseudonymize: int
    redact: int

    class Config:
        populate_by_name = True

class ScanResponse(BaseModel):
    original_text: str
    sanitized_text: str
    telemetry: List[TelemetryItem]
    stats: Dict[str, int]

class SimulateLLMRequest(BaseModel):
    sanitized_text: str = Field(..., description="Sanitized text forwarded to the LLM")
    query: Optional[str] = Field("Summarize the request and action items safely.", description="Instruction or question for the downstream LLM")

class SimulateLLMResponse(BaseModel):
    query: str
    sanitized_input: str
    llm_response: str
    privacy_guarantee: str

# ──────────────────────────────────────────────────────────────────────────────
# PRESET BENCHMARK DATA
# ──────────────────────────────────────────────────────────────────────────────

BENCHMARK_PRESETS = [
    {
        "id": "preset_1",
        "title": "Preset 1: Public Contact (PASS)",
        "category": "PUBLIC_BUSINESS",
        "expected_action": "PASS",
        "text": "For any inquiries or enterprise sales questions, please reach out to Alice at alice@acme.com."
    },
    {
        "id": "preset_2",
        "title": "Preset 2: Confidential Health (PSEUDONYMIZE)",
        "category": "HEALTH_CONFIDENTIAL",
        "expected_action": "PSEUDONYMIZE",
        "text": "Please note that Alice at alice@acme.com was diagnosed with leukemia and will begin chemotherapy treatment tomorrow."
    },
    {
        "id": "preset_3",
        "title": "Preset 3: Internal Financial (REDACT)",
        "category": "FINANCIAL_INTERNAL",
        "expected_action": "REDACT",
        "text": "Finance team: Rahul's Q4 appraisal bonus of $18,500 has been transferred to his account ending in 4102."
    },
    {
        "id": "preset_4",
        "title": "Preset 4: Generic PII (MASK)",
        "category": "GENERAL_PII",
        "expected_action": "MASK",
        "text": "Call me on 9845012345 when you arrive at the gate."
    }
]

# ──────────────────────────────────────────────────────────────────────────────
# API ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Context-Aware Data Privacy Guard",
        "problem_statement": "DEVHOST 2026 - PS 2.2",
        "active_surrogates": len(surrogate_store.get_all_mappings())
    }

@app.get("/api/presets")
def get_presets():
    """Returns official benchmark demonstration presets."""
    return {"presets": BENCHMARK_PRESETS}

@app.post("/api/scan", response_model=ScanResponse)
def scan_endpoint(payload: ScanRequest):
    """
    Scans input text, determines semantic context per entity candidate,
    and applies PASS, MASK, PSEUDONYMIZE, or REDACT policies.
    """
    if not payload.text:
        raise HTTPException(status_code=400, detail="Input text cannot be empty.")

    result = scan_and_sanitize(payload.text)
    return result

@app.post("/api/simulate-llm", response_model=SimulateLLMResponse)
def simulate_llm_endpoint(payload: SimulateLLMRequest):
    """
    Simulates a downstream safe LLM response showing that reasoning is preserved
    without exposing raw sensitive information.
    """
    result = simulate_llm_response(payload.sanitized_text, payload.query)
    return result

@app.get("/api/surrogates")
def get_surrogates():
    """Returns active reversible surrogate mappings for authorized de-anonymization."""
    return {"surrogates": surrogate_store}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
