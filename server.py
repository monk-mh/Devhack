"""
ContextGuard — FastAPI Backend Server
Problem Statement: DEVHOST 2026 - PS 2.2 | Team: Error404
St Joseph Engineering College, Vamanjoor Mangalore
"""

from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from privacy_engine import evaluate_and_enforce, simulate_llm_response, ROLES, CATEGORIES, ROLE_POLICY_MATRIX

app = FastAPI(
    title="ContextGuard API — Privacy Firewall for AI",
    description="Context-Aware Data Privacy Firewall enforcing role-based clearance (Intern, Manager, HR) across 7 sensitivity categories.",
    version="2.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EvaluateRequest(BaseModel):
    text: str = Field(..., description="Raw input text to evaluate and enforce")
    role: Optional[str] = Field("Manager", description="Viewer role: Manager or HR")

class AuditItem(BaseModel):
    detected_text: str
    category: str
    description: str
    detector: str
    role: str
    action: str
    reason: str

class EvaluateResponse(BaseModel):
    original_text: str
    sanitized_text: str
    overall_status: str
    audit_log: List[AuditItem]
    stats: Dict[str, int]

class SimulateAIRequest(BaseModel):
    sanitized_text: str
    query: Optional[str] = "Process request safely."

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "ContextGuard Privacy Firewall",
        "team": "Error404",
        "college": "St Joseph Engineering College, Vamanjoor Mangalore",
        "problem_statement": "DEVHOST 2026 - PS 2.2"
    }

@app.get("/api/matrix")
def get_clearance_matrix():
    return {
        "roles": ROLES,
        "categories": CATEGORIES,
        "matrix": ROLE_POLICY_MATRIX
    }

@app.post("/api/evaluate", response_model=EvaluateResponse)
def evaluate_endpoint(payload: EvaluateRequest):
    if not payload.text:
        raise HTTPException(status_code=400, detail="Input text cannot be empty.")
    return evaluate_and_enforce(payload.text, role=payload.role)

@app.post("/api/simulate-ai")
def simulate_ai_endpoint(payload: SimulateAIRequest):
    return simulate_llm_response(payload.sanitized_text, payload.query)

# Backwards compatibility endpoint
@app.post("/api/scan")
def scan_endpoint(payload: EvaluateRequest):
    return evaluate_and_enforce(payload.text, role=payload.role)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
