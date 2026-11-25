from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any

from app.models import (
    NetworkSegment,
    Resource,
    PolicyRule,
    SecurityGuardrail,
    SimulationRequest,
    SimulationResponse
)
from app.policy_engine import (
    load_network_data,
    load_current_policies,
    load_security_guardrails,
    simulate_policy_change
)

app = FastAPI(
    title="NetImpact Policy Simulation API",
    description="Network Change Impact and Security Risk Analysis Platform - Milestone 1",
    version="1.0.0"
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "message": "Welcome to NetImpact API",
        "docs_url": "/docs",
        "version": "1.0.0",
        "status": "healthy"
    }


@app.get("/api/health")
def health_check():
    return {"status": "ok", "app": "NetImpact Backend"}


@app.get("/api/network-topology")
def get_topology():
    segments, resources = load_network_data()
    return {
        "segments": list(segments.values()),
        "resources": list(resources.values())
    }


@app.get("/api/policies/current", response_model=List[PolicyRule])
def get_current_policies():
    return load_current_policies()


@app.get("/api/security-guardrails", response_model=List[SecurityGuardrail])
def get_guardrails():
    return load_security_guardrails()


def _validate_and_simulate(request: SimulationRequest) -> SimulationResponse:
    """Validates source segment and destination resource, then runs the policy engine."""
    segments, resources = load_network_data()

    if request.source_segment not in segments:
        raise HTTPException(
            status_code=400,
            detail=f"Source segment '{request.source_segment}' not found in network topology."
        )

    if request.destination_resource not in resources:
        raise HTTPException(
            status_code=400,
            detail=f"Destination resource '{request.destination_resource}' not found."
        )

    return simulate_policy_change(
        source_segment=request.source_segment,
        destination_resource=request.destination_resource,
        port=request.port,
        protocol=request.protocol,
        proposed_rule=request.proposed_rule
    )


@app.post("/api/simulate", response_model=SimulationResponse)
def run_simulation(request: SimulationRequest):
    return _validate_and_simulate(request)


@app.post("/api/connectivity", response_model=SimulationResponse)
def analyze_connectivity(request: SimulationRequest):
    """Calculates baseline and optional proposed connectivity using the Python policy engine."""
    return _validate_and_simulate(request)


@app.get("/api/example-scenarios")
def get_example_scenarios():
    """Provides curated preset scenarios for rapid demonstration and testing."""
    return [
        {
            "id": "scenario-risky-hr-to-fin-db",
            "name": "🚨 Risky Change: Allow HR to Finance DB",
            "description": "Simulates a proposed rule allowing HR segment full access to the Finance Core Database (Port 5432). Expects CRITICAL security guardrail violation.",
            "request": {
                "source_segment": "seg-hr",
                "destination_resource": "res-fin-db",
                "port": 5432,
                "protocol": "TCP",
                "proposed_rule": {
                    "id": "RULE-PROPOSED-001",
                    "name": "Proposed: Permit HR access to Finance DB",
                    "source_segment": "seg-hr",
                    "destination_resource": "res-fin-db",
                    "port": 5432,
                    "protocol": "TCP",
                    "action": "ALLOW",
                    "priority": 15,
                    "description": "Accidental rule allowing HR to query finance database directly."
                }
            }
        },
        {
            "id": "scenario-safe-finance-access",
            "name": "✅ Baseline Permitted: Finance to Finance DB",
            "description": "Tests standard authorized access from Finance Segment to Finance Core Database under baseline rules.",
            "request": {
                "source_segment": "seg-finance",
                "destination_resource": "res-fin-db",
                "port": 5432,
                "protocol": "TCP",
                "proposed_rule": None
            }
        },
        {
            "id": "scenario-baseline-denied",
            "name": "⛔ Baseline Denied: HR to Management Jumpbox",
            "description": "Tests unauthorized connection attempt from HR to IT Jumpbox on Port 22 SSH. Blocked by default-deny.",
            "request": {
                "source_segment": "seg-hr",
                "destination_resource": "res-it-jumpbox",
                "port": 22,
                "protocol": "TCP",
                "proposed_rule": None
            }
        },
        {
            "id": "scenario-safe-web-portal",
            "name": "🌐 Safe Access: HR to Finance Web Expense Portal",
            "description": "Tests standard HTTPS access to the web expense portal (Port 443) which is permitted for all corporate users.",
            "request": {
                "source_segment": "seg-hr",
                "destination_resource": "res-fin-web",
                "port": 443,
                "protocol": "TCP",
                "proposed_rule": None
            }
        }
    ]
