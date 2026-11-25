from typing import Optional, List, Literal
from pydantic import BaseModel, Field


class NetworkSegment(BaseModel):
    id: str = Field(..., description="Unique identifier for network segment, e.g. 'seg-hr'")
    name: str = Field(..., description="Human readable name, e.g. 'Human Resources'")
    cidr: str = Field(..., description="CIDR block, e.g. '10.10.1.0/24'")
    security_zone: str = Field(..., description="Security zone classification")
    description: str = Field(..., description="Description of the segment")


class Resource(BaseModel):
    id: str = Field(..., description="Unique identifier for resource, e.g. 'res-fin-db'")
    name: str = Field(..., description="Human readable resource name, e.g. 'Finance Core Database'")
    ip: str = Field(..., description="IP address or DNS hostname, e.g. '10.10.2.50'")
    port: int = Field(..., description="Default listening port, e.g. 5432")
    protocol: str = Field(..., description="Protocol: TCP, UDP, or ICMP")
    segment_id: str = Field(..., description="Parent segment ID, e.g. 'seg-finance'")
    is_critical: bool = Field(False, description="Flag indicating high-value or high-risk asset")
    description: str = Field(..., description="Purpose and data classification")


class PolicyRule(BaseModel):
    id: str = Field(..., description="Rule ID, e.g. 'RULE-020'")
    name: str = Field(..., description="Descriptive rule label")
    source_segment: str = Field(..., description="Source segment ID or '*' for any")
    destination_resource: str = Field(..., description="Destination resource ID, segment ID, or '*' for any")
    port: Optional[int] = Field(None, description="Destination port or None for any port")
    protocol: str = Field("TCP", description="Protocol: TCP, UDP, or ANY")
    action: Literal["ALLOW", "DENY"] = Field(..., description="Action: ALLOW or DENY")
    priority: int = Field(..., description="Rule evaluation order (lower integer = higher priority)")
    description: Optional[str] = None


class SecurityGuardrail(BaseModel):
    id: str = Field(..., description="Guardrail ID, e.g. 'SG-01'")
    name: str = Field(..., description="Guardrail name")
    forbidden_source: str = Field(..., description="Segment ID forbidden from connecting")
    forbidden_destination: str = Field(..., description="Resource or segment ID protected")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(..., description="Risk severity level")
    description: str = Field(..., description="Explanation of the policy rule")
    rationale: str = Field(..., description="Regulatory, business, or compliance justification")


class SimulationRequest(BaseModel):
    source_segment: str = Field(..., description="Initiating network segment ID")
    destination_resource: str = Field(..., description="Target resource ID")
    port: int = Field(..., description="Target port number")
    protocol: str = Field("TCP", description="Target protocol (TCP/UDP)")
    proposed_rule: Optional[PolicyRule] = Field(
        None, 
        description="Optional proposed policy rule to test alongside current policies"
    )


class RuleEvaluation(BaseModel):
    status: Literal["ALLOWED", "DENIED"]
    matched_rule_id: str
    matched_rule_name: str
    matched_rule_priority: int
    action: Literal["ALLOW", "DENY"]
    explanation: str
    matched_rule_description: Optional[str] = None
    is_default_deny: bool = False
    default_deny_reason: Optional[str] = None


class GuardrailViolation(BaseModel):
    guardrail_id: str
    name: str
    severity: str
    description: str
    rationale: str


class SimulationResponse(BaseModel):
    source_segment: str
    source_segment_name: str
    source_cidr: str = "Unknown"
    destination_resource: str
    destination_resource_name: str
    destination_ip: str
    destination_segment_id: Optional[str] = None
    port: int
    protocol: str
    is_critical_target: bool
    current_evaluation: RuleEvaluation
    proposed_evaluation: RuleEvaluation
    change_type: Literal["NO_CHANGE", "ACCESS_GRANTED", "ACCESS_REVOKED"]
    risk_detected: bool
    violations: List[GuardrailViolation] = []
    overall_verdict: Literal["SAFE", "BLOCKED", "CRITICAL_RISK", "POLICY_CHANGE_OK"]
    recommendation: str
