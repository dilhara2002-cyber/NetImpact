import json
from pathlib import Path
from typing import List, Dict, Tuple, Optional

from app.models import (
    NetworkSegment,
    Resource,
    PolicyRule,
    SecurityGuardrail,
    RuleEvaluation,
    GuardrailViolation,
    SimulationResponse
)

DATA_DIR = Path(__file__).resolve().parent / "data"


def load_network_data() -> Tuple[Dict[str, NetworkSegment], Dict[str, Resource]]:
    """Loads network segments and destination resources from JSON."""
    file_path = DATA_DIR / "network_segments.json"
    with open(file_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)
    
    segments = {s["id"]: NetworkSegment(**s) for s in raw_data.get("segments", [])}
    resources = {r["id"]: Resource(**r) for r in raw_data.get("resources", [])}
    return segments, resources


def load_current_policies() -> List[PolicyRule]:
    """Loads current baseline firewall policy rules sorted by priority."""
    file_path = DATA_DIR / "current_policies.json"
    with open(file_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)
    
    rules = [PolicyRule(**r) for r in raw_data.get("policies", [])]
    rules.sort(key=lambda x: x.priority)
    return rules


def load_security_guardrails() -> List[SecurityGuardrail]:
    """Loads organization security guardrails/compliance boundaries."""
    file_path = DATA_DIR / "security_rules.json"
    with open(file_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)
    
    return [SecurityGuardrail(**g) for g in raw_data.get("guardrails", [])]


def rule_matches(
    rule: PolicyRule,
    source_segment: str,
    destination_resource: str,
    port: int,
    protocol: str
) -> bool:
    """
    Evaluates whether a single policy rule matches the given traffic flow.
    Supports wildcard '*' for source, destination, port, and protocol.
    """
    # 1. Check Source Segment
    if rule.source_segment != "*" and rule.source_segment != source_segment:
        return False
    
    # 2. Check Destination Resource
    if rule.destination_resource != "*" and rule.destination_resource != destination_resource:
        return False
    
    # 3. Check Port
    if rule.port is not None and rule.port != port:
        return False
    
    # 4. Check Protocol
    if rule.protocol != "ANY" and rule.protocol.upper() != protocol.upper():
        return False
    
    return True


def evaluate_connection_against_rules(
    rules: List[PolicyRule],
    source_segment: str,
    destination_resource: str,
    port: int,
    protocol: str
) -> RuleEvaluation:
    """
    Evaluates connection against an ordered set of rules.
    Highest priority (lowest priority integer) rule that matches determines the outcome.
    Implements strict default-deny if no rules match.
    """
    sorted_rules = sorted(rules, key=lambda r: r.priority)
    
    for rule in sorted_rules:
        if rule_matches(rule, source_segment, destination_resource, port, protocol):
            action_status = "ALLOWED" if rule.action == "ALLOW" else "DENIED"
            is_default_deny = (
                rule.action == "DENY"
                and rule.source_segment == "*"
                and rule.destination_resource == "*"
                and rule.port is None
            )
            default_deny_reason = None
            if is_default_deny:
                default_deny_reason = (
                    f"No higher-priority rule permitted traffic from '{source_segment}' to "
                    f"'{destination_resource}' on {protocol.upper()}/{port}. "
                    f"Connection fell through to {rule.id} ({rule.name}, Priority {rule.priority}): "
                    f"{rule.description or 'Zero-trust default-deny baseline.'}"
                )
            explanation = (
                f"Matched Rule '{rule.name}' (Priority {rule.priority}): "
                f"Action set to {rule.action}."
            )
            return RuleEvaluation(
                status=action_status,
                matched_rule_id=rule.id,
                matched_rule_name=rule.name,
                matched_rule_priority=rule.priority,
                action=rule.action,
                explanation=explanation,
                matched_rule_description=rule.description,
                is_default_deny=is_default_deny,
                default_deny_reason=default_deny_reason
            )
    
    # Strict Default-Deny Fallback
    fallback_reason = (
        f"No matching firewall rule found for '{source_segment}' to '{destination_resource}' "
        f"on {protocol.upper()}/{port}. Connection blocked by implicit default-deny."
    )
    return RuleEvaluation(
        status="DENIED",
        matched_rule_id="DEFAULT-DENY",
        matched_rule_name="Implicit Default Deny",
        matched_rule_priority=9999,
        action="DENY",
        explanation=fallback_reason,
        matched_rule_description="Implicit fallback rule applied when no explicit rule matches.",
        is_default_deny=True,
        default_deny_reason=fallback_reason
    )


def check_security_guardrails(
    source_segment: str,
    destination_resource: str
) -> List[GuardrailViolation]:
    """
    Independent compliance check:
    Verifies proposed traffic against organizational security guardrails,
    regardless of whether a firewall rule permits the flow.
    """
    guardrails = load_security_guardrails()
    violations: List[GuardrailViolation] = []
    
    for g in guardrails:
        if g.forbidden_source == source_segment and g.forbidden_destination == destination_resource:
            violations.append(
                GuardrailViolation(
                    guardrail_id=g.id,
                    name=g.name,
                    severity=g.severity,
                    description=g.description,
                    rationale=g.rationale
                )
            )
            
    return violations


def simulate_policy_change(
    source_segment: str,
    destination_resource: str,
    port: int,
    protocol: str,
    proposed_rule: Optional[PolicyRule] = None
) -> SimulationResponse:
    """
    Runs the full NetImpact simulation:
    1. Evaluates Current Access under active baseline policies.
    2. Builds the Proposed Policy set (Current + Proposed Rule) and evaluates Proposed Access.
    3. Independently runs Security Guardrail checks to detect compliance violations.
    4. Computes change delta and provides an actionable verdict.
    """
    segments, resources = load_network_data()
    current_rules = load_current_policies()
    
    # Retrieve segment and resource metadata for human-friendly reports
    source_info = segments.get(source_segment)
    source_name = source_info.name if source_info else source_segment
    source_cidr = source_info.cidr if source_info else "Unknown"
    
    dest_info = resources.get(destination_resource)
    dest_name = dest_info.name if dest_info else destination_resource
    dest_ip = dest_info.ip if dest_info else "Unknown"
    dest_segment_id = dest_info.segment_id if dest_info else None
    is_critical = dest_info.is_critical if dest_info else False
    
    # 1. Evaluate Current State
    current_eval = evaluate_connection_against_rules(
        rules=current_rules,
        source_segment=source_segment,
        destination_resource=destination_resource,
        port=port,
        protocol=protocol
    )
    
    # 2. Build Proposed Policy Set
    proposed_rules = list(current_rules)
    if proposed_rule:
        # If a proposed rule has the same ID as an existing rule, replace it; otherwise add it
        proposed_rules = [r for r in proposed_rules if r.id != proposed_rule.id]
        proposed_rules.append(proposed_rule)
    
    # Evaluate Proposed State
    proposed_eval = evaluate_connection_against_rules(
        rules=proposed_rules,
        source_segment=source_segment,
        destination_resource=destination_resource,
        port=port,
        protocol=protocol
    )
    
    # 3. Determine Change Type
    if current_eval.status == proposed_eval.status:
        change_type = "NO_CHANGE"
    elif current_eval.status == "DENIED" and proposed_eval.status == "ALLOWED":
        change_type = "ACCESS_GRANTED"
    else:
        change_type = "ACCESS_REVOKED"
    
    # 4. Check Security Guardrails independently
    # Only flag risk if the proposed state allows the traffic
    violations: List[GuardrailViolation] = []
    risk_detected = False
    
    if proposed_eval.status == "ALLOWED":
        violations = check_security_guardrails(source_segment, destination_resource)
        if violations:
            risk_detected = True
            
    # 5. Formulate Overall Verdict & Recommendation
    if risk_detected:
        overall_verdict = "CRITICAL_RISK"
        violation_names = ", ".join([v.name for v in violations])
        recommendation = (
            f"REJECT DEPLOYMENT: The proposed rule grants access that violates critical security "
            f"boundary [{violation_names}]. Segregation of duties is violated."
        )
    elif proposed_eval.status == "ALLOWED":
        if change_type == "ACCESS_GRANTED":
            overall_verdict = "POLICY_CHANGE_OK"
            recommendation = (
                "SAFE TO REVIEW: Proposed policy cleanly grants access without violating any known "
                "security guardrails. Standard peer review recommended before deployment."
            )
        else:
            overall_verdict = "SAFE"
            recommendation = "SAFE: Traffic is permitted and aligns with active security baseline."
    else:
        overall_verdict = "BLOCKED"
        recommendation = (
            "DENIED: Traffic is blocked under proposed rules. If this traffic is required for "
            "business operations, an authorized allow rule must be defined."
        )
        
    return SimulationResponse(
        source_segment=source_segment,
        source_segment_name=source_name,
        source_cidr=source_cidr,
        destination_resource=destination_resource,
        destination_resource_name=dest_name,
        destination_ip=dest_ip,
        destination_segment_id=dest_segment_id,
        port=port,
        protocol=protocol.upper(),
        is_critical_target=is_critical,
        current_evaluation=current_eval,
        proposed_evaluation=proposed_eval,
        change_type=change_type,
        risk_detected=risk_detected,
        violations=violations,
        overall_verdict=overall_verdict,
        recommendation=recommendation
    )
