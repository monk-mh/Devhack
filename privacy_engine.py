"""
ContextGuard — Privacy Firewall Engine
Problem Statement: DEVHOST 2026 - PS 2.2 | Team: Error404
St Joseph Engineering College, Vamanjoor Mangalore

Features:
- Hybrid Context Analysis (Structured Identifiers + Semantic Disclosures)
- Role-Based Access Control: Intern · Manager · HR
- 7 Sensitivity Categories x 3 Actions: ALLOW · REDACT · BLOCK
- Full Audit Log with contextual reason for every decision
"""

import re
from typing import Dict, Any, List

# ──────────────────────────────────────────────────────────────────────────────
# ROLES & CLEARANCE POLICY MATRIX (PPT SLIDE 3 & 4)
# ──────────────────────────────────────────────────────────────────────────────

ROLES = ["Intern", "Manager", "HR"]

CATEGORIES = [
    "CREDENTIALS",
    "HEALTH_MEDICAL",
    "FINANCIAL_PERSONAL",
    "FINANCIAL_POLICY",
    "NATIONAL_ID",
    "PII_CONTACT",
    "BUSINESS_PUBLIC"
]

# Clearance Matrix: Category -> { Role -> Action (ALLOW, REDACT, BLOCK) }
CLEARANCE_RULES = {
    "CREDENTIALS": {
        "Intern": "BLOCK",
        "Manager": "BLOCK",
        "HR": "BLOCK"
    },
    "HEALTH_MEDICAL": {
        "Intern": "REDACT",
        "Manager": "REDACT",
        "HR": "REDACT"
    },
    "FINANCIAL_PERSONAL": {
        "Intern": "REDACT",
        "Manager": "REDACT",
        "HR": "ALLOW"
    },
    "FINANCIAL_POLICY": {
        "Intern": "ALLOW",
        "Manager": "ALLOW",
        "HR": "ALLOW"
    },
    "NATIONAL_ID": {
        "Intern": "REDACT",
        "Manager": "REDACT",
        "HR": "ALLOW"
    },
    "PII_CONTACT": {
        "Intern": "REDACT",
        "Manager": "ALLOW",
        "HR": "ALLOW"
    },
    "BUSINESS_PUBLIC": {
        "Intern": "ALLOW",
        "Manager": "ALLOW",
        "HR": "ALLOW"
    }
}

ROLE_POLICY_MATRIX = {
    "Category": [
        "1. Credentials & Secrets",
        "2. Private Health & Chemo",
        "3. Personal Salary & Compensation",
        "4. General Salary Band & Policy",
        "5. Indian National IDs (Aadhaar/PAN)",
        "6. Personal Contact (Phone/Email)",
        "7. Public Business Directory"
    ],
    "Intern Clearance": ["⛔ BLOCK", "🔒 REDACT", "🔒 REDACT", "✅ ALLOW", "🔒 REDACT", "🔒 REDACT", "✅ ALLOW"],
    "Manager Clearance": ["⛔ BLOCK", "🔒 REDACT", "🔒 REDACT", "✅ ALLOW", "🔒 REDACT", "✅ ALLOW", "✅ ALLOW"],
    "HR Clearance": ["⛔ BLOCK", "🔒 REDACT", "✅ ALLOW", "✅ ALLOW", "✅ ALLOW", "✅ ALLOW", "✅ ALLOW"]
}

# ──────────────────────────────────────────────────────────────────────────────
# LAYER 1: STRUCTURED DETECTORS & PATTERNS (PPT SLIDE 4 & 5)
# ──────────────────────────────────────────────────────────────────────────────

PATTERNS = [
    # 1. Credentials & Database URIs (Slide 3 & 4)
    (r"\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/[^\s]+", "CREDENTIALS", "Database Connection String & Credentials"),
    (r"\b(?:sk_live_[a-zA-Z0-9]{24,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36})\b", "CREDENTIALS", "Cloud API Key / Token"),

    # 2. Indian National IDs (Aadhaar & PAN) (Slide 2 & 4)
    (r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b", "NATIONAL_ID", "Indian Aadhaar Number"),
    (r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", "NATIONAL_ID", "Indian Permanent Account Number (PAN)"),

    # 3. PII Contact (Emails & Phones)
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "PII_CONTACT", "Email Address"),
    (r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|\b[6-9]\d{9}\b", "PII_CONTACT", "Phone Number"),
]

# ──────────────────────────────────────────────────────────────────────────────
# LAYER 2: CONTEXTUAL DISCLOSURE ANALYZER (PPT SLIDE 2, 4 & 5)
# Separates policy/bands from personal salary disclosures & detects medical cues
# ──────────────────────────────────────────────────────────────────────────────

def detect_contextual_findings(text: str) -> List[Dict[str, Any]]:
    findings = []
    text_lower = text.lower()

    # Context Check A: General Salary Band (PPT Slide 2 False Positive)
    # e.g., "The salary band for this role is 8–12 LPA."
    band_match = re.search(r"\b(?:salary\s+band|pay\s+scale|bracket|budget\s+for\s+this\s+role)[^.\n]*?(?:is\s+)?(\d+(?:[–\-]\d+)?\s*(?:lpa|inr|usd|k|\$))\b", text, re.IGNORECASE)
    if band_match:
        findings.append({
            "start": band_match.start(1),
            "end": band_match.end(1),
            "detected_text": band_match.group(1),
            "category": "FINANCIAL_POLICY",
            "description": "General Salary Band Policy (Public)",
            "detector": "Context Analyzer (Policy Check)",
            "context_reason": "Surrounding context indicates an organizational pay range / policy info, not personal compensation."
        })

    # Context Check B: Personal Salary Disclosure (PPT Slide 3 Contrast)
    # e.g., "Rahul earns 11 LPA as a Senior Software Engineer"
    personal_sal_match = re.search(r"\b([A-Z][a-z]+)\s+(?:earns|draws|salary\s+is|paid|bonus\s+of)\s+([^.\n,]+?(?:lpa|\$|\binr\b|usd|\d{4,}))", text, re.IGNORECASE)
    if personal_sal_match:
        # Person name
        findings.append({
            "start": personal_sal_match.start(1),
            "end": personal_sal_match.end(1),
            "detected_text": personal_sal_match.group(1),
            "category": "FINANCIAL_PERSONAL",
            "description": "Employee Name linked to Personal Compensation",
            "detector": "Context Analyzer (Entity Linking)",
            "context_reason": "Entity directly associated with individual salary disclosure."
        })
        # Salary amount
        findings.append({
            "start": personal_sal_match.start(2),
            "end": personal_sal_match.end(2),
            "detected_text": personal_sal_match.group(2).strip(),
            "category": "FINANCIAL_PERSONAL",
            "description": "Personal Compensation / Salary Figure",
            "detector": "Context Analyzer (Financial Disclosure)",
            "context_reason": "Discloses individual employee salary/earnings."
        })

    # Context Check C: Private Health & Medical (PPT Slide 2 False Negative)
    # e.g., "Priya won’t be in till March — her chemo cycle starts Monday."
    health_cues = ["chemo", "chemotherapy", "cancer", "leukemia", "diagnosed", "surgery", "leave", "hospital", "patient", "illness"]
    if any(cue in text_lower for cue in health_cues):
        # Look for medical condition/treatment spans
        med_match = re.search(r"\b(chemo(?:\s+cycle)?|chemotherapy|cancer|leukemia|surgery|treatment|diagnosed\s+with\s+[a-zA-Z]+)\b", text, re.IGNORECASE)
        if med_match:
            findings.append({
                "start": med_match.start(1),
                "end": med_match.end(1),
                "detected_text": med_match.group(1),
                "category": "HEALTH_MEDICAL",
                "description": "Private Health & Treatment Disclosure",
                "detector": "Context Analyzer (Medical Semantic)",
                "context_reason": "Confidential medical treatment/diagnosis revealed without consent."
            })

    # Context Check D: Public Business Contact
    # e.g., "inquiries or sales questions, contact Alice at alice@acme.com"
    public_cues = ["inquiries", "inquiry", "sales", "support", "contact", "reach out", "customer care", "helpdesk"]
    is_public_channel = any(cue in text_lower for cue in public_cues)

    # Layer 1 Structured Matchers
    for pattern, category, desc in PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            val = m.group(0)
            start, end = m.start(), m.end()

            # Skip if already captured by policy or personal context
            if any(f["start"] <= start and f["end"] >= end for f in findings):
                continue

            eff_cat = category
            reason = f"Identified {desc.lower()} matching structured pattern."
            if category == "PII_CONTACT" and is_public_channel:
                eff_cat = "BUSINESS_PUBLIC"
                reason = "Public business inquiry/sales context detected; safe to publish."

            findings.append({
                "start": start,
                "end": end,
                "detected_text": val,
                "category": eff_cat,
                "description": desc,
                "detector": "Rule Engine (Layer 1)",
                "context_reason": reason
            })

    # Sort by start offset
    findings.sort(key=lambda x: x["start"])
    return findings

# ──────────────────────────────────────────────────────────────────────────────
# POLICY ENGINE & FIREWALL ENFORCEMENT (PPT SLIDE 3, 5 & 6)
# ──────────────────────────────────────────────────────────────────────────────

def evaluate_and_enforce(text: str, role: str = "Intern") -> Dict[str, Any]:
    """
    Evaluates text against viewer role clearance and applies:
      - ALLOW: Passes through untouched
      - REDACT: Obfuscates as [REDACTED:CATEGORY]
      - BLOCK: Halts prompt transmission (Secrets/Credentials)
    """
    if not text or not text.strip():
        return {
            "original_text": text or "",
            "sanitized_text": text or "",
            "overall_status": "ALLOWED",
            "audit_log": [],
            "stats": {"total_findings": 0, "allowed": 0, "redacted": 0, "blocked": 0}
        }

    role = role if role in ROLES else "Intern"
    findings = detect_contextual_findings(text)

    audit_log = []
    has_blocked = False

    for item in findings:
        cat = item["category"]
        action = CLEARANCE_RULES.get(cat, {}).get(role, "REDACT")

        if action == "BLOCK":
            has_blocked = True

        audit_log.append({
            "detected_text": item["detected_text"],
            "start": item["start"],
            "end": item["end"],
            "category": cat,
            "description": item["description"],
            "detector": item["detector"],
            "role": role,
            "action": action,
            "reason": item["context_reason"]
        })

    # If ANY credential/secret was detected, BLOCK the entire transmission
    if has_blocked:
        return {
            "original_text": text,
            "sanitized_text": "[TRANSMISSION BLOCKED BY CONTEXTGUARD FIREWALL] — Infrastructure credentials / secrets detected. Not permitted for AI ingestion under enterprise security policy.",
            "overall_status": "BLOCKED",
            "audit_log": audit_log,
            "stats": {
                "total_findings": len(audit_log),
                "allowed": sum(1 for a in audit_log if a["action"] == "ALLOW"),
                "redacted": sum(1 for a in audit_log if a["action"] == "REDACT"),
                "blocked": sum(1 for a in audit_log if a["action"] == "BLOCK")
            }
        }

    # Otherwise, apply redaction replacements
    sorted_log = sorted(audit_log, key=lambda x: x["start"], reverse=True)
    sanitized = text

    for item in sorted_log:
        if item["action"] == "REDACT":
            replacement = f"[REDACTED:{item['category']}]"
            sanitized = sanitized[:item["start"]] + replacement + sanitized[item["end"]:]

    return {
        "original_text": text,
        "sanitized_text": sanitized,
        "overall_status": "SANITIZED",
        "audit_log": audit_log,
        "stats": {
            "total_findings": len(audit_log),
            "allowed": sum(1 for a in audit_log if a["action"] == "ALLOW"),
            "redacted": sum(1 for a in audit_log if a["action"] == "REDACT"),
            "blocked": 0
        }
    }

# Backwards compatibility wrappers
def scan_and_sanitize(text: str) -> Dict[str, Any]:
    res = evaluate_and_enforce(text, role="Intern")
    return {
        "original_text": res["original_text"],
        "sanitized_text": res["sanitized_text"],
        "telemetry": [{
            "entity_type": a["category"],
            "value": a["detected_text"],
            "start": a["start"],
            "end": a["end"],
            "risk_tier": "HIGH" if a["action"] in ["BLOCK", "REDACT"] else "LOW",
            "action": a["action"],
            "category": a["category"],
            "replacement": f"[REDACTED:{a['category']}]" if a["action"] == "REDACT" else a["detected_text"],
            "reason": a["reason"]
        } for a in res["audit_log"]],
        "stats": {
            "total": res["stats"]["total_findings"],
            "pass": res["stats"]["allowed"],
            "mask": 0,
            "pseudonymize": 0,
            "redact": res["stats"]["redacted"]
        }
    }

def simulate_llm_response(sanitized_text: str, query: str = "Process request safely.") -> Dict[str, Any]:
    return {
        "query": query,
        "sanitized_input": sanitized_text,
        "llm_response": (
            "Safe AI Reasoning Verified.\n\n"
            "• Firewall Status: ContextGuard evaluated transmission clearance.\n"
            "• Protection: Sensitive personal attributes shielded before LLM processing.\n"
            "• Response: Downstream tasks executed safely without data leakage."
        ),
        "privacy_guarantee": "Zero sensitive disclosures leaked to unauthorized model context."
    }

surrogate_store = {}
