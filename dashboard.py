"""
PrivacyShield AI — Streamlit Interactive Dashboard
Problem Statement: DEVHOST 2026 - PS 2.2

Context-Aware Data Privacy Guard demonstrating dynamic policy enforcement:
  - PASS: Public business/support contacts
  - MASK: General PII without public context
  - PSEUDONYMIZE: Confidential health records
  - REDACT: Internal financial/salary/account details
"""

import streamlit as st
import pandas as pd
import html
import requests
from privacy_engine import scan_and_sanitize, simulate_llm_response, surrogate_store

# ──────────────────────────────────────────────────────────────────────────────
# PAGE CONFIGURATION & CUSTOM STYLING
# ──────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Context-Aware Data Privacy Guard | DEVHOST 2026",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

CUSTOM_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}

/* Glassmorphism cards */
.glass-card {
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 20px;
    box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
}

/* Badges */
.badge-pass {
    background: #064e3b;
    color: #34d399;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 700;
    display: inline-block;
    border: 1px solid #059669;
}
.badge-mask {
    background: #78350f;
    color: #fbbf24;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 700;
    display: inline-block;
    border: 1px solid #d97706;
}
.badge-pseudo {
    background: #312e81;
    color: #a5b4fc;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 700;
    display: inline-block;
    border: 1px solid #6366f1;
}
.badge-redact {
    background: #7f1d1d;
    color: #f87171;
    padding: 4px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 700;
    display: inline-block;
    border: 1px solid #dc2626;
}

/* Highlighted replacement tokens */
.token-pass {
    background: rgba(16, 185, 129, 0.2);
    border-bottom: 2px solid #10b981;
    padding: 2px 4px;
    border-radius: 3px;
    color: #34d399;
    font-family: 'JetBrains Mono', monospace;
}
.token-mask {
    background: rgba(245, 158, 11, 0.2);
    border-bottom: 2px solid #f59e0b;
    padding: 2px 4px;
    border-radius: 3px;
    color: #fbbf24;
    font-family: 'JetBrains Mono', monospace;
}
.token-pseudo {
    background: rgba(99, 102, 241, 0.2);
    border-bottom: 2px solid #6366f1;
    padding: 2px 4px;
    border-radius: 3px;
    color: #c7d2fe;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
}
.token-redact {
    background: rgba(239, 68, 68, 0.2);
    border-bottom: 2px solid #ef4444;
    padding: 2px 4px;
    border-radius: 3px;
    color: #fca5a5;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
}

.text-box {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 16px;
    min-height: 140px;
    font-size: 0.95rem;
    line-height: 1.6;
    color: #e2e8f0;
}

.metric-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 14px 18px;
    text-align: center;
}
.metric-num {
    font-size: 1.8rem;
    font-weight: 800;
    line-height: 1.2;
}
.metric-lbl {
    font-size: 0.75rem;
    text-transform: uppercase;
    color: #94a3b8;
    letter-spacing: 0.05em;
    font-weight: 600;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ──────────────────────────────────────────────────────────────────────────────
# BENCHMARK PRESETS
# ──────────────────────────────────────────────────────────────────────────────

PRESETS = {
    "Preset 1 (Public Contact - PASS)": {
        "text": "For any inquiries or enterprise sales questions, please reach out to Alice at alice@acme.com.",
        "desc": "Public directory/sales cue -> PASS with zero over-redaction.",
        "expected": "PASS"
    },
    "Preset 2 (Confidential Health - PSEUDONYMIZE)": {
        "text": "Please note that Alice at alice@acme.com was diagnosed with leukemia and will begin chemotherapy treatment tomorrow.",
        "desc": "Medical/oncology context -> Reversible surrogate token applied.",
        "expected": "PSEUDONYMIZE"
    },
    "Preset 3 (Internal Financial - REDACT)": {
        "text": "Finance team: Rahul's Q4 appraisal bonus of $18,500 has been transferred to his account ending in 4102.",
        "desc": "Compensation/account context -> Complete redaction applied.",
        "expected": "REDACT"
    },
    "Preset 4 (Generic PII - MASK)": {
        "text": "Call me on 9845012345 when you arrive at the gate.",
        "desc": "Personal phone without public context -> Partial masking.",
        "expected": "MASK"
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# SESSION STATE INITIALIZATION
# ──────────────────────────────────────────────────────────────────────────────

if "input_text" not in st.session_state:
    st.session_state.input_text = PRESETS["Preset 1 (Public Contact - PASS)"]["text"]
if "scan_result" not in st.session_state:
    st.session_state.scan_result = scan_and_sanitize(st.session_state.input_text)
if "llm_output" not in st.session_state:
    st.session_state.llm_output = None

# ──────────────────────────────────────────────────────────────────────────────
# HEADER SECTION
# ──────────────────────────────────────────────────────────────────────────────

col_head1, col_head2 = st.columns([3, 1])
with col_head1:
    st.title("🛡️ Context-Aware Data Privacy Guard")
    st.markdown("**DEVHOST 2026 — PS 2.2** | Semantic Risk Evaluation & Dynamic Privacy Policies")
with col_head2:
    st.markdown(
        """
        <div style="text-align: right; padding-top: 15px;">
            <span style="background: #1e1b4b; border: 1px solid #4338ca; color: #818cf8; padding: 6px 14px; border-radius: 20px; font-weight: 600; font-size: 0.85rem;">
                ● Live Engine v2.2
            </span>
        </div>
        """,
        unsafe_allow_html=True
    )

st.markdown(
    """
    Standard filters rely on simple regex or keyword lists that **over-redact public information** (breaking customer support channels)
    or **leak sensitive data** when context changes. This system analyzes candidate entities within a **70-character sliding semantic window**
    and dynamically enforces: **PASS**, **MASK**, **PSEUDONYMIZE**, or **REDACT**.
    """
)

# ──────────────────────────────────────────────────────────────────────────────
# SIDEBAR CONTROLS
# ──────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("⚡ Benchmark Presets")
    st.caption("Click any preset to verify dynamic context evaluation:")

    for name, p_data in PRESETS.items():
        if st.button(name, use_container_width=True):
            st.session_state.input_text = p_data["text"]
            st.session_state.scan_result = scan_and_sanitize(p_data["text"])
            st.session_state.llm_output = None
            st.rerun()

    st.markdown("---")
    st.header("⚙️ Policy Matrix")
    st.markdown(
        """
        - 🟢 **PASS (Risk: LOW)**: Public directory, inquiries, support.
        - 🟡 **MASK (Risk: MEDIUM)**: Generic PII, unverified phone/email.
        - 🔵 **PSEUDONYMIZE (Risk: HIGH)**: Confidential health/medical.
        - 🔴 **REDACT (Risk: HIGH)**: Internal payroll, bonuses, bank accounts.
        """
    )
    
    st.markdown("---")
    st.subheader("🔑 Active Reversible Tokens")
    mappings = surrogate_store
    if mappings:
        for token, orig in mappings.items():
            st.code(f"{token} ➜ {orig}")
    else:
        st.caption("No surrogates generated yet.")

# ──────────────────────────────────────────────────────────────────────────────
# INPUT & ACTION BAR
# ──────────────────────────────────────────────────────────────────────────────

st.subheader("1. Input Data Stream")
input_text = st.text_area(
    "Enter text containing candidate entities (support queries, employee notes, medical logs):",
    value=st.session_state.input_text,
    height=110,
    key="text_input_area"
)

btn_col1, btn_col2, btn_col3 = st.columns([1.5, 1.5, 3])
with btn_col1:
    if st.button("🔍 Analyze & Sanitize", type="primary", use_container_width=True):
        st.session_state.input_text = input_text
        st.session_state.scan_result = scan_and_sanitize(input_text)
        st.session_state.llm_output = None
        st.rerun()

with btn_col2:
    if st.button("🤖 Test Safe LLM Reasoning", use_container_width=True):
        if st.session_state.scan_result:
            sanitized = st.session_state.scan_result["sanitized_text"]
            st.session_state.llm_output = simulate_llm_response(sanitized)
            st.rerun()

# ──────────────────────────────────────────────────────────────────────────────
# METRICS BAR
# ──────────────────────────────────────────────────────────────────────────────

res = st.session_state.scan_result
stats = res.get("stats", {"total": 0, "pass": 0, "mask": 0, "pseudonymize": 0, "redact": 0})

m1, m2, m3, m4, m5 = st.columns(5)
with m1:
    st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #60a5fa;">{stats["total"]}</div><div class="metric-lbl">Total Entities</div></div>', unsafe_allow_html=True)
with m2:
    st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #34d399;">{stats["pass"]}</div><div class="metric-lbl">Passed (Public)</div></div>', unsafe_allow_html=True)
with m3:
    st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #fbbf24;">{stats["mask"]}</div><div class="metric-lbl">Masked (PII)</div></div>', unsafe_allow_html=True)
with m4:
    st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #a5b4fc;">{stats["pseudonymize"]}</div><div class="metric-lbl">Pseudonymized</div></div>', unsafe_allow_html=True)
with m5:
    st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #f87171;">{stats["redact"]}</div><div class="metric-lbl">Redacted</div></div>', unsafe_allow_html=True)

st.markdown("<br/>", unsafe_allow_html=True)

# ──────────────────────────────────────────────────────────────────────────────
# SIDE-BY-SIDE COMPARISON PANEL
# ──────────────────────────────────────────────────────────────────────────────

st.subheader("2. Context-Aware Transformation (Before vs. After)")
col_left, col_right = st.columns(2)

with col_left:
    st.markdown("**Original Raw Input (High Risk Exposure):**")
    st.markdown(f'<div class="text-box">{html.escape(res["original_text"])}</div>', unsafe_allow_html=True)

with col_right:
    st.markdown("**Sanitized Safe Output (Context-Enforced):**")
    
    # Render with highlight tokens
    sanitized_display = html.escape(res["original_text"])
    sorted_items = sorted(res["telemetry"], key=lambda x: x["start"], reverse=True)
    for item in sorted_items:
        act = item["action"]
        rep = html.escape(item["replacement"])
        if act == "PASS":
            badge_html = f'<span class="token-pass">{rep} (PASS)</span>'
        elif act == "MASK":
            badge_html = f'<span class="token-mask">{rep}</span>'
        elif act == "PSEUDONYMIZE":
            badge_html = f'<span class="token-pseudo">{rep}</span>'
        else: # REDACT
            badge_html = f'<span class="token-redact">{rep}</span>'
        
        sanitized_display = sanitized_display[:item["start"]] + badge_html + sanitized_display[item["end"]:]

    st.markdown(f'<div class="text-box">{sanitized_display}</div>', unsafe_allow_html=True)

st.markdown("<br/>", unsafe_allow_html=True)

# ──────────────────────────────────────────────────────────────────────────────
# TELEMETRY & DECISION TABLE (CRUCIAL FOR JUDGING)
# ──────────────────────────────────────────────────────────────────────────────

st.subheader("3. Telemetry & Policy Decision Log")
telemetry = res.get("telemetry", [])

if telemetry:
    table_rows = []
    for item in telemetry:
        risk_tier = item["risk_tier"]
        action = item["action"]

        if risk_tier == "LOW":
            risk_badge = "🟢 LOW"
        elif risk_tier == "MEDIUM":
            risk_badge = "🟡 MEDIUM"
        else:
            risk_badge = "🔴 HIGH"

        if action == "PASS":
            act_badge = "✅ PASS"
        elif action == "MASK":
            act_badge = "🎭 MASK"
        elif action == "PSEUDONYMIZE":
            act_badge = "🔀 PSEUDONYMIZE"
        else:
            act_badge = "🚫 REDACT"

        table_rows.append({
            "Entity Value": item["value"],
            "Entity Type": item["entity_type"],
            "Context Category": item["category"],
            "Risk Tier": risk_badge,
            "Action Taken": act_badge,
            "Replacement Value": item["replacement"],
            "Context Rationale": item["reason"]
        })

    df = pd.DataFrame(table_rows)
    st.dataframe(df, use_container_width=True, hide_index=True)
else:
    st.info("No sensitive candidate entities identified in the text.")

# ──────────────────────────────────────────────────────────────────────────────
# DOWNSTREAM LLM REASONING DEMO
# ──────────────────────────────────────────────────────────────────────────────

if st.session_state.llm_output:
    st.markdown("<br/>", unsafe_allow_html=True)
    st.subheader("4. Downstream LLM Safe Reasoning Simulation")
    llm = st.session_state.llm_output
    
    st.success("✅ Context Retained Without PII Exposure")
    c_llm1, c_llm2 = st.columns([1, 1])
    with c_llm1:
        st.markdown("**Sanitized Text Sent to External LLM:**")
        st.code(llm["sanitized_input"], language="text")
    with c_llm2:
        st.markdown("**LLM Safe Response:**")
        st.info(llm["llm_response"])
        st.caption(f"🔒 Guarantee: {llm['privacy_guarantee']}")
