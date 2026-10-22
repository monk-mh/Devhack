"""
ContextGuard — Streamlit Interactive Privacy Firewall Dashboard
Problem Statement: DEVHOST 2026 - PS 2.2 | Team: Error404
St Joseph Engineering College, Vamanjoor Mangalore

Features:
- Hybrid Context Analysis (Structured Rules + Semantic Context)
- Role-Based Enforcement (Intern · Manager · HR)
- 7 Sensitivity Categories x 3 Actions (Allow · Redact · Block)
- Full Audit Log with Reasons for Every Decision
"""

import streamlit as st
import pandas as pd
import html
from privacy_engine import evaluate_and_enforce, ROLES, CATEGORIES, ROLE_POLICY_MATRIX, simulate_llm_response

# ──────────────────────────────────────────────────────────────────────────────
# PAGE CONFIGURATION & STYLING
# ──────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="ContextGuard | Team Error404 (DEVHOST 2026)",
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

.main-title {
    font-size: 2.2rem;
    font-weight: 800;
    color: #f8fafc;
    margin-bottom: 0px;
}

.team-badge {
    background: #1e1b4b;
    border: 1px solid #4338ca;
    color: #a5b4fc;
    padding: 6px 14px;
    border-radius: 20px;
    font-weight: 600;
    font-size: 0.85rem;
    display: inline-block;
}

.text-box {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 16px;
    min-height: 120px;
    font-size: 0.95rem;
    line-height: 1.6;
    color: #e2e8f0;
}

.blocked-box {
    background: #450a0a;
    border: 2px solid #ef4444;
    border-radius: 8px;
    padding: 18px;
    color: #fecaca;
    font-weight: 600;
    line-height: 1.6;
}

.metric-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 12px 16px;
    text-align: center;
}
.metric-num {
    font-size: 1.7rem;
    font-weight: 800;
    line-height: 1.2;
}
.metric-lbl {
    font-size: 0.72rem;
    text-transform: uppercase;
    color: #94a3b8;
    letter-spacing: 0.05em;
    font-weight: 600;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# ──────────────────────────────────────────────────────────────────────────────
# BENCHMARK PRESETS (DIRECTLY FROM DEVHOST 2026 PPT SLIDES)
# ──────────────────────────────────────────────────────────────────────────────

PPT_PRESETS = {
    "1. Salary Band (PPT Slide 2 False Positive)": {
        "text": "The salary band for this role is 8–12 LPA.",
        "desc": "General policy information -> ALLOWED (Demonstrates zero false-positives/over-redaction)."
    },
    "2. Personal Salary (PPT Slide 3 Contrast)": {
        "text": "Rahul earns 11 LPA as a Senior Software Engineer.",
        "desc": "Individual salary disclosure -> REDACTED for Intern/Manager, ALLOWED for HR."
    },
    "3. Private Health (PPT Slide 2 False Negative)": {
        "text": "Priya won’t be in till March — her chemo cycle starts Monday.",
        "desc": "Private chemotherapy disclosure -> REDACTED (Demonstrates false-negative prevention)."
    },
    "4. Database Credentials (PPT Slide 3 Secrets)": {
        "text": "Deployment config: postgresql://admin:P@ssw0rdProd@db.internal:5432/finance",
        "desc": "Infrastructure credentials -> BLOCKS THE ENTIRE TRANSMISSION for all roles."
    },
    "5. Indian National IDs (Aadhaar & PAN)": {
        "text": "New contractor details: Aadhaar 4920 1829 3847, PAN ABCDE1234F, email rahul@acme.com.",
        "desc": "Aadhaar & PAN -> REDACTED for Intern, ALLOWED for HR."
    }
}

# ──────────────────────────────────────────────────────────────────────────────
# SESSION STATE
# ──────────────────────────────────────────────────────────────────────────────

if "input_text" not in st.session_state:
    st.session_state.input_text = PPT_PRESETS["1. Salary Band (PPT Slide 2 False Positive)"]["text"]
if "selected_role" not in st.session_state:
    st.session_state.selected_role = "Intern"
if "llm_output" not in st.session_state:
    st.session_state.llm_output = None

# ──────────────────────────────────────────────────────────────────────────────
# HEADER (MATCHING PPT SLIDE 1 & SLIDE 3)
# ──────────────────────────────────────────────────────────────────────────────

c_head1, c_head2 = st.columns([3, 1])
with c_head1:
    st.markdown('<div class="main-title">🛡️ ContextGuard</div>', unsafe_allow_html=True)
    st.markdown("**Context-Aware Data Privacy Firewall for AI** | Problem Statement 2.2")
with c_head2:
    st.markdown(
        """
        <div style="text-align: right; padding-top: 10px;">
            <span class="team-badge">Team: Error404</span><br/>
            <span style="font-size: 0.75rem; color: #94a3b8;">St Joseph Engineering College</span>
        </div>
        """,
        unsafe_allow_html=True
    )

st.caption("ContextGuard sits between business data and AI. It analyzes text in context, enforces role-based clearance (Intern, Manager, HR), and redacts or blocks unauthorized exposure.")

# ──────────────────────────────────────────────────────────────────────────────
# SIDEBAR: ROLE SELECTOR & BENCHMARK PRESETS (PPT SLIDE 3)
# ──────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.header("👤 Viewer Role")
    role_options = ["Intern", "Manager", "HR"]
    selected_role = st.selectbox(
        "Who is asking for the information?",
        options=role_options,
        index=role_options.index(st.session_state.selected_role)
    )
    st.session_state.selected_role = selected_role

    if selected_role == "Intern":
        st.info("🔒 **Intern View:** Cleared for public & general policy only. Personal PII, salaries, IDs, and medical data are redacted.")
    elif selected_role == "Manager":
        st.warning("📋 **Manager View:** Cleared for team PII & business projects. Personal salaries and medical details remain redacted.")
    else:
        st.success("🏢 **HR View:** Cleared for PII, Aadhaar/PAN, employee compensation, and medical records. Secrets remain blocked.")

    st.markdown("---")
    st.header("⚡ Presentation Presets")
    st.caption("Test the exact scenarios from the PPT deck:")

    for name, p_data in PPT_PRESETS.items():
        if st.button(name, use_container_width=True):
            st.session_state.input_text = p_data["text"]
            st.session_state.llm_output = None
            st.rerun()

    st.markdown("---")
    st.subheader("📊 Clearance Matrix (Slide 4 & 6)")
    matrix_df = pd.DataFrame(ROLE_POLICY_MATRIX)
    st.dataframe(matrix_df, use_container_width=True, hide_index=True)

# ──────────────────────────────────────────────────────────────────────────────
# INPUT SECTION (TEXT OR .TXT FILE - PPT SLIDE 5)
# ──────────────────────────────────────────────────────────────────────────────

st.subheader("1. Input Data Stream")

# Optional file uploader (matching PPT Slide 5: Input: Text / .txt file)
uploaded_file = st.file_uploader("Upload a text file (.txt) or paste below:", type=["txt"])
if uploaded_file is not None:
    st.session_state.input_text = uploaded_file.read().decode("utf-8")

input_text = st.text_area(
    f"Text to be processed (Viewing as: {st.session_state.selected_role}):",
    value=st.session_state.input_text,
    height=95,
    key="input_box"
)

col_b1, col_b2, col_b3 = st.columns([1.5, 1.8, 3])
with col_b1:
    if st.button("🔍 Evaluate Clearance", type="primary", use_container_width=True):
        st.session_state.input_text = input_text
        st.session_state.llm_output = None
        st.rerun()

# Run evaluation
eval_result = evaluate_and_enforce(input_text, st.session_state.selected_role)

with col_b2:
    if st.button("🤖 Simulate AI Ingestion", use_container_width=True):
        st.session_state.llm_output = simulate_llm_response(eval_result["sanitized_text"])
        st.rerun()

# ──────────────────────────────────────────────────────────────────────────────
# METRICS BAR (PPT SLIDE 6: 7 Categories, 3 Roles, 3 Actions)
# ──────────────────────────────────────────────────────────────────────────────

stats = eval_result["stats"]
m1, m2, m3, m4 = st.columns(4)
with m1:
    st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #60a5fa;">{stats["total_findings"]}</div><div class="metric-lbl">Findings Detected</div></div>', unsafe_allow_html=True)
with m2:
    st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #34d399;">{stats["allowed"]}</div><div class="metric-lbl">Allowed (Cleared)</div></div>', unsafe_allow_html=True)
with m3:
    st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #fbbf24;">{stats["redacted"]}</div><div class="metric-lbl">Redacted</div></div>', unsafe_allow_html=True)
with m4:
    st.markdown(f'<div class="metric-card"><div class="metric-num" style="color: #f87171;">{stats["blocked"]}</div><div class="metric-lbl">Blocked (Secrets)</div></div>', unsafe_allow_html=True)

st.markdown("<br/>", unsafe_allow_html=True)

# ──────────────────────────────────────────────────────────────────────────────
# SIDE-BY-SIDE OUTPUT COMPARISON (PPT SLIDE 3 & 5)
# ──────────────────────────────────────────────────────────────────────────────

st.subheader(f"2. Protected Output (Enforced for {st.session_state.selected_role})")
col_raw, col_safe = st.columns(2)

with col_raw:
    st.markdown("**Original Raw Input (Before Firewall):**")
    st.markdown(f'<div class="text-box">{html.escape(eval_result["original_text"])}</div>', unsafe_allow_html=True)

with col_safe:
    st.markdown(f"**ContextGuard Safe View ({st.session_state.selected_role}):**")
    if eval_result["overall_status"] == "BLOCKED":
        st.markdown(f'<div class="blocked-box">{html.escape(eval_result["sanitized_text"])}</div>', unsafe_allow_html=True)
    else:
        # Highlight redacted tags with custom style
        display_safe = html.escape(eval_result["sanitized_text"])
        display_safe = display_safe.replace("[REDACTED:FINANCIAL_PERSONAL]", '<span style="background: #7f1d1d; color: #fca5a5; padding: 2px 6px; border-radius: 4px; font-weight: 600;">[REDACTED:SALARY]</span>')
        display_safe = display_safe.replace("[REDACTED:HEALTH_MEDICAL]", '<span style="background: #312e81; color: #c7d2fe; padding: 2px 6px; border-radius: 4px; font-weight: 600;">[REDACTED:HEALTH]</span>')
        display_safe = display_safe.replace("[REDACTED:NATIONAL_ID]", '<span style="background: #78350f; color: #fde68a; padding: 2px 6px; border-radius: 4px; font-weight: 600;">[REDACTED:ID]</span>')
        display_safe = display_safe.replace("[REDACTED:PII_CONTACT]", '<span style="background: #831843; color: #fbcfe8; padding: 2px 6px; border-radius: 4px; font-weight: 600;">[REDACTED:PII]</span>')
        st.markdown(f'<div class="text-box">{display_safe}</div>', unsafe_allow_html=True)

st.markdown("<br/>", unsafe_allow_html=True)

# ──────────────────────────────────────────────────────────────────────────────
# AUDIT LOG TABLE (PPT SLIDE 3, 5, 6: "Every decision has a reason")
# ──────────────────────────────────────────────────────────────────────────────

st.subheader("3. Transparency & Audit Log")
audit_log = eval_result["audit_log"]

if audit_log:
    table_rows = []
    for item in audit_log:
        act = item["action"]
        if act == "ALLOW":
            act_badge = "✅ ALLOW"
        elif act == "BLOCK":
            act_badge = "⛔ BLOCK"
        else:
            act_badge = "🔒 REDACT"

        table_rows.append({
            "Detected Text": item["detected_text"],
            "Category": item["category"],
            "Description": item["description"],
            "Detector": item["detector"],
            "Role Checked": item["role"],
            "Action": act_badge,
            "Context Rationale": item["reason"]
        })

    df = pd.DataFrame(table_rows)
    st.dataframe(df, use_container_width=True, hide_index=True)
else:
    st.info("No sensitive candidate findings in the submitted text.")

# ──────────────────────────────────────────────────────────────────────────────
# DOWNSTREAM AI INGESTION SIMULATION
# ──────────────────────────────────────────────────────────────────────────────

if st.session_state.llm_output:
    st.markdown("<br/>", unsafe_allow_html=True)
    st.subheader("4. Downstream AI Ingestion Simulation")
    llm = st.session_state.llm_output
    if eval_result["overall_status"] == "BLOCKED":
        st.error("⛔ Pipeline Halted: AI ingestion aborted because critical credentials were blocked.")
    else:
        st.success("✅ Safe Transmission Cleared for AI Processing")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Sanitized Input Delivered to Model:**")
            st.code(llm["sanitized_input"], language="text")
        with c2:
            st.markdown("**Model Response:**")
            st.info(llm["llm_response"])
            st.caption(f"🔒 Security Guarantee: {llm['privacy_guarantee']}")
