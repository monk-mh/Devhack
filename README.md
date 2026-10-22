# 🛡️ PrivacyShield AI — Context-Aware Data Privacy Guard
> **Problem Statement: DEVHOST 2026 — PS 2.2**  
> Dynamic Semantic Risk Evaluation & Policy Enforcement (PASS, MASK, PSEUDONYMIZE, REDACT)

---

## 📌 Problem & Context
Standard privacy filters and regex patterns suffer from two major flaws:
1. **Over-redaction (False Positives)**: Redacting emails or names from public sales/support inquiries breaks customer support channels.
2. **False Negatives & Privacy Leaks**: Missing sensitive healthcare or financial details when tokens change context.

**PrivacyShield AI** analyzes candidate entities (PII, Financial, Medical, Contact) within a **70-character sliding semantic context window** and dynamically assigns one of four policies:

| Policy | Context Trigger Cues | Risk Tier | Action Description | Example |
| :--- | :--- | :---: | :--- | :--- |
| 🟢 **PASS** | `PUBLIC_BUSINESS` (*sales, support, inquiries, contact*) | **LOW** | Allows data through untouched without over-redaction | `alice@acme.com` |
| 🟡 **MASK** | `GENERAL_PII` (*unattributed phone, personal contact*) | **MEDIUM** | Partial obfuscation preserving structure & utility | `98450****5` |
| 🔵 **PSEUDONYMIZE** | `HEALTH_CONFIDENTIAL` (*diagnosed, leukemia, treatment, medical*) | **HIGH** | Reversible surrogate token stored in protected mapping | `[PERSON_REF_101]` |
| 🔴 **REDACT** | `FINANCIAL_INTERNAL` (*salary, bonus, appraisal, account*) | **HIGH** | Complete irreversible removal | `[REDACTED_FINANCIAL]` |

---

## 🚀 Quickstart (Run in 2 Commands)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 2. Start Backend & Dashboard

**Command 1 (FastAPI Server):**
```bash
python -m uvicorn server:app --host 127.0.0.1 --port 8000 --reload
```
*API running at `http://localhost:8000` | Swagger interactive docs at `http://localhost:8000/docs`*

**Command 2 (Streamlit Interactive Dashboard):**
```bash
python -m streamlit run dashboard.py
```
*Dashboard running at `http://localhost:8501`*

---

## 🧪 Benchmark Demonstration Presets

Click any of the 4 benchmark presets in the dashboard sidebar to evaluate context-awareness instantly:

- **Preset 1 (Public Contact ➜ PASS)**  
  `"For any inquiries or enterprise sales questions, please reach out to Alice at alice@acme.com."`  
  *Result*: Both `Alice` and `alice@acme.com` are passed untouched because public sales cues are present.
- **Preset 2 (Confidential Health ➜ PSEUDONYMIZE)**  
  `"Please note that Alice at alice@acme.com was diagnosed with leukemia and will begin chemotherapy treatment tomorrow."`  
  *Result*: Replaced with `[PERSON_REF_101]` and `[EMAIL_REF_101]`. Reversible token mapped in secure surrogate store.
- **Preset 3 (Internal Financial ➜ REDACT)**  
  `"Finance team: Rahul's Q4 appraisal bonus of $18,500 has been transferred to his account ending in 4102."`  
  *Result*: Replaced with `[REDACTED_FINANCIAL]`.
- **Preset 4 (Generic PII ➜ MASK)**  
  `"Call me on 9845012345 when you arrive at the gate."`  
  *Result*: Masked to `98450****5`.

---

## 📡 API Specification

### 1. `POST /api/scan`
Evaluates text and returns sanitized output and comprehensive decision telemetry.

**Request:**
```json
{
  "text": "For any inquiries or enterprise sales questions, please reach out to Alice at alice@acme.com."
}
```

**Response:**
```json
{
  "original_text": "For any inquiries or enterprise sales questions, please reach out to Alice at alice@acme.com.",
  "sanitized_text": "For any inquiries or enterprise sales questions, please reach out to Alice at alice@acme.com.",
  "telemetry": [
    {
      "entity_type": "PERSON",
      "value": "Alice",
      "start": 69,
      "end": 74,
      "risk_tier": "LOW",
      "action": "PASS",
      "category": "PUBLIC_BUSINESS",
      "replacement": "Alice",
      "reason": "Public business directory or support channel cues detected (sales, inquiries). Safe to pass untouched."
    },
    {
      "entity_type": "EMAIL_ADDRESS",
      "value": "alice@acme.com",
      "start": 78,
      "end": 92,
      "risk_tier": "LOW",
      "action": "PASS",
      "category": "PUBLIC_BUSINESS",
      "replacement": "alice@acme.com",
      "reason": "Public business directory or support channel cues detected (sales, inquiries). Safe to pass untouched."
    }
  ],
  "stats": {
    "total": 2,
    "pass": 2,
    "mask": 0,
    "pseudonymize": 0,
    "redact": 0
  }
}
```

### 2. `POST /api/simulate-llm`
Forwards sanitized text downstream to prove reasoning works without exposing raw sensitive data.

**Request:**
```json
{
  "sanitized_text": "Please note that [PERSON_REF_101] at [EMAIL_REF_101] was diagnosed with leukemia.",
  "query": "Summarize the request and action items safely."
}
```

**Response:**
```json
{
  "query": "Summarize the request and action items safely.",
  "sanitized_input": "Please note that [PERSON_REF_101] at [EMAIL_REF_101] was diagnosed with leukemia.",
  "llm_response": "Safe LLM Processing Complete.\n\nContext Comprehension: The downstream AI received the sanitized prompt without raw PII exposure.\nKey Entities Handled: 1 context boundaries applied.\nAnalysis: Identified clinical/health record associated with anonymous surrogate reference. Protected from HIPAA exposure.",
  "privacy_guarantee": "Zero raw sensitive PII transmitted to external model provider."
}
```

---

## 📂 Project Structure
```
devhack/
├── requirements.txt      # Dependency manifest (FastAPI, Presidio, Streamlit)
├── privacy_engine.py     # Core NLP sliding-window context evaluator & policy engine
├── server.py             # Production FastAPI REST backend
├── dashboard.py          # Interactive Streamlit UI with presets & telemetry
├── test_engine.py        # Automated test suite for all 4 benchmark presets
├── index.html            # Standalone Vanilla Web Application (alternative frontend)
├── app.js                # Frontend controller & UI interactions
├── engine.js             # Client-side context engine
└── style.css             # Dark-mode glassmorphic styling
```
