# 🛡️ ContextGuard — Privacy Firewall for AI
> **Problem Statement: DEVHOST 2026 — PS 2.2**  
> **Team Name:** `Error404` | **Institution:** `St Joseph Engineering College, Vamanjoor Mangalore`  
> **Team Members:** Nikhil A Poojary, Kavya D Marla, Manvith Bangera, Sudharshan  

---

## 📌 Executive Summary
**ContextGuard** is a context-aware data privacy firewall that sits between business data and AI systems. It evaluates information in context, enforces role-based clearance (**Intern · Manager · HR**), and dynamically **Allows**, **Redacts**, or **Blocks** unauthorized exposure.

> *"The same information needs different protection depending on who is asking."*

---

## ⚡ The Core Problem & Context-Aware Solution

| Traditional Keyword Filter *(Flawed)* | ContextGuard Firewall *(Our Solution)* |
| :--- | :--- |
| **False Positive:** Blocks general policy information like *"The salary band for this role is 8–12 LPA"* because it sees words like "salary". | **Context Analysis (Layer 2):** Identifies organizational pay range / policy data and **`ALLOWS`** it for all roles with zero over-redaction. |
| **False Negative:** Allows private medical text like *"Priya won’t be in till March — her chemo cycle starts Monday"* because there is no keyword trigger. | **Semantic Context:** Recognizes chemotherapy treatment disclosures and **`REDACTS`** to protect health privacy. |
| **Blanket Treatment:** Treats an intern the same as an HR manager. | **Least Privilege by Design:** Personal salary disclosures (e.g. *"Rahul earns 11 LPA"*) are **`REDACTED`** for Interns & Managers, but **`ALLOWED`** for HR personnel. |
| **Secrets Exposure:** Leaks connection strings into LLM training context. | **Hard Stop Security:** Critical infrastructure credentials (e.g. `postgresql://...`) **`BLOCK`** the entire transmission immediately. |

---

## 📊 Role-Based Clearance Matrix (7 Categories × 3 Roles)

| Sensitivity Category | Description | 🔒 Intern View | 📋 Manager View | 🏢 HR View |
| :--- | :--- | :---: | :---: | :---: |
| **1. Credentials & Secrets** | Database URIs, passwords, API tokens | ⛔ **BLOCK** | ⛔ **BLOCK** | ⛔ **BLOCK** |
| **2. Private Health & Chemo** | Medical conditions, cancer, chemotherapy | 🔒 **REDACT** | 🔒 **REDACT** | 🔒 **REDACT** |
| **3. Personal Compensation** | Individual employee salaries & bonuses | 🔒 **REDACT** | 🔒 **REDACT** | ✅ **ALLOW** |
| **4. General Salary Band** | Organizational pay scale & hiring budget | ✅ **ALLOW** | ✅ **ALLOW** | ✅ **ALLOW** |
| **5. Indian National IDs** | Indian Aadhaar (12-digit) & PAN | 🔒 **REDACT** | 🔒 **REDACT** | ✅ **ALLOW** |
| **6. Contact Information** | Personal phone numbers & personal emails | 🔒 **REDACT** | ✅ **ALLOW** | ✅ **ALLOW** |
| **7. Public Business Directory** | Support desks, sales emails, press contacts | ✅ **ALLOW** | ✅ **ALLOW** | ✅ **ALLOW** |

---

## 🧪 5 Presentation Benchmark Scenarios (PPT Slides 2 & 3)

1. **Preset 1 (Salary Band - Slide 2 False Positive):**  
   `"The salary band for this role is 8–12 LPA."`  
   ➜ **Result:** **`ALLOW`** for all roles (Zero false-positive over-redaction).

2. **Preset 2 (Personal Salary - Slide 3 Contrast):**  
   `"Rahul earns 11 LPA as a Senior Software Engineer."`  
   ➜ **Result:** **`REDACTED`** for Intern/Manager (`[REDACTED:SALARY]`), **`ALLOW`** for HR.

3. **Preset 3 (Private Health - Slide 2 False Negative):**  
   `"Priya won’t be in till March — her chemo cycle starts Monday."`  
   ➜ **Result:** **`REDACTED`** (`[REDACTED:HEALTH]`) protecting confidential medical data.

4. **Preset 4 (Database Credentials - Slide 3 Secrets):**  
   `"Deployment config: postgresql://admin:P@ssw0rdProd@db.internal:5432/finance"`  
   ➜ **Result:** ⛔ **`TRANSMISSION BLOCKED`** for all roles before reaching the AI.

5. **Preset 5 (Indian National IDs - Aadhaar & PAN):**  
   `"New contractor details: Aadhaar 4920 1829 3847, PAN ABCDE1234F, email rahul@acme.com."`  
   ➜ **Result:** **`REDACTED`** for Intern, **`ALLOW`** for HR onboarding.

---

## 🚀 Quickstart & Running Locally

### 1. Run the Streamlit Interactive Dashboard
```bash
py -m streamlit run dashboard.py
```
*Live at: `http://localhost:8501`*

### 2. Run the FastAPI Backend Server (Optional)
```bash
py -m uvicorn server:app --host 127.0.0.1 --port 8000 --reload
```
*API docs at: `http://localhost:8000/docs`*

### 3. Run Automated Benchmark Test Suite
```bash
py -u test_engine.py
```
