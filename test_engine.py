from privacy_engine import scan_and_sanitize, simulate_llm_response
import json

presets = [
    ("Preset 1: Public Contact (PASS)", "For any inquiries or enterprise sales questions, please reach out to Alice at alice@acme.com."),
    ("Preset 2: Confidential Health (PSEUDONYMIZE)", "Please note that Alice at alice@acme.com was diagnosed with leukemia and will begin chemotherapy treatment tomorrow."),
    ("Preset 3: Internal Financial (REDACT)", "Finance team: Rahul's Q4 appraisal bonus of $18,500 has been transferred to his account ending in 4102."),
    ("Preset 4: Generic PII (MASK)", "Call me on 9845012345 when you arrive at the gate.")
]

for title, text in presets:
    print(f"\n{'='*60}\n{title}\n{'='*60}")
    res = scan_and_sanitize(text)
    print("Original :", res["original_text"])
    print("Sanitized:", res["sanitized_text"])
    print("Telemetry:")
    for item in res["telemetry"]:
        print(f"  • {item['value']} [{item['entity_type']}] -> Action: {item['action']} ({item['category']}) | Risk: {item['risk_tier']}")
        print(f"    Replacement: {item['replacement']}")
        print(f"    Rationale  : {item['reason']}")

print("\n" + "="*60 + "\nTesting Safe LLM Simulation\n" + "="*60)
sample_sanitized = res["sanitized_text"]
llm_sim = simulate_llm_response(sample_sanitized)
print("LLM Response:\n", llm_sim["llm_response"])
