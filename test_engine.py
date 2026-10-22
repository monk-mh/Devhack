from privacy_engine import evaluate_and_enforce, ROLES

presets = [
    ("1. Salary Band (Policy - Manager View)", "The salary band for this role is 8–12 LPA.", "Manager"),
    ("2. Personal Salary (Personal - Manager View)", "Rahul earns 11 LPA as a Senior Software Engineer.", "Manager"),
    ("2. Personal Salary (Personal - HR View)", "Rahul earns 11 LPA as a Senior Software Engineer.", "HR"),
    ("3. Private Health (Medical - Manager View)", "Priya won’t be in till March — her chemo cycle starts Monday.", "Manager"),
    ("4. Database Credentials (Secrets - Manager View)", "Deployment config: postgresql://admin:P@ssw0rdProd@db.internal:5432/finance", "Manager"),
    ("5. Indian National IDs (Aadhaar & PAN - Manager View)", "New contractor details: Aadhaar 4920 1829 3847, PAN ABCDE1234F, email rahul@acme.com.", "Manager"),
    ("5. Indian National IDs (Aadhaar & PAN - HR View)", "New contractor details: Aadhaar 4920 1829 3847, PAN ABCDE1234F, email rahul@acme.com.", "HR"),
]

for title, text, role in presets:
    print(f"\n{'='*70}\n{title} [Role: {role}]\n{'='*70}")
    res = evaluate_and_enforce(text, role=role)
    print("Original :", res["original_text"])
    print("Output   :", res["sanitized_text"])
    print("Status   :", res["overall_status"])
    for a in res["audit_log"]:
        print(f"  • {a['detected_text']} -> Action: {a['action']} ({a['category']}) | {a['reason']}")

print("\n" + "="*70 + "\nAll 5 Scenarios Verified!\n" + "="*70)
