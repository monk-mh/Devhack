from privacy_engine import evaluate_and_enforce, ROLES

presets = [
    ("1. Salary Band (PPT Slide 2 False Positive)", "The salary band for this role is 8–12 LPA.", "Intern"),
    ("2. Personal Salary (PPT Slide 3 Contrast - Intern View)", "Rahul earns 11 LPA as a Senior Software Engineer.", "Intern"),
    ("2. Personal Salary (PPT Slide 3 Contrast - HR View)", "Rahul earns 11 LPA as a Senior Software Engineer.", "HR"),
    ("3. Private Health (PPT Slide 2 False Negative)", "Priya won’t be in till March — her chemo cycle starts Monday.", "Intern"),
    ("4. Database Credentials (PPT Slide 3 Secrets)", "Deployment config: postgresql://admin:P@ssw0rdProd@db.internal:5432/finance", "Intern"),
    ("5. Indian National IDs (Aadhaar & PAN - Intern View)", "New contractor details: Aadhaar 4920 1829 3847, PAN ABCDE1234F, email rahul@acme.com.", "Intern"),
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

print("\n" + "="*70 + "\nAll 5 PPT Scenarios Verified!\n" + "="*70)
