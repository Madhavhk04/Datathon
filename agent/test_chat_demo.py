import sys
import os
import json

sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chat_analyst import process_chat_query

demo_tests = [
    ("1. Investigate EMP11218", "Investigate EMP11218", "EMP11218"),
    ("2. Why is EMP11218 critical?", "Why is EMP11218 critical?", "EMP11218"),
    ("3. Show the evidence.", "Show the evidence.", "EMP11218"),
    ("4. What happened on the endpoint?", "What happened on the endpoint?", "EMP11218"),
    ("5. How much network traffic occurred?", "How much network traffic occurred?", "EMP11218"),
    ("6. What threats are active?", "What threats are active?", "EMP11218"),
    ("7. Investigate EMP10296", "Investigate EMP10296", "EMP10296"),
    ("8. Compare EMP11218 and EMP10296", "Compare EMP11218 and EMP10296", "EMP11218"),
    ("9. Investigate EMP10002 (Low Risk)", "Investigate EMP10002", "EMP10002"),
    ("10. Investigate EMP99999 (Not Found)", "Investigate EMP99999", "EMP99999"),
    ("11. Does network traffic alone prove exfiltration?", "Does network traffic alone prove exfiltration?", "EMP11218"),
    ("12. What data sources did you use?", "What data sources did you use?", "EMP11218"),
]

print("==================================================")
print("  EXECUTING 12 DEMO TEST SUITES FOR CONVERSATIONAL AI")
print("  (100% REAL TELEMETRY DATASETS)")
print("==================================================\n")

for label, query, ctx in demo_tests:
    res = process_chat_query(query, ctx)
    print(f"--- {label} ---")
    print(f"QUERY: {query}")
    print(f"TARGET USER ID: {res.get('active_user_id')}")
    print(f"ANSWER SNIPPET:\n{res.get('answer')[:350]}...\n")
    print("--------------------------------------------------\n")
