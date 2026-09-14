import sys
import os
import json

sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chat_analyst import process_chat_query

demo_tests = [
    ("1. Investigate USR-1001", "Investigate USR-1001", "USR-1001"),
    ("2. Why is USR-1001 critical?", "Why is USR-1001 critical?", "USR-1001"),
    ("3. Show the evidence.", "Show the evidence.", "USR-1001"),
    ("4. What happened on the endpoint?", "What happened on the endpoint?", "USR-1001"),
    ("5. How much network traffic occurred?", "How much network traffic occurred?", "USR-1001"),
    ("6. What threats are active?", "What threats are active?", "USR-1001"),
    ("7. Investigate USR-1002", "Investigate USR-1002", "USR-1002"),
    ("8. Compare USR-1001 and USR-1002", "Compare USR-1001 and USR-1002", "USR-1001"),
    ("9. Investigate USR-1004", "Investigate USR-1004", "USR-1004"),
    ("10. Investigate USR-9999", "Investigate USR-9999", "USR-9999"),
    ("11. Does network traffic alone prove exfiltration?", "Does network traffic alone prove exfiltration?", "USR-1001"),
    ("12. What data sources did you use?", "What data sources did you use?", "USR-1001"),
]

print("==================================================")
print("  EXECUTING 12 DEMO TEST SUITES FOR CONVERSATIONAL AI")
print("==================================================\n")

for label, query, ctx in demo_tests:
    res = process_chat_query(query, ctx)
    print(f"--- {label} ---")
    print(f"QUERY: {query}")
    print(f"TARGET USER ID: {res.get('active_user_id')}")
    print(f"ANSWER SNIPPET:\n{res.get('answer')[:300]}...\n")
    print("--------------------------------------------------\n")
