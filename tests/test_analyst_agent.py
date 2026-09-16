import pytest
import os
import sys

# Add agent directory to sys.path directly to import agent.py directly as a module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../agent')))

from agent import chat_with_analyst

def test_greeting():
    '''Expected: Respond naturally without running an investigation.'''
    res = chat_with_analyst("hello")
    ans = res['answer'].lower()
    assert "hello" in ans or "hi" in ans
    assert "investigate" in ans
    assert not res.get('evidence') or not res['evidence'].get('USR-1001', {}).get('active_threat_detections')

def test_general_investigate():
    '''Expected: Investigate USR-1001 and give an overall summary.'''
    res = chat_with_analyst("Investigate USR-1001")
    assert "EMP11218" in res['target_users'] or "USR-1001" in res['target_users']
    assert len(res['evidence']) > 0

def test_why_critical():
    '''Expected: Explain the evidence supporting critical classification for USR-1001.'''
    res = chat_with_analyst("Why is USR-1001 critical?")
    ans = res['answer'].lower()
    assert "risk" in ans or "score" in ans or "critical" in ans

def test_show_evidence():
    '''Expected: Return the relevant evidence events.'''
    res = chat_with_analyst("Show me the evidence for USR-1001")
    assert "EMP11218" in res['target_users'] or "USR-1001" in res['target_users']
    assert res['evidence']

def test_endpoint():
    '''Expected: Focus specifically on endpoint/EDR events.'''
    res = chat_with_analyst("What happened on the endpoint?", context_user_id="USR-1001")
    ans = res['answer'].lower()
    assert "endpoint" in ans or "edr" in ans or "alert" in ans

def test_network_traffic():
    '''Expected: Focus on firewall/network telemetry.'''
    res = chat_with_analyst("How much network traffic occurred?", context_user_id="USR-1001")
    ans = res['answer'].lower()
    assert "mb" in ans or "byte" in ans or "network" in ans or "firewall" in ans or "traffic" in ans

def test_exfiltration():
    '''Expected: Distinguish observed network traffic from exfiltration conclusion.'''
    res = chat_with_analyst("Does 200 MB of traffic prove data exfiltration?", context_user_id="USR-1001")
    ans = res['answer'].lower()
    assert "exfiltration" in ans
    assert "prove" in ans or "does not" in ans or "not necessarily" in ans or "corroborating" in ans or "alone" in ans

def test_mfa_failures():
    '''Expected: Search actual telemetry and explicitly mention MFA failure state.'''
    res = chat_with_analyst("What MFA failures did USR-1001 have?")
    ans = res['answer'].lower()
    assert "mfa" in ans or "multi-factor" in ans
    
def test_salary():
    '''Expected: The LLM must explicitly state the datasets do not contain salary info.'''
    res = chat_with_analyst("What is USR-1001's salary?")
    ans = res['answer'].lower()
    assert "don't have that information" in ans or "not present" in ans or "available security datasets" in ans

def test_investigate_other():
    '''Expected: Investigate USR-1004, not USR-1001.'''
    res = chat_with_analyst("Investigate USR-1004")
    assert "EMP12745" in res['target_users'] or "USR-1004" in res['target_users']
    assert "EMP11218" not in res['target_users'] and "USR-1001" not in res['target_users']

def test_compare_users():
    '''Expected: Retrieve BOTH users and provide a comparison.'''
    res = chat_with_analyst("Compare USR-1001 and USR-1002")
    users = res['target_users']
    assert ("EMP11218" in users or "USR-1001" in users)
    assert ("EMP10296" in users or "USR-1002" in users)
    assert len(res['evidence']) >= 2

def test_quick_prompt_critical_accounts():
    '''Expected: Return list of critical accounts when asked "Which accounts are critical?"'''
    res = chat_with_analyst("Which accounts are critical?")
    ans = res['answer'].lower()
    assert "critical" in ans or "emp11218" in ans
    assert len(res.get('target_users', [])) >= 1 or "emp11218" in ans

def test_unknown_user_handling():
    '''Expected: Explicitly state user ID is not found in datasets instead of defaulting or hallucinating.'''
    res = chat_with_analyst("investigate emp567")
    ans = res['answer'].lower()
    assert "don't have information" in ans or "not present" in ans or "emp567" in ans
    assert "karan goda" not in ans


