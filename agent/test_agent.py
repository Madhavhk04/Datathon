import unittest
import json
import os
import sys

# Add parent directory to sys.path to ensure imports work smoothly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools import (
    get_user_risk,
    get_user_threats,
    get_identity_context,
    get_iam_events,
    get_endpoint_events,
    get_firewall_events,
    get_related_hosts,
    build_evidence_timeline
)
from agent import investigate_user
from chat_analyst import process_chat_query

class TestAISecurityAgent(unittest.TestCase):

    def test_01_tools_data_retrieval(self):
        """Test individual tool data retrieval functions against real production data."""
        uid = "EMP11218"
        risk = get_user_risk(uid)
        self.assertEqual(risk["user_id"], uid)
        self.assertEqual(risk["risk_score"], 86.5)
        self.assertEqual(risk["risk_band"].upper(), "CRITICAL")
        self.assertTrue(risk["post_termination_flag"])
        self.assertIn("score_breakdown", risk)
        self.assertIn("authentication", risk["score_breakdown"])

        threats = get_user_threats(uid)
        self.assertEqual(threats["user_id"], uid)
        self.assertGreaterEqual(len(threats["threat_detections"]), 1)
        self.assertIsNotNone(threats["investigation_queue"])
        self.assertEqual(threats["investigation_queue"]["investigation_priority"], "Critical")

        identity = get_identity_context(uid)
        self.assertEqual(identity["user_id"], uid)
        self.assertEqual(identity["user_name"], "Karan Goda")
        self.assertEqual(identity["employment_status"], "Disabled")
        self.assertEqual(identity["termination_date"], "2023-07-18 22:30:35")
        self.assertEqual(identity["hostname"], "WS-11218")

        iam = get_iam_events(uid, limit=10)
        self.assertGreaterEqual(len(iam), 1)

        edr = get_endpoint_events(uid, limit=10)
        self.assertGreaterEqual(len(edr), 1)

        hosts = get_related_hosts(uid)
        self.assertIn("WS-11218", [h.upper() for h in hosts])

        fw = get_firewall_events(uid, limit=10)
        self.assertGreaterEqual(len(fw), 1)

        timeline = build_evidence_timeline(uid)
        self.assertGreaterEqual(len(timeline["timeline"]), 1)
        self.assertIn("chart_data", timeline)
        self.assertGreaterEqual(len(timeline["chart_data"]), 1)

    def test_02_critical_user_investigation(self):
        """Test real investigation report generation for Top Critical User EMP11218."""
        report = investigate_user("EMP11218")
        self.assertEqual(report["user_id"], "EMP11218")
        self.assertEqual(report["user_name"], "Karan Goda")
        self.assertEqual(report["overall_risk"]["band"], "CRITICAL")
        self.assertEqual(report["overall_risk"]["score"], 86.5)
        
        # Verify post-termination detection rule guardrail
        critical_findings_str = " ".join(report["critical_findings"])
        self.assertIn("post-termination activity detected", critical_findings_str.lower())
        
        # Verify active threats populated
        self.assertGreaterEqual(len(report["active_threats"]), 1)
        
        # Verify chart data
        self.assertGreater(len(report["chart_data"]), 0)

    def test_03_high_priority_user_investigation(self):
        """Test investigation report generation for Priority Rank 2 User EMP10296."""
        report = investigate_user("EMP10296")
        self.assertEqual(report["user_id"], "EMP10296")
        self.assertEqual(report["user_name"], "Osha Kapur")
        self.assertEqual(report["overall_risk"]["band"], "CRITICAL")
        self.assertEqual(report["overall_risk"]["score"], 83.0)

    def test_04_low_risk_user_investigation(self):
        """Test investigation report generation for Low Risk User EMP10002."""
        report = investigate_user("EMP10002")
        self.assertEqual(report["user_id"], "EMP10002")
        self.assertEqual(report["overall_risk"]["band"], "LOW")
        self.assertLessEqual(report["overall_risk"]["score"], 39.0)

    def test_05_chat_analyst_query(self):
        """Test conversational AI analyst query processing and actions contract with real data."""
        res = process_chat_query("Investigate EMP11218", "EMP11218")
        self.assertEqual(res["active_user_id"], "EMP11218")
        self.assertIn("Karan Goda", res["answer"])
        self.assertIn("quick_actions", res)
        self.assertIn("suggested_actions", res)
        self.assertEqual(res["quick_actions"], res["suggested_actions"])

    def test_06_uncertainty_verification(self):
        """Test that challenge/uncertainty question is correctly answered without intent shadowing."""
        res = process_chat_query("Does network traffic alone prove exfiltration?", "EMP11218")
        self.assertIn("Threat Hypothesis Verification & Uncertainty Challenge", res["answer"])
        self.assertIn("does NOT provide definitive proof", res["answer"])

    def test_07_highest_risk_user_query(self):
        """Test dynamic highest-risk user query resolution."""
        res = process_chat_query("Who is the highest risk user?")
        self.assertIn("EMP11218", res["answer"])
        self.assertIn("Karan Goda", res["answer"])

if __name__ == "__main__":
    unittest.main()
