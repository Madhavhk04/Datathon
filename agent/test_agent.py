import unittest
import json
import os
import sys

# Add parent directory to sys.path to ensure imports work smoothly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools import get_user_risk, get_user_threats, get_identity_context, build_evidence_timeline
from agent import investigate_user

class TestAISecurityAgent(unittest.TestCase):

    def test_01_tools_data_retrieval(self):
        """Test individual tool data retrieval functions."""
        risk = get_user_risk("USR-1001")
        self.assertEqual(risk["risk_score"], 92)
        self.assertEqual(risk["risk_band"], "CRITICAL")
        self.assertIn("score_breakdown", risk)

        threats = get_user_threats("USR-1001")
        self.assertGreaterEqual(len(threats["threat_detections"]), 1)

        identity = get_identity_context("USR-1001")
        self.assertEqual(identity["user_name"], "Alex Vance")
        self.assertEqual(identity["employment_status"], "TERMINATED")

        timeline = build_evidence_timeline("USR-1001")
        self.assertGreaterEqual(len(timeline["timeline"]), 1)
        self.assertIn("chart_data", timeline)
        self.assertGreaterEqual(len(timeline["chart_data"]), 1)

    def test_02_critical_user_investigation(self):
        """Test investigation report generation for Critical User USR-1001."""
        report = investigate_user("USR-1001")
        self.assertEqual(report["user_id"], "USR-1001")
        self.assertEqual(report["overall_risk"]["band"], "CRITICAL")
        self.assertGreaterEqual(report["overall_risk"]["score"], 80)
        
        # Verify post-termination detection rule guardrail
        critical_findings_str = " ".join(report["critical_findings"])
        self.assertIn("Post-termination activity detected", critical_findings_str)
        
        # Verify chart data
        self.assertGreater(len(report["chart_data"]), 0)

    def test_03_high_user_investigation(self):
        """Test investigation report generation for High Risk User USR-1002."""
        report = investigate_user("USR-1002")
        self.assertEqual(report["user_id"], "USR-1002")
        self.assertEqual(report["overall_risk"]["band"], "HIGH")
        self.assertEqual(report["employment_status"], "ACTIVE")

    def test_04_medium_user_investigation(self):
        """Test investigation report generation for Medium Risk User USR-1003."""
        report = investigate_user("USR-1003")
        self.assertEqual(report["user_id"], "USR-1003")
        self.assertEqual(report["overall_risk"]["band"], "MEDIUM")

    def test_05_chat_analyst_query(self):
        """Test conversational AI analyst query processing and suggested_actions contract."""
        from chat_analyst import process_chat_query
        res = process_chat_query("Investigate USR-1001", "USR-1001")
        self.assertEqual(res["active_user_id"], "USR-1001")
        self.assertIn("Alex Vance", res["answer"])
        self.assertIn("quick_actions", res)
        self.assertIn("suggested_actions", res)
        self.assertEqual(res["quick_actions"], res["suggested_actions"])

    def test_06_uncertainty_verification(self):
        """Test that challenge/uncertainty question is correctly answered without intent shadowing."""
        from chat_analyst import process_chat_query
        res = process_chat_query("Does network traffic alone prove exfiltration?", "USR-1001")
        self.assertIn("Threat Hypothesis Verification & Uncertainty Challenge", res["answer"])
        self.assertIn("does NOT provide definitive proof", res["answer"])

if __name__ == "__main__":
    unittest.main()
