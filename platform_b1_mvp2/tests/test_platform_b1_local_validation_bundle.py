import json
import subprocess
import sys
import unittest
from pathlib import Path

from platform_b1_mvp2.validation import platform_b1_local_validation_bundle as bundle


class PlatformB1LocalValidationBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = bundle.run_validation_bundle()
        cls.result_text = json.dumps(cls.result, indent=2)

    def test_bundle_identity_is_locked(self):
        self.assertEqual(
            self.result["bundle_name"],
            "Platform B1 / MVP2 Local Validation Bundle",
        )
        self.assertEqual(
            self.result["bundle_status"],
            "LOCKED_LOCAL_VALIDATION_BUNDLE_ONLY",
        )

    def test_bundle_passes_with_11_validations(self):
        self.assertTrue(self.result["passed"])
        self.assertEqual(self.result["validation_count"], 11)
        self.assertEqual(self.result["failed_validation_count"], 0)
        self.assertEqual(
            self.result["pass_signal"],
            "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED",
        )

    def test_required_commands_are_locked(self):
        required_commands = [
            "digital_twin_object_model_unit_test",
            "digital_twin_mock_fixtures_unit_test",
            "digital_twin_mock_fixture_validator_cli",
            "digital_twin_mock_fixture_validator_unit_test",
            "result_summary_fixture_validator_cli",
            "result_summary_fixture_validator_unit_test",
            "thread_d2_ramat_vision_display_fixture_validator_cli",
            "status_manifest_validator_cli",
            "thread_d2_ramat_vision_display_fixture_validator_unit_test",
            "agentic_ambient_ai_vendor_assurance_passport_validator_cli",
            "local_validation_evidence_ledger_validator_cli",
        ]

        command_ids = [command["id"] for command in self.result["commands_locked"]]

        self.assertEqual(len(command_ids), 11)
        for command_id in required_commands:
            with self.subTest(command_id):
                self.assertIn(command_id, command_ids)
                self.assertIn(command_id, self.result_text)

    def test_required_assurance_outputs_are_present(self):
        required_outputs = [
            "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED",
            "DIGITAL TWIN OBJECT MODEL VALIDATED",
            "DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED",
            "LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION PASSED",
            "THREAD D2 RAMAT VISION DISPLAY FIXTURE VALIDATION PASSED",
            "PLATFORM B1 THREAD D2 LOCAL VALIDATION STATUS MANIFEST VALIDATION PASSED",
            "AI OUTPUT HASHED",
            "HASH VERIFIED",
            "AGENT ACTION NOT ADMISSIBLE",
            "RAMAT VISION DISPLAY READY",
            "PLATFORM B1 DECISION DISPLAYED",
            "AGENTIC AMBIENT AI VENDOR ASSURANCE PASSPORT VALIDATION PASSED",
            "PLATFORM B1 LOCAL VALIDATION EVIDENCE LEDGER VALIDATION PASSED",
        ]

        for output in required_outputs:
            with self.subTest(output):
                self.assertIn(output, self.result["assurance_outputs"])
                self.assertIn(output, self.result_text)

    def test_evidence_ledger_validator_result_passed(self):
        ledger_results = [
            item for item in self.result["results"]
            if item["id"] == "local_validation_evidence_ledger_validator_cli"
        ]

        self.assertEqual(len(ledger_results), 1)
        self.assertTrue(ledger_results[0]["passed"])
        self.assertTrue(ledger_results[0]["expected_signal_found"])
        self.assertIn(
            "PLATFORM B1 LOCAL VALIDATION EVIDENCE LEDGER VALIDATION PASSED",
            ledger_results[0]["stdout"],
        )

    def test_agentic_validator_result_still_present(self):
        agentic_results = [
            item for item in self.result["results"]
            if item["id"] == "agentic_ambient_ai_vendor_assurance_passport_validator_cli"
        ]

        self.assertEqual(len(agentic_results), 1)
        self.assertTrue(agentic_results[0]["passed"])
        self.assertTrue(agentic_results[0]["expected_signal_found"])

    def test_boundary_is_preserved(self):
        required_boundary = [
            "No status manifest update yet.",
            "No Azure deployment.",
            "No Azure Digital Twins deployment.",
            "No Platform B v1 change.",
            "No Thread D v1 change.",
            "No MVP3 activation.",
            "No PHI.",
            "No company production data.",
            "No regulated action execution.",
            "No binding operational consequence.",
            "Platform B1 evaluates.",
            "Thread D2 displays.",
            "RAMAT Vision displays only.",
            "Official records remain in source systems.",
            "Humans remain accountable.",
        ]

        boundary_text = " ".join(self.result["boundary"])
        for boundary in required_boundary:
            with self.subTest(boundary):
                self.assertIn(boundary, boundary_text)

    def test_bundle_cli_emits_pass_signal(self):
        completed = subprocess.run(
            [sys.executable, str(Path(bundle.__file__).resolve())],
            capture_output=True,
            text=True,
        )

        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED", completed.stdout)
        self.assertIn("local_validation_evidence_ledger_validator_cli", completed.stdout)
        self.assertIn(
            "PLATFORM B1 LOCAL VALIDATION EVIDENCE LEDGER VALIDATION PASSED",
            completed.stdout,
        )


if __name__ == "__main__":
    unittest.main()

