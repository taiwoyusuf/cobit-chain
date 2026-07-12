import unittest

from platform_b1_mvp2.validation import platform_b1_local_validation_bundle as bundle


EXPECTED_COMMAND_IDS = [
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
]

EXPECTED_ASSURANCE_OUTPUTS = [
    "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED",
    "DIGITAL TWIN OBJECT MODEL VALIDATED",
    "DIGITAL TWIN MOCK FIXTURE VALIDATION PASSED",
    "LOCAL VALIDATION RESULT SUMMARY FIXTURE VALIDATION PASSED",
    "THREAD D2 RAMAT VISION DISPLAY FIXTURE VALIDATION PASSED",
    "AI OUTPUT HASHED",
    "HASH VERIFIED",
    "AGENT ACTION NOT ADMISSIBLE",
    "RAMAT VISION DISPLAY READY",
    "PLATFORM B1 DECISION DISPLAYED",
    "AGENTIC AMBIENT AI VENDOR ASSURANCE PASSPORT VALIDATION PASSED",
]


class PlatformB1LocalValidationBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = bundle.run_bundle()

    def test_bundle_identity_is_locked(self):
        self.assertEqual(
            self.result["bundle_name"],
            "Platform B1 / MVP2 Local Validation Bundle",
        )
        self.assertEqual(
            self.result["bundle_status"],
            "LOCKED_LOCAL_VALIDATION_BUNDLE_ONLY",
        )
        self.assertEqual(
            self.result["pass_signal"],
            "PLATFORM B1 LOCAL VALIDATION BUNDLE PASSED",
        )

    def test_bundle_passes_with_validation_count_10(self):
        self.assertTrue(self.result["passed"])
        self.assertEqual(self.result["validation_count"], 10)
        self.assertEqual(self.result["failed_validation_count"], 0)
        self.assertEqual(len(self.result["results"]), 10)

    def test_all_results_pass(self):
        for validation_result in self.result["results"]:
            with self.subTest(validation_result["id"]):
                self.assertTrue(validation_result["passed"])
                self.assertEqual(validation_result["returncode"], 0)
                self.assertTrue(validation_result["expected_signal_found"])

    def test_command_ids_are_locked(self):
        result_ids = [entry["id"] for entry in self.result["results"]]
        command_ids = [entry["id"] for entry in self.result["commands_locked"]]

        self.assertEqual(result_ids, EXPECTED_COMMAND_IDS)
        self.assertEqual(command_ids, EXPECTED_COMMAND_IDS)

    def test_agentic_ambient_ai_validator_is_included(self):
        matching = [
            entry for entry in self.result["results"]
            if entry["id"] == "agentic_ambient_ai_vendor_assurance_passport_validator_cli"
        ]
        self.assertEqual(len(matching), 1)

        validator_result = matching[0]
        self.assertTrue(validator_result["passed"])
        self.assertTrue(validator_result["expected_signal_found"])
        self.assertEqual(
            validator_result["expected_signal"],
            "AGENTIC AMBIENT AI VENDOR ASSURANCE PASSPORT VALIDATION PASSED",
        )
        self.assertIn(
            "platform_b1_agentic_ambient_ai_vendor_assurance_passport_validator.py",
            " ".join(validator_result["command"]),
        )

    def test_assurance_outputs_are_locked(self):
        self.assertEqual(
            self.result["assurance_outputs"],
            EXPECTED_ASSURANCE_OUTPUTS,
        )
        self.assertIn(
            "AGENTIC AMBIENT AI VENDOR ASSURANCE PASSPORT VALIDATION PASSED",
            self.result["assurance_outputs"],
        )

    def test_boundary_terms_are_preserved(self):
        boundary = " ".join(self.result["boundary"])

        self.assertIn("No Azure deployment.", boundary)
        self.assertIn("No Azure Digital Twins deployment.", boundary)
        self.assertIn("No Platform B v1 change.", boundary)
        self.assertIn("No Thread D v1 change.", boundary)
        self.assertIn("No MVP3 activation.", boundary)
        self.assertIn("No PHI.", boundary)
        self.assertIn("No company production data.", boundary)
        self.assertIn("No regulated action execution.", boundary)
        self.assertIn("No binding operational consequence.", boundary)
        self.assertIn("Platform B1 evaluates.", boundary)
        self.assertIn("Thread D2 displays.", boundary)
        self.assertIn("RAMAT Vision displays only.", boundary)
        self.assertIn("Official records remain in source systems.", boundary)
        self.assertIn("Humans remain accountable.", boundary)


if __name__ == "__main__":
    unittest.main()
