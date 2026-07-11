import importlib.util
import unittest
from copy import deepcopy
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "platform_b1_mvp2"
VALIDATOR_PATH = (
    ROOT
    / "regulated_operations_digital_twin"
    / "validator"
    / "digital_twin_mock_fixture_validator.py"
)


def load_validator_module():
    spec = importlib.util.spec_from_file_location(
        "digital_twin_mock_fixture_validator",
        VALIDATOR_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DigitalTwinMockFixtureValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validator = load_validator_module()

    def test_validator_module_loads(self):
        self.assertEqual(
            self.validator.REQUIRED_FIXTURE_STATUS,
            "LOCKED_MOCK_FIXTURE_ONLY",
        )
        self.assertIn("compound_pharmacy", self.validator.TRACK_RULES)
        self.assertIn("irlt_radiopharma_operations", self.validator.TRACK_RULES)
        self.assertIn(
            "dscsa_evidence_integrity_exception_assurance",
            self.validator.TRACK_RULES,
        )

    def test_all_current_mock_fixtures_pass(self):
        report = self.validator.validate_all_fixtures()

        self.assertTrue(report["passed"])
        self.assertEqual(report["fixture_count"], 3)

        for result in report["results"]:
            self.assertTrue(result["passed"])
            self.assertEqual(result["errors"], [])

    def test_validator_rejects_missing_product_release_boundary(self):
        fixture_path = (
            self.validator.DEFAULT_FIXTURE_DIR
            / "compound_pharmacy_preparation_package_review.json"
        )
        fixture = self.validator.load_fixture(fixture_path)

        fixture = deepcopy(fixture)
        fixture["boundary"] = [
            item
            for item in fixture["boundary"]
            if item != "No product release decision."
        ]

        errors = self.validator.validate_fixture(
            fixture,
            filename="compound_pharmacy_preparation_package_review.json",
        )

        combined = " ".join(errors)
        self.assertIn("No product release decision", combined)

    def test_validator_rejects_missing_expected_output(self):
        fixture_path = (
            self.validator.DEFAULT_FIXTURE_DIR
            / "irlt_equipment_ci_quality_handoff_review.json"
        )
        fixture = self.validator.load_fixture(fixture_path)

        fixture = deepcopy(fixture)
        fixture["expected_platform_b1_outputs"] = [
            item
            for item in fixture["expected_platform_b1_outputs"]
            if item != "QUALITY DEPENDENCY BLOCKED"
        ]

        errors = self.validator.validate_fixture(
            fixture,
            filename="irlt_equipment_ci_quality_handoff_review.json",
        )

        combined = " ".join(errors)
        self.assertIn("QUALITY DEPENDENCY BLOCKED", combined)

    def test_validator_rejects_ramat_approval_authority(self):
        fixture_path = (
            self.validator.DEFAULT_FIXTURE_DIR
            / "dscsa_late_epcis_vrs_no_response_exception.json"
        )
        fixture = self.validator.load_fixture(fixture_path)

        fixture = deepcopy(fixture)
        fixture["twin_state"]["ramat_vision_display"]["approval_authority"] = True

        errors = self.validator.validate_fixture(
            fixture,
            filename="dscsa_late_epcis_vrs_no_response_exception.json",
        )

        combined = " ".join(errors)
        self.assertIn("approval_authority must be false", combined)

    def test_validator_rejects_ai_approval_boundary_change(self):
        fixture_path = (
            self.validator.DEFAULT_FIXTURE_DIR
            / "compound_pharmacy_preparation_package_review.json"
        )
        fixture = self.validator.load_fixture(fixture_path)

        fixture = deepcopy(fixture)
        fixture["twin_state"]["ai_agent_output"]["approval_boundary"] = "approval"

        errors = self.validator.validate_fixture(
            fixture,
            filename="compound_pharmacy_preparation_package_review.json",
        )

        combined = " ".join(errors)
        self.assertIn("approval_boundary must be recommendation_only", combined)

    def test_validator_rejects_missing_hash_verified(self):
        fixture_path = (
            self.validator.DEFAULT_FIXTURE_DIR
            / "dscsa_late_epcis_vrs_no_response_exception.json"
        )
        fixture = self.validator.load_fixture(fixture_path)

        fixture = deepcopy(fixture)
        fixture["twin_state"]["evidence_integrity"]["outputs"] = [
            item
            for item in fixture["twin_state"]["evidence_integrity"]["outputs"]
            if item != "HASH VERIFIED"
        ]

        errors = self.validator.validate_fixture(
            fixture,
            filename="dscsa_late_epcis_vrs_no_response_exception.json",
        )

        combined = " ".join(errors)
        self.assertIn("HASH VERIFIED", combined)


if __name__ == "__main__":
    unittest.main()
