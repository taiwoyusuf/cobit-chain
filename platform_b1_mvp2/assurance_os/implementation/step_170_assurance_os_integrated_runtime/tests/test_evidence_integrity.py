import unittest

from src.evidence_integrity import (
    create_seal,
    verify_payload,
)


class EvidenceIntegrityTests(unittest.TestCase):
    def test_tamper_is_detected(self):
        payload = {
            "value": "original"
        }

        seal = create_seal(
            payload,
            "OBJ-1",
            "2026-07-13T00:00:00Z",
        )

        self.assertTrue(
            verify_payload(
                payload,
                seal,
            )["valid"]
        )

        payload["value"] = "changed"

        self.assertFalse(
            verify_payload(
                payload,
                seal,
            )["valid"]
        )


if __name__ == "__main__":
    unittest.main()
