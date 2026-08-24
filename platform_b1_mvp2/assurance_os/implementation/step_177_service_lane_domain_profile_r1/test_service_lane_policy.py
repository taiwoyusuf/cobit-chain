import unittest

from service_lane_policy import (
    AssuranceStanding,
    CommercialContext,
    ServiceLane,
    TechnicalBasis,
    commercial_status_can_raise_standing,
    evaluate_assurance_standing,
)


class ServiceLanePolicyTests(unittest.TestCase):
    def full_basis(self):
        return TechnicalBasis(True, True, True, True, True)

    def test_full_technical_basis_is_supportable(self):
        c = CommercialContext(ServiceLane.CONTINUOUS_ASSURANCE)
        self.assertEqual(evaluate_assurance_standing(c, self.full_basis()), AssuranceStanding.SUPPORTABLE)

    def test_payment_cannot_rescue_missing_evidence(self):
        c = CommercialContext(ServiceLane.ENTERPRISE_ASSURANCE_DEPLOYMENT, paid=True, subscribed=True)
        b = TechnicalBasis(False, True, True, True, True)
        self.assertEqual(evaluate_assurance_standing(c, b), AssuranceStanding.NOT_ESTABLISHED)

    def test_registration_cannot_rescue_invalid_dependencies(self):
        c = CommercialContext(ServiceLane.ARCHITECTURE_EVIDENCE_PROVENANCE, registered=True)
        b = TechnicalBasis(True, True, False, True, True)
        self.assertEqual(evaluate_assurance_standing(c, b), AssuranceStanding.NOT_ESTABLISHED)

    def test_review_purchase_cannot_rescue_missing_authority(self):
        c = CommercialContext(ServiceLane.BOUNDED_ASSURANCE_REVIEW, review_purchased=True, paid=True)
        b = TechnicalBasis(True, True, True, False, True)
        self.assertEqual(evaluate_assurance_standing(c, b), AssuranceStanding.NOT_ESTABLISHED)

    def test_subscription_cannot_rescue_missing_evaluation(self):
        c = CommercialContext(ServiceLane.CONTINUOUS_ASSURANCE, subscribed=True, paid=True)
        b = TechnicalBasis(True, True, True, True, False)
        self.assertEqual(evaluate_assurance_standing(c, b), AssuranceStanding.NOT_ESTABLISHED)

    def test_commercial_status_never_raises_standing(self):
        self.assertFalse(commercial_status_can_raise_standing())


if __name__ == "__main__":
    unittest.main()
