from .canonicalization import sha256_json


def build_passport(
    track_id,
    scenario_id,
    regulated_object,
    source_state,
    evidence_result,
    dependency_result,
    authority_result,
    admissibility_result,
    timestamp,
):
    passport = {
        "schema_version": "1.0",
        "track_id": track_id,
        "scenario_id": scenario_id,
        "regulated_object": regulated_object,
        "source_state": source_state,
        "evidence_integrity": evidence_result,
        "workflow_dependencies": dependency_result,
        "authority": authority_result,
        "action_admissibility": (
            admissibility_result
        ),
        "generated_at": timestamp,
        "provenance": (
            "SYNTHETIC_LOCAL_DEMONSTRATION"
        ),
        "binding_authority": (
            "IDENTIFIED_ACCOUNTABLE_HUMAN"
        ),
    }

    passport["passport_content_sha256"] = (
        sha256_json(passport)
    )

    return passport
