from .canonicalization import sha256_json


def build_bundle(
    passports,
    runtime_summary,
    timestamp,
):
    bundle = {
        "schema_version": "1.0",
        "generated_at": timestamp,
        "passports": passports,
        "runtime_summary": runtime_summary,
        "inspection_message": (
            "Evidence-native, provenance-backed, "
            "AI-readable demonstration package."
        ),
    }

    manifest = {
        "schema_version": "1.0",
        "bundle_sha256": (
            sha256_json(bundle)
        ),
        "passport_count": len(passports),
        "generated_at": timestamp,
    }

    return bundle, manifest
