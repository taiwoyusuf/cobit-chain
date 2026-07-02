from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_GOVERNANCE_LAYER_STRENGTHENING_PATCH_V1_ACTIVE"

governance_strengthening = {
    "patch_marker": PATCH_MARKER,
    "patch_type": "governance_layer_strengthening_not_new_module",
    "architecture_change": False,
    "new_module": False,
    "platform_rule": "No new module. No new architecture. Strengthen the existing Governance layer.",
    "governance_supports": [
        "Multi-jurisdiction AI regulations",
        "Regional control mapping",
        "Evidence mapping",
        "Provider and deployer responsibilities",
        "Third-party oversight",
        "Cross-border compliance"
    ],
    "governance_operational_question": "Which legal, regional, operational, ownership, third-party, cross-border, control, and evidence obligations apply to this AI system?",
    "governance_stage_expansion": {
        "multi_jurisdiction_ai_regulations": {
            "question": "Which AI laws, regulatory regimes, sector expectations, and regional requirements apply to this AI system?",
            "expected_outputs": [
                "Jurisdiction applicability record",
                "Regulatory obligation map",
                "Regional compliance profile",
                "Legal basis and applicability rationale"
            ]
        },
        "regional_control_mapping": {
            "question": "Which controls are required by region, business unit, sector, and use context?",
            "expected_outputs": [
                "Regional control map",
                "Control applicability matrix",
                "Control owner assignment",
                "Control implementation status"
            ]
        },
        "evidence_mapping": {
            "question": "Which evidence objects prove that governance obligations are implemented and current?",
            "expected_outputs": [
                "Evidence obligation map",
                "Evidence owner record",
                "Evidence freshness rule",
                "Evidence-to-control traceability"
            ]
        },
        "provider_deployer_responsibilities": {
            "question": "Which obligations belong to the AI provider, deployer, user organization, vendor, or internal owner?",
            "expected_outputs": [
                "Provider responsibility map",
                "Deployer responsibility map",
                "Internal owner responsibility map",
                "Responsibility boundary record"
            ]
        },
        "third_party_oversight": {
            "question": "Which vendors, external models, APIs, tools, data providers, and managed services require oversight?",
            "expected_outputs": [
                "Third-party AI dependency register",
                "Vendor oversight record",
                "External API oversight record",
                "Third-party evidence requirement"
            ]
        },
        "cross_border_compliance": {
            "question": "Do data, model access, users, inference, evidence, or workflow execution cross jurisdictional boundaries?",
            "expected_outputs": [
                "Cross-border processing record",
                "Data transfer assessment",
                "Regional access control record",
                "Cross-border evidence package"
            ]
        }
    },
    "evidence_objects_to_bind": [
        "Jurisdiction applicability record",
        "Regional control map",
        "Evidence obligation map",
        "Provider responsibility map",
        "Deployer responsibility map",
        "Third-party oversight record",
        "Cross-border processing record",
        "Governance synchronization record"
    ],
    "strengthened_governance_statement": "Governance does not only ask whether controls exist. Governance also asks which legal, regional, operational, ownership, third-party, cross-border, and evidence obligations apply to the AI system."
}

def load_json(path):
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))

def save_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def add_unique_list(target, values):
    if target is None:
        target = []
    existing = set(target)
    for value in values:
        if value not in existing:
            target.append(value)
            existing.add(value)
    return target

def patch_lifecycle_seed():
    path = Path("platform_lifecycle_integration_seed.json")
    if not path.exists():
        print("SKIP: platform_lifecycle_integration_seed.json not found.")
        return False

    data = load_json(path)
    data["governance_layer_strengthening"] = governance_strengthening

    for stage in data.get("integration_flow", []):
        stage_id = stage.get("stage_id", "")

        if stage_id in ["governance_operationalization", "governance_lifecycle"]:
            stage["governance_supports"] = governance_strengthening["governance_supports"]
            stage["governance_operational_question"] = governance_strengthening["governance_operational_question"]
            stage["governance_stage_expansion"] = governance_strengthening["governance_stage_expansion"]

            stage["expected_objects"] = add_unique_list(stage.get("expected_objects", []), [
                "JurisdictionApplicability",
                "RegionalControlMap",
                "EvidenceObligationMap",
                "ProviderResponsibilityMap",
                "DeployerResponsibilityMap",
                "ThirdPartyOversightRecord",
                "CrossBorderComplianceRecord",
                "GovernanceSynchronizationRecord"
            ])

            stage["evidence_outputs"] = add_unique_list(stage.get("evidence_outputs", []), [
                "Jurisdiction applicability record",
                "Regional control map",
                "Evidence obligation map",
                "Provider responsibility map",
                "Deployer responsibility map",
                "Third-party oversight record",
                "Cross-border compliance record",
                "Governance synchronization record"
            ])

        if stage_id == "governance_operationalization":
            stage["stage_purpose"] = (
                "Evaluate whether governance documentation is reflected in operational practice through controls, evidence, workflows, monitoring, synchronization, human oversight, incident workflows, current risk posture, multi-jurisdiction regulation mapping, regional control mapping, provider/deployer responsibility mapping, third-party oversight, and cross-border compliance."
            )
            stage["operational_question"] = (
                "Is governance only documented, or is it actually operating through controls, evidence, workflows, regional obligations, responsibility boundaries, third-party oversight, cross-border compliance, monitoring, and current system state?"
            )

        if stage_id == "governance_lifecycle":
            stage["stage_purpose"] = (
                "Evaluate governance across discovery, visibility, risk classification, readiness, deployment, monitoring, evidence freshness, operational trust, continuous assurance, jurisdictional obligations, regional controls, provider/deployer responsibilities, third-party oversight, and cross-border compliance."
            )
            stage["operational_question"] = (
                "Where is this AI system within its governance lifecycle, and can every governance, regional, responsibility, third-party, cross-border, and evidence stage be evidenced?"
            )

    save_json(path, data)
    print("PATCHED: platform_lifecycle_integration_seed.json")
    return True

def patch_blueprint_seed():
    path = Path("platform_blueprint_library_seed.json")
    if not path.exists():
        print("SKIP: platform_blueprint_library_seed.json not found.")
        return False

    data = load_json(path)
    data["governance_layer_strengthening"] = governance_strengthening

    for bp in data.get("blueprints", []):
        bp["governance_layer_strengthening"] = governance_strengthening
        bp["questions_answered"] = add_unique_list(bp.get("questions_answered", []), [
            "Which jurisdictions apply to this AI use case?",
            "Which regional controls apply?",
            "Which evidence proves the governance obligation is implemented?",
            "Who is the provider?",
            "Who is the deployer?",
            "Which third parties require oversight?",
            "Does the workflow create cross-border compliance obligations?"
        ])

        for stage in bp.get("lifecycle", []):
            if stage.get("stage_name") in ["Governance"]:
                stage["stage_question"] = (
                    stage.get("stage_question", "") +
                    " Which multi-jurisdiction, regional control, provider/deployer, third-party, cross-border, and evidence obligations apply?"
                )
                stage["operational_focus"] = (
                    stage.get("operational_focus", "") +
                    " Strengthen governance by mapping applicable jurisdictions, regional controls, evidence obligations, provider/deployer responsibilities, third-party oversight, and cross-border compliance."
                )
                stage["governance_supports"] = governance_strengthening["governance_supports"]
                stage["governance_stage_expansion"] = governance_strengthening["governance_stage_expansion"]
                stage["evidence_outputs"] = add_unique_list(stage.get("evidence_outputs", []), [
                    "Jurisdiction applicability record",
                    "Regional control map",
                    "Evidence obligation map",
                    "Provider responsibility map",
                    "Deployer responsibility map",
                    "Third-party oversight record",
                    "Cross-border compliance record"
                ])

    save_json(path, data)
    print("PATCHED: platform_blueprint_library_seed.json")
    return True

def patch_html_banner(path, banner_html, insertion_anchor):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path} not found.")
        return False

    text = p.read_text(encoding="utf-8")

    start = f"<!-- {PATCH_MARKER} -->"
    end = f"<!-- END {PATCH_MARKER} -->"
    text = re.sub(
        re.escape(start) + r".*?" + re.escape(end),
        "",
        text,
        flags=re.DOTALL
    )

    block = f"\n{start}\n{banner_html}\n{end}\n"

    if insertion_anchor in text:
        text = text.replace(insertion_anchor, insertion_anchor + block, 1)
    else:
        text = text.replace("</section>", block + "\n</section>", 1)

    p.write_text(text, encoding="utf-8")
    print(f"PATCHED: {path}")
    return True

platform_banner = r'''
<div class="statement" style="margin-top:22px;">
    <strong>Governance strengthened:</strong> the existing Governance layer now explicitly supports multi-jurisdiction AI regulations, regional control mapping, evidence mapping, provider/deployer responsibilities, third-party oversight, and cross-border compliance. This is not a new module or architecture change.
</div>
'''

route_registry_banner = r'''
<section class="section">
    <div class="section-head">
        <div>
            <h2>Governance Layer Strengthening</h2>
            <p>The existing Governance layer now explicitly supports multi-jurisdiction AI regulations, regional control mapping, evidence mapping, provider/deployer responsibilities, third-party oversight, and cross-border compliance. This is not a new platform capability; it strengthens Governance inside the existing lifecycle.</p>
        </div>
        <span class="tag">Governance strengthened</span>
    </div>
    <div class="route-grid">
        <a class="route" href="/platform/lifecycle-integration"><strong>Lifecycle Integration</strong><span>Governance stages now include jurisdiction applicability, regional controls, evidence obligations, responsibility boundaries, third-party oversight, and cross-border compliance.</span><code>/platform/lifecycle-integration</code></a>
        <a class="route" href="/platform/blueprints"><strong>Blueprint Library</strong><span>Industry and enterprise blueprints now reuse the strengthened Governance layer without adding architecture.</span><code>/platform/blueprints</code></a>
        <a class="route" href="/platform/ai-assurance-evidence-contract"><strong>Evidence Contract</strong><span>Evidence obligations can be mapped to regional controls, provider/deployer responsibilities, third-party oversight, and cross-border compliance.</span><code>/platform/ai-assurance-evidence-contract</code></a>
        <a class="route" href="/platform/evidence-packages"><strong>Evidence Vault</strong><span>Governance evidence can be bound into replayable proof packages.</span><code>/platform/evidence-packages</code></a>
    </div>
</section>
'''

patch_lifecycle_seed()
patch_blueprint_seed()

patch_html_banner(
    "platform_ab_command_center.html",
    platform_banner,
    '<div class="nav">'
)

patch_html_banner(
    "platform_route_registry_command_center.html",
    route_registry_banner,
    '<div class="footer">'
)

Path("governance_layer_strengthening_patch_v1_summary.json").write_text(
    json.dumps(governance_strengthening, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("governance_layer_strengthening_patch_v1_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/platform/lifecycle-integration",
        "http://127.0.0.1:5000/platform/blueprints",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/model/demo",
        "http://127.0.0.1:5000/api/platform/blueprints/model/demo"
    ]),
    encoding="utf-8"
)

print("")
print("Governance Layer Strengthening Patch completed.")
print("Marker:")
print("  " + PATCH_MARKER)
print("No new module. No new architecture.")
