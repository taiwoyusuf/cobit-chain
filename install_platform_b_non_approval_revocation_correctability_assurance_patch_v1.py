from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_NON_APPROVAL_REVOCATION_CORRECTABILITY_ASSURANCE_PATCH_V1_ACTIVE"
LOCKED_LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"

CAPABILITIES = [
    "Non-Approval Assurance",
    "AI Revocation Pathway Assurance",
    "Degraded Mode Assurance",
    "Correctability Assurance",
    "Governance Enforcement Boundary",
    "Independent Attestation Assurance",
    "AI Records Lifecycle Assurance",
    "Residual Risk Reassessment Trigger",
    "AI Kill-Switch Exercise Evidence",
    "AI Authority Revocation Evidence"
]

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_stage": False,
    "new_pillar": False,
    "new_architecture": False,
    "capability_type": "Non-Approval, Revocation, and Correctability Assurance as cross-cutting Platform B capabilities",
    "locked_lifecycle_sequence": LOCKED_LIFECYCLE_SEQUENCE,
    "architecture_instruction": "Do not create a new module, stage, pillar, or architecture. Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust. Add Non-Approval Assurance, AI Revocation Pathway Assurance, Degraded Mode Assurance, Correctability Assurance, Governance Enforcement Boundary, Independent Attestation Assurance, AI Records Lifecycle Assurance, Residual Risk Reassessment Trigger, AI Kill-Switch Exercise Evidence, and AI Authority Revocation Evidence as cross-cutting capabilities.",
    "cross_cutting_capabilities": CAPABILITIES,
    "discovery_extension": [
        "Unacceptable AI use-case criteria",
        "Residual risk thresholds",
        "Autonomy level",
        "Authority boundary",
        "Human owner",
        "Risk owner",
        "Revocation owner",
        "Escalation owner",
        "Fallback process",
        "Degraded mode",
        "System-of-record dependency",
        "Records/data lifecycle impact",
        "Sensitive data exposure",
        "Monitoring dependency",
        "Explainability limitation",
        "Post-deployment reassessment triggers"
    ],
    "visibility_extension": [
        "Approval status",
        "Not-yet status",
        "Non-approval reason",
        "Residual risk level",
        "Correctability status",
        "Revocation readiness",
        "Tested kill-switch status",
        "Degraded mode readiness",
        "Fallback owner",
        "Monitoring coverage",
        "Authority creep",
        "Lifecycle reassessment due",
        "Records retention status",
        "Independent evidence status",
        "Operational Trust Score"
    ],
    "governance_extension": [
        "Criteria for approve",
        "Criteria for not yet",
        "Criteria for do not proceed",
        "Residual risk appetite",
        "Unacceptable-use-case rules",
        "Correctability requirements",
        "Revocation triggers",
        "Emergency authority",
        "Degraded-mode rules",
        "Kill-switch test cadence",
        "Independent attestation requirements",
        "Records lifecycle requirements",
        "Legal hold / retention / deletion rules"
    ],
    "operationalization_extension": [
        "No deployment without owner",
        "No deployment without monitoring",
        "No high-risk autonomy without human oversight",
        "No sensitive-data use without safeguards",
        "No action beyond authority boundary",
        "No production use without revocation path",
        "No approval without fallback/degraded mode",
        "No AI-generated record without records classification",
        "Automatic restriction when residual risk exceeds threshold",
        "Escalation when monitoring or evidence fails"
    ],
    "manufacturing_monitoring_extension": [
        "AI-assisted operations",
        "Authority creep",
        "Unapproved workflow expansion",
        "Post-approval model/data/process changes",
        "Monitoring decay",
        "Loss of explainability",
        "Excessive autonomy",
        "Kill-switch readiness",
        "Degraded-mode activation",
        "Fallback execution",
        "Record creation and retention",
        "GxP process impact"
    ],
    "evidence_extension": [
        "Approval decision",
        "Non-approval rationale",
        "Residual risk acceptance",
        "Risk reassessment",
        "Revocation test result",
        "Degraded-mode test result",
        "Fallback process evidence",
        "Owner acknowledgement",
        "Monitoring evidence",
        "Authority-boundary evidence",
        "Independent attestation",
        "Record classification",
        "Retention/deletion/legal-hold evidence",
        "Recovery evidence"
    ],
    "continuous_assurance_extension": [
        "Residual risk drift",
        "Monitoring failure",
        "Authority creep",
        "Business-purpose drift",
        "Model/provider change",
        "New data-source risk",
        "Explainability gap",
        "Correctability weakness",
        "Untested kill-switch",
        "Degraded-mode failure",
        "Governance evidence gaps",
        "AI records lifecycle gaps",
        "Operational trust decline"
    ],
    "operational_trust_question": "Can this AI use case still be approved, corrected, restricted, revoked, recovered, and defended right now?",
    "platform_principle": "Platform B treats approval as a reversible, evidence-bound operational state. AI use cases must be capable of being denied, delayed, corrected, restricted, revoked, degraded, recovered, and defended through evidence before and after deployment.",
    "capability_profiles": {
        "Non-Approval Assurance": [
            "Unacceptable AI use-case criteria",
            "Approval status",
            "Not-yet status",
            "Non-approval reason",
            "Criteria for approve",
            "Criteria for not yet",
            "Criteria for do not proceed",
            "Non-approval rationale"
        ],
        "AI Revocation Pathway Assurance": [
            "Revocation owner",
            "Revocation readiness",
            "Revocation triggers",
            "No production use without revocation path",
            "Revocation test result",
            "Recovery evidence",
            "AI authority revocation evidence"
        ],
        "Degraded Mode Assurance": [
            "Fallback process",
            "Degraded mode",
            "Degraded mode readiness",
            "Fallback owner",
            "Degraded-mode rules",
            "No approval without fallback/degraded mode",
            "Degraded-mode activation",
            "Degraded-mode test result"
        ],
        "Correctability Assurance": [
            "Correctability status",
            "Correctability requirements",
            "Risk reassessment",
            "Correctability weakness",
            "Residual risk drift",
            "Business-purpose drift",
            "Model/provider change",
            "New data-source risk"
        ],
        "Governance Enforcement Boundary": [
            "Autonomy level",
            "Authority boundary",
            "Emergency authority",
            "No action beyond authority boundary",
            "Automatic restriction when residual risk exceeds threshold",
            "Escalation when monitoring or evidence fails",
            "Authority-boundary evidence",
            "Authority creep"
        ],
        "Independent Attestation Assurance": [
            "Independent evidence status",
            "Independent attestation requirements",
            "Independent attestation",
            "Owner acknowledgement",
            "Monitoring evidence",
            "Governance evidence gaps",
            "Operational trust decline"
        ],
        "AI Records Lifecycle Assurance": [
            "Records/data lifecycle impact",
            "Records retention status",
            "Records lifecycle requirements",
            "Legal hold / retention / deletion rules",
            "No AI-generated record without records classification",
            "Record creation and retention",
            "Record classification",
            "Retention/deletion/legal-hold evidence"
        ],
        "Residual Risk Reassessment Trigger": [
            "Residual risk thresholds",
            "Residual risk level",
            "Residual risk appetite",
            "Residual risk acceptance",
            "Post-deployment reassessment triggers",
            "Lifecycle reassessment due",
            "Risk reassessment",
            "Residual risk drift"
        ],
        "AI Kill-Switch Exercise Evidence": [
            "Tested kill-switch status",
            "Kill-switch test cadence",
            "Kill-switch readiness",
            "Untested kill-switch",
            "Revocation test result",
            "Degraded-mode failure",
            "Recovery evidence"
        ],
        "AI Authority Revocation Evidence": [
            "Human owner",
            "Risk owner",
            "Escalation owner",
            "Sensitive data exposure",
            "Monitoring dependency",
            "Explainability limitation",
            "Loss of explainability",
            "Excessive autonomy"
        ]
    }
}

def load_json(path):
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8-sig"))

def save_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def stable_key(item):
    if isinstance(item, dict):
        return json.dumps(item, sort_keys=True, ensure_ascii=False)
    return str(item)

def add_unique(items, additions):
    if not isinstance(items, list):
        items = []
    result = []
    seen = set()
    for item in items + additions:
        key = stable_key(item)
        if key not in seen:
            result.append(item)
            seen.add(key)
    return result

def flatten_profiles(profiles):
    out = []
    for name, controls in profiles.items():
        out.append(name)
        out.extend(controls)
    return out

def capability_key(name):
    return (
        name.lower()
        .replace("-", "_")
        .replace("/", "_")
        .replace(" ", "_")
        .replace("(", "")
        .replace(")", "")
    )

def patch_seed(path):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path}")
        return

    data = load_json(path)
    if not isinstance(data, dict):
        print(f"SKIP: {path} is not JSON object")
        return

    data["platform_b_non_approval_revocation_correctability_assurance_patch"] = PATCH
    data["platform_b_architecture_change"] = False
    data["platform_b_new_module"] = False
    data["platform_b_new_stage"] = False
    data["platform_b_new_pillar"] = False
    data["platform_b_new_architecture"] = False
    data["platform_b_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE

    for capability in CAPABILITIES:
        data[f"platform_b_{capability_key(capability)}_module_created"] = False

    profile_items = flatten_profiles(PATCH["capability_profiles"])

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["new_module"] = False
            bp["new_stage"] = False
            bp["new_pillar"] = False
            bp["new_architecture"] = False
            bp["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            bp["non_approval_revocation_correctability_assurance"] = PATCH

            bp["discovery_scope"] = add_unique(
                bp.get("discovery_scope", []),
                PATCH["discovery_extension"] + CAPABILITIES
            )

            bp["visibility_scope"] = add_unique(
                bp.get("visibility_scope", []),
                PATCH["visibility_extension"]
            )

            bp["governance_scope"] = add_unique(
                bp.get("governance_scope", []),
                PATCH["governance_extension"]
            )

            bp["operationalization_scope"] = add_unique(
                bp.get("operationalization_scope", []),
                PATCH["operationalization_extension"] + profile_items
            )

            bp["manufacturing_monitoring_scope"] = add_unique(
                bp.get("manufacturing_monitoring_scope", []),
                PATCH["manufacturing_monitoring_extension"]
            )

            bp["evidence_assurance"] = add_unique(
                bp.get("evidence_assurance", []),
                PATCH["evidence_extension"]
            )

            bp["continuous_assurance"] = add_unique(
                bp.get("continuous_assurance", []),
                PATCH["continuous_assurance_extension"]
            )

            bp["operational_trust_scope"] = add_unique(
                bp.get("operational_trust_scope", []),
                [PATCH["operational_trust_question"], PATCH["platform_principle"]] + CAPABILITIES
            )

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [PATCH["operational_trust_question"]]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["non_approval_revocation_correctability_assurance_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["new_stage"] = False
            assessment["new_pillar"] = False
            assessment["new_architecture"] = False
            assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            assessment["non_approval_assurance_active"] = True
            assessment["ai_revocation_pathway_assurance_active"] = True
            assessment["degraded_mode_assurance_active"] = True
            assessment["correctability_assurance_active"] = True
            assessment["governance_enforcement_boundary_active"] = True
            assessment["independent_attestation_assurance_active"] = True
            assessment["ai_records_lifecycle_assurance_active"] = True
            assessment["residual_risk_reassessment_trigger_active"] = True
            assessment["ai_kill_switch_exercise_evidence_active"] = True
            assessment["ai_authority_revocation_evidence_active"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]

            for capability in CAPABILITIES:
                key = capability_key(capability)
                assessment[f"{key}_active"] = True
                assessment[f"{key}_module_created"] = False

            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["non_approval_revocation_correctability_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_stage"] = False
        assessment["new_pillar"] = False
        assessment["new_architecture"] = False
        assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
        assessment["non_approval_revocation_correctability_assurance"] = PATCH

        assessment["operationalization_targets"] = add_unique(
            assessment.get("operationalization_targets", []),
            PATCH["operationalization_extension"] + profile_items
        )

        assessment["manufacturing_monitoring_targets"] = add_unique(
            assessment.get("manufacturing_monitoring_targets", []),
            PATCH["manufacturing_monitoring_extension"]
        )

        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            PATCH["evidence_extension"]
        )

        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            PATCH["continuous_assurance_extension"]
        )

        assessment["implementation_priority"] = add_unique(
            assessment.get("implementation_priority", []),
            [
                "Do not create a new module, stage, pillar, or architecture for Non-Approval, Revocation, and Correctability Assurance.",
                "Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust.",
                "Implement non-approval, revocation pathway, degraded mode, correctability, governance enforcement boundary, independent attestation, AI records lifecycle, residual risk reassessment, kill-switch exercise evidence, and authority revocation evidence as cross-cutting capabilities.",
                "Continuously answer whether this AI use case can still be approved, corrected, restricted, revoked, recovered, and defended right now."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="revocation-card">
        <div class="revocation-title">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def profile_cards(profiles):
    return "\n".join([card(name, controls) for name, controls in profiles.items()])

HTML_BLOCK = f"""
<style>
.platform-b-revocation-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(248,113,113,.10), rgba(168,85,247,.08));
}}
.platform-b-revocation-wrap h2 {{
    margin: 0 0 12px 0;
    font-size: 28px;
}}
.platform-b-revocation-wrap p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 1120px;
}}
.platform-b-revocation-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.10);
    border: 1px solid rgba(248,113,113,.22);
    color: #fecaca;
    line-height: 1.55;
    font-weight: 800;
}}
.platform-b-revocation-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-revocation-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}
.revocation-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.revocation-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.revocation-title {{
    color: #fecaca;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
</style>

<section class="platform-b-revocation-wrap">
    <h2>Non-Approval, Revocation, and Correctability Assurance</h2>
    <p><strong>No new module, stage, pillar, or architecture.</strong> Platform B implements Non-Approval Assurance, AI Revocation Pathway Assurance, Degraded Mode Assurance, Correctability Assurance, Governance Enforcement Boundary, Independent Attestation Assurance, AI Records Lifecycle Assurance, Residual Risk Reassessment Trigger, AI Kill-Switch Exercise Evidence, and AI Authority Revocation Evidence as cross-cutting capabilities inside the existing lifecycle.</p>
    <p>{html_escape(PATCH["platform_principle"])}</p>

    <div class="platform-b-revocation-warning">
        AI approval is not permanent. A trustworthy AI system must have evidence-backed pathways for non-approval, correction, restriction, revocation, degraded operation, recovery, records control, and independent defense.
    </div>

    <div class="platform-b-revocation-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-revocation-grid">
        {card("Discovery", PATCH["discovery_extension"])}
        {card("Visibility", PATCH["visibility_extension"])}
        {card("Governance", PATCH["governance_extension"])}
        {card("Operationalization", PATCH["operationalization_extension"])}
        {card("Manufacturing Monitoring", PATCH["manufacturing_monitoring_extension"])}
        {card("Evidence", PATCH["evidence_extension"])}
        {card("Continuous Assurance", PATCH["continuous_assurance_extension"])}
        {card("Cross-Cutting Capabilities", CAPABILITIES)}
        {profile_cards(PATCH["capability_profiles"])}
    </div>
</section>
"""

def remove_old_block(text):
    start = f"<!-- {PATCH_MARKER} -->"
    end = f"<!-- END {PATCH_MARKER} -->"
    return re.sub(re.escape(start) + r".*?" + re.escape(end), "", text, flags=re.DOTALL)

def clean_trailing_whitespace(text):
    lines = text.splitlines(keepends=True)
    cleaned = []
    for line in lines:
        if line.endswith("\r\n"):
            cleaned.append(line[:-2].rstrip(" \t") + "\r\n")
        elif line.endswith("\n"):
            cleaned.append(line[:-1].rstrip(" \t") + "\n")
        else:
            cleaned.append(line.rstrip(" \t"))
    return "".join(cleaned)

def patch_html(path):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path}")
        return

    text = p.read_text(encoding="utf-8-sig")
    text = remove_old_block(text)

    wrapped = f"\n<!-- {PATCH_MARKER} -->\n{HTML_BLOCK}\n<!-- END {PATCH_MARKER} -->\n"

    anchors = [
        "<!-- COBITCHAIN_PLATFORM_B_AI_RMF_TO_ASSURANCE_EVIDENCE_BRIDGE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_ENTERPRISE_CONTROL_LAYER_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_AI_DESIGNED_ASSET_PROVENANCE_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_CONTROLLED_ADAPTATION_AGENTICITY_AI_CONFIGURATION_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_REGULATORY_EVIDENCE_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_ACCOUNTABILITY_PRESENCE_GOVERNANCE_OPERATING_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_ASSURANCE_AWARE_AI_STACK_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_AUDIT_SURVIVABLE_SAFETY_BOUNDED_CYBER_PHYSICAL_AI_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_CONTEXT_ASSURED_WEARABLE_PRE_DEVIATION_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_PRE_DEVIATION_CAPA_EFFECTIVENESS_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_ADVANCED_CROSS_CUTTING_CAPABILITIES_LOCKED_LIFECYCLE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_AI_CAPABILITY_ASSURANCE_LIBRARY_PATCH_V1_ACTIVE -->",
        "<div class=\"footer\">",
        "</main>",
        "</body>"
    ]

    inserted = False
    for anchor in anchors:
        if anchor in text:
            text = text.replace(anchor, wrapped + "\n" + anchor, 1)
            inserted = True
            break

    if not inserted:
        text = text.rstrip() + wrapped

    p.write_text(clean_trailing_whitespace(text), encoding="utf-8")
    print(f"PATCHED: {path}")

patch_seed("platform_blueprint_library_seed.json")
patch_seed("platform_lifecycle_integration_seed.json")

for html in [
    "platform_ab_command_center.html",
    "platform_blueprint_library.html",
    "platform_ai_enabled_cmc_blueprint.html",
    "platform_agentic_enterprise_blueprint.html",
    "platform_enterprise_execution_assurance.html",
    "platform_route_registry_command_center.html"
]:
    patch_html(html)

Path("platform_b_non_approval_revocation_correctability_assurance_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_non_approval_revocation_correctability_assurance_patch_v1_urls.txt").write_text(
    "\n".join([
        "http://127.0.0.1:5000/platform",
        "http://127.0.0.1:5000/platform/blueprints",
        "http://127.0.0.1:5000/platform/blueprints/ai-enabled-cmc",
        "http://127.0.0.1:5000/platform/blueprints/agentic-enterprise",
        "http://127.0.0.1:5000/platform/lifecycle-integration",
        "http://127.0.0.1:5000/platform/enterprise-execution-assurance",
        "http://127.0.0.1:5000/platform/execution-assurance",
        "http://127.0.0.1:5000/platform/routes",
        "http://127.0.0.1:5000/api/platform/blueprints/model/demo",
        "http://127.0.0.1:5000/api/platform/lifecycle-integration/model/demo",
        "http://127.0.0.1:5000/api/platform/enterprise-execution-assurance/demo",
        "http://127.0.0.1:5000/api/platform/execution-assurance/demo"
    ]),
    encoding="utf-8"
)

print("")
print("Platform B Non-Approval, Revocation, and Correctability Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("New stage: False")
print("New pillar: False")
print("New architecture: False")
print("Locked lifecycle:", LOCKED_LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
