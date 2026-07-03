from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_REGULATORY_CONFIDENCE_DEFENSIBILITY_ASSURANCE_PATCH_V1_ACTIVE"
LOCKED_LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"

CAPABILITIES = [
    "Regulatory Confidence Assurance",
    "Regulatory Currency Assurance",
    "Defensibility Decay Monitoring",
    "Sectoral-Law Interoperability Assurance",
    "Safety-Function Boundary Assurance",
    "Agentic AI Regulatory Classification Assurance",
    "Real-World Testing Assurance",
    "AI Office Enforcement Readiness",
    "Heterogeneous AI Infrastructure Assurance",
    "Identity Journey Assurance"
]

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_stage": False,
    "new_pillar": False,
    "new_architecture": False,
    "capability_type": "Regulatory Confidence and Defensibility Assurance as cross-cutting Platform B capabilities",
    "locked_lifecycle_sequence": LOCKED_LIFECYCLE_SEQUENCE,
    "architecture_instruction": "Do not create a new module, stage, pillar, or architecture. Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust. Add Regulatory Confidence Assurance, Regulatory Currency Assurance, Defensibility Decay Monitoring, Sectoral-Law Interoperability Assurance, Safety-Function Boundary Assurance, Agentic AI Regulatory Classification Assurance, Real-World Testing Assurance, AI Office Enforcement Readiness, Heterogeneous AI Infrastructure Assurance, and Identity Journey Assurance as cross-cutting capabilities.",
    "cross_cutting_capabilities": CAPABILITIES,
    "discovery_extension": [
        "AI system/use case",
        "Intended use",
        "Regulatory context",
        "Sectoral law applicability",
        "Model confidence metrics",
        "Validation status",
        "Applicable guidance/SOP/law",
        "Safety-function status",
        "Agentic AI classification",
        "Runtime/infrastructure environment",
        "Identity/access dependency",
        "Real-world testing plan",
        "Post-market monitoring requirement",
        "Regulatory owner",
        "System owner",
        "Evidence owner"
    ],
    "visibility_extension": [
        "AI confidence score",
        "Regulatory confidence score",
        "Validation status",
        "Reproducibility status",
        "Audit trail completeness",
        "Regulatory currency status",
        "Stale guidance risk",
        "Safety-function boundary",
        "Agentic classification",
        "Sectoral-law overlap map",
        "Real-world testing status",
        "Enforcement-readiness status",
        "Operational Trust Score"
    ],
    "governance_extension": [
        "Intended-use boundaries",
        "Validation requirements",
        "Regulatory currency requirements",
        "Evidence requirements",
        "Sectoral-law mapping rules",
        "Safety-function classification rules",
        "Agentic AI classification rules",
        "Real-world testing approval rules",
        "AI Office / regulator response process",
        "Infrastructure and identity assurance rules"
    ],
    "operationalization_extension": [
        "No regulated use without validation pathway",
        "No AI output use if source/guidance is stale",
        "No high-risk use without sector-law mapping",
        "No safety-function use without safety-boundary assessment",
        "No agentic AI use without autonomy classification",
        "No real-world testing without approved plan",
        "No identity-based AI workflow without verified identity context",
        "Evidence capture before regulated output is used"
    ],
    "manufacturing_monitoring_extension": [
        "Regulated AI outputs",
        "Model/provider changes",
        "Guidance/SOP/regulation changes",
        "Safety-function boundary changes",
        "Real-world testing events",
        "AI-assisted operational decisions",
        "Infrastructure changes",
        "Identity context changes",
        "Post-market monitoring signals",
        "Defensibility decay"
    ],
    "evidence_extension": [
        "Model confidence evidence",
        "Validation evidence",
        "Source/guidance version",
        "Regulatory currency check",
        "Intended-use rationale",
        "Sectoral-law mapping",
        "Safety-function assessment",
        "Agentic AI classification",
        "Real-world testing plan and results",
        "Post-market monitoring evidence",
        "Identity/access evidence",
        "Regulator-response package"
    ],
    "continuous_assurance_extension": [
        "Stale regulatory knowledge",
        "Expired validation assumptions",
        "Model/data/use-case drift",
        "Safety-function reclassification risk",
        "Agentic authority creep",
        "Incomplete real-world testing evidence",
        "Missing post-market monitoring",
        "Infrastructure/runtime drift",
        "Identity signal weakness",
        "Enforcement-readiness gaps",
        "Operational trust decline"
    ],
    "operational_trust_question": "Can this AI system or output be trusted, reproduced, defended, and kept current within its regulatory, sectoral, safety, identity, infrastructure, and evidence boundaries right now?",
    "platform_principle": "Platform B distinguishes AI confidence from regulatory confidence. AI confidence may reflect model probability, benchmark performance, or output quality; regulatory confidence requires validated intended use, current regulatory knowledge, source traceability, reproducibility, human review, governance evidence, audit readiness, and defensibility under regulatory, legal, clinical, quality, or enforcement challenge.",
    "capability_profiles": {
        "Regulatory Confidence Assurance": [
            "AI confidence score",
            "Regulatory confidence score",
            "Model confidence evidence",
            "Validation evidence",
            "Intended-use rationale",
            "Reproducibility status",
            "Audit trail completeness",
            "Evidence owner"
        ],
        "Regulatory Currency Assurance": [
            "Applicable guidance/SOP/law",
            "Regulatory currency status",
            "Source/guidance version",
            "Regulatory currency check",
            "Stale guidance risk",
            "Stale regulatory knowledge",
            "No AI output use if source/guidance is stale"
        ],
        "Defensibility Decay Monitoring": [
            "Defensibility decay",
            "Expired validation assumptions",
            "Model/data/use-case drift",
            "Model/provider changes",
            "Post-market monitoring signals",
            "Operational trust decline",
            "Regulator-response package"
        ],
        "Sectoral-Law Interoperability Assurance": [
            "Regulatory context",
            "Sectoral law applicability",
            "Sectoral-law overlap map",
            "Sectoral-law mapping rules",
            "Sectoral-law mapping",
            "No high-risk use without sector-law mapping",
            "AI Office / regulator response process"
        ],
        "Safety-Function Boundary Assurance": [
            "Safety-function status",
            "Safety-function boundary",
            "Safety-function classification rules",
            "Safety-function assessment",
            "Safety-function boundary changes",
            "Safety-function reclassification risk",
            "No safety-function use without safety-boundary assessment"
        ],
        "Agentic AI Regulatory Classification Assurance": [
            "Agentic AI classification",
            "Agentic classification",
            "Agentic AI classification rules",
            "Agentic AI classification evidence",
            "Agentic authority creep",
            "No agentic AI use without autonomy classification",
            "AI-assisted operational decisions"
        ],
        "Real-World Testing Assurance": [
            "Real-world testing plan",
            "Real-world testing status",
            "Real-world testing approval rules",
            "Real-world testing events",
            "Real-world testing plan and results",
            "Incomplete real-world testing evidence",
            "No real-world testing without approved plan"
        ],
        "AI Office Enforcement Readiness": [
            "Enforcement-readiness status",
            "Enforcement-readiness gaps",
            "AI Office / regulator response process",
            "Regulator-response package",
            "Regulatory owner",
            "Audit trail completeness",
            "Post-market monitoring evidence"
        ],
        "Heterogeneous AI Infrastructure Assurance": [
            "Runtime/infrastructure environment",
            "Infrastructure and identity assurance rules",
            "Infrastructure changes",
            "Infrastructure/runtime drift",
            "Runtime environment evidence",
            "System owner",
            "No regulated use without validation pathway"
        ],
        "Identity Journey Assurance": [
            "Identity/access dependency",
            "Identity context changes",
            "Identity signal weakness",
            "Identity/access evidence",
            "No identity-based AI workflow without verified identity context",
            "Infrastructure and identity assurance rules",
            "Evidence capture before regulated output is used"
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

    data["platform_b_regulatory_confidence_defensibility_assurance_patch"] = PATCH
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
            bp["regulatory_confidence_defensibility_assurance"] = PATCH

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

            assessment["regulatory_confidence_defensibility_assurance_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["new_stage"] = False
            assessment["new_pillar"] = False
            assessment["new_architecture"] = False
            assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            assessment["regulatory_confidence_assurance_active"] = True
            assessment["regulatory_currency_assurance_active"] = True
            assessment["defensibility_decay_monitoring_active"] = True
            assessment["sectoral_law_interoperability_assurance_active"] = True
            assessment["safety_function_boundary_assurance_active"] = True
            assessment["agentic_ai_regulatory_classification_assurance_active"] = True
            assessment["real_world_testing_assurance_active"] = True
            assessment["ai_office_enforcement_readiness_active"] = True
            assessment["heterogeneous_ai_infrastructure_assurance_active"] = True
            assessment["identity_journey_assurance_active"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]

            for capability in CAPABILITIES:
                key = capability_key(capability)
                assessment[f"{key}_active"] = True
                assessment[f"{key}_module_created"] = False

            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["regulatory_confidence_defensibility_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_stage"] = False
        assessment["new_pillar"] = False
        assessment["new_architecture"] = False
        assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
        assessment["regulatory_confidence_defensibility_assurance"] = PATCH

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
                "Do not create a new module, stage, pillar, or architecture for Regulatory Confidence and Defensibility Assurance.",
                "Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust.",
                "Implement regulatory confidence, regulatory currency, defensibility decay, sectoral-law interoperability, safety-function boundary, agentic AI regulatory classification, real-world testing, AI Office enforcement readiness, heterogeneous AI infrastructure, and identity journey assurance as cross-cutting capabilities.",
                "Continuously answer whether this AI system or output can be trusted, reproduced, defended, and kept current within regulatory, sectoral, safety, identity, infrastructure, and evidence boundaries right now."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="reg-confidence-card">
        <div class="reg-confidence-title">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def profile_cards(profiles):
    return "\n".join([card(name, controls) for name, controls in profiles.items()])

HTML_BLOCK = f"""
<style>
.platform-b-reg-confidence-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(14,165,233,.10), rgba(234,179,8,.08));
}}
.platform-b-reg-confidence-wrap h2 {{
    margin: 0 0 12px 0;
    font-size: 28px;
}}
.platform-b-reg-confidence-wrap p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 1120px;
}}
.platform-b-reg-confidence-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(234,179,8,.10);
    border: 1px solid rgba(234,179,8,.22);
    color: #fef3c7;
    line-height: 1.55;
    font-weight: 800;
}}
.platform-b-reg-confidence-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-reg-confidence-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}
.reg-confidence-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.reg-confidence-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.reg-confidence-title {{
    color: #fde68a;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
</style>

<section class="platform-b-reg-confidence-wrap">
    <h2>Regulatory Confidence and Defensibility Assurance</h2>
    <p><strong>No new module, stage, pillar, or architecture.</strong> Platform B implements Regulatory Confidence Assurance, Regulatory Currency Assurance, Defensibility Decay Monitoring, Sectoral-Law Interoperability Assurance, Safety-Function Boundary Assurance, Agentic AI Regulatory Classification Assurance, Real-World Testing Assurance, AI Office Enforcement Readiness, Heterogeneous AI Infrastructure Assurance, and Identity Journey Assurance as cross-cutting capabilities inside the existing lifecycle.</p>
    <p>{html_escape(PATCH["platform_principle"])}</p>

    <div class="platform-b-reg-confidence-warning">
        AI confidence is not regulatory confidence. A high-performing AI output is not defensible unless it is validated for intended use, current against applicable requirements, traceable, reproducible, human-reviewed, governed, and ready for audit or enforcement challenge.
    </div>

    <div class="platform-b-reg-confidence-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-reg-confidence-grid">
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
        "<!-- COBITCHAIN_PLATFORM_B_NON_APPROVAL_REVOCATION_CORRECTABILITY_ASSURANCE_PATCH_V1_ACTIVE -->",
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

Path("platform_b_regulatory_confidence_defensibility_assurance_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_regulatory_confidence_defensibility_assurance_patch_v1_urls.txt").write_text(
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
print("Platform B Regulatory Confidence and Defensibility Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("New stage: False")
print("New pillar: False")
print("New architecture: False")
print("Locked lifecycle:", LOCKED_LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
