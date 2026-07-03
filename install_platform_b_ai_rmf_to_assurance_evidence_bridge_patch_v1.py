from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_AI_RMF_TO_ASSURANCE_EVIDENCE_BRIDGE_PATCH_V1_ACTIVE"
LOCKED_LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"

CAPABILITIES = [
    "AI RMF-to-Assurance Evidence Bridge",
    "NIST AI RMF Crosswalk",
    "Trustworthiness Evidence Graph",
    "TEVV Evidence Register",
    "Current-to-Target AI Trust Profile",
    "AI Actor Accountability Map",
    "Residual Risk Evidence Assurance",
    "AI RMF Profile Gap Dashboard"
]

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_stage": False,
    "new_pillar": False,
    "new_architecture": False,
    "capability_type": "AI RMF-to-Assurance Evidence Bridge as cross-cutting Platform B capabilities",
    "locked_lifecycle_sequence": LOCKED_LIFECYCLE_SEQUENCE,
    "architecture_instruction": "Do not create a new module, stage, pillar, or architecture. Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust. Add AI RMF-to-Assurance Evidence Bridge, NIST AI RMF Crosswalk, Trustworthiness Evidence Graph, TEVV Evidence Register, Current-to-Target AI Trust Profile, AI Actor Accountability Map, Residual Risk Evidence Assurance, and AI RMF Profile Gap Dashboard as cross-cutting capabilities.",
    "cross_cutting_capabilities": CAPABILITIES,
    "discovery_extension": [
        "AI system",
        "Intended use",
        "Context of use",
        "AI actor roles",
        "Business owner",
        "Risk owner",
        "Model owner",
        "Data owner",
        "Deployer/operator",
        "Third-party components",
        "Applicable NIST AI RMF categories",
        "Trustworthiness characteristics",
        "Residual risk areas",
        "TEVV requirements"
    ],
    "visibility_extension": [
        "NIST AI RMF crosswalk",
        "Govern/Map/Measure/Manage status",
        "Trustworthiness evidence status",
        "Current vs target trust profile",
        "AI actor accountability map",
        "TEVV evidence completeness",
        "Residual risk register",
        "Gaps in measurement",
        "Third-party risk visibility",
        "Operational Trust Score"
    ],
    "governance_extension": [
        "Risk tolerance",
        "AI governance roles",
        "AI RMF alignment rules",
        "Trustworthy AI requirements",
        "TEVV expectations",
        "Accountability requirements",
        "Human oversight rules",
        "Risk acceptance rules",
        "Residual risk review cadence",
        "Current/target profile requirements"
    ],
    "operationalization_extension": [
        "AI registration before use",
        "Context mapping before deployment",
        "TEVV before production",
        "Human oversight assignment",
        "Control implementation",
        "Risk treatment workflow",
        "Go/no-go decision pathway",
        "Residual risk approval",
        "AI RMF evidence capture"
    ],
    "manufacturing_monitoring_extension": [
        "AI use in regulated workflows",
        "Performance drift",
        "Safety risk",
        "Security/resilience events",
        "Human oversight activity",
        "Residual risk changes",
        "Third-party component risk",
        "AI actor responsibility gaps",
        "Real-world risk emergence"
    ],
    "evidence_extension": [
        "AI RMF category mapping",
        "Context assessment",
        "Risk classification",
        "Trustworthiness assessment",
        "TEVV records",
        "Human oversight evidence",
        "Risk treatment evidence",
        "Go/no-go decision",
        "Residual risk acceptance",
        "Monitoring evidence",
        "Review and reassessment records"
    ],
    "continuous_assurance_extension": [
        "RMF control gaps",
        "Stale risk assessments",
        "Missing TEVV evidence",
        "Trustworthiness degradation",
        "Residual risk increase",
        "Third-party risk changes",
        "Accountability gaps",
        "Unmanaged emergent risks",
        "Monitoring failures",
        "Operational trust decline"
    ],
    "operational_trust_question": "Can this AI system demonstrate that NIST-aligned governance, mapping, measurement, management, TEVV, accountability, and residual-risk controls are functioning right now?",
    "platform_principle": "Platform B converts AI risk management alignment into operational assurance evidence by mapping governance, context, measurement, management, TEVV, accountability, trustworthiness, third-party risk, and residual-risk controls into evidence that can be monitored, defended, and trusted in operation.",
    "capability_profiles": {
        "AI RMF-to-Assurance Evidence Bridge": [
            "AI system",
            "Intended use",
            "Context of use",
            "AI RMF evidence capture",
            "AI RMF category mapping",
            "Control implementation",
            "Operational trust decline detection"
        ],
        "NIST AI RMF Crosswalk": [
            "Applicable NIST AI RMF categories",
            "Govern/Map/Measure/Manage status",
            "AI RMF alignment rules",
            "Risk tolerance",
            "Risk treatment workflow",
            "RMF control gap detection",
            "Gaps in measurement"
        ],
        "Trustworthiness Evidence Graph": [
            "Trustworthiness characteristics",
            "Trustworthiness evidence status",
            "Trustworthy AI requirements",
            "Trustworthiness assessment",
            "Trustworthiness degradation detection",
            "Safety risk monitoring",
            "Security/resilience event monitoring"
        ],
        "TEVV Evidence Register": [
            "TEVV requirements",
            "TEVV expectations",
            "TEVV before production",
            "TEVV records",
            "TEVV evidence completeness",
            "Missing TEVV evidence detection",
            "Review and reassessment records"
        ],
        "Current-to-Target AI Trust Profile": [
            "Current vs target trust profile",
            "Current/target profile requirements",
            "Risk classification",
            "Context assessment",
            "Go/no-go decision pathway",
            "Go/no-go decision",
            "Stale risk assessment detection"
        ],
        "AI Actor Accountability Map": [
            "AI actor roles",
            "Business owner",
            "Risk owner",
            "Model owner",
            "Data owner",
            "Deployer/operator",
            "AI actor responsibility gap detection"
        ],
        "Residual Risk Evidence Assurance": [
            "Residual risk areas",
            "Residual risk register",
            "Risk acceptance rules",
            "Residual risk review cadence",
            "Residual risk approval",
            "Residual risk acceptance",
            "Residual risk increase detection"
        ],
        "AI RMF Profile Gap Dashboard": [
            "Third-party components",
            "Third-party risk visibility",
            "Third-party component risk monitoring",
            "Third-party risk change detection",
            "Unmanaged emergent risk detection",
            "Monitoring failure detection",
            "Operational Trust Score"
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

    data["platform_b_ai_rmf_to_assurance_evidence_bridge_patch"] = PATCH
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
            bp["ai_rmf_to_assurance_evidence_bridge"] = PATCH

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

            assessment["ai_rmf_to_assurance_evidence_bridge_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["new_stage"] = False
            assessment["new_pillar"] = False
            assessment["new_architecture"] = False
            assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            assessment["ai_rmf_to_assurance_evidence_bridge_active"] = True
            assessment["nist_ai_rmf_crosswalk_active"] = True
            assessment["trustworthiness_evidence_graph_active"] = True
            assessment["tevv_evidence_register_active"] = True
            assessment["current_to_target_ai_trust_profile_active"] = True
            assessment["ai_actor_accountability_map_active"] = True
            assessment["residual_risk_evidence_assurance_active"] = True
            assessment["ai_rmf_profile_gap_dashboard_active"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]

            for capability in CAPABILITIES:
                key = capability_key(capability)
                assessment[f"{key}_active"] = True
                assessment[f"{key}_module_created"] = False

            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["ai_rmf_to_assurance_evidence_bridge_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_stage"] = False
        assessment["new_pillar"] = False
        assessment["new_architecture"] = False
        assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
        assessment["ai_rmf_to_assurance_evidence_bridge"] = PATCH

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
                "Do not create a new module, stage, pillar, or architecture for AI RMF-to-Assurance Evidence Bridge.",
                "Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust.",
                "Implement AI RMF crosswalk, trustworthiness evidence graph, TEVV evidence register, current-to-target AI trust profile, AI actor accountability map, residual risk evidence assurance, and AI RMF profile gap dashboard as cross-cutting capabilities.",
                "Continuously answer whether this AI system can demonstrate that NIST-aligned governance, mapping, measurement, management, TEVV, accountability, and residual-risk controls are functioning right now."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="ai-rmf-card">
        <div class="ai-rmf-title">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def profile_cards(profiles):
    return "\n".join([card(name, controls) for name, controls in profiles.items()])

HTML_BLOCK = f"""
<style>
.platform-b-ai-rmf-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(34,197,94,.10), rgba(99,102,241,.08));
}}
.platform-b-ai-rmf-wrap h2 {{
    margin: 0 0 12px 0;
    font-size: 28px;
}}
.platform-b-ai-rmf-wrap p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 1120px;
}}
.platform-b-ai-rmf-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
    font-weight: 800;
}}
.platform-b-ai-rmf-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-ai-rmf-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}
.ai-rmf-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.ai-rmf-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.ai-rmf-title {{
    color: #bbf7d0;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
</style>

<section class="platform-b-ai-rmf-wrap">
    <h2>AI RMF-to-Assurance Evidence Bridge</h2>
    <p><strong>No new module, stage, pillar, or architecture.</strong> Platform B implements AI RMF-to-Assurance Evidence Bridge, NIST AI RMF Crosswalk, Trustworthiness Evidence Graph, TEVV Evidence Register, Current-to-Target AI Trust Profile, AI Actor Accountability Map, Residual Risk Evidence Assurance, and AI RMF Profile Gap Dashboard as cross-cutting capabilities inside the existing lifecycle.</p>
    <p>{html_escape(PATCH["platform_principle"])}</p>

    <div class="platform-b-ai-rmf-warning">
        Framework alignment is not the same as operational assurance. Platform B requires NIST-aligned governance, mapping, measurement, management, TEVV, accountability, trustworthiness, third-party risk, and residual-risk controls to generate evidence that proves the controls are functioning.
    </div>

    <div class="platform-b-ai-rmf-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-ai-rmf-grid">
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

Path("platform_b_ai_rmf_to_assurance_evidence_bridge_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_ai_rmf_to_assurance_evidence_bridge_patch_v1_urls.txt").write_text(
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
print("Platform B AI RMF-to-Assurance Evidence Bridge Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("New stage: False")
print("New pillar: False")
print("New architecture: False")
print("Locked lifecycle:", LOCKED_LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
