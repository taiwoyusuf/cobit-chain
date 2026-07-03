from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_CONTROLLED_ADAPTATION_AGENTICITY_AI_CONFIGURATION_ASSURANCE_PATCH_V1_ACTIVE"
LOCKED_LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"

CAPABILITIES = [
    "Controlled Adaptation Assurance",
    "Learning Ledger",
    "What-Not-To-Learn Policy",
    "Agenticity Classification Assurance",
    "Enterprise AI Configuration Assurance",
    "Regulatory Response Defensibility Assurance",
    "Agent Readiness Reassessment",
    "AI Configuration Drift Detection",
    "Continual Learning Risk Monitoring"
]

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_stage": False,
    "new_pillar": False,
    "new_architecture": False,
    "capability_type": "Controlled Adaptation, Agenticity, and AI Configuration Assurance as cross-cutting Platform B capabilities",
    "locked_lifecycle_sequence": LOCKED_LIFECYCLE_SEQUENCE,
    "architecture_instruction": "Do not create a new module, stage, pillar, or architecture. Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust. Add Controlled Adaptation Assurance, Learning Ledger, What-Not-To-Learn Policy, Agenticity Classification Assurance, Enterprise AI Configuration Assurance, Regulatory Response Defensibility Assurance, Agent Readiness Reassessment, AI Configuration Drift Detection, and Continual Learning Risk Monitoring as cross-cutting capabilities.",
    "cross_cutting_capabilities": CAPABILITIES,
    "discovery_extension": [
        "AI type",
        "Agenticity level",
        "Memory capability",
        "Learning/adaptation capability",
        "Tool/API access",
        "Orchestration pattern",
        "Human owner",
        "Model owner",
        "Workflow owner",
        "Approved data sources",
        "Search sources",
        "Plugins",
        "Licensing/region availability",
        "Configuration dependencies",
        "Regulated use case",
        "Inspection/regulatory response relevance"
    ],
    "visibility_extension": [
        "Agenticity level",
        "Autonomy level",
        "Memory status",
        "Learning/adaptation status",
        "Configuration readiness",
        "Missing plugins",
        "Incomplete data",
        "Role/access gaps",
        "Search-source status",
        "Model/provider status",
        "Learning ledger",
        "Adaptation risk",
        "What-not-to-learn policy coverage",
        "Regulatory response evidence completeness",
        "Operational Trust Score"
    ],
    "governance_extension": [
        "Allowed agenticity levels by use case",
        "Permitted memory use",
        "Permitted learning/adaptation pathways",
        "Prohibited learning sources",
        "Approval rules for learning updates",
        "Rollback requirements",
        "Readiness criteria before AI activation",
        "Reassessment rules after configuration fixes",
        "Inspection-response review requirements",
        "Human oversight requirements for adaptive agents"
    ],
    "operationalization_extension": [
        "No adaptive behavior unless approved",
        "No learning from unauthorized or unapproved sources",
        "Learning/adaptation approval gate",
        "Configuration readiness check before launch",
        "Plugin/search/source validation",
        "Role and permission validation",
        "Reassessment after remediation",
        "AI output labeling",
        "Regulatory-response review before use",
        "Stop/verify/escalate controls for agentic workflows"
    ],
    "manufacturing_monitoring_extension": [
        "Adaptive AI behavior in regulated workflows",
        "Memory updates",
        "Tool usage",
        "Configuration changes",
        "Plugin changes",
        "Search-source changes",
        "Role changes",
        "Workflow exposure changes",
        "AI-generated inspection content",
        "Human review activity",
        "Performance after adaptation",
        "Process impact after AI changes"
    ],
    "evidence_extension": [
        "Agent classification",
        "Autonomy level",
        "Model/tool/version",
        "Memory state",
        "Learning event",
        "Feedback source",
        "Approval record",
        "Pre/post-test results",
        "Rollback path",
        "Configuration readiness evidence",
        "Reassessment evidence",
        "Regulatory response source mapping",
        "Human review evidence",
        "Final accepted output"
    ],
    "continuous_assurance_extension": [
        "Unauthorized learning",
        "Memory contamination",
        "Catastrophic forgetting risk",
        "Adaptation without approval",
        "Degraded performance after update",
        "Configuration drift",
        "Missing plugins",
        "Stale search sources",
        "Incomplete data",
        "Role/permission mismatch",
        "Readiness decline after changes",
        "Weak inspection-response evidence",
        "Operational trust degradation"
    ],
    "operational_trust_question": "Can this AI system, agent, configuration, memory, learning update, or regulatory response be trusted right now?",
    "platform_principle": "Platform B treats adaptation, memory, agenticity, configuration, search, plugins, licensing, access, and regulatory-response generation as controlled assurance objects that must be classified, approved, tested, monitored, evidenced, and reassessed before regulated use.",
    "capability_profiles": {
        "Controlled Adaptation Assurance": [
            "Learning/adaptation capability",
            "Permitted learning pathway",
            "Learning/adaptation approval gate",
            "Pre/post-test results",
            "Rollback path",
            "No adaptive behavior unless approved",
            "Adaptation without approval detection"
        ],
        "Learning Ledger": [
            "Learning event",
            "Feedback source",
            "Approval record",
            "Memory state",
            "Model/tool/version",
            "Performance after adaptation",
            "Learning history evidence"
        ],
        "What-Not-To-Learn Policy": [
            "Prohibited learning sources",
            "What-not-to-learn policy coverage",
            "No learning from unauthorized sources",
            "Approved data sources",
            "Search source validation",
            "Memory contamination detection",
            "Unauthorized learning detection"
        ],
        "Agenticity Classification Assurance": [
            "AI type",
            "Agenticity level",
            "Autonomy level",
            "Tool/API access",
            "Orchestration pattern",
            "Allowed agenticity level by use case",
            "Stop/verify/escalate control state"
        ],
        "Enterprise AI Configuration Assurance": [
            "Configuration readiness",
            "Configuration dependencies",
            "Plugins",
            "Search sources",
            "Licensing/region availability",
            "Role/access gaps",
            "Configuration readiness evidence"
        ],
        "Regulatory Response Defensibility Assurance": [
            "Inspection/regulatory response relevance",
            "AI-generated inspection content",
            "Regulatory-response review before use",
            "Regulatory response source mapping",
            "Human review evidence",
            "Final accepted output",
            "Weak inspection-response evidence detection"
        ],
        "Agent Readiness Reassessment": [
            "Readiness criteria before AI activation",
            "Reassessment rules after configuration fixes",
            "Reassessment after remediation",
            "Reassessment evidence",
            "Readiness decline after changes",
            "Role and permission validation",
            "Workflow exposure change monitoring"
        ],
        "AI Configuration Drift Detection": [
            "Configuration changes",
            "Plugin changes",
            "Search-source changes",
            "Role changes",
            "Model/provider status",
            "Configuration drift",
            "Missing plugin detection"
        ],
        "Continual Learning Risk Monitoring": [
            "Continual learning risk",
            "Catastrophic forgetting risk",
            "Degraded performance after update",
            "Process impact after AI changes",
            "Stale search source detection",
            "Incomplete data detection",
            "Operational trust degradation detection"
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

    data["platform_b_controlled_adaptation_agenticity_ai_configuration_assurance_patch"] = PATCH
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
            bp["controlled_adaptation_agenticity_ai_configuration_assurance"] = PATCH

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

            assessment["controlled_adaptation_agenticity_ai_configuration_assurance_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["new_stage"] = False
            assessment["new_pillar"] = False
            assessment["new_architecture"] = False
            assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            assessment["controlled_adaptation_assurance_active"] = True
            assessment["learning_ledger_active"] = True
            assessment["what_not_to_learn_policy_active"] = True
            assessment["agenticity_classification_assurance_active"] = True
            assessment["enterprise_ai_configuration_assurance_active"] = True
            assessment["regulatory_response_defensibility_assurance_active"] = True
            assessment["agent_readiness_reassessment_active"] = True
            assessment["ai_configuration_drift_detection_active"] = True
            assessment["continual_learning_risk_monitoring_active"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]

            for capability in CAPABILITIES:
                key = capability_key(capability)
                assessment[f"{key}_active"] = True
                assessment[f"{key}_module_created"] = False

            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["controlled_adaptation_agenticity_ai_configuration_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_stage"] = False
        assessment["new_pillar"] = False
        assessment["new_architecture"] = False
        assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
        assessment["controlled_adaptation_agenticity_ai_configuration_assurance"] = PATCH

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
                "Do not create a new module, stage, pillar, or architecture for Controlled Adaptation, Agenticity, and AI Configuration Assurance.",
                "Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust.",
                "Implement controlled adaptation, learning ledger, what-not-to-learn policy, agenticity classification, enterprise AI configuration, regulatory response defensibility, agent reassessment, configuration drift, and continual learning risk monitoring as cross-cutting capabilities.",
                "Continuously answer whether this AI system, agent, configuration, memory, learning update, or regulatory response can be trusted right now."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="controlled-adaptation-card">
        <div class="controlled-adaptation-title">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def profile_cards(profiles):
    return "\n".join([card(name, controls) for name, controls in profiles.items()])

HTML_BLOCK = f"""
<style>
.platform-b-controlled-adaptation-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(168,85,247,.10), rgba(34,197,94,.08));
}}
.platform-b-controlled-adaptation-wrap h2 {{
    margin: 0 0 12px 0;
    font-size: 28px;
}}
.platform-b-controlled-adaptation-wrap p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 1120px;
}}
.platform-b-controlled-adaptation-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
    font-weight: 800;
}}
.platform-b-controlled-adaptation-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-controlled-adaptation-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}
.controlled-adaptation-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.controlled-adaptation-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.controlled-adaptation-title {{
    color: #d8b4fe;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
</style>

<section class="platform-b-controlled-adaptation-wrap">
    <h2>Controlled Adaptation, Agenticity, and AI Configuration Assurance</h2>
    <p><strong>No new module, stage, pillar, or architecture.</strong> Platform B implements Controlled Adaptation Assurance, Learning Ledger, What-Not-To-Learn Policy, Agenticity Classification Assurance, Enterprise AI Configuration Assurance, Regulatory Response Defensibility Assurance, Agent Readiness Reassessment, AI Configuration Drift Detection, and Continual Learning Risk Monitoring as cross-cutting capabilities inside the existing lifecycle.</p>
    <p>{html_escape(PATCH["platform_principle"])}</p>

    <div class="platform-b-controlled-adaptation-warning">
        Adaptive AI, memory, plugins, search sources, enterprise configuration, and agentic tool access cannot be treated as background technical settings. In regulated use, each change must be approved, evidenced, reassessed, and bounded before operational use.
    </div>

    <div class="platform-b-controlled-adaptation-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-controlled-adaptation-grid">
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

Path("platform_b_controlled_adaptation_agenticity_ai_configuration_assurance_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_controlled_adaptation_agenticity_ai_configuration_assurance_patch_v1_urls.txt").write_text(
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
print("Platform B Controlled Adaptation, Agenticity, and AI Configuration Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("New stage: False")
print("New pillar: False")
print("New architecture: False")
print("Locked lifecycle:", LOCKED_LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
