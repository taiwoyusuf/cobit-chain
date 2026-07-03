from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_HUMAN_OVERSIGHT_EFFECTIVENESS_ASSURANCE_PATCH_V1_ACTIVE"
LOCKED_LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"

CAPABILITIES = [
    "Human Oversight Effectiveness Assurance",
    "Stop-the-Line Authority Assurance",
    "Oversight Quality Metrics",
    "Oversight Workload and Fatigue Assurance",
    "Automation Bias Resistance Assurance",
    "Oversight Change Revalidation",
    "Oversight Interface Assurance",
    "Oversight Audit and Red-Team Assurance"
]

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_stage": False,
    "new_pillar": False,
    "new_architecture": False,
    "capability_type": "Human Oversight Effectiveness Assurance as cross-cutting Platform B capabilities",
    "locked_lifecycle_sequence": LOCKED_LIFECYCLE_SEQUENCE,
    "architecture_instruction": "Do not create a new module, stage, pillar, or architecture. Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust. Add Human Oversight Effectiveness Assurance, Stop-the-Line Authority Assurance, Oversight Quality Metrics, Oversight Workload and Fatigue Assurance, Automation Bias Resistance Assurance, Oversight Change Revalidation, Oversight Interface Assurance, and Oversight Audit and Red-Team Assurance as cross-cutting capabilities.",
    "cross_cutting_capabilities": CAPABILITIES,
    "discovery_extension": [
        "AI/ADM decision points",
        "Human reviewer role",
        "Operator role",
        "Escalation owner",
        "Stop-the-line authority",
        "Reviewer competency requirements",
        "Training requirements",
        "System limitations",
        "Known failure scenarios",
        "Override/suspend/disregard capability",
        "Review workload expectations",
        "User interface controls",
        "Appeal/feedback mechanism",
        "Audit and sampling requirements"
    ],
    "visibility_extension": [
        "Oversight coverage",
        "Reviewer assignment",
        "Reviewer competency status",
        "Training status",
        "Review workload",
        "Approval/rejection/override patterns",
        "Fast-approval/rubber-stamp signals",
        "Disagreement rate",
        "Escalation activity",
        "Stop-the-line readiness",
        "Oversight KPI dashboard",
        "Audit findings",
        "Automation bias risk",
        "Operational Trust Score"
    ],
    "governance_extension": [
        "When human oversight is mandatory",
        "What reviewer must inspect",
        "What context must be visible",
        "What authority reviewer has",
        "When override is required",
        "When suspension is required",
        "When disagreement escalates",
        "Reviewer competence requirements",
        "Training and refresher cadence",
        "Workload limits",
        "Oversight KPI thresholds",
        "Audit sampling rules",
        "Post-change oversight reassessment rules"
    ],
    "operationalization_extension": [
        "No high-risk AI/ADM workflow without assigned oversight",
        "No approval without visible decision context",
        "No reviewer assignment without training",
        "No production use without override/suspend pathway",
        "Workload quota controls",
        "Four-eyes review for high-impact decisions",
        "Escalation workflow for disagreement",
        "Mandatory RCA after oversight failure",
        "Oversight protocol reassessment after AI/system update"
    ],
    "manufacturing_monitoring_extension": [
        "AI-supported decisions",
        "High-risk outputs",
        "Reviewer behavior",
        "Repeated corrections",
        "Repeated overrides",
        "Skipped reviews",
        "Fast approvals",
        "Reviewer overload",
        "Operator reaction time",
        "Missed anomalies",
        "Stop-the-line events",
        "Bias/error signals",
        "Deviation-prone decisions"
    ],
    "evidence_extension": [
        "AI/ADM output",
        "Input context",
        "Confidence score where applicable",
        "Reviewer identity",
        "Reviewer training status",
        "Reviewer decision",
        "Approval/rejection/override",
        "Disagreement record",
        "Escalation record",
        "Stop-the-line action",
        "RCA after failure",
        "Audit trail",
        "Sampled decision logs",
        "Anomaly test results",
        "Management reporting evidence"
    ],
    "continuous_assurance_extension": [
        "Oversight becoming a formality",
        "Automation bias",
        "Rubber-stamp approval",
        "Reviewer overload",
        "Missing training",
        "Missing context",
        "Weak escalation",
        "Repeated human corrections",
        "Ineffective system design",
        "Override failure",
        "Stop-the-line weakness",
        "Post-change oversight gaps",
        "Operational trust decline"
    ],
    "operational_trust_question": "Can this AI/ADM decision be trusted because human oversight was competent, informed, timely, authorized, measurable, and evidenced?",
    "platform_principle": "Platform B treats human oversight as an operational control system, not as the mere presence of a human reviewer. Oversight is effective only when the reviewer is competent, trained, informed, timely, authorized to challenge or stop the system, protected by escalation pathways, and supported by measurable evidence.",
    "capability_profiles": {
        "Human Oversight Effectiveness Assurance": [
            "AI/ADM decision points",
            "Human reviewer role",
            "Oversight coverage",
            "Reviewer assignment",
            "Reviewer competency status",
            "Training status",
            "Reviewer decision",
            "Operational Trust Score"
        ],
        "Stop-the-Line Authority Assurance": [
            "Stop-the-line authority",
            "Stop-the-line readiness",
            "Stop-the-line action",
            "When suspension is required",
            "No production use without override/suspend pathway",
            "Escalation workflow for disagreement",
            "Stop-the-line weakness"
        ],
        "Oversight Quality Metrics": [
            "Oversight KPI dashboard",
            "Oversight KPI thresholds",
            "Approval/rejection/override patterns",
            "Disagreement rate",
            "Escalation activity",
            "Sampled decision logs",
            "Management reporting evidence"
        ],
        "Oversight Workload and Fatigue Assurance": [
            "Review workload expectations",
            "Review workload",
            "Workload limits",
            "Workload quota controls",
            "Reviewer overload",
            "Operator reaction time",
            "Missed anomalies"
        ],
        "Automation Bias Resistance Assurance": [
            "Automation bias risk",
            "Automation bias",
            "Fast-approval/rubber-stamp signals",
            "Fast approvals",
            "Rubber-stamp approval",
            "Skipped reviews",
            "Repeated human corrections"
        ],
        "Oversight Change Revalidation": [
            "Post-change oversight reassessment rules",
            "Oversight protocol reassessment after AI/system update",
            "Post-change oversight gaps",
            "System limitations",
            "Known failure scenarios",
            "Ineffective system design",
            "Override failure"
        ],
        "Oversight Interface Assurance": [
            "What reviewer must inspect",
            "What context must be visible",
            "No approval without visible decision context",
            "Input context",
            "User interface controls",
            "Appeal/feedback mechanism",
            "Missing context"
        ],
        "Oversight Audit and Red-Team Assurance": [
            "Audit and sampling requirements",
            "Audit sampling rules",
            "Audit findings",
            "Audit trail",
            "Anomaly test results",
            "Mandatory RCA after oversight failure",
            "RCA after failure"
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

    data["platform_b_human_oversight_effectiveness_assurance_patch"] = PATCH
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
            bp["human_oversight_effectiveness_assurance"] = PATCH

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

            assessment["human_oversight_effectiveness_assurance_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["new_stage"] = False
            assessment["new_pillar"] = False
            assessment["new_architecture"] = False
            assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            assessment["human_oversight_effectiveness_assurance_active"] = True
            assessment["stop_the_line_authority_assurance_active"] = True
            assessment["oversight_quality_metrics_active"] = True
            assessment["oversight_workload_and_fatigue_assurance_active"] = True
            assessment["automation_bias_resistance_assurance_active"] = True
            assessment["oversight_change_revalidation_active"] = True
            assessment["oversight_interface_assurance_active"] = True
            assessment["oversight_audit_and_red_team_assurance_active"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]

            for capability in CAPABILITIES:
                key = capability_key(capability)
                assessment[f"{key}_active"] = True
                assessment[f"{key}_module_created"] = False

            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["human_oversight_effectiveness_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_stage"] = False
        assessment["new_pillar"] = False
        assessment["new_architecture"] = False
        assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
        assessment["human_oversight_effectiveness_assurance"] = PATCH

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
                "Do not create a new module, stage, pillar, or architecture for Human Oversight Effectiveness Assurance.",
                "Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust.",
                "Implement human oversight effectiveness, stop-the-line authority, oversight quality metrics, workload/fatigue, automation bias resistance, change revalidation, interface assurance, and audit/red-team assurance as cross-cutting capabilities.",
                "Continuously answer whether this AI/ADM decision can be trusted because human oversight was competent, informed, timely, authorized, measurable, and evidenced."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="human-oversight-card">
        <div class="human-oversight-title">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def profile_cards(profiles):
    return "\n".join([card(name, controls) for name, controls in profiles.items()])

HTML_BLOCK = f"""
<style>
.platform-b-human-oversight-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(16,185,129,.10), rgba(59,130,246,.08));
}}
.platform-b-human-oversight-wrap h2 {{
    margin: 0 0 12px 0;
    font-size: 28px;
}}
.platform-b-human-oversight-wrap p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 1120px;
}}
.platform-b-human-oversight-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.10);
    border: 1px solid rgba(248,113,113,.22);
    color: #fecaca;
    line-height: 1.55;
    font-weight: 800;
}}
.platform-b-human-oversight-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-human-oversight-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}
.human-oversight-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.human-oversight-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.human-oversight-title {{
    color: #bbf7d0;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
</style>

<section class="platform-b-human-oversight-wrap">
    <h2>Human Oversight Effectiveness Assurance</h2>
    <p><strong>No new module, stage, pillar, or architecture.</strong> Platform B implements Human Oversight Effectiveness Assurance, Stop-the-Line Authority Assurance, Oversight Quality Metrics, Oversight Workload and Fatigue Assurance, Automation Bias Resistance Assurance, Oversight Change Revalidation, Oversight Interface Assurance, and Oversight Audit and Red-Team Assurance as cross-cutting capabilities inside the existing lifecycle.</p>
    <p>{html_escape(PATCH["platform_principle"])}</p>

    <div class="platform-b-human-oversight-warning">
        Human oversight is not the presence of a human. It is the presence of a trained, competent, informed, authorized, timely, accountable human who can challenge, override, suspend, disregard, escalate, or stop AI/ADM output with evidence.
    </div>

    <div class="platform-b-human-oversight-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-human-oversight-grid">
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
        "<!-- COBITCHAIN_PLATFORM_B_REGULATORY_CONFIDENCE_DEFENSIBILITY_ASSURANCE_PATCH_V1_ACTIVE -->",
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

Path("platform_b_human_oversight_effectiveness_assurance_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_human_oversight_effectiveness_assurance_patch_v1_urls.txt").write_text(
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
print("Platform B Human Oversight Effectiveness Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("New stage: False")
print("New pillar: False")
print("New architecture: False")
print("Locked lifecycle:", LOCKED_LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
