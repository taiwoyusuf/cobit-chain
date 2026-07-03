from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_ACCOUNTABILITY_PRESENCE_GOVERNANCE_OPERATING_ASSURANCE_PATCH_V1_ACTIVE"
LOCKED_LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"

CAPABILITIES = [
    "Accountability Presence Assurance",
    "AI Governance Operating Function Assurance",
    "Policy-to-Practice Assurance",
    "Management-System-to-System Assurance",
    "AI Vendor / Procurement Trust Assurance",
    "Human Oversight Function Monitoring",
    "AI Governance Resourcing Signal",
    "Governance Evidence Gap Detection"
]

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_stage": False,
    "new_pillar": False,
    "new_architecture": False,
    "capability_type": "Accountability Presence and Governance Operating Assurance as cross-cutting Platform B capabilities",
    "locked_lifecycle_sequence": LOCKED_LIFECYCLE_SEQUENCE,
    "architecture_instruction": "Do not create a new module, stage, pillar, or architecture. Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust. Add Accountability Presence Assurance, AI Governance Operating Function Assurance, Policy-to-Practice Assurance, Management-System-to-System Assurance, AI Vendor / Procurement Trust Assurance, Human Oversight Function Monitoring, AI Governance Resourcing Signal, and Governance Evidence Gap Detection as cross-cutting capabilities.",
    "cross_cutting_capabilities": CAPABILITIES,
    "discovery_extension": [
        "AI policy",
        "AI risk owner",
        "Business owner",
        "System owner",
        "Model owner",
        "Data owner",
        "Human reviewer",
        "Approver",
        "Legal/privacy/security stakeholders",
        "Quality Unit role where applicable",
        "Governance forum or committee",
        "ISO 42001 alignment",
        "Applicable regulation",
        "Vendor certification or assurance evidence",
        "Operational oversight responsibilities"
    ],
    "visibility_extension": [
        "AI owner presence",
        "Reviewer activity",
        "Approval activity",
        "Governance coverage",
        "Oversight gaps",
        "Orphan AI systems",
        "AI policy-to-control mapping",
        "ISO 42001-to-use-case mapping",
        "Regulatory obligation mapping",
        "Vendor trust evidence",
        "Governance workload",
        "Unresolved AI risk decisions",
        "Operational Trust Score"
    ],
    "governance_extension": [
        "AI ownership model",
        "Governance roles and responsibilities",
        "Escalation paths",
        "Human oversight rules",
        "Policy-to-control requirements",
        "Legal/privacy/security review rules",
        "Quality Unit review where required",
        "Vendor assurance requirements",
        "Procurement trust criteria",
        "ISO 42001 management-system expectations",
        "Evidence requirements for each AI use case"
    ],
    "operationalization_extension": [
        "Named owner before deployment",
        "Reviewer assignment before regulated use",
        "Approval gates for high-risk use",
        "Legal/privacy/security review where required",
        "Quality Unit review where applicable",
        "Vendor evidence check before adoption",
        "Policy acknowledgment",
        "Governance workflow activation",
        "Escalation if oversight is missing"
    ],
    "manufacturing_monitoring_extension": [
        "AI-enabled operational use",
        "Human oversight actually performed",
        "Delayed reviews",
        "Missing approvals",
        "Unresolved risks",
        "Governance workload",
        "Quality Unit review burden",
        "AI policy exceptions",
        "Repeated use outside approved scope",
        "Shadow AI behavior"
    ],
    "evidence_extension": [
        "Who owned the AI use case",
        "Who reviewed it",
        "Who approved it",
        "What policy applied",
        "What risk assessment was completed",
        "What compliance obligation applied",
        "What human oversight occurred",
        "What vendor evidence was reviewed",
        "What decision was made",
        "What exception was accepted",
        "What escalation occurred"
    ],
    "continuous_assurance_extension": [
        "Owner absence",
        "Reviewer inactivity",
        "Policy not operationalized",
        "Controls without evidence",
        "Legal-only governance weakness",
        "Vendor assurance gaps",
        "Unfunded governance function risk",
        "Oversight fatigue",
        "Governance drift",
        "ISO alignment without operational evidence",
        "AI use outside approved scope"
    ],
    "operational_trust_question": "Is AI governance actually functioning right now, or does the organization only have governance on paper?",
    "platform_principle": "Platform B treats AI governance as operationally real only when accountability is present, funded, competent, observable, evidenced, and continuously exercised across owners, reviewers, approvers, quality, privacy, security, legal, vendor, and governance functions.",
    "capability_profiles": {
        "Accountability Presence Assurance": [
            "Named AI owner evidence",
            "Risk owner evidence",
            "Business owner evidence",
            "Reviewer assignment evidence",
            "Approval activity evidence",
            "Escalation activity evidence",
            "Operational accountability presence state"
        ],
        "AI Governance Operating Function Assurance": [
            "Governance forum evidence",
            "Operational oversight responsibility",
            "Governance workflow activation",
            "Unresolved AI risk decision",
            "Governance workload",
            "Governance resourcing signal",
            "Governance function operating state"
        ],
        "Policy-to-Practice Assurance": [
            "AI policy-to-control mapping",
            "Policy acknowledgment",
            "Control execution evidence",
            "Evidence requirement per use case",
            "Policy exception monitoring",
            "Policy not operationalized detection",
            "Control without evidence detection"
        ],
        "Management-System-to-System Assurance": [
            "ISO 42001 alignment",
            "ISO 42001-to-use-case mapping",
            "Applicable regulation mapping",
            "Management system expectation",
            "Regulatory obligation mapping",
            "Operational evidence linkage",
            "ISO alignment without operational evidence detection"
        ],
        "AI Vendor / Procurement Trust Assurance": [
            "Vendor certification evidence",
            "Vendor assurance evidence",
            "Vendor evidence check before adoption",
            "Procurement trust criteria",
            "Vendor assurance requirement",
            "Vendor trust evidence",
            "Vendor assurance gap detection"
        ],
        "Human Oversight Function Monitoring": [
            "Human reviewer assignment",
            "Human oversight rule",
            "Human oversight actually performed",
            "Reviewer activity",
            "Delayed review detection",
            "Reviewer inactivity detection",
            "Oversight fatigue signal"
        ],
        "AI Governance Resourcing Signal": [
            "Governance workload",
            "Quality Unit review burden",
            "Unresolved risk load",
            "Delayed review load",
            "Missing approval load",
            "Unfunded governance function risk",
            "Operating capacity signal"
        ],
        "Governance Evidence Gap Detection": [
            "Missing owner evidence",
            "Missing review evidence",
            "Missing approval evidence",
            "Missing policy-to-control evidence",
            "Missing vendor evidence",
            "Missing escalation evidence",
            "Governance evidence gap alert"
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

    data["platform_b_accountability_presence_governance_operating_assurance_patch"] = PATCH
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
            bp["accountability_presence_governance_operating_assurance"] = PATCH

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

            assessment["accountability_presence_governance_operating_assurance_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["new_stage"] = False
            assessment["new_pillar"] = False
            assessment["new_architecture"] = False
            assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            assessment["accountability_presence_assurance_active"] = True
            assessment["ai_governance_operating_function_assurance_active"] = True
            assessment["policy_to_practice_assurance_active"] = True
            assessment["management_system_to_system_assurance_active"] = True
            assessment["ai_vendor_procurement_trust_assurance_active"] = True
            assessment["human_oversight_function_monitoring_active"] = True
            assessment["ai_governance_resourcing_signal_active"] = True
            assessment["governance_evidence_gap_detection_active"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]

            for capability in CAPABILITIES:
                key = capability_key(capability)
                assessment[f"{key}_active"] = True
                assessment[f"{key}_module_created"] = False

            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["accountability_presence_governance_operating_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_stage"] = False
        assessment["new_pillar"] = False
        assessment["new_architecture"] = False
        assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
        assessment["accountability_presence_governance_operating_assurance"] = PATCH

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
                "Do not create a new module, stage, pillar, or architecture for Accountability Presence and Governance Operating Assurance.",
                "Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust.",
                "Implement accountability presence, governance operating function, policy-to-practice, management-system-to-system, vendor/procurement trust, human oversight monitoring, governance resourcing, and governance evidence gap detection as cross-cutting capabilities.",
                "Continuously answer whether AI governance is actually functioning or only exists on paper."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="accountability-governance-card">
        <div class="accountability-governance-title">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def profile_cards(profiles):
    return "\n".join([card(name, controls) for name, controls in profiles.items()])

HTML_BLOCK = f"""
<style>
.platform-b-accountability-governance-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(245,158,11,.10), rgba(99,102,241,.08));
}}
.platform-b-accountability-governance-wrap h2 {{
    margin: 0 0 12px 0;
    font-size: 28px;
}}
.platform-b-accountability-governance-wrap p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 1120px;
}}
.platform-b-accountability-governance-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
    font-weight: 800;
}}
.platform-b-accountability-governance-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-accountability-governance-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}
.accountability-governance-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.accountability-governance-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.accountability-governance-title {{
    color: #fde68a;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
</style>

<section class="platform-b-accountability-governance-wrap">
    <h2>Accountability Presence and Governance Operating Assurance</h2>
    <p><strong>No new module, stage, pillar, or architecture.</strong> Platform B implements Accountability Presence Assurance, AI Governance Operating Function Assurance, Policy-to-Practice Assurance, Management-System-to-System Assurance, AI Vendor / Procurement Trust Assurance, Human Oversight Function Monitoring, AI Governance Resourcing Signal, and Governance Evidence Gap Detection as cross-cutting capabilities inside the existing lifecycle.</p>
    <p>{html_escape(PATCH["platform_principle"])}</p>

    <div class="platform-b-accountability-governance-warning">
        AI governance is not proven by a policy, legal review, named owner, or ISO 42001-aligned documentation alone. It is proven by operational accountability, active oversight, evidence, escalation, and control performance.
    </div>

    <div class="platform-b-accountability-governance-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-accountability-governance-grid">
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

Path("platform_b_accountability_presence_governance_operating_assurance_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_accountability_presence_governance_operating_assurance_patch_v1_urls.txt").write_text(
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
print("Platform B Accountability Presence and Governance Operating Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("New stage: False")
print("New pillar: False")
print("New architecture: False")
print("Locked lifecycle:", LOCKED_LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
