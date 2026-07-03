from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_ADVANCED_CROSS_CUTTING_CAPABILITIES_LOCKED_LIFECYCLE_PATCH_V1_ACTIVE"
LOCKED_LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"

CAPABILITIES = [
    "Assured Autonomy",
    "Operational Trust Passport",
    "Assurance Handshake",
    "Authority Boundary Graph",
    "AI Flight Recorder",
    "Failure Containment Architecture",
    "Human Oversight Evidence Engine",
    "AI Cyber Assurance",
    "Trust Surface Management",
    "Just-in-Time Autonomy",
    "AI Action Firewall",
    "Assurance Debt Register",
    "AI Immune System",
    "Evidence Integrity Firewall",
    "Assurance Half-Life",
    "Patient-Dose-Time-Cyber Assurance",
    "Context-Assured Wearable Endpoint",
    "Agent Failure Assurance"
]

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_stage": False,
    "new_pillar": False,
    "new_architecture": False,
    "capability_type": "Advanced cross-cutting capabilities inside the existing Platform B lifecycle",
    "locked_lifecycle_sequence": LOCKED_LIFECYCLE_SEQUENCE,
    "architecture_instruction": "Do not create new modules, stages, pillars, or architectures. Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust. Add the listed capabilities only as cross-cutting capabilities inside the existing lifecycle.",
    "cross_cutting_capabilities": CAPABILITIES,
    "discovery_extension": [
        "AI systems",
        "AI agents",
        "Models",
        "Workflows",
        "Wearables",
        "Digital twins",
        "Tools",
        "MCP/API connectors",
        "Data sources",
        "Memory stores",
        "Human owners",
        "Approval roles",
        "Authority boundaries",
        "Autonomy levels",
        "Evidence sources",
        "Cyber exposure",
        "Trust surface",
        "Patient/dose/time-sensitive operations"
    ],
    "visibility_extension": [
        "Operational Trust Passport",
        "Autonomy level",
        "Current authority state",
        "Active permissions",
        "Trust surface map",
        "Context freshness",
        "Memory integrity",
        "Tool access",
        "Human oversight status",
        "AI cyber posture",
        "Evidence completeness",
        "Assurance debt",
        "Expiring trust windows",
        "Failure risk",
        "Wearable assurance state",
        "Operational Trust Score"
    ],
    "governance_extension": [
        "Permitted autonomy",
        "Forbidden actions",
        "Authority boundaries",
        "Approval rules",
        "Human oversight rules",
        "Escalation rules",
        "Stopping conditions",
        "Memory governance",
        "Evidence integrity rules",
        "AI cyber controls",
        "Trust validity windows",
        "Patient-dose-time controls",
        "Wearable use policies",
        "Recovery policies"
    ],
    "operationalization_extension": [
        "Runtime policy checks",
        "Identity checks",
        "Authority checks",
        "Tool-permission checks",
        "Just-in-time autonomy",
        "AI Action Firewall",
        "Prompt injection controls",
        "Memory write controls",
        "Approval gates",
        "Wearable confirmation checks",
        "Action blocking",
        "Rollback / recovery triggers",
        "Assurance handshake before AI-to-AI or AI-to-system interaction"
    ],
    "manufacturing_monitoring_extension": [
        "AI-assisted manufacturing actions",
        "Equipment context",
        "Batch/dose timing",
        "AI recommendations",
        "Human confirmations",
        "Wearable-guided activities",
        "Deviation risk",
        "Cyber-physical risk",
        "Context drift",
        "Execution mismatch",
        "Patient-dose-time alignment"
    ],
    "evidence_extension": [
        "What the AI perceived",
        "What the AI reasoned",
        "What data the AI retrieved",
        "What the AI was authorized to do",
        "What tool the AI called",
        "What action the AI attempted",
        "What action the AI completed",
        "What the human reviewed",
        "What was approved/rejected/escalated",
        "What system was touched",
        "What evidence was generated",
        "Whether evidence passed integrity checks",
        "Whether the action occurred inside the valid assurance window"
    ],
    "continuous_assurance_extension": [
        "Prompt injection",
        "Privilege drift",
        "Context drift",
        "Memory contamination",
        "Tool misuse",
        "Unauthorized access",
        "Missing approval",
        "Silent performance degradation",
        "Evidence weakness",
        "False evidence",
        "Audit gaps",
        "Expired trust",
        "Cyber anomalies",
        "Degraded operational trust",
        "Patient-dose-time risk"
    ],
    "operational_trust_question": "Can this AI-enabled action, workflow, agent, wearable, evidence object, or autonomous system be trusted right now?",
    "platform_principle": "Platform B is not another AI governance dashboard. It is operational trust infrastructure for autonomous AI in regulated, cyber-physical, human-critical, and evidence-sensitive environments.",
    "capability_profiles": {
        "Assured Autonomy": [
            "Autonomy level",
            "Authority boundary",
            "Tool permissions",
            "Memory capability",
            "Human approval requirements",
            "Runtime enforcement",
            "Stopping condition"
        ],
        "Operational Trust Passport": [
            "AI asset identity",
            "Agent identity",
            "Workflow identity",
            "Owner identity",
            "Permission state",
            "Evidence state",
            "Risk state",
            "Operational Trust Score"
        ],
        "Assurance Handshake": [
            "AI-to-AI handoff check",
            "AI-to-system handoff check",
            "Control handoff validation",
            "Evidence handoff validation",
            "Receiving workflow verification",
            "Approval requirement check",
            "Trust state transfer"
        ],
        "Authority Boundary Graph": [
            "Authority boundary map",
            "Permitted autonomy map",
            "Forbidden action map",
            "Tool permission map",
            "Human approval boundary",
            "Escalation boundary",
            "Cyber boundary"
        ],
        "AI Flight Recorder": [
            "Perception record",
            "Reasoning summary",
            "Retrieved data record",
            "Authorization record",
            "Tool call record",
            "Attempted action record",
            "Completed action record",
            "Evidence timestamp"
        ],
        "Failure Containment Architecture": [
            "Failure mode",
            "Stopping condition",
            "Containment trigger",
            "Escalation path",
            "Rollback path",
            "Recovery policy",
            "Recovery evidence"
        ],
        "Human Oversight Evidence Engine": [
            "Human reviewer identity",
            "Approval role",
            "Review action",
            "Approval/rejection/escalation decision",
            "Oversight timestamp",
            "Missing oversight detection",
            "Oversight evidence"
        ],
        "AI Cyber Assurance": [
            "Prompt injection control",
            "Unauthorized access control",
            "Privilege drift control",
            "Tool misuse control",
            "Cyber anomaly detection",
            "Cyber-physical risk",
            "Cyber event evidence"
        ],
        "Trust Surface Management": [
            "Agent exposure",
            "Tool exposure",
            "Memory exposure",
            "Data access exposure",
            "Connector exposure",
            "Evidence exposure",
            "Cyber exposure"
        ],
        "Just-in-Time Autonomy": [
            "Time-bound autonomy",
            "Justified autonomy grant",
            "Approval-gated autonomy",
            "Tool access time limit",
            "Autonomy revocation after use",
            "Re-check before execution",
            "Expired autonomy block"
        ],
        "AI Action Firewall": [
            "Forbidden action block",
            "Tool-permission block",
            "Policy violation block",
            "Prompt attack block",
            "Unauthorized system touch block",
            "Expired context block",
            "High-risk action stop"
        ],
        "Assurance Debt Register": [
            "Evidence weakness",
            "Audit gap",
            "Deferred control",
            "Late evidence",
            "Expired trust",
            "Owner assignment",
            "Remediation due date"
        ],
        "AI Immune System": [
            "Prompt injection detection",
            "Privilege drift detection",
            "Memory contamination detection",
            "Tool misuse detection",
            "Silent degradation detection",
            "Degraded trust detection",
            "Containment response"
        ],
        "Evidence Integrity Firewall": [
            "Evidence completeness check",
            "Evidence freshness check",
            "Evidence lineage check",
            "False evidence detection",
            "Integrity failure block",
            "Tamper-risk check",
            "Evidence acceptance/rejection"
        ],
        "Assurance Half-Life": [
            "Trust validity window",
            "Approval validity window",
            "AI recommendation timestamp",
            "Wearable instruction timestamp",
            "Evidence freshness requirement",
            "Expired trust detection",
            "Refresh/re-approval evidence"
        ],
        "Patient-Dose-Time-Cyber Assurance": [
            "Patient appointment window",
            "Dose/batch timing",
            "Shipment window",
            "Release evidence freshness",
            "Cyber posture",
            "Patient-dose-time alignment",
            "Late or stale action block"
        ],
        "Context-Assured Wearable Endpoint": [
            "Wearable identity",
            "Wearable instruction timestamp",
            "Human confirmation",
            "Workflow context",
            "Location/context check",
            "Cyber posture check",
            "Wearable-guided activity evidence"
        ],
        "Agent Failure Assurance": [
            "Goal integrity",
            "Prompt integrity",
            "Context drift",
            "Tool overreach",
            "Memory contamination",
            "Loop detection",
            "Multi-agent conflict",
            "Unauthorized access",
            "Silent degradation"
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

    data["platform_b_advanced_cross_cutting_capabilities_patch"] = PATCH
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
            bp["advanced_cross_cutting_capabilities"] = PATCH

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

            assessment["advanced_cross_cutting_capabilities_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["new_stage"] = False
            assessment["new_pillar"] = False
            assessment["new_architecture"] = False
            assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]
            assessment["platform_principle"] = PATCH["platform_principle"]

            for capability in CAPABILITIES:
                key = capability_key(capability)
                assessment[f"{key}_active"] = True
                assessment[f"{key}_module_created"] = False

            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["advanced_cross_cutting_capabilities_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_stage"] = False
        assessment["new_pillar"] = False
        assessment["new_architecture"] = False
        assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
        assessment["advanced_cross_cutting_capabilities"] = PATCH

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
                "Do not create new modules, stages, pillars, or architectures.",
                "Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust.",
                "Implement advanced cross-cutting capabilities inside the existing lifecycle only.",
                "Continuously answer whether the AI-enabled action, workflow, agent, wearable, evidence object, or autonomous system can be trusted right now."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="adv-xcap-card">
        <div class="adv-xcap-title">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def profile_cards(profiles):
    return "\n".join([card(name, controls) for name, controls in profiles.items()])

HTML_BLOCK = f"""
<style>
.platform-b-advanced-xcap-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(20,184,166,.10), rgba(99,102,241,.08));
}}
.platform-b-advanced-xcap-wrap h2 {{
    margin: 0 0 12px 0;
    font-size: 28px;
}}
.platform-b-advanced-xcap-wrap p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 1120px;
}}
.platform-b-advanced-xcap-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
    font-weight: 800;
}}
.platform-b-advanced-xcap-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-advanced-xcap-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}
.adv-xcap-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.adv-xcap-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.adv-xcap-title {{
    color: #99f6e4;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
</style>

<section class="platform-b-advanced-xcap-wrap">
    <h2>Advanced Cross-Cutting Capabilities</h2>
    <p><strong>No new modules, stages, pillars, or architectures.</strong> Platform B keeps the lifecycle locked as Discovery → Visibility → Governance → Operationalization → Manufacturing Monitoring → Evidence → Continuous Assurance → Operational Trust.</p>
    <p>{html_escape(PATCH["platform_principle"])}</p>

    <div class="platform-b-advanced-xcap-warning">
        These capabilities are cross-cutting only. They enrich the existing lifecycle and must not become separate modules.
    </div>

    <div class="platform-b-advanced-xcap-question">
        Operational Trust continuously asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-advanced-xcap-grid">
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
        "<!-- COBITCHAIN_PLATFORM_B_AI_CAPABILITY_ASSURANCE_LIBRARY_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_ASSURED_AUTONOMY_CROSS_CUTTING_CAPABILITY_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_AGENT_FAILURE_ASSURANCE_CONTROL_SET_PATCH_V1_ACTIVE -->",
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

Path("platform_b_advanced_cross_cutting_capabilities_locked_lifecycle_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_advanced_cross_cutting_capabilities_locked_lifecycle_patch_v1_urls.txt").write_text(
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
print("Platform B Advanced Cross-Cutting Capabilities Locked Lifecycle Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("New stage: False")
print("New pillar: False")
print("New architecture: False")
print("Locked lifecycle:", LOCKED_LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
