from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_CONTEXT_ASSURED_WEARABLE_PRE_DEVIATION_ASSURANCE_PATCH_V1_ACTIVE"
LOCKED_LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"

CAPABILITY = "Context-Assured Wearable Endpoint for Pre-Deviation Assurance"

WEARABLE_MODES = [
    "Deviation Intercept Mode",
    "Context Proof",
    "Wrong-Action Prevention",
    "CAPA-at-the-Source Evidence Capture",
    "Human Oversight Replay",
    "Weak-Signal Learning",
    "Evidence Integrity Lock",
    "Assurance Overlay"
]

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_stage": False,
    "new_pillar": False,
    "new_architecture": False,
    "capability_type": "Context-Assured Wearable Endpoint as a cross-cutting Platform B capability for Pre-Deviation Assurance",
    "locked_lifecycle_sequence": LOCKED_LIFECYCLE_SEQUENCE,
    "architecture_instruction": "Do not create a new module, stage, pillar, or architecture. Add Context-Assured Wearable Endpoint for Pre-Deviation Assurance as a cross-cutting capability inside the existing Platform B lifecycle.",
    "cross_cutting_capability": CAPABILITY,
    "wearable_support_modes": WEARABLE_MODES,
    "discovery_extension": [
        "Wearable device ID",
        "Operator identity",
        "Operator role",
        "Approved task",
        "SOP/work instruction",
        "Equipment ID",
        "Batch/work order/patient/dose context where applicable",
        "Location/room",
        "Required evidence",
        "Human approval requirement",
        "Risk history for that task",
        "Prior deviations linked to the same step, equipment, process, or operator workflow"
    ],
    "visibility_extension": [
        "Current operator context",
        "Equipment match status",
        "SOP step status",
        "Authorization status",
        "Deviation risk level",
        "Evidence completeness",
        "Approval requirement",
        "Active AI recommendation",
        "Wearable trust state",
        "Weak-signal alerts",
        "Operational Trust Score"
    ],
    "governance_extension": [
        "Where wearables are allowed",
        "What the wearable may capture",
        "What the wearable must not capture",
        "Who may use the wearable",
        "What steps require confirmation",
        "What actions require escalation",
        "When AI recommendations require human approval",
        "When wearable evidence is required",
        "How wearable evidence is reviewed",
        "How privacy, security, and data integrity are protected"
    ],
    "operationalization_extension": [
        "Identity check",
        "Location check",
        "Equipment check",
        "SOP step check",
        "Batch/context check",
        "Authorization check",
        "Evidence requirement check",
        "AI recommendation validation",
        "Stop / verify / escalate rules",
        "Wrong-action warning",
        "Red/yellow/green assurance overlay"
    ],
    "manufacturing_monitoring_extension": [
        "Repeated wrong-equipment approach",
        "Skipped confirmation",
        "Repeated manual override",
        "Repeated evidence gap",
        "Operator hesitation pattern",
        "Alarm acknowledgement pattern",
        "SOP step confusion",
        "Late escalation",
        "Recurring near-miss pattern",
        "Context mismatch before action"
    ],
    "evidence_extension": [
        "What the operator saw",
        "What instruction was displayed",
        "What AI recommended",
        "What system context was active",
        "What the operator confirmed",
        "What was rejected",
        "What was escalated",
        "What evidence was collected",
        "Timestamp",
        "Location",
        "Equipment/process context",
        "Reviewer approval",
        "Deviation-prevention action"
    ],
    "continuous_assurance_extension": [
        "Pre-deviation signals",
        "Wrong context",
        "Stale instruction",
        "Unauthorized action",
        "Missing evidence",
        "Approval bypass",
        "Repeated near-miss pattern",
        "Ineffective CAPA recurrence",
        "Evidence weakness",
        "Wearable misuse",
        "Degraded operational trust"
    ],
    "operational_trust_question": "Can this human-AI-assisted action be trusted right now, based on the operator, context, equipment, instruction, authorization, evidence, and risk state?",
    "platform_principle": "Platform B uses Context-Assured Wearable Endpoint to intercept pre-deviation risk at the point of action by binding operator identity, equipment context, SOP step, authorization, AI recommendation, evidence capture, and operational trust state.",
    "capability_profiles": {
        "Deviation Intercept Mode": [
            "Pre-deviation signal detected at point of action",
            "Wrong context detected before execution",
            "High-risk action paused",
            "Stop / verify / escalate rule applied",
            "Deviation-prevention action captured"
        ],
        "Context Proof": [
            "Operator identity confirmed",
            "Operator role confirmed",
            "Location/room confirmed",
            "Equipment ID confirmed",
            "Batch/work order/patient/dose context confirmed",
            "SOP/work instruction confirmed"
        ],
        "Wrong-Action Prevention": [
            "Wrong-equipment approach warning",
            "Wrong-step warning",
            "Unauthorized action block",
            "Stale instruction block",
            "Context mismatch warning",
            "Red/yellow/green assurance overlay"
        ],
        "CAPA-at-the-Source Evidence Capture": [
            "CAPA-related evidence captured where work occurs",
            "Operator confirmation captured",
            "Rejected alternative captured",
            "Escalation captured",
            "Preventive intervention evidence captured",
            "Reviewer approval linked"
        ],
        "Human Oversight Replay": [
            "What the operator saw",
            "What instruction was displayed",
            "What AI recommended",
            "What the operator confirmed",
            "What was rejected",
            "What was escalated",
            "Reviewer replay evidence"
        ],
        "Weak-Signal Learning": [
            "Operator hesitation pattern",
            "Repeated manual override",
            "Skipped confirmation",
            "Repeated evidence gap",
            "Alarm acknowledgement pattern",
            "SOP step confusion",
            "Near-miss recurrence pattern"
        ],
        "Evidence Integrity Lock": [
            "Evidence source locked",
            "Timestamp locked",
            "Location locked",
            "Equipment/process context locked",
            "Reviewer approval locked",
            "Evidence completeness checked",
            "Tamper risk reduced"
        ],
        "Assurance Overlay": [
            "Green state: trusted context",
            "Yellow state: verify before action",
            "Red state: stop and escalate",
            "Operational Trust Score displayed",
            "Approval requirement displayed",
            "Evidence completeness displayed",
            "Deviation risk displayed"
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

def patch_seed(path):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path}")
        return

    data = load_json(path)
    if not isinstance(data, dict):
        print(f"SKIP: {path} is not JSON object")
        return

    data["platform_b_context_assured_wearable_pre_deviation_assurance_patch"] = PATCH
    data["platform_b_architecture_change"] = False
    data["platform_b_new_module"] = False
    data["platform_b_new_stage"] = False
    data["platform_b_new_pillar"] = False
    data["platform_b_new_architecture"] = False
    data["platform_b_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
    data["platform_b_context_assured_wearable_endpoint_module_created"] = False

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
            bp["context_assured_wearable_pre_deviation_assurance"] = PATCH

            bp["discovery_scope"] = add_unique(
                bp.get("discovery_scope", []),
                PATCH["discovery_extension"] + [CAPABILITY] + WEARABLE_MODES
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
                [PATCH["operational_trust_question"], PATCH["platform_principle"], CAPABILITY] + WEARABLE_MODES
            )

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [PATCH["operational_trust_question"]]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["context_assured_wearable_pre_deviation_assurance_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["new_stage"] = False
            assessment["new_pillar"] = False
            assessment["new_architecture"] = False
            assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            assessment["context_assured_wearable_endpoint_module_created"] = False
            assessment["deviation_intercept_mode_active"] = True
            assessment["context_proof_active"] = True
            assessment["wrong_action_prevention_active"] = True
            assessment["capa_at_the_source_evidence_capture_active"] = True
            assessment["human_oversight_replay_active"] = True
            assessment["weak_signal_learning_active"] = True
            assessment["evidence_integrity_lock_active"] = True
            assessment["assurance_overlay_active"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["context_assured_wearable_pre_deviation_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_stage"] = False
        assessment["new_pillar"] = False
        assessment["new_architecture"] = False
        assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
        assessment["context_assured_wearable_pre_deviation_assurance"] = PATCH

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
                "Do not create a new module, stage, pillar, or architecture for Context-Assured Wearable Endpoint.",
                "Implement Context-Assured Wearable Endpoint for Pre-Deviation Assurance as a cross-cutting capability inside the existing lifecycle.",
                "Use wearable context to intercept wrong action, capture CAPA-at-the-source evidence, support human oversight replay, learn weak signals, and lock evidence integrity."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="wearable-predev-card">
        <div class="wearable-predev-title">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def profile_cards(profiles):
    return "\n".join([card(name, controls) for name, controls in profiles.items()])

HTML_BLOCK = f"""
<style>
.platform-b-wearable-predev-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(34,197,94,.10), rgba(14,165,233,.08));
}}
.platform-b-wearable-predev-wrap h2 {{
    margin: 0 0 12px 0;
    font-size: 28px;
}}
.platform-b-wearable-predev-wrap p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 1120px;
}}
.platform-b-wearable-predev-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
    font-weight: 800;
}}
.platform-b-wearable-predev-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-wearable-predev-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}
.wearable-predev-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.wearable-predev-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.wearable-predev-title {{
    color: #bbf7d0;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
</style>

<section class="platform-b-wearable-predev-wrap">
    <h2>Context-Assured Wearable Endpoint for Pre-Deviation Assurance</h2>
    <p><strong>No new module, stage, pillar, or architecture.</strong> Platform B implements Context-Assured Wearable Endpoint as a cross-cutting capability inside the existing lifecycle: Discovery → Visibility → Governance → Operationalization → Manufacturing Monitoring → Evidence → Continuous Assurance → Operational Trust.</p>
    <p>{html_escape(PATCH["platform_principle"])}</p>

    <div class="platform-b-wearable-predev-warning">
        The wearable is not a standalone product module. It is a context, evidence, and operational trust endpoint for preventing wrong action before deviation.
    </div>

    <div class="platform-b-wearable-predev-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-wearable-predev-grid">
        {card("Wearable Support Modes", WEARABLE_MODES)}
        {card("Discovery", PATCH["discovery_extension"])}
        {card("Visibility", PATCH["visibility_extension"])}
        {card("Governance", PATCH["governance_extension"])}
        {card("Operationalization", PATCH["operationalization_extension"])}
        {card("Manufacturing Monitoring", PATCH["manufacturing_monitoring_extension"])}
        {card("Evidence", PATCH["evidence_extension"])}
        {card("Continuous Assurance", PATCH["continuous_assurance_extension"])}
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

Path("platform_b_context_assured_wearable_pre_deviation_assurance_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_context_assured_wearable_pre_deviation_assurance_patch_v1_urls.txt").write_text(
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
print("Platform B Context-Assured Wearable Endpoint for Pre-Deviation Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("New stage: False")
print("New pillar: False")
print("New architecture: False")
print("Locked lifecycle:", LOCKED_LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
