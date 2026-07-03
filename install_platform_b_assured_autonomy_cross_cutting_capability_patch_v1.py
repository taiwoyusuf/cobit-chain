from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_ASSURED_AUTONOMY_CROSS_CUTTING_CAPABILITY_PATCH_V1_ACTIVE"
LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_lifecycle": False,
    "new_module": False,
    "capability_name": "Assured Autonomy",
    "capability_type": "Cross-cutting capability across the existing Platform B lifecycle",
    "architecture_instruction": "Do not create a new module and do not create a new lifecycle. Add Assured Autonomy as a cross-cutting capability across Discovery, Visibility, Governance, Operationalization, Evidence, Continuous Assurance, and Operational Trust.",
    "lifecycle_sequence": LIFECYCLE_SEQUENCE,
    "discovery_extension": [
        "Autonomy level",
        "Authority boundary",
        "Tool permissions",
        "Memory capability",
        "Human approval requirements"
    ],
    "visibility_extension": [
        "Autonomy status",
        "Active permissions",
        "Context freshness",
        "Memory integrity",
        "Tool access",
        "Operational Trust Score"
    ],
    "governance_extension": [
        "Autonomy limits",
        "Approval rules",
        "Escalation rules",
        "Stopping conditions",
        "Recovery policies"
    ],
    "operationalization_extension": [
        "Authority checks",
        "Policy checks",
        "Risk checks",
        "Human approval gates",
        "Runtime enforcement"
    ],
    "evidence_extension": [
        "What the AI perceived",
        "What the AI reasoned",
        "What the AI was authorized to do",
        "What the AI actually did",
        "Who approved it",
        "What evidence was generated"
    ],
    "continuous_assurance_extension": [
        "Context drift",
        "Memory drift",
        "Tool misuse",
        "Unauthorized action",
        "Human oversight failure",
        "Recovery evidence"
    ],
    "operational_trust_question": "Can this autonomous system still be trusted right now?",
    "platform_statement": "Platform B does not treat autonomy as a feature flag or a separate module. Platform B adds Assured Autonomy as a cross-cutting capability that continuously evaluates authority, permissions, memory, context, approval, execution, evidence, recovery, and operational trust across the existing lifecycle.",
    "principle": "Autonomy is not trusted because an AI system can act. Autonomy is trusted only when its authority boundaries, permissions, memory, context, approvals, runtime actions, recovery, and evidence remain continuously assured.",
    "evidence_questions": [
        "What autonomy level is active?",
        "What is the authority boundary?",
        "Which tool permissions are active?",
        "What memory capability is enabled?",
        "What human approval is required?",
        "What is the current autonomy status?",
        "Are active permissions still valid?",
        "Is context fresh enough for the autonomous action?",
        "Is memory integrity intact?",
        "Which tools can the AI access?",
        "What is the Operational Trust Score?",
        "Which autonomy limits apply?",
        "Which approval rules apply?",
        "Which escalation rules apply?",
        "Which stopping conditions apply?",
        "Which recovery policies apply?",
        "Were authority checks performed?",
        "Were policy checks performed?",
        "Were risk checks performed?",
        "Were human approval gates completed?",
        "Was runtime enforcement executed?",
        "What did the AI perceive?",
        "What did the AI reason?",
        "What was the AI authorized to do?",
        "What did the AI actually do?",
        "Who approved the autonomous action?",
        "What evidence was generated?",
        "Is context drift present?",
        "Is memory drift present?",
        "Is tool misuse present?",
        "Was an unauthorized action attempted?",
        "Did human oversight fail?",
        "Is recovery evidence complete?",
        "Can this autonomous system still be trusted right now?"
    ]
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

def patch_seed(path):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path}")
        return

    data = load_json(path)
    if not isinstance(data, dict):
        print(f"SKIP: {path} is not JSON object")
        return

    data["platform_b_assured_autonomy_cross_cutting_capability_patch"] = PATCH
    data["platform_b_architecture_change"] = False
    data["platform_b_new_lifecycle"] = False
    data["platform_b_new_module"] = False
    data["platform_b_assured_autonomy_module_created"] = False
    data["platform_b_lifecycle_sequence"] = LIFECYCLE_SEQUENCE

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["new_lifecycle"] = False
            bp["new_module"] = False
            bp["assured_autonomy_module_created"] = False
            bp["assured_autonomy_cross_cutting_capability"] = PATCH

            bp["discovery_scope"] = add_unique(
                bp.get("discovery_scope", []),
                PATCH["discovery_extension"]
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
                PATCH["operationalization_extension"]
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
                [PATCH["operational_trust_question"], "Operational Trust Score"]
            )

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                PATCH["evidence_questions"]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["assured_autonomy_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_lifecycle"] = False
            assessment["new_module"] = False
            assessment["assured_autonomy_module_created"] = False
            assessment["cross_cutting_capability"] = True
            assessment["autonomy_level_tracked"] = True
            assessment["authority_boundary_tracked"] = True
            assessment["tool_permissions_tracked"] = True
            assessment["memory_capability_tracked"] = True
            assessment["human_approval_requirements_tracked"] = True
            assessment["autonomy_status_visible"] = True
            assessment["active_permissions_visible"] = True
            assessment["context_freshness_visible"] = True
            assessment["memory_integrity_visible"] = True
            assessment["tool_access_visible"] = True
            assessment["operational_trust_score_visible"] = True
            assessment["autonomy_limits_governed"] = True
            assessment["approval_rules_governed"] = True
            assessment["escalation_rules_governed"] = True
            assessment["stopping_conditions_governed"] = True
            assessment["recovery_policies_governed"] = True
            assessment["authority_checks_required"] = True
            assessment["policy_checks_required"] = True
            assessment["risk_checks_required"] = True
            assessment["human_approval_gates_required"] = True
            assessment["runtime_enforcement_required"] = True
            assessment["ai_perception_evidence_required"] = True
            assessment["ai_reasoning_evidence_required"] = True
            assessment["ai_authorization_evidence_required"] = True
            assessment["ai_action_evidence_required"] = True
            assessment["approval_evidence_required"] = True
            assessment["generated_evidence_required"] = True
            assessment["context_drift_monitored"] = True
            assessment["memory_drift_monitored"] = True
            assessment["tool_misuse_monitored"] = True
            assessment["unauthorized_action_monitored"] = True
            assessment["human_oversight_failure_monitored"] = True
            assessment["recovery_evidence_monitored"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["assured_autonomy_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_lifecycle"] = False
        assessment["new_module"] = False
        assessment["assured_autonomy_module_created"] = False
        assessment["assured_autonomy_cross_cutting_capability"] = PATCH

        assessment["operationalization_targets"] = add_unique(
            assessment.get("operationalization_targets", []),
            PATCH["operationalization_extension"]
        )

        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            PATCH["evidence_extension"] + PATCH["evidence_questions"]
        )

        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            PATCH["continuous_assurance_extension"]
        )

        assessment["implementation_priority"] = add_unique(
            assessment.get("implementation_priority", []),
            [
                "Do not create an Assured Autonomy module.",
                "Do not create a new lifecycle for autonomy.",
                "Add Assured Autonomy as a cross-cutting capability across the existing Platform B lifecycle.",
                "Extend Discovery with autonomy level, authority boundary, tool permissions, memory capability, and human approval requirements.",
                "Extend Visibility with autonomy status, active permissions, context freshness, memory integrity, tool access, and Operational Trust Score.",
                "Extend Governance with autonomy limits, approval rules, escalation rules, stopping conditions, and recovery policies.",
                "Extend Operationalization with authority checks, policy checks, risk checks, human approval gates, and runtime enforcement.",
                "Capture evidence of what the AI perceived, reasoned, was authorized to do, actually did, who approved it, and what evidence was generated.",
                "Continuously monitor context drift, memory drift, tool misuse, unauthorized action, human oversight failure, and recovery evidence.",
                "Ask whether the autonomous system can still be trusted right now."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="assured-autonomy-card">
        <div class="assured-autonomy-domain">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def pill_list(items, cls):
    return "".join([f'<span class="{cls}">{html_escape(x)}</span>' for x in items])

HTML_BLOCK = f"""
<style>
.platform-b-assured-autonomy-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(34,197,94,.10), rgba(14,165,233,.08));
}}
.platform-b-assured-autonomy-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 18px;
}}
.platform-b-assured-autonomy-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-assured-autonomy-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 980px;
}}
.platform-b-assured-autonomy-tag {{
    border: 1px solid rgba(134,239,172,.45);
    color: #bbf7d0;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(34,197,94,.10);
}}
.platform-b-assured-autonomy-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
}}
.platform-b-assured-autonomy-principle {{
    margin: 18px 0;
    padding: 18px;
    border-left: 4px solid #86efac;
    color: #dcfce7;
    background: rgba(255,255,255,.055);
    border-radius: 16px;
    line-height: 1.65;
    font-size: 17px;
    font-weight: 800;
}}
.platform-b-assured-autonomy-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-assured-autonomy-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
}}
.assured-autonomy-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.assured-autonomy-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.assured-autonomy-domain {{
    color: #bbf7d0;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
.platform-b-assured-autonomy-pills {{
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
}}
.platform-b-assured-autonomy-pill {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 8px 12px;
    color: #d8dee9;
    font-size: 13px;
}}
</style>

<section class="platform-b-assured-autonomy-wrap">
    <div class="platform-b-assured-autonomy-head">
        <div>
            <h2>Assured Autonomy</h2>
            <p>
                No new module. No new lifecycle. Platform B adds Assured Autonomy as a cross-cutting capability
                across the existing lifecycle, continuously assuring autonomy level, authority boundary, permissions,
                memory, human approval, runtime enforcement, evidence, recovery, and operational trust.
            </p>
        </div>
        <span class="platform-b-assured-autonomy-tag">Cross-Cutting Capability</span>
    </div>

    <div class="platform-b-assured-autonomy-warning">
        Do not create an Assured Autonomy module. This capability enriches existing lifecycle stages and asks whether the autonomous system can still be trusted right now.
    </div>

    <div class="platform-b-assured-autonomy-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-assured-autonomy-principle">
        {html_escape(PATCH["principle"])}
    </div>

    <div class="platform-b-assured-autonomy-grid">
        {card("Discovery", PATCH["discovery_extension"])}
        {card("Visibility", PATCH["visibility_extension"])}
        {card("Governance", PATCH["governance_extension"])}
        {card("Operationalization", PATCH["operationalization_extension"])}
        {card("Evidence", PATCH["evidence_extension"])}
        {card("Continuous Assurance", PATCH["continuous_assurance_extension"])}
    </div>

    <div class="platform-b-assured-autonomy-pills">
        {pill_list(PATCH["evidence_questions"], "platform-b-assured-autonomy-pill")}
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
        "<!-- COBITCHAIN_PLATFORM_B_AGENT_FAILURE_ASSURANCE_CONTROL_SET_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_ENTERPRISE_AI_ADOPTION_AGENT_OPERATIONAL_TRUST_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_AI_SECURITY_RUNTIME_GOVERNANCE_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_ISO42001_LIFECYCLE_MAPPING_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_GOVERNANCE_FRAMEWORK_MAPPING_CONSOLE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_AI_COMPETENCY_GOVERNANCE_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_REGULATORY_AI_EVIDENCE_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_AI_FRAMEWORK_RUNTIME_OPERATIONALIZATION_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_IDENTITY_PERMISSION_AWARE_EXECUTION_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_PRODUCTION_RAG_EXECUTION_ASSURANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_GOVERNANCE_SUSTAINED_COMPLIANCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_PRODUCTION_OWNERSHIP_CONTINUITY_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_BUSINESS_VALUE_KPI_EVIDENCE_PATCH_V1_ACTIVE -->",
        "<!-- COBITCHAIN_PLATFORM_B_EXISTING_CAPABILITY_DEEPENING_PATCH_V1_ACTIVE -->",
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

Path("platform_b_assured_autonomy_cross_cutting_capability_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_assured_autonomy_cross_cutting_capability_patch_v1_urls.txt").write_text(
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
print("Platform B Assured Autonomy Cross-Cutting Capability Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New lifecycle: False")
print("New module: False")
print("Capability type:", PATCH["capability_type"])
print("Lifecycle:", LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
