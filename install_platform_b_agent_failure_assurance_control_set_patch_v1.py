from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_AGENT_FAILURE_ASSURANCE_CONTROL_SET_PATCH_V1_ACTIVE"
LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_lifecycle": False,
    "new_module": False,
    "agent_failure_module_created": False,
    "capability_name": "Agent Failure Assurance Control Set",
    "placement": [
        "Execution Assurance",
        "Continuous Assurance"
    ],
    "architecture_instruction": "Do not create a new lifecycle and do not create another module. Add Agent Failure Assurance as a control set under existing Execution Assurance and Continuous Assurance.",
    "lifecycle_sequence": LIFECYCLE_SEQUENCE,
    "operating_pattern": [
        "Prevent",
        "Detect",
        "Respond",
        "Recover",
        "Evidence"
    ],
    "control_set": [
        "Goal integrity",
        "Prompt integrity",
        "Context drift",
        "Tool overreach",
        "Memory contamination",
        "Loop detection",
        "Multi-agent conflict",
        "Unauthorized access",
        "Human approval gaps",
        "Silent degradation",
        "Audit completeness",
        "Ownership ambiguity"
    ],
    "execution_assurance_controls": [
        "Prevent goal integrity failure before execution",
        "Prevent prompt integrity failure before execution",
        "Prevent tool overreach during execution",
        "Prevent unauthorized access during execution",
        "Prevent missing human approval during execution",
        "Prevent ownership ambiguity before execution",
        "Detect loop formation during execution",
        "Detect multi-agent conflict during execution",
        "Detect silent degradation during execution",
        "Respond to agent failure signals during execution",
        "Recover failed or unsafe agent execution",
        "Generate execution evidence for each control operation"
    ],
    "continuous_assurance_monitors": [
        "Goal integrity drift",
        "Prompt integrity drift",
        "Context drift",
        "Tool overreach trend",
        "Memory contamination trend",
        "Loop detection events",
        "Multi-agent conflict events",
        "Unauthorized access attempts",
        "Human approval gap trend",
        "Silent degradation signals",
        "Audit completeness score",
        "Ownership ambiguity backlog"
    ],
    "evidence_extension": [
        "Goal integrity checked",
        "Prompt integrity checked",
        "Context drift detected",
        "Tool overreach blocked",
        "Memory contamination checked",
        "Loop detected",
        "Multi-agent conflict detected",
        "Unauthorized access blocked",
        "Human approval gap identified",
        "Silent degradation detected",
        "Audit completeness verified",
        "Ownership ambiguity resolved",
        "Prevent action recorded",
        "Detect action recorded",
        "Respond action recorded",
        "Recover action recorded",
        "Evidence generated"
    ],
    "operational_trust_question": "Can this agent failure risk be prevented, detected, responded to, recovered from, and evidenced inside the existing Platform B lifecycle?",
    "platform_statement": "Platform B does not add a new lifecycle for Agent Failure Assurance. Platform B adds an Agent Failure Assurance control set under Execution Assurance and Continuous Assurance so agent failure risks are managed through Prevent, Detect, Respond, Recover, and Evidence.",
    "principle": "Agent failure assurance is not a separate lifecycle. It is an execution and continuous assurance control set that proves whether agent failures can be prevented, detected, responded to, recovered from, and evidenced."
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

    data["platform_b_agent_failure_assurance_control_set_patch"] = PATCH
    data["platform_b_architecture_change"] = False
    data["platform_b_new_lifecycle"] = False
    data["platform_b_new_module"] = False
    data["platform_b_agent_failure_module_created"] = False
    data["platform_b_lifecycle_sequence"] = LIFECYCLE_SEQUENCE

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["new_lifecycle"] = False
            bp["new_module"] = False
            bp["agent_failure_module_created"] = False
            bp["agent_failure_assurance_control_set"] = PATCH

            bp["execution_assurance_scope"] = add_unique(
                bp.get("execution_assurance_scope", []),
                ["Agent Failure Assurance Control Set"] + PATCH["control_set"] + PATCH["execution_assurance_controls"]
            )

            bp["continuous_assurance"] = add_unique(
                bp.get("continuous_assurance", []),
                PATCH["continuous_assurance_monitors"]
            )

            bp["evidence_assurance"] = add_unique(
                bp.get("evidence_assurance", []),
                PATCH["evidence_extension"]
            )

            bp["operational_trust_scope"] = add_unique(
                bp.get("operational_trust_scope", []),
                [PATCH["operational_trust_question"]]
            )

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [
                    "Was goal integrity checked?",
                    "Was prompt integrity checked?",
                    "Was context drift detected?",
                    "Was tool overreach blocked?",
                    "Was memory contamination checked?",
                    "Was loop detection active?",
                    "Was multi-agent conflict detected?",
                    "Was unauthorized access blocked?",
                    "Were human approval gaps identified?",
                    "Was silent degradation detected?",
                    "Was audit completeness verified?",
                    "Was ownership ambiguity resolved?",
                    PATCH["operational_trust_question"]
                ]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["agent_failure_assurance_control_set_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_lifecycle"] = False
            assessment["new_module"] = False
            assessment["agent_failure_module_created"] = False
            assessment["placed_under_execution_assurance"] = True
            assessment["placed_under_continuous_assurance"] = True
            assessment["prevent_detect_respond_recover_evidence_pattern"] = True
            assessment["goal_integrity_tracked"] = True
            assessment["prompt_integrity_tracked"] = True
            assessment["context_drift_tracked"] = True
            assessment["tool_overreach_tracked"] = True
            assessment["memory_contamination_tracked"] = True
            assessment["loop_detection_tracked"] = True
            assessment["multi_agent_conflict_tracked"] = True
            assessment["unauthorized_access_tracked"] = True
            assessment["human_approval_gaps_tracked"] = True
            assessment["silent_degradation_tracked"] = True
            assessment["audit_completeness_tracked"] = True
            assessment["ownership_ambiguity_tracked"] = True
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["agent_failure_assurance_control_set_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_lifecycle"] = False
        assessment["new_module"] = False
        assessment["agent_failure_module_created"] = False
        assessment["agent_failure_assurance_control_set"] = PATCH

        assessment["execution_assurance_targets"] = add_unique(
            assessment.get("execution_assurance_targets", []),
            PATCH["control_set"] + PATCH["execution_assurance_controls"]
        )

        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            PATCH["continuous_assurance_monitors"]
        )

        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            PATCH["evidence_extension"]
        )

        assessment["implementation_priority"] = add_unique(
            assessment.get("implementation_priority", []),
            [
                "Do not create a new lifecycle for Agent Failure Assurance.",
                "Do not create an Agent Failure module.",
                "Add Agent Failure Assurance as a control set under Execution Assurance and Continuous Assurance.",
                "Track goal integrity, prompt integrity, context drift, tool overreach, memory contamination, loop detection, multi-agent conflict, unauthorized access, human approval gaps, silent degradation, audit completeness, and ownership ambiguity.",
                "Use Prevent, Detect, Respond, Recover, and Evidence as the operating pattern.",
                "Capture evidence that each agent failure control operated."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="agent-failure-control-card">
        <div class="agent-failure-control-domain">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def pill_list(items, cls):
    return "".join([f'<span class="{cls}">{html_escape(x)}</span>' for x in items])

HTML_BLOCK = f"""
<style>
.platform-b-agent-failure-control-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(245,158,11,.11), rgba(14,165,233,.08));
}}
.platform-b-agent-failure-control-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 18px;
}}
.platform-b-agent-failure-control-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-agent-failure-control-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 980px;
}}
.platform-b-agent-failure-control-tag {{
    border: 1px solid rgba(251,191,36,.45);
    color: #fde68a;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(245,158,11,.10);
}}
.platform-b-agent-failure-control-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
}}
.platform-b-agent-failure-control-principle {{
    margin: 18px 0;
    padding: 18px;
    border-left: 4px solid #fbbf24;
    color: #fef3c7;
    background: rgba(255,255,255,.055);
    border-radius: 16px;
    line-height: 1.65;
    font-size: 17px;
    font-weight: 800;
}}
.platform-b-agent-failure-control-pattern {{
    margin: 18px 0;
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
}}
.platform-b-agent-failure-control-pattern span {{
    border: 1px solid rgba(251,191,36,.25);
    background: rgba(245,158,11,.10);
    color: #fde68a;
    border-radius: 999px;
    padding: 9px 14px;
    font-weight: 800;
}}
.platform-b-agent-failure-control-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
}}
.agent-failure-control-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.agent-failure-control-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.agent-failure-control-domain {{
    color: #fde68a;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
.platform-b-agent-failure-control-pills {{
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
}}
.platform-b-agent-failure-control-pill {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 8px 12px;
    color: #d8dee9;
    font-size: 13px;
}}
</style>

<section class="platform-b-agent-failure-control-wrap">
    <div class="platform-b-agent-failure-control-head">
        <div>
            <h2>Agent Failure Assurance Control Set</h2>
            <p>
                No new lifecycle. No new module. Platform B places Agent Failure Assurance under existing
                Execution Assurance and Continuous Assurance so agent failures are prevented, detected,
                responded to, recovered from, and evidenced.
            </p>
        </div>
        <span class="platform-b-agent-failure-control-tag">Execution / Continuous Assurance Control Set</span>
    </div>

    <div class="platform-b-agent-failure-control-warning">
        Do not create an Agent Failure module or new lifecycle. This is a control set inside existing Execution Assurance and Continuous Assurance.
    </div>

    <div class="platform-b-agent-failure-control-principle">
        {html_escape(PATCH["principle"])}
    </div>

    <div class="platform-b-agent-failure-control-pattern">
        {pill_list(PATCH["operating_pattern"], "platform-b-agent-failure-control-pattern-pill")}
    </div>

    <div class="platform-b-agent-failure-control-grid">
        {card("Tracked Control Dimensions", PATCH["control_set"])}
        {card("Execution Assurance Controls", PATCH["execution_assurance_controls"])}
        {card("Continuous Assurance Monitors", PATCH["continuous_assurance_monitors"])}
        {card("Evidence Captured", PATCH["evidence_extension"])}
    </div>

    <div class="platform-b-agent-failure-control-pills">
        {pill_list([PATCH["operational_trust_question"]], "platform-b-agent-failure-control-pill")}
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

Path("platform_b_agent_failure_assurance_control_set_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_agent_failure_assurance_control_set_patch_v1_urls.txt").write_text(
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
print("Platform B Agent Failure Assurance Control Set Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New lifecycle: False")
print("New module: False")
print("Agent failure module created: False")
print("Placement: Execution Assurance / Continuous Assurance")
print("Operating pattern:", " -> ".join(PATCH["operating_pattern"]))
print("Lifecycle:", LIFECYCLE_SEQUENCE)
