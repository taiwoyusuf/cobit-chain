from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_ENTERPRISE_AI_ADOPTION_AGENT_OPERATIONAL_TRUST_PATCH_V1_ACTIVE"
LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "agent_failure_module_created": False,
    "adoption_module_created": False,
    "capability_name": "Enterprise AI Adoption and Agent Operational Trust Lifecycle Extension",
    "primary_stages": [
        "Operationalization",
        "Operational Trust"
    ],
    "architecture_instruction": "Do not create another module. Extend each lifecycle stage so enterprise AI adoption, pilot-to-production transition, master protocol governance, business value assurance, agent failure prevention, and Agent Operational Trust Score operate inside the existing Platform B Assurance Lifecycle.",
    "lifecycle_sequence": LIFECYCLE_SEQUENCE,

    "enterprise_ai_adoption": {
        "discovery_extension": [
            "Master Protocol Discovery",
            "AI Strategy Discovery",
            "Business Objective Discovery",
            "AI Pilot Discovery",
            "Use Case Readiness",
            "Documentation Readiness"
        ],
        "visibility_extension": [
            "AI Adoption Dashboard",
            "AI Pilot Status",
            "AI Value Dashboard",
            "AI Review Workload",
            "Quality Unit Capacity",
            "Master Protocol Dashboard"
        ],
        "governance_extension": [
            "Master Protocol Governance",
            "AI Approval Authority",
            "AI Documentation Governance",
            "Human Review Governance",
            "AI Strategy Governance"
        ],
        "operationalization_extension": [
            "Pilot to Production",
            "User Adoption",
            "Business KPIs",
            "AI Scaling",
            "ServiceNow AI Rollout",
            "Knowledge Readiness",
            "Trusted Data Readiness",
            "Workflow Integration"
        ],
        "evidence_extension": [
            "Human Review Evidence",
            "AI Strategy Evidence",
            "Adoption Evidence",
            "KPI Evidence",
            "Business Value Evidence",
            "Master Protocol Evidence"
        ],
        "continuous_assurance_extension": [
            "Adoption Drift",
            "Review Fatigue",
            "Quality Drift",
            "AI Documentation Quality",
            "Pilot Success",
            "Production Readiness",
            "Continuous Business Value"
        ]
    },

    "agent_operational_trust": {
        "discovery_extension": [
            "Agent type",
            "Agent autonomy level",
            "Tool permissions",
            "Memory architecture",
            "Human approval requirements",
            "Multi-agent topology",
            "Failure risks",
            "Runtime dependencies"
        ],
        "visibility_extension": [
            "Agent Failure Risk",
            "Prompt injection exposure",
            "Hallucination likelihood",
            "Tool overreach",
            "Memory contamination",
            "Context drift",
            "Unauthorized access",
            "Loop detection",
            "Auditability score",
            "Human oversight coverage"
        ],
        "governance_extension": [
            "Agent Failure Governance",
            "Prompt safety",
            "Goal validation",
            "Memory governance",
            "Agent coordination",
            "Tool authorization",
            "Stopping conditions",
            "Escalation policies",
            "Recovery policies"
        ],
        "operationalization_prevention_layer": [
            "Goal misinterpretation prevention",
            "Prompt injection prevention",
            "Context drift prevention",
            "Tool abuse prevention",
            "Memory poisoning prevention",
            "Infinite loop prevention",
            "Unauthorized retrieval prevention",
            "Agent conflict prevention",
            "Missing approval prevention",
            "Silent degradation prevention",
            "Missing audit log prevention"
        ],
        "evidence_extension": [
            "Goal validated",
            "Prompt filtered",
            "Context refreshed",
            "Tool authorization verified",
            "Memory checked",
            "Human approval completed",
            "Loop interrupted",
            "Conflict resolved",
            "Audit generated",
            "Recovery executed"
        ],
        "continuous_assurance_extension": [
            "Prompt attacks",
            "Context drift",
            "Memory drift",
            "Agent conflicts",
            "Performance degradation",
            "Tool misuse",
            "Access violations",
            "Approval bypass",
            "Audit completeness"
        ],
        "operational_trust_question": "Can the enterprise trust this agent continuously?",
        "not_the_primary_question": "Is the agent working?",
        "agent_operational_trust_score": [
            "Goal Integrity",
            "Prompt Integrity",
            "Context Integrity",
            "Memory Integrity",
            "Tool Integrity",
            "Identity Integrity",
            "Human Oversight",
            "Audit Completeness",
            "Runtime Stability",
            "Recovery Capability"
        ]
    },

    "operational_trust_questions": [
        "Is the AI pilot ready to move into production?",
        "Are users adopting the AI workflow as intended?",
        "Are business KPIs improving or deteriorating?",
        "Is the AI rollout supported by ServiceNow, knowledge readiness, trusted data, and workflow integration?",
        "Is the Quality Unit overloaded by AI review demand?",
        "Is business value continuously demonstrated after deployment?",
        "What agent type is operating?",
        "What is the agent autonomy level?",
        "What tools can the agent use?",
        "What memory architecture supports the agent?",
        "What human approvals are required?",
        "What multi-agent topology is active?",
        "What runtime dependencies exist?",
        "Was the goal validated?",
        "Was the prompt filtered?",
        "Was context refreshed?",
        "Was tool authorization verified?",
        "Was memory checked?",
        "Was human approval completed?",
        "Was a loop interrupted?",
        "Was an agent conflict resolved?",
        "Was an audit generated?",
        "Was recovery executed?",
        "Can the enterprise trust this agent continuously?"
    ],

    "platform_statement": "Platform B does not treat enterprise AI adoption as a launch event or agent assurance as a simple uptime check. Platform B extends the existing lifecycle so strategy, pilots, master protocols, business objectives, user adoption, ServiceNow AI rollout, Quality Unit capacity, workflow integration, agent failure governance, runtime prevention, evidence capture, continuous monitoring, and Agent Operational Trust Score are continuously assured.",
    "principle": "Enterprise AI is not operationally trusted because a pilot launched or an agent appears to work. It is operationally trusted when adoption, governance, workflow integration, human oversight, runtime prevention, evidence, business value, recovery, and agent trust remain continuously demonstrated."
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

def flat(name):
    return PATCH[name]

def patch_seed(path):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path}")
        return

    data = load_json(path)
    if not isinstance(data, dict):
        print(f"SKIP: {path} is not JSON object")
        return

    adoption = PATCH["enterprise_ai_adoption"]
    agent = PATCH["agent_operational_trust"]

    data["platform_b_enterprise_ai_adoption_agent_operational_trust_patch"] = PATCH
    data["platform_b_architecture_change"] = False
    data["platform_b_new_module"] = False
    data["platform_b_agent_failure_module_created"] = False
    data["platform_b_adoption_module_created"] = False
    data["platform_b_lifecycle_sequence"] = LIFECYCLE_SEQUENCE

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["new_module"] = False
            bp["agent_failure_module_created"] = False
            bp["adoption_module_created"] = False
            bp["enterprise_ai_adoption_agent_operational_trust"] = PATCH

            bp["discovery_scope"] = add_unique(
                bp.get("discovery_scope", []),
                adoption["discovery_extension"] + agent["discovery_extension"]
            )

            bp["visibility_scope"] = add_unique(
                bp.get("visibility_scope", []),
                adoption["visibility_extension"] + agent["visibility_extension"]
            )

            bp["governance_scope"] = add_unique(
                bp.get("governance_scope", []),
                adoption["governance_extension"] + agent["governance_extension"]
            )

            bp["operationalization_scope"] = add_unique(
                bp.get("operationalization_scope", []),
                adoption["operationalization_extension"] + agent["operationalization_prevention_layer"]
            )

            bp["evidence_assurance"] = add_unique(
                bp.get("evidence_assurance", []),
                adoption["evidence_extension"] + agent["evidence_extension"]
            )

            bp["continuous_assurance"] = add_unique(
                bp.get("continuous_assurance", []),
                adoption["continuous_assurance_extension"] + agent["continuous_assurance_extension"]
            )

            bp["operational_trust_scope"] = add_unique(
                bp.get("operational_trust_scope", []),
                [agent["operational_trust_question"], "Agent Operational Trust Score"] + agent["agent_operational_trust_score"]
            )

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                PATCH["operational_trust_questions"]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["enterprise_ai_adoption_agent_operational_trust_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["agent_failure_module_created"] = False
            assessment["adoption_module_created"] = False

            assessment["master_protocol_discovery_enabled"] = True
            assessment["ai_strategy_discovery_enabled"] = True
            assessment["ai_adoption_dashboard_enabled"] = True
            assessment["quality_unit_capacity_visible"] = True
            assessment["master_protocol_governance_enabled"] = True
            assessment["ai_approval_authority_governed"] = True
            assessment["pilot_to_production_operationalized"] = True
            assessment["servicenow_ai_rollout_operationalized"] = True
            assessment["business_value_evidence_required"] = True
            assessment["continuous_business_value_monitored"] = True

            assessment["agent_failure_governance_enabled"] = True
            assessment["agent_failure_risk_dashboard_enabled"] = True
            assessment["goal_integrity_scored"] = True
            assessment["prompt_integrity_scored"] = True
            assessment["context_integrity_scored"] = True
            assessment["memory_integrity_scored"] = True
            assessment["tool_integrity_scored"] = True
            assessment["identity_integrity_scored"] = True
            assessment["human_oversight_scored"] = True
            assessment["audit_completeness_scored"] = True
            assessment["runtime_stability_scored"] = True
            assessment["recovery_capability_scored"] = True
            assessment["agent_operational_trust_question"] = agent["operational_trust_question"]

            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        adoption = PATCH["enterprise_ai_adoption"]
        agent = PATCH["agent_operational_trust"]

        assessment["enterprise_ai_adoption_agent_operational_trust_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["agent_failure_module_created"] = False
        assessment["adoption_module_created"] = False
        assessment["enterprise_ai_adoption_agent_operational_trust"] = PATCH

        assessment["operationalization_targets"] = add_unique(
            assessment.get("operationalization_targets", []),
            adoption["operationalization_extension"] + agent["operationalization_prevention_layer"]
        )

        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            adoption["evidence_extension"] + agent["evidence_extension"] + PATCH["operational_trust_questions"]
        )

        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            adoption["continuous_assurance_extension"] + agent["continuous_assurance_extension"]
        )

        assessment["operational_trust_score_dimensions"] = add_unique(
            assessment.get("operational_trust_score_dimensions", []),
            agent["agent_operational_trust_score"]
        )

        assessment["implementation_priority"] = add_unique(
            assessment.get("implementation_priority", []),
            [
                "Extend Discovery with master protocol, AI strategy, business objective, AI pilot, use case readiness, documentation readiness, agent type, autonomy level, tool permissions, memory architecture, approval requirements, topology, failure risks, and runtime dependencies.",
                "Extend Visibility with AI adoption, pilot, value, review workload, Quality Unit capacity, master protocol, and Agent Failure Risk dashboards.",
                "Extend Governance with master protocol governance, AI approval authority, documentation governance, human review governance, AI strategy governance, and Agent Failure Governance.",
                "Strengthen Operationalization with pilot-to-production, user adoption, business KPIs, AI scaling, ServiceNow AI rollout, knowledge readiness, trusted data readiness, workflow integration, and runtime prevention controls.",
                "Capture human review, AI strategy, adoption, KPI, business value, master protocol, goal validation, prompt filtering, context refresh, tool authorization, memory check, approval, loop interruption, conflict resolution, audit, and recovery evidence.",
                "Continuously monitor adoption drift, review fatigue, quality drift, documentation quality, pilot success, production readiness, continuous business value, prompt attacks, context drift, memory drift, conflicts, degradation, tool misuse, access violations, approval bypass, and audit completeness.",
                "Add Agent Operational Trust Score inside Operational Trust using goal, prompt, context, memory, tool, identity, human oversight, audit completeness, runtime stability, and recovery dimensions."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="enterprise-agent-trust-card">
        <div class="enterprise-agent-trust-domain">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def pill_list(items, cls):
    return "".join([f'<span class="{cls}">{html_escape(x)}</span>' for x in items])

adoption = PATCH["enterprise_ai_adoption"]
agent = PATCH["agent_operational_trust"]

HTML_BLOCK = f"""
<style>
.platform-b-enterprise-agent-trust-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(168,85,247,.10), rgba(14,165,233,.08));
}}
.platform-b-enterprise-agent-trust-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 18px;
}}
.platform-b-enterprise-agent-trust-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-enterprise-agent-trust-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 980px;
}}
.platform-b-enterprise-agent-trust-tag {{
    border: 1px solid rgba(216,180,254,.45);
    color: #e9d5ff;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(168,85,247,.10);
}}
.platform-b-enterprise-agent-trust-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
}}
.platform-b-enterprise-agent-trust-principle {{
    margin: 18px 0;
    padding: 18px;
    border-left: 4px solid #d8b4fe;
    color: #f5f3ff;
    background: rgba(255,255,255,.055);
    border-radius: 16px;
    line-height: 1.65;
    font-size: 17px;
    font-weight: 800;
}}
.platform-b-enterprise-agent-trust-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-enterprise-agent-trust-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
}}
.enterprise-agent-trust-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.enterprise-agent-trust-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.enterprise-agent-trust-domain {{
    color: #e9d5ff;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
.platform-b-enterprise-agent-trust-pills {{
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
}}
.platform-b-enterprise-agent-trust-pill {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 8px 12px;
    color: #d8dee9;
    font-size: 13px;
}}
</style>

<section class="platform-b-enterprise-agent-trust-wrap">
    <div class="platform-b-enterprise-agent-trust-head">
        <div>
            <h2>Enterprise AI Adoption and Agent Operational Trust</h2>
            <p>
                No new module. Platform B extends the existing lifecycle so enterprise AI adoption,
                master protocol governance, pilot-to-production, ServiceNow AI rollout, business value evidence,
                agent failure governance, runtime prevention, and Agent Operational Trust Score are continuously assured.
            </p>
        </div>
        <span class="platform-b-enterprise-agent-trust-tag">Lifecycle Extension</span>
    </div>

    <div class="platform-b-enterprise-agent-trust-warning">
        Do not create separate adoption, pilot, master protocol, business value, agent failure, or agent assurance modules.
        These controls extend existing Discovery, Visibility, Governance, Operationalization, Evidence, Continuous Assurance,
        and Operational Trust.
    </div>

    <div class="platform-b-enterprise-agent-trust-question">
        Operational Trust asks: {html_escape(agent["operational_trust_question"])}
    </div>

    <div class="platform-b-enterprise-agent-trust-principle">
        {html_escape(PATCH["principle"])}
    </div>

    <div class="platform-b-enterprise-agent-trust-grid">
        {card("Enterprise Discovery", adoption["discovery_extension"])}
        {card("Enterprise Visibility", adoption["visibility_extension"])}
        {card("Enterprise Governance", adoption["governance_extension"])}
        {card("Enterprise Operationalization", adoption["operationalization_extension"])}
        {card("Enterprise Evidence", adoption["evidence_extension"])}
        {card("Enterprise Continuous Assurance", adoption["continuous_assurance_extension"])}
        {card("Agent Discovery", agent["discovery_extension"])}
        {card("Agent Failure Risk Visibility", agent["visibility_extension"])}
        {card("Agent Failure Governance", agent["governance_extension"])}
        {card("Runtime Prevention Layer", agent["operationalization_prevention_layer"])}
        {card("Agent Evidence", agent["evidence_extension"])}
        {card("Agent Continuous Assurance", agent["continuous_assurance_extension"])}
        {card("Agent Operational Trust Score", agent["agent_operational_trust_score"])}
    </div>

    <div class="platform-b-enterprise-agent-trust-pills">
        {pill_list(PATCH["operational_trust_questions"], "platform-b-enterprise-agent-trust-pill")}
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

Path("platform_b_enterprise_ai_adoption_agent_operational_trust_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_enterprise_ai_adoption_agent_operational_trust_patch_v1_urls.txt").write_text(
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
print("Platform B Enterprise AI Adoption and Agent Operational Trust Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("Agent failure module created: False")
print("Adoption module created: False")
print("Primary stages: Operationalization, Operational Trust")
print("Lifecycle:", LIFECYCLE_SEQUENCE)
print("Agent Operational Trust question:", PATCH["agent_operational_trust"]["operational_trust_question"])
