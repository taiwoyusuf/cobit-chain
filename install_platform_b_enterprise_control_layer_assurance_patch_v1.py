from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_ENTERPRISE_CONTROL_LAYER_ASSURANCE_PATCH_V1_ACTIVE"
LOCKED_LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"

CAPABILITIES = [
    "Enterprise Control-Layer Assurance",
    "Operational Context Fabric Assurance",
    "Agent-Orchestrated Workflow Assurance",
    "Integration Boundary Assurance",
    "Control-Tower Evidence Assurance",
    "ServiceNow AI Context Readiness",
    "AI-to-Workflow Execution Assurance",
    "Cross-System Action Traceability"
]

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_stage": False,
    "new_pillar": False,
    "new_architecture": False,
    "capability_type": "Enterprise Control-Layer Assurance as cross-cutting Platform B capabilities",
    "locked_lifecycle_sequence": LOCKED_LIFECYCLE_SEQUENCE,
    "architecture_instruction": "Do not create a new module, stage, pillar, or architecture. Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust. Add Enterprise Control-Layer Assurance, Operational Context Fabric Assurance, Agent-Orchestrated Workflow Assurance, Integration Boundary Assurance, Control-Tower Evidence Assurance, ServiceNow AI Context Readiness, AI-to-Workflow Execution Assurance, and Cross-System Action Traceability as cross-cutting capabilities.",
    "cross_cutting_capabilities": CAPABILITIES,
    "discovery_extension": [
        "ServiceNow AI agents",
        "Now Assist use cases",
        "AI Agent Studio / Orchestrator configurations",
        "Workflows",
        "Flow Designer / Playbooks / Decision Builder logic",
        "CMDB relationships",
        "Knowledge Graph relationships",
        "Workflow Data Fabric sources",
        "AI Search sources",
        "Integration Hub / MID Server / API connections",
        "Human approval points",
        "Control tower telemetry sources",
        "AI asset inventory",
        "Business owner / technical owner / risk owner",
        "Affected CIs, applications, services, and systems of record"
    ],
    "visibility_extension": [
        "Enterprise control-layer map",
        "AI agent-to-workflow relationships",
        "Workflow-to-CI relationships",
        "CMDB and knowledge graph trust state",
        "Data source freshness",
        "Integration health",
        "Permission status",
        "Human oversight status",
        "Workflow execution status",
        "Control tower evidence status",
        "Missing approvals",
        "Orphan agents",
        "Stale knowledge",
        "Incomplete CMDB context",
        "Operational Trust Score"
    ],
    "governance_extension": [
        "Approved AI agent use cases",
        "Agent authority boundaries",
        "Workflow execution rules",
        "Integration approval rules",
        "CMDB/knowledge graph quality rules",
        "AI Search source governance",
        "Human oversight rules",
        "Control tower reporting rules",
        "Incident/change/problem linkage",
        "Evidence requirements for AI-assisted enterprise actions"
    ],
    "operationalization_extension": [
        "Approved agent-to-tool access",
        "Approved workflow execution paths",
        "Permission-aware retrieval",
        "CMDB relationship checks",
        "Knowledge source checks",
        "Human approval gates",
        "No unsafe write-through to systems of record",
        "Integration boundary checks",
        "Evidence capture before action",
        "ServiceNow change/incident/workflow linkage"
    ],
    "manufacturing_monitoring_extension": [
        "AI-assisted ServiceNow workflows",
        "Change records",
        "Incidents/problems",
        "CI changes",
        "Workflow failures",
        "Integration failures",
        "Control tower alerts",
        "Agent actions touching regulated systems",
        "Support group/LCM ownership gaps",
        "AI recommendations affecting GMP operations"
    ],
    "evidence_extension": [
        "Agent identity",
        "Workflow executed",
        "CI/application/service affected",
        "Data/knowledge source used",
        "Tool/API/MID/MCP call",
        "Permission check",
        "Human approval",
        "System of record boundary",
        "Incident/change/task linkage",
        "Execution result",
        "Rollback status",
        "Audit trail",
        "Operational Trust Passport state"
    ],
    "continuous_assurance_extension": [
        "Stale CMDB relationships",
        "Incomplete knowledge graph relationships",
        "Workflow drift",
        "Integration drift",
        "Missing telemetry",
        "Agent permission creep",
        "Orphan agents",
        "Unapproved tool access",
        "Missing approvals",
        "Human oversight gaps",
        "Control tower blind spots",
        "Degraded operational trust"
    ],
    "operational_trust_question": "Can this enterprise AI workflow be trusted right now across agent, data, CMDB, workflow, integration, human oversight, evidence, and system-of-record boundaries?",
    "platform_principle": "Platform B treats enterprise AI control layers as assurance-critical operating surfaces where agents, workflows, CMDB, knowledge graphs, data fabric, search, integrations, approvals, telemetry, evidence, and systems of record must remain governed, observable, contextual, traceable, and operationally trustworthy.",
    "capability_profiles": {
        "Enterprise Control-Layer Assurance": [
            "Enterprise control-layer map",
            "AI asset inventory",
            "Approved AI agent use case",
            "Agent authority boundary",
            "Affected CI/application/service/system of record",
            "Operational Trust Passport state",
            "Degraded operational trust detection"
        ],
        "Operational Context Fabric Assurance": [
            "CMDB relationships",
            "Knowledge Graph relationships",
            "Workflow Data Fabric sources",
            "AI Search sources",
            "Data source freshness",
            "Incomplete CMDB context detection",
            "Stale knowledge detection"
        ],
        "Agent-Orchestrated Workflow Assurance": [
            "ServiceNow AI agents",
            "Now Assist use cases",
            "AI Agent Studio / Orchestrator configurations",
            "AI agent-to-workflow relationship",
            "Workflow execution status",
            "Workflow drift detection",
            "Orphan agent detection"
        ],
        "Integration Boundary Assurance": [
            "Integration Hub / MID Server / API connections",
            "Tool/API/MID/MCP call",
            "Integration health",
            "Integration approval rule",
            "Integration boundary check",
            "Integration failure monitoring",
            "Integration drift detection"
        ],
        "Control-Tower Evidence Assurance": [
            "Control tower telemetry sources",
            "Control tower evidence status",
            "Control tower reporting rules",
            "Control tower alerts",
            "Missing telemetry detection",
            "Control tower blind spot detection",
            "Evidence capture before action"
        ],
        "ServiceNow AI Context Readiness": [
            "Flow Designer / Playbooks / Decision Builder logic",
            "Workflow-to-CI relationship",
            "CMDB and knowledge graph trust state",
            "ServiceNow change/incident/workflow linkage",
            "Incident/change/problem linkage",
            "Support group/LCM ownership gap",
            "Permission-aware retrieval"
        ],
        "AI-to-Workflow Execution Assurance": [
            "Approved workflow execution path",
            "Human approval gate",
            "No unsafe write-through to systems of record",
            "Workflow executed",
            "Execution result",
            "Rollback status",
            "Missing approval detection"
        ],
        "Cross-System Action Traceability": [
            "Agent identity",
            "CI/application/service affected",
            "Data/knowledge source used",
            "Permission check",
            "System of record boundary",
            "Incident/change/task linkage",
            "Audit trail"
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

    data["platform_b_enterprise_control_layer_assurance_patch"] = PATCH
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
            bp["enterprise_control_layer_assurance"] = PATCH

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

            assessment["enterprise_control_layer_assurance_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["new_stage"] = False
            assessment["new_pillar"] = False
            assessment["new_architecture"] = False
            assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            assessment["enterprise_control_layer_assurance_active"] = True
            assessment["operational_context_fabric_assurance_active"] = True
            assessment["agent_orchestrated_workflow_assurance_active"] = True
            assessment["integration_boundary_assurance_active"] = True
            assessment["control_tower_evidence_assurance_active"] = True
            assessment["servicenow_ai_context_readiness_active"] = True
            assessment["ai_to_workflow_execution_assurance_active"] = True
            assessment["cross_system_action_traceability_active"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]

            for capability in CAPABILITIES:
                key = capability_key(capability)
                assessment[f"{key}_active"] = True
                assessment[f"{key}_module_created"] = False

            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["enterprise_control_layer_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_stage"] = False
        assessment["new_pillar"] = False
        assessment["new_architecture"] = False
        assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
        assessment["enterprise_control_layer_assurance"] = PATCH

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
                "Do not create a new module, stage, pillar, or architecture for Enterprise Control-Layer Assurance.",
                "Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust.",
                "Implement enterprise control-layer, operational context fabric, agent-orchestrated workflow, integration boundary, control-tower evidence, ServiceNow AI context readiness, AI-to-workflow execution, and cross-system action traceability as cross-cutting capabilities.",
                "Continuously answer whether this enterprise AI workflow can be trusted across agent, data, CMDB, workflow, integration, human oversight, evidence, and system-of-record boundaries right now."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="enterprise-control-card">
        <div class="enterprise-control-title">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def profile_cards(profiles):
    return "\n".join([card(name, controls) for name, controls in profiles.items()])

HTML_BLOCK = f"""
<style>
.platform-b-enterprise-control-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(59,130,246,.10), rgba(245,158,11,.08));
}}
.platform-b-enterprise-control-wrap h2 {{
    margin: 0 0 12px 0;
    font-size: 28px;
}}
.platform-b-enterprise-control-wrap p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 1120px;
}}
.platform-b-enterprise-control-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
    font-weight: 800;
}}
.platform-b-enterprise-control-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-enterprise-control-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}
.enterprise-control-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.enterprise-control-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.enterprise-control-title {{
    color: #bfdbfe;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
</style>

<section class="platform-b-enterprise-control-wrap">
    <h2>Enterprise Control-Layer Assurance</h2>
    <p><strong>No new module, stage, pillar, or architecture.</strong> Platform B implements Enterprise Control-Layer Assurance, Operational Context Fabric Assurance, Agent-Orchestrated Workflow Assurance, Integration Boundary Assurance, Control-Tower Evidence Assurance, ServiceNow AI Context Readiness, AI-to-Workflow Execution Assurance, and Cross-System Action Traceability as cross-cutting capabilities inside the existing lifecycle.</p>
    <p>{html_escape(PATCH["platform_principle"])}</p>

    <div class="platform-b-enterprise-control-warning">
        Enterprise AI control layers are not trustworthy only because an agent can execute a workflow. Trust requires verified context, CMDB and knowledge graph quality, permission-aware retrieval, integration boundaries, human approval, telemetry, incident/change linkage, and evidence before action.
    </div>

    <div class="platform-b-enterprise-control-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-enterprise-control-grid">
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

Path("platform_b_enterprise_control_layer_assurance_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_enterprise_control_layer_assurance_patch_v1_urls.txt").write_text(
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
print("Platform B Enterprise Control-Layer Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("New stage: False")
print("New pillar: False")
print("New architecture: False")
print("Locked lifecycle:", LOCKED_LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
