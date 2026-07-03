from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_RUNTIME_AUTHORITY_REACHABLE_CONSEQUENCE_ASSURANCE_PATCH_V1_ACTIVE"
LOCKED_LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"

CAPABILITIES = [
    "Runtime Authority Assurance",
    "Reachable Consequence Assurance",
    "Live Scope Revalidation",
    "Action Admissibility Record",
    "Recovery Feasibility Assurance",
    "Physical State Evidence Assurance",
    "Cross-Framework Incident Taxonomy Assurance",
    "Regulatory Timeline Precision Assurance",
    "Action-Proof AI Security",
    "OT/ICS AI Boundary Assurance"
]

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_stage": False,
    "new_pillar": False,
    "new_architecture": False,
    "freeze_platform_b_after_this_patch": True,
    "platform_b_v1_freeze_candidate": True,
    "capability_type": "Runtime Authority and Reachable Consequence Assurance as cross-cutting Platform B capabilities",
    "locked_lifecycle_sequence": LOCKED_LIFECYCLE_SEQUENCE,
    "architecture_instruction": "Do not create a new module, stage, pillar, or architecture. Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust. Add Runtime Authority Assurance, Reachable Consequence Assurance, Live Scope Revalidation, Action Admissibility Record, Recovery Feasibility Assurance, Physical State Evidence Assurance, Cross-Framework Incident Taxonomy Assurance, Regulatory Timeline Precision Assurance, Action-Proof AI Security, and OT/ICS AI Boundary Assurance as cross-cutting capabilities.",
    "cross_cutting_capabilities": CAPABILITIES,
    "discovery_extension": [
        "AI agent / workflow / assistant",
        "Identity used",
        "Tool/API/MCP/A2A access",
        "Data sources",
        "Memory state",
        "Delegation path",
        "Approval state",
        "Reachable action classes",
        "Highest-impact reachable action",
        "Rollback/restore/compensation path",
        "OT/ICS or physical-system dependency",
        "Historian/controller/actuator/safety-system evidence sources",
        "AI Act/NIS2/DORA/privacy/GxP obligations",
        "Applicable deadline and reporting requirement"
    ],
    "visibility_extension": [
        "Live authority state",
        "Effective scope object",
        "Current data lineage",
        "Current tool scope",
        "Approval state",
        "Highest-impact reachable consequence",
        "Action admissibility status",
        "Recovery feasibility status",
        "OT/physical impact status",
        "Incident taxonomy mapping",
        "Regulatory deadline status",
        "Operational Trust Score"
    ],
    "governance_extension": [
        "Action classes",
        "Material transition thresholds",
        "Permitted and prohibited actions",
        "Pre-action authorization rules",
        "Live scope invalidation rules",
        "Data-lineage escalation rules",
        "Approval requirements by risk tier",
        "Recovery requirements",
        "OT/ICS advisory-only boundaries",
        "Physical actuation restrictions",
        "Cross-framework incident taxonomy",
        "Regulatory timeline rules"
    ],
    "operationalization_extension": [
        "Policy check before material action",
        "Identity check before tool use",
        "Scope revalidation when new data enters decision path",
        "Fresh authorization when reachable consequence increases",
        "Human approval for high-impact transitions",
        "Block action if recovery path is unavailable",
        "Advisory-only mode for unsafe OT/physical actions",
        "Evidence capture before execution",
        "Incident classification across AI/cyber/GxP frameworks"
    ],
    "manufacturing_monitoring_extension": [
        "Agent actions touching regulated workflows",
        "Tool calls",
        "Data reads that seed later writes",
        "Scope expansion",
        "Authority creep",
        "Approval bypass",
        "Physical system impact",
        "Controller/actuator/historian/safety-system signals",
        "Rollback or compensation success",
        "Incident classification and reporting status"
    ],
    "evidence_extension": [
        "Agent identity",
        "Proposed action",
        "Current scope",
        "Data lineage",
        "Tool/API/MCP call",
        "Risk class",
        "Highest-impact reachable consequence",
        "Policy decision",
        "Approval state",
        "Human review",
        "Recovery feasibility",
        "Action admissibility record",
        "Physical state before/after",
        "Incident taxonomy",
        "Regulatory obligation and deadline"
    ],
    "continuous_assurance_extension": [
        "Static approval being used after scope changed",
        "Authority creep",
        "Newly reachable high-impact actions",
        "Data lineage changes",
        "Tool misuse",
        "Approval state mismatch",
        "Missing action admissibility record",
        "Missing recovery path",
        "OT/ICS boundary violation",
        "Physical-state evidence gap",
        "Incident taxonomy mismatch",
        "Regulatory timeline drift",
        "Operational trust decline"
    ],
    "operational_trust_question": "Was this AI action allowed, recoverable, evidenced, and bounded under the current live state before it executed?",
    "platform_principle": "Platform B treats AI authorization as a live-state control, not a static approval. An AI action is trustworthy only when its identity, tools, data lineage, scope, reachable consequences, recovery path, physical-system boundary, incident taxonomy, and regulatory timeline are current and evidenced before execution.",
    "freeze_statement": "After this patch is committed and pushed, Platform B v1 should be frozen for packaging, release summary, screenshots, Azure verification, PhD/AEBOK write-up, and funding/demo positioning.",
    "capability_profiles": {
        "Runtime Authority Assurance": [
            "Live authority state",
            "Identity used",
            "Tool/API/MCP/A2A access",
            "Current tool scope",
            "Approval state",
            "Pre-action authorization rules",
            "Identity check before tool use"
        ],
        "Reachable Consequence Assurance": [
            "Reachable action classes",
            "Highest-impact reachable action",
            "Highest-impact reachable consequence",
            "Fresh authorization when reachable consequence increases",
            "Newly reachable high-impact actions",
            "Material transition thresholds"
        ],
        "Live Scope Revalidation": [
            "Effective scope object",
            "Current data lineage",
            "Scope expansion",
            "Scope revalidation when new data enters decision path",
            "Live scope invalidation rules",
            "Static approval being used after scope changed"
        ],
        "Action Admissibility Record": [
            "Proposed action",
            "Risk class",
            "Policy decision",
            "Action admissibility status",
            "Action admissibility record",
            "Missing action admissibility record",
            "Evidence capture before execution"
        ],
        "Recovery Feasibility Assurance": [
            "Rollback/restore/compensation path",
            "Recovery requirements",
            "Recovery feasibility status",
            "Recovery feasibility",
            "Rollback or compensation success",
            "Block action if recovery path is unavailable",
            "Missing recovery path"
        ],
        "Physical State Evidence Assurance": [
            "Physical state before/after",
            "OT/physical impact status",
            "Physical system impact",
            "Historian/controller/actuator/safety-system evidence sources",
            "Controller/actuator/historian/safety-system signals",
            "Physical-state evidence gap"
        ],
        "Cross-Framework Incident Taxonomy Assurance": [
            "AI Act/NIS2/DORA/privacy/GxP obligations",
            "Cross-framework incident taxonomy",
            "Incident taxonomy mapping",
            "Incident classification across AI/cyber/GxP frameworks",
            "Incident taxonomy",
            "Incident taxonomy mismatch"
        ],
        "Regulatory Timeline Precision Assurance": [
            "Applicable deadline and reporting requirement",
            "Regulatory timeline rules",
            "Regulatory deadline status",
            "Regulatory obligation and deadline",
            "Incident classification and reporting status",
            "Regulatory timeline drift"
        ],
        "Action-Proof AI Security": [
            "Tool misuse",
            "Authority creep",
            "Approval bypass",
            "Permitted and prohibited actions",
            "Policy check before material action",
            "Approval state mismatch",
            "Human approval for high-impact transitions"
        ],
        "OT/ICS AI Boundary Assurance": [
            "OT/ICS or physical-system dependency",
            "OT/ICS advisory-only boundaries",
            "Physical actuation restrictions",
            "Advisory-only mode for unsafe OT/physical actions",
            "OT/ICS boundary violation",
            "OT/physical impact status"
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

    data["platform_b_runtime_authority_reachable_consequence_assurance_patch"] = PATCH
    data["platform_b_architecture_change"] = False
    data["platform_b_new_module"] = False
    data["platform_b_new_stage"] = False
    data["platform_b_new_pillar"] = False
    data["platform_b_new_architecture"] = False
    data["platform_b_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
    data["platform_b_v1_freeze_candidate_after_runtime_authority_patch"] = True

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
            bp["runtime_authority_reachable_consequence_assurance"] = PATCH
            bp["platform_b_v1_freeze_candidate_after_this_patch"] = True

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
                [PATCH["operational_trust_question"], PATCH["platform_principle"], PATCH["freeze_statement"]] + CAPABILITIES
            )

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [PATCH["operational_trust_question"]]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["runtime_authority_reachable_consequence_assurance_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["new_stage"] = False
            assessment["new_pillar"] = False
            assessment["new_architecture"] = False
            assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            assessment["platform_b_v1_freeze_candidate_after_this_patch"] = True
            assessment["runtime_authority_assurance_active"] = True
            assessment["reachable_consequence_assurance_active"] = True
            assessment["live_scope_revalidation_active"] = True
            assessment["action_admissibility_record_active"] = True
            assessment["recovery_feasibility_assurance_active"] = True
            assessment["physical_state_evidence_assurance_active"] = True
            assessment["cross_framework_incident_taxonomy_assurance_active"] = True
            assessment["regulatory_timeline_precision_assurance_active"] = True
            assessment["action_proof_ai_security_active"] = True
            assessment["ot_ics_ai_boundary_assurance_active"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]

            for capability in CAPABILITIES:
                key = capability_key(capability)
                assessment[f"{key}_active"] = True
                assessment[f"{key}_module_created"] = False

            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["runtime_authority_reachable_consequence_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_stage"] = False
        assessment["new_pillar"] = False
        assessment["new_architecture"] = False
        assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
        assessment["runtime_authority_reachable_consequence_assurance"] = PATCH
        assessment["platform_b_v1_freeze_candidate_after_this_patch"] = True

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
                "Do not create a new module, stage, pillar, or architecture for Runtime Authority and Reachable Consequence Assurance.",
                "Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust.",
                "Implement runtime authority, reachable consequence, live scope revalidation, action admissibility, recovery feasibility, physical-state evidence, cross-framework incident taxonomy, regulatory timeline precision, action-proof AI security, and OT/ICS boundary assurance as cross-cutting capabilities.",
                "Continuously answer whether this AI action was allowed, recoverable, evidenced, and bounded under the current live state before execution.",
                "Freeze Platform B v1 after this patch is committed and pushed."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="runtime-authority-card">
        <div class="runtime-authority-title">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def profile_cards(profiles):
    return "\n".join([card(name, controls) for name, controls in profiles.items()])

HTML_BLOCK = f"""
<style>
.platform-b-runtime-authority-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(168,85,247,.12), rgba(14,165,233,.08));
}}
.platform-b-runtime-authority-wrap h2 {{
    margin: 0 0 12px 0;
    font-size: 28px;
}}
.platform-b-runtime-authority-wrap p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 1120px;
}}
.platform-b-runtime-authority-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(168,85,247,.12);
    border: 1px solid rgba(216,180,254,.24);
    color: #f3e8ff;
    line-height: 1.55;
    font-weight: 800;
}}
.platform-b-runtime-authority-freeze {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(34,197,94,.10);
    border: 1px solid rgba(134,239,172,.24);
    color: #dcfce7;
    line-height: 1.55;
    font-weight: 800;
}}
.platform-b-runtime-authority-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-runtime-authority-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}
.runtime-authority-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.runtime-authority-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.runtime-authority-title {{
    color: #ddd6fe;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
</style>

<section class="platform-b-runtime-authority-wrap">
    <h2>Runtime Authority and Reachable Consequence Assurance</h2>
    <p><strong>No new module, stage, pillar, or architecture.</strong> Platform B implements Runtime Authority Assurance, Reachable Consequence Assurance, Live Scope Revalidation, Action Admissibility Record, Recovery Feasibility Assurance, Physical State Evidence Assurance, Cross-Framework Incident Taxonomy Assurance, Regulatory Timeline Precision Assurance, Action-Proof AI Security, and OT/ICS AI Boundary Assurance as cross-cutting capabilities inside the existing lifecycle.</p>
    <p>{html_escape(PATCH["platform_principle"])}</p>

    <div class="platform-b-runtime-authority-warning">
        Static approval is not enough. Platform B must know the live authority state, current scope, reachable consequence, recovery path, physical boundary, and regulatory deadline before an AI action executes.
    </div>

    <div class="platform-b-runtime-authority-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-runtime-authority-freeze">
        Freeze instruction: {html_escape(PATCH["freeze_statement"])}
    </div>

    <div class="platform-b-runtime-authority-grid">
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
        "<!-- COBITCHAIN_PLATFORM_B_HUMAN_OVERSIGHT_EFFECTIVENESS_ASSURANCE_PATCH_V1_ACTIVE -->",
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

Path("platform_b_runtime_authority_reachable_consequence_assurance_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_runtime_authority_reachable_consequence_assurance_patch_v1_urls.txt").write_text(
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
print("Platform B Runtime Authority and Reachable Consequence Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("New stage: False")
print("New pillar: False")
print("New architecture: False")
print("Freeze Platform B after this patch: True")
print("Locked lifecycle:", LOCKED_LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
