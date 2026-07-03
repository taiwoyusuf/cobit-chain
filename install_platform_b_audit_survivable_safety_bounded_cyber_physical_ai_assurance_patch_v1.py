from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_AUDIT_SURVIVABLE_SAFETY_BOUNDED_CYBER_PHYSICAL_AI_ASSURANCE_PATCH_V1_ACTIVE"
LOCKED_LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust"

CAPABILITIES = [
    "Audit Survival Assurance",
    "Probabilistic-to-Deterministic Safety Boundary",
    "Information Assurance Graph",
    "AI-OT/ICS Cyber-Safety Assurance",
    "Assurance Boundary Architecture"
]

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_stage": False,
    "new_pillar": False,
    "new_architecture": False,
    "capability_type": "Audit-survivable, safety-bounded, cyber-physical AI assurance as cross-cutting Platform B capabilities",
    "locked_lifecycle_sequence": LOCKED_LIFECYCLE_SEQUENCE,
    "architecture_instruction": "Do not create a new module, stage, pillar, or architecture. Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust. Add Audit Survival Assurance, Probabilistic-to-Deterministic Safety Boundary, Information Assurance Graph, AI-OT/ICS Cyber-Safety Assurance, and Assurance Boundary Architecture as cross-cutting capabilities.",
    "cross_cutting_capabilities": CAPABILITIES,
    "discovery_extension": [
        "AI system / model / agent / wearable",
        "Intended use",
        "Regulatory classification",
        "Data sources",
        "Information owner",
        "System of record",
        "Applicable law/policy",
        "Human owner",
        "Deployer/integrator responsibility",
        "Authority boundary",
        "Safety-critical functions",
        "OT/ICS connection",
        "Equipment/system relationship",
        "Deterministic control requirements",
        "Audit evidence requirements"
    ],
    "visibility_extension": [
        "Audit survival score",
        "Compliance risk score",
        "Information assurance state",
        "Data provenance",
        "Ownership gaps",
        "Authority boundary map",
        "AI advisory vs execution boundary",
        "Safety-critical control boundary",
        "OT/ICS cyber exposure",
        "Human oversight status",
        "Evidence completeness",
        "Operational Trust Score"
    ],
    "governance_extension": [
        "Acceptable AI use",
        "Forbidden AI actions",
        "Audit evidence requirements",
        "Model/use-case approval criteria",
        "Human oversight requirements",
        "Information governance rules",
        "Data access rules",
        "Retention/disposal rules",
        "Deterministic safety boundary",
        "OT/ICS segmentation expectations",
        "Cyber-physical escalation rules"
    ],
    "operationalization_extension": [
        "AI Action Firewall",
        "Audit-readiness checks",
        "Data provenance checks",
        "Information access checks",
        "Human oversight gates",
        "Advisory-only mode where safety-critical action is involved",
        "Deterministic control handoff",
        "OT/ICS access restrictions",
        "Wearable stop/verify/escalate controls",
        "Safety boundary enforcement"
    ],
    "manufacturing_monitoring_extension": [
        "AI recommendations influencing manufacturing",
        "Equipment state",
        "OT/ICS signals",
        "Operator actions",
        "Cyber-physical anomalies",
        "Safety-critical boundary violations",
        "Stale information",
        "Unauthorized access",
        "Control/action mismatch",
        "Deviation-prone signals"
    ],
    "evidence_extension": [
        "Why the model/use case was selected",
        "What data was used",
        "Who owned the information",
        "What law/policy applied",
        "What AI recommended",
        "Whether AI acted or only advised",
        "What human reviewed",
        "What deterministic control accepted/rejected",
        "What safety boundary applied",
        "What system/equipment was touched",
        "What audit evidence was generated"
    ],
    "continuous_assurance_extension": [
        "Compliance drift",
        "Information governance gaps",
        "Missing audit evidence",
        "Authority boundary violations",
        "AI crossing from advisory into unsafe execution",
        "OT/ICS cyber anomalies",
        "Control degradation",
        "Evidence weakness",
        "Human oversight failure",
        "Safety boundary erosion"
    ],
    "operational_trust_question": "Can this AI system survive audit and remain trustworthy within its authority, information, safety, cyber, and evidence boundaries right now?",
    "platform_principle": "Platform B makes AI assurance audit-survivable and safety-bounded by linking information ownership, authority boundaries, deterministic safety controls, cyber-physical exposure, human oversight, and evidence integrity across the existing lifecycle.",
    "capability_profiles": {
        "Audit Survival Assurance": [
            "Audit survival score",
            "Applicable law/policy mapping",
            "Regulatory classification mapping",
            "Audit evidence requirement",
            "Model/use-case approval evidence",
            "Human oversight evidence",
            "Evidence completeness and retention check"
        ],
        "Probabilistic-to-Deterministic Safety Boundary": [
            "AI advisory vs execution boundary",
            "Safety-critical action classification",
            "Advisory-only enforcement",
            "Deterministic control handoff",
            "Control accepted/rejected evidence",
            "Unsafe execution block",
            "Safety boundary erosion detection"
        ],
        "Information Assurance Graph": [
            "Data source provenance",
            "Information owner",
            "System of record",
            "Data access rule",
            "Retention/disposal rule",
            "Ownership gap detection",
            "Information governance state"
        ],
        "AI-OT/ICS Cyber-Safety Assurance": [
            "OT/ICS connection discovery",
            "Equipment/system relationship",
            "OT/ICS segmentation expectation",
            "Cyber-physical anomaly detection",
            "Unauthorized access detection",
            "Control/action mismatch detection",
            "Cyber-physical escalation"
        ],
        "Assurance Boundary Architecture": [
            "Authority boundary map",
            "Information boundary map",
            "Safety-critical control boundary",
            "Cyber boundary",
            "Human oversight boundary",
            "Evidence boundary",
            "Operational Trust boundary state"
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

    data["platform_b_audit_survivable_safety_bounded_cyber_physical_ai_assurance_patch"] = PATCH
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
            bp["audit_survivable_safety_bounded_cyber_physical_ai_assurance"] = PATCH

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

            assessment["audit_survivable_safety_bounded_cyber_physical_ai_assurance_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["new_stage"] = False
            assessment["new_pillar"] = False
            assessment["new_architecture"] = False
            assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
            assessment["audit_survival_assurance_active"] = True
            assessment["probabilistic_to_deterministic_safety_boundary_active"] = True
            assessment["information_assurance_graph_active"] = True
            assessment["ai_ot_ics_cyber_safety_assurance_active"] = True
            assessment["assurance_boundary_architecture_active"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]

            for capability in CAPABILITIES:
                key = capability_key(capability)
                assessment[f"{key}_active"] = True
                assessment[f"{key}_module_created"] = False

            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["audit_survivable_safety_bounded_cyber_physical_ai_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_stage"] = False
        assessment["new_pillar"] = False
        assessment["new_architecture"] = False
        assessment["locked_lifecycle_sequence"] = LOCKED_LIFECYCLE_SEQUENCE
        assessment["audit_survivable_safety_bounded_cyber_physical_ai_assurance"] = PATCH

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
                "Do not create a new module, stage, pillar, or architecture for audit-survivable, safety-bounded, cyber-physical AI assurance.",
                "Keep the lifecycle locked as Discovery -> Visibility -> Governance -> Operationalization -> Manufacturing Monitoring -> Evidence -> Continuous Assurance -> Operational Trust.",
                "Implement Audit Survival Assurance, Probabilistic-to-Deterministic Safety Boundary, Information Assurance Graph, AI-OT/ICS Cyber-Safety Assurance, and Assurance Boundary Architecture as cross-cutting capabilities.",
                "Continuously answer whether the AI system can survive audit and remain trustworthy within its authority, information, safety, cyber, and evidence boundaries right now."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="audit-safety-cyber-card">
        <div class="audit-safety-cyber-title">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def profile_cards(profiles):
    return "\n".join([card(name, controls) for name, controls in profiles.items()])

HTML_BLOCK = f"""
<style>
.platform-b-audit-safety-cyber-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(168,85,247,.10), rgba(239,68,68,.08));
}}
.platform-b-audit-safety-cyber-wrap h2 {{
    margin: 0 0 12px 0;
    font-size: 28px;
}}
.platform-b-audit-safety-cyber-wrap p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 1120px;
}}
.platform-b-audit-safety-cyber-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
    font-weight: 800;
}}
.platform-b-audit-safety-cyber-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(14,165,233,.10);
    border: 1px solid rgba(125,211,252,.22);
    color: #e0f2fe;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-audit-safety-cyber-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}
.audit-safety-cyber-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.audit-safety-cyber-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.audit-safety-cyber-title {{
    color: #ddd6fe;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
</style>

<section class="platform-b-audit-safety-cyber-wrap">
    <h2>Audit-Survivable, Safety-Bounded, Cyber-Physical AI Assurance</h2>
    <p><strong>No new module, stage, pillar, or architecture.</strong> Platform B implements Audit Survival Assurance, Probabilistic-to-Deterministic Safety Boundary, Information Assurance Graph, AI-OT/ICS Cyber-Safety Assurance, and Assurance Boundary Architecture as cross-cutting capabilities inside the existing lifecycle.</p>
    <p>{html_escape(PATCH["platform_principle"])}</p>

    <div class="platform-b-audit-safety-cyber-warning">
        These capabilities protect the boundary between probabilistic AI recommendation and deterministic safety-critical control. They also make AI operations audit-survivable, information-governed, cyber-physical aware, and evidence-complete.
    </div>

    <div class="platform-b-audit-safety-cyber-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    <div class="platform-b-audit-safety-cyber-grid">
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

Path("platform_b_audit_survivable_safety_bounded_cyber_physical_ai_assurance_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_audit_survivable_safety_bounded_cyber_physical_ai_assurance_patch_v1_urls.txt").write_text(
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
print("Platform B Audit-Survivable, Safety-Bounded, Cyber-Physical AI Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("New stage: False")
print("New pillar: False")
print("New architecture: False")
print("Locked lifecycle:", LOCKED_LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
