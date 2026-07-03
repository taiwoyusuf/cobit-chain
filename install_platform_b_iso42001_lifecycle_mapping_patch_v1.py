from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_ISO42001_LIFECYCLE_MAPPING_PATCH_V1_ACTIVE"
LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "do_not_create": [
        "ISO 42001 module",
        "ISO/IEC 42001 module",
        "AI management system module",
        "Framework-specific module"
    ],
    "capability_name": "ISO 42001 Lifecycle Mapping",
    "primary_stage": "Governance",
    "architecture_instruction": "Do not build an ISO 42001 module. Map each ISO 42001 pillar into the existing Platform B Assurance Lifecycle and strengthen existing Discovery, Visibility, Governance, Evidence, Continuous Assurance, and Operational Trust capabilities.",
    "lifecycle_sequence": LIFECYCLE_SEQUENCE,
    "governance_statement": "AI governance is not a document you file once. It is a system you run continuously.",
    "assurance_engineering_statement": "Assurance Engineering continuously generates evidence that the AI management system remains effective throughout AI operation.",
    "operational_trust_question": "Does this AI system continue to operate in accordance with its governance?",
    "not_the_question": "Was governance implemented?",
    "iso42001_pillar_mapping": [
        {"iso_42001_pillar": "AI Policy", "existing_assurance_lifecycle": "Governance"},
        {"iso_42001_pillar": "Ownership Map", "existing_assurance_lifecycle": "Governance"},
        {"iso_42001_pillar": "Management Review", "existing_assurance_lifecycle": "Governance"},
        {"iso_42001_pillar": "AI Inventory", "existing_assurance_lifecycle": "Discovery"},
        {"iso_42001_pillar": "Risk Classification", "existing_assurance_lifecycle": "Governance"},
        {"iso_42001_pillar": "Impact Assessment", "existing_assurance_lifecycle": "Governance"},
        {"iso_42001_pillar": "AI Passport", "existing_assurance_lifecycle": "Visibility"},
        {"iso_42001_pillar": "Decision Traceability", "existing_assurance_lifecycle": "Evidence"},
        {"iso_42001_pillar": "Disclosure", "existing_assurance_lifecycle": "Governance / Evidence"},
        {"iso_42001_pillar": "Incident Register", "existing_assurance_lifecycle": "Operationalization"},
        {"iso_42001_pillar": "Monitoring Protocol", "existing_assurance_lifecycle": "Continuous Assurance"},
        {"iso_42001_pillar": "Corrective Actions", "existing_assurance_lifecycle": "Continuous Assurance"},
        {"iso_42001_pillar": "Regulation Mapping", "existing_assurance_lifecycle": "Governance"},
        {"iso_42001_pillar": "Audit Schedule", "existing_assurance_lifecycle": "Continuous Assurance"},
        {"iso_42001_pillar": "Improvement Cycle", "existing_assurance_lifecycle": "Continuous Assurance"}
    ],
    "discovery_extension": [
        "AI inventory",
        "AI assets",
        "AI owners",
        "AI systems",
        "AI business purpose",
        "Context of use"
    ],
    "visibility_ai_passport_extension": [
        "Risk classification",
        "Intended use",
        "Governance owner",
        "Deployment status",
        "Model version",
        "Human approver",
        "Supporting evidence"
    ],
    "governance_frameworks_mapped_into_one_layer": [
        "ISO 42001",
        "NIST AI RMF",
        "EU AI Act",
        "FDA CSA",
        "MHRA guidance"
    ],
    "evidence_extension": [
        "Decision traceability",
        "Human review",
        "Evidence lineage",
        "Scientific verification",
        "Approval history"
    ],
    "continuous_assurance_extension": [
        "Monitoring effectiveness",
        "Incident management",
        "CAPAs",
        "Governance reviews",
        "Policy effectiveness",
        "Operational performance",
        "Drift",
        "Evidence completeness"
    ],
    "evidence_questions": [
        "Which AI systems are in the AI inventory?",
        "Which AI assets support the system?",
        "Who owns the AI system?",
        "What is the AI business purpose?",
        "What is the context of use?",
        "What is the risk classification?",
        "What is the intended use?",
        "Who is the governance owner?",
        "What is the deployment status?",
        "Which model version is operating?",
        "Who approved deployment or use?",
        "What supporting evidence exists?",
        "How are AI decisions traceable?",
        "Was human review performed?",
        "Is evidence lineage complete?",
        "Was scientific verification performed?",
        "What approval history exists?",
        "Are incidents captured and managed?",
        "Are CAPAs tracked and verified?",
        "Are governance reviews current?",
        "Is policy effectiveness being evaluated?",
        "Is operational performance being monitored?",
        "Is drift being monitored?",
        "Is evidence complete?",
        "Does this AI system continue to operate in accordance with its governance?"
    ],
    "principle": "AI governance is not a document you file once. It is a system you run continuously. Assurance Engineering continuously generates evidence that the AI management system remains effective throughout AI operation."
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

    data["platform_b_iso42001_lifecycle_mapping_patch"] = PATCH
    data["platform_b_architecture_change"] = False
    data["platform_b_new_module"] = False
    data["platform_b_iso42001_module_created"] = False
    data["platform_b_lifecycle_sequence"] = LIFECYCLE_SEQUENCE
    data["platform_b_governance_operating_statement"] = PATCH["governance_statement"]
    data["platform_b_assurance_engineering_statement"] = PATCH["assurance_engineering_statement"]
    data["platform_b_operational_trust_question"] = PATCH["operational_trust_question"]

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["new_module"] = False
            bp["iso42001_module_created"] = False
            bp["iso42001_lifecycle_mapping"] = PATCH

            bp["discovery_scope"] = add_unique(
                bp.get("discovery_scope", []),
                PATCH["discovery_extension"]
            )

            bp["visibility_scope"] = add_unique(
                bp.get("visibility_scope", []),
                PATCH["visibility_ai_passport_extension"]
            )

            bp["governance_frameworks"] = add_unique(
                bp.get("governance_frameworks", []),
                PATCH["governance_frameworks_mapped_into_one_layer"]
            )

            bp["governance_scope"] = add_unique(
                bp.get("governance_scope", []),
                [
                    "AI Policy",
                    "Ownership Map",
                    "Management Review",
                    "Risk Classification",
                    "Impact Assessment",
                    "Disclosure",
                    "Regulation Mapping",
                    "Unified governance layer for ISO 42001, NIST AI RMF, EU AI Act, FDA CSA, and MHRA guidance"
                ]
            )

            bp["evidence_assurance"] = add_unique(
                bp.get("evidence_assurance", []),
                PATCH["evidence_extension"]
            )

            bp["continuous_assurance"] = add_unique(
                bp.get("continuous_assurance", []),
                PATCH["continuous_assurance_extension"]
            )

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [PATCH["operational_trust_question"]] + PATCH["evidence_questions"]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["iso42001_lifecycle_mapping_state"] = "ACTIVE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["iso42001_module_created"] = False
            assessment["ai_management_system_continuously_assured"] = True
            assessment["ai_inventory_discovered"] = True
            assessment["ai_passport_expanded"] = True
            assessment["multi_framework_governance_layer"] = True
            assessment["decision_traceability_evidenced"] = True
            assessment["human_review_evidenced"] = True
            assessment["continuous_monitoring_effectiveness_evaluated"] = True
            assessment["incident_management_evaluated"] = True
            assessment["capa_effectiveness_evaluated"] = True
            assessment["drift_monitored"] = True
            assessment["evidence_completeness_monitored"] = True
            assessment["operational_trust_question"] = PATCH["operational_trust_question"]
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["iso42001_lifecycle_mapping_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["iso42001_module_created"] = False
        assessment["iso42001_lifecycle_mapping"] = PATCH
        assessment["governance_frameworks"] = add_unique(
            assessment.get("governance_frameworks", []),
            PATCH["governance_frameworks_mapped_into_one_layer"]
        )
        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            PATCH["evidence_extension"] + PATCH["evidence_questions"]
        )
        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            PATCH["continuous_assurance_extension"]
        )
        assessment["operational_trust_question"] = PATCH["operational_trust_question"]
        assessment["implementation_priority"] = add_unique(
            assessment.get("implementation_priority", []),
            [
                "Map ISO 42001 pillars into the existing Assurance Lifecycle instead of creating an ISO 42001 module.",
                "Extend Discovery to discover AI inventory, AI assets, AI owners, AI systems, AI business purpose, and context of use.",
                "Expand AI Passports with risk classification, intended use, governance owner, deployment status, model version, human approver, and supporting evidence.",
                "Map ISO 42001, NIST AI RMF, EU AI Act, FDA CSA, and MHRA guidance into one Governance layer.",
                "Extend Evidence with decision traceability, human review, evidence lineage, scientific verification, and approval history.",
                "Continuously verify monitoring effectiveness, incident management, CAPAs, governance reviews, policy effectiveness, operational performance, drift, and evidence completeness.",
                "Ask whether the AI system continues to operate in accordance with its governance, not merely whether governance was implemented."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="iso42001-map-card">
        <div class="iso42001-map-domain">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def mapping_table(rows):
    body = ""
    for row in rows:
        body += f"""
        <tr>
            <td>{html_escape(row["iso_42001_pillar"])}</td>
            <td>{html_escape(row["existing_assurance_lifecycle"])}</td>
        </tr>
        """
    return f"""
    <div class="iso42001-map-table-wrap">
        <table class="iso42001-map-table">
            <thead>
                <tr>
                    <th>ISO 42001 Pillar</th>
                    <th>Existing Assurance Lifecycle</th>
                </tr>
            </thead>
            <tbody>{body}</tbody>
        </table>
    </div>
    """

def pill_list(items, cls):
    return "".join([f'<span class="{cls}">{html_escape(x)}</span>' for x in items])

HTML_BLOCK = f"""
<style>
.platform-b-iso42001-map-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(37,99,235,.10), rgba(16,185,129,.08));
}}
.platform-b-iso42001-map-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 18px;
}}
.platform-b-iso42001-map-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-iso42001-map-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 980px;
}}
.platform-b-iso42001-map-tag {{
    border: 1px solid rgba(147,197,253,.45);
    color: #bfdbfe;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(37,99,235,.10);
}}
.platform-b-iso42001-map-principle {{
    margin: 18px 0;
    padding: 18px;
    border-left: 4px solid #93c5fd;
    color: #eff6ff;
    background: rgba(255,255,255,.055);
    border-radius: 16px;
    line-height: 1.65;
    font-size: 17px;
    font-weight: 800;
}}
.platform-b-iso42001-map-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(16,185,129,.10);
    border: 1px solid rgba(110,231,183,.22);
    color: #d1fae5;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-iso42001-map-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
}}
.platform-b-iso42001-map-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
}}
.iso42001-map-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.iso42001-map-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.iso42001-map-domain {{
    color: #bfdbfe;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
.iso42001-map-table-wrap {{
    margin: 18px 0;
    overflow-x: auto;
    border-radius: 18px;
    border: 1px solid rgba(255,255,255,.10);
}}
.iso42001-map-table {{
    width: 100%;
    border-collapse: collapse;
    color: #dbeafe;
    background: rgba(255,255,255,.035);
}}
.iso42001-map-table th,
.iso42001-map-table td {{
    text-align: left;
    padding: 12px 14px;
    border-bottom: 1px solid rgba(255,255,255,.08);
}}
.iso42001-map-table th {{
    color: #bfdbfe;
    text-transform: uppercase;
    font-size: 12px;
    letter-spacing: .04em;
}}
.platform-b-iso42001-map-pills {{
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
}}
.platform-b-iso42001-map-pill {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 8px 12px;
    color: #d8dee9;
    font-size: 13px;
}}
</style>

<section class="platform-b-iso42001-map-wrap">
    <div class="platform-b-iso42001-map-head">
        <div>
            <h2>ISO 42001 Lifecycle Mapping</h2>
            <p>
                No ISO 42001 module. Platform B maps each ISO 42001 pillar into the existing Assurance Lifecycle
                and continuously generates evidence that the AI management system remains effective during AI operation.
            </p>
        </div>
        <span class="platform-b-iso42001-map-tag">Governance Mapping Extension</span>
    </div>

    <div class="platform-b-iso42001-map-warning">
        Do not build an ISO 42001 module. ISO 42001 fits naturally into the existing architecture:
        Discovery, Visibility, Governance, Operationalization, Evidence, Continuous Assurance, and Operational Trust.
    </div>

    <div class="platform-b-iso42001-map-principle">
        {html_escape(PATCH["governance_statement"])}<br>
        {html_escape(PATCH["assurance_engineering_statement"])}
    </div>

    <div class="platform-b-iso42001-map-question">
        Operational Trust asks: {html_escape(PATCH["operational_trust_question"])}
    </div>

    {mapping_table(PATCH["iso42001_pillar_mapping"])}

    <div class="platform-b-iso42001-map-grid">
        {card("Discovery Extends To Discover", PATCH["discovery_extension"])}
        {card("AI Passport Visibility Expands", PATCH["visibility_ai_passport_extension"])}
        {card("Governance Maps Into One Layer", PATCH["governance_frameworks_mapped_into_one_layer"])}
        {card("Evidence Captures", PATCH["evidence_extension"])}
        {card("Continuous Assurance Verifies", PATCH["continuous_assurance_extension"])}
    </div>

    <div class="platform-b-iso42001-map-pills">
        {pill_list(PATCH["evidence_questions"], "platform-b-iso42001-map-pill")}
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

Path("platform_b_iso42001_lifecycle_mapping_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_iso42001_lifecycle_mapping_patch_v1_urls.txt").write_text(
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
print("Platform B ISO 42001 Lifecycle Mapping Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("ISO 42001 module created: False")
print("Primary stage: Governance")
print("Lifecycle:", LIFECYCLE_SEQUENCE)
print("Operational Trust question:", PATCH["operational_trust_question"])
