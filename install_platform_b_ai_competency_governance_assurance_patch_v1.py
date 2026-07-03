from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_AI_COMPETENCY_GOVERNANCE_ASSURANCE_PATCH_V1_ACTIVE"
LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

PATCH = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "do_not_create": [
        "Certification Assurance module",
        "Training-only assurance module",
        "Credential-only assurance module",
        "Standalone competency module"
    ],
    "capability_name": "AI Competency Governance Assurance",
    "architecture_instruction": "Do not build a Certification Assurance module. Extend existing Discovery, Visibility, Governance, Evidence, Continuous Assurance, and Operational Trust capabilities.",
    "lifecycle_sequence": LIFECYCLE_SEQUENCE,
    "core_question": "Can the organization demonstrate that accountable AI governance roles were assigned, qualified, trained, authorized, and actively performing oversight?",
    "operational_trust_questions": [
        "Was the reviewer qualified?",
        "Did the reviewer actually perform the review?",
        "Was the decision evidence-based?",
        "Can accountability be demonstrated?"
    ],
    "platform_statement": "Platform B does not treat competency as a certificate-only question. Platform B continuously assures whether AI reviewers, approvers, operators, owners, and risk owners are assigned, trained, authorized, separated by duty, actively performing oversight, and accountable through evidence.",
    "discovery": [
        "AI governance roles",
        "AI business owners",
        "AI reviewers",
        "AI approvers",
        "AI operators",
        "AI risk owners"
    ],
    "visibility": [
        "Assigned responsibilities",
        "Required competencies",
        "Training completion",
        "Role assignments",
        "Separation of duties",
        "Approval authority"
    ],
    "governance_extension": {
        "name": "AI Competency Governance",
        "evaluates": [
            "Role-based competency requirements",
            "Required training",
            "Delegated authority",
            "Competency reviews",
            "Approval authority alignment",
            "Separation of duties"
        ]
    },
    "evidence_of_demonstrated_competence": [
        "Human review performed",
        "Challenge exercised",
        "Decisions justified",
        "Escalations completed",
        "Approvals recorded",
        "Oversight documented",
        "Corrective actions taken"
    ],
    "continuous_assurance": [
        "Competent personnel remain assigned",
        "Mandatory training remains current",
        "Approval authority remains valid",
        "Critical roles remain filled",
        "Separation of duties is maintained"
    ],
    "execution_evidence_questions": [
        "Who was assigned as the AI business owner?",
        "Who reviewed the AI output?",
        "Who approved the AI decision or content?",
        "Was the reviewer qualified?",
        "Was required training current?",
        "Was approval authority valid?",
        "Was separation of duties maintained?",
        "Did the reviewer actually perform the review?",
        "Was the decision evidence-based?",
        "Was challenge exercised?",
        "Were escalations completed?",
        "Were approvals recorded?",
        "Was oversight documented?",
        "Were corrective actions taken where required?",
        "Can accountability be demonstrated?"
    ],
    "operational_trust_statement": "Operational Trust should demonstrate that qualified, trained, authorized, and accountable personnel actually performed review, challenge, approval, escalation, oversight, and corrective action where required.",
    "principle": "Professional qualifications indicate potential competence; Platform B continuously evaluates demonstrated competence through operational evidence of review, challenge, decision-making, escalation, approval, oversight, and accountability."
}

def load_json(path):
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8-sig"))

def save_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def add_unique(items, additions):
    if not isinstance(items, list):
        items = []
    result = []
    seen = set()
    for item in items + additions:
        key = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
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

    data["platform_b_ai_competency_governance_assurance_patch"] = PATCH
    data["platform_b_architecture_change"] = False
    data["platform_b_new_module"] = False
    data["platform_b_lifecycle_sequence"] = LIFECYCLE_SEQUENCE

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["new_module"] = False
            bp["ai_competency_governance_assurance"] = PATCH

            bp["discovery_scope"] = add_unique(
                bp.get("discovery_scope", []),
                PATCH["discovery"]
            )

            bp["visibility_scope"] = add_unique(
                bp.get("visibility_scope", []),
                PATCH["visibility"]
            )

            bp["governance_scope"] = add_unique(
                bp.get("governance_scope", []),
                PATCH["governance_extension"]["evaluates"]
            )

            bp["evidence_assurance"] = add_unique(
                bp.get("evidence_assurance", []),
                PATCH["evidence_of_demonstrated_competence"]
            )

            bp["continuous_assurance"] = add_unique(
                bp.get("continuous_assurance", []),
                PATCH["continuous_assurance"]
            )

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [PATCH["core_question"]] + PATCH["operational_trust_questions"] + PATCH["execution_evidence_questions"]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["ai_competency_governance_assurance_state"] = "EXTEND_EXISTING_CAPABILITIES"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["certification_assurance_module_created"] = False
            assessment["ai_competency_governance_extended"] = True
            assessment["role_based_competency_required"] = True
            assessment["training_currency_required"] = True
            assessment["approval_authority_alignment_required"] = True
            assessment["separation_of_duties_required"] = True
            assessment["demonstrated_competence_evidence_required"] = True
            assessment["accountability_evidence_required"] = True
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["ai_competency_governance_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["certification_assurance_module_created"] = False
        assessment["ai_competency_governance_assurance"] = PATCH
        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            PATCH["evidence_of_demonstrated_competence"] + PATCH["execution_evidence_questions"]
        )
        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            PATCH["continuous_assurance"]
        )
        assessment["implementation_priority"] = add_unique(
            assessment.get("implementation_priority", []),
            [
                "Discover AI governance roles, AI business owners, AI reviewers, AI approvers, AI operators, and AI risk owners.",
                "Display assigned responsibilities, required competencies, training completion, role assignments, separation of duties, and approval authority.",
                "Extend Governance with AI Competency Governance for role-based competency requirements, required training, delegated authority, competency reviews, approval authority alignment, and separation of duties.",
                "Capture demonstrated competence evidence including human review performed, challenge exercised, decisions justified, escalations completed, approvals recorded, oversight documented, and corrective actions taken.",
                "Continuously verify competent personnel remain assigned, mandatory training remains current, approval authority remains valid, critical roles remain filled, and separation of duties is maintained."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def card(title, items):
    lis = "".join([f"<li>{html_escape(x)}</li>" for x in items])
    return f"""
    <div class="ai-competency-card">
        <div class="ai-competency-domain">{html_escape(title)}</div>
        <ul>{lis}</ul>
    </div>
    """

def pill_list(items, cls):
    return "".join([f'<span class="{cls}">{html_escape(x)}</span>' for x in items])

HTML_BLOCK = f"""
<style>
.platform-b-ai-competency-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(245,158,11,.10), rgba(99,102,241,.08));
}}
.platform-b-ai-competency-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 18px;
}}
.platform-b-ai-competency-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-ai-competency-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 980px;
}}
.platform-b-ai-competency-tag {{
    border: 1px solid rgba(251,191,36,.45);
    color: #fde68a;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(245,158,11,.10);
}}
.platform-b-ai-competency-principle {{
    margin: 18px 0;
    padding: 16px;
    border-left: 4px solid #fbbf24;
    color: #e5e7eb;
    background: rgba(255,255,255,.045);
    border-radius: 14px;
    line-height: 1.6;
}}
.platform-b-ai-competency-question {{
    margin: 18px 0;
    padding: 16px;
    border-radius: 16px;
    background: rgba(99,102,241,.10);
    border: 1px solid rgba(165,180,252,.22);
    color: #e0e7ff;
    font-weight: 800;
    font-size: 18px;
}}
.platform-b-ai-competency-warning {{
    margin: 18px 0;
    padding: 14px 16px;
    border-radius: 14px;
    background: rgba(248,113,113,.08);
    border: 1px solid rgba(248,113,113,.18);
    color: #fecaca;
    line-height: 1.55;
}}
.platform-b-ai-competency-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
}}
.ai-competency-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.ai-competency-card ul {{
    margin: 10px 0 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.ai-competency-domain {{
    color: #fde68a;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
.platform-b-ai-competency-pills {{
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
}}
.platform-b-ai-competency-pill {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 8px 12px;
    color: #d8dee9;
    font-size: 13px;
}}
</style>

<section class="platform-b-ai-competency-wrap">
    <div class="platform-b-ai-competency-head">
        <div>
            <h2>AI Competency Governance Assurance</h2>
            <p>
                No Certification Assurance module. Platform B extends Governance, Evidence, Continuous Assurance,
                and Operational Trust to demonstrate that AI reviewers, approvers, operators, business owners,
                and risk owners are assigned, trained, authorized, separated by duty, and actively performing accountable oversight.
            </p>
        </div>
        <span class="platform-b-ai-competency-tag">Governance + Evidence Extension</span>
    </div>

    <div class="platform-b-ai-competency-warning">
        Do not build a Certification Assurance module. Competency is assured through role assignment,
        required training, delegated authority, separation of duties, performed review, challenge evidence,
        decision justification, approvals, escalation, oversight, corrective action, and continuous assurance.
    </div>

    <div class="platform-b-ai-competency-question">
        {html_escape(PATCH["core_question"])}
    </div>

    <div class="platform-b-ai-competency-principle">
        {html_escape(PATCH["principle"])}
    </div>

    <div class="platform-b-ai-competency-grid">
        {card("Discovery", PATCH["discovery"])}
        {card("Visibility", PATCH["visibility"])}
        {card("AI Competency Governance", PATCH["governance_extension"]["evaluates"])}
        {card("Demonstrated Competence Evidence", PATCH["evidence_of_demonstrated_competence"])}
        {card("Continuous Assurance", PATCH["continuous_assurance"])}
        {card("Operational Trust Questions", PATCH["operational_trust_questions"])}
    </div>

    <div class="platform-b-ai-competency-pills">
        {pill_list(PATCH["execution_evidence_questions"], "platform-b-ai-competency-pill")}
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

Path("platform_b_ai_competency_governance_assurance_patch_v1_summary.json").write_text(
    json.dumps(PATCH, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_ai_competency_governance_assurance_patch_v1_urls.txt").write_text(
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
print("Platform B AI Competency Governance Assurance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("Lifecycle:", LIFECYCLE_SEQUENCE)
