from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_GOVERNANCE_SUSTAINED_COMPLIANCE_PATCH_V1_ACTIVE"
LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

GOVERNANCE_ENRICHMENT = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "new_module": False,
    "new_approval_workflow": False,
    "architecture_instruction": "Do not add a new module or approval workflow. Enrich existing Governance, Continuous Assurance, and Operational Trust stages only.",
    "capability_name": "Governance Effectiveness and Sustained Compliance Enrichment",
    "lifecycle_sequence": LIFECYCLE_SEQUENCE,
    "enriched_stages": ["Governance", "Continuous Assurance", "Operational Trust"],
    "existing_governance_controls": [
        "Risk Classification",
        "Approval Authority",
        "Human Review",
        "Escalation",
        "Evidence",
        "Continuous Oversight"
    ],
    "core_question": "Did the organization only correct the deviation, or did it strengthen the governance system enough to prevent recurrence and sustain trusted outcomes?",
    "assurance_questions": [
        "Was the deviation corrected?",
        "What systemic weakness allowed it to occur?",
        "Has the governance process been strengthened?",
        "Is Quality Unit oversight effective?",
        "Is there evidence that corrective actions remain effective over time?",
        "Can the organization demonstrate sustained compliance rather than one-time remediation?"
    ],
    "governance_evaluation": [
        {
            "control": "Risk Classification",
            "question": "Was the issue classified according to risk, impact, recurrence potential, and regulated process exposure?",
            "evidence": ["risk classification record", "impact assessment", "recurrence risk", "GxP or quality impact"]
        },
        {
            "control": "Approval Authority",
            "question": "Was the correct authority responsible for accepting, escalating, approving, or closing the issue?",
            "evidence": ["approval authority record", "delegation evidence", "Quality Unit approval", "decision accountability"]
        },
        {
            "control": "Human Review",
            "question": "Did qualified personnel review the deviation, CAPA, systemic weakness, and effectiveness evidence?",
            "evidence": ["human reviewer", "review timestamp", "review comments", "qualification or role"]
        },
        {
            "control": "Escalation",
            "question": "Were systemic or recurring risks escalated to the right governance forum or Quality Unit authority?",
            "evidence": ["escalation trigger", "escalation owner", "escalation decision", "governance forum record"]
        },
        {
            "control": "Evidence",
            "question": "Can the organization reconstruct the correction, root cause, governance decision, CAPA, and effectiveness evidence?",
            "evidence": ["deviation record", "root cause evidence", "CAPA record", "effectiveness check", "audit trail"]
        },
        {
            "control": "Continuous Oversight",
            "question": "Does oversight continue after CAPA closure to verify that controls remain effective?",
            "evidence": ["post-closure monitoring", "trend review", "recurrence check", "control effectiveness evidence"]
        }
    ],
    "continuous_assurance_targets": [
        "CAPA effectiveness after closure",
        "Recurring deviation detection",
        "Systemic weakness recurrence",
        "Quality Unit oversight effectiveness",
        "Control effectiveness over time",
        "Governance process strengthening",
        "Evidence completeness after remediation",
        "Sustained compliance monitoring",
        "One-time remediation risk",
        "Audit readiness after closure"
    ],
    "operational_trust_evidence": [
        "Deviation correction evidence",
        "Systemic weakness analysis",
        "Governance strengthening record",
        "Quality Unit oversight record",
        "CAPA effectiveness evidence",
        "Post-closure monitoring evidence",
        "Sustained compliance evidence",
        "Recurrence prevention evidence",
        "Control effectiveness trend",
        "Audit reconstruction package"
    ],
    "positioning_statement": "Platform B does not treat CAPA closure or deviation correction as the end of assurance. It continuously verifies whether governance, Quality Unit oversight, corrective actions, and controls remain effective after closure.",
    "principle": "Sustained compliance is not proven by one-time remediation. It is proven by continuous evidence that systemic weaknesses were addressed, governance was strengthened, oversight remains effective, and recurrence is prevented over time."
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

    data["platform_b_governance_sustained_compliance_patch"] = GOVERNANCE_ENRICHMENT
    data["platform_b_architecture_change"] = False
    data["platform_b_new_module"] = False
    data["platform_b_new_approval_workflow"] = False
    data["platform_b_lifecycle_sequence"] = LIFECYCLE_SEQUENCE

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["new_module"] = False
            bp["new_approval_workflow"] = False
            bp["governance_sustained_compliance_enrichment"] = GOVERNANCE_ENRICHMENT

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                GOVERNANCE_ENRICHMENT["assurance_questions"]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["governance_sustained_compliance_state"] = "ENRICH_EXISTING_GOVERNANCE_AND_CONTINUOUS_ASSURANCE"
            assessment["architecture_change"] = False
            assessment["new_module"] = False
            assessment["new_approval_workflow"] = False
            assessment["risk_classification_required"] = True
            assessment["approval_authority_required"] = True
            assessment["human_review_required"] = True
            assessment["escalation_required"] = True
            assessment["evidence_required"] = True
            assessment["continuous_oversight_required"] = True
            assessment["quality_unit_oversight_required"] = True
            assessment["capa_effectiveness_after_closure_required"] = True
            assessment["sustained_compliance_evidence_required"] = True
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["governance_sustained_compliance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["new_module"] = False
        assessment["new_approval_workflow"] = False
        assessment["governance_sustained_compliance_enrichment"] = GOVERNANCE_ENRICHMENT
        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            GOVERNANCE_ENRICHMENT["operational_trust_evidence"]
        )
        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            GOVERNANCE_ENRICHMENT["continuous_assurance_targets"]
        )
        assessment["implementation_priority"] = add_unique(
            assessment.get("implementation_priority", []),
            [
                "Enrich Governance with Risk Classification, Approval Authority, Human Review, Escalation, Evidence, and Continuous Oversight.",
                "Verify CAPA effectiveness after closure.",
                "Monitor recurring deviations and systemic weakness recurrence.",
                "Evaluate Quality Unit oversight effectiveness.",
                "Demonstrate sustained compliance rather than one-time remediation."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def governance_cards():
    cards = []
    for item in GOVERNANCE_ENRICHMENT["governance_evaluation"]:
        evidence = "".join([f"<li>{html_escape(x)}</li>" for x in item["evidence"]])
        cards.append(f"""
        <div class="gov-compliance-card">
            <div class="gov-compliance-domain">{html_escape(item["control"])}</div>
            <h3>{html_escape(item["question"])}</h3>
            <ul>{evidence}</ul>
        </div>
        """)
    return "\n".join(cards)

HTML_BLOCK = f"""
<style>
.platform-b-gov-compliance-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(14,165,233,.10), rgba(255,122,24,.08));
}}
.platform-b-gov-compliance-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 18px;
}}
.platform-b-gov-compliance-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-gov-compliance-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 980px;
}}
.platform-b-gov-compliance-tag {{
    border: 1px solid rgba(125,211,252,.45);
    color: #7dd3fc;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(14,165,233,.10);
}}
.platform-b-gov-compliance-principle {{
    margin: 18px 0;
    padding: 16px;
    border-left: 4px solid #7dd3fc;
    color: #e5e7eb;
    background: rgba(255,255,255,.045);
    border-radius: 14px;
    line-height: 1.6;
}}
.platform-b-gov-compliance-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(270px, 1fr));
    gap: 16px;
}}
.gov-compliance-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.gov-compliance-card h3 {{
    margin: 8px 0 12px;
    color: #fff;
    font-size: 16px;
    line-height: 1.35;
}}
.gov-compliance-card ul {{
    margin: 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.gov-compliance-domain {{
    color: #7dd3fc;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
.platform-b-gov-compliance-questions {{
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
}}
.platform-b-gov-compliance-question {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 8px 12px;
    color: #d8dee9;
    font-size: 13px;
}}
</style>

<section class="platform-b-gov-compliance-wrap">
    <div class="platform-b-gov-compliance-head">
        <div>
            <h2>Governance Effectiveness and Sustained Compliance</h2>
            <p>
                No new module and no new approval workflow. This enriches the existing Governance, Continuous Assurance,
                and Operational Trust stages so Platform B can show whether deviations were corrected, systemic weaknesses
                were addressed, Quality Unit oversight remains effective, and corrective actions remain effective over time.
            </p>
        </div>
        <span class="platform-b-gov-compliance-tag">Governance + Continuous Assurance + Operational Trust</span>
    </div>
    <div class="platform-b-gov-compliance-principle">
        {html_escape(GOVERNANCE_ENRICHMENT["principle"])}
    </div>
    <div class="platform-b-gov-compliance-grid">
        {governance_cards()}
    </div>
    <div class="platform-b-gov-compliance-questions">
        {"".join([f'<span class="platform-b-gov-compliance-question">{html_escape(x)}</span>' for x in GOVERNANCE_ENRICHMENT["assurance_questions"]])}
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

Path("platform_b_governance_sustained_compliance_patch_v1_summary.json").write_text(
    json.dumps(GOVERNANCE_ENRICHMENT, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_governance_sustained_compliance_patch_v1_urls.txt").write_text(
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
print("Platform B Governance Effectiveness and Sustained Compliance Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("New module: False")
print("New approval workflow: False")
print("Lifecycle:", LIFECYCLE_SEQUENCE)
