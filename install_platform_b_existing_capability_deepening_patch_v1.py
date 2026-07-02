from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_EXISTING_CAPABILITY_DEEPENING_PATCH_V1_ACTIVE"

UPDATED_LIFECYCLE = [
    "Discovery",
    "Visibility",
    "Governance",
    "Operationalization",
    "Execution Assurance",
    "Evidence",
    "Continuous Assurance",
    "Operational Trust"
]

UPDATED_LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

CAPABILITY_DEEPENING = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "architecture_instruction": "Do not change the architecture. Deepen existing Platform B lifecycle capabilities only.",
    "updated_lifecycle_sequence": UPDATED_LIFECYCLE_SEQUENCE,
    "stage_deepening": {
        "Discovery": {
            "question": "Are we solving the right problem?",
            "expanded_evaluation": [
                "Business problem defined",
                "Success metrics (KPIs)",
                "Business owner assigned",
                "Intended outcome documented",
                "Production objective identified"
            ]
        },
        "Visibility": {
            "question": "Can the organization see where AI is being used and whether similar efforts already exist?",
            "expanded_evaluation": [
                "AI inventory",
                "Duplicate AI initiatives",
                "Shared platform reuse",
                "Data readiness",
                "Workflow readiness"
            ]
        },
        "Governance": {
            "question": "Who owns this AI after the demonstration ends?",
            "expanded_evaluation": [
                "Ownership continuity from pilot to production",
                "Business accountability",
                "Support ownership",
                "Adoption ownership",
                "Platform ownership"
            ]
        },
        "Operationalization": {
            "question": "Has the AI become part of day-to-day operations?",
            "expanded_evaluation": [
                "Workflow integration",
                "User adoption",
                "Production deployment",
                "Monitoring enabled",
                "Support model",
                "Operational runbooks",
                "Business KPI monitoring"
            ]
        },
        "Execution Assurance": {
            "question": "Did AI actually improve the business process?",
            "expanded_evaluation": [
                "Business process executed",
                "Workflow completed",
                "Expected outcome achieved",
                "KPI captured",
                "Adoption measured"
            ]
        },
        "Evidence": {
            "question": "Can business value, operational use, and assurance outcomes be reconstructed?",
            "expanded_evidence": [
                "Adoption rate",
                "Usage metrics",
                "Business KPI improvement",
                "Operational metrics",
                "User acceptance",
                "Production incidents"
            ]
        },
        "Continuous Assurance": {
            "question": "Is Platform B continuously detecting whether AI value, ownership, adoption, and operational performance are degrading?",
            "expanded_monitoring": [
                "Declining adoption",
                "Workflow failures",
                "KPI degradation",
                "Duplicate AI initiatives",
                "Ownership gaps",
                "Support effectiveness"
            ]
        }
    },
    "positioning_statement": "Platform B should not add a new architecture. It should deepen its existing lifecycle by proving that AI initiatives solve the right problem, have accountable owners, enter day-to-day operations, improve measurable business processes, and remain continuously assured after production deployment.",
    "core_principle": "AI operational trust is not demonstrated by a successful demo. It is demonstrated when the AI capability is adopted, integrated, supported, measured, monitored, and continuously improved in production."
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
        print(f"SKIP: {path} is not a JSON object")
        return

    data["platform_b_existing_capability_deepening_patch"] = CAPABILITY_DEEPENING
    data["platform_b_architecture_change"] = False
    data["platform_b_lifecycle_sequence"] = UPDATED_LIFECYCLE_SEQUENCE
    data["platform_b_lifecycle"] = UPDATED_LIFECYCLE

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["platform_b_lifecycle_sequence"] = UPDATED_LIFECYCLE_SEQUENCE
            bp["existing_capability_deepening"] = CAPABILITY_DEEPENING["stage_deepening"]

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [
                    "Are we solving the right problem?",
                    "Can the organization see where AI is being used and whether similar efforts already exist?",
                    "Who owns this AI after the demonstration ends?",
                    "Has the AI become part of day-to-day operations?",
                    "Did AI actually improve the business process?",
                    "Can business value, operational use, and assurance outcomes be reconstructed?"
                ]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["platform_b_capability_deepening_state"] = "EXISTING_CAPABILITIES_DEEPENED_WITHOUT_ARCHITECTURE_CHANGE"
            assessment["architecture_change"] = False
            assessment["business_problem_required"] = True
            assessment["kpi_required"] = True
            assessment["ownership_continuity_required"] = True
            assessment["production_adoption_required"] = True
            assessment["business_process_improvement_required"] = True
            assessment["continuous_value_monitoring_required"] = True
            assessment["updated_lifecycle_sequence"] = UPDATED_LIFECYCLE_SEQUENCE
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["platform_b_capability_deepening_state"] = "EXISTING_CAPABILITIES_DEEPENED_WITHOUT_ARCHITECTURE_CHANGE"
        assessment["architecture_change"] = False
        assessment["stage_deepening"] = CAPABILITY_DEEPENING["stage_deepening"]
        assessment["implementation_priority"] = add_unique(
            assessment.get("implementation_priority", []),
            [
                "Define the business problem before approving AI work.",
                "Assign business ownership before pilots begin.",
                "Identify duplicate AI initiatives before funding new work.",
                "Confirm workflow readiness before production deployment.",
                "Maintain ownership continuity from pilot to production.",
                "Measure user adoption and business KPI improvement after deployment.",
                "Monitor declining adoption, workflow failures, KPI degradation, duplicate AI initiatives, ownership gaps, and support effectiveness."
            ]
        )
        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            [
                "Business problem statement",
                "Success KPI record",
                "Business owner assignment",
                "Production objective record",
                "AI inventory record",
                "Duplicate initiative check",
                "Shared platform reuse assessment",
                "Workflow readiness assessment",
                "Ownership continuity record",
                "Support ownership record",
                "Adoption ownership record",
                "Operational runbook",
                "Usage metrics",
                "Adoption rate",
                "Business KPI improvement",
                "Operational metrics",
                "User acceptance evidence",
                "Production incident record",
                "Support effectiveness monitoring"
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def build_stage_cards():
    cards = []
    for stage, model in CAPABILITY_DEEPENING["stage_deepening"].items():
        items_key = "expanded_evaluation"
        if stage == "Evidence":
            items_key = "expanded_evidence"
        if stage == "Continuous Assurance":
            items_key = "expanded_monitoring"

        items = "".join([f"<li>{html_escape(x)}</li>" for x in model.get(items_key, [])])

        cards.append(f"""
        <div class="capability-deepening-card">
            <div class="capability-stage">{html_escape(stage)}</div>
            <h3>{html_escape(model["question"])}</h3>
            <ul>{items}</ul>
        </div>
        """)
    return "\n".join(cards)

HTML_BLOCK = f"""
<style>
.platform-b-deepening-wrap {{
    margin: 28px 0;
    padding: 24px;
    border: 1px solid rgba(255,255,255,.12);
    border-radius: 24px;
    background: linear-gradient(135deg, rgba(255,122,24,.12), rgba(59,130,246,.06));
}}
.platform-b-deepening-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 20px;
}}
.platform-b-deepening-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-deepening-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 920px;
}}
.platform-b-deepening-tag {{
    border: 1px solid rgba(255,178,95,.45);
    color: #ffb25f;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(255,122,24,.08);
}}
.platform-b-deepening-flow {{
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
    align-items: center;
    margin: 18px 0 22px;
}}
.platform-b-deepening-node {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 9px 13px;
    color: #d8dee9;
    font-size: 13px;
}}
.platform-b-deepening-arrow {{
    color: #ffb25f;
}}
.platform-b-deepening-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
}}
.capability-deepening-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.capability-deepening-card h3 {{
    margin: 8px 0 12px;
    color: #fff;
    font-size: 17px;
    line-height: 1.35;
}}
.capability-deepening-card ul {{
    margin: 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.capability-stage {{
    color: #ffb25f;
    font-weight: 700;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
</style>

<section class="platform-b-deepening-wrap">
    <div class="platform-b-deepening-head">
        <div>
            <h2>Platform B Existing Capability Deepening</h2>
            <p>
                No architecture change. Platform B deepens the existing lifecycle by strengthening business-problem fit,
                visibility, ownership continuity, production adoption, execution outcomes, value evidence, and continuous
                monitoring after deployment.
            </p>
        </div>
        <span class="platform-b-deepening-tag">No architecture change</span>
    </div>

    <div class="platform-b-deepening-flow">
        <span class="platform-b-deepening-node">Discovery</span><span class="platform-b-deepening-arrow">-&gt;</span>
        <span class="platform-b-deepening-node">Visibility</span><span class="platform-b-deepening-arrow">-&gt;</span>
        <span class="platform-b-deepening-node">Governance</span><span class="platform-b-deepening-arrow">-&gt;</span>
        <span class="platform-b-deepening-node">Operationalization</span><span class="platform-b-deepening-arrow">-&gt;</span>
        <span class="platform-b-deepening-node">Execution Assurance</span><span class="platform-b-deepening-arrow">-&gt;</span>
        <span class="platform-b-deepening-node">Evidence</span><span class="platform-b-deepening-arrow">-&gt;</span>
        <span class="platform-b-deepening-node">Continuous Assurance</span><span class="platform-b-deepening-arrow">-&gt;</span>
        <span class="platform-b-deepening-node">Operational Trust</span>
    </div>

    <div class="platform-b-deepening-grid">
        {build_stage_cards()}
    </div>
</section>
"""

def remove_old_block(text):
    start = f"<!-- {PATCH_MARKER} -->"
    end = f"<!-- END {PATCH_MARKER} -->"
    return re.sub(re.escape(start) + r".*?" + re.escape(end), "", text, flags=re.DOTALL)

def patch_html(path):
    p = Path(path)
    if not p.exists():
        print(f"SKIP: {path}")
        return

    text = p.read_text(encoding="utf-8-sig")
    text = remove_old_block(text)

    wrapped = f"\n<!-- {PATCH_MARKER} -->\n{HTML_BLOCK}\n<!-- END {PATCH_MARKER} -->\n"

    anchors = [
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

    p.write_text(text, encoding="utf-8")
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

Path("platform_b_existing_capability_deepening_patch_v1_summary.json").write_text(
    json.dumps(CAPABILITY_DEEPENING, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_existing_capability_deepening_patch_v1_urls.txt").write_text(
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
print("Platform B Existing Capability Deepening Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("Lifecycle:", UPDATED_LIFECYCLE_SEQUENCE)
