from pathlib import Path
import json
import re

PATCH_MARKER = "COBITCHAIN_PLATFORM_B_BUSINESS_VALUE_KPI_EVIDENCE_PATCH_V1_ACTIVE"
LIFECYCLE_SEQUENCE = "Discovery -> Visibility -> Governance -> Operationalization -> Execution Assurance -> Evidence -> Continuous Assurance -> Operational Trust"

BUSINESS_VALUE_ASSURANCE = {
    "patch_marker": PATCH_MARKER,
    "architecture_change": False,
    "architecture_instruction": "Do not change Platform B architecture. Deepen existing Evidence and Continuous Assurance capabilities only.",
    "capability_name": "Business Value Assurance / KPI Evidence",
    "capability_layer": ["Evidence", "Continuous Assurance"],
    "lifecycle_sequence": LIFECYCLE_SEQUENCE,
    "core_question": "Did the AI capability produce measurable business value after production deployment?",
    "evidence_question": "Can adoption, usage, KPI improvement, support effectiveness, ownership continuity, and production incidents be reconstructed?",
    "continuous_assurance_question": "Is the business value of the AI capability sustained after go-live?",
    "evidence_objects": [
        "Baseline KPI before AI deployment",
        "Target KPI after AI deployment",
        "Actual KPI after deployment",
        "Adoption rate",
        "Usage metrics",
        "Active user count",
        "Workflow completion rate",
        "Cycle-time reduction",
        "Quality improvement",
        "Error or deviation reduction",
        "Operational efficiency gain",
        "User acceptance evidence",
        "Support tickets",
        "Production incidents",
        "Ownership continuity record",
        "Business owner attestation",
        "Support owner attestation",
        "Adoption owner attestation",
        "Platform owner attestation"
    ],
    "continuous_monitoring_signals": [
        "Adoption decline",
        "Usage decline",
        "KPI degradation",
        "Workflow failure increase",
        "Support backlog increase",
        "Production incident trend",
        "Duplicate AI initiative detected",
        "Ownership gap detected",
        "User acceptance decline",
        "Operational value no longer demonstrable"
    ],
    "business_value_metrics": [
        {
            "metric": "Adoption Rate",
            "question": "Are intended users actually using the AI capability?",
            "evidence": ["Active users", "Eligible users", "Usage trend", "Adoption owner"]
        },
        {
            "metric": "Usage Metrics",
            "question": "Is the AI capability being used in real workflows rather than only demo scenarios?",
            "evidence": ["Workflow usage count", "Transaction count", "Session count", "Business process link"]
        },
        {
            "metric": "Business KPI Improvement",
            "question": "Did the AI capability improve the business metric it was created to improve?",
            "evidence": ["Baseline KPI", "Target KPI", "Actual KPI", "Measurement period"]
        },
        {
            "metric": "Operational Metrics",
            "question": "Did the AI capability improve operational execution?",
            "evidence": ["Cycle time", "Throughput", "Error rate", "Rework rate", "SLA performance"]
        },
        {
            "metric": "User Acceptance",
            "question": "Do business users accept the AI capability as useful, usable, and reliable?",
            "evidence": ["Survey result", "Feedback record", "Acceptance decision", "Adoption risk"]
        },
        {
            "metric": "Production Incidents",
            "question": "Is the AI capability creating operational risk after go-live?",
            "evidence": ["Incident count", "Severity", "Root cause", "CAPA or remediation"]
        },
        {
            "metric": "Support Effectiveness",
            "question": "Can the organization support the AI capability after the demo team leaves?",
            "evidence": ["Support owner", "Runbook", "Ticket response time", "Resolution SLA"]
        },
        {
            "metric": "Ownership Continuity",
            "question": "Is there clear ownership from pilot through production?",
            "evidence": ["Business owner", "Support owner", "Platform owner", "Adoption owner"]
        }
    ],
    "positioning_statement": "Platform B does not stop at AI deployment. It continuously assures whether the AI capability is adopted, used, supported, improving the intended business KPI, and still operationally trusted after production release.",
    "principle": "AI value is not proven by a successful pilot. It is proven by sustained adoption, measurable KPI improvement, operational supportability, and reconstructable production evidence."
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

    data["platform_b_business_value_assurance_kpi_evidence_patch"] = BUSINESS_VALUE_ASSURANCE
    data["platform_b_architecture_change"] = False
    data["platform_b_lifecycle_sequence"] = LIFECYCLE_SEQUENCE

    if "blueprints" in data and isinstance(data["blueprints"], list):
        for bp in data["blueprints"]:
            if not isinstance(bp, dict):
                continue

            bp["architecture_change"] = False
            bp["business_value_assurance"] = BUSINESS_VALUE_ASSURANCE

            bp["questions_answered"] = add_unique(
                bp.get("questions_answered", []),
                [
                    "Did the AI capability produce measurable business value after production deployment?",
                    "Can adoption, usage, KPI improvement, support effectiveness, ownership continuity, and production incidents be reconstructed?",
                    "Is the business value of the AI capability sustained after go-live?"
                ]
            )

            assessment = bp.get("sample_blueprint_assessment", {})
            if not isinstance(assessment, dict):
                assessment = {}

            assessment["business_value_assurance_state"] = "KPI_EVIDENCE_AND_CONTINUOUS_VALUE_MONITORING_REQUIRED"
            assessment["architecture_change"] = False
            assessment["adoption_rate_required"] = True
            assessment["usage_metrics_required"] = True
            assessment["business_kpi_improvement_required"] = True
            assessment["operational_metrics_required"] = True
            assessment["user_acceptance_required"] = True
            assessment["production_incidents_required"] = True
            assessment["support_effectiveness_required"] = True
            assessment["ownership_continuity_required"] = True
            assessment["continuous_value_monitoring_required"] = True
            bp["sample_blueprint_assessment"] = assessment

    if "sample_integration_assessment" in data and isinstance(data["sample_integration_assessment"], dict):
        assessment = data["sample_integration_assessment"]
        assessment["business_value_assurance_state"] = "ACTIVE"
        assessment["architecture_change"] = False
        assessment["business_value_assurance"] = BUSINESS_VALUE_ASSURANCE
        assessment["evidence_automation_targets"] = add_unique(
            assessment.get("evidence_automation_targets", []),
            BUSINESS_VALUE_ASSURANCE["evidence_objects"]
        )
        assessment["continuous_monitoring_targets"] = add_unique(
            assessment.get("continuous_monitoring_targets", []),
            BUSINESS_VALUE_ASSURANCE["continuous_monitoring_signals"]
        )
        assessment["implementation_priority"] = add_unique(
            assessment.get("implementation_priority", []),
            [
                "Capture baseline KPI before production deployment.",
                "Measure adoption rate after go-live.",
                "Measure actual usage against intended users and workflows.",
                "Compare target KPI against actual KPI after deployment.",
                "Monitor support effectiveness and production incidents.",
                "Escalate if adoption declines, KPI degrades, ownership gaps appear, or duplicate AI initiatives emerge."
            ]
        )

    save_json(path, data)
    print(f"PATCHED: {path}")

def html_escape(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def metric_cards():
    cards = []
    for item in BUSINESS_VALUE_ASSURANCE["business_value_metrics"]:
        evidence = "".join([f"<li>{html_escape(x)}</li>" for x in item["evidence"]])
        cards.append(f"""
        <div class="kpi-evidence-card">
            <div class="kpi-metric">{html_escape(item["metric"])}</div>
            <h3>{html_escape(item["question"])}</h3>
            <ul>{evidence}</ul>
        </div>
        """)
    return "\n".join(cards)

HTML_BLOCK = f"""
<style>
.platform-b-kpi-wrap {{
    margin: 28px 0;
    padding: 24px;
    border-radius: 24px;
    border: 1px solid rgba(255,255,255,.12);
    background: linear-gradient(135deg, rgba(34,197,94,.10), rgba(255,122,24,.08));
}}
.platform-b-kpi-head {{
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: flex-start;
    margin-bottom: 18px;
}}
.platform-b-kpi-head h2 {{
    margin: 0;
    font-size: 28px;
}}
.platform-b-kpi-head p {{
    color: #cbd5e1;
    line-height: 1.65;
    max-width: 960px;
}}
.platform-b-kpi-tag {{
    border: 1px solid rgba(34,197,94,.45);
    color: #86efac;
    border-radius: 999px;
    padding: 8px 12px;
    font-size: 12px;
    white-space: nowrap;
    background: rgba(34,197,94,.08);
}}
.platform-b-kpi-principle {{
    margin: 18px 0;
    padding: 16px;
    border-left: 4px solid #86efac;
    color: #e5e7eb;
    background: rgba(255,255,255,.045);
    border-radius: 14px;
    line-height: 1.6;
}}
.platform-b-kpi-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 16px;
}}
.kpi-evidence-card {{
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(255,255,255,.045);
    border-radius: 18px;
    padding: 18px;
}}
.kpi-evidence-card h3 {{
    margin: 8px 0 12px;
    color: #fff;
    font-size: 16px;
    line-height: 1.35;
}}
.kpi-evidence-card ul {{
    margin: 0;
    padding-left: 18px;
    color: #cbd5e1;
    line-height: 1.6;
}}
.kpi-metric {{
    color: #86efac;
    font-weight: 800;
    letter-spacing: .04em;
    text-transform: uppercase;
    font-size: 12px;
}}
.platform-b-kpi-signals {{
    margin-top: 18px;
    display: flex;
    flex-wrap: wrap;
    gap: 9px;
}}
.platform-b-kpi-signal {{
    border: 1px solid rgba(255,255,255,.12);
    background: rgba(255,255,255,.045);
    border-radius: 999px;
    padding: 8px 12px;
    color: #d8dee9;
    font-size: 13px;
}}
</style>

<section class="platform-b-kpi-wrap">
    <div class="platform-b-kpi-head">
        <div>
            <h2>Business Value Assurance / KPI Evidence</h2>
            <p>
                No architecture change. This deepens the existing Evidence and Continuous Assurance layers by proving
                whether AI is adopted, used in production workflows, improving the intended business KPI, supported
                operationally, and still trustworthy after go-live.
            </p>
        </div>
        <span class="platform-b-kpi-tag">Evidence + Continuous Assurance</span>
    </div>

    <div class="platform-b-kpi-principle">
        {html_escape(BUSINESS_VALUE_ASSURANCE["principle"])}
    </div>

    <div class="platform-b-kpi-grid">
        {metric_cards()}
    </div>

    <div class="platform-b-kpi-signals">
        {"".join([f'<span class="platform-b-kpi-signal">{html_escape(x)}</span>' for x in BUSINESS_VALUE_ASSURANCE["continuous_monitoring_signals"]])}
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

Path("platform_b_business_value_assurance_kpi_evidence_patch_v1_summary.json").write_text(
    json.dumps(BUSINESS_VALUE_ASSURANCE, indent=2, ensure_ascii=False),
    encoding="utf-8"
)

Path("platform_b_business_value_assurance_kpi_evidence_patch_v1_urls.txt").write_text(
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
print("Platform B Business Value Assurance / KPI Evidence Patch completed.")
print("Marker:", PATCH_MARKER)
print("Architecture change: False")
print("Lifecycle:", LIFECYCLE_SEQUENCE)
