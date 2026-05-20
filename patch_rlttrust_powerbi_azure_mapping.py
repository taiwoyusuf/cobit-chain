from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_POWERBI_AZURE_DEPLOYMENT_MAPPING_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLTTrust Power BI + Azure Deployment Mapping already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_POWERBI_AZURE_DEPLOYMENT_MAPPING_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Power BI Executive Dashboard Mapping + Azure Deployment Verification
# Purpose: Provide Power BI-ready API datasets, dashboard design mapping,
#          Azure/local verification links, and executive reporting structure.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify, request, current_app
from datetime import datetime

def _rlttrust_powerbi_route_exists(route):
    try:
        return any(str(rule.rule) == route for rule in current_app.url_map.iter_rules())
    except Exception:
        return False


def _rlttrust_powerbi_azure_mapping_data():
    modules = [
        {"module_id": 1, "module": "Executive Summary", "route": "/irlt-commercial-readiness/executive-summary", "domain": "Executive", "score": 94, "risk_level": "Low", "buyer_value": "One-page boardroom story"},
        {"module_id": 2, "module": "Commercial Package", "route": "/irlt-commercial-readiness/commercial-package", "domain": "Commercial", "score": 95, "risk_level": "Low", "buyer_value": "Brochure-style buyer packaging"},
        {"module_id": 3, "module": "Product Launchpad", "route": "/irlt-commercial-readiness/launchpad", "domain": "Navigation", "score": 95, "risk_level": "Low", "buyer_value": "Unified product home"},
        {"module_id": 4, "module": "Buyer Demo", "route": "/irlt-commercial-readiness/buyer-demo", "domain": "Commercial", "score": 92, "risk_level": "Low", "buyer_value": "Buyer story and objection handling"},
        {"module_id": 5, "module": "Command Center", "route": "/irlt-commercial-readiness", "domain": "Readiness", "score": 86, "risk_level": "Medium", "buyer_value": "Executive operational cockpit"},
        {"module_id": 6, "module": "Can We Treat Tomorrow?", "route": "/irlt-commercial-readiness/can-we-treat-tomorrow", "domain": "Treatment Readiness", "score": 82, "risk_level": "Medium", "buyer_value": "Tomorrow treatment readiness"},
        {"module_id": 7, "module": "Isotope-to-Patient Evidence Graph", "route": "/irlt-commercial-readiness/isotope-to-patient", "domain": "Dose Journey", "score": 83, "risk_level": "Medium", "buyer_value": "End-to-end isotope-to-patient traceability"},
        {"module_id": 8, "module": "Radioactive Material Ledger", "route": "/irlt-commercial-readiness/radioactive-material-ledger", "domain": "Radiation Safety", "score": 82, "risk_level": "Medium", "buyer_value": "Material accountability and reconciliation"},
        {"module_id": 9, "module": "Release Defensibility", "route": "/irlt-commercial-readiness/release-defensibility", "domain": "QA Release", "score": 81, "risk_level": "Medium", "buyer_value": "QA release evidence defense"},
        {"module_id": 10, "module": "Inspection Tomorrow", "route": "/irlt-commercial-readiness/inspection-tomorrow", "domain": "Inspection", "score": 80, "risk_level": "Medium", "buyer_value": "Inspection exposure simulation"},
        {"module_id": 11, "module": "Auditor Evidence Engine", "route": "/irlt-commercial-readiness/auditor-question-evidence", "domain": "Audit Response", "score": 85, "risk_level": "Low", "buyer_value": "Question-to-evidence mapping"},
        {"module_id": 12, "module": "Governance Black Box", "route": "/irlt-commercial-readiness/governance-black-box", "domain": "Governance Memory", "score": 86, "risk_level": "Low", "buyer_value": "Human decision and AI advisory timeline"},
        {"module_id": 13, "module": "Patient Slot Protection", "route": "/irlt-commercial-readiness/patient-slot-protection", "domain": "Patient Slot", "score": 79, "risk_level": "Medium", "buyer_value": "Dose-to-slot readiness protection"},
        {"module_id": 14, "module": "Network Readiness Mesh", "route": "/irlt-commercial-readiness/network-readiness-mesh", "domain": "Scale-Up", "score": 78, "risk_level": "Medium", "buyer_value": "Cross-site commercial readiness"},
        {"module_id": 15, "module": "Commercialization Stress Test", "route": "/irlt-commercial-readiness/commercialization-stress-test", "domain": "Stress Testing", "score": 76, "risk_level": "Medium", "buyer_value": "What-if commercial disruption simulation"},
        {"module_id": 16, "module": "Passport Factory", "route": "/irlt-commercial-readiness/passport-factory", "domain": "Executive Artifacts", "score": 88, "risk_level": "Low", "buyer_value": "Readiness passports and evidence artifacts"},
        {"module_id": 17, "module": "Pilot ROI", "route": "/irlt-commercial-readiness/pilot-roi", "domain": "ROI", "score": 84, "risk_level": "Medium", "buyer_value": "Pilot proposal and ROI justification"},
        {"module_id": 18, "module": "Demo Flow", "route": "/irlt-commercial-readiness/demo-flow", "domain": "Demo Control", "score": 90, "risk_level": "Low", "buyer_value": "Presentation-safe navigation"},
        {"module_id": 19, "module": "Final QA", "route": "/irlt-commercial-readiness/final-qa", "domain": "Verification", "score": 91, "risk_level": "Low", "buyer_value": "Route and API smoke testing"},
        {"module_id": 20, "module": "Handover Summary", "route": "/irlt-commercial-readiness/handover-summary", "domain": "Handover", "score": 93, "risk_level": "Low", "buyer_value": "Final inventory and next-step plan"}
    ]

    kpis = [
        {"kpi": "Overall Product Readiness", "value": 90, "unit": "%", "status": "Strong", "domain": "Executive"},
        {"kpi": "Radiopharma Specificity", "value": 96, "unit": "%", "status": "World-class", "domain": "Differentiation"},
        {"kpi": "Inspection Defensibility Value", "value": 94, "unit": "%", "status": "Strong", "domain": "Inspection"},
        {"kpi": "Buyer Demo Readiness", "value": 93, "unit": "%", "status": "Strong", "domain": "Commercial"},
        {"kpi": "Pilot Readiness", "value": 86, "unit": "%", "status": "Ready", "domain": "Pilot"},
        {"kpi": "Governance Maturity", "value": 91, "unit": "%", "status": "Strong", "domain": "Governance"},
        {"kpi": "Power BI Dashboard Readiness", "value": 88, "unit": "%", "status": "Ready", "domain": "Analytics"},
        {"kpi": "Azure Demo Readiness", "value": 85, "unit": "%", "status": "Verify After Deployment", "domain": "Deployment"}
    ]

    evidence_domains = [
        {"domain": "QA Release", "evidence_packet": "Release Defensibility Passport", "owner": "QA Release / QC / Compliance", "readiness": 81, "risk": "CAPA/EM evidence closure"},
        {"domain": "Dose Journey", "evidence_packet": "Dose Journey Passport", "owner": "QA / Supply Chain / Treatment Coordination", "readiness": 83, "risk": "Final receipt and slot linkage"},
        {"domain": "Radioactive Material", "evidence_packet": "Material Accountability Passport", "owner": "Radiation Safety / QA", "readiness": 82, "risk": "Final reconciliation"},
        {"domain": "Inspection", "evidence_packet": "Inspection Survivability Passport", "owner": "QA / Compliance", "readiness": 80, "risk": "Open major findings"},
        {"domain": "Patient Slot", "evidence_packet": "Patient Slot Protection Passport", "owner": "Treatment Coordination / Nuclear Medicine / QA", "readiness": 79, "risk": "Timing margin and site readiness"},
        {"domain": "Network Scale-Up", "evidence_packet": "Cross-Site Readiness Passport", "owner": "Commercialization Leadership / Operations", "readiness": 78, "risk": "Fallback capacity and release bottlenecks"},
        {"domain": "Audit Response", "evidence_packet": "Auditor Question-to-Evidence Passport", "owner": "QA / Compliance / Audit Response Team", "readiness": 85, "risk": "Human confirmation required"},
        {"domain": "Governance Memory", "evidence_packet": "Governance Black Box Passport", "owner": "QA / Compliance / Operations Leadership", "readiness": 86, "risk": "Decision links and stale events"}
    ]

    pilot_roi = [
        {"metric": "Pilot Scope", "value": 1, "unit": "site", "description": "One site, one dose journey, one release pathway"},
        {"metric": "Pilot Duration", "value": 8, "unit": "weeks", "description": "Recommended 6–8 week focused pilot"},
        {"metric": "Target Evidence Maturity", "value": 90, "unit": "%", "description": "Target maturity after evidence mapping"},
        {"metric": "Target Readiness Lift", "value": 16, "unit": "%", "description": "Baseline 72% to target 88%"},
        {"metric": "Expected Time Reduction", "value": 35, "unit": "%", "description": "Reduced manual evidence search and readiness preparation"},
        {"metric": "Directional Pilot ROI", "value": -23, "unit": "%", "description": "Demo assumption; refine with buyer finance data"},
        {"metric": "Annualized Value", "value": 178875, "unit": "$", "description": "Directional annualized value using default assumptions"}
    ]

    powerbi_visuals = [
        {"page": "Executive Overview", "visual": "KPI Cards", "dataset": "/irlt-commercial-readiness/powerbi/kpis/api", "purpose": "Show boardroom product readiness metrics."},
        {"page": "Module Readiness", "visual": "Bar Chart", "dataset": "/irlt-commercial-readiness/powerbi/modules/api", "purpose": "Compare readiness by RLTTrust™ module."},
        {"page": "Risk Heatmap", "visual": "Matrix / Heatmap", "dataset": "/irlt-commercial-readiness/powerbi/modules/api", "purpose": "Show domain risk levels by product module."},
        {"page": "Evidence Governance", "visual": "Table + Donut", "dataset": "/irlt-commercial-readiness/powerbi/evidence/api", "purpose": "Show evidence packets, owners, readiness, and risk."},
        {"page": "Pilot ROI", "visual": "Waterfall / KPI Cards", "dataset": "/irlt-commercial-readiness/powerbi/pilot-roi/api", "purpose": "Show pilot scope, value assumptions, readiness lift, and ROI."},
        {"page": "Route Health", "visual": "Status Table", "dataset": "/irlt-commercial-readiness/powerbi/routes/api", "purpose": "Show demo route availability and deployment readiness."}
    ]

    route_health = []
    for item in modules:
        exists = _rlttrust_powerbi_route_exists(item["route"])
        route_health.append({
            "module_id": item["module_id"],
            "module": item["module"],
            "route": item["route"],
            "exists_local": exists,
            "status": "Available" if exists else "Check Route",
            "score": 100 if exists else 0,
            "domain": item["domain"]
        })

    available_routes = sum(1 for route in route_health if route["exists_local"])
    total_routes = len(route_health)
    route_readiness = round((available_routes / total_routes) * 100) if total_routes else 0

    azure_base = request.args.get("azure_base", "https://cobitchain-app-demo.azurewebsites.net").rstrip("/")
    local_base = request.host_url.rstrip("/")

    azure_test_links = [
        {"name": "Executive Summary", "local": local_base + "/irlt-commercial-readiness/executive-summary", "azure": azure_base + "/irlt-commercial-readiness/executive-summary"},
        {"name": "Commercial Package", "local": local_base + "/irlt-commercial-readiness/commercial-package", "azure": azure_base + "/irlt-commercial-readiness/commercial-package"},
        {"name": "Product Launchpad", "local": local_base + "/irlt-commercial-readiness/launchpad", "azure": azure_base + "/irlt-commercial-readiness/launchpad"},
        {"name": "Final QA", "local": local_base + "/irlt-commercial-readiness/final-qa", "azure": azure_base + "/irlt-commercial-readiness/final-qa"},
        {"name": "Handover Summary", "local": local_base + "/irlt-commercial-readiness/handover-summary", "azure": azure_base + "/irlt-commercial-readiness/handover-summary"},
        {"name": "Power BI Mapping", "local": local_base + "/irlt-commercial-readiness/powerbi-mapping", "azure": azure_base + "/irlt-commercial-readiness/powerbi-mapping"}
    ]

    dashboard_pages = [
        {
            "page": "Page 1 — Executive Readiness Overview",
            "visuals": ["Overall Product Readiness KPI", "Radiopharma Specificity KPI", "Inspection Value KPI", "Buyer Demo Readiness KPI", "Top Module Readiness Bar Chart"],
            "message": "RLTTrust™ is commercially packaged and ready for executive demonstration."
        },
        {
            "page": "Page 2 — IRLT Governance Domains",
            "visuals": ["Evidence Domain Matrix", "Readiness by Evidence Packet", "Owner Accountability Table", "Risk Donut"],
            "message": "Readiness is tied to evidence, owners, and governance risk."
        },
        {
            "page": "Page 3 — Release / Dose / Material Defensibility",
            "visuals": ["Release Score Card", "Dose Journey Score", "Material Accountability Score", "Inspection Risk Matrix"],
            "message": "The strongest pilot value is release defensibility plus isotope-to-patient traceability."
        },
        {
            "page": "Page 4 — Pilot ROI and Expansion",
            "visuals": ["Pilot Scope Cards", "Readiness Lift KPI", "Evidence Maturity KPI", "Annualized Value Card", "Expansion Path Table"],
            "message": "Start with a focused pilot and expand to site/network rollout."
        },
        {
            "page": "Page 5 — Deployment Health",
            "visuals": ["Route Health Table", "Available Routes KPI", "Missing Routes KPI", "Azure Test Link Table"],
            "message": "Demo readiness can be checked before leadership or buyer presentation."
        }
    ]

    powerbi_next_steps = [
        "Open Power BI Desktop.",
        "Choose Get Data → Web.",
        "Use the API endpoints listed on this page.",
        "Load KPI, module, evidence, pilot ROI, and route-health datasets as separate tables.",
        "Create relationships using module_id where applicable.",
        "Build the five dashboard pages listed in the dashboard design section.",
        "Publish to Power BI Service when the Azure URL is live.",
        "Refresh the dataset after every Azure deployment or major product update."
    ]

    deployment_steps = [
        "Run this patch locally and confirm python -m py_compile app.py passes.",
        "Commit and push to GitHub main.",
        "Confirm Azure App Service deployment succeeds from GitHub CI/CD or connected deployment.",
        "Open the Azure Executive Summary route.",
        "Open the Azure Final QA route.",
        "Open the Azure Power BI Mapping route.",
        "Use the Azure API endpoints in Power BI instead of 127.0.0.1.",
        "After confirming Azure routes, create a stable tag for the deployed version."
    ]

    return {
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "product": "RLTTrust™ / IRLT Commercial Readiness Governance Command Center™",
        "platform": "COBIT-Chain™ / AssuranceLayer™ Platform A",
        "local_base": local_base,
        "azure_base": azure_base,
        "route_readiness": route_readiness,
        "available_routes": available_routes,
        "total_routes": total_routes,
        "kpis": kpis,
        "modules": modules,
        "evidence_domains": evidence_domains,
        "pilot_roi": pilot_roi,
        "powerbi_visuals": powerbi_visuals,
        "route_health": route_health,
        "azure_test_links": azure_test_links,
        "dashboard_pages": dashboard_pages,
        "powerbi_next_steps": powerbi_next_steps,
        "deployment_steps": deployment_steps,
        "governance_note": "Power BI Executive Dashboard Mapping is an analytics and reporting layer. AI remains advisory only. Human QA, compliance, radiation safety, operations, and leadership authority remain authoritative."
    }


@app.route("/irlt-commercial-readiness/powerbi-mapping")
@app.route("/irlt-commercial-readiness/powerbi-dashboard-map")
@app.route("/rlttrust/powerbi-mapping")
def rlttrust_powerbi_azure_dashboard_mapping():
    result = _rlttrust_powerbi_azure_mapping_data()

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Power BI + Azure Deployment Mapping | RLTTrust™</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            :root {
                --orange: #ff7a18;
                --orange2: #ff9f1c;
                --amber: #ffd166;
                --text: #f4f7fb;
                --muted: #aeb6c6;
            }

            body {
                margin: 0;
                font-family: Inter, Segoe UI, Arial, sans-serif;
                color: var(--text);
                background:
                    radial-gradient(circle at 10% 0%, rgba(255,122,24,0.30), transparent 30%),
                    radial-gradient(circle at 92% 8%, rgba(255,159,28,0.18), transparent 34%),
                    linear-gradient(135deg, #050608 0%, #11151f 46%, #06070b 100%);
            }

            .wrap {
                max-width: 1960px;
                margin: 0 auto;
                padding: 34px 46px;
            }

            .hero, .panel, .metric {
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 32px;
                padding: 26px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.025)),
                    rgba(20,24,33,0.88);
                box-shadow: 0 24px 70px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.05);
                backdrop-filter: blur(14px);
            }

            .hero {
                border-color: rgba(255,122,24,0.38);
                background:
                    linear-gradient(135deg, rgba(255,122,24,0.24), rgba(20,24,33,0.94) 39%, rgba(7,8,12,0.97)),
                    repeating-linear-gradient(90deg, rgba(255,255,255,0.026) 0 1px, transparent 1px 76px);
            }

            .hero-grid {
                display: grid;
                grid-template-columns: minmax(0, 1.55fr) minmax(420px, .82fr);
                gap: 34px;
                align-items: stretch;
            }

            .eyebrow {
                color: var(--orange2);
                text-transform: uppercase;
                font-size: 12px;
                letter-spacing: .18em;
                font-weight: 950;
            }

            h1 {
                margin: 10px 0;
                font-size: clamp(50px, 5.8vw, 100px);
                line-height: .88;
                letter-spacing: -.08em;
            }

            h2 {
                font-size: clamp(24px, 2vw, 36px);
                letter-spacing: -.03em;
                margin: 0 0 14px;
            }

            h3 { margin: 0 0 8px; }

            p {
                color: var(--muted);
                line-height: 1.55;
            }

            .score {
                font-size: clamp(74px, 7vw, 128px);
                line-height: .85;
                font-weight: 950;
                letter-spacing: -.07em;
                color: var(--orange2);
                text-shadow: 0 0 38px rgba(255,122,24,0.38);
                margin: 18px 0;
            }

            .nav {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-top: 22px;
            }

            .nav a, .open-link {
                text-decoration: none;
                color: #f4f7fb;
                padding: 10px 14px;
                border-radius: 999px;
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,122,24,0.25);
                display: inline-block;
            }

            .section { margin-top: 32px; }

            .grid-2 {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 18px;
            }

            .grid-4 {
                display: grid;
                grid-template-columns: repeat(4, minmax(0, 1fr));
                gap: 16px;
            }

            .metric strong {
                display: block;
                font-size: 34px;
                color: #fff2e6;
                letter-spacing: -.04em;
                margin-bottom: 6px;
            }

            .metric span {
                color: var(--orange2);
                font-size: 12px;
                font-weight: 900;
                text-transform: uppercase;
                letter-spacing: .08em;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                overflow: hidden;
                border-radius: 24px;
                background: rgba(20,24,33,0.88);
                border: 1px solid rgba(255,255,255,0.12);
            }

            th, td {
                padding: 14px;
                border-bottom: 1px solid rgba(255,255,255,0.10);
                text-align: left;
                vertical-align: top;
                color: var(--muted);
                font-size: 14px;
            }

            th {
                color: #fff2e6;
                background: rgba(255,122,24,0.10);
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: .09em;
            }

            td strong { color: #fff2e6; }

            .pill {
                display: inline-block;
                margin: 5px 6px 5px 0;
                padding: 8px 10px;
                border-radius: 999px;
                background: rgba(255,122,24,0.10);
                border: 1px solid rgba(255,122,24,0.30);
                color: #ffd7ad;
                font-size: 12px;
                font-weight: 850;
            }

            ul {
                margin: 10px 0 0 20px;
                padding: 0;
                color: var(--muted);
                line-height: 1.65;
            }

            .note {
                color: #ffd7ad;
                border: 1px solid rgba(255,122,24,0.30);
                background: rgba(255,122,24,0.08);
                border-radius: 18px;
                padding: 14px;
                margin-top: 14px;
            }

            @media (max-width: 1250px) {
                .hero-grid, .grid-2, .grid-4 { grid-template-columns: 1fr; }
                .wrap { padding: 24px; }
            }
        </style>
    </head>
    <body>
        <div class="wrap">
            <section class="hero">
                <div class="hero-grid">
                    <div>
                        <div class="eyebrow">RLTTrust™ Analytics + Deployment Layer</div>
                        <h1>Power BI + Azure Deployment Mapping</h1>
                        <p>
                            This page gives Power BI clean API tables and gives you a deployment verification map
                            for local and Azure testing.
                        </p>
                        <p><strong style="color:#ffd7ad;">Local base:</strong> {{ result.local_base }}</p>
                        <p><strong style="color:#ffd7ad;">Azure base:</strong> {{ result.azure_base }}</p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness/handover-summary">Handover Summary</a>
                            <a href="/irlt-commercial-readiness/final-qa">Final QA</a>
                            <a href="/irlt-commercial-readiness/powerbi-mapping/api">Full API</a>
                            <a href="/irlt-commercial-readiness/powerbi/kpis/api">KPI API</a>
                            <a href="/irlt-commercial-readiness/powerbi/modules/api">Module API</a>
                            <a href="/irlt-commercial-readiness/powerbi/evidence/api">Evidence API</a>
                        </div>
                    </div>

                    <div class="panel">
                        <div class="eyebrow">Local Route Readiness</div>
                        <div class="score">{{ result.route_readiness }}%</div>
                        <p>{{ result.available_routes }} of {{ result.total_routes }} mapped routes are registered locally.</p>
                        <div class="note">{{ result.governance_note }}</div>
                    </div>
                </div>
            </section>

            <section class="section">
                <div class="grid-4">
                    {% for kpi in result.kpis[:4] %}
                    <div class="metric">
                        <strong>{{ kpi.value }}{{ kpi.unit }}</strong>
                        <span>{{ kpi.kpi }}</span>
                        <p>{{ kpi.status }} — {{ kpi.domain }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Power BI API Endpoints</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Dataset</th>
                                <th>Endpoint</th>
                                <th>Use</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for visual in result.powerbi_visuals %}
                            <tr>
                                <td><strong>{{ visual.page }} — {{ visual.visual }}</strong></td>
                                <td><a class="open-link" href="{{ visual.dataset }}">{{ visual.dataset }}</a></td>
                                <td>{{ visual.purpose }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Power BI Next Steps</h2>
                    <ul>
                        {% for step in result.powerbi_next_steps %}
                        <li>{{ step }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Recommended Power BI Dashboard Pages</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Dashboard Page</th>
                                <th>Visuals</th>
                                <th>Message</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for page in result.dashboard_pages %}
                            <tr>
                                <td><strong>{{ page.page }}</strong></td>
                                <td>
                                    {% for visual in page.visuals %}
                                    <span class="pill">{{ visual }}</span>
                                    {% endfor %}
                                </td>
                                <td>{{ page.message }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Azure Test Links</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Page</th>
                                <th>Local</th>
                                <th>Azure</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for link in result.azure_test_links %}
                            <tr>
                                <td><strong>{{ link.name }}</strong></td>
                                <td><a class="open-link" href="{{ link.local }}">Local</a></td>
                                <td><a class="open-link" href="{{ link.azure }}">Azure</a></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Azure Deployment Steps</h2>
                    <ul>
                        {% for step in result.deployment_steps %}
                        <li>{{ step }}</li>
                        {% endfor %}
                    </ul>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Route Health for Power BI</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Module</th>
                                <th>Domain</th>
                                <th>Route</th>
                                <th>Status</th>
                                <th>Score</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for route in result.route_health %}
                            <tr>
                                <td><strong>{{ route.module }}</strong></td>
                                <td>{{ route.domain }}</td>
                                <td><a class="open-link" href="{{ route.route }}">Open</a></td>
                                <td>{{ route.status }}</td>
                                <td>{{ route.score }}%</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, result=result)


@app.route("/irlt-commercial-readiness/powerbi-mapping/api")
@app.route("/irlt-commercial-readiness/powerbi-dashboard-map/api")
@app.route("/rlttrust/powerbi-mapping/api")
def rlttrust_powerbi_azure_dashboard_mapping_api():
    return jsonify(_rlttrust_powerbi_azure_mapping_data())


@app.route("/irlt-commercial-readiness/powerbi/kpis/api")
@app.route("/rlttrust/powerbi/kpis/api")
def rlttrust_powerbi_kpis_api():
    return jsonify(_rlttrust_powerbi_azure_mapping_data()["kpis"])


@app.route("/irlt-commercial-readiness/powerbi/modules/api")
@app.route("/rlttrust/powerbi/modules/api")
def rlttrust_powerbi_modules_api():
    return jsonify(_rlttrust_powerbi_azure_mapping_data()["modules"])


@app.route("/irlt-commercial-readiness/powerbi/evidence/api")
@app.route("/rlttrust/powerbi/evidence/api")
def rlttrust_powerbi_evidence_api():
    return jsonify(_rlttrust_powerbi_azure_mapping_data()["evidence_domains"])


@app.route("/irlt-commercial-readiness/powerbi/pilot-roi/api")
@app.route("/rlttrust/powerbi/pilot-roi/api")
def rlttrust_powerbi_pilot_roi_api():
    return jsonify(_rlttrust_powerbi_azure_mapping_data()["pilot_roi"])


@app.route("/irlt-commercial-readiness/powerbi/routes/api")
@app.route("/rlttrust/powerbi/routes/api")
def rlttrust_powerbi_routes_api():
    return jsonify(_rlttrust_powerbi_azure_mapping_data()["route_health"])

# ============================================================
# End Power BI Executive Dashboard Mapping + Azure Deployment Verification
# ============================================================

'''

    # Add Power BI Mapping link to navigation where Handover Summary exists.
    nav_marker = "RLTTRUST_NAV_POWERBI_AZURE_MAPPING_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/handover-summary">Handover Summary</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_POWERBI_AZURE_MAPPING_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/powerbi-mapping">Power BI / Azure</a>',
            1
        )
        print("Added Power BI / Azure link to navigation.")
    else:
        print("Navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted RLTTrust Power BI + Azure Deployment Mapping successfully.")

