from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_ISOTOPE_TO_PATIENT_EVIDENCE_GRAPH_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("Isotope-to-Patient Evidence Graph already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_ISOTOPE_TO_PATIENT_EVIDENCE_GRAPH_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Isotope-to-Patient Evidence Graph™
# Purpose: Governed traceability from isotope source to treatment readiness.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify

def _rlttrust_isotope_to_patient_graph_data():
    nodes = [
        {
            "id": "ISO-001",
            "stage": "Isotope Source",
            "title": "Isotope Origin & Receipt",
            "owner": "Radiopharma Supply / Radiation Safety",
            "score": 92,
            "status": "Strong",
            "evidence": [
                "Supplier certificate",
                "Activity receipt record",
                "Radioactive material receipt log",
                "Initial chain-of-custody record"
            ],
            "risk": "If source evidence is incomplete, downstream batch and material accountability become weak.",
            "governance_engine": "Radioactive Material Accountability Ledger™"
        },
        {
            "id": "MFG-002",
            "stage": "Manufacturing",
            "title": "Radiolabeling / Dose Preparation",
            "owner": "Manufacturing / Production",
            "score": 86,
            "status": "Governed Warning",
            "evidence": [
                "Batch manufacturing record",
                "Operator accountability",
                "Equipment readiness evidence",
                "SOP version confirmation"
            ],
            "risk": "Operator, equipment, or SOP mismatch can affect release defensibility.",
            "governance_engine": "SOPTrust™ + AccessTrust™"
        },
        {
            "id": "QC-003",
            "stage": "QC Testing",
            "title": "QC Method & Result Readiness",
            "owner": "QC / QA",
            "score": 84,
            "status": "Governed Warning",
            "evidence": [
                "QC result packet",
                "Method readiness evidence",
                "OOS/OOT status",
                "Result approval trail"
            ],
            "risk": "QC delay can consume the isotope usability window and compress QA release timing.",
            "governance_engine": "Release Defensibility Engine™"
        },
        {
            "id": "QA-004",
            "stage": "QA Release",
            "title": "Release Defensibility",
            "owner": "QA Release",
            "score": 78,
            "status": "At Risk",
            "evidence": [
                "QA release decision",
                "Deviation/CAPA disposition",
                "Environmental monitoring review",
                "Human approval lineage"
            ],
            "risk": "Release may be approved but not inspection-defensible if dependencies are unresolved.",
            "governance_engine": "CAPATrust™ + AuditVault™"
        },
        {
            "id": "SHIP-005",
            "stage": "Shipment",
            "title": "Cold-Chain & Custody Movement",
            "owner": "Logistics / Supply Chain",
            "score": 88,
            "status": "Strong",
            "evidence": [
                "Courier dispatch record",
                "Temperature/cold-chain evidence",
                "Custody transfer confirmation",
                "Exception log"
            ],
            "risk": "Courier or custody exception can threaten treatment-window readiness.",
            "governance_engine": "Chain-of-Custody Governance"
        },
        {
            "id": "SITE-006",
            "stage": "Treatment Site",
            "title": "Receipt & Nuclear Medicine Readiness",
            "owner": "Treatment Site / Nuclear Medicine",
            "score": 81,
            "status": "Governed Warning",
            "evidence": [
                "Receipt confirmation",
                "Site readiness attestation",
                "Authorized user readiness",
                "Treatment coordination status"
            ],
            "risk": "Treatment-site readiness gap can waste a viable dose or delay patient care.",
            "governance_engine": "Treatment Coordination Governance"
        },
        {
            "id": "PAT-007",
            "stage": "Patient Slot",
            "title": "Patient-Slot Protection",
            "owner": "Treatment Coordination",
            "score": 79,
            "status": "At Risk",
            "evidence": [
                "Appointment readiness",
                "Dose-to-slot match",
                "Schedule confirmation",
                "Exception escalation record"
            ],
            "risk": "Patient-slot misalignment can convert a technically released dose into operational failure.",
            "governance_engine": "Patient Slot Protection Engine™"
        },
        {
            "id": "PASS-008",
            "stage": "Governance Passport",
            "title": "Dose Journey Passport",
            "owner": "QA / Compliance / Leadership",
            "score": 83,
            "status": "Governed Warning",
            "evidence": [
                "End-to-end evidence graph",
                "AuditVault™ verification",
                "Release defensibility score",
                "Inspection survivability packet"
            ],
            "risk": "If the journey is not passported, leadership lacks one defensible readiness artifact.",
            "governance_engine": "Governance Passport™ + AuditVault™"
        }
    ]

    edges = [
        {"from": "Isotope Source", "to": "Manufacturing", "dependency": "Material receipt and activity evidence must support batch start."},
        {"from": "Manufacturing", "to": "QC Testing", "dependency": "Manufacturing completion must link to QC sample/result readiness."},
        {"from": "QC Testing", "to": "QA Release", "dependency": "QC results and exceptions must be reviewable before release."},
        {"from": "QA Release", "to": "Shipment", "dependency": "Release decision must occur within the operational decay window."},
        {"from": "Shipment", "to": "Treatment Site", "dependency": "Custody and cold-chain evidence must prove controlled movement."},
        {"from": "Treatment Site", "to": "Patient Slot", "dependency": "Site receipt must align with appointment and authorized-treatment readiness."},
        {"from": "Patient Slot", "to": "Governance Passport", "dependency": "Final treatment readiness must be captured as a governed artifact."}
    ]

    auditor_questions = [
        {
            "question": "Can you prove the isotope source and radioactive material receipt?",
            "mapped_stage": "Isotope Source",
            "evidence_answer": "Supplier certificate, activity receipt record, radioactive material log, and custody entry.",
            "readiness": "Strong"
        },
        {
            "question": "Can you prove the batch was manufactured under the correct SOP and trained operators?",
            "mapped_stage": "Manufacturing",
            "evidence_answer": "Batch record, operator accountability, SOP version, and training alignment packet.",
            "readiness": "Governed Warning"
        },
        {
            "question": "Can QA defend release if QC or EM had timing pressure or exceptions?",
            "mapped_stage": "QA Release",
            "evidence_answer": "QC result packet, deviation/CAPA disposition, EM review, and release rationale.",
            "readiness": "At Risk"
        },
        {
            "question": "Can you prove the shipment remained controlled until receipt?",
            "mapped_stage": "Shipment",
            "evidence_answer": "Courier dispatch, custody transfer, temperature evidence, and exception log.",
            "readiness": "Strong"
        },
        {
            "question": "Can you prove the dose was aligned to the treatment slot?",
            "mapped_stage": "Patient Slot",
            "evidence_answer": "Appointment readiness, dose-to-slot confirmation, and treatment coordination evidence.",
            "readiness": "At Risk"
        }
    ]

    risk_signals = [
        {
            "signal": "QA release defensibility below 80%",
            "impact": "Release may be approved but weak under inspection challenge.",
            "control": "Trigger Release Defensibility Engine™ and require QA rationale."
        },
        {
            "signal": "Patient-slot readiness below 80%",
            "impact": "Dose may be viable but operationally at risk.",
            "control": "Trigger Patient Slot Protection Engine™ and treatment coordination escalation."
        },
        {
            "signal": "Treatment-site readiness warning",
            "impact": "Receipt, authorized user, or nuclear medicine readiness may create last-mile failure.",
            "control": "Require site readiness attestation before passport closure."
        },
        {
            "signal": "Evidence packet not fully passported",
            "impact": "Leadership lacks a single defensible artifact for the dose journey.",
            "control": "Generate Dose Journey Passport and link to AuditVault™."
        }
    ]

    average_score = round(sum(n["score"] for n in nodes) / len(nodes))

    if average_score >= 88:
        executive_status = "Strong — dose journey appears inspection-defensible."
    elif average_score >= 80:
        executive_status = "Governed Warning — journey is promising but needs evidence closure."
    elif average_score >= 70:
        executive_status = "At Risk — material, release, custody, or treatment readiness gaps remain."
    else:
        executive_status = "Critical — dose journey is not commercially defensible."

    return {
        "average_score": average_score,
        "executive_status": executive_status,
        "nodes": nodes,
        "edges": edges,
        "auditor_questions": auditor_questions,
        "risk_signals": risk_signals,
        "governance_note": "This graph is a governance assurance overlay. It does not replace MES, LIMS, ERP, Veeva, ServiceNow, CTMS, shipping platforms, or treatment scheduling systems."
    }


@app.route("/irlt-commercial-readiness/isotope-to-patient")
@app.route("/rlttrust/isotope-to-patient")
@app.route("/rlttrust/isotope-to-patient-evidence-graph")
def rlttrust_isotope_to_patient_evidence_graph():
    data = _rlttrust_isotope_to_patient_graph_data()

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Isotope-to-Patient Evidence Graph™ | RLTTrust™</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            :root {
                --orange: #ff7a18;
                --orange2: #ff9f1c;
                --amber: #ffd166;
                --charcoal: #07080c;
                --graphite: #151922;
                --panel: rgba(20, 24, 33, 0.88);
                --line: rgba(255,255,255,0.12);
                --text: #f4f7fb;
                --muted: #aeb6c6;
                --green: #37d67a;
                --red: #ff5c7a;
                --steel: #8d96a8;
            }

            body {
                margin: 0;
                font-family: Inter, Segoe UI, Arial, sans-serif;
                color: var(--text);
                background:
                    radial-gradient(circle at 9% 0%, rgba(255,122,24,0.24), transparent 30%),
                    radial-gradient(circle at 90% 12%, rgba(255,159,28,0.15), transparent 35%),
                    radial-gradient(circle at 50% 32%, rgba(255,255,255,0.05), transparent 28%),
                    linear-gradient(135deg, #050608 0%, #11151f 46%, #06070b 100%);
            }

            .wrap {
                max-width: 1900px;
                margin: 0 auto;
                padding: 34px 46px;
            }

            .hero {
                position: relative;
                overflow: hidden;
                border: 1px solid rgba(255,122,24,0.32);
                border-radius: 36px;
                padding: 36px;
                background:
                    linear-gradient(135deg, rgba(255,122,24,0.20), rgba(20,24,33,0.93) 38%, rgba(7,8,12,0.96)),
                    repeating-linear-gradient(90deg, rgba(255,255,255,0.025) 0 1px, transparent 1px 76px);
                box-shadow: 0 34px 120px rgba(0,0,0,0.56);
            }

            .hero:after {
                content: "";
                position: absolute;
                right: -150px;
                top: -190px;
                width: 600px;
                height: 600px;
                border-radius: 50%;
                border: 1px solid rgba(255,122,24,0.25);
                box-shadow: inset 0 0 80px rgba(255,122,24,0.10), 0 0 100px rgba(255,122,24,0.12);
            }

            .hero-grid {
                position: relative;
                z-index: 2;
                display: grid;
                grid-template-columns: minmax(0, 1.65fr) minmax(380px, 0.72fr);
                gap: 30px;
                align-items: stretch;
            }

            .eyebrow {
                color: var(--orange2);
                text-transform: uppercase;
                font-size: 12px;
                letter-spacing: .16em;
                font-weight: 950;
                text-shadow: 0 0 18px rgba(255,122,24,0.28);
            }

            h1 {
                margin: 12px 0;
                font-size: clamp(42px, 4.8vw, 84px);
                line-height: .92;
                letter-spacing: -.06em;
            }

            h2 {
                font-size: clamp(24px, 2vw, 36px);
                letter-spacing: -.03em;
                margin: 0 0 16px;
            }

            h3 {
                margin: 0 0 8px;
                letter-spacing: -.02em;
            }

            p {
                color: var(--muted);
                line-height: 1.55;
            }

            .score-card {
                border-radius: 30px;
                padding: 26px;
                background: linear-gradient(180deg, rgba(255,122,24,0.12), rgba(15,18,26,0.92));
                border: 1px solid rgba(255,122,24,0.34);
                box-shadow: 0 22px 80px rgba(0,0,0,0.42);
            }

            .score {
                font-size: clamp(76px, 7vw, 132px);
                line-height: .85;
                font-weight: 950;
                letter-spacing: -.07em;
                color: var(--orange2);
                text-shadow: 0 0 35px rgba(255,122,24,0.34);
                margin: 18px 0;
            }

            .nav {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-top: 22px;
            }

            .nav a {
                text-decoration: none;
                color: #f4f7fb;
                padding: 10px 14px;
                border-radius: 999px;
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,122,24,0.25);
                transition: transform .18s ease, border-color .18s ease, background .18s ease;
            }

            .nav a:hover {
                transform: translateY(-2px);
                border-color: rgba(255,122,24,0.72);
                background: rgba(255,122,24,0.13);
            }

            .section {
                margin-top: 32px;
            }

            .graph-shell {
                border: 1px solid rgba(255,122,24,0.25);
                border-radius: 34px;
                padding: 24px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.025)),
                    rgba(17,20,28,0.88);
                box-shadow: 0 28px 90px rgba(0,0,0,0.42), inset 0 1px 0 rgba(255,255,255,0.06);
                overflow: hidden;
            }

            .journey {
                display: grid;
                grid-template-columns: repeat(8, minmax(180px, 1fr));
                gap: 14px;
                overflow-x: auto;
                padding-bottom: 8px;
            }

            .node-card {
                position: relative;
                min-height: 330px;
                border-radius: 26px;
                padding: 18px;
                border: 1px solid rgba(255,255,255,0.12);
                background:
                    radial-gradient(circle at top right, rgba(255,122,24,0.16), transparent 35%),
                    linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.025)),
                    rgba(15,18,26,0.90);
                box-shadow: 0 20px 60px rgba(0,0,0,0.32);
            }

            .node-card:after {
                content: "→";
                position: absolute;
                right: -20px;
                top: 50%;
                transform: translateY(-50%);
                color: var(--orange2);
                font-size: 32px;
                font-weight: 900;
                text-shadow: 0 0 20px rgba(255,122,24,0.40);
                z-index: 3;
            }

            .node-card:last-child:after {
                display: none;
            }

            .node-id {
                color: #ffd7ad;
                font-size: 11px;
                font-weight: 950;
                letter-spacing: .11em;
                text-transform: uppercase;
            }

            .stage {
                display: inline-block;
                margin: 10px 0;
                padding: 7px 10px;
                border-radius: 999px;
                color: #fff2e6;
                background: rgba(255,122,24,0.12);
                border: 1px solid rgba(255,122,24,0.30);
                font-size: 11px;
                font-weight: 900;
            }

            .node-score {
                font-size: 44px;
                color: var(--orange2);
                font-weight: 950;
                letter-spacing: -.06em;
                margin: 8px 0;
            }

            .bar {
                height: 10px;
                border-radius: 999px;
                overflow: hidden;
                background: rgba(255,255,255,0.08);
                border: 1px solid rgba(255,255,255,0.06);
                margin: 10px 0 14px;
            }

            .bar span {
                display: block;
                height: 100%;
                border-radius: 999px;
                background: linear-gradient(90deg, #ff4d4d, #ff7a18, #ffd166, #37d67a);
                box-shadow: 0 0 18px rgba(255,122,24,0.30);
            }

            ul {
                margin: 10px 0 0 18px;
                padding: 0;
                color: var(--muted);
                line-height: 1.55;
                font-size: 13px;
            }

            .status {
                display: inline-block;
                padding: 7px 10px;
                border-radius: 999px;
                font-size: 11px;
                font-weight: 950;
                margin-bottom: 10px;
            }

            .strong {
                color: #b9ffd0;
                border: 1px solid rgba(55,214,122,0.38);
                background: rgba(55,214,122,0.10);
            }

            .warning {
                color: #ffe6a8;
                border: 1px solid rgba(255,209,102,0.38);
                background: rgba(255,209,102,0.10);
            }

            .risk {
                color: #ffc2c2;
                border: 1px solid rgba(255,92,122,0.38);
                background: rgba(255,92,122,0.10);
            }

            .grid-2 {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 18px;
            }

            .grid-3 {
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 18px;
            }

            .panel {
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 28px;
                padding: 22px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.025)),
                    rgba(20,24,33,0.88);
                box-shadow: 0 24px 70px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.05);
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
                padding: 15px;
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

            td strong {
                color: #fff2e6;
            }

            .footer-note {
                border: 1px solid rgba(255,122,24,0.28);
                background: rgba(255,122,24,0.08);
                color: #ffd7ad;
                border-radius: 20px;
                padding: 16px;
                margin-top: 18px;
            }

            @media (max-width: 1250px) {
                .hero-grid, .grid-2, .grid-3 {
                    grid-template-columns: 1fr;
                }
                .wrap {
                    padding: 24px;
                }
            }
        </style>
    </head>
    <body>
        <div class="wrap">
            <section class="hero">
                <div class="hero-grid">
                    <div>
                        <div class="eyebrow">RLTTrust™ Traceability Backbone</div>
                        <h1>Isotope-to-Patient Evidence Graph™</h1>
                        <p>
                            A governed end-to-end evidence graph that connects isotope source, radiopharma manufacturing,
                            QC readiness, QA release, shipment custody, treatment-site receipt, patient-slot protection,
                            and the final Dose Journey Passport.
                        </p>
                        <p>
                            This is the traceability layer that lets leadership answer whether a dose journey is operationally ready,
                            inspection-survivable, and defensible with governed evidence.
                        </p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness">Command Center</a>
                            <a href="/irlt-commercial-readiness/can-we-treat-tomorrow">Can We Treat Tomorrow?</a>
                            <a href="/irlt-commercial-readiness/passport">Governance Passport</a>
                            <a href="/irlt-commercial-readiness/isotope-to-patient/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Dose Journey Readiness</div>
                        <div class="score">{{ average_score }}%</div>
                        <h3>Executive Status</h3>
                        <p>{{ executive_status }}</p>
                        <p><strong style="color:#ffd7ad;">Governance Note:</strong> {{ governance_note }}</p>
                    </div>
                </div>
            </section>

            <section class="section">
                <div class="graph-shell">
                    <div class="eyebrow">Live Journey Graph</div>
                    <h2>From Isotope Source to Patient-Slot Readiness</h2>
                    <div class="journey">
                        {% for n in nodes %}
                        <div class="node-card">
                            <div class="node-id">{{ n.id }}</div>
                            <span class="stage">{{ n.stage }}</span>
                            <h3>{{ n.title }}</h3>
                            <div class="node-score">{{ n.score }}%</div>
                            <div class="bar"><span style="width: {{ n.score }}%;"></span></div>

                            {% if n.score >= 88 %}
                                <span class="status strong">{{ n.status }}</span>
                            {% elif n.score >= 80 %}
                                <span class="status warning">{{ n.status }}</span>
                            {% else %}
                                <span class="status risk">{{ n.status }}</span>
                            {% endif %}

                            <p><strong style="color:#fff2e6;">Owner:</strong> {{ n.owner }}</p>
                            <p><strong style="color:#fff2e6;">Engine:</strong> {{ n.governance_engine }}</p>
                            <p><strong style="color:#fff2e6;">Risk:</strong> {{ n.risk }}</p>

                            <h4 style="margin-bottom:4px;">Evidence</h4>
                            <ul>
                                {% for e in n.evidence %}
                                <li>{{ e }}</li>
                                {% endfor %}
                            </ul>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Dependency Chain</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>From</th>
                                <th>To</th>
                                <th>Governance Dependency</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for e in edges %}
                            <tr>
                                <td><strong>{{ e.from }}</strong></td>
                                <td><strong>{{ e.to }}</strong></td>
                                <td>{{ e.dependency }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Risk Signals</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Signal</th>
                                <th>Impact</th>
                                <th>Control</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for r in risk_signals %}
                            <tr>
                                <td><strong>{{ r.signal }}</strong></td>
                                <td>{{ r.impact }}</td>
                                <td>{{ r.control }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Auditor Question-to-Evidence Mapping™</h2>
                    <p>
                        This is what makes the graph powerful. It does not only show status.
                        It maps inspection questions directly to governed evidence packets.
                    </p>

                    <table>
                        <thead>
                            <tr>
                                <th>Auditor Question</th>
                                <th>Mapped Stage</th>
                                <th>Evidence Answer</th>
                                <th>Readiness</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for q in auditor_questions %}
                            <tr>
                                <td><strong>{{ q.question }}</strong></td>
                                <td>{{ q.mapped_stage }}</td>
                                <td>{{ q.evidence_answer }}</td>
                                <td>{{ q.readiness }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>

                    <div class="footer-note">
                        AI may help explain the evidence chain and surface gaps. It does not approve release,
                        approve treatment readiness, or replace QA/compliance authority.
                    </div>
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, **data)


@app.route("/irlt-commercial-readiness/isotope-to-patient/api")
@app.route("/rlttrust/isotope-to-patient/api")
def rlttrust_isotope_to_patient_evidence_graph_api():
    return jsonify(_rlttrust_isotope_to_patient_graph_data())

# ============================================================
# End Isotope-to-Patient Evidence Graph™
# ============================================================

'''

    # Add helpful command center nav links if the original nav anchor exists.
    nav_marker = "RLTTRUST_NAV_ISOTOPE_TO_PATIENT_LINK_V1"
    nav_old = '<a href="/irlt-commercial-readiness/api">API Summary</a>'
    nav_new = '''<!-- RLTTRUST_NAV_ISOTOPE_TO_PATIENT_LINK_V1 -->
                            <a href="/irlt-commercial-readiness/can-we-treat-tomorrow">Can We Treat Tomorrow</a>
                            <a href="/irlt-commercial-readiness/isotope-to-patient">Isotope-to-Patient Graph</a>
                            <a href="/irlt-commercial-readiness/api">API Summary</a>'''
    if nav_marker not in text and nav_old in text:
        text = text.replace(nav_old, nav_new, 1)
        print("Added RLTTrust navigation links to command center.")
    else:
        print("Command center nav link insertion skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted Isotope-to-Patient Evidence Graph successfully.")

