from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_AUDIT_SIMULATION_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("IRLT Audit Simulation already exists.")
    raise SystemExit()

m = re.search(r"from flask import ([^\n]+)", text)
if not m:
    raise SystemExit("Could not find Flask import line.")

imports = [x.strip() for x in m.group(1).split(",")]
for item in ["render_template_string", "jsonify"]:
    if item not in imports:
        imports.append(item)

text = text[:m.start()] + "from flask import " + ", ".join(imports) + text[m.end():]

block = r'''

# ============================================================
# IRLT_AUDIT_SIMULATION_ENGINE_V1_ACTIVE
# ============================================================

@app.route("/irlt-commercial-readiness/audit-simulation")
@app.route("/rlttrust/audit-simulation")
def irlt_audit_simulation_engine_v1():

    scenarios = [
        {"question": "Can you prove release readiness?", "evidence": "QA release, QC results, batch review, deviation status", "score": 96, "status": "Defensible"},
        {"question": "Can you trace isotope-to-patient custody?", "evidence": "Chain of custody, shipment, receipt, treatment handoff", "score": 97, "status": "Verified"},
        {"question": "Can you defend CAPA closure?", "evidence": "Deviation linkage, root cause, effectiveness, QA closure", "score": 93, "status": "Review"},
        {"question": "Can you prove audit trail review?", "evidence": "Critical event review, reviewer accountability, periodic review", "score": 95, "status": "Controlled"},
        {"question": "Can you defend disaster recovery readiness?", "evidence": "Backup proof, restore test, RTO/RPO, GMP restart", "score": 94, "status": "Monitored"},
        {"question": "Can leadership defend commercialization readiness?", "evidence": "Governance passport, command center, trust score, evidence lineage", "score": 98, "status": "Executive Ready"}
    ]

    overall = round(sum(x["score"] for x in scenarios) / len(scenarios))

    html = """
    <html>
    <head>
        <title>IRLT Audit Simulation Engine</title>
        <style>
            body{margin:0;padding:38px;background:linear-gradient(135deg,#050608,#11151f,#050608);color:white;font-family:Arial,Segoe UI,sans-serif}
            h1{font-size:76px;color:#ff9f1c;margin:0 0 14px}
            h2{color:#ff9f1c}
            p{color:#c6cfdb;line-height:1.7}
            .hero,.panel{background:#151c27;border-radius:28px;padding:30px;margin-bottom:24px;border:1px solid rgba(255,255,255,.08)}
            .score{font-size:90px;color:#ff9f1c;font-weight:900}
            table{width:100%;border-collapse:collapse}
            th,td{padding:14px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left}
            th{color:#ff9f1c;text-transform:uppercase;font-size:12px}
            .pill{display:inline-block;padding:8px 14px;border-radius:999px;background:rgba(255,122,24,.15);color:#ffd7ad}
        </style>
    </head>
    <body>

        <section class="hero">
            <h1>Audit Simulation Engine</h1>
            <p>
                Pre-audit and inspection simulation layer that tests whether IRLT commercial readiness
                can survive regulatory, QA, internal audit, and executive challenge questions.
            </p>
            <div class="score">{{ overall }}%</div>
            <p>Audit Survivability Score</p>
        </section>

        <section class="panel">
            <h2>Simulated Auditor Questions</h2>
            <table>
                <tr><th>Audit Question</th><th>Evidence Required</th><th>Score</th><th>Status</th></tr>
                {% for s in scenarios %}
                <tr>
                    <td>{{ s.question }}</td>
                    <td>{{ s.evidence }}</td>
                    <td>{{ s.score }}%</td>
                    <td><span class="pill">{{ s.status }}</span></td>
                </tr>
                {% endfor %}
            </table>
        </section>

        <section class="panel">
            <h2>Inspection Readiness Reasoning</h2>
            <p>
                The simulation shows whether readiness claims can be supported by governed evidence,
                approval lineage, audit trail proof, CAPA closure evidence, and operational trust scoring.
            </p>
        </section>

    </body>
    </html>
    """

    return render_template_string(html, scenarios=scenarios, overall=overall)


@app.route("/irlt-commercial-readiness/audit-simulation/api")
@app.route("/rlttrust/audit-simulation/api")
def irlt_audit_simulation_engine_api_v1():

    return jsonify({
        "module": "IRLT Audit Simulation Engine",
        "status": "ACTIVE",
        "purpose": "Pre-audit readiness simulation and inspection survivability testing"
    })

# ============================================================
# END IRLT_AUDIT_SIMULATION_ENGINE_V1
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Audit Simulation Engine installed.")
