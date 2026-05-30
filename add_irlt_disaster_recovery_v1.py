from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_DISASTER_RECOVERY_GOVERNANCE_V1_ACTIVE"

if MARKER in text:
    print("IRLT Disaster Recovery Governance already exists.")
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
# IRLT_DISASTER_RECOVERY_GOVERNANCE_V1_ACTIVE
# ============================================================

@app.route("/irlt-commercial-readiness/disaster-recovery")
@app.route("/rlttrust/disaster-recovery")
def irlt_disaster_recovery_governance_v1():

    domains = [
        {"name": "DR Activation Criteria", "score": 96, "status": "Defined"},
        {"name": "RTO/RPO Governance", "score": 94, "status": "Controlled"},
        {"name": "Recovery Dependency Validation", "score": 93, "status": "Mapped"},
        {"name": "GMP Restart Gate", "score": 95, "status": "Ready"},
        {"name": "Backup Restore Proof", "score": 92, "status": "Monitored"},
        {"name": "Recovery Evidence Lineage", "score": 97, "status": "Verified"}
    ]

    overall = round(sum(x["score"] for x in domains) / len(domains))

    html = """
    <html>
    <head>
        <title>IRLT Disaster Recovery Governance Intelligence</title>
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
            <h1>Disaster Recovery Governance Intelligence</h1>
            <p>
                Governance oversight layer for IRLT recovery readiness, RTO/RPO assurance,
                cross-system recovery dependencies, GMP restart gates, backup proof,
                and recovery evidence lineage.
            </p>
            <div class="score">{{ overall }}%</div>
            <p>Recovery Governance Readiness</p>
        </section>

        <section class="panel">
            <h2>Recovery Governance Domains</h2>
            <table>
                <tr><th>Domain</th><th>Score</th><th>Status</th></tr>
                {% for d in domains %}
                <tr>
                    <td>{{ d.name }}</td>
                    <td>{{ d.score }}%</td>
                    <td><span class="pill">{{ d.status }}</span></td>
                </tr>
                {% endfor %}
            </table>
        </section>

        <section class="panel">
            <h2>GMP Restart Reasoning</h2>
            <p>
                Recovery is not considered defensible until backup restoration proof,
                data reconciliation, system dependency validation, QA approval,
                and GMP restart evidence are all complete.
            </p>
        </section>

    </body>
    </html>
    """

    return render_template_string(html, domains=domains, overall=overall)


@app.route("/irlt-commercial-readiness/disaster-recovery/api")
@app.route("/rlttrust/disaster-recovery/api")
def irlt_disaster_recovery_governance_api_v1():

    return jsonify({
        "module": "IRLT Disaster Recovery Governance Intelligence",
        "status": "ACTIVE",
        "purpose": "RTO/RPO, recovery dependency validation, GMP restart, and recovery evidence lineage"
    })

# ============================================================
# END IRLT_DISASTER_RECOVERY_GOVERNANCE_V1
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Disaster Recovery Governance installed.")
