from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_EXECUTIVE_MISSION_CONTROL_V1_ACTIVE"

if MARKER in text:
    print("IRLT Executive Mission Control already exists.")
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
# IRLT_EXECUTIVE_MISSION_CONTROL_V1_ACTIVE
# ============================================================

@app.route("/irlt-commercial-readiness/mission-control")
@app.route("/rlttrust/mission-control")
def irlt_executive_mission_control_v1():

    modules = IRLT_DYNAMIC_MODULES_V2
    total = len(modules)
    score = round(sum(m["score"] for m in modules.values()) / total)

    strengths = sorted(
        [{"slug": slug, **m} for slug, m in modules.items()],
        key=lambda x: x["score"],
        reverse=True
    )[:8]

    risks = sorted(
        [{"slug": slug, **m} for slug, m in modules.items()],
        key=lambda x: x["score"]
    )[:8]

    passport = "READY" if score >= 96 else "CONDITIONAL" if score >= 90 else "AT RISK"

    html = """
    <html>
    <head>
        <title>IRLT Executive Mission Control</title>
        <style>
            body{margin:0;padding:38px;background:linear-gradient(135deg,#050608,#11151f,#050608);color:white;font-family:Arial,Segoe UI,sans-serif}
            h1{font-size:78px;color:#ff9f1c;margin:0 0 14px;letter-spacing:-0.05em}
            h2{color:#ff9f1c;margin-top:0}
            p{color:#c6cfdb;line-height:1.7}
            .hero,.panel{background:#151c27;border-radius:28px;padding:30px;margin-bottom:24px;border:1px solid rgba(255,255,255,.08)}
            .metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:18px;margin-top:28px}
            .metric{background:rgba(255,255,255,.04);border-radius:20px;padding:22px;border:1px solid rgba(255,255,255,.08)}
            .metric strong{display:block;font-size:42px;color:#ff9f1c}
            .grid{display:grid;grid-template-columns:1fr 1fr;gap:24px}
            table{width:100%;border-collapse:collapse}
            th,td{padding:14px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left}
            th{color:#ff9f1c;text-transform:uppercase;font-size:12px}
            .pill{display:inline-block;padding:8px 14px;border-radius:999px;background:rgba(255,122,24,.15);color:#ffd7ad}
            a{color:#ff9f1c;text-decoration:none}
            .status{font-size:72px;color:#ff9f1c;font-weight:900;margin:20px 0}
            @media(max-width:1200px){.metrics,.grid{grid-template-columns:1fr}h1{font-size:44px}}
        </style>
    </head>
    <body>

        <section class="hero">
            <h1>IRLT Executive Mission Control</h1>
            <p>
                Executive command cockpit answering the primary commercialization question:
                can leadership operationally defend IRLT readiness with governed evidence?
            </p>

            <div class="metrics">
                <div class="metric"><strong>{{ score }}%</strong>Commercial Readiness</div>
                <div class="metric"><strong>{{ score }}%</strong>Enterprise Trust</div>
                <div class="metric"><strong>{{ total }}</strong>Governed Gates</div>
                <div class="metric"><strong>{{ risks|length }}</strong>Watch Items</div>
                <div class="metric"><strong>{{ passport }}</strong>Passport Status</div>
            </div>
        </section>

        <section class="panel">
            <h2>Executive Readiness Decision</h2>
            <div class="status">{{ passport }}</div>
            <p>
                {% if passport == "READY" %}
                Commercial readiness is currently defensible with governed evidence, operational trust scoring,
                evidence lineage, and inspection survivability indicators.
                {% elif passport == "CONDITIONAL" %}
                Commercial readiness is conditionally defensible and requires executive review of the lowest-scoring
                readiness constraints before final launch confidence.
                {% else %}
                Commercial readiness is not currently defensible and requires governance escalation.
                {% endif %}
            </p>
        </section>

        <div class="grid">
            <section class="panel">
                <h2>Top Executive Strengths</h2>
                <table>
                    <tr><th>Gate</th><th>Category</th><th>Score</th><th>Status</th></tr>
                    {% for item in strengths %}
                    <tr>
                        <td><a href="/irlt-commercial-readiness/module-v2/{{ item.slug }}">{{ item.title }}</a></td>
                        <td>{{ item.category }}</td>
                        <td>{{ item.score }}%</td>
                        <td><span class="pill">{{ item.status }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>Top Executive Risks / Constraints</h2>
                <table>
                    <tr><th>Gate</th><th>Category</th><th>Score</th><th>Status</th></tr>
                    {% for item in risks %}
                    <tr>
                        <td><a href="/irlt-commercial-readiness/module-v2/{{ item.slug }}">{{ item.title }}</a></td>
                        <td>{{ item.category }}</td>
                        <td>{{ item.score }}%</td>
                        <td><span class="pill">{{ item.status }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>
        </div>

        <section class="panel">
            <h2>Mission Control Narrative</h2>
            <p>
                RLTTrust™ operates as a governance assurance and operational trust overlay above existing systems.
                It does not replace Veeva, MES, LIMS, ERP, ServiceNow, CTMS, logistics, or treatment systems.
                It converts distributed readiness signals into executive-defensible governance intelligence.
            </p>
        </section>

    </body>
    </html>
    """

    return render_template_string(
        html,
        score=score,
        total=total,
        strengths=strengths,
        risks=risks,
        passport=passport
    )


@app.route("/irlt-commercial-readiness/mission-control/api")
@app.route("/rlttrust/mission-control/api")
def irlt_executive_mission_control_api_v1():

    modules = IRLT_DYNAMIC_MODULES_V2
    total = len(modules)
    score = round(sum(m["score"] for m in modules.values()) / total)

    return jsonify({
        "mission_control": "IRLT Executive Mission Control",
        "score": score,
        "total_gates": total,
        "passport_status": "READY" if score >= 96 else "CONDITIONAL" if score >= 90 else "AT RISK",
        "modules": modules
    })

# ============================================================
# END IRLT_EXECUTIVE_MISSION_CONTROL_V1
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Executive Mission Control installed.")
