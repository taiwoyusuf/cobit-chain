from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_PASSPORT_V1_ACTIVE"

if MARKER in text:
    print("IRLT Governance Passport already exists.")
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
# IRLT_GOVERNANCE_PASSPORT_V1_ACTIVE
# ============================================================

@app.route("/irlt-commercial-readiness/passport")
@app.route("/rlttrust/passport")
def irlt_governance_passport_v1():

    modules = IRLT_DYNAMIC_MODULES_V2
    total = len(modules)
    score = round(sum(m["score"] for m in modules.values()) / total)

    status = "CERTIFIED" if score >= 96 else "CONDITIONAL" if score >= 90 else "AT RISK"

    evidence_ready = len([m for m in modules.values() if m["score"] >= 95])
    watch_items = len([m for m in modules.values() if m["score"] < 95])

    html = """
    <html>
    <head>
        <title>IRLT Governance Passport</title>
        <style>
            body{margin:0;padding:40px;background:linear-gradient(135deg,#050608,#11151f,#050608);color:white;font-family:Arial}
            h1{font-size:78px;color:#ff9f1c;margin:0 0 15px}
            h2{color:#ff9f1c}
            .hero,.panel{background:#151c27;border-radius:28px;padding:30px;margin-bottom:24px;border:1px solid rgba(255,255,255,.08)}
            .passport{font-size:96px;color:#ff9f1c;font-weight:900;margin:25px 0}
            .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:20px}
            .card{background:rgba(255,255,255,.04);border-radius:20px;padding:22px}
            .card strong{display:block;font-size:44px;color:#ff9f1c}
            table{width:100%;border-collapse:collapse}
            th,td{padding:14px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left}
            th{color:#ff9f1c;text-transform:uppercase;font-size:12px}
            a{color:#ff9f1c;text-decoration:none}
            @media(max-width:1200px){.grid{grid-template-columns:1fr}h1{font-size:44px}}
        </style>
    </head>
    <body>
        <section class="hero">
            <h1>IRLT Governance Passport</h1>
            <p>Portable governance readiness certificate for commercial IRLT scale-up, inspection survivability, operational trust, and evidence defensibility.</p>
            <div class="passport">{{ status }}</div>

            <div class="grid">
                <div class="card"><strong>{{ score }}%</strong>Passport Score</div>
                <div class="card"><strong>{{ total }}</strong>Governed Gates</div>
                <div class="card"><strong>{{ evidence_ready }}</strong>Evidence Ready</div>
                <div class="card"><strong>{{ watch_items }}</strong>Watch Items</div>
            </div>
        </section>

        <section class="panel">
            <h2>Passport Certification Basis</h2>
            <table>
                <tr><th>Gate</th><th>Category</th><th>Score</th><th>Status</th></tr>
                {% for slug, m in modules.items() %}
                <tr>
                    <td><a href="/irlt-commercial-readiness/module-v2/{{ slug }}">{{ m.title }}</a></td>
                    <td>{{ m.category }}</td>
                    <td>{{ m.score }}%</td>
                    <td>{{ m.status }}</td>
                </tr>
                {% endfor %}
            </table>
        </section>

        <section class="panel">
            <h2>Executive Passport Statement</h2>
            <p>
                This passport confirms whether IRLT commercial readiness can be defended with governed evidence.
                AI remains advisory only. Human governance remains the authoritative control layer.
            </p>
        </section>
    </body>
    </html>
    """

    return render_template_string(
        html,
        modules=modules,
        score=score,
        total=total,
        status=status,
        evidence_ready=evidence_ready,
        watch_items=watch_items
    )


@app.route("/irlt-commercial-readiness/passport/api")
@app.route("/rlttrust/passport/api")
def irlt_governance_passport_api_v1():

    modules = IRLT_DYNAMIC_MODULES_V2
    total = len(modules)
    score = round(sum(m["score"] for m in modules.values()) / total)

    return jsonify({
        "passport": "IRLT Governance Passport",
        "score": score,
        "status": "CERTIFIED" if score >= 96 else "CONDITIONAL" if score >= 90 else "AT RISK",
        "total_gates": total,
        "modules": modules
    })

# ============================================================
# END IRLT_GOVERNANCE_PASSPORT_V1
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Governance Passport installed.")
