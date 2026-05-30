from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_AI_GOVERNANCE_COPILOT_V1_ACTIVE"

if MARKER in text:
    print("IRLT AI Governance Copilot already exists.")
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
# IRLT_AI_GOVERNANCE_COPILOT_V1_ACTIVE
# ============================================================

@app.route("/irlt-commercial-readiness/copilot")
@app.route("/rlttrust/copilot")
def irlt_ai_governance_copilot_v1():

    modules = IRLT_DYNAMIC_MODULES_V2
    total = len(modules)
    score = round(sum(m["score"] for m in modules.values()) / total)

    lowest = sorted(
        [{"slug": slug, **m} for slug, m in modules.items()],
        key=lambda x: x["score"]
    )[:6]

    highest = sorted(
        [{"slug": slug, **m} for slug, m in modules.items()],
        key=lambda x: x["score"],
        reverse=True
    )[:6]

    html = """
    <html>
    <head>
        <title>IRLT AI Governance Copilot</title>
        <style>
            body{margin:0;padding:38px;background:linear-gradient(135deg,#050608,#11151f,#050608);color:white;font-family:Arial,Segoe UI,sans-serif}
            h1{font-size:78px;color:#ff9f1c;margin:0 0 14px;letter-spacing:-0.05em}
            h2{color:#ff9f1c;margin-top:0}
            p{color:#c6cfdb;line-height:1.7}
            .hero,.panel{background:#151c27;border-radius:28px;padding:30px;margin-bottom:24px;border:1px solid rgba(255,255,255,.08)}
            .grid{display:grid;grid-template-columns:1fr 1fr;gap:24px}
            .warning{font-size:34px;color:#ff9f1c;font-weight:900;margin:20px 0}
            table{width:100%;border-collapse:collapse}
            th,td{padding:14px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left}
            th{color:#ff9f1c;text-transform:uppercase;font-size:12px}
            .pill{display:inline-block;padding:8px 14px;border-radius:999px;background:rgba(255,122,24,.15);color:#ffd7ad}
            a{color:#ff9f1c;text-decoration:none}
            @media(max-width:1200px){.grid{grid-template-columns:1fr}h1{font-size:44px}}
        </style>
    </head>
    <body>

        <section class="hero">
            <h1>AI Governance Copilot</h1>
            <p>
                Governed AI advisory interface for IRLT commercialization readiness.
                The copilot explains readiness signals, risk drivers, and recommended human review actions.
            </p>
            <div class="warning">
                AI is advisory only. Human governance remains authoritative.
            </div>
        </section>

        <section class="panel">
            <h2>Governed AI Positioning</h2>
            <p>
                AI is not the source of truth. Governed evidence, human approvals, audit trails,
                operational controls, and validated system records remain authoritative.
                The copilot supports analysis only and does not approve release, treatment readiness,
                inspection readiness, or commercialization decisions.
            </p>
        </section>

        <div class="grid">
            <section class="panel">
                <h2>Copilot Risk Focus</h2>
                <table>
                    <tr><th>Gate</th><th>Score</th><th>Suggested Human Review</th></tr>
                    {% for item in lowest %}
                    <tr>
                        <td><a href="/irlt-commercial-readiness/module-v2/{{ item.slug }}">{{ item.title }}</a></td>
                        <td>{{ item.score }}%</td>
                        <td><span class="pill">Review dependency and evidence</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>Copilot Confidence Signals</h2>
                <table>
                    <tr><th>Gate</th><th>Score</th><th>Signal</th></tr>
                    {% for item in highest %}
                    <tr>
                        <td><a href="/irlt-commercial-readiness/module-v2/{{ item.slug }}">{{ item.title }}</a></td>
                        <td>{{ item.score }}%</td>
                        <td><span class="pill">Strong evidence basis</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>
        </div>

        <section class="panel">
            <h2>Example Copilot Recommendation</h2>
            <p>
                Current readiness score is {{ score }}% across {{ total }} governed gates.
                The copilot recommends prioritizing the lowest-scoring gates for human governance review before executive commercialization approval.
            </p>
            <p>
                Final decisions remain with QA, Compliance, Operations, and accountable leadership.
            </p>
        </section>

    </body>
    </html>
    """

    return render_template_string(
        html,
        modules=modules,
        total=total,
        score=score,
        lowest=lowest,
        highest=highest
    )


@app.route("/irlt-commercial-readiness/copilot/api")
@app.route("/rlttrust/copilot/api")
def irlt_ai_governance_copilot_api_v1():

    modules = IRLT_DYNAMIC_MODULES_V2
    score = round(sum(m["score"] for m in modules.values()) / len(modules))

    return jsonify({
        "module": "IRLT AI Governance Copilot",
        "ai_authority": "advisory_only",
        "human_governance": "authoritative",
        "readiness_score": score
    })

# ============================================================
# END IRLT_AI_GOVERNANCE_COPILOT_V1
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT AI Governance Copilot installed.")
