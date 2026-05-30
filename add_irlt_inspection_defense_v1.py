from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_INSPECTION_QUESTION_DEFENSE_V1_ACTIVE"

if MARKER in text:
    print("IRLT Inspection Question Defense already exists.")
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
# IRLT_INSPECTION_QUESTION_DEFENSE_V1_ACTIVE
# ============================================================

@app.route("/irlt-commercial-readiness/inspection-defense")
@app.route("/rlttrust/inspection-defense")
def irlt_inspection_question_defense_v1():

    questions = [
        {"q": "Can you prove release readiness?", "e": "QA disposition, QC results, batch review, deviation status", "score": 96, "status": "Defensible"},
        {"q": "Can you trace isotope-to-patient custody?", "e": "Custody record, shipment evidence, receiving confirmation, treatment handoff", "score": 97, "status": "Verified"},
        {"q": "Can you defend audit trail review?", "e": "Critical event review, reviewer accountability, periodic review evidence", "score": 95, "status": "Controlled"},
        {"q": "Can you prove CAPA closure?", "e": "Deviation linkage, root cause, effectiveness check, QA closure", "score": 93, "status": "Review Required"},
        {"q": "Can you defend training readiness?", "e": "Role training, GMP readiness, access alignment, training drift check", "score": 95, "status": "Ready"},
        {"q": "Can leadership defend commercialization readiness?", "e": "Command center, passport, trust score, evidence lineage", "score": 98, "status": "Executive Ready"}
    ]

    overall = round(sum(x["score"] for x in questions) / len(questions))

    html = """
    <html>
    <head>
        <title>IRLT Inspection Question Defense Engine</title>
        <style>
            body{margin:0;padding:38px;background:linear-gradient(135deg,#050608,#11151f,#050608);color:white;font-family:Arial,Segoe UI,sans-serif}
            h1{font-size:76px;color:#ff9f1c;margin:0 0 14px}
            h2{color:#ff9f1c}
            p{color:#c6cfdb;line-height:1.7}
            .hero,.panel{background:#151c27;border-radius:28px;padding:30px;margin-bottom:24px;border:1px solid rgba(255,255,255,.08)}
            .score{font-size:96px;color:#ff9f1c;font-weight:900}
            table{width:100%;border-collapse:collapse}
            th,td{padding:14px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left}
            th{color:#ff9f1c;text-transform:uppercase;font-size:12px}
            .pill{display:inline-block;padding:8px 14px;border-radius:999px;background:rgba(255,122,24,.15);color:#ffd7ad}
        </style>
    </head>
    <body>

        <section class="hero">
            <h1>Inspection Question Defense Engine</h1>
            <p>
                Converts expected FDA, QA, internal audit, and executive questions into governed evidence,
                accountable records, readiness scores, and defensible inspection responses.
            </p>
            <div class="score">{{ overall }}%</div>
            <p>Inspection Defense Confidence</p>
        </section>

        <section class="panel">
            <h2>Question-to-Evidence Defense Matrix</h2>
            <table>
                <tr><th>Inspection Question</th><th>Evidence Defense</th><th>Score</th><th>Status</th></tr>
                {% for item in questions %}
                <tr>
                    <td>{{ item.q }}</td>
                    <td>{{ item.e }}</td>
                    <td>{{ item.score }}%</td>
                    <td><span class="pill">{{ item.status }}</span></td>
                </tr>
                {% endfor %}
            </table>
        </section>

        <section class="panel">
            <h2>Dissertation Value</h2>
            <p>
                This view demonstrates how COBIT-Chain converts governance evidence into inspection-ready
                answers rather than simply storing documents or displaying dashboards.
            </p>
        </section>

    </body>
    </html>
    """

    return render_template_string(html, questions=questions, overall=overall)


@app.route("/irlt-commercial-readiness/inspection-defense/api")
@app.route("/rlttrust/inspection-defense/api")
def irlt_inspection_question_defense_api_v1():
    return jsonify({
        "module": "IRLT Inspection Question Defense Engine",
        "status": "ACTIVE",
        "purpose": "Question-to-evidence inspection defense"
    })

# ============================================================
# END IRLT_INSPECTION_QUESTION_DEFENSE_V1
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Inspection Question Defense installed.")
