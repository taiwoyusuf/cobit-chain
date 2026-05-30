from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_ENTERPRISE_TRUST_SCORE_V1_ACTIVE"

if MARKER in text:
    print("IRLT Enterprise Trust Score already exists.")
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
# IRLT_ENTERPRISE_TRUST_SCORE_V1_ACTIVE
# ============================================================

@app.route("/irlt-commercial-readiness/enterprise-trust-score")
@app.route("/rlttrust/enterprise-trust-score")
def irlt_enterprise_trust_score_v1():

    modules = IRLT_DYNAMIC_MODULES_V2

    domains = [
        {"name": "Quality Trust", "filter": ["quality", "qa", "qc", "release"]},
        {"name": "Operational Trust", "filter": ["operational", "manufacturing", "readiness"]},
        {"name": "Evidence Trust", "filter": ["evidence", "lineage", "audit"]},
        {"name": "Inspection Trust", "filter": ["inspection", "audit", "defense"]},
        {"name": "Treatment Trust", "filter": ["treatment", "patient", "dose"]},
        {"name": "Governance Trust", "filter": ["governance", "passport", "trust"]}
    ]

    results = []

    for d in domains:
        selected = []
        for slug, m in modules.items():
            blob = (slug + " " + m.get("title","") + " " + m.get("category","") + " " + m.get("summary","")).lower()
            if any(word in blob for word in d["filter"]):
                selected.append(m["score"])

        score = round(sum(selected) / len(selected)) if selected else 0

        results.append({
            "domain": d["name"],
            "score": score,
            "items": len(selected),
            "status": "Trusted" if score >= 96 else "Monitored" if score >= 92 else "Attention"
        })

    overall = round(sum(x["score"] for x in results if x["score"] > 0) / len([x for x in results if x["score"] > 0]))

    html = """
    <html>
    <head>
        <title>IRLT Enterprise Trust Score</title>
        <style>
            body{margin:0;padding:38px;background:linear-gradient(135deg,#050608,#11151f,#050608);color:white;font-family:Arial,Segoe UI,sans-serif}
            h1{font-size:76px;color:#ff9f1c;margin:0 0 14px}
            h2{color:#ff9f1c}
            p{color:#c6cfdb;line-height:1.7}
            .hero,.panel{background:#151c27;border-radius:28px;padding:30px;margin-bottom:24px;border:1px solid rgba(255,255,255,.08)}
            .score{font-size:100px;color:#ff9f1c;font-weight:900}
            .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:22px}
            .card{background:rgba(255,255,255,.04);border-radius:22px;padding:24px;border:1px solid rgba(255,255,255,.08)}
            .card strong{display:block;font-size:46px;color:#ff9f1c}
            .pill{display:inline-block;padding:8px 14px;border-radius:999px;background:rgba(255,122,24,.15);color:#ffd7ad}
            @media(max-width:1200px){.grid{grid-template-columns:1fr}h1{font-size:44px}}
        </style>
    </head>
    <body>

        <section class="hero">
            <h1>Enterprise Trust Score</h1>
            <p>
                Executive trust-scoring layer aggregating quality, operational, evidence,
                inspection, treatment, and governance confidence into one commercial
                readiness trust score.
            </p>
            <div class="score">{{ overall }}%</div>
            <p>Enterprise Operational Trust Score</p>
        </section>

        <section class="panel">
            <h2>Trust Domains</h2>
            <div class="grid">
                {% for r in results %}
                <div class="card">
                    <h2>{{ r.domain }}</h2>
                    <strong>{{ r.score }}%</strong>
                    <p>{{ r.items }} contributing readiness gates</p>
                    <span class="pill">{{ r.status }}</span>
                </div>
                {% endfor %}
            </div>
        </section>

        <section class="panel">
            <h2>Executive Trust Interpretation</h2>
            <p>
                This score indicates whether leadership can defend commercialization readiness
                using governed evidence, operational controls, approval lineage, and inspection-ready
                trust indicators.
            </p>
        </section>

    </body>
    </html>
    """

    return render_template_string(html, results=results, overall=overall)


@app.route("/irlt-commercial-readiness/enterprise-trust-score/api")
@app.route("/rlttrust/enterprise-trust-score/api")
def irlt_enterprise_trust_score_api_v1():

    return jsonify({
        "module": "IRLT Enterprise Trust Score",
        "status": "ACTIVE"
    })

# ============================================================
# END IRLT_ENTERPRISE_TRUST_SCORE_V1
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Enterprise Trust Score installed.")
