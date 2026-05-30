from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_COMMERCIALIZATION_RISK_HEATMAP_V1_ACTIVE"

if MARKER in text:
    print("IRLT Risk Heatmap already exists.")
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
# IRLT_COMMERCIALIZATION_RISK_HEATMAP_V1_ACTIVE
# ============================================================

@app.route("/irlt-commercial-readiness/risk-heatmap")
@app.route("/rlttrust/risk-heatmap")
def irlt_commercialization_risk_heatmap_v1():

    modules = IRLT_DYNAMIC_MODULES_V2

    categories = {}
    for slug, m in modules.items():
        cat = m.get("category", "Uncategorized")
        categories.setdefault(cat, []).append({"slug": slug, **m})

    heatmap = []
    for cat, items in categories.items():
        avg = round(sum(i["score"] for i in items) / len(items))
        risk = "LOW" if avg >= 96 else "MEDIUM" if avg >= 92 else "HIGH"
        heatmap.append({
            "category": cat,
            "score": avg,
            "risk": risk,
            "count": len(items)
        })

    heatmap = sorted(heatmap, key=lambda x: x["score"])
    constraints = sorted([{"slug": slug, **m} for slug, m in modules.items()], key=lambda x: x["score"])[:10]
    overall = round(sum(m["score"] for m in modules.values()) / len(modules))

    html = """
    <html>
    <head>
        <title>IRLT Commercialization Risk Heatmap</title>
        <style>
            body{margin:0;padding:38px;background:linear-gradient(135deg,#050608,#11151f,#050608);color:white;font-family:Arial,Segoe UI,sans-serif}
            h1{font-size:76px;color:#ff9f1c;margin:0 0 14px}
            h2{color:#ff9f1c}
            p{color:#c6cfdb;line-height:1.7}
            .hero,.panel{background:#151c27;border-radius:28px;padding:30px;margin-bottom:24px;border:1px solid rgba(255,255,255,.08)}
            .score{font-size:96px;color:#ff9f1c;font-weight:900}
            .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
            .card{background:rgba(255,255,255,.04);border-radius:22px;padding:24px;border:1px solid rgba(255,255,255,.08)}
            .card strong{display:block;font-size:44px;color:#ff9f1c}
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
            <h1>Commercialization Risk Heatmap</h1>
            <p>
                Executive heatmap showing commercialization risk exposure across quality,
                manufacturing, logistics, inspection, evidence, treatment, and governance domains.
            </p>
            <div class="score">{{ overall }}%</div>
            <p>Commercialization Risk-Adjusted Readiness</p>
        </section>

        <section class="panel">
            <h2>Domain Risk Heatmap</h2>
            <div class="grid">
                {% for h in heatmap %}
                <div class="card">
                    <h2>{{ h.category }}</h2>
                    <strong>{{ h.score }}%</strong>
                    <p>{{ h.count }} contributing gates</p>
                    <span class="pill">{{ h.risk }} RISK</span>
                </div>
                {% endfor %}
            </div>
        </section>

        <section class="panel">
            <h2>Top Risk Contributors</h2>
            <table>
                <tr><th>Gate</th><th>Category</th><th>Score</th><th>Status</th></tr>
                {% for c in constraints %}
                <tr>
                    <td><a href="/irlt-commercial-readiness/module-v2/{{ c.slug }}">{{ c.title }}</a></td>
                    <td>{{ c.category }}</td>
                    <td>{{ c.score }}%</td>
                    <td><span class="pill">{{ c.status }}</span></td>
                </tr>
                {% endfor %}
            </table>
        </section>

    </body>
    </html>
    """

    return render_template_string(html, heatmap=heatmap, constraints=constraints, overall=overall)


@app.route("/irlt-commercial-readiness/risk-heatmap/api")
@app.route("/rlttrust/risk-heatmap/api")
def irlt_commercialization_risk_heatmap_api_v1():
    return jsonify({
        "module": "IRLT Commercialization Risk Heatmap",
        "status": "ACTIVE"
    })

# ============================================================
# END IRLT_COMMERCIALIZATION_RISK_HEATMAP_V1
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Commercialization Risk Heatmap installed.")
