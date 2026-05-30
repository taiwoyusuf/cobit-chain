from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_COMMERCIAL_READINESS_COMMAND_CENTER_V1_ACTIVE"

if MARKER in text:
    print("IRLT Command Center already exists.")
    raise SystemExit()

# Ensure Flask imports
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
# IRLT_COMMERCIAL_READINESS_COMMAND_CENTER_V1_ACTIVE
# ============================================================

@app.route("/irlt-commercial-readiness/command-center")
@app.route("/rlttrust/command-center")
def irlt_commercial_readiness_command_center_v1():

    modules = IRLT_DYNAMIC_MODULES_V2

    total = len(modules)
    avg_score = round(sum(m["score"] for m in modules.values()) / total)

    critical = [
        {"slug": slug, **m}
        for slug, m in modules.items()
        if m["score"] < 95
    ]

    top_modules = sorted(
        [{"slug": slug, **m} for slug, m in modules.items()],
        key=lambda x: x["score"],
        reverse=True
    )[:8]

    watch_items = sorted(
        [{"slug": slug, **m} for slug, m in modules.items()],
        key=lambda x: x["score"]
    )[:8]

    categories = {}
    for slug, module in modules.items():
        cat = module.get("category", "Uncategorized")
        categories.setdefault(cat, []).append(module["score"])

    category_scores = [
        {
            "category": cat,
            "score": round(sum(scores) / len(scores)),
            "count": len(scores)
        }
        for cat, scores in categories.items()
    ]

    category_scores = sorted(category_scores, key=lambda x: x["score"], reverse=True)

    passport_status = "READY" if avg_score >= 95 else "CONDITIONAL" if avg_score >= 90 else "AT RISK"

    html = """
    <html>
    <head>
        <title>IRLT Commercial Readiness Governance Command Center</title>
        <style>
            body{
                margin:0;
                padding:38px;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.22), transparent 32%),
                    linear-gradient(135deg,#050608,#11151f,#050608);
                color:white;
                font-family:Arial,Segoe UI,sans-serif;
            }

            h1{
                font-size:78px;
                color:#ff9f1c;
                margin:0 0 14px;
                letter-spacing:-0.05em;
            }

            h2{
                color:#ff9f1c;
                margin-top:0;
            }

            p{
                color:#c6cfdb;
                line-height:1.7;
            }

            .hero,.panel{
                background:rgba(20,24,33,0.9);
                border:1px solid rgba(255,255,255,0.08);
                border-radius:28px;
                padding:30px;
                margin-bottom:24px;
            }

            .metrics{
                display:grid;
                grid-template-columns:repeat(5,1fr);
                gap:18px;
                margin-top:28px;
            }

            .metric{
                background:rgba(255,255,255,0.04);
                border:1px solid rgba(255,255,255,0.08);
                border-radius:20px;
                padding:22px;
            }

            .metric strong{
                display:block;
                font-size:44px;
                color:#ff9f1c;
            }

            .grid{
                display:grid;
                grid-template-columns:1fr 1fr;
                gap:24px;
            }

            table{
                width:100%;
                border-collapse:collapse;
            }

            th,td{
                padding:14px;
                border-bottom:1px solid rgba(255,255,255,0.08);
                text-align:left;
            }

            th{
                color:#ff9f1c;
                font-size:12px;
                text-transform:uppercase;
            }

            .pill{
                display:inline-block;
                padding:8px 14px;
                border-radius:999px;
                background:rgba(255,122,24,0.15);
                border:1px solid rgba(255,122,24,0.30);
                color:#ffd7ad;
                font-weight:700;
                font-size:12px;
            }

            a{
                color:#ff9f1c;
                text-decoration:none;
            }

            .passport{
                font-size:64px;
                color:#ff9f1c;
                font-weight:900;
                margin:18px 0;
            }

            @media(max-width:1200px){
                .metrics,.grid{
                    grid-template-columns:1fr;
                }
                h1{
                    font-size:44px;
                }
            }
        </style>
    </head>

    <body>

        <section class="hero">
            <h1>IRLT Commercial Readiness Governance Command Center</h1>

            <p>
                Executive governance cockpit for defending commercial IRLT readiness
                with governed evidence, operational trust scoring, inspection
                survivability, dependency visibility, and readiness intelligence.
            </p>

            <div class="metrics">
                <div class="metric">
                    <strong>{{ avg_score }}%</strong>
                    Enterprise Trust Score
                </div>

                <div class="metric">
                    <strong>{{ total }}</strong>
                    Governed Readiness Gates
                </div>

                <div class="metric">
                    <strong>{{ critical|length }}</strong>
                    Watch Items
                </div>

                <div class="metric">
                    <strong>{{ category_scores|length }}</strong>
                    Governance Domains
                </div>

                <div class="metric">
                    <strong>{{ passport_status }}</strong>
                    Passport Status
                </div>
            </div>
        </section>

        <div class="grid">

            <section class="panel">
                <h2>Top Readiness Strengths</h2>

                <table>
                    <tr>
                        <th>Gate</th>
                        <th>Category</th>
                        <th>Score</th>
                        <th>Status</th>
                    </tr>

                    {% for item in top_modules %}
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
                <h2>Executive Watch Items</h2>

                <table>
                    <tr>
                        <th>Gate</th>
                        <th>Category</th>
                        <th>Score</th>
                        <th>Status</th>
                    </tr>

                    {% for item in watch_items %}
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
            <h2>Governance Domain Heatmap</h2>

            <table>
                <tr>
                    <th>Domain</th>
                    <th>Average Score</th>
                    <th>Gates</th>
                    <th>Executive Interpretation</th>
                </tr>

                {% for row in category_scores %}
                <tr>
                    <td>{{ row.category }}</td>
                    <td>{{ row.score }}%</td>
                    <td>{{ row.count }}</td>
                    <td>
                        {% if row.score >= 96 %}
                            Strong and defensible
                        {% elif row.score >= 92 %}
                            Stable with monitoring
                        {% else %}
                            Requires executive attention
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </table>
        </section>

        <section class="panel">
            <h2>Governance Passport Reasoning</h2>

            <div class="passport">{{ passport_status }}</div>

            <p>
                Current commercial readiness posture is calculated from all governed
                IRLT readiness gates in the dynamic registry. The platform does not
                replace Veeva, MES, LIMS, ERP, ServiceNow, CTMS, logistics, or
                treatment systems. It acts as the governance assurance and operational
                trust overlay above them.
            </p>

            <p>
                Executive interpretation:
                {% if avg_score >= 95 %}
                    commercial readiness is currently defensible with governed evidence.
                {% elif avg_score >= 90 %}
                    commercial readiness is conditionally defensible and requires focused review of watch items.
                {% else %}
                    commercial readiness is not yet defensible and requires governance escalation.
                {% endif %}
            </p>
        </section>

    </body>
    </html>
    """

    return render_template_string(
        html,
        modules=modules,
        total=total,
        avg_score=avg_score,
        critical=critical,
        top_modules=top_modules,
        watch_items=watch_items,
        category_scores=category_scores,
        passport_status=passport_status
    )


@app.route("/irlt-commercial-readiness/command-center/api")
@app.route("/rlttrust/command-center/api")
def irlt_commercial_readiness_command_center_api_v1():

    modules = IRLT_DYNAMIC_MODULES_V2
    total = len(modules)
    avg_score = round(sum(m["score"] for m in modules.values()) / total)

    return jsonify({
        "overall_trust_score": avg_score,
        "total_gates": total,
        "passport_status": "READY" if avg_score >= 95 else "CONDITIONAL" if avg_score >= 90 else "AT RISK",
        "modules": modules
    })

# ============================================================
# END IRLT_COMMERCIAL_READINESS_COMMAND_CENTER_V1
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Commercial Readiness Command Center installed.")
