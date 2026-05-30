from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_DEPENDENCY_GRAPH_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Dependency Graph View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_DEPENDENCY_GRAPH_VIEW_V1_ACTIVE
# ============================================================

IRLT_DEPENDENCY_GRAPH_V1 = [
    {
        "source": "Cold Chain Governance",
        "depends_on": "Shipment Timing, Dose Viability, QA Release",
        "risk": "Critical"
    },
    {
        "source": "Dose Traceability",
        "depends_on": "Manufacturing Records, Chain of Custody, Treatment Coordination",
        "risk": "Critical"
    },
    {
        "source": "Inspection Readiness",
        "depends_on": "Evidence Completeness, CAPA Closure, Training Readiness",
        "risk": "High"
    },
    {
        "source": "Commercial Release",
        "depends_on": "QA Approval, Batch Records, Environmental Monitoring, Cold Chain",
        "risk": "Critical"
    },
    {
        "source": "Governance Passport",
        "depends_on": "Trust Score, Evidence Lineage, Owner Validation, Control Mapping",
        "risk": "High"
    },
    {
        "source": "Executive Readiness",
        "depends_on": "All Operational Governance Domains",
        "risk": "Enterprise Critical"
    }
]

@app.route("/irlt-commercial-readiness/dependency-graph")
def irlt_dependency_graph():

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Dependency Graph</title>

        <style>

            body{
                margin:0;
                padding:40px;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.18), transparent 30%),
                    linear-gradient(135deg,#050608,#10151d,#050608);
                color:white;
                font-family:Arial;
            }

            h1{
                color:#ff9f1c;
                font-size:76px;
                margin-bottom:10px;
            }

            p{
                color:#bfc7d4;
                line-height:1.7;
                max-width:1150px;
            }

            .grid{
                display:grid;
                grid-template-columns:repeat(2,1fr);
                gap:20px;
                margin-top:30px;
            }

            .card{
                background:#161d28;
                border-radius:22px;
                padding:28px;
                border:1px solid rgba(255,255,255,0.08);
            }

            h2{
                color:#ff9f1c;
                margin-top:0;
            }

            .pill{
                display:inline-block;
                padding:8px 14px;
                border-radius:999px;
                background:rgba(255,122,24,0.15);
                border:1px solid rgba(255,122,24,0.35);
                margin-top:12px;
            }

        </style>

    </head>

    <body>

        <h1>IRLT Dependency Graph</h1>

        <p>
            Dependency intelligence view showing how major IRLT governance domains
            depend on each other across release, cold chain, dose traceability,
            evidence readiness, inspection defense, and executive commercialization confidence.
        </p>

        <div class="grid">

            {% for row in graph %}

            <div class="card">

                <h2>{{ row.source }}</h2>

                <p><b>Depends On:</b> {{ row.depends_on }}</p>

                <div class="pill">Risk Level: {{ row.risk }}</div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''', graph=IRLT_DEPENDENCY_GRAPH_V1)


@app.route("/irlt-commercial-readiness/dependency-graph/api")
def irlt_dependency_graph_api():

    return jsonify({
        "dependency_graph": IRLT_DEPENDENCY_GRAPH_V1
    })

# ============================================================
# END IRLT_DEPENDENCY_GRAPH_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Dependency Graph View appended successfully.")
