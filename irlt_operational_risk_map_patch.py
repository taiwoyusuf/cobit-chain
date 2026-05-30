from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_OPERATIONAL_RISK_MAP_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Operational Risk Map already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_OPERATIONAL_RISK_MAP_VIEW_V1_ACTIVE
# ============================================================

IRLT_OPERATIONAL_RISK_MAP_V1 = [
    {
        "risk": "Cold Chain Failure",
        "severity": "Critical",
        "impact": "Dose viability and treatment continuity risk"
    },
    {
        "risk": "Inspection Evidence Gap",
        "severity": "High",
        "impact": "Inspection defensibility exposure"
    },
    {
        "risk": "Release Governance Breakdown",
        "severity": "Critical",
        "impact": "Commercial shipment delay and compliance exposure"
    },
    {
        "risk": "CAPA Closure Drift",
        "severity": "Medium",
        "impact": "Operational governance inconsistency"
    },
    {
        "risk": "Training Readiness Gap",
        "severity": "High",
        "impact": "Operational execution and audit readiness risk"
    },
    {
        "risk": "Cross-System Visibility Failure",
        "severity": "Critical",
        "impact": "Leadership loses unified commercialization readiness visibility"
    }
]

@app.route("/irlt-commercial-readiness/operational-risk-map")
def irlt_operational_risk_map():

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Operational Risk Map</title>

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

            .critical{
                color:#ff4d4d;
                font-weight:bold;
            }

            .high{
                color:#ffb347;
                font-weight:bold;
            }

            .medium{
                color:#ffd966;
                font-weight:bold;
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

        <h1>IRLT Operational Risk Map</h1>

        <p>
            Executive operational risk visibility layer showing major commercialization,
            inspection, release, evidence, training, and cross-system governance risks
            across IRLT operations.
        </p>

        <div class="grid">

            {% for row in risks %}

            <div class="card">

                <h2>{{ row.risk }}</h2>

                <p><b>Impact:</b> {{ row.impact }}</p>

                <div class="pill">
                    Severity:
                    {% if row.severity == "Critical" %}
                        <span class="critical">{{ row.severity }}</span>
                    {% elif row.severity == "High" %}
                        <span class="high">{{ row.severity }}</span>
                    {% else %}
                        <span class="medium">{{ row.severity }}</span>
                    {% endif %}
                </div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''', risks=IRLT_OPERATIONAL_RISK_MAP_V1)


@app.route("/irlt-commercial-readiness/operational-risk-map/api")
def irlt_operational_risk_map_api():

    return jsonify({
        "risks": IRLT_OPERATIONAL_RISK_MAP_V1
    })

# ============================================================
# END IRLT_OPERATIONAL_RISK_MAP_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Operational Risk Map View appended successfully.")
