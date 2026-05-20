from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_NEURAL_MESH_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Neural Mesh already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_NEURAL_MESH_ENGINE_V1_ACTIVE
# ============================================================

IRLT_NEURAL_MESH_V1 = [
    {
        "mesh": "Commercial Intelligence",
        "synchronization": 96,
        "state": "Aligned"
    },
    {
        "mesh": "Inspection Cognition",
        "synchronization": 95,
        "state": "Protected"
    },
    {
        "mesh": "Evidence Correlation",
        "synchronization": 98,
        "state": "Verified"
    },
    {
        "mesh": "Cold Chain Coordination",
        "synchronization": 92,
        "state": "Stable"
    },
    {
        "mesh": "CAPA Escalation Awareness",
        "synchronization": 84,
        "state": "Observed"
    },
    {
        "mesh": "Dose Governance Intelligence",
        "synchronization": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/neural-mesh")
def irlt_neural_mesh():

    neural_score = round(
        sum(x["synchronization"] for x in IRLT_NEURAL_MESH_V1)
        / len(IRLT_NEURAL_MESH_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Governance Neural Mesh</title>

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
                font-size:72px;
                margin-bottom:10px;
            }

            p{
                color:#bfc7d4;
                line-height:1.7;
            }

            .score{
                font-size:120px;
                color:#ff9f1c;
                margin:30px 0;
            }

            .grid{
                display:grid;
                grid-template-columns:repeat(3,1fr);
                gap:20px;
                margin-top:30px;
            }

            .card{
                background:#161d28;
                border-radius:20px;
                padding:24px;
                border:1px solid rgba(255,255,255,0.08);
            }

            .card h2{
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

        <h1>Governance Neural Mesh</h1>

        <p>
            Enterprise governance cognition mesh for
            operational intelligence synchronization,
            commercialization trust orchestration,
            inspection survivability awareness,
            and radiopharma governance correlation.
        </p>

        <div class="score">
            {{ neural_score }}%
        </div>

        <div class="grid">

            {% for row in neural %}

            <div class="card">

                <h2>{{ row.mesh }}</h2>

                <p>
                    Synchronization: {{ row.synchronization }}%
                </p>

                <div class="pill">
                    {{ row.state }}
                </div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''',
    neural=IRLT_NEURAL_MESH_V1,
    neural_score=neural_score
    )


@app.route("/irlt-commercial-readiness/neural-mesh/api")
def irlt_neural_mesh_api():

    return jsonify({
        "neural_score": round(
            sum(x["synchronization"] for x in IRLT_NEURAL_MESH_V1)
            / len(IRLT_NEURAL_MESH_V1)
        ),
        "neural": IRLT_NEURAL_MESH_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_NEURAL_MESH_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Governance Neural Mesh appended successfully.")
