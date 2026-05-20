from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_QUANTUM_GOVERNANCE_ORCHESTRATOR_V1_ACTIVE"

if MARKER in text:
    print("Quantum Governance Orchestrator already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_QUANTUM_GOVERNANCE_ORCHESTRATOR_V1_ACTIVE
# ============================================================

IRLT_QUANTUM_GOVERNANCE_V1 = [
    {
        "vector": "Commercial Intelligence",
        "coherence": 97,
        "state": "Synchronized"
    },
    {
        "vector": "Inspection Survivability",
        "coherence": 95,
        "state": "Protected"
    },
    {
        "vector": "Evidence Correlation",
        "coherence": 99,
        "state": "Verified"
    },
    {
        "vector": "Cold Chain Coordination",
        "coherence": 92,
        "state": "Stable"
    },
    {
        "vector": "CAPA Escalation Mapping",
        "coherence": 85,
        "state": "Observed"
    },
    {
        "vector": "Dose Governance Continuity",
        "coherence": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/quantum-governance")
def irlt_quantum_governance():

    quantum_score = round(
        sum(x["coherence"] for x in IRLT_QUANTUM_GOVERNANCE_V1)
        / len(IRLT_QUANTUM_GOVERNANCE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Quantum Governance Orchestrator</title>

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

        <h1>Quantum Governance Orchestrator</h1>

        <p>
            Enterprise governance orchestration environment for
            operational coherence synchronization,
            commercialization survivability intelligence,
            radiopharma governance continuity,
            and inspection defense correlation mapping.
        </p>

        <div class="score">
            {{ quantum_score }}%
        </div>

        <div class="grid">

            {% for row in quantum %}

            <div class="card">

                <h2>{{ row.vector }}</h2>

                <p>
                    Coherence: {{ row.coherence }}%
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
    quantum=IRLT_QUANTUM_GOVERNANCE_V1,
    quantum_score=quantum_score
    )


@app.route("/irlt-commercial-readiness/quantum-governance/api")
def irlt_quantum_governance_api():

    return jsonify({
        "quantum_score": round(
            sum(x["coherence"] for x in IRLT_QUANTUM_GOVERNANCE_V1)
            / len(IRLT_QUANTUM_GOVERNANCE_V1)
        ),
        "quantum": IRLT_QUANTUM_GOVERNANCE_V1
    })

# ============================================================
# END IRLT_QUANTUM_GOVERNANCE_ORCHESTRATOR_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Quantum Governance Orchestrator appended successfully.")
