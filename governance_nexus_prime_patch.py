from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_GOVERNANCE_NEXUS_PRIME_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Governance Nexus Prime already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_GOVERNANCE_NEXUS_PRIME_ENGINE_V1_ACTIVE
# ============================================================

IRLT_GOVERNANCE_NEXUS_PRIME_V1 = [
    {
        "prime": "Commercial Readiness Core",
        "synchronization": 100,
        "state": "Operational"
    },
    {
        "prime": "Inspection Defense Matrix",
        "synchronization": 99,
        "state": "Protected"
    },
    {
        "prime": "Evidence Integrity Nexus",
        "synchronization": 100,
        "state": "Verified"
    },
    {
        "prime": "Cold Chain Coordination",
        "synchronization": 96,
        "state": "Stable"
    },
    {
        "prime": "CAPA Recovery Governance",
        "synchronization": 92,
        "state": "Observed"
    },
    {
        "prime": "Dose Traceability Command",
        "synchronization": 100,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/governance-nexus-prime")
def irlt_governance_nexus_prime():

    prime_score = round(
        sum(x["synchronization"] for x in IRLT_GOVERNANCE_NEXUS_PRIME_V1)
        / len(IRLT_GOVERNANCE_NEXUS_PRIME_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Governance Nexus Prime Engine</title>

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

        <h1>Governance Nexus Prime Engine</h1>

        <p>
            Enterprise governance nexus prime environment for
            commercialization intelligence synchronization,
            operational survivability orchestration,
            inspection defense convergence,
            and radiopharma governance command continuity.
        </p>

        <div class="score">
            {{ prime_score }}%
        </div>

        <div class="grid">

            {% for row in prime %}

            <div class="card">

                <h2>{{ row.prime }}</h2>

                <p>
                    Synchronization Index: {{ row.synchronization }}%
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
    prime=IRLT_GOVERNANCE_NEXUS_PRIME_V1,
    prime_score=prime_score
    )


@app.route("/irlt-commercial-readiness/governance-nexus-prime/api")
def irlt_governance_nexus_prime_api():

    return jsonify({
        "prime_score": round(
            sum(x["synchronization"] for x in IRLT_GOVERNANCE_NEXUS_PRIME_V1)
            / len(IRLT_GOVERNANCE_NEXUS_PRIME_V1)
        ),
        "prime": IRLT_GOVERNANCE_NEXUS_PRIME_V1
    })

# ============================================================
# END IRLT_GOVERNANCE_NEXUS_PRIME_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Governance Nexus Prime Engine appended successfully.")
