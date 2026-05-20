from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_RELEASE_CONSTELLATION_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Release Constellation Engine already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_RELEASE_CONSTELLATION_ENGINE_V1_ACTIVE
# ============================================================

IRLT_RELEASE_CONSTELLATION_V1 = [
    {
        "domain": "Batch Release Governance",
        "readiness": 97,
        "state": "Approved"
    },
    {
        "domain": "Inspection Defense",
        "readiness": 95,
        "state": "Protected"
    },
    {
        "domain": "Evidence Verification",
        "readiness": 99,
        "state": "Verified"
    },
    {
        "domain": "Cold Chain Coordination",
        "readiness": 92,
        "state": "Stable"
    },
    {
        "domain": "Deviation Recovery",
        "readiness": 85,
        "state": "Observed"
    },
    {
        "domain": "Dose Traceability",
        "readiness": 99,
        "state": "Certified"
    }
]

@app.route("/irlt-commercial-readiness/release-constellation")
def irlt_release_constellation():

    constellation_score = round(
        sum(x["readiness"] for x in IRLT_RELEASE_CONSTELLATION_V1)
        / len(IRLT_RELEASE_CONSTELLATION_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>Release Constellation Engine</title>

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

        <h1>Release Constellation Engine</h1>

        <p>
            Enterprise release governance environment for
            commercialization synchronization,
            operational release survivability,
            inspection defense continuity,
            and radiopharma release intelligence orchestration.
        </p>

        <div class="score">
            {{ constellation_score }}%
        </div>

        <div class="grid">

            {% for row in constellation %}

            <div class="card">

                <h2>{{ row.domain }}</h2>

                <p>
                    Readiness: {{ row.readiness }}%
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
    constellation=IRLT_RELEASE_CONSTELLATION_V1,
    constellation_score=constellation_score
    )


@app.route("/irlt-commercial-readiness/release-constellation/api")
def irlt_release_constellation_api():

    return jsonify({
        "constellation_score": round(
            sum(x["readiness"] for x in IRLT_RELEASE_CONSTELLATION_V1)
            / len(IRLT_RELEASE_CONSTELLATION_V1)
        ),
        "constellation": IRLT_RELEASE_CONSTELLATION_V1
    })

# ============================================================
# END IRLT_RELEASE_CONSTELLATION_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Release Constellation Engine appended successfully.")
