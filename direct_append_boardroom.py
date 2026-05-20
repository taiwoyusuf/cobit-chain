from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_BOARDROOM_ORCHESTRATION_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Boardroom already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_BOARDROOM_ORCHESTRATION_ENGINE_V1_ACTIVE
# ============================================================

IRLT_BOARDROOM_STREAMS_V1 = [
    {
        "pillar": "Commercialization Readiness",
        "score": 96,
        "state": "Board Ready"
    },
    {
        "pillar": "Inspection Defense",
        "score": 94,
        "state": "Defensible"
    },
    {
        "pillar": "Dose Traceability",
        "score": 99,
        "state": "Verified"
    }
]

@app.route("/irlt-commercial-readiness/boardroom")
def irlt_boardroom():

    return render_template_string('''

    <html>

    <head>

        <title>Boardroom Orchestration</title>

        <style>

            body{
                background:#0b0f14;
                color:white;
                font-family:Arial;
                padding:40px;
            }

            .card{
                background:#1a2230;
                padding:20px;
                border-radius:18px;
                margin-bottom:20px;
            }

            h1{
                color:#ff9f1c;
                font-size:58px;
            }

            h2{
                color:#ff9f1c;
            }

        </style>

    </head>

    <body>

        <h1>Boardroom Orchestration</h1>

        {% for row in streams %}

        <div class="card">

            <h2>{{ row.pillar }}</h2>

            <p>Score: {{ row.score }}%</p>

            <p>Status: {{ row.state }}</p>

        </div>

        {% endfor %}

    </body>

    </html>

    ''', streams=IRLT_BOARDROOM_STREAMS_V1)


@app.route("/irlt-commercial-readiness/boardroom/api")
def irlt_boardroom_api():

    return jsonify(IRLT_BOARDROOM_STREAMS_V1)

# ============================================================
# END IRLT_BOARDROOM_ORCHESTRATION_ENGINE_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("Boardroom appended successfully.")
