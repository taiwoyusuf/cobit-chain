# -*- coding: utf-8 -*-

from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_EVIDENCE_VAULT_SIMPLE_V1_ACTIVE"

if MARKER in text:
    print("Already inserted.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# IRLT_EVIDENCE_VAULT_SIMPLE_V1_ACTIVE
# ============================================================

IRLT_EVIDENCE_SIMPLE = [
    {
        "id": "IRLT-001",
        "title": "Release Defensibility Packet",
        "status": "Verified",
        "score": 96
    },
    {
        "id": "IRLT-002",
        "title": "Isotope-to-Patient Evidence",
        "status": "Verified",
        "score": 94
    },
    {
        "id": "IRLT-003",
        "title": "Radioactive Material Ledger",
        "status": "Verified",
        "score": 92
    }
]

@app.route("/irlt-commercial-readiness/evidence-vault")
def irlt_evidence_vault_simple():

    html = '''

    <html>
    <head>
        <title>IRLT Evidence Vault</title>

        <style>

            body{
                background:#0b1020;
                color:white;
                font-family:Arial;
                padding:40px;
            }

            .card{
                background:#151c2e;
                border-radius:18px;
                padding:20px;
                margin-bottom:20px;
                border:1px solid #ff9f1c;
            }

            h1{
                color:#ff9f1c;
                font-size:48px;
            }

        </style>

    </head>

    <body>

        <h1>IRLT Evidence Vault</h1>

        {% for row in records %}

            <div class="card">

                <h2>{{ row.title }}</h2>

                <p><b>Evidence ID:</b> {{ row.id }}</p>

                <p><b>Status:</b> {{ row.status }}</p>

                <p><b>Trust Score:</b> {{ row.score }}%</p>

            </div>

        {% endfor %}

    </body>

    </html>

    '''

    return render_template_string(
        html,
        records=IRLT_EVIDENCE_SIMPLE
    )

# ============================================================
# END IRLT_EVIDENCE_VAULT_SIMPLE_V1_ACTIVE
# ============================================================

"""

needle = '\nif __name__ == "__main__":'

if needle not in text:
    needle = "\nif __name__ == '__main__':"

text = text.replace(
    needle,
    "\n" + INSERT + "\n" + needle,
    1
)

APP.write_text(text, encoding="utf-8")

print("IRLT Evidence Vault inserted successfully.")
