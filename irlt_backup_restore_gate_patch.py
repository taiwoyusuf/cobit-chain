from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_BACKUP_RESTORE_GATE_VIEW_V1_ACTIVE"

if MARKER in text:
    print("IRLT Backup Restore Gate View already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_BACKUP_RESTORE_GATE_VIEW_V1_ACTIVE
# ============================================================

IRLT_BACKUP_RESTORE_GATE_V1 = [
    {
        "gate": "Backup Completion Evidence",
        "condition": "Required backup evidence must show completion status, timestamp, system scope, and reviewer visibility.",
        "status": "Verified",
        "score": 96
    },
    {
        "gate": "Restore Test Readiness",
        "condition": "Restore capability must be periodically tested or supported by governed recovery evidence.",
        "status": "Controlled",
        "score": 93
    },
    {
        "gate": "GMP System Recovery Priority",
        "condition": "GMP-impacting systems must be prioritized based on operational criticality, RTO, and RPO expectations.",
        "status": "Critical",
        "score": 97
    },
    {
        "gate": "Evidence Retention",
        "condition": "Backup and restore evidence must be retained, traceable, and inspection-defensible.",
        "status": "Defensible",
        "score": 95
    },
    {
        "gate": "Failure Escalation",
        "condition": "Backup failure or restore uncertainty must trigger governance escalation and documented risk review.",
        "status": "Monitored",
        "score": 91
    },
    {
        "gate": "Recovery Dependency Mapping",
        "condition": "System recovery dependencies must be mapped across infrastructure, applications, data, users, and process owners.",
        "status": "Planned Integration",
        "score": 90
    }
]

@app.route("/irlt-commercial-readiness/backup-restore-gate")
def irlt_backup_restore_gate():

    backup_score = round(
        sum(x["score"] for x in IRLT_BACKUP_RESTORE_GATE_V1)
        / len(IRLT_BACKUP_RESTORE_GATE_V1)
    )

    return render_template_string('''

    <html>

    <head>

        <title>IRLT Backup Restore Gate</title>

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

            .score{
                font-size:120px;
                color:#ff9f1c;
                margin:30px 0;
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

        <h1>IRLT Backup Restore Gate</h1>

        <p>
            Governed backup and restore readiness layer for IRLT operations. This view checks whether
            backup evidence, restore readiness, GMP recovery prioritization, retention, failure escalation,
            and recovery dependency mapping are controlled and inspection-defensible.
        </p>

        <div class="score">{{ backup_score }}%</div>

        <p>Overall Backup Restore Governance Confidence</p>

        <div class="grid">

            {% for row in gates %}

            <div class="card">

                <h2>{{ row.gate }}</h2>

                <p>{{ row.condition }}</p>

                <p>Score: {{ row.score }}%</p>

                <div class="pill">{{ row.status }}</div>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    ''',
    gates=IRLT_BACKUP_RESTORE_GATE_V1,
    backup_score=backup_score
    )


@app.route("/irlt-commercial-readiness/backup-restore-gate/api")
def irlt_backup_restore_gate_api():

    return jsonify({
        "backup_score": round(
            sum(x["score"] for x in IRLT_BACKUP_RESTORE_GATE_V1)
            / len(IRLT_BACKUP_RESTORE_GATE_V1)
        ),
        "gates": IRLT_BACKUP_RESTORE_GATE_V1
    })

# ============================================================
# END IRLT_BACKUP_RESTORE_GATE_VIEW_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Backup Restore Gate View appended successfully.")
