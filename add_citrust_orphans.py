from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_ORPHAN_CI_INTELLIGENCE_V1_ACTIVE"

if MARKER in text:
    print("CITrust Orphan CI Intelligence already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_ORPHAN_CI_INTELLIGENCE_V1_ACTIVE
# ============================================================

@app.route("/citrust/orphans")
@app.route("/citrust/orphan-ci-intelligence")
def citrust_orphan_ci_intelligence_v1():

    orphan_records = [
        {"ci": "EQP-1803", "name": "Demo Isolator Integrity Tester", "owner": "Missing", "support": "Missing", "myaccess": "Not mapped", "risk": "HIGH", "score": 0},
        {"ci": "EQP-0747", "name": "Building Management / Facilities System", "owner": "Pending", "support": "Missing", "myaccess": "Not mapped", "risk": "HIGH", "score": 20},
        {"ci": "EQP-1264", "name": "Enterprise Application / CMMS", "owner": "Unknown", "support": "Pending", "myaccess": "Incomplete", "risk": "MEDIUM", "score": 40},
        {"ci": "EQP-0651", "name": "Application Service / Computerized System", "owner": "Missing", "support": "Pending", "myaccess": "Incomplete", "risk": "MEDIUM", "score": 40},
    ]

    avg_score = round(sum(x["score"] for x in orphan_records) / len(orphan_records))

    html = """
    <html>
    <head>
        <title>CITrust Orphan CI Intelligence</title>
        <style>
            body{margin:0;padding:36px;background:linear-gradient(135deg,#050608,#11151f,#050608);color:white;font-family:Arial}
            h1{font-size:76px;color:#ff9f1c;margin:0 0 12px}
            h2{color:#ff9f1c}
            p{color:#c6cfdb;line-height:1.7}
            .hero,.panel{background:#151c27;border-radius:26px;padding:30px;margin-bottom:24px;border:1px solid rgba(255,255,255,.08)}
            .score{font-size:84px;color:#ff9f1c;font-weight:900}
            table{width:100%;border-collapse:collapse}
            th,td{padding:14px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left}
            th{color:#ff9f1c;text-transform:uppercase;font-size:12px}
            .pill{display:inline-block;padding:8px 14px;border-radius:999px;background:rgba(255,122,24,.15);color:#ffd7ad}
        </style>
    </head>
    <body>

        <section class="hero">
            <h1>Orphan CI Intelligence</h1>
            <p>
                Detects Configuration Items that should not be trusted because ownership,
                support group, LCM responsibility, or MyAccess routing is missing or incomplete.
            </p>
            <div class="score">{{ avg_score }}%</div>
            <p>Average Orphan CI Trust Readiness</p>
        </section>

        <section class="panel">
            <h2>Orphan / Weak CI Queue</h2>
            <table>
                <tr>
                    <th>CI</th><th>Name</th><th>Owner</th><th>Support Group</th><th>MyAccess</th><th>Risk</th><th>Trust</th>
                </tr>
                {% for r in orphan_records %}
                <tr>
                    <td>{{ r.ci }}</td>
                    <td>{{ r.name }}</td>
                    <td><span class="pill">{{ r.owner }}</span></td>
                    <td><span class="pill">{{ r.support }}</span></td>
                    <td><span class="pill">{{ r.myaccess }}</span></td>
                    <td><span class="pill">{{ r.risk }}</span></td>
                    <td>{{ r.score }}%</td>
                </tr>
                {% endfor %}
            </table>
        </section>

        <section class="panel">
            <h2>LCM Governance Message</h2>
            <p>
                An orphaned CI is not only a data-quality issue. It can break access routing,
                audit accountability, incident ownership, support escalation, and regulated system readiness.
                CITrust™ highlights those gaps before they become operational or compliance failures.
            </p>
        </section>

    </body>
    </html>
    """

    return render_template_string(html, orphan_records=orphan_records, avg_score=avg_score)

# ============================================================
# END CITRUST_ORPHAN_CI_INTELLIGENCE_V1
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Orphan CI Intelligence installed.")
