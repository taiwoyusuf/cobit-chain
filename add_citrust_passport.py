from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "CITRUST_PASSPORT_V1_ACTIVE"

if MARKER in text:
    print("CITrust Passport already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# CITRUST_PASSPORT_V1_ACTIVE
# ============================================================

@app.route("/citrust/passport")
@app.route("/citrust/ci-passport")
def citrust_passport_v1():

    controls = [
        {"domain": "CI Owner", "status": "Missing", "score": 0},
        {"domain": "Support Group", "status": "Missing", "score": 0},
        {"domain": "LCM Assignment", "status": "Pending", "score": 25},
        {"domain": "MyAccess Mapping", "status": "Not Ready", "score": 0},
        {"domain": "SOP Linkage", "status": "Incomplete", "score": 20},
        {"domain": "Evidence Readiness", "status": "Missing", "score": 0},
        {"domain": "Shift Handoff", "status": "Incomplete", "score": 20},
        {"domain": "Data Integrity", "status": "Unknown", "score": 10},
        {"domain": "Deviation Risk", "status": "High", "score": 0},
    ]

    overall = round(sum(c["score"] for c in controls) / len(controls))
    verdict = "TRUSTED" if overall >= 85 else "CONDITIONAL" if overall >= 60 else "NOT TRUSTED"

    html = """
    <html>
    <head>
        <title>CITrust Passport</title>
        <style>
            body{margin:0;padding:36px;background:linear-gradient(135deg,#050608,#11151f,#050608);color:white;font-family:Arial,Segoe UI,sans-serif}
            h1{font-size:76px;color:#ff9f1c;margin:0 0 12px}
            h2{color:#ff9f1c}
            p{color:#c6cfdb;line-height:1.7}
            .hero,.panel{background:#151c27;border-radius:26px;padding:30px;margin-bottom:24px;border:1px solid rgba(255,255,255,.08)}
            .verdict{font-size:84px;color:#ff9f1c;font-weight:900;margin:20px 0}
            .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:18px}
            .card{background:rgba(255,255,255,.04);border-radius:20px;padding:22px;border:1px solid rgba(255,255,255,.08)}
            .card strong{display:block;font-size:40px;color:#ff9f1c}
            table{width:100%;border-collapse:collapse}
            th,td{padding:14px;border-bottom:1px solid rgba(255,255,255,.08);text-align:left}
            th{color:#ff9f1c;text-transform:uppercase;font-size:12px}
            .pill{display:inline-block;padding:8px 14px;border-radius:999px;background:rgba(255,122,24,.15);color:#ffd7ad}
            @media(max-width:1200px){.grid{grid-template-columns:1fr}h1{font-size:44px}}
        </style>
    </head>
    <body>

        <section class="hero">
            <h1>CITrust™ Passport</h1>
            <p>
                Portable governance passport showing whether a Configuration Item can be trusted
                before ServiceNow reliance, MyAccess routing, audit review, or regulated operational use.
            </p>

            <div class="verdict">{{ verdict }}</div>

            <div class="grid">
                <div class="card"><strong>{{ overall }}%</strong>CITrust Score</div>
                <div class="card"><strong>CI-DEMO-1803</strong>CI Reference</div>
                <div class="card"><strong>HIGH</strong>Deviation Exposure</div>
                <div class="card"><strong>NOT READY</strong>ServiceNow Readiness</div>
            </div>
        </section>

        <section class="panel">
            <h2>CI Passport Control Matrix</h2>
            <table>
                <tr><th>Governance Domain</th><th>Status</th><th>Score</th></tr>
                {% for c in controls %}
                <tr>
                    <td>{{ c.domain }}</td>
                    <td><span class="pill">{{ c.status }}</span></td>
                    <td>{{ c.score }}%</td>
                </tr>
                {% endfor %}
            </table>
        </section>

        <section class="panel">
            <h2>LCM Interpretation</h2>
            <p>
                This CI should not be considered operationally trusted until ownership,
                support group, MyAccess routing, SOP linkage, evidence readiness, and data integrity
                have been validated. ServiceNow can store the CI, but CITrust™ determines whether
                the CI is governance-ready.
            </p>
        </section>

    </body>
    </html>
    """

    return render_template_string(
        html,
        controls=controls,
        overall=overall,
        verdict=verdict
    )

# ============================================================
# END CITRUST_PASSPORT_V1
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("CITrust Passport installed.")
