from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "RLT_OPERATIONS_VERTICAL_ACTIVE"

if MARKER in text:
    print("RLT Operations module already exists. No duplicate patch applied.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ============================================================
# RLT_OPERATIONS_VERTICAL_ACTIVE
# RLT Operations AssuranceLayer™
# Operational Trust & Governance Intelligence for RLT Manufacturing
# ============================================================

from flask import render_template_string

RLT_OPERATIONS_DATA = {
    "readiness": 96,
    "trust_score": 94,
    "governance_integrity": 98,
    "deviation_probability": "LOW",
    "environmental_stability": "PASS",
    "audit_readiness": "READY",
    "decision": "SAFE TO PROCEED",
    "controls": [
        {"name": "SOP Currency", "status": "VERIFIED", "score": 98},
        {"name": "CAPA Exposure", "status": "MINIMAL", "score": 92},
        {"name": "Training Validity", "status": "CURRENT", "score": 100},
        {"name": "Backup Verification", "status": "COMPLETE", "score": 95},
        {"name": "Audit Trail Review", "status": "CURRENT", "score": 96},
        {"name": "Shift Handoff Integrity", "status": "PASS", "score": 94},
    ],
    "blast_radius": [
        "Deviation Trigger",
        "Equipment / Isolator",
        "Impacted Batch",
        "Shift Record",
        "SOP Version",
        "Operator / Reviewer",
        "Release Risk"
    ],
    "heatmap": [
        {"area": "Isolator Readiness", "risk": "LOW", "confidence": "97%"},
        {"area": "Environmental Monitoring", "risk": "LOW", "confidence": "96%"},
        {"area": "Shift Handoff Governance", "risk": "MEDIUM", "confidence": "88%"},
        {"area": "Audit Trail Review", "risk": "LOW", "confidence": "95%"},
        {"area": "SOP Alignment", "risk": "LOW", "confidence": "98%"},
        {"area": "CAPA Exposure", "risk": "LOW", "confidence": "92%"},
    ]
}

def rlt_page(title, body):
    return render_template_string(f"""
    <!doctype html>
    <html>
    <head>
        <title>{title}</title>
        <style>
            body {{
                margin:0;
                font-family: Arial, Helvetica, sans-serif;
                background:#07111f;
                color:#e8f4ff;
            }}
            .wrap {{
                max-width:1200px;
                margin:0 auto;
                padding:34px;
            }}
            .hero {{
                background:linear-gradient(135deg,#0d2038,#102b4c,#083c4a);
                border:1px solid #1f6f8b;
                border-radius:22px;
                padding:28px;
                box-shadow:0 0 30px rgba(0,255,255,.12);
            }}
            h1 {{
                margin:0;
                font-size:34px;
                letter-spacing:.5px;
            }}
            .sub {{
                color:#a8d8ff;
                margin-top:8px;
                font-size:16px;
            }}
            .grid {{
                display:grid;
                grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
                gap:18px;
                margin-top:24px;
            }}
            .card {{
                background:#0c1b2d;
                border:1px solid #214d70;
                border-radius:18px;
                padding:20px;
                box-shadow:0 0 18px rgba(0,180,255,.08);
            }}
            .label {{
                color:#9bc7e8;
                font-size:13px;
                text-transform:uppercase;
                letter-spacing:.8px;
            }}
            .value {{
                font-size:32px;
                font-weight:700;
                margin-top:8px;
                color:#7fffd4;
            }}
            .section {{
                margin-top:26px;
                background:#091827;
                border:1px solid #1d4b68;
                border-radius:20px;
                padding:24px;
            }}
            .decision {{
                padding:18px;
                border-radius:16px;
                background:#063b2d;
                border:1px solid #20d69b;
                color:#87ffd8;
                font-size:26px;
                font-weight:700;
                text-align:center;
                margin:18px 0;
            }}
            table {{
                width:100%;
                border-collapse:collapse;
                margin-top:14px;
            }}
            th,td {{
                padding:13px;
                border-bottom:1px solid #173850;
                text-align:left;
            }}
            th {{
                color:#a8d8ff;
                font-size:13px;
                text-transform:uppercase;
            }}
            .pill {{
                display:inline-block;
                padding:6px 10px;
                border-radius:999px;
                background:#102f45;
                border:1px solid #2b85ad;
                color:#b7ecff;
                font-size:12px;
                font-weight:700;
            }}
            .chain {{
                display:flex;
                flex-wrap:wrap;
                gap:10px;
                margin-top:18px;
            }}
            .node {{
                background:#10283f;
                border:1px solid #2b85ad;
                border-radius:14px;
                padding:14px;
                min-width:130px;
                text-align:center;
            }}
            .arrow {{
                align-self:center;
                color:#7fffd4;
                font-size:22px;
            }}
            a {{
                color:#7fffd4;
                text-decoration:none;
            }}
            .nav {{
                margin-top:18px;
                display:flex;
                flex-wrap:wrap;
                gap:12px;
            }}
            .nav a {{
                background:#0e2a42;
                border:1px solid #24759b;
                padding:10px 14px;
                border-radius:12px;
            }}
        </style>
    </head>
    <body>
        <div class="wrap">
            {body}
        </div>
    </body>
    </html>
    """)

@app.route("/rlt-operations")
def rlt_operations_home():
    d = RLT_OPERATIONS_DATA
    body = f"""
    <div class="hero">
        <h1>RLT Operations Mission Control™</h1>
        <div class="sub">Operational Trust & Governance Intelligence for Radioligand Manufacturing</div>
        <div class="nav">
            <a href="/rlt-operations/readiness">Readiness Engine</a>
            <a href="/rlt-operations/trust-score">Trust Score</a>
            <a href="/rlt-operations/blast-radius">Blast Radius</a>
            <a href="/rlt-operations/risk-heatmap">Risk Heat Map</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Operational Readiness</div><div class="value">{d["readiness"]}%</div></div>
        <div class="card"><div class="label">Manufacturing Trust Score</div><div class="value">{d["trust_score"]}%</div></div>
        <div class="card"><div class="label">Governance Integrity</div><div class="value">{d["governance_integrity"]}%</div></div>
        <div class="card"><div class="label">Deviation Probability</div><div class="value">{d["deviation_probability"]}</div></div>
        <div class="card"><div class="label">Environmental Stability</div><div class="value">{d["environmental_stability"]}</div></div>
        <div class="card"><div class="label">Audit Readiness</div><div class="value">{d["audit_readiness"]}</div></div>
    </div>

    <div class="section">
        <h2>Operational Readiness Assurance Engine™</h2>
        <div class="decision">{d["decision"]}</div>
        <table>
            <tr><th>Control Area</th><th>Status</th><th>Score</th></tr>
            {''.join([f'<tr><td>{c["name"]}</td><td><span class="pill">{c["status"]}</span></td><td>{c["score"]}%</td></tr>' for c in d["controls"]])}
        </table>
    </div>

    <div class="section">
        <h2>Deviation Blast Radius Intelligence™</h2>
        <p>Maps operational impact from a deviation trigger through equipment, batch, shift, SOP, operator, and release exposure.</p>
        <div class="chain">
            {''.join([f'<div class="node">{x}</div><div class="arrow">→</div>' for x in d["blast_radius"]])}
        </div>
    </div>
    """
    return rlt_page("RLT Operations Mission Control", body)

@app.route("/rlt-operations/readiness")
def rlt_operations_readiness():
    d = RLT_OPERATIONS_DATA
    body = f"""
    <div class="hero">
        <h1>Operational Readiness Assurance Engine™</h1>
        <div class="sub">Determines whether RLT manufacturing operations are trustworthy enough to proceed.</div>
        <div class="nav"><a href="/rlt-operations">Back to Mission Control</a></div>
    </div>
    <div class="section">
        <div class="decision">{d["decision"]}</div>
        <table>
            <tr><th>Readiness Control</th><th>Status</th><th>Confidence</th></tr>
            {''.join([f'<tr><td>{c["name"]}</td><td><span class="pill">{c["status"]}</span></td><td>{c["score"]}%</td></tr>' for c in d["controls"]])}
        </table>
    </div>
    """
    return rlt_page("Operational Readiness", body)

@app.route("/rlt-operations/trust-score")
def rlt_operations_trust_score():
    d = RLT_OPERATIONS_DATA
    body = f"""
    <div class="hero">
        <h1>Manufacturing Trust Score™</h1>
        <div class="sub">A calculated confidence score showing whether the current manufacturing state can be trusted.</div>
        <div class="nav"><a href="/rlt-operations">Back to Mission Control</a></div>
    </div>
    <div class="grid">
        <div class="card"><div class="label">Overall Trust</div><div class="value">{d["trust_score"]}%</div></div>
        <div class="card"><div class="label">Evidence Integrity</div><div class="value">98%</div></div>
        <div class="card"><div class="label">Documentation Completeness</div><div class="value">95%</div></div>
        <div class="card"><div class="label">Governance Stability</div><div class="value">94%</div></div>
    </div>
    <div class="section">
        <h2>Trust Interpretation</h2>
        <p>The operation is currently in a trusted state. Minor governance monitoring remains active around shift handoff continuity and CAPA exposure.</p>
    </div>
    """
    return rlt_page("Manufacturing Trust Score", body)

@app.route("/rlt-operations/blast-radius")
def rlt_operations_blast_radius():
    d = RLT_OPERATIONS_DATA
    body = f"""
    <div class="hero">
        <h1>Deviation Blast Radius Intelligence™</h1>
        <div class="sub">Shows what else may be affected when a deviation or operational issue occurs.</div>
        <div class="nav"><a href="/rlt-operations">Back to Mission Control</a></div>
    </div>
    <div class="section">
        <div class="chain">
            {''.join([f'<div class="node">{x}</div><div class="arrow">→</div>' for x in d["blast_radius"]])}
        </div>
    </div>
    <div class="section">
        <h2>Impact Summary</h2>
        <table>
            <tr><th>Impact Area</th><th>Assessment</th></tr>
            <tr><td>Impacted Batches</td><td>1 active batch under review</td></tr>
            <tr><td>Linked SOPs</td><td>2 procedures verified current</td></tr>
            <tr><td>Operators / Reviewers</td><td>All training current</td></tr>
            <tr><td>Release Exposure</td><td>Low; no immediate hold recommended</td></tr>
        </table>
    </div>
    """
    return rlt_page("Deviation Blast Radius", body)

@app.route("/rlt-operations/risk-heatmap")
def rlt_operations_risk_heatmap():
    d = RLT_OPERATIONS_DATA
    body = f"""
    <div class="hero">
        <h1>Operational Risk Heat Map</h1>
        <div class="sub">Executive view of governance risk across key RLT operational areas.</div>
        <div class="nav"><a href="/rlt-operations">Back to Mission Control</a></div>
    </div>
    <div class="section">
        <table>
            <tr><th>Operational Area</th><th>Risk</th><th>Confidence</th></tr>
            {''.join([f'<tr><td>{r["area"]}</td><td><span class="pill">{r["risk"]}</span></td><td>{r["confidence"]}</td></tr>' for r in d["heatmap"]])}
        </table>
    </div>
    """
    return rlt_page("Operational Risk Heat Map", body)

'''

new_text = text.replace(insert_before, code + insert_before)
APP.write_text(new_text, encoding="utf-8")

print("RLT Operations AssuranceLayer patch applied successfully.")
