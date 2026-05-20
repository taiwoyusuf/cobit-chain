from pathlib import Path
import re

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

TRUST_MARKER = "# RLT_AUTONOMOUS_GMP_TRUST_FABRIC_ACTIVE"
UI_MARKER = "# RLT_WIDE_ENTERPRISE_UI_ACTIVE"

if TRUST_MARKER in text and UI_MARKER in text:
    print("RLT Trust Fabric and UI upgrade already exist. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_SHIFT_INTEGRITY_ENGINE_ACTIVE",
    "RLT_AUTONOMOUS_AUDIT_RECONSTRUCTION_ACTIVE",
    "RLT_GOVERNANCE_DRIFT_INTELLIGENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker not found: {item}")

# ------------------------------------------------------------
# 1. Upgrade shared RLT page shell only
# ------------------------------------------------------------
if UI_MARKER not in text:
    pattern = r'def rlt_page\(title, body\):.*?(?=\n@app\.route\("/rlt-operations"\))'
    match = re.search(pattern, text, flags=re.DOTALL)

    if not match:
        raise RuntimeError("Could not locate existing rlt_page function for safe UI upgrade.")

    new_rlt_page = r'''# RLT_WIDE_ENTERPRISE_UI_ACTIVE
def rlt_page(title, body):
    return render_template_string(f"""
    <!doctype html>
    <html>
    <head>
        <title>{title}</title>
        <style>
            :root {{
                --bg:#06111f;
                --panel:#0b1b2f;
                --panel2:#102a45;
                --line:#214d70;
                --text:#eaf6ff;
                --muted:#9fc4dd;
                --cyan:#7fffd4;
                --blue:#8fd3ff;
                --warn:#facc15;
                --danger:#fb7185;
                --good:#34d399;
            }}
            * {{ box-sizing:border-box; }}
            body {{
                margin:0;
                font-family: Inter, Segoe UI, Arial, Helvetica, sans-serif;
                background:
                    radial-gradient(circle at top left, rgba(127,255,212,.16), transparent 30%),
                    radial-gradient(circle at top right, rgba(56,189,248,.13), transparent 26%),
                    linear-gradient(135deg,#050b14,#07111f 42%,#0a1728);
                color:var(--text);
                min-height:100vh;
            }}
            .topbar {{
                position:sticky;
                top:0;
                z-index:50;
                backdrop-filter: blur(14px);
                background:rgba(5,13,24,.78);
                border-bottom:1px solid rgba(143,211,255,.18);
            }}
            .topbar-inner {{
                max-width:1560px;
                margin:0 auto;
                padding:14px 26px;
                display:flex;
                justify-content:space-between;
                align-items:center;
                gap:18px;
            }}
            .brand {{
                font-weight:900;
                letter-spacing:.3px;
                color:#ffffff;
            }}
            .brand span {{
                color:var(--cyan);
            }}
            .toplinks {{
                display:flex;
                flex-wrap:wrap;
                gap:10px;
                justify-content:flex-end;
            }}
            .toplinks a {{
                color:#dff7ff;
                text-decoration:none;
                font-size:13px;
                padding:8px 11px;
                border:1px solid rgba(143,211,255,.22);
                border-radius:999px;
                background:rgba(16,42,69,.58);
            }}
            .wrap {{
                max-width:1560px;
                width:100%;
                margin:0 auto;
                padding:30px 28px 54px;
            }}
            .hero {{
                position:relative;
                overflow:hidden;
                background:
                    linear-gradient(135deg,rgba(13,32,56,.96),rgba(16,43,76,.94),rgba(8,60,74,.92));
                border:1px solid rgba(127,255,212,.28);
                border-radius:28px;
                padding:32px;
                box-shadow:0 24px 70px rgba(0,0,0,.28), 0 0 36px rgba(0,255,220,.11);
            }}
            .hero:after {{
                content:"";
                position:absolute;
                right:-90px;
                top:-90px;
                width:280px;
                height:280px;
                border-radius:50%;
                background:rgba(127,255,212,.12);
                filter:blur(4px);
            }}
            h1 {{
                margin:0;
                font-size:42px;
                line-height:1.05;
                letter-spacing:-.8px;
            }}
            h2 {{
                margin:0 0 14px;
                font-size:24px;
                letter-spacing:-.3px;
            }}
            .sub {{
                color:#b7ddf5;
                margin-top:11px;
                font-size:16px;
                line-height:1.65;
                max-width:1120px;
            }}
            .grid {{
                display:grid;
                grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
                gap:18px;
                margin-top:24px;
            }}
            .card {{
                background:linear-gradient(180deg,rgba(16,42,69,.96),rgba(8,24,42,.96));
                border:1px solid rgba(143,211,255,.20);
                border-radius:22px;
                padding:22px;
                box-shadow:0 18px 38px rgba(0,0,0,.18);
                min-height:128px;
            }}
            .card:hover {{
                border-color:rgba(127,255,212,.46);
                transform:translateY(-1px);
                transition:.18s ease;
            }}
            .label {{
                color:#9bc7e8;
                font-size:12px;
                text-transform:uppercase;
                letter-spacing:.9px;
                font-weight:800;
            }}
            .value {{
                font-size:35px;
                font-weight:900;
                margin-top:10px;
                color:var(--cyan);
                letter-spacing:-.6px;
            }}
            .section {{
                margin-top:26px;
                background:rgba(9,24,39,.88);
                border:1px solid rgba(143,211,255,.20);
                border-radius:24px;
                padding:26px;
                box-shadow:0 18px 44px rgba(0,0,0,.18);
            }}
            .section p {{
                color:#c8dff0;
                line-height:1.72;
                font-size:15px;
            }}
            .decision {{
                padding:20px;
                border-radius:18px;
                background:linear-gradient(135deg,#063b2d,#0f513f);
                border:1px solid #20d69b;
                color:#9dffe0;
                font-size:25px;
                font-weight:900;
                text-align:center;
                margin:18px 0;
                box-shadow:0 0 24px rgba(32,214,155,.13);
            }}
            table {{
                width:100%;
                border-collapse:separate;
                border-spacing:0;
                margin-top:14px;
                overflow:hidden;
                border-radius:16px;
            }}
            th,td {{
                padding:14px 15px;
                border-bottom:1px solid rgba(143,211,255,.13);
                text-align:left;
                vertical-align:top;
            }}
            th {{
                color:#a8d8ff;
                font-size:12px;
                text-transform:uppercase;
                letter-spacing:.8px;
                background:rgba(16,42,69,.70);
            }}
            td {{
                color:#e7f4ff;
                background:rgba(8,24,42,.42);
                line-height:1.45;
            }}
            tr:hover td {{
                background:rgba(16,42,69,.55);
            }}
            .pill {{
                display:inline-block;
                padding:7px 11px;
                border-radius:999px;
                background:rgba(16,47,69,.92);
                border:1px solid rgba(127,255,212,.28);
                color:#b7fff0;
                font-size:12px;
                font-weight:900;
                white-space:nowrap;
            }}
            .chain {{
                display:flex;
                flex-wrap:wrap;
                gap:10px;
                margin-top:18px;
            }}
            .node {{
                background:linear-gradient(180deg,#10283f,#0b1d31);
                border:1px solid rgba(127,255,212,.28);
                border-radius:16px;
                padding:15px;
                min-width:145px;
                text-align:center;
                color:#e8f7ff;
                box-shadow:0 10px 24px rgba(0,0,0,.18);
            }}
            .arrow {{
                align-self:center;
                color:var(--cyan);
                font-size:22px;
                font-weight:900;
            }}
            a {{
                color:var(--cyan);
                text-decoration:none;
            }}
            .nav {{
                margin-top:22px;
                display:flex;
                flex-wrap:wrap;
                gap:12px;
                position:relative;
                z-index:2;
            }}
            .nav a {{
                background:rgba(14,42,66,.84);
                border:1px solid rgba(127,255,212,.30);
                padding:11px 15px;
                border-radius:14px;
                color:#dffff7;
                font-weight:800;
                font-size:13px;
                box-shadow:0 8px 20px rgba(0,0,0,.16);
            }}
            .nav a:hover, .toplinks a:hover {{
                background:rgba(127,255,212,.16);
                border-color:rgba(127,255,212,.62);
            }}
            @media (max-width:760px) {{
                .wrap {{ padding:18px 14px 36px; }}
                h1 {{ font-size:30px; }}
                .hero {{ padding:24px; border-radius:22px; }}
                .topbar-inner {{ align-items:flex-start; flex-direction:column; }}
            }}
        </style>
    </head>
    <body>
        <div class="topbar">
            <div class="topbar-inner">
                <div class="brand">COBIT-Chain™ <span>RLT Operations AssuranceLayer™</span></div>
                <div class="toplinks">
                    <a href="/rlt-operations">Mission Control</a>
                    <a href="/rlt-operations/readiness">Readiness</a>
                    <a href="/rlt-operations/trust-score">Trust Score</a>
                    <a href="/rlt-operations/blast-radius">Blast Radius</a>
                    <a href="/rlt-operations/shift-integrity">Shift Integrity</a>
                    <a href="/rlt-operations/audit-reconstruction">Audit Reconstruction</a>
                    <a href="/rlt-operations/governance-drift">Governance Drift</a>
                    <a href="/command-center">Command Center</a>
                </div>
            </div>
        </div>
        <div class="wrap">
            {body}
        </div>
    </body>
    </html>
    """)
'''
    text = text[:match.start()] + new_rlt_page + text[match.end():]

# ------------------------------------------------------------
# 2. Add Trust Fabric route
# ------------------------------------------------------------
if TRUST_MARKER not in text:
    insert_before = '\nif __name__ == "__main__":'
    if insert_before not in text:
        raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

    trust_code = r'''

# ============================================================
# RLT_AUTONOMOUS_GMP_TRUST_FABRIC_ACTIVE
# Autonomous GMP Trust Fabric™
# Advanced RLT Operations AssuranceLayer™ module
# ============================================================

RLT_TRUST_FABRIC_DATA = {
    "fabric_state": "TRUSTED WITH MONITORING",
    "trust_score": 92,
    "propagation": "ACTIVE",
    "weakest_node": "Environmental Rationale Closure",
    "decision": "TRUST CHAIN DEFENSIBLE — CLOSE PARTIAL RATIONALE BEFORE FINAL RELEASE ASSURANCE",
    "nodes": [
        {"node": "Operator Qualification", "state": "Trusted", "score": "100%", "dependency": "Training evidence current"},
        {"node": "SOP Currency", "state": "Trusted", "score": "98%", "dependency": "Controlled procedure current"},
        {"node": "Equipment Readiness", "state": "Trusted", "score": "95%", "dependency": "Readiness log verified"},
        {"node": "Shift Handoff", "state": "Trusted with Watch", "score": "91%", "dependency": "Minor recurring handoff delay"},
        {"node": "Environmental Review", "state": "Partial Trust", "score": "86%", "dependency": "Rationale closure pending"},
        {"node": "Supervisor Review", "state": "Trusted", "score": "92%", "dependency": "Review completed with traceability"},
        {"node": "Release Exposure", "state": "Controlled", "score": "90%", "dependency": "No immediate release hold required"},
    ],
    "trust_flow": [
        "Qualified Operator",
        "Current SOP",
        "Ready Equipment",
        "Controlled Shift",
        "Reviewed Environment",
        "Supervisor Gate",
        "Release Confidence"
    ],
    "fabric_rules": [
        {"rule": "Trust cannot propagate when evidence is missing or partial.", "status": "ENFORCED"},
        {"rule": "Release confidence depends on weakest unresolved governance node.", "status": "ACTIVE"},
        {"rule": "Human reliability signals influence operational trust state.", "status": "ACTIVE"},
        {"rule": "Audit reconstruction must support final assurance output.", "status": "ACTIVE"},
        {"rule": "Governance drift reduces trust score before deviation occurs.", "status": "ACTIVE"},
    ]
}

@app.route("/rlt-operations/trust-fabric")
def rlt_autonomous_gmp_trust_fabric():
    d = RLT_TRUST_FABRIC_DATA

    node_rows = ''.join([
        f'<tr><td>{n["node"]}</td><td><span class="pill">{n["state"]}</span></td><td>{n["score"]}</td><td>{n["dependency"]}</td></tr>'
        for n in d["nodes"]
    ])

    flow = ''.join([
        f'<div class="node">{x}</div><div class="arrow">→</div>'
        for x in d["trust_flow"]
    ])

    rule_rows = ''.join([
        f'<tr><td>{r["rule"]}</td><td><span class="pill">{r["status"]}</span></td></tr>'
        for r in d["fabric_rules"]
    ])

    body = f"""
    <div class="hero">
        <h1>Autonomous GMP Trust Fabric™</h1>
        <div class="sub">
            A live trust orchestration layer for RLT operations. It connects people, SOPs, equipment readiness,
            shift handoff, environmental review, supervisor gates, audit reconstruction, governance drift, and
            release confidence into one defensible GMP trust chain.
        </div>
        <div class="nav">
            <a href="/rlt-operations">Back to RLT Mission Control</a>
            <a href="/rlt-operations/shift-integrity">Shift Integrity</a>
            <a href="/rlt-operations/audit-reconstruction">Audit Reconstruction</a>
            <a href="/rlt-operations/governance-drift">Governance Drift</a>
            <a href="/rlt-operations/blast-radius">Blast Radius</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Fabric State</div><div class="value" style="font-size:24px;">{d["fabric_state"]}</div></div>
        <div class="card"><div class="label">Trust Score</div><div class="value">{d["trust_score"]}%</div></div>
        <div class="card"><div class="label">Trust Propagation</div><div class="value">{d["propagation"]}</div></div>
        <div class="card"><div class="label">Weakest Trust Node</div><div class="value" style="font-size:22px;">{d["weakest_node"]}</div></div>
    </div>

    <div class="section">
        <h2>Autonomous Trust Decision</h2>
        <div class="decision">{d["decision"]}</div>
        <p>
            The Trust Fabric does not simply show whether records exist. It determines whether trust can safely
            propagate across the operational chain. If one node is partial, weak, delayed, or unsupported, the
            final assurance state is constrained until that node is resolved.
        </p>
    </div>

    <div class="section">
        <h2>RLT GMP Trust Chain</h2>
        <div class="chain">
            {flow}
        </div>
    </div>

    <div class="section">
        <h2>Trust Node Register</h2>
        <table>
            <tr><th>Trust Node</th><th>State</th><th>Score</th><th>Dependency</th></tr>
            {node_rows}
        </table>
    </div>

    <div class="section">
        <h2>Autonomous Trust Rules</h2>
        <table>
            <tr><th>Rule</th><th>Status</th></tr>
            {rule_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>
        <p>
            This module is the future-state layer: COBIT-Chain™ becomes a GMP trust fabric that continuously
            evaluates whether operational trust is complete enough to support production confidence, audit
            defensibility, and release-readiness decisions. It shows how trust is built, where it weakens,
            how it recovers, and when leadership should intervene.
        </p>
    </div>
    """

    return rlt_page("Autonomous GMP Trust Fabric", body)

'''
    text = text.replace(insert_before, trust_code + insert_before)

APP.write_text(text, encoding="utf-8")
print("RLT Trust Fabric module and wide enterprise UI upgrade applied successfully.")
