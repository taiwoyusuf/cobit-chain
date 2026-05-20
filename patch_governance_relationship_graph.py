from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "GOVERNANCE_RELATIONSHIP_GRAPH_ACTIVE"

if MARKER in text:
    print("Governance Relationship Graph already exists. No changes made.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
idx = text.find(insert_before)

if idx == -1:
    raise SystemExit("ERROR: Could not find final if __name__ == \"__main__\" block.")

route_code = r'''

# ============================================================
# GOVERNANCE_RELATIONSHIP_GRAPH_ACTIVE
# Safe additive route only.
# Adds /governance-relationship-graph without modifying protected modules.
# Visual relationship graph across ticket, shift, technician, equipment,
# evidence, review, confidence, audit, CAPA/deviation exposure.
# ============================================================

@app.route("/governance-relationship-graph")
def governance_relationship_graph():
    graph_nodes = [
        {"id": "ticket", "label": "ServiceNow Ticket", "type": "Workflow", "state": "In Progress", "risk": "MEDIUM", "x": 60, "y": 210},
        {"id": "shift", "label": "Shift Overlap", "type": "Continuity", "state": "B→C Transition", "risk": "MEDIUM", "x": 240, "y": 90},
        {"id": "technician", "label": "Technician Owner", "type": "Accountability", "state": "Ack Pending", "risk": "HIGH", "x": 420, "y": 90},
        {"id": "equipment", "label": "Equipment", "type": "Asset", "state": "Warning", "risk": "HIGH", "x": 240, "y": 330},
        {"id": "evidence", "label": "Evidence Package", "type": "Evidence", "state": "Partial", "risk": "HIGH", "x": 420, "y": 330},
        {"id": "review", "label": "Supervisor Review", "type": "Control", "state": "Required", "risk": "MEDIUM", "x": 610, "y": 210},
        {"id": "confidence", "label": "Confidence Score", "type": "Executive KPI", "state": "89%", "risk": "MEDIUM", "x": 800, "y": 110},
        {"id": "audit", "label": "Audit State", "type": "Audit", "state": "Conditional", "risk": "MEDIUM", "x": 800, "y": 310},
        {"id": "capa", "label": "CAPA / Deviation Exposure", "type": "Quality Risk", "state": "Watch", "risk": "MEDIUM", "x": 1010, "y": 210},
    ]

    graph_edges = [
        {"source": "ticket", "target": "shift", "label": "assigned into overlap window", "risk": "MEDIUM"},
        {"source": "shift", "target": "technician", "label": "requires incoming owner", "risk": "HIGH"},
        {"source": "ticket", "target": "equipment", "label": "impacts equipment context", "risk": "HIGH"},
        {"source": "equipment", "target": "evidence", "label": "requires audit trail evidence", "risk": "HIGH"},
        {"source": "technician", "target": "evidence", "label": "must attach evidence", "risk": "HIGH"},
        {"source": "evidence", "target": "review", "label": "drives review readiness", "risk": "MEDIUM"},
        {"source": "review", "target": "audit", "label": "supports audit defensibility", "risk": "MEDIUM"},
        {"source": "evidence", "target": "confidence", "label": "reduces trust if incomplete", "risk": "MEDIUM"},
        {"source": "audit", "target": "capa", "label": "weak audit state increases exposure", "risk": "MEDIUM"},
        {"source": "confidence", "target": "capa", "label": "low confidence increases quality risk", "risk": "MEDIUM"},
    ]

    insight_cards = [
        {
            "title": "Highest Risk Node",
            "value": "Evidence Package",
            "detail": "Evidence is partial; missing audit trail export drives audit and confidence weakness.",
            "risk": "HIGH"
        },
        {
            "title": "Weakest Relationship",
            "value": "Shift → Technician",
            "detail": "Incoming owner acknowledgement is pending during B-to-C transition.",
            "risk": "HIGH"
        },
        {
            "title": "Executive Trust Impact",
            "value": "-8 confidence points",
            "detail": "Evidence and handoff gaps reduce leadership reliance on the operational record.",
            "risk": "MEDIUM"
        },
        {
            "title": "Recovery Path",
            "value": "3 actions",
            "detail": "Acknowledge owner, attach evidence, complete supervisor review.",
            "risk": "LOW"
        },
    ]

    graph_table = [
        {"path": "Ticket → Shift → Technician", "meaning": "Workflow ownership must survive the overlap window.", "status": "Weak", "risk": "HIGH"},
        {"path": "Ticket → Equipment → Evidence", "meaning": "Operational event must be supported by equipment-specific evidence.", "status": "Partial", "risk": "HIGH"},
        {"path": "Evidence → Review → Audit", "meaning": "Evidence completeness determines audit defensibility.", "status": "Watch", "risk": "MEDIUM"},
        {"path": "Confidence → CAPA Exposure", "meaning": "Low confidence can become quality risk if recurring.", "status": "Controlled", "risk": "MEDIUM"},
    ]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>COBIT-Chain Governance Relationship Graph</title>
        <style>
            body { margin:0; font-family:Arial, Helvetica, sans-serif; background:#f4f7fb; color:#0f172a; }
            .top {
                background:#0f172a;
                color:white;
                padding:14px 24px;
                display:flex;
                justify-content:space-between;
                align-items:center;
                gap:18px;
                flex-wrap:wrap;
                position:sticky;
                top:0;
                z-index:10;
            }
            .brand { font-weight:900; font-size:18px; }
            .brand span { color:#38bdf8; }
            .nav { display:flex; gap:10px; flex-wrap:wrap; }
            .nav a {
                color:#dbeafe;
                text-decoration:none;
                font-size:12px;
                font-weight:800;
                padding:8px 10px;
                border-radius:999px;
                background:rgba(255,255,255,.08);
                border:1px solid rgba(255,255,255,.12);
            }
            .nav a:hover { background:#2563eb; color:white; }
            .hero {
                background:linear-gradient(135deg,#111827,#7c3aed);
                color:white;
                padding:36px 44px 78px;
                border-bottom-left-radius:28px;
                border-bottom-right-radius:28px;
            }
            .hero h1 { margin:0 0 10px; font-size:40px; }
            .hero p { color:#ede9fe; max-width:1120px; line-height:1.55; font-size:16px; }
            .badge {
                display:inline-block;
                background:rgba(255,255,255,.14);
                border:1px solid rgba(255,255,255,.25);
                padding:8px 13px;
                border-radius:999px;
                margin:10px 8px 0 0;
                font-size:12px;
                font-weight:800;
            }
            .wrap { max-width:1320px; margin:-46px auto 40px; padding:0 24px; }
            .grid4 { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin-bottom:22px; }
            .card, .panel {
                background:white;
                border-radius:20px;
                padding:22px;
                box-shadow:0 12px 30px rgba(15,23,42,.09);
                margin-bottom:22px;
            }
            .card h3 { margin:0 0 8px; color:#312e81; }
            .card strong { display:block; font-size:22px; margin-bottom:8px; }
            .graph-panel {
                background:white;
                border-radius:22px;
                padding:24px;
                box-shadow:0 12px 30px rgba(15,23,42,.09);
                margin-bottom:24px;
                overflow-x:auto;
            }
            svg { min-width:1120px; width:100%; height:500px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:18px; }
            .edge { stroke:#64748b; stroke-width:2; marker-end:url(#arrow); }
            .edge.HIGH { stroke:#dc2626; stroke-width:3; }
            .edge.MEDIUM { stroke:#f59e0b; stroke-width:2.5; }
            .node-circle { stroke:#0f172a; stroke-width:1.5; }
            .node-circle.HIGH { fill:#fee2e2; stroke:#dc2626; }
            .node-circle.MEDIUM { fill:#fef3c7; stroke:#f59e0b; }
            .node-circle.LOW { fill:#dcfce7; stroke:#16a34a; }
            .node-label { font-size:13px; font-weight:800; fill:#0f172a; }
            .node-state { font-size:11px; fill:#475569; }
            .edge-label { font-size:10px; fill:#475569; }
            .pill { display:inline-block; padding:6px 10px; border-radius:999px; font-weight:900; font-size:11px; }
            .HIGH { background:#fee2e2; color:#991b1b; }
            .MEDIUM { background:#fef3c7; color:#92400e; }
            .LOW { background:#dcfce7; color:#166534; }
            table { width:100%; border-collapse:collapse; }
            th { background:#f5f3ff; color:#5b21b6; text-align:left; padding:12px; font-size:13px; }
            td { border-bottom:1px solid #e5e7eb; padding:12px; font-size:13px; vertical-align:top; }
            .note { background:#f5f3ff; border:1px solid #ddd6fe; color:#4c1d95; padding:16px; border-radius:16px; margin-bottom:22px; }
            @media(max-width:900px){ .grid4{grid-template-columns:repeat(2,1fr);} .hero h1{font-size:32px;} }
            @media(max-width:650px){ .grid4{grid-template-columns:1fr;} }
        </style>
    </head>
    <body>
        <div class="top">
            <div class="brand">COBIT-Chain™ <span>Relationship Graph</span></div>
            <nav class="nav">
                <a href="/enterprise-workspaces">Workspaces</a>
                <a href="/executive-demo-flow">Demo Flow</a>
                <a href="/governance-digital-twin">Digital Twin</a>
                <a href="/governance-confidence-engine">Confidence</a>
                <a href="/audit-simulation-engine">Audit</a>
                <a href="/enterprise-shell-preview">Shell</a>
            </nav>
        </div>

        <section class="hero">
            <h1>Interactive Governance Relationship Graph</h1>
            <p>
                A visual trust graph showing how workflow, shift continuity, technician ownership, equipment state,
                evidence, supervisor review, confidence, audit readiness, and CAPA/deviation exposure connect as one governed ecosystem.
            </p>
            <span class="badge">OPERATIONAL TRUST GRAPH</span>
            <span class="badge">BLAST RADIUS VISUAL</span>
            <span class="badge">CONFIDENCE INFLUENCE</span>
            <span class="badge">AUDIT TRACEABILITY</span>
        </section>

        <main class="wrap">
            <div class="note">
                <b>Executive meaning:</b> The graph shows why a small handoff or evidence gap is not isolated.
                It can travel through ownership, evidence, review, confidence, audit readiness, and quality exposure.
            </div>

            <section class="grid4">
                {% for i in insight_cards %}
                <div class="card">
                    <h3>{{ i.title }}</h3>
                    <strong>{{ i.value }}</strong>
                    <p>{{ i.detail }}</p>
                    <span class="pill {{ i.risk }}">{{ i.risk }}</span>
                </div>
                {% endfor %}
            </section>

            <section class="graph-panel">
                <h2>1. Governance Relationship Graph</h2>
                <svg viewBox="0 0 1120 500" role="img" aria-label="Governance relationship graph">
                    <defs>
                        <marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto" markerUnits="strokeWidth">
                            <path d="M0,0 L0,6 L9,3 z" fill="#64748b"></path>
                        </marker>
                    </defs>

                    {% for e in graph_edges %}
                        {% set s = graph_nodes | selectattr("id", "equalto", e.source) | list | first %}
                        {% set t = graph_nodes | selectattr("id", "equalto", e.target) | list | first %}
                        <line class="edge {{ e.risk }}" x1="{{ s.x + 58 }}" y1="{{ s.y }}" x2="{{ t.x - 58 }}" y2="{{ t.y }}"></line>
                        <text class="edge-label" x="{{ (s.x + t.x) / 2 - 50 }}" y="{{ (s.y + t.y) / 2 - 8 }}">{{ e.label }}</text>
                    {% endfor %}

                    {% for n in graph_nodes %}
                        <circle class="node-circle {{ n.risk }}" cx="{{ n.x }}" cy="{{ n.y }}" r="58"></circle>
                        <text class="node-label" x="{{ n.x - 48 }}" y="{{ n.y - 8 }}">{{ n.label }}</text>
                        <text class="node-state" x="{{ n.x - 42 }}" y="{{ n.y + 12 }}">{{ n.state }}</text>
                        <text class="node-state" x="{{ n.x - 38 }}" y="{{ n.y + 30 }}">{{ n.risk }}</text>
                    {% endfor %}
                </svg>
            </section>

            <section class="panel">
                <h2>2. Relationship Paths</h2>
                <table>
                    <tr><th>Path</th><th>Meaning</th><th>Status</th><th>Risk</th></tr>
                    {% for row in graph_table %}
                    <tr>
                        <td><b>{{ row.path }}</b></td>
                        <td>{{ row.meaning }}</td>
                        <td>{{ row.status }}</td>
                        <td><span class="pill {{ row.risk }}">{{ row.risk }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>

            <section class="panel">
                <h2>3. Relationship Edge Detail</h2>
                <table>
                    <tr><th>Source</th><th>Target</th><th>Relationship</th><th>Risk</th></tr>
                    {% for e in graph_edges %}
                    <tr>
                        <td><b>{{ e.source }}</b></td>
                        <td><b>{{ e.target }}</b></td>
                        <td>{{ e.label }}</td>
                        <td><span class="pill {{ e.risk }}">{{ e.risk }}</span></td>
                    </tr>
                    {% endfor %}
                </table>
            </section>
        </main>
    </body>
    </html>
    """

    return render_template_string(
        html,
        graph_nodes=graph_nodes,
        graph_edges=graph_edges,
        insight_cards=insight_cards,
        graph_table=graph_table
    )


'''

new_text = text[:idx] + route_code + text[idx:]
APP.write_text(new_text, encoding="utf-8")

required = [
    "GOVERNANCE_RELATIONSHIP_GRAPH_ACTIVE",
    '@app.route("/governance-relationship-graph")',
    "Interactive Governance Relationship Graph",
    "Governance Relationship Graph",
    "Relationship Edge Detail"
]

missing = [x for x in required if x not in new_text]
if missing:
    raise SystemExit("ERROR missing expected markers: " + ", ".join(missing))

print("SUCCESS: Governance Relationship Graph added safely at /governance-relationship-graph")
