from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_TREATMENT_WINDOW_COMPRESSION_ACTIVE"

if MARKER in text:
    print("Shift Treatment Window Compression Simulator already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_TREATMENT_CONTINUITY_RISK_ENGINE_ACTIVE",
    "SHIFT_GOVERNANCE_FATIGUE_HEATMAP_ACTIVE",
    "SHIFT_PEER_BACKUP_COVERAGE_RESILIENCE_ACTIVE",
    "SHIFT_TOPOLOGY_INTELLIGENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_TREATMENT_WINDOW_COMPRESSION_ACTIVE
# Treatment Window Compression Simulator™
# Advanced ShiftTrust™ patient-aware timing model
# ============================================================

@app.route("/shift-treatment-window-compression")
def shift_treatment_window_compression():
    stages = [
        {"stage": "Manufacturing Support", "planned": "100%", "current": "91%", "compression": "9%", "driver": "Open MES/eBR support watch"},
        {"stage": "QC / QA Review Support", "planned": "100%", "current": "89%", "compression": "11%", "driver": "Pending support confirmation"},
        {"stage": "Packaging / Labeler Readiness", "planned": "100%", "current": "84%", "compression": "16%", "driver": "Printer/labeler queue instability"},
        {"stage": "Courier / Distribution Buffer", "planned": "100%", "current": "88%", "compression": "12%", "driver": "Downstream timing pressure"},
        {"stage": "Treatment Administration Window", "planned": "100%", "current": "82%", "compression": "18%", "driver": "Accumulated operational delay pressure"},
    ]

    scenarios = [
        {"scenario": "Printer issue unresolved for 2 more hours", "effect": "Packaging readiness drops; treatment-window confidence falls to 78%.", "risk": "High"},
        {"scenario": "Backup verification closes before handoff", "effect": "Operational defensibility improves; window confidence rises to 86%.", "risk": "Low"},
        {"scenario": "Peer backup activated before shift gap", "effect": "Continuity survives missed shift; timing compression stabilizes.", "risk": "Medium"},
        {"scenario": "MES/eBR alert carries into next shift without owner", "effect": "Support delay compounds and release support confidence declines.", "risk": "Critical"},
    ]

    rows = ''.join([
        f'<tr><td>{x["stage"]}</td><td>{x["planned"]}</td><td>{x["current"]}</td><td><span class="pill">{x["compression"]}</span></td><td>{x["driver"]}</td></tr>'
        for x in stages
    ])

    scenario_rows = ''.join([
        f'<tr><td>{x["scenario"]}</td><td>{x["effect"]}</td><td><span class="pill">{x["risk"]}</span></td></tr>'
        for x in scenarios
    ])

    body = f"""
    <div class="hero">
        <h1>Treatment Window Compression Simulator™</h1>
        <div class="sub">
            Patient-aware timing simulator for ShiftTrust™. It shows how unresolved shift issues, delayed triage,
            printer/labeler instability, missed backup confirmation, and incomplete handoff ownership can compress
            downstream manufacturing-to-treatment timing.
        </div>
        <div class="nav">
            <a href="/shift-treatment-continuity">Treatment Continuity</a>
            <a href="/shift-governance-fatigue">Governance Fatigue</a>
            <a href="/shift-peer-backup">Peer Backup</a>
            <a href="/shift-autonomous-continuity">Autonomous Continuity</a>
            <a href="/shift-advanced">ShiftTrust Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Treatment Window Confidence</div><div class="value">82%</div></div>
        <div class="card"><div class="label">Compression Pressure</div><div class="value" style="font-size:24px;">MOD-HIGH</div></div>
        <div class="card"><div class="label">Largest Compression</div><div class="value">18%</div></div>
        <div class="card"><div class="label">Recovery Available</div><div class="value" style="font-size:24px;">YES</div></div>
        <div class="card"><div class="label">Critical Driver</div><div class="value" style="font-size:23px;">Ownership Gap</div></div>
        <div class="card"><div class="label">Escalation State</div><div class="value" style="font-size:24px;">WATCH</div></div>
    </div>

    <div class="section">
        <h2>Compression Decision</h2>
        <div class="decision">TREATMENT WINDOW STILL PROTECTED — CLOSE OWNERSHIP AND LABELER WATCH ITEMS BEFORE COMPRESSION ESCALATES</div>
        <p>
            This module does not make clinical or patient-care decisions. It helps operations understand whether
            production-support delays could reduce the usable timing buffer needed to protect treatment continuity.
        </p>
    </div>

    <div class="section">
        <h2>Manufacturing-to-Treatment Timing Compression</h2>
        <table>
            <tr><th>Stage</th><th>Planned Buffer</th><th>Current Confidence</th><th>Compression</th><th>Driver</th></tr>
            {rows}
        </table>
    </div>

    <div class="section">
        <h2>What-If Compression Scenarios</h2>
        <table>
            <tr><th>Scenario</th><th>Predicted Effect</th><th>Risk</th></tr>
            {scenario_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>
        <p>
            Traditional IT dashboards show whether a device or ticket is open. This simulator shows whether those
            unresolved support issues are beginning to consume the timing buffer that protects manufacturing release,
            courier movement, and patient administration readiness.
        </p>
    </div>
    """

    return rlt_page("Treatment Window Compression Simulator", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Treatment Window Compression Simulator patch applied.")
