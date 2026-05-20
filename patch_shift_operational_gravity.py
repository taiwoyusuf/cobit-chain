from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_OPERATIONAL_GRAVITY_ENGINE_ACTIVE"

if MARKER in text:
    print("Shift Operational Gravity Engine already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_TREATMENT_WINDOW_COMPRESSION_ACTIVE",
    "SHIFT_GOVERNANCE_FATIGUE_HEATMAP_ACTIVE",
    "SHIFT_TREATMENT_CONTINUITY_RISK_ENGINE_ACTIVE",
    "SHIFT_PEER_BACKUP_COVERAGE_RESILIENCE_ACTIVE",
    "SHIFT_AUTONOMOUS_CONTINUITY_INTELLIGENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_OPERATIONAL_GRAVITY_ENGINE_ACTIVE
# Operational Gravity Engine™
# Advanced ShiftTrust™ instability-pull model
# ============================================================

@app.route("/shift-operational-gravity")
def shift_operational_gravity_engine():
    gravity_items = [
        {"issue": "MES/eBR alert without clear next-shift owner", "gravity": "HIGH", "pull": "31%", "impact": "Can pull release support, treatment window confidence, and handoff trust downward."},
        {"issue": "Printer/labeler queue instability", "gravity": "MEDIUM-HIGH", "pull": "24%", "impact": "Can compress packaging readiness and downstream courier buffer."},
        {"issue": "Walkaround item not closed", "gravity": "MEDIUM", "pull": "18%", "impact": "Can decay visibility across shift boundary and weaken audit defensibility."},
        {"issue": "Backup verification pending", "gravity": "MEDIUM", "pull": "16%", "impact": "Can reduce operational defensibility if support window becomes unstable."},
        {"issue": "Night-shift backup watch", "gravity": "WATCH", "pull": "11%", "impact": "Can increase fatigue and coverage pressure if absence occurs."},
    ]

    gravity_chain = [
        "Unowned MES/eBR Alert",
        "Handoff Trust Weakens",
        "Release Support Confidence Drops",
        "Treatment Window Compresses",
        "Executive Intervention Required"
    ]

    actions = [
        {"action": "Assign named incoming owner to MES/eBR alert before shift acceptance.", "effect": "Reduces highest operational gravity pull."},
        {"action": "Close or explicitly carry forward printer/labeler queue watch item.", "effect": "Protects packaging support readiness."},
        {"action": "Convert walkaround item into next-shift acceptance condition.", "effect": "Prevents visibility decay."},
        {"action": "Confirm backup verification status before production-support window.", "effect": "Improves operational defensibility."},
    ]

    rows = ''.join([
        f'<tr><td>{x["issue"]}</td><td><span class="pill">{x["gravity"]}</span></td><td>{x["pull"]}</td><td>{x["impact"]}</td></tr>'
        for x in gravity_items
    ])

    chain = ''.join([
        f'<div class="node">{x}</div><div class="arrow">→</div>'
        for x in gravity_chain
    ])

    action_rows = ''.join([
        f'<tr><td>{x["action"]}</td><td>{x["effect"]}</td></tr>'
        for x in actions
    ])

    body = f"""
    <div class="hero">
        <h1>Operational Gravity Engine™</h1>
        <div class="sub">
            Identifies which unresolved shift issue is pulling the whole operation toward instability.
            Not every open item has equal force. This engine ranks the issues that create the strongest downstream
            pull on handoff trust, release support, treatment-window confidence, and operational survivability.
        </div>
        <div class="nav">
            <a href="/shift-advanced">ShiftTrust Launcher</a>
            <a href="/shift-treatment-window-compression">Window Compression</a>
            <a href="/shift-governance-fatigue">Governance Fatigue</a>
            <a href="/shift-treatment-continuity">Treatment Continuity</a>
            <a href="/shift-autonomous-continuity">Autonomous Continuity</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Highest Gravity Issue</div><div class="value" style="font-size:23px;">MES/eBR Ownership</div></div>
        <div class="card"><div class="label">Gravity Pull</div><div class="value">31%</div></div>
        <div class="card"><div class="label">Stability Direction</div><div class="value" style="font-size:24px;">DOWNWARD</div></div>
        <div class="card"><div class="label">Treatment Impact</div><div class="value" style="font-size:24px;">WATCH</div></div>
        <div class="card"><div class="label">Recovery Path</div><div class="value" style="font-size:24px;">AVAILABLE</div></div>
        <div class="card"><div class="label">Intervention Priority</div><div class="value" style="font-size:24px;">P1</div></div>
    </div>

    <div class="section">
        <h2>Gravity Decision</h2>
        <div class="decision">OWNERSHIP GAP HAS THE STRONGEST OPERATIONAL GRAVITY — ASSIGN INCOMING OWNER BEFORE SHIFT ACCEPTANCE</div>
        <p>
            This module helps leadership focus on the few unresolved items that can pull the whole operation toward
            instability. It prevents teams from treating every open item as equal when some issues create much stronger
            downstream risk.
        </p>
    </div>

    <div class="section">
        <h2>Operational Gravity Board</h2>
        <table>
            <tr><th>Unresolved Issue</th><th>Gravity</th><th>Pull</th><th>Downstream Impact</th></tr>
            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Instability Pull Chain</h2>
        <div class="chain">
            {chain}
        </div>
    </div>

    <div class="section">
        <h2>Gravity Reduction Actions</h2>
        <table>
            <tr><th>Action</th><th>Expected Effect</th></tr>
            {action_rows}
        </table>
    </div>
    """

    return rlt_page("Operational Gravity Engine", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Operational Gravity Engine patch applied.")
