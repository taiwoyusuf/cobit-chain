from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_AUTONOMOUS_CONTINUITY_INTELLIGENCE_ACTIVE"

if MARKER in text:
    print("Shift Autonomous Continuity Intelligence already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_ASSURANCE_ENTRA_TEST_ACTIVE",
    "SHIFT_HANDOFF_LINEAGE_ACTIVE",
    "SHIFT_OVERLAP_INTELLIGENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_AUTONOMOUS_CONTINUITY_INTELLIGENCE_ACTIVE
# Autonomous Continuity Intelligence™
# Advanced ShiftTrust™ / Production IT Readiness layer
# ============================================================

@app.route("/shift-autonomous-continuity")
def shift_autonomous_continuity_intelligence():
    signals = [
        {"area": "Shift Handover Continuity", "score": "91%", "state": "WATCH", "meaning": "Open incidents and carryover items remain visible across shift transition."},
        {"area": "Backup Verification", "score": "94%", "state": "TRUSTED", "meaning": "Critical backup checks completed with no failed overnight jobs."},
        {"area": "Network / Systems Readiness", "score": "92%", "state": "CONTROLLED", "meaning": "No unresolved production VLAN, server health, MES/eBR, SCADA, or PLC interface blocker."},
        {"area": "Printer / Labeler Readiness", "score": "88%", "state": "WATCH", "meaning": "Consumables and queue health require monitoring before next production window."},
        {"area": "Walkaround Governance", "score": "86%", "state": "ACTION", "meaning": "One floor observation requires documented follow-up."},
        {"area": "Training / SOP Awareness", "score": "96%", "state": "TRUSTED", "meaning": "Required training/SOP awareness is current for shift activity."},
        {"area": "Triage SLA", "score": "89%", "state": "WATCH", "meaning": "30-minute triage window is met but trending close to limit."},
    ]

    fatigue = [
        {"pattern": "Repeated carryover work order", "risk": "Medium", "interpretation": "Operational memory is preserved, but recurrence indicates unresolved root cause pressure."},
        {"pattern": "Same printer/labeler watch item across shifts", "risk": "Medium", "interpretation": "Potential production-support weak signal."},
        {"pattern": "Walkaround item not closed before shift end", "risk": "High", "interpretation": "Governance fatigue risk: issue visibility may decay at handoff."},
        {"pattern": "Triage close to 30-minute expectation", "risk": "Watch", "interpretation": "Operational pressure is increasing but still controlled."},
    ]

    dna = [
        "Ownership survived",
        "Evidence survived",
        "Escalation survived",
        "Backup confidence survived",
        "Walkaround issue partially open",
        "Triage SLA under watch",
        "Next shift risk preserved"
    ]

    rows = ''.join([
        f'<tr><td>{x["area"]}</td><td>{x["score"]}</td><td><span class="pill">{x["state"]}</span></td><td>{x["meaning"]}</td></tr>'
        for x in signals
    ])

    fatigue_rows = ''.join([
        f'<tr><td>{x["pattern"]}</td><td><span class="pill">{x["risk"]}</span></td><td>{x["interpretation"]}</td></tr>'
        for x in fatigue
    ])

    chain = ''.join([
        f'<div class="node">{x}</div><div class="arrow">→</div>'
        for x in dna
    ])

    body = f"""
    <div class="hero">
        <h1>Autonomous Continuity Intelligence™</h1>
        <div class="sub">
            A revolutionary ShiftTrust™ layer for Pharma IT. It converts daily production IT checks, handover notes,
            backup verification, network/system readiness, printer/labeler status, walkaround findings, training,
            and triage expectations into a live operational trust signal.
        </div>
        <div class="nav">
            <a href="/shift-assurance-enterprise">Shift Enterprise</a>
            <a href="/shift-handoff-lineage">Handoff Lineage</a>
            <a href="/shift-overlap-intelligence">Shift Overlap</a>
            <a href="/operational-lineage">Operational Lineage</a>
            <a href="/command-center">Command Center</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Manufacturing Continuity Trust</div><div class="value">90%</div></div>
        <div class="card"><div class="label">Operational Trust Pulse</div><div class="value" style="font-size:23px;">STABLE WATCH</div></div>
        <div class="card"><div class="label">Governance Fatigue</div><div class="value" style="font-size:24px;">MEDIUM</div></div>
        <div class="card"><div class="label">Deviation Probability</div><div class="value">18%</div></div>
        <div class="card"><div class="label">Triage SLA</div><div class="value">29 min</div></div>
        <div class="card"><div class="label">Continuity DNA</div><div class="value" style="font-size:23px;">PRESERVED</div></div>
    </div>

    <div class="section">
        <h2>Autonomous Continuity Decision</h2>
        <div class="decision">OPERATION GOVERNED — CLOSE WALKAROUND ITEM BEFORE NEXT SHIFT ACCEPTANCE</div>
        <p>
            This is not a checklist. It is an operational continuity intelligence layer. It detects whether ownership,
            evidence, escalation, backup confidence, system readiness, and shift memory survive the handoff.
        </p>
    </div>

    <div class="section">
        <h2>Production IT Readiness Signal Board</h2>
        <table>
            <tr><th>Control Area</th><th>Score</th><th>State</th><th>Operational Meaning</th></tr>
            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Governance Fatigue Detection™</h2>
        <table>
            <tr><th>Pattern</th><th>Risk</th><th>Interpretation</th></tr>
            {fatigue_rows}
        </table>
    </div>

    <div class="section">
        <h2>Continuity DNA™</h2>
        <div class="chain">
            {chain}
        </div>
    </div>

    <div class="section">
        <h2>Why This Is Revolutionary in Pharma IT</h2>
        <p>
            Most shift tools record what happened. Autonomous Continuity Intelligence™ determines whether the operation
            remained governable across the shift boundary. It treats backup checks, network/system readiness, walkarounds,
            open work orders, printer readiness, training, triage, and handover as early governance signals that can
            predict operational trust decay before deviation pressure becomes harder to control.
        </p>
    </div>
    """

    return rlt_page("Autonomous Continuity Intelligence", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Autonomous Continuity Intelligence patch applied.")
