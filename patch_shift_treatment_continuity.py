from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_TREATMENT_CONTINUITY_RISK_ENGINE_ACTIVE"

if MARKER in text:
    print("Shift Treatment Continuity Risk Engine already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_AUTONOMOUS_CONTINUITY_INTELLIGENCE_ACTIVE",
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
# SHIFT_TREATMENT_CONTINUITY_RISK_ENGINE_ACTIVE
# Treatment Continuity Risk Engine™
# Advanced ShiftTrust™ / Time-Critical Manufacturing Intelligence
# ============================================================

@app.route("/shift-treatment-continuity")
def shift_treatment_continuity_risk_engine():
    chain = [
        {"stage": "Manufacturing Support", "confidence": "91%", "state": "WATCH", "risk": "Open MES alert and backup check under monitoring"},
        {"stage": "QC / QA Readiness", "confidence": "89%", "state": "CONTROLLED", "risk": "Review window still protected"},
        {"stage": "Packaging / Labeling", "confidence": "86%", "state": "WATCH", "risk": "Printer/labeler queue instability may compress downstream timing"},
        {"stage": "Distribution / Courier", "confidence": "92%", "state": "TRUSTED", "risk": "Transit path still viable"},
        {"stage": "Hospital Receipt", "confidence": "90%", "state": "TRUSTED", "risk": "No immediate receipt-risk signal"},
        {"stage": "Patient Administration Window", "confidence": "84%", "state": "WATCH", "risk": "Timing compression could increase if support issue persists"},
    ]

    drivers = [
        {"driver": "Printer/labeler instability", "effect": "Could delay packaging readiness", "severity": "Medium"},
        {"driver": "Backup verification pending", "effect": "Reduces operational defensibility during support window", "severity": "Medium"},
        {"driver": "MES/eBR alert carryover", "effect": "May create release-timing uncertainty if unresolved", "severity": "High"},
        {"driver": "Shift handoff dependency", "effect": "Requires continuity peer acknowledgement", "severity": "Medium"},
    ]

    recovery = [
        {"action": "Activate continuity peer for MES/eBR follow-up", "gain": "+4% confidence", "owner": "Incoming Shift / Backup Peer"},
        {"action": "Close printer/labeler queue watch item before packaging support window", "gain": "+3% confidence", "owner": "Production IT"},
        {"action": "Confirm backup verification status before shift acceptance", "gain": "+2% confidence", "owner": "Shift Lead"},
        {"action": "Attach continuity note to handoff lineage", "gain": "+2% audit defensibility", "owner": "Outgoing Technician"},
    ]

    chain_rows = ''.join([
        f'<tr><td>{x["stage"]}</td><td>{x["confidence"]}</td><td><span class="pill">{x["state"]}</span></td><td>{x["risk"]}</td></tr>'
        for x in chain
    ])

    driver_rows = ''.join([
        f'<tr><td>{x["driver"]}</td><td>{x["effect"]}</td><td><span class="pill">{x["severity"]}</span></td></tr>'
        for x in drivers
    ])

    recovery_rows = ''.join([
        f'<tr><td>{x["action"]}</td><td>{x["gain"]}</td><td>{x["owner"]}</td></tr>'
        for x in recovery
    ])

    body = f"""
    <div class="hero">
        <h1>Treatment Continuity Risk Engine™</h1>
        <div class="sub">
            Patient-aware operational trust intelligence for time-critical manufacturing support.
            This engine links shift continuity, handoff survival, backup coverage, system readiness,
            labeler/printer readiness, and production support risk to downstream treatment continuity.
        </div>
        <div class="nav">
            <a href="/shift-autonomous-continuity">Autonomous Continuity</a>
            <a href="/shift-assurance-enterprise">Shift Enterprise</a>
            <a href="/shift-handoff-lineage">Handoff Lineage</a>
            <a href="/shift-overlap-intelligence">Shift Overlap</a>
            <a href="/rlt-operations/executive-war-room">RLT War Room</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Treatment Continuity Confidence</div><div class="value">84%</div></div>
        <div class="card"><div class="label">Shelf-Life Pressure</div><div class="value" style="font-size:24px;">MODERATE</div></div>
        <div class="card"><div class="label">Operational Survivability</div><div class="value">88%</div></div>
        <div class="card"><div class="label">Continuity Peer Coverage</div><div class="value" style="font-size:24px;">ACTIVE</div></div>
        <div class="card"><div class="label">Patient Window Risk</div><div class="value" style="font-size:24px;">WATCH</div></div>
        <div class="card"><div class="label">Recovery Path</div><div class="value" style="font-size:24px;">AVAILABLE</div></div>
    </div>

    <div class="section">
        <h2>Patient-Aware Continuity Decision</h2>
        <div class="decision">CONTINUITY PROTECTED — RESOLVE MES AND LABELER WATCH ITEMS BEFORE TIMING COMPRESSION INCREASES</div>
        <p>
            This does not manage patient care or make clinical decisions. It helps operations understand whether
            manufacturing-support degradation could eventually compress downstream treatment timing.
        </p>
    </div>

    <div class="section">
        <h2>Manufacturing-to-Patient Trust Chain</h2>
        <table>
            <tr><th>Stage</th><th>Confidence</th><th>State</th><th>Risk Signal</th></tr>
            {chain_rows}
        </table>
    </div>

    <div class="section">
        <h2>Continuity Risk Drivers</h2>
        <table>
            <tr><th>Driver</th><th>Potential Effect</th><th>Severity</th></tr>
            {driver_rows}
        </table>
    </div>

    <div class="section">
        <h2>Autonomous Recovery Recommendations</h2>
        <table>
            <tr><th>Action</th><th>Expected Gain</th><th>Owner</th></tr>
            {recovery_rows}
        </table>
    </div>

    <div class="section">
        <h2>Why This Wows Pharma IT Leadership</h2>
        <p>
            Traditional tools show tickets, shifts, or system health separately. This engine connects them into one
            patient-aware operational risk model. It shows whether shift-support instability could threaten treatment
            continuity before the risk becomes a formal deviation, escalation, or patient-impact concern.
        </p>
    </div>
    """

    return rlt_page("Treatment Continuity Risk Engine", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Treatment Continuity Risk Engine patch applied.")
