from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_PRESENTATION_CONTROL_CENTER_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Presentation Control Center already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_EXECUTIVE_WAR_ROOM_ACTIVE",
    "RLT_REAL_TIME_MANUFACTURING_CONFIDENCE_ACTIVE",
    "RLT_BATCH_TRUST_PASSPORT_ACTIVE",
    "RLT_AUTONOMOUS_DEVIATION_PREVENTION_ACTIVE",
    "RLT_CAPA_EFFECTIVENESS_INTELLIGENCE_ACTIVE",
    "RLT_OPERATIONAL_DIGITAL_TWIN_ACTIVE",
    "RLT_ENTERPRISE_GOVERNANCE_MESH_ACTIVE",
    "RLT_ENTERPRISE_SYSTEM_FEDERATION_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ============================================================
# RLT_PRESENTATION_CONTROL_CENTER_ACTIVE
# RLT Presentation Control Center™
# Demo navigation layer for RLT Operations AssuranceLayer™
# ============================================================

RLT_PRESENTATION_FLOW = [
    {"step": "1", "title": "Executive Opening", "route": "/rlt-operations/executive-war-room", "message": "Start with the leadership cockpit: confidence, trust, watch items, and recommended interventions."},
    {"step": "2", "title": "Mission Control", "route": "/rlt-operations", "message": "Show the RLT operational trust foundation: readiness, trust score, blast radius, and risk heat map."},
    {"step": "3", "title": "Live Confidence", "route": "/rlt-operations/manufacturing-confidence", "message": "Explain that COBIT-Chain™ tracks confidence movement, not just static status."},
    {"step": "4", "title": "Deviation Prevention", "route": "/rlt-operations/deviation-prevention", "message": "Show how weak signals become preventive action before formal deviation escalation."},
    {"step": "5", "title": "Batch Trust Passport", "route": "/rlt-operations/batch-trust-passport", "message": "Show the portable operational trust record for a batch/run."},
    {"step": "6", "title": "Release Confidence", "route": "/rlt-operations/release-confidence", "message": "Explain governed release-confidence logic without replacing QA authority."},
    {"step": "7", "title": "Audit Reconstruction", "route": "/rlt-operations/audit-reconstruction", "message": "Show how the system reconstructs the GMP storyline automatically."},
    {"step": "8", "title": "Digital Twin", "route": "/rlt-operations/digital-twin", "message": "Show the live operating state vs. governance mirror."},
    {"step": "9", "title": "Enterprise Federation", "route": "/rlt-operations/enterprise-system-federation", "message": "Explain future-state connection to Veeva, Blue Mountain, myAccess, ServiceNow, and batch evidence."},
]

@app.route("/rlt-operations/presentation-control-center")
def rlt_presentation_control_center():
    rows = ''.join([
        f'''
        <tr>
            <td><span class="pill">Step {x["step"]}</span></td>
            <td><strong>{x["title"]}</strong></td>
            <td>{x["message"]}</td>
            <td><a href="{x["route"]}">Open</a></td>
        </tr>
        '''
        for x in RLT_PRESENTATION_FLOW
    ])

    body = f"""
    <div class="hero">
        <h1>RLT Presentation Control Center™</h1>
        <div class="sub">
            A guided executive demo path for presenting COBIT-Chain™ as Operational Trust & Governance Intelligence
            for Radioligand Manufacturing. Use this page to move through the story cleanly during the meeting.
        </div>
        <div class="nav">
            <a href="/rlt-operations/executive-war-room">Start Demo</a>
            <a href="/rlt-operations">Mission Control</a>
            <a href="/rlt-operations/manufacturing-confidence">Live Confidence</a>
            <a href="/rlt-operations/deviation-prevention">Deviation Prevention</a>
            <a href="/rlt-operations/batch-trust-passport">Batch Passport</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Demo Story</div><div class="value" style="font-size:23px;">RLT Operational Trust</div></div>
        <div class="card"><div class="label">Recommended Duration</div><div class="value" style="font-size:25px;">8–12 min</div></div>
        <div class="card"><div class="label">Audience</div><div class="value" style="font-size:23px;">RLT Operations</div></div>
        <div class="card"><div class="label">Positioning</div><div class="value" style="font-size:22px;">Governance Intelligence</div></div>
    </div>

    <div class="section">
        <h2>Recommended Talk Track</h2>
        <div class="decision">COBIT-Chain™ helps leadership see whether RLT operations are trustworthy enough to proceed.</div>
        <p>
            Do not present this as blockchain, crypto, or generic IT governance. Present it as an operational trust layer
            that sits above existing systems and helps leaders detect readiness gaps, deviation pressure, audit exposure,
            release-confidence issues, and governance drift.
        </p>
    </div>

    <div class="section">
        <h2>Guided Demo Flow</h2>
        <table>
            <tr><th>Step</th><th>Module</th><th>What To Say</th><th>Link</th></tr>
            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Closing Message</h2>
        <p>
            The strongest closing line is: “Most systems tell us what happened. COBIT-Chain™ helps determine whether
            the operational state is trustworthy enough to proceed, before deviation pressure becomes harder to control.”
        </p>
    </div>
    """

    return rlt_page("RLT Presentation Control Center", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Presentation Control Center patch applied successfully.")
