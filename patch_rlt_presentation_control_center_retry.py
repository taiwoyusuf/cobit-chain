from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# RLT_PRESENTATION_CONTROL_CENTER_ACTIVE"

if MARKER in text:
    print("RLT Presentation Control Center already exists.")
    raise SystemExit(0)

if "RLT_OPERATIONS_VERTICAL_ACTIVE" not in text:
    raise RuntimeError("RLT base vertical marker missing.")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Insertion point not found.')

code = r'''

# ============================================================
# RLT_PRESENTATION_CONTROL_CENTER_ACTIVE
# RLT Presentation Control Center™
# ============================================================

@app.route("/rlt-operations/presentation-control-center")
def rlt_presentation_control_center():
    flow = [
        ("1", "Executive War Room", "/rlt-operations/executive-war-room", "Open with the leadership cockpit: trust, confidence, watch items, and interventions."),
        ("2", "RLT Mission Control", "/rlt-operations", "Show the foundation: readiness, trust score, deviation probability, and operational risk."),
        ("3", "Real-Time Manufacturing Confidence", "/rlt-operations/manufacturing-confidence", "Show that COBIT-Chain tracks confidence movement, not only static status."),
        ("4", "Deviation Prevention", "/rlt-operations/deviation-prevention", "Show how weak signals become preventive action before formal deviation escalation."),
        ("5", "Batch Trust Passport", "/rlt-operations/batch-trust-passport", "Show one portable operational trust record for a batch/run."),
        ("6", "Release Confidence", "/rlt-operations/release-confidence", "Show governed release-confidence logic without replacing QA authority."),
        ("7", "Audit Reconstruction", "/rlt-operations/audit-reconstruction", "Show how the GMP operational storyline is reconstructed."),
        ("8", "Operational Digital Twin", "/rlt-operations/digital-twin", "Show live operating state versus governance mirror."),
        ("9", "Enterprise System Federation", "/rlt-operations/enterprise-system-federation", "Show future-state linkage to Veeva, Blue Mountain, myAccess, ServiceNow, and batch evidence.")
    ]

    rows = ''.join([
        f'''
        <tr>
            <td><span class="pill">Step {step}</span></td>
            <td><strong>{title}</strong></td>
            <td>{message}</td>
            <td><a href="{route}">Open</a></td>
        </tr>
        '''
        for step, title, route, message in flow
    ])

    body = f"""
    <div class="hero">
        <h1>RLT Presentation Control Center™</h1>
        <div class="sub">
            Guided executive demo path for presenting COBIT-Chain™ as Operational Trust & Governance Intelligence
            for Radioligand Manufacturing.
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
            Most systems tell us what happened. COBIT-Chain™ helps determine whether the operational state is
            trustworthy enough to proceed before deviation pressure becomes harder to control.
        </p>
    </div>
    """

    return rlt_page("RLT Presentation Control Center", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Presentation Control Center retry patch applied.")
