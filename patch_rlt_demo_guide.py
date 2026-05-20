from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# RLT_DEMO_GUIDE_ACTIVE"

if MARKER in text:
    print("RLT Demo Guide already exists.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# RLT_DEMO_GUIDE_ACTIVE
# RLT Demo Guide
# ============================================================

@app.route("/rlt-demo")
def rlt_demo_guide():
    body = """
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
        <h2>Guided Demo Flow</h2>
        <table>
            <tr><th>Step</th><th>Module</th><th>What To Say</th><th>Link</th></tr>
            <tr><td><span class="pill">Step 1</span></td><td>Executive War Room</td><td>Start with leadership cockpit: trust, confidence, watch items, and interventions.</td><td><a href="/rlt-operations/executive-war-room">Open</a></td></tr>
            <tr><td><span class="pill">Step 2</span></td><td>Mission Control</td><td>Show readiness, trust score, deviation probability, and operational risk.</td><td><a href="/rlt-operations">Open</a></td></tr>
            <tr><td><span class="pill">Step 3</span></td><td>Live Manufacturing Confidence</td><td>Show confidence movement, not only static status.</td><td><a href="/rlt-operations/manufacturing-confidence">Open</a></td></tr>
            <tr><td><span class="pill">Step 4</span></td><td>Deviation Prevention</td><td>Show how weak signals become preventive action before escalation.</td><td><a href="/rlt-operations/deviation-prevention">Open</a></td></tr>
            <tr><td><span class="pill">Step 5</span></td><td>Batch Trust Passport</td><td>Show one portable operational trust record for a batch/run.</td><td><a href="/rlt-operations/batch-trust-passport">Open</a></td></tr>
            <tr><td><span class="pill">Step 6</span></td><td>Release Confidence</td><td>Show governed release-confidence logic without replacing QA authority.</td><td><a href="/rlt-operations/release-confidence">Open</a></td></tr>
            <tr><td><span class="pill">Step 7</span></td><td>Operational Digital Twin</td><td>Show live state versus governance mirror.</td><td><a href="/rlt-operations/digital-twin">Open</a></td></tr>
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

print("RLT Demo Guide route inserted.")
