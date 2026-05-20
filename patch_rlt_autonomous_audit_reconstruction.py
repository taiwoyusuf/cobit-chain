from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_AUTONOMOUS_AUDIT_RECONSTRUCTION_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Autonomous Audit Reconstruction already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_SHIFT_INTEGRITY_ENGINE_ACTIVE",
    "/rlt-operations",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker/link not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ============================================================
# RLT_AUTONOMOUS_AUDIT_RECONSTRUCTION_ACTIVE
# Autonomous Audit Reconstruction™
# Advanced RLT Operations AssuranceLayer™ module
# ============================================================

RLT_AUDIT_RECONSTRUCTION_DATA = {
    "confidence": 93,
    "timeline_status": "RECONSTRUCTED",
    "evidence_gaps": 2,
    "decision": "AUDIT STORYLINE DEFENSIBLE",
    "timeline": [
        {"time": "06:10", "event": "Pre-shift readiness check completed", "source": "Shift record", "confidence": "96%"},
        {"time": "06:25", "event": "SOP version confirmed current", "source": "Controlled procedure index", "confidence": "98%"},
        {"time": "06:40", "event": "Operator training state verified", "source": "Training evidence", "confidence": "100%"},
        {"time": "07:05", "event": "Equipment readiness confirmed", "source": "Equipment readiness log", "confidence": "94%"},
        {"time": "08:15", "event": "Environmental state reviewed", "source": "Environmental monitoring record", "confidence": "91%"},
        {"time": "09:20", "event": "Supervisor review completed", "source": "Review record", "confidence": "89%"},
        {"time": "09:45", "event": "Release exposure assessed", "source": "Governance decision log", "confidence": "92%"},
    ],
    "evidence": [
        {"record": "Shift handoff note", "status": "FOUND", "risk": "Low"},
        {"record": "SOP version evidence", "status": "FOUND", "risk": "Low"},
        {"record": "Training verification", "status": "FOUND", "risk": "Low"},
        {"record": "Reviewer signoff timestamp", "status": "FOUND", "risk": "Low"},
        {"record": "Environmental exception rationale", "status": "PARTIAL", "risk": "Medium"},
        {"record": "Secondary reviewer availability note", "status": "PARTIAL", "risk": "Medium"},
    ],
    "findings": [
        {"finding": "Timeline can be reconstructed without manual spreadsheet stitching.", "impact": "High value"},
        {"finding": "Two partial records require reviewer clarification before final audit pack closure.", "impact": "Medium"},
        {"finding": "No critical break in SOP, training, or equipment readiness chain.", "impact": "Low risk"},
    ]
}

@app.route("/rlt-operations/audit-reconstruction")
def rlt_autonomous_audit_reconstruction():
    d = RLT_AUDIT_RECONSTRUCTION_DATA

    timeline_rows = ''.join([
        f'<tr><td>{x["time"]}</td><td>{x["event"]}</td><td>{x["source"]}</td><td>{x["confidence"]}</td></tr>'
        for x in d["timeline"]
    ])

    evidence_rows = ''.join([
        f'<tr><td>{x["record"]}</td><td><span class="pill">{x["status"]}</span></td><td>{x["risk"]}</td></tr>'
        for x in d["evidence"]
    ])

    finding_rows = ''.join([
        f'<tr><td>{x["finding"]}</td><td><span class="pill">{x["impact"]}</span></td></tr>'
        for x in d["findings"]
    ])

    body = f"""
    <div class="hero">
        <h1>Autonomous Audit Reconstruction™</h1>
        <div class="sub">
            Reconstructs the GMP operational storyline across shift activity, SOP state, training evidence,
            equipment readiness, environmental review, supervisor actions, and release exposure.
        </div>
        <div class="nav">
            <a href="/rlt-operations">Back to RLT Mission Control</a>
            <a href="/rlt-operations/shift-integrity">Shift Integrity</a>
            <a href="/rlt-operations/blast-radius">Blast Radius</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Audit Confidence</div><div class="value">{d["confidence"]}%</div></div>
        <div class="card"><div class="label">Timeline Status</div><div class="value">{d["timeline_status"]}</div></div>
        <div class="card"><div class="label">Evidence Gaps</div><div class="value">{d["evidence_gaps"]}</div></div>
        <div class="card"><div class="label">Decision</div><div class="value" style="font-size:22px;">{d["decision"]}</div></div>
    </div>

    <div class="section">
        <h2>Reconstructed GMP Timeline</h2>
        <table>
            <tr><th>Time</th><th>Operational Event</th><th>Evidence Source</th><th>Confidence</th></tr>
            {timeline_rows}
        </table>
    </div>

    <div class="section">
        <h2>Evidence Completeness Check</h2>
        <table>
            <tr><th>Evidence Record</th><th>Status</th><th>Risk</th></tr>
            {evidence_rows}
        </table>
    </div>

    <div class="section">
        <h2>Audit Reconstruction Findings</h2>
        <table>
            <tr><th>Finding</th><th>Impact</th></tr>
            {finding_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>
        <p>
            Instead of waiting for teams to manually rebuild what happened during a deviation, inspection,
            batch review, or operational question, this module reconstructs the defensible GMP storyline
            from governed evidence. It shows what is complete, what is partial, and what must be clarified
            before final assurance is issued.
        </p>
    </div>
    """

    return rlt_page("Autonomous Audit Reconstruction", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Autonomous Audit Reconstruction patch applied successfully.")
