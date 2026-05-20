from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_BATCH_TRUST_PASSPORT_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Batch Trust Passport already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_AUTONOMOUS_GMP_TRUST_FABRIC_ACTIVE",
    "RLT_PRODUCTION_RELEASE_CONFIDENCE_ACTIVE",
    "RLT_GOVERNANCE_DRIFT_INTELLIGENCE_ACTIVE",
    "RLT_AUTONOMOUS_AUDIT_RECONSTRUCTION_ACTIVE",
    "RLT_SHIFT_INTEGRITY_ENGINE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ============================================================
# RLT_BATCH_TRUST_PASSPORT_ACTIVE
# Batch Trust Passport™
# Advanced RLT Operations AssuranceLayer™ module
# ============================================================

RLT_BATCH_TRUST_PASSPORT_DATA = {
    "passport_id": "RLT-PASS-2026-001",
    "batch_id": "RLT-BATCH-041",
    "product_context": "Radioligand Manufacturing Run",
    "passport_status": "CONDITIONALLY DEFENSIBLE",
    "overall_confidence": 91,
    "release_confidence": 90,
    "trust_fabric": 92,
    "audit_confidence": 93,
    "drift_score": 18,
    "open_conditions": 1,
    "domains": [
        {"domain": "Batch Identity", "status": "VERIFIED", "evidence": "Batch/run reference linked to governed operating record."},
        {"domain": "Operator Qualification", "status": "VERIFIED", "evidence": "Training state current and aligned to task scope."},
        {"domain": "SOP Currency", "status": "VERIFIED", "evidence": "Controlled procedure confirmed current during execution window."},
        {"domain": "Equipment Readiness", "status": "VERIFIED", "evidence": "Readiness log supports production continuity."},
        {"domain": "Shift Integrity", "status": "WATCH", "evidence": "Minor recurring handoff delay monitored."},
        {"domain": "Audit Reconstruction", "status": "DEFENSIBLE", "evidence": "Operational timeline reconstructed with 93% confidence."},
        {"domain": "Governance Drift", "status": "WATCH", "evidence": "Early drift detected but not critical."},
        {"domain": "Release Confidence", "status": "CONDITIONAL", "evidence": "Environmental rationale closure required before final assurance."},
    ],
    "chain": [
        "Batch Identity",
        "SOP State",
        "Training State",
        "Equipment Readiness",
        "Shift Integrity",
        "Audit Reconstruction",
        "Trust Fabric",
        "Release Confidence"
    ],
    "conditions": [
        {"condition": "Close environmental rationale record before final release assurance.", "owner": "Supervisor / QA Review", "priority": "High"},
        {"condition": "Monitor repeated handoff delay in next RLT production window.", "owner": "Operations Lead", "priority": "Medium"},
        {"condition": "Attach reconstructed GMP timeline to batch trust record.", "owner": "Governance Reviewer", "priority": "Medium"},
    ]
}

@app.route("/rlt-operations/batch-trust-passport")
def rlt_batch_trust_passport():
    d = RLT_BATCH_TRUST_PASSPORT_DATA

    domain_rows = ''.join([
        f'<tr><td>{x["domain"]}</td><td><span class="pill">{x["status"]}</span></td><td>{x["evidence"]}</td></tr>'
        for x in d["domains"]
    ])

    chain = ''.join([
        f'<div class="node">{x}</div><div class="arrow">→</div>'
        for x in d["chain"]
    ])

    condition_rows = ''.join([
        f'<tr><td>{x["condition"]}</td><td>{x["owner"]}</td><td><span class="pill">{x["priority"]}</span></td></tr>'
        for x in d["conditions"]
    ])

    body = f"""
    <div class="hero">
        <h1>Batch Trust Passport™</h1>
        <div class="sub">
            A portable operational trust record for an RLT batch/run. It consolidates identity, SOP state,
            training validity, equipment readiness, shift integrity, audit reconstruction, governance drift,
            trust fabric, and release confidence into one defensible passport.
        </div>
        <div class="nav">
            <a href="/rlt-operations">Back to RLT Mission Control</a>
            <a href="/rlt-operations/release-confidence">Release Confidence</a>
            <a href="/rlt-operations/trust-fabric">Trust Fabric</a>
            <a href="/rlt-operations/audit-reconstruction">Audit Reconstruction</a>
            <a href="/rlt-operations/governance-drift">Governance Drift</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Passport ID</div><div class="value" style="font-size:24px;">{d["passport_id"]}</div></div>
        <div class="card"><div class="label">Batch / Run</div><div class="value" style="font-size:24px;">{d["batch_id"]}</div></div>
        <div class="card"><div class="label">Passport Status</div><div class="value" style="font-size:22px;">{d["passport_status"]}</div></div>
        <div class="card"><div class="label">Overall Confidence</div><div class="value">{d["overall_confidence"]}%</div></div>
        <div class="card"><div class="label">Release Confidence</div><div class="value">{d["release_confidence"]}%</div></div>
        <div class="card"><div class="label">Trust Fabric</div><div class="value">{d["trust_fabric"]}%</div></div>
        <div class="card"><div class="label">Audit Confidence</div><div class="value">{d["audit_confidence"]}%</div></div>
        <div class="card"><div class="label">Open Conditions</div><div class="value">{d["open_conditions"]}</div></div>
    </div>

    <div class="section">
        <h2>Passport Verdict</h2>
        <div class="decision">{d["passport_status"]}</div>
        <p>
            This passport does not replace the official batch record or QA release authority. It creates a portable,
            executive-readable trust record that explains whether the operational chain is complete, defensible,
            and ready for final assurance decision-making.
        </p>
    </div>

    <div class="section">
        <h2>Operational Trust Chain</h2>
        <div class="chain">
            {chain}
        </div>
    </div>

    <div class="section">
        <h2>Passport Evidence Register</h2>
        <table>
            <tr><th>Trust Domain</th><th>Status</th><th>Evidence Statement</th></tr>
            {domain_rows}
        </table>
    </div>

    <div class="section">
        <h2>Open Conditions Before Final Assurance</h2>
        <table>
            <tr><th>Condition</th><th>Owner</th><th>Priority</th></tr>
            {condition_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>
        <p>
            The Batch Trust Passport™ gives leadership one governed record for the question:
            can this RLT batch/run be trusted from an operational, evidence, audit, and governance perspective?
            It turns scattered readiness signals into a portable assurance artifact.
        </p>
    </div>
    """

    return rlt_page("Batch Trust Passport", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Batch Trust Passport patch applied successfully.")
