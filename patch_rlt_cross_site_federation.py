from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_CROSS_SITE_GOVERNANCE_FEDERATION_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Cross-Site Governance Federation already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_OPERATIONAL_DIGITAL_TWIN_ACTIVE",
    "RLT_EXECUTIVE_WAR_ROOM_ACTIVE",
    "RLT_REAL_TIME_MANUFACTURING_CONFIDENCE_ACTIVE",
    "RLT_BATCH_TRUST_PASSPORT_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ============================================================
# RLT_CROSS_SITE_GOVERNANCE_FEDERATION_ACTIVE
# RLT Cross-Site Governance Federation™
# Advanced RLT Operations AssuranceLayer™ module
# ============================================================

RLT_CROSS_SITE_FEDERATION_DATA = {
    "federation_state": "FEDERATED WITH LOCAL WATCH ITEMS",
    "global_confidence": 89,
    "site_count": 3,
    "open_watch_items": 4,
    "decision": "FEDERATED ASSURANCE ACTIVE — LOCAL CLOSURES REQUIRED",
    "sites": [
        {"site": "RLT Site A", "readiness": "96%", "release": "92%", "trust": "94%", "state": "Trusted"},
        {"site": "RLT Site B", "readiness": "91%", "release": "88%", "trust": "90%", "state": "Watch"},
        {"site": "RLT Site C", "readiness": "87%", "release": "84%", "trust": "86%", "state": "Local closure required"},
    ],
    "federated_controls": [
        {"control": "Common Readiness Model", "status": "ACTIVE", "meaning": "Sites evaluated using the same readiness logic."},
        {"control": "Portable Batch Trust Passport", "status": "ACTIVE", "meaning": "Batch trust can be compared across operating contexts."},
        {"control": "Cross-Site Drift Detection", "status": "WATCH", "meaning": "Similar handoff and reviewer-latency patterns detected."},
        {"control": "Release Confidence Normalization", "status": "ACTIVE", "meaning": "Release confidence is scored consistently across sites."},
        {"control": "Executive Federation View", "status": "ACTIVE", "meaning": "Leadership can see where local risk affects enterprise trust."},
    ],
    "interventions": [
        {"intervention": "Close Site C environmental rationale before federation confidence improves.", "owner": "Site C Operations / QA"},
        {"intervention": "Compare Site B reviewer-latency trend with Site A best practice.", "owner": "RLT Operations Excellence"},
        {"intervention": "Standardize handoff evidence fields across all RLT production windows.", "owner": "Governance Lead"},
    ]
}

@app.route("/rlt-operations/cross-site-federation")
def rlt_cross_site_governance_federation():
    d = RLT_CROSS_SITE_FEDERATION_DATA

    site_rows = ''.join([
        f'<tr><td>{x["site"]}</td><td>{x["readiness"]}</td><td>{x["release"]}</td><td>{x["trust"]}</td><td><span class="pill">{x["state"]}</span></td></tr>'
        for x in d["sites"]
    ])

    control_rows = ''.join([
        f'<tr><td>{x["control"]}</td><td><span class="pill">{x["status"]}</span></td><td>{x["meaning"]}</td></tr>'
        for x in d["federated_controls"]
    ])

    intervention_rows = ''.join([
        f'<tr><td>{x["intervention"]}</td><td>{x["owner"]}</td></tr>'
        for x in d["interventions"]
    ])

    body = f"""
    <div class="hero">
        <h1>RLT Cross-Site Governance Federation™</h1>
        <div class="sub">
            Federates operational trust across RLT sites, production windows, batches, reviewers, and governance states.
            This module shows how local readiness, release confidence, drift, and batch passports roll up into enterprise assurance.
        </div>
        <div class="nav">
            <a href="/rlt-operations/executive-war-room">Executive War Room</a>
            <a href="/rlt-operations/digital-twin">Operational Digital Twin</a>
            <a href="/rlt-operations/batch-trust-passport">Batch Passport</a>
            <a href="/rlt-operations/release-confidence">Release Confidence</a>
            <a href="/rlt-operations/manufacturing-confidence">Manufacturing Confidence</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Federation State</div><div class="value" style="font-size:23px;">{d["federation_state"]}</div></div>
        <div class="card"><div class="label">Global Confidence</div><div class="value">{d["global_confidence"]}%</div></div>
        <div class="card"><div class="label">Sites Federated</div><div class="value">{d["site_count"]}</div></div>
        <div class="card"><div class="label">Open Watch Items</div><div class="value">{d["open_watch_items"]}</div></div>
    </div>

    <div class="section">
        <h2>Federated Assurance Decision</h2>
        <div class="decision">{d["decision"]}</div>
        <p>
            This module does not assume every site is identical. It creates a common governance language so leadership
            can compare readiness, trust, release confidence, and risk across RLT operations without flattening local context.
        </p>
    </div>

    <div class="section">
        <h2>Cross-Site Trust Board</h2>
        <table>
            <tr><th>Site</th><th>Readiness</th><th>Release Confidence</th><th>Trust Score</th><th>State</th></tr>
            {site_rows}
        </table>
    </div>

    <div class="section">
        <h2>Federated Governance Controls</h2>
        <table>
            <tr><th>Control</th><th>Status</th><th>Meaning</th></tr>
            {control_rows}
        </table>
    </div>

    <div class="section">
        <h2>Enterprise Interventions</h2>
        <table>
            <tr><th>Intervention</th><th>Owner</th></tr>
            {intervention_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>
        <p>
            As RLT operations scale, leadership needs more than local dashboards. Cross-Site Governance Federation™
            shows how operational trust can be normalized, compared, and governed across sites while still preserving
            local risk context.
        </p>
    </div>
    """

    return rlt_page("RLT Cross-Site Governance Federation", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Cross-Site Governance Federation patch applied successfully.")
