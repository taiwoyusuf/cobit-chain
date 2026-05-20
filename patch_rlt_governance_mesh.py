from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_ENTERPRISE_GOVERNANCE_MESH_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Enterprise Governance Mesh already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_CROSS_SITE_GOVERNANCE_FEDERATION_ACTIVE",
    "RLT_OPERATIONAL_DIGITAL_TWIN_ACTIVE",
    "RLT_EXECUTIVE_WAR_ROOM_ACTIVE",
    "RLT_REAL_TIME_MANUFACTURING_CONFIDENCE_ACTIVE",
    "RLT_BATCH_TRUST_PASSPORT_ACTIVE",
    "RLT_PRODUCTION_RELEASE_CONFIDENCE_ACTIVE",
    "RLT_AUTONOMOUS_GMP_TRUST_FABRIC_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ============================================================
# RLT_ENTERPRISE_GOVERNANCE_MESH_ACTIVE
# RLT Enterprise Governance Mesh™
# Advanced RLT Operations AssuranceLayer™ module
# ============================================================

RLT_GOVERNANCE_MESH_DATA = {
    "mesh_state": "ACTIVE FEDERATED GOVERNANCE",
    "mesh_confidence": 90,
    "connected_domains": 7,
    "decision": "ENTERPRISE GOVERNANCE MESH ACTIVE — LOCAL WATCH ITEMS CONTROLLED",
    "domains": [
        {"domain": "RLT Operations", "signal": "Manufacturing confidence and release posture", "state": "Active"},
        {"domain": "Batch Trust Passport", "signal": "Portable batch/run assurance", "state": "Active"},
        {"domain": "Operational Digital Twin", "signal": "Live state vs governance mirror", "state": "Active"},
        {"domain": "Cross-Site Federation", "signal": "Site-level trust normalization", "state": "Active"},
        {"domain": "Recovery Governance", "signal": "Restart and recovery assurance dependencies", "state": "Linked"},
        {"domain": "Assurance Product Stack", "signal": "Portable assurance factory and maturity scoring", "state": "Linked"},
        {"domain": "Executive War Room", "signal": "Leadership intervention orchestration", "state": "Active"},
    ],
    "mesh_links": [
        "RLT Operations",
        "Digital Twin",
        "Batch Passport",
        "Release Confidence",
        "Cross-Site Federation",
        "Recovery Governance",
        "Executive Assurance"
    ],
    "controls": [
        {"control": "Common Trust Language", "status": "ACTIVE", "value": "All modules speak readiness, confidence, drift, trust, and assurance."},
        {"control": "Cross-Domain Escalation", "status": "ACTIVE", "value": "Weak signals can escalate to executive intervention."},
        {"control": "Portable Assurance Records", "status": "ACTIVE", "value": "Passports allow trust evidence to travel across contexts."},
        {"control": "Federated Governance View", "status": "ACTIVE", "value": "Local operating signals roll up into enterprise governance intelligence."},
    ]
}

@app.route("/rlt-operations/governance-mesh")
def rlt_enterprise_governance_mesh():
    d = RLT_GOVERNANCE_MESH_DATA

    domain_rows = ''.join([
        f'<tr><td>{x["domain"]}</td><td>{x["signal"]}</td><td><span class="pill">{x["state"]}</span></td></tr>'
        for x in d["domains"]
    ])

    mesh_chain = ''.join([
        f'<div class="node">{x}</div><div class="arrow">→</div>'
        for x in d["mesh_links"]
    ])

    control_rows = ''.join([
        f'<tr><td>{x["control"]}</td><td><span class="pill">{x["status"]}</span></td><td>{x["value"]}</td></tr>'
        for x in d["controls"]
    ])

    body = f"""
    <div class="hero">
        <h1>RLT Enterprise Governance Mesh™</h1>
        <div class="sub">
            Connects RLT operations, digital twin signals, batch trust passports, release confidence,
            cross-site federation, recovery governance, and executive assurance into one governed trust mesh.
        </div>
        <div class="nav">
            <a href="/rlt-operations/executive-war-room">Executive War Room</a>
            <a href="/rlt-operations/cross-site-federation">Cross-Site Federation</a>
            <a href="/rlt-operations/digital-twin">Digital Twin</a>
            <a href="/rlt-operations/batch-trust-passport">Batch Passport</a>
            <a href="/rlt-operations/release-confidence">Release Confidence</a>
            <a href="/recovery-governance-command-center">Recovery Governance</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Mesh State</div><div class="value" style="font-size:23px;">{d["mesh_state"]}</div></div>
        <div class="card"><div class="label">Mesh Confidence</div><div class="value">{d["mesh_confidence"]}%</div></div>
        <div class="card"><div class="label">Connected Domains</div><div class="value">{d["connected_domains"]}</div></div>
    </div>

    <div class="section">
        <h2>Mesh Decision</h2>
        <div class="decision">{d["decision"]}</div>
        <p>
            This layer shows COBIT-Chain™ as a governance operating architecture, not a single app page.
            It links operational trust, recovery trust, release trust, site trust, and executive assurance into one mesh.
        </p>
    </div>

    <div class="section">
        <h2>Governance Mesh Flow</h2>
        <div class="chain">
            {mesh_chain}
        </div>
    </div>

    <div class="section">
        <h2>Connected Governance Domains</h2>
        <table>
            <tr><th>Domain</th><th>Signal</th><th>State</th></tr>
            {domain_rows}
        </table>
    </div>

    <div class="section">
        <h2>Mesh Control Model</h2>
        <table>
            <tr><th>Control</th><th>Status</th><th>Enterprise Value</th></tr>
            {control_rows}
        </table>
    </div>
    """

    return rlt_page("RLT Enterprise Governance Mesh", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Enterprise Governance Mesh patch applied successfully.")
