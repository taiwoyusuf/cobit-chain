from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_ENTERPRISE_SYSTEM_FEDERATION_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Enterprise System Federation already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_DSCSA_CHAIN_OF_CUSTODY_TRUST_ACTIVE",
    "RLT_SUPPLIER_MANUFACTURING_TRUST_EXCHANGE_ACTIVE",
    "RLT_ENTERPRISE_GOVERNANCE_MESH_ACTIVE",
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
# RLT_ENTERPRISE_SYSTEM_FEDERATION_ACTIVE
# Veeva / Blue Mountain / myAccess Federation Layer™
# Advanced RLT Operations AssuranceLayer™ module
# ============================================================

RLT_ENTERPRISE_SYSTEM_FEDERATION_DATA = {
    "federation_state": "FUTURE-STATE CONNECTOR MODEL",
    "confidence": 86,
    "systems_mapped": 5,
    "decision": "SYSTEM FEDERATION MODEL READY — LIVE INTEGRATION NOT ENABLED",
    "systems": [
        {"system": "Veeva Vault", "role": "Controlled documents, SOPs, QA records, CAPA evidence", "signal": "Document and quality-trace confidence", "state": "Future connector"},
        {"system": "Blue Mountain RAM", "role": "Equipment readiness, maintenance, calibration, asset lifecycle", "signal": "Equipment trust and readiness confidence", "state": "Future connector"},
        {"system": "myAccess", "role": "Access governance, role fit, user entitlement evidence", "signal": "Role/access trust and segregation visibility", "state": "Future connector"},
        {"system": "ServiceNow", "role": "Tickets, CIs, change/incident context", "signal": "Operational workflow and CI lineage", "state": "Future connector"},
        {"system": "Batch / Shift Evidence Layer", "role": "Local operational evidence, handoff, review, release context", "signal": "Execution trust and batch confidence", "state": "Active model"},
    ],
    "federation_controls": [
        {"control": "No system replacement", "status": "ENFORCED", "value": "COBIT-Chain reads trust signals; it does not replace authoritative systems."},
        {"control": "Evidence-source hierarchy", "status": "ACTIVE", "value": "Authoritative records remain in source systems."},
        {"control": "Cross-system reconciliation", "status": "MODELLED", "value": "Detects mismatch between document, equipment, access, and operational evidence."},
        {"control": "Human approval gate", "status": "ENFORCED", "value": "Federated signals support human governance decisions."},
    ]
}

@app.route("/rlt-operations/enterprise-system-federation")
def rlt_enterprise_system_federation():
    d = RLT_ENTERPRISE_SYSTEM_FEDERATION_DATA

    system_rows = ''.join([
        f'<tr><td>{x["system"]}</td><td>{x["role"]}</td><td>{x["signal"]}</td><td><span class="pill">{x["state"]}</span></td></tr>'
        for x in d["systems"]
    ])

    control_rows = ''.join([
        f'<tr><td>{x["control"]}</td><td><span class="pill">{x["status"]}</span></td><td>{x["value"]}</td></tr>'
        for x in d["federation_controls"]
    ])

    body = f"""
    <div class="hero">
        <h1>Veeva / Blue Mountain / myAccess Federation Layer™</h1>
        <div class="sub">
            Future-state federation view showing how RLT operational trust could connect controlled documents,
            equipment readiness, access governance, ServiceNow context, and batch/shift evidence without replacing
            authoritative enterprise systems.
        </div>
        <div class="nav">
            <a href="/rlt-operations/governance-mesh">Governance Mesh</a>
            <a href="/rlt-operations/digital-twin">Digital Twin</a>
            <a href="/rlt-operations/batch-trust-passport">Batch Passport</a>
            <a href="/rlt-operations/executive-war-room">Executive War Room</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Federation State</div><div class="value" style="font-size:23px;">{d["federation_state"]}</div></div>
        <div class="card"><div class="label">Model Confidence</div><div class="value">{d["confidence"]}%</div></div>
        <div class="card"><div class="label">Systems Mapped</div><div class="value">{d["systems_mapped"]}</div></div>
    </div>

    <div class="section">
        <h2>Federation Decision</h2>
        <div class="decision">{d["decision"]}</div>
        <p>
            This is not presented as a live production connector. It is a future-state trust architecture showing
            how COBIT-Chain™ can sit above enterprise systems as a governance intelligence layer.
        </p>
    </div>

    <div class="section">
        <h2>Enterprise System Trust Map</h2>
        <table>
            <tr><th>System</th><th>Role</th><th>Trust Signal</th><th>State</th></tr>
            {system_rows}
        </table>
    </div>

    <div class="section">
        <h2>Federation Control Model</h2>
        <table>
            <tr><th>Control</th><th>Status</th><th>Value</th></tr>
            {control_rows}
        </table>
    </div>
    """

    return rlt_page("RLT Enterprise System Federation", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Enterprise System Federation patch applied successfully.")
