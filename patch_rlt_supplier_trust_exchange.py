from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_SUPPLIER_MANUFACTURING_TRUST_EXCHANGE_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT Supplier / Manufacturing Trust Exchange already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_AI_ANOMALY_REASONING_ACTIVE",
    "RLT_ENTERPRISE_GOVERNANCE_MESH_ACTIVE",
    "RLT_CROSS_SITE_GOVERNANCE_FEDERATION_ACTIVE",
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
# RLT_SUPPLIER_MANUFACTURING_TRUST_EXCHANGE_ACTIVE
# RLT Supplier / Manufacturing Trust Exchange™
# Advanced RLT Operations AssuranceLayer™ module
# ============================================================

RLT_SUPPLIER_TRUST_EXCHANGE_DATA = {
    "exchange_state": "TRUST EXCHANGE READY",
    "network_confidence": 88,
    "partner_nodes": 4,
    "open_exceptions": 2,
    "decision": "EXTERNAL TRUST EXCHANGE READY — EXCEPTIONS REQUIRE LOCAL REVIEW",
    "nodes": [
        {"node": "Internal RLT Manufacturing", "trust": "91%", "state": "Trusted", "evidence": "Batch passport and release confidence available"},
        {"node": "External Material / Component Partner", "trust": "87%", "state": "Watch", "evidence": "Supplier evidence packet partially complete"},
        {"node": "Logistics / Chain-of-Custody", "trust": "89%", "state": "Controlled", "evidence": "Custody checkpoints traceable"},
        {"node": "Quality Review Interface", "trust": "90%", "state": "Trusted with Monitoring", "evidence": "Review package aligned but exception closure pending"},
    ],
    "exchange_controls": [
        {"control": "Portable Batch Trust Passport", "status": "ACTIVE", "value": "Shares batch/run trust context without exposing unnecessary internal detail."},
        {"control": "Evidence Completeness Check", "status": "WATCH", "value": "Flags incomplete supplier or partner evidence packets."},
        {"control": "Chain-of-Custody Confidence", "status": "ACTIVE", "value": "Tracks custody checkpoint confidence across handoffs."},
        {"control": "Exception Propagation", "status": "ACTIVE", "value": "External exceptions can reduce internal release confidence."},
        {"control": "Human Governance Gate", "status": "ENFORCED", "value": "External trust signals require human review before regulated decisions."},
    ],
    "exceptions": [
        {"exception": "Supplier evidence packet missing secondary review timestamp.", "severity": "Medium", "owner": "Supplier Quality / Operations"},
        {"exception": "Custody checkpoint rationale requires clarification.", "severity": "Medium", "owner": "Logistics / QA Review"},
    ]
}

@app.route("/rlt-operations/supplier-trust-exchange")
def rlt_supplier_manufacturing_trust_exchange():
    d = RLT_SUPPLIER_TRUST_EXCHANGE_DATA

    node_rows = ''.join([
        f'<tr><td>{x["node"]}</td><td>{x["trust"]}</td><td><span class="pill">{x["state"]}</span></td><td>{x["evidence"]}</td></tr>'
        for x in d["nodes"]
    ])

    control_rows = ''.join([
        f'<tr><td>{x["control"]}</td><td><span class="pill">{x["status"]}</span></td><td>{x["value"]}</td></tr>'
        for x in d["exchange_controls"]
    ])

    exception_rows = ''.join([
        f'<tr><td>{x["exception"]}</td><td><span class="pill">{x["severity"]}</span></td><td>{x["owner"]}</td></tr>'
        for x in d["exceptions"]
    ])

    body = f"""
    <div class="hero">
        <h1>Supplier / Manufacturing Trust Exchange™</h1>
        <div class="sub">
            Extends RLT operational trust beyond the internal site by exchanging governed confidence signals across
            suppliers, materials, logistics, quality review, custody checkpoints, and batch trust passports.
        </div>
        <div class="nav">
            <a href="/rlt-operations/executive-war-room">Executive War Room</a>
            <a href="/rlt-operations/governance-mesh">Governance Mesh</a>
            <a href="/rlt-operations/cross-site-federation">Cross-Site Federation</a>
            <a href="/rlt-operations/batch-trust-passport">Batch Passport</a>
            <a href="/rlt-operations/anomaly-reasoning">AI Anomaly Reasoning</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Exchange State</div><div class="value" style="font-size:23px;">{d["exchange_state"]}</div></div>
        <div class="card"><div class="label">Network Confidence</div><div class="value">{d["network_confidence"]}%</div></div>
        <div class="card"><div class="label">Partner Nodes</div><div class="value">{d["partner_nodes"]}</div></div>
        <div class="card"><div class="label">Open Exceptions</div><div class="value">{d["open_exceptions"]}</div></div>
    </div>

    <div class="section">
        <h2>Trust Exchange Decision</h2>
        <div class="decision">{d["decision"]}</div>
        <p>
            This layer does not expose confidential internal records. It exchanges governed confidence signals:
            what is trusted, what is partial, what is missing, and what requires human review before assurance can propagate.
        </p>
    </div>

    <div class="section">
        <h2>Trust Exchange Network</h2>
        <table>
            <tr><th>Node</th><th>Trust</th><th>State</th><th>Evidence Signal</th></tr>
            {node_rows}
        </table>
    </div>

    <div class="section">
        <h2>Exchange Control Model</h2>
        <table>
            <tr><th>Control</th><th>Status</th><th>Enterprise Value</th></tr>
            {control_rows}
        </table>
    </div>

    <div class="section">
        <h2>Open Trust Exceptions</h2>
        <table>
            <tr><th>Exception</th><th>Severity</th><th>Owner</th></tr>
            {exception_rows}
        </table>
    </div>
    """

    return rlt_page("Supplier / Manufacturing Trust Exchange", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT Supplier / Manufacturing Trust Exchange patch applied successfully.")
