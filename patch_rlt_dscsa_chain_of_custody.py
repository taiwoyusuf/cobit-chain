from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

ACTIVE_MARKER = "# RLT_DSCSA_CHAIN_OF_CUSTODY_TRUST_ACTIVE"

if ACTIVE_MARKER in text:
    print("RLT DSCSA Chain-of-Custody Trust already exists. No duplicate patch applied.")
    raise SystemExit(0)

required = [
    "RLT_OPERATIONS_VERTICAL_ACTIVE",
    "RLT_SUPPLIER_MANUFACTURING_TRUST_EXCHANGE_ACTIVE",
    "RLT_BATCH_TRUST_PASSPORT_ACTIVE",
    "DSCSA_TRUSTCHAIN_V1_PROMOTED_REDIRECT_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required existing marker not found: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError('Could not find if __name__ == "__main__": insertion point.')

code = r'''

# ============================================================
# RLT_DSCSA_CHAIN_OF_CUSTODY_TRUST_ACTIVE
# RLT DSCSA / Chain-of-Custody Trust Layer™
# Advanced RLT Operations AssuranceLayer™ module
# ============================================================

RLT_DSCSA_CHAIN_OF_CUSTODY_DATA = {
    "custody_state": "TRACEABLE WITH REVIEW ITEMS",
    "trust_score": 89,
    "custody_checkpoints": 6,
    "open_exceptions": 2,
    "decision": "CHAIN-OF-CUSTODY TRUST ACTIVE — REVIEW EXCEPTIONS BEFORE FINAL ASSURANCE",
    "checkpoints": [
        {"checkpoint": "Manufacturing Release Context", "status": "Trusted", "confidence": "91%", "evidence": "Batch Trust Passport available"},
        {"checkpoint": "Material / Component Evidence", "status": "Watch", "confidence": "87%", "evidence": "Supplier evidence partially complete"},
        {"checkpoint": "Internal Custody Handoff", "status": "Trusted", "confidence": "93%", "evidence": "Handoff trace captured"},
        {"checkpoint": "Logistics Transfer", "status": "Controlled", "confidence": "89%", "evidence": "Transfer checkpoint traceable"},
        {"checkpoint": "Quality Review Interface", "status": "Trusted with Monitoring", "confidence": "90%", "evidence": "Review package aligned"},
        {"checkpoint": "Exception Closure", "status": "Action Required", "confidence": "84%", "evidence": "Two exception clarifications pending"},
    ],
    "trust_path": [
        "Batch Trust Passport",
        "Supplier Evidence",
        "Internal Custody",
        "Logistics Transfer",
        "Quality Review",
        "Exception Closure",
        "Final Assurance"
    ],
    "exceptions": [
        {"exception": "Supplier evidence packet missing secondary review timestamp.", "severity": "Medium", "owner": "Supplier Quality"},
        {"exception": "Custody checkpoint rationale requires clarification.", "severity": "Medium", "owner": "Logistics / QA Review"},
    ]
}

@app.route("/rlt-operations/dscsa-chain-of-custody")
def rlt_dscsa_chain_of_custody_trust():
    d = RLT_DSCSA_CHAIN_OF_CUSTODY_DATA

    checkpoint_rows = ''.join([
        f'<tr><td>{x["checkpoint"]}</td><td><span class="pill">{x["status"]}</span></td><td>{x["confidence"]}</td><td>{x["evidence"]}</td></tr>'
        for x in d["checkpoints"]
    ])

    chain = ''.join([
        f'<div class="node">{x}</div><div class="arrow">→</div>'
        for x in d["trust_path"]
    ])

    exception_rows = ''.join([
        f'<tr><td>{x["exception"]}</td><td><span class="pill">{x["severity"]}</span></td><td>{x["owner"]}</td></tr>'
        for x in d["exceptions"]
    ])

    body = f"""
    <div class="hero">
        <h1>RLT DSCSA / Chain-of-Custody Trust Layer™</h1>
        <div class="sub">
            RLT-specific chain-of-custody trust intelligence that connects batch trust, supplier evidence,
            internal custody, logistics handoff, quality review, and exception closure into one governed assurance path.
        </div>
        <div class="nav">
            <a href="/rlt-operations/supplier-trust-exchange">Supplier Trust Exchange</a>
            <a href="/rlt-operations/batch-trust-passport">Batch Passport</a>
            <a href="/rlt-operations/governance-mesh">Governance Mesh</a>
            <a href="/dscsa-trustchain">Existing DSCSA TrustChain</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Custody State</div><div class="value" style="font-size:23px;">{d["custody_state"]}</div></div>
        <div class="card"><div class="label">Custody Trust Score</div><div class="value">{d["trust_score"]}%</div></div>
        <div class="card"><div class="label">Checkpoints</div><div class="value">{d["custody_checkpoints"]}</div></div>
        <div class="card"><div class="label">Open Exceptions</div><div class="value">{d["open_exceptions"]}</div></div>
    </div>

    <div class="section">
        <h2>Custody Trust Decision</h2>
        <div class="decision">{d["decision"]}</div>
        <p>
            This module does not duplicate the existing DSCSA TrustChain. It extends RLT operations with a
            custody-specific trust layer that shows whether batch, supplier, logistics, and quality handoff evidence
            can support final assurance.
        </p>
    </div>

    <div class="section">
        <h2>Chain-of-Custody Trust Path</h2>
        <div class="chain">
            {chain}
        </div>
    </div>

    <div class="section">
        <h2>Custody Checkpoint Register</h2>
        <table>
            <tr><th>Checkpoint</th><th>Status</th><th>Confidence</th><th>Evidence</th></tr>
            {checkpoint_rows}
        </table>
    </div>

    <div class="section">
        <h2>Open Custody Exceptions</h2>
        <table>
            <tr><th>Exception</th><th>Severity</th><th>Owner</th></tr>
            {exception_rows}
        </table>
    </div>
    """

    return rlt_page("RLT DSCSA Chain-of-Custody Trust", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("RLT DSCSA Chain-of-Custody Trust patch applied successfully.")
