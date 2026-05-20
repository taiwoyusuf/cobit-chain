from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_RECOVERY_CONFIDENCE_ENGINE_ACTIVE"

if MARKER in text:
    print("Shift Recovery Confidence Engine already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_SURVIVABILITY_INDEX_ACTIVE",
    "SHIFT_OPERATIONAL_MEMORY_ENGINE_ACTIVE",
    "SHIFT_ESCALATION_LINEAGE_ENGINE_ACTIVE",
    "SHIFT_HUMAN_DEPENDENCY_CONCENTRATION_ENGINE_ACTIVE",
    "SHIFT_GOVERNANCE_DRIFT_INTELLIGENCE_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_RECOVERY_CONFIDENCE_ENGINE_ACTIVE
# ShiftTrust™ Recovery Confidence Engine
# ============================================================

@app.route("/shift-recovery-confidence")
def shift_recovery_confidence():

    recovery_domains = [
        {
            "domain": "Operational Memory Recovery",
            "confidence": "93%",
            "risk": "LOW",
            "meaning": "Operational inheritance survives disruption."
        },
        {
            "domain": "Escalation Recovery Continuity",
            "confidence": "88%",
            "risk": "WATCH",
            "meaning": "Escalation lineage mostly stable."
        },
        {
            "domain": "Human Dependency Recovery",
            "confidence": "74%",
            "risk": "HIGH",
            "meaning": "Recovery still depends on specific individuals."
        },
        {
            "domain": "Peer Backup Recovery",
            "confidence": "95%",
            "risk": "LOW",
            "meaning": "Coverage survivability remains strong."
        },
        {
            "domain": "Governance Drift Recovery",
            "confidence": "81%",
            "risk": "WATCH",
            "meaning": "Normalization pressure still visible."
        }
    ]

    stabilization_actions = [
        {
            "action": "Reduce single-person recovery ownership",
            "effect": "Improves recovery survivability"
        },
        {
            "action": "Strengthen escalation inheritance acknowledgement",
            "effect": "Stabilizes continuity restoration"
        },
        {
            "action": "Protect operational memory transfer",
            "effect": "Prevents recovery knowledge loss"
        },
        {
            "action": "Preserve peer redundancy during disruption",
            "effect": "Maintains recovery resilience"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["confidence"]}</td>
            <td><span class="pill">{x["risk"]}</span></td>
            <td>{x["meaning"]}</td>
        </tr>
        """
        for x in recovery_domains
    ])

    action_rows = ''.join([
        f"""
        <tr>
            <td>{x["action"]}</td>
            <td>{x["effect"]}</td>
        </tr>
        """
        for x in stabilization_actions
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Recovery Confidence Engine</h1>

        <div class="sub">
            Predicts whether operational continuity can realistically recover after disruption,
            escalation overload, personnel absence, governance drift, or continuity degradation.
        </div>

        <div class="nav">
            <a href="/shift-survivability-index">Survivability Index</a>
            <a href="/shift-mission-control">Mission Control</a>
            <a href="/shift-operational-memory">Operational Memory</a>
            <a href="/shift-human-dependency">Human Dependency</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Recovery Confidence</div><div class="value">87%</div></div>
        <div class="card"><div class="label">Continuity Restoration</div><div class="value">STABLE</div></div>
        <div class="card"><div class="label">Recovery Dependency Risk</div><div class="value">WATCH</div></div>
        <div class="card"><div class="label">Recovery Survivability</div><div class="value">HIGH</div></div>
    </div>

    <div class="section">
        <h2>Executive Recovery Decision</h2>

        <div class="decision">
            RECOVERY CONFIDENCE REMAINS STABLE — HUMAN DEPENDENCY CONCENTRATION SHOULD BE REDUCED
        </div>

        <p>
            ShiftTrust™ Recovery Confidence Engine predicts whether the operation can realistically
            restore continuity after operational disruption without losing governance control.
        </p>
    </div>

    <div class="section">
        <h2>Recovery Confidence Domains</h2>

        <table>
            <tr>
                <th>Recovery Domain</th>
                <th>Confidence</th>
                <th>Risk</th>
                <th>Operational Meaning</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Recovery Stabilization Actions</h2>

        <table>
            <tr>
                <th>Leadership Action</th>
                <th>Expected Effect</th>
            </tr>

            {action_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ DOES NOT ONLY MEASURE FAILURE RISK — IT MEASURES RECOVERY REALISM
        </div>

        <p>
            Most operational platforms detect disruption after it occurs.
            ShiftTrust™ Recovery Confidence Engine evaluates whether continuity can realistically
            recover while preserving escalation lineage, operational memory, peer resilience,
            and governance integrity.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Recovery Confidence Engine", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Shift Recovery Confidence Engine patch applied.")
