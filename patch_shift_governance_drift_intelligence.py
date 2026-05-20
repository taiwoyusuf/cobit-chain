from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_GOVERNANCE_DRIFT_INTELLIGENCE_ACTIVE"

if MARKER in text:
    print("Shift Governance Drift Intelligence already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_ESCALATION_LINEAGE_ENGINE_ACTIVE",
    "SHIFT_OPERATIONAL_MEMORY_ENGINE_ACTIVE",
    "SHIFT_EXECUTIVE_NARRATIVE_ENGINE_ACTIVE",
    "SHIFT_MISSION_CONTROL_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_GOVERNANCE_DRIFT_INTELLIGENCE_ACTIVE
# ShiftTrust™ Governance Drift Intelligence
# ============================================================

@app.route("/shift-governance-drift-intelligence")
def shift_governance_drift_intelligence():

    drift_signals = [
        {
            "signal": "Repeated unresolved carryover",
            "severity": "WATCH",
            "meaning": "Temporary workaround behavior becoming normalized.",
            "risk": "Operational drift pressure increasing."
        },
        {
            "signal": "Escalation inheritance without acknowledgement",
            "severity": "HIGH",
            "meaning": "Governance ownership becoming unstable.",
            "risk": "Invisible escalation gap forming."
        },
        {
            "signal": "Night-shift overload dependency",
            "severity": "WATCH",
            "meaning": "Resilience model depends too heavily on specific individuals.",
            "risk": "Long-term survivability degradation."
        },
        {
            "signal": "Recurring peer backup activation",
            "severity": "MEDIUM",
            "meaning": "Emergency operating pattern becoming operational norm.",
            "risk": "Governance erosion risk."
        }
    ]

    actions = [
        {
            "control": "Escalate recurring carryover patterns after 3 cycles",
            "effect": "Prevents normalization of unresolved governance debt"
        },
        {
            "control": "Require acknowledgement lineage before handoff closure",
            "effect": "Protects accountability continuity"
        },
        {
            "control": "Track repeated dependency on same peer backup path",
            "effect": "Detects survivability concentration risk"
        },
        {
            "control": "Review drift telemetry during leadership operations review",
            "effect": "Makes hidden governance erosion visible"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["signal"]}</td>
            <td><span class="pill">{x["severity"]}</span></td>
            <td>{x["meaning"]}</td>
            <td>{x["risk"]}</td>
        </tr>
        """
        for x in drift_signals
    ])

    action_rows = ''.join([
        f"""
        <tr>
            <td>{x["control"]}</td>
            <td>{x["effect"]}</td>
        </tr>
        """
        for x in actions
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Governance Drift Intelligence</h1>

        <div class="sub">
            Detects when temporary operational workarounds slowly become normalized behavior.
            ShiftTrust™ identifies hidden governance erosion before operational instability becomes visible.
        </div>

        <div class="nav">
            <a href="/shift-mission-control">Mission Control</a>
            <a href="/shift-executive-summary">Executive Summary</a>
            <a href="/shift-operational-memory">Operational Memory</a>
            <a href="/shift-escalation-lineage">Escalation Lineage</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Governance Drift Pressure</div><div class="value">18%</div></div>
        <div class="card"><div class="label">Normalization Risk</div><div class="value">WATCH</div></div>
        <div class="card"><div class="label">Escalation Drift</div><div class="value">HIGH</div></div>
        <div class="card"><div class="label">Operational Survivability</div><div class="value">STABLE</div></div>
    </div>

    <div class="section">
        <h2>Governance Drift Decision</h2>

        <div class="decision">
            EARLY GOVERNANCE DRIFT DETECTED — TEMPORARY WORKAROUNDS ARE SHOWING NORMALIZATION PATTERNS
        </div>

        <p>
            ShiftTrust™ Governance Drift Intelligence detects when operational teams begin unconsciously
            accepting unresolved governance debt as normal operating behavior.
        </p>
    </div>

    <div class="section">
        <h2>Drift Signal Intelligence</h2>

        <table>
            <tr>
                <th>Drift Signal</th>
                <th>Severity</th>
                <th>Operational Meaning</th>
                <th>Governance Risk</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Governance Stabilization Controls</h2>

        <table>
            <tr>
                <th>Control</th>
                <th>Expected Effect</th>
            </tr>

            {action_rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ DETECTS GOVERNANCE EROSION BEFORE IT BECOMES OPERATIONAL FAILURE
        </div>

        <p>
            Most organizations only notice governance breakdown after deviation, escalation failure,
            or operational instability occurs. ShiftTrust™ Governance Drift Intelligence identifies
            the weak signals early enough for leadership intervention.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Governance Drift Intelligence", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Governance Drift Intelligence patch applied.")
