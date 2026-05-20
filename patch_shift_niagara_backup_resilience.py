from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_NIAGARA_BACKUP_RESILIENCE_ACTIVE"

if MARKER in text:
    print("Niagara Backup Resilience already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_NIAGARA_ACCESS_INTELLIGENCE_ACTIVE",
    "SHIFT_NIAGARA_AUDIT_INTELLIGENCE_ACTIVE",
    "SHIFT_NIAGARA_GOVERNANCE_HUB_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_NIAGARA_BACKUP_RESILIENCE_ACTIVE
# ShiftTrust™ Niagara Backup Resilience
# ============================================================

@app.route("/shift-niagara-backup-resilience")
def shift_niagara_backup_resilience():

    resilience_matrix = [
        {
            "domain": "Monthly Backup Review",
            "recoverability": "Verified",
            "resilience": "High",
            "confidence": "Stable"
        },
        {
            "domain": "Operational Restore Readiness",
            "recoverability": "Monitoring",
            "resilience": "Moderate",
            "confidence": "Tracked"
        },
        {
            "domain": "Backup Governance Lineage",
            "recoverability": "Connected",
            "resilience": "High",
            "confidence": "Strong"
        },
        {
            "domain": "Continuity Survivability",
            "recoverability": "Protected",
            "resilience": "High",
            "confidence": "Stable"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["domain"]}</td>
            <td>{x["recoverability"]}</td>
            <td>{x["resilience"]}</td>
            <td>{x["confidence"]}</td>
        </tr>
        """
        for x in resilience_matrix
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Niagara Backup Resilience</h1>

        <div class="sub">
            Operational backup survivability intelligence layer providing recovery defensibility analytics,
            continuity readiness scoring,
            restoration confidence telemetry, and operational resilience propagation.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-niagara-access-intelligence">Niagara Access Intelligence</a>
            <a href="/shift-niagara-audit-intelligence">Niagara Audit Intelligence</a>
            <a href="/shift-niagara-governance-hub">Niagara Governance Hub</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Backup Resilience</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Recoverability Confidence</div><div class="value">95%</div></div>
        <div class="card"><div class="label">Continuity Readiness</div><div class="value">LIVE</div></div>
        <div class="card"><div class="label">Operational Survivability</div><div class="value">STABLE</div></div>
    </div>

    <div class="section">
        <h2>Operational Recovery Decision</h2>

        <div class="decision">
            SHIFTTRUST™ CAN DETECT RECOVERY READINESS WEAKNESS BEFORE OPERATIONAL FAILURE OCCURS
        </div>

        <p>
            ShiftTrust™ Niagara Backup Resilience transforms backup governance into an operational
            survivability intelligence layer capable of recoverability scoring,
            restoration confidence analytics, continuity readiness reasoning,
            and resilience defensibility telemetry.
        </p>
    </div>

    <div class="section">
        <h2>Niagara Backup Resilience Matrix</h2>

        <table>
            <tr>
                <th>Recovery Governance Domain</th>
                <th>Recoverability State</th>
                <th>Resilience Level</th>
                <th>Confidence State</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ EVOLVES INTO A REAL OPERATIONAL RECOVERY INTELLIGENCE PLATFORM
        </div>

        <p>
            Traditional backup reviews remain passive operational activities.
            ShiftTrust™ Niagara Backup Resilience converts backup governance into continuously
            correlated survivability intelligence capable of recovery defensibility analytics,
            restoration confidence scoring, operational resilience propagation,
            and continuity readiness orchestration.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Niagara Backup Resilience", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Niagara Backup Resilience patch applied.")
