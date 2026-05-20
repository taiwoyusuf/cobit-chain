from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_EXECUTIVE_NARRATIVE_ENGINE_ACTIVE"

if MARKER in text:
    print("Shift Executive Narrative Engine already exists.")
    raise SystemExit(0)

required = [
    "SHIFT_EXECUTIVE_SUMMARY_ACTIVE",
    "SHIFT_MISSION_CONTROL_ACTIVE",
    "SHIFT_OPERATIONAL_GRAVITY_ENGINE_ACTIVE",
    "SHIFT_TREATMENT_WINDOW_COMPRESSION_ACTIVE",
    "SHIFT_GOVERNANCE_FATIGUE_HEATMAP_ACTIVE",
]

for item in required:
    if item not in text:
        raise RuntimeError(f"Required Shift marker missing: {item}")

insert_before = '\nif __name__ == "__main__":'
if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_EXECUTIVE_NARRATIVE_ENGINE_ACTIVE
# ShiftTrust™ Executive Narrative Engine
# ============================================================

@app.route("/shift-executive-narrative")
def shift_executive_narrative():
    narratives = [
        {
            "title": "Operational Stability Improving",
            "summary": "Operational gravity reduced after ownership reassignment for unresolved MES/eBR watch items.",
            "effect": "Treatment-window confidence stabilized and escalation pressure declined.",
            "status": "POSITIVE"
        },
        {
            "title": "Night Shift Pressure Increasing",
            "summary": "Governance fatigue indicators increased across overlap and carryover patterns.",
            "effect": "Peer backup readiness should be reviewed before next production-support window.",
            "status": "WATCH"
        },
        {
            "title": "Continuity Preserved During Coverage Gap",
            "summary": "Peer backup resilience prevented operational memory loss during temporary coverage reduction.",
            "effect": "Shift survivability remained intact without escalation drift.",
            "status": "STABLE"
        },
        {
            "title": "Treatment Timing Compression Detected",
            "summary": "Packaging-support instability slightly compressed downstream treatment timing confidence.",
            "effect": "Leadership intervention recommended before compression spreads further.",
            "status": "ATTENTION"
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["title"]}</td>
            <td>{x["summary"]}</td>
            <td>{x["effect"]}</td>
            <td><span class="pill">{x["status"]}</span></td>
        </tr>
        """
        for x in narratives
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Executive Narrative Engine</h1>
        <div class="sub">
            Converts governance telemetry into leadership-ready operational narratives.
            Instead of forcing leadership to interpret technical dashboards, ShiftTrust™
            explains what is happening operationally and why it matters.
        </div>

        <div class="nav">
            <a href="/shift-executive-summary">Executive Summary</a>
            <a href="/shift-mission-control">Mission Control</a>
            <a href="/shift-operational-gravity">Operational Gravity</a>
            <a href="/shift-treatment-window-compression">Window Compression</a>
            <a href="/shift-advanced">Advanced Launcher</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Narrative Confidence</div><div class="value">91%</div></div>
        <div class="card"><div class="label">Leadership Readiness</div><div class="value">HIGH</div></div>
        <div class="card"><div class="label">Operational Storyline</div><div class="value">STABLE</div></div>
        <div class="card"><div class="label">Escalation Pressure</div><div class="value">WATCH</div></div>
    </div>

    <div class="section">
        <h2>Executive Narrative Feed</h2>

        <table>
            <tr>
                <th>Narrative</th>
                <th>Operational Meaning</th>
                <th>Expected Impact</th>
                <th>Status</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ DOES NOT ONLY SHOW DATA — IT EXPLAINS THE OPERATIONAL STORY
        </div>

        <p>
            Leadership teams usually receive fragmented operational signals:
            tickets, escalation emails, shift notes, and isolated dashboards.
            ShiftTrust™ Executive Narrative Engine converts governance telemetry into
            plain-English operational intelligence that leadership can immediately understand.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Executive Narrative Engine", body)

'''

text = text.replace(insert_before, code + insert_before)
APP.write_text(text, encoding="utf-8")

print("Shift Executive Narrative Engine patch applied.")
