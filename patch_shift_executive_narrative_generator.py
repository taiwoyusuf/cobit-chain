from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "# SHIFT_EXECUTIVE_NARRATIVE_GENERATOR_ACTIVE"

if MARKER in text:
    print("Executive Narrative Generator already exists.")
    raise SystemExit(0)

insert_before = '\nif __name__ == "__main__":'

if insert_before not in text:
    raise RuntimeError("Insertion point not found.")

code = r'''

# ============================================================
# SHIFT_EXECUTIVE_NARRATIVE_GENERATOR_ACTIVE
# ShiftTrust™ Executive Narrative Generator
# ============================================================

@app.route("/shift-executive-narrative-generator")
def shift_executive_narrative_generator():

    narratives = [
        {
            "title": "Executive Continuity Narrative",
            "summary": "Operational survivability remains stable, though hidden dependency concentration requires leadership attention."
        },
        {
            "title": "Governance Stability Narrative",
            "summary": "Governance drift remains controlled but requires monitoring."
        },
        {
            "title": "Recovery Confidence Narrative",
            "summary": "Recovery realism remains strong because escalation lineage and peer redundancy are preserved."
        }
    ]

    rows = ''.join([
        f"""
        <tr>
            <td>{x["title"]}</td>
            <td>{x["summary"]}</td>
        </tr>
        """
        for x in narratives
    ])

    body = f"""
    <div class="hero">
        <h1>ShiftTrust™ Executive Narrative Generator</h1>

        <div class="sub">
            Generates leadership-ready governance narratives,
            survivability summaries, continuity intelligence,
            and executive operational talking points.
        </div>

        <div class="nav">
            <a href="/shift-executive-command-center">Executive Command Center</a>
            <a href="/shift-operational-collapse-forecast">Collapse Forecast</a>
            <a href="/shift-executive-intervention-simulator">Executive Intervention</a>
            <a href="/shift-survivability-index">Survivability Index</a>
        </div>
    </div>

    <div class="grid">
        <div class="card"><div class="label">Narrative Readiness</div><div class="value">ACTIVE</div></div>
        <div class="card"><div class="label">Leadership Briefing</div><div class="value">92%</div></div>
        <div class="card"><div class="label">Governance Messaging</div><div class="value">STABLE</div></div>
        <div class="card"><div class="label">Audit Narrative</div><div class="value">READY</div></div>
    </div>

    <div class="section">
        <h2>Generated Executive Narratives</h2>

        <table>
            <tr>
                <th>Narrative Type</th>
                <th>Executive Summary</th>
            </tr>

            {rows}
        </table>
    </div>

    <div class="section">
        <h2>Executive Meaning</h2>

        <div class="decision">
            SHIFTTRUST™ CONVERTS GOVERNANCE SIGNALS INTO EXECUTIVE LANGUAGE
        </div>

        <p>
            ShiftTrust™ Executive Narrative Generator transforms survivability analytics,
            governance drift intelligence, recovery confidence, and operational continuity
            signals into leadership-ready communication.
        </p>
    </div>
    """

    return rlt_page("ShiftTrust Executive Narrative Generator", body)

'''

text = text.replace(insert_before, code + insert_before)

APP.write_text(text, encoding="utf-8")

print("Executive Narrative Generator patch applied.")
