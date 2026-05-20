from pathlib import Path

p = Path("app.py")
t = p.read_text(encoding="utf-8")

marker = "# PROTOCOL_GRAPH_TOPOLOGY_V3_ACTIVE"

if marker in t:
   print("Already inserted.")
   raise SystemExit

insert_before = """
        <div class=\"section\">
            <h2>Governance Assurance PassportT</h2>
"""

new_block = """

        <!-- PROTOCOL_GRAPH_TOPOLOGY_V3_ACTIVE -->

        <div class=\"section\">
            <h2>Governance Flow TopologyT</h2>

            <div style=\"padding:30px;border-radius:18px;background:linear-gradient^(135deg,#07111f,#0d2f46^);border:1px solid #1ee6a5;margin-top:20px;\">

                <div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:18px;text-align:center;font-weight:700;\">

                    <div><div style=\"font-size:12px;color:#7fdcff;\">Protocol</div><div style=\"padding:16px;border-radius:12px;background:#09243a;\">v4.1 Approved</div></div>
                    <div style=\"font-size:30px;color:#1ee6a5;\"></div>
                    <div><div style=\"font-size:12px;color:#7fdcff;\">eConsent</div><div style=\"padding:16px;border-radius:12px;background:#09243a;\">Verified</div></div>
                    <div style=\"font-size:30px;color:#1ee6a5;\"></div>
                    <div><div style=\"font-size:12px;color:#7fdcff;\">EDC</div><div style=\"padding:16px;border-radius:12px;background:#09243a;\">Validated</div></div>
                    <div style=\"font-size:30px;color:#ffd166;\"></div>
                    <div><div style=\"font-size:12px;color:#7fdcff;\">Safety Review</div><div style=\"padding:16px;border-radius:12px;background:#3a2409;color:#ffd166;\">Pending</div></div>
                    <div style=\"font-size:30px;color:#ff5d73;\"></div>
                    <div><div style=\"font-size:12px;color:#7fdcff;\">Governance Verdict</div><div style=\"padding:16px;border-radius:12px;background:#3a0911;color:#ff7f90;\">Conditionally Defensible</div></div>

                </div>
            </div>
        </div>

        <div class=\"section\">
            <h2>Dependency Validation IntelligenceT</h2>

            <table>
                <tr><th>Evidence Domain</th><th>Required Dependency</th><th>Validation State</th><th>Governance Impact</th></tr>
                <tr><td>eConsent</td><td>Protocol v4.1</td><td>VERIFIED</td><td>Operational Trust Maintained</td></tr>
                <tr><td>Site Monitoring</td><td>CAPA-019 Closure</td><td>PENDING</td><td>Inspection Defensibility Reduced</td></tr>
                <tr><td>Safety Review</td><td>SAE Closure Evidence</td><td>BLOCKED</td><td>Submission Release Risk</td></tr>
            </table>
        </div>

        <div class=\"section\">
            <h2>Governance Reasoning EngineT</h2>

            <div class=\"decision\" style=\"background:linear-gradient^(135deg,#3a0911,#1b0c12^);border:1px solid #ff5d73;\">
                SUBMISSION RELEASE CURRENTLY BLOCKED
            </div>

            <div style=\"margin-top:20px;padding:24px;border-radius:16px;background:#081521;border:1px solid #16344c;\">
                <ul style=\"line-height:2;\">
                    <li>SAE review evidence remains unresolved across downstream safety governance layers.</li>
                    <li>Protocol amendment reconciliation mismatch detected between Site 11 and EDC lineage.</li>
                    <li>Monitoring evidence dependency chain incomplete for CAPA-linked review.</li>
                    <li>Retention classification mismatch detected within Purview governance federation.</li>
                </ul>

                <div class=\"decision\" style=\"margin-top:25px;background:linear-gradient^(135deg,#0d3529,#09231a^);border:1px solid #1ee6a5;\">
                    GOVERNANCE RECOMMENDATION - RECONCILIATION REQUIRED BEFORE REGULATORY SUBMISSION
                </div>
            </div>
        </div>

        <div class=\"section\">
            <h2>Inspection Readiness ProjectionT</h2>

            <div class=\"grid\">
                <div class=\"card\"><div class=\"label\">FDA Inspection Confidence</div><div class=\"value\">91%%</div></div>
                <div class=\"card\"><div class=\"label\">EMA Readiness</div><div class=\"value\">89%%</div></div>
                <div class=\"card\"><div class=\"label\">Protocol Defensibility</div><div class=\"value\">92%%</div></div>
                <div class=\"card\"><div class=\"label\">Operational Trust Stability</div><div class=\"value\">94%%</div></div>
            </div>
        </div>

"""

if insert_before not in t:
   print("Insert target not found.")
   raise SystemExit

t = t.replace(insert_before, new_block + insert_before)

p.write_text(t, encoding="utf-8")

print("Protocol topology v3 inserted successfully.")
