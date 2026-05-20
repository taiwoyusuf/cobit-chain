from pathlib import Path
import re

p = Path("app.py")
t = p.read_text(encoding="utf-8")

marker = "PROTOCOL_GRAPH_V2_ENTERPRISE_ACTIVE"

if marker in t:
   print("Already upgraded.")
   raise SystemExit

old = """        ^<div class=\"section\"^>
        <h2>Protocol Drift Intelligence</h2>

        <div class=\"decision\">
            SITE 11 DEVIATED FROM PROTOCOL AMENDMENT v4.1 - GOVERNANCE RECONCILIATION REQUIRED
        </div>
    </div>
"""

new = """
        <div class=\"section\">
            <h2>Protocol Drift Intelligence</h2>

            <div class=\"decision\">
                SITE 11 DEVIATED FROM PROTOCOL AMENDMENT v4.1 - GOVERNANCE RECONCILIATION REQUIRED
            </div>

            <table>
                <tr><th>Drift Signal</th><th>Risk State</th><th>Governance Impact</th></tr>
                <tr><td>Missing Consent Timestamp</td><td>HIGH</td><td>Inspection Defensibility Risk</td></tr>
                <tr><td>Delayed SAE Review</td><td>HIGH</td><td>Safety Escalation Required</td></tr>
                <tr><td>Missing Monitoring Evidence</td><td>MEDIUM</td><td>Operational Trust Reduction</td></tr>
                <tr><td>Retention Classification Mismatch</td><td>HIGH</td><td>Purview Governance Alert</td></tr>
            </table>

            <div class=\"decision\" style=\"margin-top:20px;\">
                DRIFT PROPAGATION RISK - CROSS-SYSTEM GOVERNANCE EXPOSURE DETECTED
            </div>
        </div>

        <!-- PROTOCOL_GRAPH_V2_ENTERPRISE_ACTIVE -->

        <div class=\"section\">

            <div class=\"grid\">
                <div class=\"card\"><div class=\"label\">Sensitivity Labels</div><div class=\"value\">VERIFIED</div></div>
                <div class=\"card\"><div class=\"label\">Retention Governance</div><div class=\"value\">ACTIVE</div></div>
                <div class=\"card\"><div class=\"label\">DLP Monitoring</div><div class=\"value\">ENABLED</div></div>
                <div class=\"card\"><div class=\"label\">Cross-Border Controls</div><div class=\"value\">CONTROLLED</div></div>
            </div>

            <p>
                Microsoft Purview governance federation continuously correlates
                classification intelligence,
                retention controls,
                DLP governance,
                evidence lineage,
                and protocol integrity orchestration across regulated clinical-trial ecosystems.
            </p>
        </div>

        <div class=\"section\">

            <table>
                <tr><th>Governance Domain</th><th>Readiness Score</th></tr>
                <tr><td>Protocol Integrity</td><td>96%%</td></tr>
                <tr><td>Evidence Completeness</td><td>91%%</td></tr>
                <tr><td>ALCOA+ Alignment</td><td>93%%</td></tr>
                <tr><td>TMF Defensibility</td><td>88%%</td></tr>
                <tr><td>Regulatory Trust Score</td><td>92%%</td></tr>
            </table>

            <div class=\"decision\" style=\"margin-top:20px;\">
                FINAL SUBMISSION STATUS - CONDITIONALLY DEFENSIBLE
            </div>
        </div>

        <div class=\"section\">

            <table>
                <tr><td>EDC</td><td>COMPLETE</td></tr>
                <tr><td>TMF</td><td>COMPLETE</td></tr>
                <tr><td>Safety Platform</td><td>PENDING REVIEW</td></tr>
                <tr><td>CAPA Governance</td><td>OPEN</td></tr>
                <tr><td>Purview Compliance</td><td>VERIFIED</td></tr>
            </table>

            <div class=\"decision\" style=\"margin-top:20px;\">
                RECONCILIATION VERDICT - SUBMISSION RELEASE BLOCKED
            </div>
        </div>

        <div class=\"section\">

            <table>
                <tr><td>Study ID</td><td>CT-IRLT-2026-041</td></tr>
                <tr><td>Protocol Version</td><td>v4.1</td></tr>
                <tr><td>Evidence Hash</td><td>SHA256 VERIFIED</td></tr>
                <tr><td>Ledger Registration</td><td>IMMUTABLE PASS</td></tr>
                <tr><td>Dependency Validation</td><td>CONFIRMED</td></tr>
                <tr><td>Governance Closure</td><td>CONTROLLED</td></tr>
            </table>

            <div class=\"decision\" style=\"margin-top:20px;\">
                PASSPORT STATUS - PORTABLE ASSURANCE READY
            </div>
        </div>
"""

if old not in t:
   print("Target block not found.")
   raise SystemExit

t = t.replace(old, new)

p.write_text(t, encoding="utf-8")

print("Protocol Graph v2 enterprise upgrade complete.")
