from pathlib import Path

p = Path("app.py")
t = p.read_text(encoding="utf-8")

marker = "# PROTOCOL_TO_EVIDENCE_INTEGRITY_GRAPH_ACTIVE"

if marker in t:
   print("Already exists.")
   raise SystemExit

insert_before = '\nif __name__ == "__main__":'

code = r'''

# ============================================================
# PROTOCOL_TO_EVIDENCE_INTEGRITY_GRAPH_ACTIVE
# Protocol-to-Evidence Integrity GraphT
# ============================================================

@app.route('/protocol-to-evidence-integrity-graph')
def protocol_to_evidence_integrity_graph():

   body = """
   <div class="hero">
       <h1>Protocol-to-Evidence Integrity GraphT</h1>

       <div class="sub">
           Enterprise clinical-trial governance topology correlating protocol lineage,
           ALCOA+ evidence integrity,
           governance reconciliation,
           immutable verification,
           and submission-trust orchestration.
       </div>
   </div>

   <div class="grid">
       <div class="card"><div class="label">Submission Trust</div><div class="value">98.4%%</div></div>
       <div class="card"><div class="label">ALCOA+ Integrity</div><div class="value">VERIFIED</div></div>
       <div class="card"><div class="label">Governance Drift</div><div class="value">CONTROLLED</div></div>
       <div class="card"><div class="label">Immutable Verification</div><div class="value">PASS</div></div>
   </div>

   <div class="section">
       <h2>Protocol-to-Evidence Governance Graph</h2>

       <table>
           <tr><th>Governance Node</th><th>Operational State</th><th>Trust Confidence</th></tr>
           <tr><td>Clinical Protocol</td><td>Approved</td><td>98%%</td></tr>
           <tr><td>eConsent Evidence</td><td>Verified</td><td>99%%</td></tr>
           <tr><td>EDC Capture</td><td>Validated</td><td>98%%</td></tr>
           <tr><td>Safety Signal Monitoring</td><td>Active</td><td>97%%</td></tr>
           <tr><td>Deviation Management</td><td>Connected</td><td>95%%</td></tr>
           <tr><td>Purview Classification</td><td>Mapped</td><td>98%%</td></tr>
           <tr><td>Hash Verification</td><td>PASS</td><td>100%%</td></tr>
           <tr><td>Immutable Ledger</td><td>Anchored</td><td>100%%</td></tr>
           <tr><td>Governance Reconciliation</td><td>Resolved</td><td>97%%</td></tr>
           <tr><td>Submission Trust Verdict</td><td>APPROVED</td><td>98.4%%</td></tr>
       </table>
   </div>

   <div class="section">
       <h2>Protocol Drift Intelligence</h2>

       <div class="decision">
           SITE 11 DEVIATED FROM PROTOCOL AMENDMENT v4.1 - GOVERNANCE RECONCILIATION REQUIRED
       </div>
   </div>

   """

   return rlt_page("Protocol-to-Evidence Integrity Graph", body)

'''

t = t.replace(insert_before, code + insert_before)

p.write_text(t, encoding="utf-8")

print("Protocol-to-Evidence Integrity Graph added.")
