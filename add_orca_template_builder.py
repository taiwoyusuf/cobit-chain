from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_ORCA_TEMPLATE_BUILDER_V1_ACTIVE"

if MARKER in text:
    print("ORCA Template Builder already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# COBITCHAIN_ORCA_TEMPLATE_BUILDER_V1_ACTIVE
# ============================================================

@app.route("/orca/builder")
@app.route("/orca/template-builder")
@app.route("/cobitchain/orca-template-builder")
@app.route("/cobitchain/operational-readiness-assurance-builder")
def cobitchain_orca_template_builder():
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ORCA™ Template Builder</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
:root{
--bg:#050914;--panel:rgba(255,255,255,.08);--glass:rgba(255,255,255,.10);
--line:rgba(255,255,255,.18);--text:#f3f7ff;--muted:#aebbd4;
--azure:#0078d4;--servicenow:#86ed78;--cyan:#56d7ff;--purple:#9b7cff;
--green:#36d399;--yellow:#ffd166;--red:#ff5c75;--orange:#ff9f43;
}
*{box-sizing:border-box}
body{
margin:0;font-family:Segoe UI,Arial,sans-serif;color:var(--text);
background:
radial-gradient(circle at 10% 5%,rgba(0,120,212,.38),transparent 28%),
radial-gradient(circle at 92% 8%,rgba(134,237,120,.25),transparent 28%),
radial-gradient(circle at 70% 90%,rgba(155,124,255,.28),transparent 32%),
linear-gradient(135deg,#040711,#071329 55%,#04131c);
}
.page{max-width:1680px;margin:auto;padding:28px}
.hero{
border:1px solid var(--line);border-radius:34px;padding:34px;
background:linear-gradient(135deg,rgba(255,255,255,.14),rgba(255,255,255,.06));
box-shadow:0 35px 95px rgba(0,0,0,.45);backdrop-filter:blur(18px);
display:grid;grid-template-columns:1.2fr .8fr;gap:24px;align-items:center
}
.eyebrow{color:var(--servicenow);font-weight:900;letter-spacing:2px;text-transform:uppercase;font-size:13px}
h1{font-size:52px;line-height:1;margin:12px 0}
.subtitle{color:#dce9ff;font-size:18px;line-height:1.55;max-width:980px}
.heroCard{
border:1px solid rgba(86,215,255,.35);border-radius:26px;padding:22px;
background:linear-gradient(135deg,rgba(0,120,212,.22),rgba(134,237,120,.10));
}
.heroCard b{color:white}.heroCard p{color:var(--muted);line-height:1.55}
.grid{display:grid;grid-template-columns:380px 1fr;gap:20px;margin-top:22px}
.panel{
border:1px solid var(--line);border-radius:28px;padding:22px;background:var(--panel);
box-shadow:0 20px 65px rgba(0,0,0,.25);backdrop-filter:blur(16px)
}
.panel h2{margin:0 0 14px;font-size:22px}
label{display:block;color:#dce9ff;font-size:13px;font-weight:800;margin:14px 0 7px}
select,input,textarea{
width:100%;border:1px solid rgba(255,255,255,.22);border-radius:14px;padding:12px 13px;
background:rgba(255,255,255,.09);color:white;outline:none;font-size:14px
}
option{color:#111}
textarea{min-height:90px;resize:vertical}
.controls{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:12px}
.control{
border:1px solid rgba(255,255,255,.18);border-radius:18px;padding:13px;
background:rgba(255,255,255,.07);cursor:pointer;transition:.2s
}
.control:hover{transform:translateY(-2px);border-color:var(--cyan)}
.control input{width:auto;margin-right:7px}
.control span{font-size:13px;color:#eaf2ff;font-weight:800}
button{
border:0;border-radius:16px;padding:14px 18px;margin-top:16px;width:100%;
font-weight:900;color:#04111f;background:linear-gradient(135deg,var(--servicenow),var(--cyan));
cursor:pointer;box-shadow:0 16px 40px rgba(86,215,255,.24)
}
.dashboard{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.metric{
border:1px solid var(--line);border-radius:22px;padding:18px;background:rgba(255,255,255,.08)
}
.metric .label{color:var(--muted);font-size:12px;text-transform:uppercase;font-weight:900}
.metric .value{font-size:30px;font-weight:950;margin-top:6px}
.flow{margin-top:18px;border:1px solid var(--line);border-radius:26px;overflow:hidden;background:rgba(255,255,255,.06)}
.phases{display:grid;grid-template-columns:repeat(5,1fr)}
.phase{padding:17px;border-right:1px solid var(--line);background:linear-gradient(135deg,rgba(0,120,212,.38),rgba(155,124,255,.20))}
.phase:last-child{border-right:0}
.phase b{display:block}.phase span{display:block;color:var(--muted);font-size:12px;margin-top:5px}
.lanes{display:grid;grid-template-columns:170px repeat(5,1fr);border-top:1px solid var(--line)}
.laneTitle{padding:18px;font-weight:950;background:rgba(134,237,120,.16);display:flex;align-items:center}
.cell{padding:12px;border-left:1px solid var(--line);border-bottom:1px solid var(--line);min-height:105px}
.step{height:100%;border-radius:18px;padding:13px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.15);font-size:12px;line-height:1.4}
.step b{display:block;color:white;margin-bottom:5px}
.good{border-color:rgba(54,211,153,.65);background:rgba(54,211,153,.10)}
.warn{border-color:rgba(255,209,102,.65);background:rgba(255,209,102,.10)}
.red{border-color:rgba(255,92,117,.65);background:rgba(255,92,117,.10)}
.blue{border-color:rgba(86,215,255,.65);background:rgba(86,215,255,.10)}
.result{
margin-top:18px;border-radius:28px;padding:24px;
background:linear-gradient(135deg,rgba(54,211,153,.16),rgba(0,120,212,.14));
border:1px solid rgba(54,211,153,.35)
}
.result h2{margin:0;font-size:28px}
.badge{display:inline-block;padding:7px 10px;border-radius:999px;font-size:12px;font-weight:950;margin:4px 4px 0 0}
.bgreen{background:var(--green);color:#001b10}.byellow{background:var(--yellow);color:#201400}.bred{background:var(--red);color:white}.bblue{background:var(--cyan);color:#00121a}
table{width:100%;border-collapse:collapse;margin-top:16px;overflow:hidden;border-radius:18px}
th{background:rgba(0,120,212,.35);padding:12px;text-align:left;font-size:12px;text-transform:uppercase}
td{padding:12px;border-bottom:1px solid var(--line);font-size:13px;color:#eaf2ff;vertical-align:top}
.footer{color:var(--muted);font-size:12px;margin-top:20px;text-align:center}
@media(max-width:1200px){.hero,.grid,.dashboard{grid-template-columns:1fr}.controls{grid-template-columns:1fr}.phases,.lanes{display:block}}
</style>
</head>
<body>
<div class="page">

<section class="hero">
<div>
<div class="eyebrow">COBIT-Chain™ Product Module</div>
<h1>ORCA™ Template Builder</h1>
<div class="subtitle">
Operational Readiness & Cutover Assurance for any organization. Select the scenario, choose governance controls, enter evidence, classify assumptions and blockers, then generate an executive readiness decision.
</div>
</div>
<div class="heroCard">
<b>Designed for Azure, ServiceNow, GMP, manufacturing, lab, cloud, cybersecurity and enterprise cutover governance.</b>
<p>ORCA™ converts readiness activity into an auditable Go / No-Go decision using controls, evidence, risk acceptance and operational trust logic.</p>
</div>
</section>

<section class="grid">
<div class="panel">
<h2>1. Build Assurance Template</h2>

<label>Organization / Program Name</label>
<input id="org" value="Enterprise Cutover Program">

<label>Cutover / Readiness Scenario</label>
<select id="scenario">
<option>Regulated Pharma Lab & Manufacturing Cutover</option>
<option>General IT Cutover</option>
<option>Cloud Migration</option>
<option>ServiceNow CMDB Onboarding</option>
<option>CyberArk / PAM Onboarding</option>
<option>MESA Readiness</option>
<option>AI Agent Deployment</option>
<option>Network Migration</option>
<option>Data Center Migration</option>
<option>GMP System Go-Live</option>
</select>

<label>Operating Model</label>
<select id="model">
<option>Current SOP / CSV</option>
<option>GSOP Transition</option>
<option>Hybrid SOP / GSOP</option>
<option>Non-GMP ITIL Change Model</option>
<option>Validated GxP Model</option>
</select>

<label>Known Context / Evidence</label>
<textarea id="evidence">AD and OU available. ServiceNow CI onboarding in progress. CyberArk onboarding can begin. Network transition in progress. Temporary exception may be required.</textarea>

<label>Readiness Confidence</label>
<select id="confidence">
<option value="78">Moderate confidence - evidence still being collected</option>
<option value="92">High confidence - evidence mostly complete</option>
<option value="55">Low confidence - significant gaps remain</option>
<option value="35">Critical - blockers likely</option>
</select>

<label>Governance Controls</label>
<div class="controls">
<div class="control"><input type="checkbox" checked><span>Validation / CSV</span></div>
<div class="control"><input type="checkbox" checked><span>SOP / GSOP</span></div>
<div class="control"><input type="checkbox" checked><span>CMDB / ServiceNow</span></div>
<div class="control"><input type="checkbox" checked><span>Access / Identity</span></div>
<div class="control"><input type="checkbox" checked><span>CyberArk / PAM</span></div>
<div class="control"><input type="checkbox" checked><span>Cybersecurity</span></div>
<div class="control"><input type="checkbox" checked><span>Network</span></div>
<div class="control"><input type="checkbox" checked><span>Infrastructure</span></div>
<div class="control"><input type="checkbox" checked><span>Change Control</span></div>
<div class="control"><input type="checkbox" checked><span>Risk Acceptance</span></div>
<div class="control"><input type="checkbox" checked><span>Rollback</span></div>
<div class="control"><input type="checkbox" checked><span>Hypercare</span></div>
</div>

<button onclick="generate()">Generate ORCA™ Result</button>
</div>

<div>
<div class="dashboard">
<div class="metric"><div class="label">Operational trust</div><div class="value" id="trust">78%</div></div>
<div class="metric"><div class="label">Decision</div><div class="value" id="decision" style="color:var(--yellow)">Risk Managed</div></div>
<div class="metric"><div class="label">Evidence posture</div><div class="value" id="posture" style="color:var(--cyan)">In Progress</div></div>
<div class="metric"><div class="label">Reusable template</div><div class="value" style="color:var(--servicenow)">Active</div></div>
</div>

<div class="flow">
<div class="phases">
<div class="phase"><b>1. Scenario</b><span>Choose cutover type</span></div>
<div class="phase"><b>2. Controls</b><span>Select governance controls</span></div>
<div class="phase"><b>3. Evidence</b><span>Capture facts and proof</span></div>
<div class="phase"><b>4. Assurance</b><span>Classify risk and blockers</span></div>
<div class="phase"><b>5. Decision</b><span>Generate Go / No-Go</span></div>
</div>

<div class="lanes">
<div class="laneTitle">Governance</div>
<div class="cell"><div class="step blue"><b>Define objective</b>What business event needs operational readiness assurance?</div></div>
<div class="cell"><div class="step good"><b>Map controls</b>Validation, CMDB, access, cyber, change, rollback, risk.</div></div>
<div class="cell"><div class="step warn"><b>Evidence test</b>Separate confirmed facts from assumptions.</div></div>
<div class="cell"><div class="step warn"><b>Risk decision</b>Decide if risk is acceptable, blocked or unresolved.</div></div>
<div class="cell"><div class="step good"><b>Executive output</b>Ready, ready with risk, not ready, or investigate.</div></div>

<div class="laneTitle">Technology</div>
<div class="cell"><div class="step blue"><b>System scope</b>Apps, infrastructure, endpoints, network, integrations.</div></div>
<div class="cell"><div class="step good"><b>Platform readiness</b>AD, OU, ServiceNow, CyberArk, Azure or local infrastructure.</div></div>
<div class="cell"><div class="step warn"><b>Dependency proof</b>Connectivity, ownership, CI, access, monitoring.</div></div>
<div class="cell"><div class="step warn"><b>Exception control</b>Temporary platforms or gaps require approval.</div></div>
<div class="cell"><div class="step good"><b>Operate safely</b>Support model, escalation, hypercare, monitoring.</div></div>

<div class="laneTitle">Evidence</div>
<div class="cell"><div class="step blue"><b>Collect</b>Tickets, approvals, validation, screenshots, reports.</div></div>
<div class="cell"><div class="step good"><b>Validate</b>Evidence must be current, owned and relevant.</div></div>
<div class="cell"><div class="step warn"><b>Classify</b>Assumption, validated fact, blocker, resolved blocker.</div></div>
<div class="cell"><div class="step warn"><b>Trace</b>Link evidence to readiness claims.</div></div>
<div class="cell"><div class="step good"><b>Audit ready</b>Decision can be explained and replayed.</div></div>
</div>
</div>

<div class="result">
<h2 id="resultTitle">Ready with Approved Risk Acceptance</h2>
<p id="resultText">The selected scenario is suitable to proceed if open risks are documented, owned and approved. No assumption should be treated as a blocker unless supported by objective evidence.</p>
<div>
<span class="badge bgreen">Evidence-based governance</span>
<span class="badge byellow">Risk acceptance required</span>
<span class="badge bblue">ServiceNow-ready</span>
<span class="badge bblue">Azure-style operating model</span>
</div>

<table>
<thead><tr><th>Classification</th><th>Meaning</th><th>ORCA™ Treatment</th></tr></thead>
<tbody>
<tr><td>Validated fact</td><td>Supported by evidence</td><td>Used to increase readiness confidence</td></tr>
<tr><td>Assumption</td><td>No evidence yet</td><td>Investigate; not a blocker</td></tr>
<tr><td>Evidence-based blocker</td><td>Evidence proves unsafe or non-compliant operation</td><td>Blocks cutover until resolved</td></tr>
<tr><td>Managed risk</td><td>Known gap with owner and approval path</td><td>Proceed only with risk acceptance</td></tr>
</tbody>
</table>
</div>
</div>
</section>

<div class="footer">
ORCA™ is a reusable COBIT-Chain™ assurance module. It does not replace ServiceNow, Azure, ITIL, QA, CSV, Cybersecurity, Change Control, or accountable management approval.
</div>
</div>

<script>
function generate(){
let org=document.getElementById("org").value;
let scenario=document.getElementById("scenario").value;
let model=document.getElementById("model").value;
let confidence=parseInt(document.getElementById("confidence").value);
document.getElementById("trust").innerText=confidence+"%";

let decision="Risk Managed";
let posture="In Progress";
let title="Ready with Approved Risk Acceptance";
let text=org+" has been assessed under the ORCA™ assurance model for "+scenario+". The operating model selected is "+model+". Based on the current confidence score, the program can proceed only where evidence is complete and residual risks are formally accepted.";

if(confidence>=90){
decision="Ready";
posture="Strong";
title="Ready for Cutover";
text=org+" shows strong evidence coverage for "+scenario+". The system or service can be recommended for cutover subject to final management approval.";
}
if(confidence<60){
decision="Investigate";
posture="Weak";
title="Investigation Required";
text=org+" does not yet have enough evidence for a reliable Go / No-Go decision. Assumptions must be validated before any blocker or readiness claim is accepted.";
}
if(confidence<40){
decision="Not Ready";
posture="Critical";
title="Not Ready — Evidence-Based Blocker Likely";
text=org+" has significant readiness gaps. Cutover should not proceed unless blockers are resolved or formally accepted by accountable leadership.";
}

document.getElementById("decision").innerText=decision;
document.getElementById("posture").innerText=posture;
document.getElementById("resultTitle").innerText=title;
document.getElementById("resultText").innerText=text;
}
</script>
</body>
</html>
    """
    return html

# ============================================================
# END COBITCHAIN_ORCA_TEMPLATE_BUILDER_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("ORCA Template Builder installed.")
