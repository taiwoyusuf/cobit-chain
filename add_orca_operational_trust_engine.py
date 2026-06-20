from pathlib import Path

APP = Path("app.py")
text = APP.read_text(encoding="utf-8")

MARKER = "COBITCHAIN_ORCA_OPERATIONAL_TRUST_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("ORCA Operational Trust Engine already exists.")
    raise SystemExit()

block = r'''

# ============================================================
# COBITCHAIN_ORCA_OPERATIONAL_TRUST_ENGINE_V1_ACTIVE
# ============================================================

@app.route("/orca")
@app.route("/orca/operational-trust")
@app.route("/orca/operational-trust-engine")
@app.route("/cobitchain/orca")
@app.route("/cobitchain/orca-operational-trust-engine")
def cobitchain_orca_operational_trust_engine():
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ORCA™ Operational Trust Engine</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
:root{
--bg:#020617;--panel:rgba(255,255,255,.08);--panel2:rgba(255,255,255,.12);
--line:rgba(255,255,255,.18);--text:#f8fbff;--muted:#aebbd2;
--azure:#0078d4;--snow:#86ed78;--cyan:#5ee7ff;--purple:#9d7cff;
--green:#39e59f;--yellow:#ffd166;--red:#ff5570;--orange:#ff9f43;
}
*{box-sizing:border-box}
body{
margin:0;font-family:Segoe UI,Arial,sans-serif;color:var(--text);
background:
radial-gradient(circle at 8% 4%,rgba(0,120,212,.50),transparent 30%),
radial-gradient(circle at 92% 10%,rgba(134,237,120,.22),transparent 28%),
radial-gradient(circle at 50% 100%,rgba(157,124,255,.32),transparent 36%),
linear-gradient(135deg,#020617,#071b3a 55%,#041013);
}
.page{max-width:1880px;margin:auto;padding:30px}
.hero{
border:1px solid var(--line);border-radius:36px;padding:34px;
background:linear-gradient(135deg,rgba(255,255,255,.15),rgba(255,255,255,.06));
box-shadow:0 35px 100px rgba(0,0,0,.50);backdrop-filter:blur(22px);
display:grid;grid-template-columns:1.35fr .65fr;gap:28px;align-items:center
}
.eyebrow{color:var(--snow);font-weight:950;letter-spacing:2px;text-transform:uppercase;font-size:13px}
h1{font-size:56px;line-height:1;margin:10px 0}
.subtitle{color:#dfeaff;font-size:18px;line-height:1.55;max-width:1100px}
.heroBox{border:1px solid rgba(94,231,255,.35);border-radius:28px;padding:22px;background:linear-gradient(135deg,rgba(0,120,212,.25),rgba(134,237,120,.10))}
.heroBox b{font-size:18px}.heroBox p{color:var(--muted);line-height:1.55}
.tabs{display:flex;gap:10px;flex-wrap:wrap;margin-top:20px}
.tab{padding:10px 13px;border-radius:999px;border:1px solid var(--line);background:rgba(255,255,255,.08);font-size:12px;font-weight:900}
.layout{display:grid;grid-template-columns:430px 1fr;gap:20px;margin-top:22px}
.panel{border:1px solid var(--line);border-radius:30px;padding:22px;background:var(--panel);box-shadow:0 20px 70px rgba(0,0,0,.28);backdrop-filter:blur(18px)}
.panel h2{margin:0 0 12px;font-size:22px}
label{display:block;color:#e6efff;font-size:13px;font-weight:900;margin:14px 0 7px}
select,input,textarea{
width:100%;border:1px solid rgba(255,255,255,.22);border-radius:15px;padding:12px 13px;
background:rgba(255,255,255,.10);color:white;outline:none;font-size:14px
}
option{color:#111} textarea{min-height:76px;resize:vertical}
.checkgrid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.check{border:1px solid rgba(255,255,255,.17);border-radius:16px;padding:11px;background:rgba(255,255,255,.07);font-size:12px;font-weight:850;color:#eef5ff}
.check input{width:auto;margin-right:6px}
button{
border:0;border-radius:17px;padding:15px 18px;margin-top:16px;width:100%;
font-weight:950;color:#04111f;background:linear-gradient(135deg,var(--snow),var(--cyan));
cursor:pointer;box-shadow:0 18px 45px rgba(94,231,255,.25)
}
.dashboard{display:grid;grid-template-columns:repeat(6,1fr);gap:14px}
.metric{border:1px solid var(--line);border-radius:24px;padding:18px;background:rgba(255,255,255,.08)}
.metric .label{color:var(--muted);font-size:11px;text-transform:uppercase;font-weight:950}
.metric .value{font-size:28px;font-weight:950;margin-top:6px}
.engine{margin-top:16px;display:grid;grid-template-columns:1.1fr .9fr;gap:16px}
.map{border:1px solid var(--line);border-radius:28px;background:rgba(255,255,255,.06);overflow:hidden}
.phases{display:grid;grid-template-columns:repeat(6,1fr)}
.phase{padding:15px;border-right:1px solid var(--line);background:linear-gradient(135deg,rgba(0,120,212,.40),rgba(157,124,255,.20))}
.phase:last-child{border-right:0}.phase b{display:block;font-size:13px}.phase span{display:block;color:var(--muted);font-size:11px;margin-top:5px}
.lanes{display:grid;grid-template-columns:155px repeat(6,1fr)}
.laneTitle{padding:15px;font-weight:950;background:rgba(134,237,120,.15);display:flex;align-items:center;border-top:1px solid var(--line);font-size:12px}
.cell{padding:10px;border-left:1px solid var(--line);border-top:1px solid var(--line);min-height:95px}
.step{height:100%;border-radius:16px;padding:11px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.15);font-size:11px;line-height:1.35}
.step b{display:block;color:white;margin-bottom:5px}
.good{border-color:rgba(57,229,159,.65);background:rgba(57,229,159,.10)}
.warn{border-color:rgba(255,209,102,.70);background:rgba(255,209,102,.10)}
.blue{border-color:rgba(94,231,255,.65);background:rgba(94,231,255,.10)}
.red{border-color:rgba(255,85,112,.65);background:rgba(255,85,112,.10)}
.sideStack{display:flex;flex-direction:column;gap:16px}
.result{border:1px solid rgba(57,229,159,.38);border-radius:28px;padding:22px;background:linear-gradient(135deg,rgba(57,229,159,.13),rgba(0,120,212,.14))}
.result h2{margin:0;font-size:25px}.result p{color:#dbe7ff;line-height:1.55}
.badge{display:inline-block;padding:7px 10px;border-radius:999px;font-size:11px;font-weight:950;margin:4px 4px 0 0}
.bgreen{background:var(--green);color:#001b10}.byellow{background:var(--yellow);color:#201400}.bred{background:var(--red);color:white}.bblue{background:var(--cyan);color:#00121a}.bpurple{background:var(--purple);color:white}
.approvals{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:16px}
.sign{border:1px solid var(--line);border-radius:20px;padding:14px;background:rgba(255,255,255,.07)}
.sign h3{margin:0 0 8px;font-size:14px}.sign p{font-size:12px;color:var(--muted);line-height:1.45}.sign button{margin-top:8px;padding:10px;border-radius:13px;font-size:12px}
.signed{border-color:rgba(57,229,159,.7);background:rgba(57,229,159,.12)}
table{width:100%;border-collapse:collapse;margin-top:16px;border-radius:18px;overflow:hidden}
th{background:rgba(0,120,212,.38);padding:11px;text-align:left;font-size:11px;text-transform:uppercase}
td{padding:11px;border-bottom:1px solid var(--line);font-size:12px;color:#edf4ff;vertical-align:top}
.hash{font-family:Consolas,monospace;font-size:12px;word-break:break-all;color:var(--snow);padding:13px;border:1px dashed rgba(134,237,120,.5);border-radius:16px;background:rgba(0,0,0,.22)}
.footer{color:var(--muted);font-size:12px;margin-top:20px;text-align:center;line-height:1.5}
@media(max-width:1300px){.hero,.layout,.engine,.dashboard,.approvals{grid-template-columns:1fr}.phases,.lanes{display:block}}
</style>
</head>
<body>
<div class="page">

<section class="hero">
<div>
<div class="eyebrow">COBIT-Chain™ / ORCA™ Flagship Module</div>
<h1>Operational Trust Engine™</h1>
<div class="subtitle">
A reusable evidence-driven assurance platform for cutover, go-live, migration, GMP system onboarding, ServiceNow readiness, CyberArk/PAM onboarding, MESA readiness, cloud transition and regulated operations.
</div>
<div class="tabs">
<span class="tab">Operational Trust™ centerpiece</span>
<span class="tab">Human approval workflow</span>
<span class="tab">CAB intelligence</span>
<span class="tab">Evidence vault</span>
<span class="tab">Comment intelligence</span>
<span class="tab">Exception countdown</span>
<span class="tab">SHA-256 final hash</span>
</div>
</div>
<div class="heroBox">
<b>ORCA™ informs. Humans approve.</b>
<p>It does not make regulated decisions. It classifies evidence, exposes assumptions, scores operational trust, and routes the final decision to accountable humans.</p>
</div>
</section>

<section class="layout">
<div class="panel">
<h2>1. Operational Trust Intake</h2>

<label>Organization / Program</label>
<input id="org" value="Enterprise Readiness Program">

<label>System / Service / Asset</label>
<input id="system" value="System Under Assessment">

<label>Assessment Scenario</label>
<select id="scenario">
<option>Regulated Pharma Lab & Manufacturing Cutover</option>
<option>GMP System Onboarding</option>
<option>Validated Lab System Go-Live</option>
<option>ServiceNow CMDB Onboarding</option>
<option>CyberArk / PAM Onboarding</option>
<option>Network Migration</option>
<option>Cloud Migration</option>
<option>MESA Readiness</option>
<option>AI Agent Deployment</option>
<option>General Enterprise Cutover</option>
</select>

<label>Operating / Quality Model</label>
<select id="model">
<option>Current SOP / CSV</option>
<option>Validated GxP Model</option>
<option>GSOP Transition</option>
<option>Hybrid SOP / GSOP</option>
<option>Non-GMP ITIL Change Model</option>
</select>

<label>Technical Standard / Exception</label>
<select id="tech">
<option>Windows Enterprise LTSC required</option>
<option>Windows Pro temporary exception</option>
<option>AD joined and correct OU required</option>
<option>CyberArk / PAM required</option>
<option>ServiceNow CI required</option>
<option>Cloud-hosted validated service</option>
<option>Non-networked system exception</option>
</select>

<label>Is CAB approval required?</label>
<select id="cab" onchange="toggleCab()">
<option value="yes">Yes - CAB approval is required</option>
<option value="no">No - CAB not required</option>
<option value="unknown">Unknown - needs change assessment</option>
</select>

<div id="cabInfo">
<label>CAB / Change Record Reference</label>
<input id="cabref" placeholder="CHG reference, CAB date, approval link, or meeting note">
</div>

<label>System Owner Confirmation Evidence</label>
<textarea id="ownerEv" placeholder="Email, Teams chat, meeting note, ServiceNow task, approval reference."></textarea>

<label>QA / CSV Confirmation Evidence</label>
<textarea id="qaEv" placeholder="QA impact assessment, CSV assessment, validation package, deviation status, approval evidence."></textarea>

<label>Project Coordinator / PM Evidence</label>
<textarea id="pmEv" placeholder="Cutover plan, milestone evidence, dependency tracker, management decision."></textarea>

<label>Cybersecurity / Risk Evidence</label>
<textarea id="cyberEv" placeholder="Cybersecurity confirmation, exception discussion, vulnerability review, PAM/CyberArk evidence."></textarea>

<label>Receiving Team / Opposing Comment</label>
<textarea id="otherComment" placeholder="Paste comment like 'lab systems are not ready'. ORCA classifies assumption, risk or evidence-based blocker."></textarea>

<label>Base Readiness Confidence</label>
<select id="confidence">
<option value="85">High - strong evidence, minor managed gaps</option>
<option value="72">Moderate - evidence exists, approvals pending</option>
<option value="55">Low - significant evidence missing</option>
<option value="35">Critical - blocker likely</option>
</select>

<label>Applicable Control Library</label>
<div class="checkgrid">
<div class="check"><input type="checkbox" checked> Validation / CSV</div>
<div class="check"><input type="checkbox" checked> QA Confirmation</div>
<div class="check"><input type="checkbox" checked> System Owner</div>
<div class="check"><input type="checkbox" checked> Project Coordinator</div>
<div class="check"><input type="checkbox" checked> CAB / Change</div>
<div class="check"><input type="checkbox" checked> CMDB / ServiceNow</div>
<div class="check"><input type="checkbox" checked> CyberArk / PAM</div>
<div class="check"><input type="checkbox" checked> Cybersecurity Risk</div>
<div class="check"><input type="checkbox" checked> Network Readiness</div>
<div class="check"><input type="checkbox" checked> Infrastructure</div>
<div class="check"><input type="checkbox" checked> SOP / GSOP</div>
<div class="check"><input type="checkbox" checked> LTSC / OS Standard</div>
<div class="check"><input type="checkbox" checked> Risk Acceptance</div>
<div class="check"><input type="checkbox" checked> Rollback</div>
<div class="check"><input type="checkbox" checked> Hypercare</div>
<div class="check"><input type="checkbox" checked> Evidence Freshness</div>
</div>

<button onclick="generate()">Generate Operational Trust™</button>
<button onclick="generateHash()">Generate Final Report Hash</button>
</div>

<div>
<div class="dashboard">
<div class="metric"><div class="label">Operational Trust™</div><div class="value" id="trust">85%</div></div>
<div class="metric"><div class="label">Decision Posture</div><div class="value" id="decision" style="color:var(--yellow)">Human Review</div></div>
<div class="metric"><div class="label">Evidence Confidence</div><div class="value" id="posture" style="color:var(--cyan)">Strong</div></div>
<div class="metric"><div class="label">CAB Status</div><div class="value" id="cabStatus" style="color:var(--snow)">Required</div></div>
<div class="metric"><div class="label">Assumption Load</div><div class="value" id="assumption" style="color:var(--orange)">Open</div></div>
<div class="metric"><div class="label">Human Control</div><div class="value" style="color:var(--snow)">Enforced</div></div>
</div>

<div class="engine">
<div class="map">
<div class="phases">
<div class="phase"><b>1. Intake</b><span>System and scope</span></div>
<div class="phase"><b>2. Standards</b><span>SOP, GSOP, CSV, LTSC</span></div>
<div class="phase"><b>3. Evidence</b><span>Proof and confirmation</span></div>
<div class="phase"><b>4. Challenge</b><span>Assumption vs blocker</span></div>
<div class="phase"><b>5. Human Approval</b><span>QA, owner, PM, cyber, CAB</span></div>
<div class="phase"><b>6. Trust Ledger</b><span>Hash and replay</span></div>
</div>

<div class="lanes">
<div class="laneTitle">Service Design</div>
<div class="cell"><div class="step blue"><b>Define intended use</b>What system or service is being trusted?</div></div>
<div class="cell"><div class="step good"><b>Choose standards</b>SOP, GSOP, CSV, LTSC, CMDB, PAM, CAB.</div></div>
<div class="cell"><div class="step warn"><b>Evidence plan</b>Required proof per control owner.</div></div>
<div class="cell"><div class="step warn"><b>Challenge mode</b>Unsupported objections stay assumptions.</div></div>
<div class="cell"><div class="step good"><b>Approval model</b>Human decision rights assigned.</div></div>
<div class="cell"><div class="step good"><b>Replay ready</b>Decision trace preserved.</div></div>

<div class="laneTitle">Service Transition</div>
<div class="cell"><div class="step blue"><b>Build/configure</b>Network, AD, OU, endpoints, apps, integrations.</div></div>
<div class="cell"><div class="step good"><b>Onboard</b>ServiceNow CI, CyberArk, MyAccess, support groups.</div></div>
<div class="cell"><div class="step warn"><b>Validate</b>QA / CSV impact and intended-use confirmation.</div></div>
<div class="cell"><div class="step warn"><b>Risk acceptance</b>Temporary gaps require owner and expiry.</div></div>
<div class="cell"><div class="step good"><b>CAB / Change</b>Approve if required.</div></div>
<div class="cell"><div class="step good"><b>Decision record</b>Evidence locked to final state.</div></div>

<div class="laneTitle">Service Operation</div>
<div class="cell"><div class="step blue"><b>Operate safely</b>Support, escalation, monitoring, hypercare.</div></div>
<div class="cell"><div class="step good"><b>Access control</b>Users, service accounts, privileged sessions.</div></div>
<div class="cell"><div class="step warn"><b>Evidence replay</b>Explain why operation was approved.</div></div>
<div class="cell"><div class="step warn"><b>Exception watch</b>Track accepted risk and expiration.</div></div>
<div class="cell"><div class="step good"><b>Go / No-Go</b>Accountable human decision.</div></div>
<div class="cell"><div class="step good"><b>Audit packet</b>Hash, timestamp, approvals, evidence.</div></div>

<div class="laneTitle">Continual Improvement</div>
<div class="cell"><div class="step blue"><b>Lessons learned</b>Capture defects and improvements.</div></div>
<div class="cell"><div class="step good"><b>Refresh standards</b>Update reusable templates.</div></div>
<div class="cell"><div class="step warn"><b>Evidence gaps</b>Convert gaps into actions.</div></div>
<div class="cell"><div class="step warn"><b>Residual risk</b>Review until closed.</div></div>
<div class="cell"><div class="step good"><b>Closure</b>Final accountability record.</div></div>
<div class="cell"><div class="step good"><b>Reusable pattern</b>Deploy to next organization.</div></div>
</div>
</div>

<div class="sideStack">
<div class="result">
<h2 id="resultTitle">Ready with Human Approval / Risk Acceptance</h2>
<p id="resultText">ORCA™ has classified the scenario as suitable for human review. Final approval remains with accountable owners, QA, cybersecurity, project leadership and CAB where applicable.</p>
<span class="badge bgreen">Operational Trust™</span>
<span class="badge byellow">Human approval required</span>
<span class="badge bblue">ServiceNow-ready</span>
<span class="badge bpurple">Azure-style governance</span>
</div>

<div class="result">
<h2>Comment Intelligence™</h2>
<p id="commentResponse">Paste a receiving-team comment, then generate assessment. ORCA will classify it as assumption, risk or evidence-based blocker.</p>
</div>

<div class="result">
<h2>Trust Gap Explorer™</h2>
<p id="gapText">Open gaps will appear here after assessment.</p>
</div>

<div class="result">
<h2>Final Trust Ledger Hash</h2>
<div class="hash" id="hashBox">Hash not generated yet.</div>
</div>
</div>
</div>

<div class="approvals">
<div class="sign" id="sigOwner"><h3>System Owner Confirmation</h3><p>Confirms ownership, intended use, operational impact and readiness position.</p><button onclick="sign('sigOwner','System Owner')">Click to Confirm</button></div>
<div class="sign" id="sigQA"><h3>QA / CSV Confirmation</h3><p>Confirms validation impact, GMP readiness, data integrity and SOP/CSV position.</p><button onclick="sign('sigQA','QA / CSV')">Click to Confirm</button></div>
<div class="sign" id="sigPM"><h3>Project Coordinator Confirmation</h3><p>Confirms cutover plan, dependency tracking, schedule and communication alignment.</p><button onclick="sign('sigPM','Project Coordinator')">Click to Confirm</button></div>
<div class="sign" id="sigCyber"><h3>Cybersecurity Confirmation</h3><p>Confirms cyber posture, PAM/CyberArk readiness, vulnerabilities and exception path.</p><button onclick="sign('sigCyber','Cybersecurity')">Click to Confirm</button></div>
<div class="sign" id="sigCAB"><h3>CAB / Change Approval</h3><p>Confirms change advisory review, change record, backout plan and schedule.</p><button onclick="sign('sigCAB','CAB / Change')">Click to Confirm</button></div>
<div class="sign" id="sigExec"><h3>Executive Go / No-Go</h3><p>Final accountable decision. ORCA informs; humans approve.</p><button onclick="sign('sigExec','Executive')">Click to Confirm</button></div>
</div>

<table>
<thead><tr><th>Advanced Capability</th><th>Cutover Pain Point Solved</th><th>ORCA™ Response</th></tr></thead>
<tbody>
<tr><td>Operational Trust™</td><td>Teams track tasks but not whether the system can be trusted.</td><td>Scores trust using evidence, controls, approvals, freshness and residual risk.</td></tr>
<tr><td>Challenge Mode™</td><td>People say “not ready” without evidence.</td><td>Classifies unsupported objections as assumptions requiring evidence.</td></tr>
<tr><td>Trust Gap Explorer™</td><td>Management does not know what is blocking readiness.</td><td>Shows missing trust percentage by owner and control.</td></tr>
<tr><td>CAB Intelligence™</td><td>Teams are unsure if CAB is required.</td><td>Triggers CAB evidence when change, production, validation or cyber impact exists.</td></tr>
<tr><td>Exception Countdown™</td><td>Temporary exceptions become permanent.</td><td>Requires owner, expiry, migration plan and risk acceptance.</td></tr>
<tr><td>Evidence Freshness™</td><td>Old approvals are reused without review.</td><td>Flags stale evidence for refresh before cutover reliance.</td></tr>
<tr><td>Trust Ledger™</td><td>Decision history disappears after meetings.</td><td>Generates SHA-256 fingerprint for the final decision state.</td></tr>
</tbody>
</table>

</div>
</section>

<div class="footer">
ORCA™ does not replace QA, CSV, CAB, cybersecurity, system owner accountability, ServiceNow, Azure, ITIL, GAMP, change control or management approval. It is an evidence-based governance assurance layer.
</div>

</div>

<script>
let signatures = {};

function toggleCab(){
 let cab=document.getElementById("cab").value;
 document.getElementById("cabInfo").style.display = cab==="yes" ? "block" : "none";
 document.getElementById("cabStatus").innerText = cab==="yes" ? "Required" : cab==="no" ? "Not Required" : "Assess";
}

function sign(id, role){
 let el=document.getElementById(id);
 let ts=new Date().toISOString();
 signatures[role]=ts;
 el.classList.add("signed");
 el.querySelector("p").innerText="Confirmed by "+role+" at "+ts+".";
}

function classifyComment(comment){
 let c=comment.toLowerCase();
 if(!comment.trim()) return "No receiving-team comment entered yet.";
 let blockerWords=["failed","cannot","not validated","critical vulnerability","no approval","no rollback","data integrity failure","patient safety","regulatory failure","failed validation","failed test"];
 let riskWords=["risk","concern","temporary","exception","pending","not ready","gap","unknown","waiting","not comfortable","not sure"];
 for(let w of blockerWords){ if(c.includes(w)) return "Classification: Evidence-based blocker may exist. Request objective evidence, owner, impact, severity and resolution path before Go / No-Go."; }
 for(let w of riskWords){ if(c.includes(w)) return "Classification: Risk / assumption requiring evidence. This should not automatically block cutover unless supporting evidence proves unsafe or non-compliant operation."; }
 return "Classification: Comment noted. No blocker language detected. Treat as observation unless evidence is provided.";
}

function generate(){
 let org=document.getElementById("org").value;
 let system=document.getElementById("system").value;
 let scenario=document.getElementById("scenario").value;
 let model=document.getElementById("model").value;
 let tech=document.getElementById("tech").value;
 let confidence=parseInt(document.getElementById("confidence").value);
 let cab=document.getElementById("cab").value;
 let owner=document.getElementById("ownerEv").value.trim();
 let qa=document.getElementById("qaEv").value.trim();
 let pm=document.getElementById("pmEv").value.trim();
 let cyber=document.getElementById("cyberEv").value.trim();
 let comment=document.getElementById("otherComment").value;

 let evidenceCount=[owner,qa,pm,cyber].filter(x=>x.length>5).length;
 let adjusted=confidence + (evidenceCount*3);
 if(cab==="unknown") adjusted-=6;
 if(cab==="yes" && !document.getElementById("cabref").value.trim()) adjusted-=5;
 if(tech.includes("temporary exception")) adjusted-=4;
 if(adjusted>99) adjusted=99;
 if(adjusted<0) adjusted=0;

 document.getElementById("trust").innerText=adjusted+"%";
 document.getElementById("commentResponse").innerText=classifyComment(comment);

 let title="Ready with Human Approval / Risk Acceptance";
 let decision="Human Review";
 let posture="Evidence Building";
 let assumption="Open";
 let gap="Open gaps: confirm QA/CSV evidence, cybersecurity evidence, CAB/change status, system owner confirmation and risk acceptance where applicable.";

 let text=org+" / "+system+" has been assessed for "+scenario+" under "+model+". Technical standard selected: "+tech+". ORCA™ indicates the scenario can proceed only after accountable human approval and closure of required evidence.";

 if(adjusted>=90){
   title="Ready for Executive Go Decision";
   decision="Ready";
   posture="Strong";
   assumption="Low";
   gap="Minimal trust gap. Final executive approval and report hash required.";
   text=system+" has strong evidence coverage. ORCA™ recommends final human Go / No-Go approval by accountable stakeholders.";
 } else if(adjusted>=70){
   title="Ready with Approved Risk Acceptance";
   decision="Risk Managed";
   posture="Moderate";
   assumption="Managed";
   gap="Trust gap mainly relates to open approvals, pending CAB/change reference, temporary exception, or evidence finalization.";
   text=system+" appears suitable to proceed if open risks are documented, owned, time-bound and approved by the relevant human authorities.";
 } else if(adjusted>=50){
   title="Investigation Required — Evidence Incomplete";
   decision="Investigate";
   posture="Weak";
   assumption="High";
   gap="Significant trust gap: assumptions must be converted into objective evidence before readiness can be claimed.";
   text=system+" does not yet have sufficient evidence for a reliable cutover decision. Assumptions must be converted into evidence or action items.";
 } else {
   title="Not Ready — Evidence-Based Blocker Likely";
   decision="Not Ready";
   posture="Critical";
   assumption="Critical";
   gap="Critical trust gap: likely unresolved blockers, missing approval, weak evidence, or unaccepted operational risk.";
   text=system+" has major readiness gaps. Cutover should not proceed until blockers are resolved or formally accepted by accountable leadership.";
 }

 document.getElementById("resultTitle").innerText=title;
 document.getElementById("resultText").innerText=text;
 document.getElementById("decision").innerText=decision;
 document.getElementById("posture").innerText=posture;
 document.getElementById("assumption").innerText=assumption;
 document.getElementById("gapText").innerText=gap;
 toggleCab();
}

async function generateHash(){
 generate();
 let payload={
  org:document.getElementById("org").value,
  system:document.getElementById("system").value,
  scenario:document.getElementById("scenario").value,
  model:document.getElementById("model").value,
  tech:document.getElementById("tech").value,
  cab:document.getElementById("cab").value,
  cabref:document.getElementById("cabref").value,
  ownerEvidence:document.getElementById("ownerEv").value,
  qaEvidence:document.getElementById("qaEv").value,
  pmEvidence:document.getElementById("pmEv").value,
  cyberEvidence:document.getElementById("cyberEv").value,
  otherComment:document.getElementById("otherComment").value,
  result:document.getElementById("resultTitle").innerText,
  trust:document.getElementById("trust").innerText,
  signatures:signatures,
  generatedAt:new Date().toISOString()
 };
 let data=new TextEncoder().encode(JSON.stringify(payload));
 let digest=await crypto.subtle.digest("SHA-256",data);
 let hash=Array.from(new Uint8Array(digest)).map(b=>b.toString(16).padStart(2,"0")).join("");
 document.getElementById("hashBox").innerText=hash;
}
toggleCab();
</script>
</body>
</html>
    """
    return html

# ============================================================
# END COBITCHAIN_ORCA_OPERATIONAL_TRUST_ENGINE_V1_ACTIVE
# ============================================================

'''

target = 'if __name__ == "__main__":'
idx = text.rfind(target)

if idx == -1:
    raise SystemExit("Could not locate startup block.")

text = text[:idx] + block + "\n\n" + text[idx:]
APP.write_text(text, encoding="utf-8")

print("ORCA Operational Trust Engine installed.")
