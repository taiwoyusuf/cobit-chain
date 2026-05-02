# SERVICENOW_LIVE_NAV_UPDATE_ACTIVE
# KNOWLEDGE_REVIEW_NAV_AND_HEALTH_ACTIVE
# KNOWLEDGE_GOVERNANCE_NAV_UPDATE_ACTIVE
# OPERATIONAL_LINEAGE_NAV_UPDATE_ACTIVE
# DEIDENTIFIED_DEMO_LANGUAGE_ACTIVE
# VISUAL_HIERARCHY_RLT_DSCSA_ACTIVE
# RLT_DSCSA_POSITIONING_ACTIVE
from flask import Flask, request, render_template_string, redirect, Response
import os, io, hashlib, datetime
import pandas as pd
from azure.storage.blob import BlobServiceClient

app = Flask(__name__)

AZURE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
CONTAINER_NAME = "cobitchain-evidence"

blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
container_client = blob_service_client.get_container_client(CONTAINER_NAME)

BASELINE_FILE = "baseline_hashes.csv"
LOG_FILE = "logs.csv"

REQUIRED_STAGES = ["Weighbridge", "Dispatch", "Invoice"]
ORDER_MAP = {"Weighbridge": 1, "Dispatch": 2, "Invoice": 3}

def clean(x):
    if x is None:
        return ""
    x = str(x).strip()
    return "" if x.lower() == "nan" else x

def sha256_text(x):
    return hashlib.sha256(x.encode()).hexdigest()

def compute_hash(b):
    return hashlib.sha256(b).hexdigest()

def load_csv(name):
    try:
        data = container_client.get_blob_client(name).download_blob().readall()
        return pd.read_csv(io.BytesIO(data), keep_default_na=False).fillna("")
    except Exception:
        return pd.DataFrame()

def save_csv(df, name):
    df = df.fillna("")
    container_client.get_blob_client(name).upload_blob(
        df.to_csv(index=False),
        overwrite=True
    )

def ensure_cols(df, cols):
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df.fillna("")

def prepare_logs():
    logs = load_csv(LOG_FILE)
    return ensure_cols(logs, [
        "filename", "batch_id", "timestamp", "current_hash", "expected_hash", "status",
        "process_stage", "evidence_category", "uploaded_by", "signed_by", "approval_status",
        "previous_hash", "record_hash", "excel_rows", "excel_columns", "missing_cells",
        "duplicate_rows", "analysis_summary", "data_quality"
    ])

def analyze_excel(bytes_data, filename):
    result = {
        "excel_rows": "",
        "excel_columns": "",
        "missing_cells": "",
        "duplicate_rows": "",
        "analysis_summary": "",
        "data_quality": "N/A"
    }

    if not filename.lower().endswith((".xlsx", ".xls")):
        result["analysis_summary"] = "Non-Excel file. Data quality analytics not applied."
        return result

    try:
        df = pd.read_excel(io.BytesIO(bytes_data), engine="openpyxl")
        rows, cols = df.shape
        missing = int(df.isna().sum().sum())
        dup = int(df.duplicated().sum())

        quality = "GOOD"
        if missing > 0 or dup > 0:
            quality = "REVIEW"

        result.update({
            "excel_rows": rows,
            "excel_columns": cols,
            "missing_cells": missing,
            "duplicate_rows": dup,
            "analysis_summary": f"{rows} rows | {cols} columns | {missing} missing cells | {dup} duplicate rows",
            "data_quality": quality
        })

    except Exception as e:
        result["analysis_summary"] = f"Excel analysis error: {e}"
        result["data_quality"] = "ERROR"

    return result

def get_status(expected, current):
    if not expected:
        return "YELLOW"
    return "GREEN" if expected == current else "RED"

def analyze_batch(batch_name, grp):
    grp = grp.fillna("")

    stages = grp["process_stage"].tolist()
    missing = [s for s in REQUIRED_STAGES if s not in stages]

    seq_issue = False
    last = 0
    for s in stages:
        if s in ORDER_MAP:
            if ORDER_MAP[s] < last:
                seq_issue = True
            last = max(last, ORDER_MAP[s])

    red = len(grp[grp["status"] == "RED"])
    yellow = len(grp[grp["status"] == "YELLOW"])
    green = len(grp[grp["status"] == "GREEN"])
    total = len(grp)
    integrity = round((green / total) * 100, 2) if total else 0

    missing_approval = len(grp[(grp["signed_by"] != "") & (grp["approval_status"] == "")])
    sod = len(grp[(grp["uploaded_by"] != "") & (grp["signed_by"] != "") & (grp["uploaded_by"].str.lower() == grp["signed_by"].str.lower())])
    data_review = len(grp[grp["data_quality"].isin(["REVIEW", "ERROR"])])

    root_causes = []

    if red > 0:
        root_causes.append("Integrity breach: one or more files changed after baseline creation.")
    if yellow > 0:
        root_causes.append("Baseline gap: one or more files are new and need future verification.")
    if missing:
        root_causes.append("Process completeness gap: missing required stage(s): " + ", ".join(missing))
    if seq_issue:
        root_causes.append("Process sequencing violation: evidence appears outside the expected Weighbridge → Dispatch → Invoice flow.")
    if missing_approval > 0:
        root_causes.append("Governance control gap: signed evidence exists without approval status.")
    if sod > 0:
        root_causes.append("Segregation of duties gap: uploader and signer are the same person.")
    if data_review > 0:
        root_causes.append("Data quality issue: Excel file contains missing cells, duplicate rows, or analysis errors.")

    if red > 0 or seq_issue or sod > 0:
        risk = "HIGH"
        verdict = "NOT AUDIT-READY"
        verdict_icon = "❌"
    elif missing or missing_approval > 0 or yellow > 0 or data_review > 0:
        risk = "MEDIUM"
        verdict = "CONDITIONALLY READY"
        verdict_icon = "⚠"
    else:
        risk = "LOW"
        verdict = "AUDIT-READY"
        verdict_icon = "✅"

    if verdict == "NOT AUDIT-READY":
        narrative = "This batch should not be relied upon for audit without remediation because critical integrity, sequencing, or governance issues were detected."
    elif verdict == "CONDITIONALLY READY":
        narrative = "This batch can support preliminary review, but governance follow-up is required before it should be treated as fully audit-ready."
    else:
        narrative = "This batch is audit-ready based on current evidence integrity, process completeness, and governance checks."

    impact = []
    if red > 0:
        impact.append("Audit reliance risk: evidence may not represent the original approved file.")
    if seq_issue:
        impact.append("Operational traceability risk: process flow may not reflect actual execution order.")
    if missing:
        impact.append("Completeness risk: audit trail does not cover the full process lifecycle.")
    if missing_approval > 0:
        impact.append("Control effectiveness risk: approval evidence is incomplete.")
    if data_review > 0:
        impact.append("Data quality risk: operational or financial records may need manual review.")

    if not impact:
        impact.append("No major control impact detected.")

    cobit = []
    if red > 0:
        cobit.append("MEA02 — Monitor internal control system")
    if yellow > 0:
        cobit.append("DSS06 — Manage business process controls")
    if missing:
        cobit.append("APO12 — Managed risk")
    if seq_issue:
        cobit.append("DSS01 — Managed operations")
    if missing_approval > 0:
        cobit.append("DSS06 — Approval and control enforcement")
    if sod > 0:
        cobit.append("EDM03 — Risk optimization")
    if data_review > 0:
        cobit.append("MEA01 — Performance and conformance monitoring")
    if not cobit:
        cobit.append("EDM03 — Risk optimization")

    stage_cards = []
    for required in REQUIRED_STAGES:
        rows = grp[grp["process_stage"] == required]
        if rows.empty:
            stage_cards.append({"stage": required, "status": "MISSING", "count": 0})
        else:
            statuses = rows["status"].tolist()
            if "RED" in statuses:
                s = "RED"
            elif "YELLOW" in statuses:
                s = "YELLOW"
            else:
                s = "GREEN"
            stage_cards.append({"stage": required, "status": s, "count": len(rows)})

    return {
        "name": batch_name,
        "risk": risk,
        "verdict": verdict,
        "verdict_icon": verdict_icon,
        "integrity": integrity,
        "total": total,
        "green": green,
        "yellow": yellow,
        "red": red,
        "missing": missing,
        "seq_issue": seq_issue,
        "missing_approval": missing_approval,
        "sod": sod,
        "data_review": data_review,
        "root_causes": root_causes if root_causes else ["No root cause exceptions detected."],
        "impact": impact,
        "narrative": narrative,
        "cobit": list(dict.fromkeys(cobit)),
        "stage_cards": stage_cards,
        "records": grp.tail(12).to_dict("records")
    }

@app.route("/download-report/<batch_id>")
def download_report(batch_id):
    logs = prepare_logs()

    if logs.empty:
        return Response("No records available.", mimetype="text/plain")

    grp = logs[logs["batch_id"] == batch_id]

    if grp.empty:
        return Response("Batch not found.", mimetype="text/plain")

    analysis = analyze_batch(batch_id, grp)

    lines = []
    lines.append("COBIT-Chain Audit Readiness Report")
    lines.append("=" * 45)
    lines.append(f"Generated UTC: {datetime.datetime.utcnow().isoformat()}")
    lines.append(f"Batch ID: {analysis['name']}")
    lines.append(f"Verdict: {analysis['verdict_icon']} {analysis['verdict']}")
    lines.append(f"Risk Level: {analysis['risk']}")
    lines.append(f"Integrity Score: {analysis['integrity']}%")
    lines.append(f"Total Records: {analysis['total']}")
    lines.append(f"Green: {analysis['green']}")
    lines.append(f"Yellow: {analysis['yellow']}")
    lines.append(f"Red: {analysis['red']}")
    lines.append("")
    lines.append("Audit Narrative")
    lines.append("-" * 45)
    lines.append(analysis["narrative"])
    lines.append("")
    lines.append("Root Cause Analysis")
    lines.append("-" * 45)
    for item in analysis["root_causes"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("Potential Audit / Business Impact")
    lines.append("-" * 45)
    for item in analysis["impact"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("COBIT 2019 Control Overlay")
    lines.append("-" * 45)
    for item in analysis["cobit"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("Evidence Records")
    lines.append("-" * 45)

    for _, r in grp.iterrows():
        lines.append(
            f"Stage: {clean(r.get('process_stage'))} | "
            f"File: {clean(r.get('filename'))} | "
            f"Status: {clean(r.get('status'))} | "
            f"Uploader: {clean(r.get('uploaded_by'))} | "
            f"Signer: {clean(r.get('signed_by'))} | "
            f"Approval: {clean(r.get('approval_status'))}"
        )
        lines.append(f"Expected Hash: {clean(r.get('expected_hash'))}")
        lines.append(f"Current Hash: {clean(r.get('current_hash'))}")
        lines.append(f"Previous Hash: {clean(r.get('previous_hash'))}")
        lines.append(f"Record Hash: {clean(r.get('record_hash'))}")
        lines.append("")

    report_text = "\n".join(lines)

    return Response(
        report_text,
        mimetype="text/plain",
        headers={
            "Content-Disposition": f"attachment; filename=COBIT-Chain-Audit-Report-{batch_id}.txt"
        }
    )

@app.route("/", methods=["GET", "POST"])
def index():
    baseline = load_csv(BASELINE_FILE)
    logs = prepare_logs()

    baseline = ensure_cols(baseline, ["filename", "baseline_hash"])

    if request.method == "POST":
        file = request.files.get("file")

        if not file or file.filename == "":
            return render_page(logs, "Please select a file before upload.")

        filename = clean(file.filename)
        batch = clean(request.form.get("batch_id"))
        stage = clean(request.form.get("process_stage"))
        category = clean(request.form.get("evidence_category"))
        user = clean(request.form.get("uploaded_by"))
        signed = clean(request.form.get("signed_by"))
        approval = clean(request.form.get("approval_status"))

        if not batch:
            return render_page(logs, "Batch ID is required.")
        if not stage:
            return render_page(logs, "Process Stage is required.")
        if not category:
            return render_page(logs, "Evidence Category is required.")
        if not user:
            return render_page(logs, "Uploaded By is required.")
        if signed and not approval:
            return render_page(logs, "Approval Status is required when Signed By is filled.")
        if user and signed and user.lower() == signed.lower():
            return render_page(logs, "Segregation of Duties violation: uploader and signer cannot be the same person.")

        file_bytes = file.read()
        h = compute_hash(file_bytes)
        ts = datetime.datetime.utcnow().isoformat()
        excel = analyze_excel(file_bytes, filename)

        existing = baseline[baseline["filename"] == filename]

        if existing.empty:
            expected = ""
            status = "YELLOW"
            baseline = pd.concat([baseline, pd.DataFrame([{
                "filename": filename,
                "baseline_hash": h
            }])], ignore_index=True)
            save_csv(baseline, BASELINE_FILE)
        else:
            expected = clean(existing.iloc[0]["baseline_hash"])
            status = get_status(expected, h)

        prev = "GENESIS" if logs.empty else clean(logs.iloc[-1]["record_hash"])
        record_hash = sha256_text(filename + batch + h + prev + ts)

        new = pd.DataFrame([{
            "filename": filename,
            "batch_id": batch,
            "timestamp": ts,
            "current_hash": h,
            "expected_hash": expected,
            "status": status,
            "process_stage": stage,
            "evidence_category": category,
            "uploaded_by": user,
            "signed_by": signed,
            "approval_status": approval,
            "previous_hash": prev,
            "record_hash": record_hash,
            **excel
        }])

        logs = pd.concat([logs, new], ignore_index=True)
        save_csv(logs, LOG_FILE)

        return redirect("/")

    return render_page(logs, "")

def render_page(logs, error):
    logs = logs.fillna("")

    total_records = len(logs)
    total_batches = logs["batch_id"].nunique() if not logs.empty else 0
    green_total = len(logs[logs["status"] == "GREEN"]) if not logs.empty else 0
    red_total = len(logs[logs["status"] == "RED"]) if not logs.empty else 0

    batches = []
    global_exceptions = []

    if not logs.empty:
        for batch_id, grp in logs.groupby("batch_id", dropna=False):
            batch_name = clean(batch_id) if clean(batch_id) else "NO-BATCH-ID"
            analysis = analyze_batch(batch_name, grp)
            batches.append(analysis)

            if analysis["verdict"] != "AUDIT-READY":
                global_exceptions.append(f"{batch_name}: {analysis['verdict']}")

    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain™</title>
<style>
:root {
    --bg:#f4f7fb; --navy:#071527; --blue:#2563eb; --cyan:#06b6d4;
    --green:#16a34a; --yellow:#f59e0b; --red:#dc2626; --muted:#64748b;
    --card:#ffffff; --border:#e5e7eb;
}
* { box-sizing:border-box; }
body {
    margin:0; font-family:Inter,Segoe UI,Arial,sans-serif;
    background:linear-gradient(135deg,#eef4ff,#f8fafc,#eefdf8);
    color:#0f172a;
}
.hero {
    background:radial-gradient(circle at top left,#1d4ed8 0%,#0f2745 42%,#071527 100%);
    color:white; padding:38px 42px 46px;
    border-bottom-left-radius:34px; border-bottom-right-radius:34px;
    box-shadow:0 18px 45px rgba(15,39,69,.25);
}
.hero-top { display:flex; align-items:center; justify-content:space-between; gap:20px; flex-wrap:wrap; }
.brand { display:flex; align-items:center; gap:14px; }
.logo {
    width:54px; height:54px; border-radius:18px;
    background:linear-gradient(135deg,#38bdf8,#22c55e);
    display:flex; align-items:center; justify-content:center;
    font-weight:900; font-size:22px;
}
.brand h1 { margin:0; font-size:34px; letter-spacing:-.8px; }
.brand p { margin:4px 0 0; color:#cbd5e1; }
.badge {
    padding:10px 15px; border-radius:999px;
    background:rgba(255,255,255,.12); border:1px solid rgba(255,255,255,.22);
    color:#e0f2fe; font-weight:800;
}
.container { max-width:1450px; margin:-28px auto 50px; padding:0 26px; }
.grid { display:grid; grid-template-columns:repeat(4,1fr); gap:18px; margin-bottom:20px; }
.metric {
    background:rgba(255,255,255,.96); border:1px solid rgba(226,232,240,.9);
    border-radius:22px; padding:22px; box-shadow:0 12px 32px rgba(15,23,42,.08);
}
.metric-label { color:var(--muted); font-weight:800; font-size:13px; text-transform:uppercase; letter-spacing:.08em; }
.metric-value { margin-top:8px; font-size:34px; font-weight:900; }
.metric-sub { color:#64748b; font-size:13px; }
.main-layout { display:grid; grid-template-columns:360px 1fr; gap:22px; align-items:start; }
.panel, .batch-body {
    background:white; border:1px solid var(--border); border-radius:24px;
    padding:22px; box-shadow:0 14px 35px rgba(15,23,42,.08);
}
.panel { margin-bottom:20px; }
input, select, button {
    width:100%; border-radius:14px; border:1px solid #dbe3ef;
    padding:12px 13px; margin:7px 0; font-size:14px; background:white;
}
button {
    border:none; background:linear-gradient(135deg,#2563eb,#06b6d4);
    color:white; font-weight:900; cursor:pointer;
}
.error {
    background:#fee2e2; color:#991b1b; border-left:6px solid var(--red);
    padding:14px; border-radius:16px; margin-bottom:18px; font-weight:900;
}
.exceptions { background:linear-gradient(135deg,#fff1f2,#fff); border-left:7px solid var(--red); }
.batch { margin-bottom:22px; }
.batch-header {
    padding:20px 22px; border-radius:24px 24px 0 0; color:white;
    display:flex; justify-content:space-between; gap:15px; align-items:center; flex-wrap:wrap;
}
.risk-HIGH .batch-header { background:linear-gradient(135deg,#991b1b,#dc2626); }
.risk-MEDIUM .batch-header { background:linear-gradient(135deg,#92400e,#f59e0b); }
.risk-LOW .batch-header { background:linear-gradient(135deg,#166534,#16a34a); }
.batch-title { font-size:22px; font-weight:900; }
.risk-pill, .verdict-pill {
    padding:9px 14px; background:rgba(255,255,255,.18);
    border:1px solid rgba(255,255,255,.35); border-radius:999px; font-weight:900;
}
.batch-body { border-radius:0 0 24px 24px; border-top:none; }
.mini-grid { display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin-bottom:18px; }
.mini { background:#f8fafc; border:1px solid #e2e8f0; border-radius:16px; padding:13px; }
.mini b { display:block; font-size:22px; margin-top:3px; }
.chain { display:flex; align-items:center; gap:12px; flex-wrap:wrap; margin:14px 0 18px; }
.stage-card {
    min-width:150px; padding:14px; border-radius:18px; color:white; font-weight:900;
    box-shadow:0 10px 25px rgba(15,23,42,.12);
}
.stage-GREEN { background:linear-gradient(135deg,#16a34a,#22c55e); }
.stage-YELLOW { background:linear-gradient(135deg,#d97706,#fbbf24); color:#111827; }
.stage-RED { background:linear-gradient(135deg,#b91c1c,#ef4444); }
.stage-MISSING { background:linear-gradient(135deg,#475569,#94a3b8); }
.arrow { color:#94a3b8; font-weight:900; font-size:22px; }
.narrative {
    background:#f8fafc; border:1px solid #e2e8f0;
    border-radius:18px; padding:16px; margin-bottom:16px; line-height:1.45;
}
.root { border-left:6px solid #dc2626; background:#fff1f2; }
.impact { border-left:6px solid #2563eb; background:#eff6ff; }
.cobit { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:16px; }
.cobit span {
    background:#eff6ff; color:#1d4ed8; border:1px solid #bfdbfe;
    padding:8px 11px; border-radius:999px; font-size:12px; font-weight:800;
}
.report-link {
    display:inline-block; text-decoration:none; background:#0f172a; color:white;
    padding:11px 14px; border-radius:14px; font-weight:900; margin-bottom:16px;
}
table { width:100%; border-collapse:collapse; border-radius:16px; overflow:hidden; font-size:12px; }
th { background:#0f172a; color:white; text-align:left; padding:11px; }
td { border-bottom:1px solid #e5e7eb; padding:10px; vertical-align:top; }
tr.row-GREEN { background:#f0fdf4; }
tr.row-YELLOW { background:#fffbeb; }
tr.row-RED { background:#fef2f2; }
.status { font-weight:900; border-radius:999px; padding:5px 9px; display:inline-block; }
.status-GREEN { background:#dcfce7; color:#166534; }
.status-YELLOW { background:#fef3c7; color:#92400e; }
.status-RED { background:#fee2e2; color:#991b1b; }

.enterprise-nav-safe-addition {
    background:white; border:1px solid #e5e7eb; border-radius:24px;
    padding:14px; box-shadow:0 14px 35px rgba(15,23,42,.08);
    display:flex; gap:10px; flex-wrap:wrap; margin-bottom:22px;
}
.enterprise-nav-safe-addition a {
    text-decoration:none; color:#0f172a; background:#f8fafc; border:1px solid #e2e8f0;
    padding:10px 13px; border-radius:999px; font-weight:900; font-size:13px;
}
.enterprise-nav-safe-addition a.active {
    background:#0f172a; color:white; border-color:#0f172a;
}


.flagship-pill{
    display:inline-block;
    background:linear-gradient(135deg,#facc15,#f97316);
    color:#111827;
    padding:8px 13px;
    border-radius:999px;
    font-weight:1000;
    letter-spacing:.06em;
    margin-right:8px;
    box-shadow:0 10px 24px rgba(249,115,22,.28);
}
.flagship-banner{
    margin-top:18px;
    background:rgba(250,204,21,.16);
    border:1px solid rgba(250,204,21,.45);
    border-left:8px solid #facc15;
    color:#fff7ed;
    padding:15px 17px;
    border-radius:18px;
    line-height:1.55;
}
.supporting-pill{
    display:inline-block;
    background:rgba(255,255,255,.14);
    color:#dbeafe;
    padding:7px 11px;
    border-radius:999px;
    font-weight:800;
    letter-spacing:.04em;
    margin-right:8px;
    border:1px solid rgba(255,255,255,.25);
}
.supporting-banner{
    margin-top:18px;
    background:rgba(255,255,255,.10);
    border:1px solid rgba(255,255,255,.18);
    border-left:6px solid #94a3b8;
    color:#e2e8f0;
    padding:14px 16px;
    border-radius:18px;
    line-height:1.55;
}

@media(max-width:1000px){ .grid,.mini-grid,.main-layout{ grid-template-columns:1fr; } }
</style>
</head>

<body>
<section class="hero">
    <div class="hero-top">
        <div class="brand">
            <div class="logo">CC</div>
            <div>
                <h1>COBIT-Chain™</h1>
                <p>Evidence Integrity • Governance Enforcement • Audit Readiness</p>
            </div>
        </div>
        <div class="badge">Governance Assurance Engine</div>
    </div>
</section>

<main class="container">

    <nav class="enterprise-nav-safe-addition">
        <a href="/executive-overview">Executive Overview</a>
        <a href="/sop-governance">SOP Governance</a>
        <a class="active" href="/">Manufacturing</a>
        <a href="/shift-assurance">Shift Assurance</a>
        <a href="/access-governance">Access Governance</a>
        <a href="/audit-capa">Audit/CAPA</a>
        <a href="/clinical-trial-integrity">Clinical Trial Integrity</a>
    </nav>

    <section class="grid">
        <div class="metric"><div class="metric-label">Total Batches</div><div class="metric-value">{{ total_batches }}</div><div class="metric-sub">Process chains tracked</div></div>
        <div class="metric"><div class="metric-label">Total Records</div><div class="metric-value">{{ total_records }}</div><div class="metric-sub">Evidence events logged</div></div>
        <div class="metric"><div class="metric-label">Verified Green</div><div class="metric-value" style="color:#16a34a">{{ green_total }}</div><div class="metric-sub">Hash matched records</div></div>
        <div class="metric"><div class="metric-label">Critical Red</div><div class="metric-value" style="color:#dc2626">{{ red_total }}</div><div class="metric-sub">Tamper detections</div></div>
    </section>

    {% if error %}<div class="error">{{ error }}</div>{% endif %}

    <section class="main-layout">
        <aside>
            <div class="panel">
                <h2>Upload Evidence</h2>
                <form method="POST" enctype="multipart/form-data">
                    <input type="file" name="file" required>
                    <input name="batch_id" placeholder="Batch ID e.g. WOLE-DEMO-001" required>

                    <select name="process_stage" required>
                        <option value="">Select Process Stage</option>
                        <option value="Weighbridge">Weighbridge</option>
                        <option value="Dispatch">Dispatch</option>
                        <option value="Invoice">Invoice</option>
                    </select>

                    <select name="evidence_category" required>
                        <option value="">Select Evidence Category</option>
                        <option value="Operational">Operational Evidence</option>
                        <option value="Financial">Financial Evidence</option>
                        <option value="QA">QA Evidence</option>
                        <option value="Compliance">Compliance Evidence</option>
                    </select>

                    <input name="uploaded_by" placeholder="Uploaded By" required>
                    <input name="signed_by" placeholder="Signed By">

                    <select name="approval_status">
                        <option value="">Approval Status</option>
                        <option value="Approved">Approved</option>
                        <option value="Pending">Pending</option>
                        <option value="Rejected">Rejected</option>
                    </select>

                    <button type="submit">Upload and Verify</button>
                </form>
            </div>

            {% if global_exceptions %}
            <div class="panel exceptions">
                <h2>⚠ Exception Center</h2>
                <ul>{% for e in global_exceptions %}<li>{{ e }}</li>{% endfor %}</ul>
            </div>
            {% endif %}
        </aside>

        <section>
            {% for b in batches %}
            <article class="batch risk-{{ b.risk }}">
                <div class="batch-header">
                    <div>
                        <div class="batch-title">{{ b.name }}</div>
                        <div>{{ b.verdict_icon }} {{ b.verdict }} • Integrity {{ b.integrity }}% • {{ b.total }} records</div>
                    </div>
                    <div>
                        <span class="risk-pill">Risk: {{ b.risk }}</span>
                    </div>
                </div>

                <div class="batch-body">
                    <a class="report-link" href="/download-report/{{ b.name }}">Download Audit Report</a>

                    <div class="mini-grid">
                        <div class="mini">Total <b>{{ b.total }}</b></div>
                        <div class="mini">Green <b style="color:#16a34a">{{ b.green }}</b></div>
                        <div class="mini">Yellow <b style="color:#d97706">{{ b.yellow }}</b></div>
                        <div class="mini">Red <b style="color:#dc2626">{{ b.red }}</b></div>
                        <div class="mini">Integrity <b>{{ b.integrity }}%</b></div>
                    </div>

                    <h3>Process Chain</h3>
                    <div class="chain">
                        {% for s in b.stage_cards %}
                            <div class="stage-card stage-{{ s.status }}">
                                {{ s.stage }}<br><small>{{ s.status }} • {{ s.count }} record(s)</small>
                            </div>
                            {% if not loop.last %}<div class="arrow">→</div>{% endif %}
                        {% endfor %}
                    </div>

                    <div class="narrative"><b>Audit Narrative:</b> {{ b.narrative }}</div>

                    <div class="narrative root">
                        <b>Root Cause Analysis</b>
                        <ul>{% for r in b.root_causes %}<li>{{ r }}</li>{% endfor %}</ul>
                    </div>

                    <div class="narrative impact">
                        <b>Potential Audit / Business Impact</b>
                        <ul>{% for i in b.impact %}<li>{{ i }}</li>{% endfor %}</ul>
                    </div>

                    <h3>COBIT 2019 Control Overlay</h3>
                    <div class="cobit">{% for c in b.cobit %}<span>{{ c }}</span>{% endfor %}</div>

                    <h3>Evidence Log</h3>
                    <table>
                        <tr>
                            <th>Stage</th><th>File</th><th>Status</th><th>Category</th><th>Uploader</th>
                            <th>Signer</th><th>Approval</th><th>Rows</th><th>Missing</th><th>Dup</th><th>Analysis</th>
                        </tr>
                        {% for r in b.records %}
                        <tr class="row-{{ r.status }}">
                            <td>{{ r.process_stage }}</td>
                            <td>{{ r.filename }}</td>
                            <td><span class="status status-{{ r.status }}">{{ r.status }}</span></td>
                            <td>{{ r.evidence_category }}</td>
                            <td>{{ r.uploaded_by }}</td>
                            <td>{{ r.signed_by }}</td>
                            <td>{{ r.approval_status }}</td>
                            <td>{{ r.excel_rows }}</td>
                            <td>{{ r.missing_cells }}</td>
                            <td>{{ r.duplicate_rows }}</td>
                            <td>{{ r.analysis_summary }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>
            </article>
            {% endfor %}
        </section>
    </section>
</main>
</body>
</html>
    """

    return render_template_string(
        html,
        error=error,
        batches=batches,
        global_exceptions=global_exceptions,
        total_records=total_records,
        total_batches=total_batches,
        green_total=green_total,
        red_total=red_total
    )


# ============================================================
# ENTERPRISE GOVERNANCE PAGES - SAFE ADDITION
# ============================================================
# These pages are added beside the existing Manufacturing/Manufacturing Core
# dashboard. The existing "/" route remains unchanged.

ENTERPRISE_PAGES = [
    {
        "number": "Page 1",
        "title": "Executive Overview",
        "route": "/executive-overview",
        "status": "LIVE SHELL",
        "purpose": "Leadership-level summary of governance risk, audit readiness, evidence integrity, open exceptions, and module status.",
        "focus": [
            "Enterprise governance scorecard",
            "Audit-readiness overview",
            "Open exception summary",
            "Evidence integrity performance",
            "Module-by-module assurance status"
        ]
    },
    {
        "number": "Page 2",
        "title": "SOP Governance",
        "route": "/sop-governance",
        "status": "LIVE SHELL",
        "purpose": "SOP-to-reality alignment, SOP gaps, process drift, review triggers, and governance recommendations.",
        "focus": [
            "SOP gap tracking",
            "Procedure-to-practice comparison",
            "Review trigger identification",
            "Control weakness classification",
            "Governance recommendation logging"
        ]
    },
    {
        "number": "Page 3",
        "title": "Manufacturing",
        "route": "/",
        "status": "LIVE",
        "purpose": "Preserved Manufacturing Core manufacturing assurance dashboard with evidence upload, hashing, verification, Excel analytics, process-chain validation, and audit report download.",
        "focus": [
            "Weighbridge → Dispatch → Invoice evidence chain",
            "Azure Blob-backed evidence records",
            "SHA-256 hash verification",
            "GREEN / YELLOW / RED integrity status",
            "COBIT 2019 control overlay"
        ]
    },
    {
        "number": "Page 4",
        "title": "Shift Assurance",
        "route": "/shift-assurance",
        "status": "LIVE SHELL",
        "purpose": "12-hour day/night shift assurance, equipment handoff, technician accountability, open issue carryover, and ServiceNow linkage.",
        "focus": [
            "Day/night shift handoff",
            "Equipment custody transfer",
            "Open issue carryover",
            "Technician accountability",
            "ServiceNow ticket linkage"
        ]
    },
    {
        "number": "Page 5",
        "title": "Access Governance",
        "route": "/access-governance",
        "status": "LIVE SHELL",
        "purpose": "myAccess alignment, user access review, binder-to-digital evidence, entitlement assurance, and quarterly certification support.",
        "focus": [
            "myAccess entitlement assurance",
            "Quarterly access review",
            "Binder evidence reconciliation",
            "Access approval traceability",
            "Segregation of duties monitoring"
        ]
    },
    {
        "number": "Page 6",
        "title": "Audit/CAPA",
        "route": "/audit-capa",
        "status": "LIVE SHELL",
        "purpose": "Audit findings, CAPA evidence, deviation linkage, remediation proof, and effectiveness-check readiness.",
        "focus": [
            "Audit finding traceability",
            "CAPA evidence integrity",
            "Deviation-to-remediation linkage",
            "Effectiveness-check readiness",
            "Audit response evidence pack"
        ]
    },
    {
        "number": "Future Page",
        "title": "Clinical Trial Integrity",
        "route": "/clinical-trial-integrity",
        "status": "PLANNED SHELL",
        "purpose": "Clinical trial evidence integrity, ALCOA+ traceability, COBIT control mapping, and regulated evidence assurance.",
        "focus": [
            "ALCOA+ evidence principles",
            "Clinical trial evidence traceability",
            "Control-to-evidence mapping",
            "Regulatory audit readiness",
            "Governance assurance overlay"
        ]
    }
]


def get_enterprise_page(route):
    for page in ENTERPRISE_PAGES:
        if page["route"] == route:
            return page
    return None


def get_enterprise_overview_metrics():
    # EXECUTIVE_OVERVIEW_V2_ACTIVE
    logs = prepare_logs()

    metrics = {
        "total_records": 0,
        "total_batches": 0,
        "green_total": 0,
        "yellow_total": 0,
        "red_total": 0,
        "audit_ready": 0,
        "conditional": 0,
        "not_ready": 0,
        "integrity_score": 0,
        "enterprise_status": "NO DATA",
        "enterprise_status_icon": "ℹ",
        "enterprise_status_class": "neutral",
        "open_exceptions": [],
        "recommended_actions": [],
        "module_maturity": [
            {"module": "Executive Overview", "status": "LIVE", "maturity": "Leadership dashboard active"},
            {"module": "SOP Governance", "status": "SHELL", "maturity": "Route live; SOP data connection pending"},
            {"module": "Manufacturing", "status": "LIVE", "maturity": "Manufacturing Core evidence hashing and audit logic active"},
            {"module": "Shift Assurance", "status": "SHELL", "maturity": "Route live; shift/equipment data pending"},
            {"module": "Access Governance", "status": "SHELL", "maturity": "Route live; myAccess/binder data pending"},
            {"module": "Audit/CAPA", "status": "SHELL", "maturity": "Route live; CAPA/deviation data pending"},
            {"module": "Clinical Trial Integrity", "status": "PLANNED", "maturity": "Concept page live"}
        ]
    }

    if logs.empty:
        metrics["recommended_actions"] = [
            "Upload manufacturing evidence to establish the first governance baseline.",
            "Use the Manufacturing dashboard as the initial controlled evidence engine.",
            "Connect Shift Assurance, Access Governance, SOP Governance, and Audit/CAPA after baseline evidence is stable."
        ]
        return metrics

    logs = logs.fillna("")
    metrics["total_records"] = len(logs)
    metrics["total_batches"] = logs["batch_id"].nunique()
    metrics["green_total"] = len(logs[logs["status"] == "GREEN"])
    metrics["yellow_total"] = len(logs[logs["status"] == "YELLOW"])
    metrics["red_total"] = len(logs[logs["status"] == "RED"])
    metrics["integrity_score"] = round((metrics["green_total"] / metrics["total_records"]) * 100, 2) if metrics["total_records"] else 0

    for batch_id, grp in logs.groupby("batch_id", dropna=False):
        batch_name = clean(batch_id) if clean(batch_id) else "NO-BATCH-ID"
        analysis = analyze_batch(batch_name, grp)

        if analysis["verdict"] == "AUDIT-READY":
            metrics["audit_ready"] += 1
        elif analysis["verdict"] == "CONDITIONALLY READY":
            metrics["conditional"] += 1
            metrics["open_exceptions"].append(f"{batch_name}: CONDITIONALLY READY")
        else:
            metrics["not_ready"] += 1
            metrics["open_exceptions"].append(f"{batch_name}: NOT AUDIT-READY")

    if metrics["red_total"] > 0 or metrics["not_ready"] > 0:
        metrics["enterprise_status"] = "CRITICAL GOVERNANCE ATTENTION REQUIRED"
        metrics["enterprise_status_icon"] = "❌"
        metrics["enterprise_status_class"] = "critical"
        metrics["recommended_actions"] = [
            "Review all RED evidence records before relying on affected batches for audit.",
            "Investigate hash mismatches and confirm whether evidence changed after baseline creation.",
            "Document remediation actions and regenerate audit reports after correction.",
            "Do not treat affected batches as audit-ready until integrity issues are resolved."
        ]
    elif metrics["yellow_total"] > 0 or metrics["conditional"] > 0:
        metrics["enterprise_status"] = "CONDITIONAL GOVERNANCE READINESS"
        metrics["enterprise_status_icon"] = "⚠"
        metrics["enterprise_status_class"] = "warning"
        metrics["recommended_actions"] = [
            "Review YELLOW records and confirm whether they represent new baselines or missing verification history.",
            "Complete missing process stages, approvals, or supporting evidence before final audit reliance.",
            "Use the Manufacturing dashboard to download audit reports for conditional batches.",
            "Prioritize connecting Shift Assurance and Access Governance data next."
        ]
    else:
        metrics["enterprise_status"] = "GOVERNANCE BASELINE HEALTHY"
        metrics["enterprise_status_icon"] = "✅"
        metrics["enterprise_status_class"] = "healthy"
        metrics["recommended_actions"] = [
            "Maintain current evidence upload discipline and baseline control.",
            "Expand the assurance model into Shift Assurance and Access Governance.",
            "Begin mapping SOP Governance evidence to existing manufacturing records.",
            "Prepare leadership demo using Executive Overview and Manufacturing pages."
        ]

    return metrics


@app.route("/manufacturing")
def manufacturing_alias():
    return redirect("/")


@app.route("/executive-overview")
def executive_overview_page():
    # EXECUTIVE_V3_PROMOTED_REDIRECT_ACTIVE
    # Safe promotion: keep /executive-overview-v3-test as the functional enterprise dashboard,
    # and redirect the main Executive Overview route to it.
    return redirect("/executive-overview-v3-test")


@app.route("/sop-governance", methods=["GET", "POST"])
def sop_governance_page():
    page = get_enterprise_page("/sop-governance")

    if request.method == "POST":
        result = run_sop_comparison(request)
        if not result.get("error"):
            save_sop_comparison_result(result)
        return render_sop_governance_v2(page, result=result)

    return render_sop_governance_v2(page)



@app.route("/shift-assurance")
def shift_assurance_page():
    # SHIFT_V2_PROMOTED_REDIRECT_ACTIVE
    # Safe promotion: keep /shift-assurance-v2-test as the functional page,
    # and redirect the main Shift Assurance route to it.
    return redirect("/shift-assurance-v2-test")


@app.route("/access-governance")
def access_governance_page():
    page = get_enterprise_page("/access-governance")
    return render_enterprise_shell_page(page)


@app.route("/audit-capa")
def audit_capa_page():
    # AUDIT_CAPA_V2_PROMOTED_REDIRECT_ACTIVE
    # Safe promotion: keep /audit-capa-v2-test as the functional page,
    # and redirect the main Audit/CAPA route to it.
    return redirect("/audit-capa-v2-test")


@app.route("/clinical-trial-integrity")
def clinical_trial_integrity_page():
    # CLINICAL_TRIAL_V3_PROMOTED_REDIRECT_ACTIVE
    # Safe promotion: keep /clinical-trial-integrity-v3-test as the functional page,
    # and redirect the main Clinical Trial Integrity route to it.
    return redirect("/clinical-trial-integrity-v3-test")


def render_enterprise_shell_page(page, metrics=None):
    metrics = metrics or {}
    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain™ Enterprise Governance Platform</title>
<style>
:root {
    --bg:#f4f7fb; --navy:#071527; --blue:#2563eb; --cyan:#06b6d4;
    --green:#16a34a; --yellow:#f59e0b; --red:#dc2626; --muted:#64748b;
    --card:#ffffff; --border:#e5e7eb;
}
* { box-sizing:border-box; }
body {
    margin:0; font-family:Inter,Segoe UI,Arial,sans-serif;
    background:linear-gradient(135deg,#eef4ff,#f8fafc,#eefdf8);
    color:#0f172a;
}
.hero {
    background:radial-gradient(circle at top left,#1d4ed8 0%,#0f2745 42%,#071527 100%);
    color:white; padding:36px 42px 46px;
    border-bottom-left-radius:34px; border-bottom-right-radius:34px;
    box-shadow:0 18px 45px rgba(15,39,69,.25);
}
.hero-top { display:flex; align-items:center; justify-content:space-between; gap:20px; flex-wrap:wrap; }
.brand { display:flex; align-items:center; gap:14px; }
.logo {
    width:54px; height:54px; border-radius:18px;
    background:linear-gradient(135deg,#38bdf8,#22c55e);
    display:flex; align-items:center; justify-content:center;
    font-weight:900; font-size:22px;
}
.brand h1 { margin:0; font-size:34px; letter-spacing:-.8px; }
.brand p { margin:4px 0 0; color:#cbd5e1; }
.badge {
    padding:10px 15px; border-radius:999px;
    background:rgba(255,255,255,.12); border:1px solid rgba(255,255,255,.22);
    color:#e0f2fe; font-weight:800;
}
.container { max-width:1450px; margin:-28px auto 50px; padding:0 26px; }
.nav {
    background:white; border:1px solid #e5e7eb; border-radius:24px;
    padding:14px; box-shadow:0 14px 35px rgba(15,23,42,.08);
    display:flex; gap:10px; flex-wrap:wrap; margin-bottom:22px;
}
.nav a {
    text-decoration:none; color:#0f172a; background:#f8fafc; border:1px solid #e2e8f0;
    padding:10px 13px; border-radius:999px; font-weight:900; font-size:13px;
}
.nav a.active { background:#0f172a; color:white; border-color:#0f172a; }
.grid { display:grid; grid-template-columns:repeat(4,1fr); gap:18px; margin-bottom:20px; }
.metric {
    background:rgba(255,255,255,.96); border:1px solid rgba(226,232,240,.9);
    border-radius:22px; padding:22px; box-shadow:0 12px 32px rgba(15,23,42,.08);
}
.metric-label { color:#64748b; font-weight:800; font-size:13px; text-transform:uppercase; letter-spacing:.08em; }
.metric-value { margin-top:8px; font-size:34px; font-weight:900; }
.metric-sub { color:#64748b; font-size:13px; }
.main-layout { display:grid; grid-template-columns:360px 1fr; gap:22px; align-items:start; }
.panel, .card {
    background:white; border:1px solid #e5e7eb; border-radius:24px;
    padding:22px; box-shadow:0 14px 35px rgba(15,23,42,.08);
}
.panel { margin-bottom:20px; }
.page-link {
    display:block; text-decoration:none; color:#0f172a; padding:13px 14px;
    border:1px solid #e2e8f0; border-radius:16px; margin:9px 0; background:#f8fafc;
}
.page-link.active {
    background:linear-gradient(135deg,#eff6ff,#ecfeff);
    border-color:#93c5fd; box-shadow:0 8px 18px rgba(37,99,235,.12);
}
.page-link b { display:block; font-size:14px; }
.page-link small { color:#64748b; font-weight:700; }
.status-pill {
    display:inline-block; margin-top:7px; padding:5px 8px; border-radius:999px;
    font-size:11px; font-weight:900; background:#e2e8f0; color:#334155;
}
.status-live { background:#dcfce7; color:#166534; }
.status-shell { background:#dbeafe; color:#1d4ed8; }
.status-planned { background:#f1f5f9; color:#475569; }
.notice {
    background:#f0fdf4; border-left:7px solid #16a34a; border-radius:18px;
    padding:17px; line-height:1.55; margin-bottom:20px;
}
.note {
    background:#fff7ed; border-left:7px solid #f59e0b; border-radius:18px;
    padding:17px; line-height:1.55; margin-bottom:20px;
}
.focus-grid { display:grid; grid-template-columns:repeat(2,1fr); gap:14px; }
.focus-item {
    background:#f8fafc; border:1px solid #e2e8f0; border-radius:18px;
    padding:15px; font-weight:800;
}
.exception-list li { margin-bottom:8px; }

.exec-table {
    width:100%; border-collapse:collapse; border-radius:16px; overflow:hidden; font-size:13px;
}
.exec-table th {
    background:#0f172a; color:white; text-align:left; padding:12px;
}
.exec-table td {
    border-bottom:1px solid #e5e7eb; padding:12px; vertical-align:top;
}
.status-card-healthy { border-left:8px solid #16a34a; background:linear-gradient(135deg,#f0fdf4,#ffffff); }
.status-card-warning { border-left:8px solid #f59e0b; background:linear-gradient(135deg,#fffbeb,#ffffff); }
.status-card-critical { border-left:8px solid #dc2626; background:linear-gradient(135deg,#fef2f2,#ffffff); }
.status-card-neutral { border-left:8px solid #64748b; background:linear-gradient(135deg,#f8fafc,#ffffff); }


.shift-grid {
    display:grid; grid-template-columns:repeat(3,1fr); gap:18px; margin-bottom:20px;
}
.shift-two-col {
    display:grid; grid-template-columns:repeat(2,1fr); gap:18px; margin-bottom:20px;
}
.shift-card, .shift-mini {
    background:white; border:1px solid #e2e8f0; border-radius:24px;
    padding:22px; box-shadow:0 14px 35px rgba(15,23,42,.08);
}
.shift-card h3 { margin:8px 0 10px; }
.shift-card p, .shift-mini p { color:#475569; line-height:1.5; }
.shift-label {
    color:#64748b; font-weight:900; font-size:12px;
    text-transform:uppercase; letter-spacing:.08em;
}
.shift-badge {
    display:inline-block; margin-top:10px; padding:7px 10px; border-radius:999px;
    background:#eff6ff; color:#1d4ed8; font-weight:900; font-size:12px;
    border:1px solid #bfdbfe;
}
.handoff-flow {
    display:flex; gap:12px; flex-wrap:wrap; align-items:stretch; margin-top:14px;
}
.handoff-step {
    flex:1; min-width:190px; background:linear-gradient(135deg,#eff6ff,#ecfeff);
    border:1px solid #bfdbfe; border-radius:18px; padding:15px;
}
.handoff-step b {
    display:block; margin-bottom:7px;
}
.handoff-step span {
    display:block; color:#475569; line-height:1.45; font-size:13px;
}
.handoff-arrow {
    display:flex; align-items:center; justify-content:center;
    color:#94a3b8; font-weight:900; font-size:22px;
}
@media(max-width:1000px){
    .shift-grid,.shift-two-col{ grid-template-columns:1fr; }
    .handoff-arrow{ display:none; }
}


.access-grid {
    display:grid; grid-template-columns:repeat(3,1fr); gap:18px; margin-bottom:20px;
}
.access-two-col {
    display:grid; grid-template-columns:repeat(2,1fr); gap:18px; margin-bottom:20px;
}
.access-card, .access-mini {
    background:white; border:1px solid #e2e8f0; border-radius:24px;
    padding:22px; box-shadow:0 14px 35px rgba(15,23,42,.08);
}
.access-card h3 { margin:8px 0 10px; }
.access-card p, .access-mini p { color:#475569; line-height:1.5; }
.access-label {
    color:#64748b; font-weight:900; font-size:12px;
    text-transform:uppercase; letter-spacing:.08em;
}
.access-badge {
    display:inline-block; margin-top:10px; padding:7px 10px; border-radius:999px;
    background:#eff6ff; color:#1d4ed8; font-weight:900; font-size:12px;
    border:1px solid #bfdbfe;
}
.access-flow {
    display:flex; gap:12px; flex-wrap:wrap; align-items:stretch; margin-top:14px;
}
.access-step {
    flex:1; min-width:190px; background:linear-gradient(135deg,#eff6ff,#ecfeff);
    border:1px solid #bfdbfe; border-radius:18px; padding:15px;
}
.access-step b {
    display:block; margin-bottom:7px;
}
.access-step span {
    display:block; color:#475569; line-height:1.45; font-size:13px;
}
.access-arrow {
    display:flex; align-items:center; justify-content:center;
    color:#94a3b8; font-weight:900; font-size:22px;
}
@media(max-width:1000px){
    .access-grid,.access-two-col{ grid-template-columns:1fr; }
    .access-arrow{ display:none; }
}


.sop-grid {
    display:grid; grid-template-columns:repeat(3,1fr); gap:18px; margin-bottom:20px;
}
.sop-two-col {
    display:grid; grid-template-columns:repeat(2,1fr); gap:18px; margin-bottom:20px;
}
.sop-card, .sop-mini {
    background:white; border:1px solid #e2e8f0; border-radius:24px;
    padding:22px; box-shadow:0 14px 35px rgba(15,23,42,.08);
}
.sop-card h3 { margin:8px 0 10px; }
.sop-card p, .sop-mini p { color:#475569; line-height:1.5; }
.sop-label {
    color:#64748b; font-weight:900; font-size:12px;
    text-transform:uppercase; letter-spacing:.08em;
}
.sop-badge {
    display:inline-block; margin-top:10px; padding:7px 10px; border-radius:999px;
    background:#eff6ff; color:#1d4ed8; font-weight:900; font-size:12px;
    border:1px solid #bfdbfe;
}
.sop-flow {
    display:flex; gap:12px; flex-wrap:wrap; align-items:stretch; margin-top:14px;
}
.sop-step {
    flex:1; min-width:190px; background:linear-gradient(135deg,#eff6ff,#ecfeff);
    border:1px solid #bfdbfe; border-radius:18px; padding:15px;
}
.sop-step b {
    display:block; margin-bottom:7px;
}
.sop-step span {
    display:block; color:#475569; line-height:1.45; font-size:13px;
}
.sop-arrow {
    display:flex; align-items:center; justify-content:center;
    color:#94a3b8; font-weight:900; font-size:22px;
}
@media(max-width:1000px){
    .sop-grid,.sop-two-col{ grid-template-columns:1fr; }
    .sop-arrow{ display:none; }
}


.audit-grid {
    display:grid; grid-template-columns:repeat(3,1fr); gap:18px; margin-bottom:20px;
}
.audit-two-col {
    display:grid; grid-template-columns:repeat(2,1fr); gap:18px; margin-bottom:20px;
}
.audit-card, .audit-mini {
    background:white; border:1px solid #e2e8f0; border-radius:24px;
    padding:22px; box-shadow:0 14px 35px rgba(15,23,42,.08);
}
.audit-card h3 { margin:8px 0 10px; }
.audit-card p, .audit-mini p { color:#475569; line-height:1.5; }
.audit-label {
    color:#64748b; font-weight:900; font-size:12px;
    text-transform:uppercase; letter-spacing:.08em;
}
.audit-badge {
    display:inline-block; margin-top:10px; padding:7px 10px; border-radius:999px;
    background:#eff6ff; color:#1d4ed8; font-weight:900; font-size:12px;
    border:1px solid #bfdbfe;
}
.audit-flow {
    display:flex; gap:12px; flex-wrap:wrap; align-items:stretch; margin-top:14px;
}
.audit-step {
    flex:1; min-width:190px; background:linear-gradient(135deg,#eff6ff,#ecfeff);
    border:1px solid #bfdbfe; border-radius:18px; padding:15px;
}
.audit-step b {
    display:block; margin-bottom:7px;
}
.audit-step span {
    display:block; color:#475569; line-height:1.45; font-size:13px;
}
.audit-arrow {
    display:flex; align-items:center; justify-content:center;
    color:#94a3b8; font-weight:900; font-size:22px;
}
@media(max-width:1000px){
    .audit-grid,.audit-two-col{ grid-template-columns:1fr; }
    .audit-arrow{ display:none; }
}


.trial-grid {
    display:grid; grid-template-columns:repeat(3,1fr); gap:18px; margin-bottom:20px;
}
.trial-two-col {
    display:grid; grid-template-columns:repeat(2,1fr); gap:18px; margin-bottom:20px;
}
.trial-card, .trial-mini {
    background:white; border:1px solid #e2e8f0; border-radius:24px;
    padding:22px; box-shadow:0 14px 35px rgba(15,23,42,.08);
}
.trial-card h3 { margin:8px 0 10px; }
.trial-card p, .trial-mini p { color:#475569; line-height:1.5; }
.trial-label {
    color:#64748b; font-weight:900; font-size:12px;
    text-transform:uppercase; letter-spacing:.08em;
}
.trial-badge {
    display:inline-block; margin-top:10px; padding:7px 10px; border-radius:999px;
    background:#eff6ff; color:#1d4ed8; font-weight:900; font-size:12px;
    border:1px solid #bfdbfe;
}
.trial-flow {
    display:flex; gap:12px; flex-wrap:wrap; align-items:stretch; margin-top:14px;
}
.trial-step {
    flex:1; min-width:190px; background:linear-gradient(135deg,#eff6ff,#ecfeff);
    border:1px solid #bfdbfe; border-radius:18px; padding:15px;
}
.trial-step b {
    display:block; margin-bottom:7px;
}
.trial-step span {
    display:block; color:#475569; line-height:1.45; font-size:13px;
}
.trial-arrow {
    display:flex; align-items:center; justify-content:center;
    color:#94a3b8; font-weight:900; font-size:22px;
}
@media(max-width:1000px){
    .trial-grid,.trial-two-col{ grid-template-columns:1fr; }
    .trial-arrow{ display:none; }
}

@media(max-width:1000px){ .grid,.main-layout,.focus-grid{ grid-template-columns:1fr; } }
</style>
</head>

<body>
<section class="hero">
    <div class="hero-top">
        <div class="brand">
            <div class="logo">CC</div>
            <div>
                <h1>COBIT-Chain™</h1>
                <p>Enterprise Governance Platform • Evidence Integrity • Audit Readiness</p>
            </div>
        </div>
        <div class="badge">{{ page.number }} • {{ page.status }}</div>
    </div>
</section>

<main class="container">
    <nav class="nav">
        {% for p in pages %}
            <a class="{% if p.route == page.route %}active{% endif %}" href="{{ p.route }}">{{ p.title }}</a>
        {% endfor %}
    </nav>

    {% if page.route == "/executive-overview" %}
    <section class="grid">
        <div class="metric"><div class="metric-label">Total Batches</div><div class="metric-value">{{ metrics.total_batches }}</div><div class="metric-sub">Manufacturing process chains</div></div>
        <div class="metric"><div class="metric-label">Total Records</div><div class="metric-value">{{ metrics.total_records }}</div><div class="metric-sub">Evidence events logged</div></div>
        <div class="metric"><div class="metric-label">Integrity Score</div><div class="metric-value" style="color:#16a34a">{{ metrics.integrity_score }}%</div><div class="metric-sub">Green records vs total records</div></div>
        <div class="metric"><div class="metric-label">Critical Red</div><div class="metric-value" style="color:#dc2626">{{ metrics.red_total }}</div><div class="metric-sub">Tamper or integrity issues</div></div>
    </section>
    {% endif %}

    <section class="main-layout">
        <aside>
            <div class="panel">
                <h2>Enterprise Pages</h2>
                {% for p in pages %}
                <a class="page-link {% if p.route == page.route %}active{% endif %}" href="{{ p.route }}">
                    <b>{{ p.number }} → {{ p.title }}</b>
                    <small>{{ p.purpose }}</small><br>
                    <span class="status-pill {% if p.status == 'LIVE' %}status-live{% elif 'SHELL' in p.status %}status-shell{% else %}status-planned{% endif %}">
                        {{ p.status }}
                    </span>
                </a>
                {% endfor %}
            </div>
        </aside>

        <section>
            <div class="card">
                <h2>{{ page.number }} → {{ page.title }}</h2>
                <p><b>Status:</b> {{ page.status }}</p>
                <p>{{ page.purpose }}</p>
            </div>

            <div class="notice">
                <b>Safe enterprise expansion:</b> This page was added beside the existing Manufacturing/Manufacturing Core dashboard.
                The original <b>/</b> dashboard remains preserved and continues to handle upload, hashing, verification,
                Azure Blob logging, process-chain validation, and audit report generation.
            </div>

            {% if page.route == "/executive-overview" %}
            <div class="card status-card-{{ metrics.enterprise_status_class }}">
                <h2>{{ metrics.enterprise_status_icon }} Executive Governance Status</h2>
                <p><b>{{ metrics.enterprise_status }}</b></p>
                <p>
                    This executive view summarizes the current governance posture using the Manufacturing Assurance evidence engine
                    while the other enterprise modules are being connected safely.
                </p>
            </div>

            <div class="card">
                <h2>Audit Readiness Summary</h2>
                <section class="grid">
                    <div class="metric"><div class="metric-label">Audit Ready</div><div class="metric-value" style="color:#16a34a">{{ metrics.audit_ready }}</div><div class="metric-sub">Batches ready</div></div>
                    <div class="metric"><div class="metric-label">Conditional</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional }}</div><div class="metric-sub">Need follow-up</div></div>
                    <div class="metric"><div class="metric-label">Not Ready</div><div class="metric-value" style="color:#dc2626">{{ metrics.not_ready }}</div><div class="metric-sub">Critical issues</div></div>
                    <div class="metric"><div class="metric-label">Yellow Records</div><div class="metric-value" style="color:#f59e0b">{{ metrics.yellow_total }}</div><div class="metric-sub">Baseline or review gaps</div></div>
                </section>
            </div>

            <div class="card">
                <h2>Module Maturity Board</h2>
                <table class="exec-table">
                    <tr>
                        <th>Module</th>
                        <th>Status</th>
                        <th>Current Maturity</th>
                    </tr>
                    {% for m in metrics.module_maturity %}
                    <tr>
                        <td><b>{{ m.module }}</b></td>
                        <td>{{ m.status }}</td>
                        <td>{{ m.maturity }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>

            <div class="card">
                <h2>Open Exceptions</h2>
                {% if metrics.open_exceptions %}
                    <ul class="exception-list">
                    {% for item in metrics.open_exceptions[:10] %}
                        <li>{{ item }}</li>
                    {% endfor %}
                    </ul>
                {% else %}
                    <p>No open exceptions detected from current manufacturing records.</p>
                {% endif %}
            </div>

            <div class="card">
                <h2>Recommended Leadership Actions</h2>
                <ul class="exception-list">
                    {% for action in metrics.recommended_actions %}
                    <li>{{ action }}</li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}

            <div class="card">
                <h2>Module Focus Areas</h2>
                <div class="focus-grid">
                    {% for item in page.focus %}
                    <div class="focus-item">{{ item }}</div>
                    {% endfor %}
                </div>
            </div>

            {% if page.route == "/shift-assurance" %}
            <!-- SHIFT_ASSURANCE_V1_ACTIVE -->
            <div class="card status-card-warning">
                <h2>⚠ Shift Assurance v1</h2>
                <p><b>Purpose:</b> create a governed 12-hour day/night shift handoff model for technicians, equipment status, unresolved issues, and ServiceNow-linked operational continuity.</p>
                <p>This page is currently a controlled enterprise module shell. It does not change the Manufacturing/Manufacturing Core dashboard or write to the existing manufacturing evidence logs.</p>
            </div>

            <section class="shift-grid">
                <div class="shift-card">
                    <div class="shift-label">Shift Model</div>
                    <h3>Day Shift / Night Shift</h3>
                    <p>Designed for 12-hour coverage where each incoming technician can see equipment condition, unresolved issues, and carryover items from the prior shift.</p>
                    <span class="shift-badge">12-hour rotation</span>
                </div>

                <div class="shift-card">
                    <div class="shift-label">Equipment Scope</div>
                    <h3>Equipment Handoff</h3>
                    <p>Tracks whether each equipment item is available, unavailable, under maintenance, out of service, or pending QA/engineering review.</p>
                    <span class="shift-badge">Custody control</span>
                </div>

                <div class="shift-card">
                    <div class="shift-label">Ticket Source</div>
                    <h3>ServiceNow Linkage</h3>
                    <p>ServiceNow remains the ticket system of record. COBIT-Chain adds governance visibility, handoff assurance, and unresolved issue carryover.</p>
                    <span class="shift-badge">Future CSV/API link</span>
                </div>
            </section>

            <div class="card">
                <h2>Shift Handoff Control Flow</h2>
                <div class="handoff-flow">
                    <div class="handoff-step">
                        <b>1. Incoming Shift Review</b>
                        <span>Review prior shift notes, open tickets, equipment status, and unresolved risks.</span>
                    </div>
                    <div class="handoff-arrow">→</div>
                    <div class="handoff-step">
                        <b>2. Equipment Status Check</b>
                        <span>Confirm each covered equipment item is available, degraded, under maintenance, or out of service.</span>
                    </div>
                    <div class="handoff-arrow">→</div>
                    <div class="handoff-step">
                        <b>3. Issue Ownership</b>
                        <span>Assign owner, escalation path, and expected next action for each carryover item.</span>
                    </div>
                    <div class="handoff-arrow">→</div>
                    <div class="handoff-step">
                        <b>4. Handoff Signoff</b>
                        <span>Outgoing and incoming technicians confirm handoff completeness and known exceptions.</span>
                    </div>
                    <div class="handoff-arrow">→</div>
                    <div class="handoff-step">
                        <b>5. Audit-Ready Record</b>
                        <span>Create traceable shift evidence for operational continuity, investigation support, and audit review.</span>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Equipment Handoff Data Model</h2>
                <table class="exec-table">
                    <tr>
                        <th>Field</th>
                        <th>Purpose</th>
                        <th>Governance Value</th>
                    </tr>
                    <tr>
                        <td><b>Shift Date / Shift Type</b></td>
                        <td>Identifies day shift or night shift coverage window.</td>
                        <td>Creates time-bound accountability.</td>
                    </tr>
                    <tr>
                        <td><b>Equipment ID / Name</b></td>
                        <td>Identifies the asset or system being handed over.</td>
                        <td>Links equipment condition to operational ownership.</td>
                    </tr>
                    <tr>
                        <td><b>Equipment Status</b></td>
                        <td>Available, degraded, under maintenance, out of service, or pending review.</td>
                        <td>Prevents unclear equipment readiness during shift transition.</td>
                    </tr>
                    <tr>
                        <td><b>ServiceNow Ticket</b></td>
                        <td>Links open incident, request, work order, or maintenance item.</td>
                        <td>Keeps ServiceNow as record of action while COBIT-Chain governs visibility.</td>
                    </tr>
                    <tr>
                        <td><b>Open Issue / Risk</b></td>
                        <td>Captures unresolved operational issue or compliance concern.</td>
                        <td>Prevents loss of critical issue context between shifts.</td>
                    </tr>
                    <tr>
                        <td><b>Outgoing Technician</b></td>
                        <td>Person handing over the shift or equipment status.</td>
                        <td>Creates accountability for outgoing information.</td>
                    </tr>
                    <tr>
                        <td><b>Incoming Technician</b></td>
                        <td>Person accepting the handoff and next action ownership.</td>
                        <td>Creates accountability for follow-up execution.</td>
                    </tr>
                    <tr>
                        <td><b>QA / Engineering Escalation</b></td>
                        <td>Indicates whether issue needs escalation beyond technician level.</td>
                        <td>Supports controlled escalation and audit defensibility.</td>
                    </tr>
                </table>
            </div>

            <section class="shift-two-col">
                <div class="card">
                    <h2>Day Shift View</h2>
                    <ul class="exception-list">
                        <li>Review carryover issues from night shift.</li>
                        <li>Confirm production-support equipment readiness.</li>
                        <li>Validate critical open ServiceNow tickets.</li>
                        <li>Escalate blocked or repeated equipment issues.</li>
                        <li>Document any handoff exception before shift close.</li>
                    </ul>
                </div>

                <div class="card">
                    <h2>Night Shift View</h2>
                    <ul class="exception-list">
                        <li>Confirm unresolved day-shift issues are still visible.</li>
                        <li>Track equipment status changes during night coverage.</li>
                        <li>Flag items requiring next-day QA or engineering action.</li>
                        <li>Preserve evidence for next shift review.</li>
                        <li>Prevent silent issue rollover without ownership.</li>
                    </ul>
                </div>
            </section>

            <div class="card">
                <h2>ServiceNow Linkage Design</h2>
                <div class="shift-grid">
                    <div class="shift-mini">
                        <b>Input</b>
                        <p>ServiceNow ticket export or API feed: ticket number, CI/equipment, status, priority, assignment group, opened date, and latest update.</p>
                    </div>
                    <div class="shift-mini">
                        <b>COBIT-Chain Governance Layer</b>
                        <p>Maps tickets to shift handoff records, equipment status, unresolved risk, technician ownership, and escalation state.</p>
                    </div>
                    <div class="shift-mini">
                        <b>Output</b>
                        <p>Shift readiness view, unresolved issue carryover, audit-ready handoff record, and exception list for leadership or QA review.</p>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Escalation Rules</h2>
                <table class="exec-table">
                    <tr>
                        <th>Condition</th>
                        <th>Risk Level</th>
                        <th>Recommended Escalation</th>
                    </tr>
                    <tr>
                        <td>Critical equipment out of service with no owner assigned</td>
                        <td>High</td>
                        <td>Escalate to IT/Engineering lead and shift supervisor.</td>
                    </tr>
                    <tr>
                        <td>Open ServiceNow ticket carried over for more than one shift</td>
                        <td>Medium</td>
                        <td>Require update note and named owner before next handoff.</td>
                    </tr>
                    <tr>
                        <td>Equipment available but status not confirmed by incoming technician</td>
                        <td>Medium</td>
                        <td>Require incoming acceptance before handoff closure.</td>
                    </tr>
                    <tr>
                        <td>QA-impacting issue with incomplete evidence</td>
                        <td>High</td>
                        <td>Escalate to QA or system owner before audit reliance.</td>
                    </tr>
                    <tr>
                        <td>No open issues and all equipment status confirmed</td>
                        <td>Low</td>
                        <td>Proceed with normal shift acceptance.</td>
                    </tr>
                </table>
            </div>

            <div class="note">
                <b>Next build step:</b> add a simple Shift Handoff CSV storage file separate from manufacturing logs, for example
                <b>shift_handoffs.csv</b>. That will allow this page to save real day/night shift records without touching the current Manufacturing Core manufacturing evidence chain.
            </div>
            {% elif page.route == "/sop-governance" %}
            <!-- SOP_GOVERNANCE_V1_ACTIVE -->
            <div class="card status-card-warning">
                <h2>⚠ SOP Governance v1</h2>
                <p><b>Purpose:</b> create a controlled governance view for SOP-to-reality alignment, process drift, SOP gaps, review triggers, and audit-ready recommendations.</p>
                <p>This page is currently a controlled enterprise module shell. It does not change the Manufacturing/Manufacturing Core dashboard or write to the existing manufacturing evidence logs.</p>
            </div>

            <section class="sop-grid">
                <div class="sop-card">
                    <div class="sop-label">Core Problem</div>
                    <h3>SOP vs Reality Gap</h3>
                    <p>Identifies where the written procedure says one thing but the business process, system workflow, or evidence trail shows something different.</p>
                    <span class="sop-badge">Process drift</span>
                </div>

                <div class="sop-card">
                    <div class="sop-label">Evidence Source</div>
                    <h3>SOP_Gap / SOP_Summary</h3>
                    <p>Future linkage Acquired Site for SOP gap files, SOP summaries, control mappings, exception narratives, and recommendation outputs.</p>
                    <span class="sop-badge">Future CSV linkage</span>
                </div>

                <div class="sop-card">
                    <div class="sop-label">Governance Output</div>
                    <h3>Review Triggers</h3>
                    <p>Flags when SOP review may be required due to audit findings, process expansion, system change, repeated deviations, or recurring control gaps.</p>
                    <span class="sop-badge">Review readiness</span>
                </div>
            </section>

            <div class="card">
                <h2>SOP Governance Control Flow</h2>
                <div class="sop-flow">
                    <div class="sop-step">
                        <b>1. SOP Intake</b>
                        <span>Capture SOP title, version, owner, effective date, process area, and key control points.</span>
                    </div>
                    <div class="sop-arrow">→</div>
                    <div class="sop-step">
                        <b>2. Reality Evidence</b>
                        <span>Compare SOP expectations against actual evidence from logs, uploads, workflows, tickets, or audit findings.</span>
                    </div>
                    <div class="sop-arrow">→</div>
                    <div class="sop-step">
                        <b>3. Gap Classification</b>
                        <span>Classify whether the issue is documentation drift, process noncompliance, missing evidence, or control weakness.</span>
                    </div>
                    <div class="sop-arrow">→</div>
                    <div class="sop-step">
                        <b>4. Review Trigger</b>
                        <span>Determine whether SOP revision, training, CAPA, system update, or governance escalation is needed.</span>
                    </div>
                    <div class="sop-arrow">→</div>
                    <div class="sop-step">
                        <b>5. Audit-Ready Recommendation</b>
                        <span>Generate a defensible recommendation showing gap, impact, owner, action, and evidence basis.</span>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>SOP Gap Data Model</h2>
                <table class="exec-table">
                    <tr>
                        <th>Field</th>
                        <th>Purpose</th>
                        <th>Governance Value</th>
                    </tr>
                    <tr>
                        <td><b>SOP ID / Title</b></td>
                        <td>Identifies the controlled procedure being assessed.</td>
                        <td>Links gap findings to the correct controlled document.</td>
                    </tr>
                    <tr>
                        <td><b>SOP Version / Effective Date</b></td>
                        <td>Shows which version was active when the gap was identified.</td>
                        <td>Prevents confusion between outdated and current procedure expectations.</td>
                    </tr>
                    <tr>
                        <td><b>Process Area</b></td>
                        <td>Identifies the business or operational process covered by the SOP.</td>
                        <td>Supports ownership and impact analysis.</td>
                    </tr>
                    <tr>
                        <td><b>Expected Procedure Step</b></td>
                        <td>Captures what the SOP says should happen.</td>
                        <td>Creates the baseline for procedural compliance assessment.</td>
                    </tr>
                    <tr>
                        <td><b>Observed Reality</b></td>
                        <td>Captures what actually happened in practice or system evidence.</td>
                        <td>Identifies process drift or execution mismatch.</td>
                    </tr>
                    <tr>
                        <td><b>Gap Type</b></td>
                        <td>Documentation gap, process gap, system gap, training gap, or evidence gap.</td>
                        <td>Supports correct remediation pathway.</td>
                    </tr>
                    <tr>
                        <td><b>Severity</b></td>
                        <td>Low, medium, high, or critical.</td>
                        <td>Prioritizes governance attention and escalation.</td>
                    </tr>
                    <tr>
                        <td><b>Recommended Action</b></td>
                        <td>SOP update, retraining, CAPA, workflow fix, control update, or no action.</td>
                        <td>Turns observation into auditable governance response.</td>
                    </tr>
                </table>
            </div>

            <section class="sop-two-col">
                <div class="card">
                    <h2>When SOP Review Should Be Triggered</h2>
                    <ul class="exception-list">
                        <li>Audit identifies mismatch between procedure and actual process.</li>
                        <li>Business expands or introduces a new product/process flow.</li>
                        <li>System or technology change affects control execution.</li>
                        <li>Repeated deviations suggest the procedure is no longer practical.</li>
                        <li>Evidence trail does not support the procedure as written.</li>
                        <li>Roles and responsibilities have changed but SOP still reflects old ownership.</li>
                    </ul>
                </div>

                <div class="card">
                    <h2>COBIT-Chain Value</h2>
                    <ul class="exception-list">
                        <li>Connects procedure expectations to operational evidence.</li>
                        <li>Distinguishes outdated SOPs from actual process noncompliance.</li>
                        <li>Creates a governance trail for SOP review and remediation.</li>
                        <li>Supports audit-ready explanation of why an SOP requires update.</li>
                        <li>Links SOP gaps to CAPA, access, shift, or manufacturing evidence where relevant.</li>
                    </ul>
                </div>
            </section>

            <div class="card">
                <h2>SOP Gap Risk Rules</h2>
                <table class="exec-table">
                    <tr>
                        <th>Condition</th>
                        <th>Risk Level</th>
                        <th>Recommended Governance Action</th>
                    </tr>
                    <tr>
                        <td>SOP requires a control step but no evidence exists that the step occurred</td>
                        <td>High</td>
                        <td>Investigate process execution and determine whether CAPA or retraining is required.</td>
                    </tr>
                    <tr>
                        <td>Business performs a valid process not reflected in the SOP</td>
                        <td>Medium</td>
                        <td>Open SOP review and update controlled procedure to reflect operational reality.</td>
                    </tr>
                    <tr>
                        <td>SOP references an old system, role, or tool</td>
                        <td>Medium</td>
                        <td>Assign SOP owner to update outdated system or responsibility references.</td>
                    </tr>
                    <tr>
                        <td>Repeated deviations occur against the same SOP section</td>
                        <td>High</td>
                        <td>Assess whether the SOP is impractical, unclear, outdated, or not properly trained.</td>
                    </tr>
                    <tr>
                        <td>SOP, process, and evidence are aligned</td>
                        <td>Low</td>
                        <td>Retain as audit-ready procedural evidence.</td>
                    </tr>
                </table>
            </div>

            <div class="card">
                <h2>SOP Governance Relationship Model</h2>
                <div class="sop-grid">
                    <div class="sop-mini">
                        <b>SOP Document</b>
                        <p>Defines the approved process, roles, control points, sequence, and required evidence.</p>
                    </div>
                    <div class="sop-mini">
                        <b>Operational Reality</b>
                        <p>Shows what users, systems, technicians, reviewers, or process owners actually do.</p>
                    </div>
                    <div class="sop-mini">
                        <b>COBIT-Chain</b>
                        <p>Acts as the governance assurance layer that compares procedure expectation to evidence-backed reality.</p>
                    </div>
                </div>
            </div>

            <div class="note">
                <b>Next build step:</b> add a separate <b>sop_gaps.csv</b> storage file for SOP gap records.
                This will allow SOP Governance to save real SOP mismatch evidence without touching the Manufacturing/Manufacturing Core evidence chain.
            </div>
            {% elif page.route == "/access-governance" %}
            <!-- ACCESS_GOVERNANCE_V1_ACTIVE -->
            <div class="card status-card-warning">
                <h2>⚠ Access Governance v1</h2>
                <p><b>Purpose:</b> provide a controlled governance view for myAccess, access review evidence, binder-to-digital reconciliation, entitlement approval, and quarterly certification readiness.</p>
                <p>This page is currently a controlled enterprise module shell. It does not write to the existing Manufacturing/Manufacturing Core evidence logs and does not change the homepage dashboard.</p>
            </div>

            <section class="access-grid">
                <div class="access-card">
                    <div class="access-label">System of Record</div>
                    <h3>myAccess Alignment</h3>
                    <p>myAccess remains the access request and approval system of record. COBIT-Chain adds governance visibility, evidence integrity, and audit-readiness mapping.</p>
                    <span class="access-badge">Approval traceability</span>
                </div>

                <div class="access-card">
                    <div class="access-label">Legacy Evidence</div>
                    <h3>Binder-to-Digital Control</h3>
                    <p>Paper binder records and Excel trackers can be converted into governed evidence packs with clear owner, approval, review, and reconciliation status.</p>
                    <span class="access-badge">Binder reconciliation</span>
                </div>

                <div class="access-card">
                    <div class="access-label">Periodic Review</div>
                    <h3>Quarterly Access Review</h3>
                    <p>Supports user access review evidence, reviewer signoff, exception tracking, and readiness for internal or external audit review.</p>
                    <span class="access-badge">Certification support</span>
                </div>
            </section>

            <div class="card">
                <h2>Access Governance Control Flow</h2>
                <div class="access-flow">
                    <div class="access-step">
                        <b>1. Access Request</b>
                        <span>User access is requested through myAccess or an approved intake process.</span>
                    </div>
                    <div class="access-arrow">→</div>
                    <div class="access-step">
                        <b>2. Approval Evidence</b>
                        <span>Approver, role, business justification, and approval date are captured as evidence.</span>
                    </div>
                    <div class="access-arrow">→</div>
                    <div class="access-step">
                        <b>3. Entitlement Mapping</b>
                        <span>Approved access is mapped to system, role, group, or application entitlement.</span>
                    </div>
                    <div class="access-arrow">→</div>
                    <div class="access-step">
                        <b>4. Review / Certification</b>
                        <span>Periodic access review confirms whether access remains appropriate.</span>
                    </div>
                    <div class="access-arrow">→</div>
                    <div class="access-step">
                        <b>5. Audit Evidence Pack</b>
                        <span>Creates a traceable evidence view showing access, approval, review, and exceptions.</span>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Access Evidence Data Model</h2>
                <table class="exec-table">
                    <tr>
                        <th>Field</th>
                        <th>Purpose</th>
                        <th>Governance Value</th>
                    </tr>
                    <tr>
                        <td><b>User / Account ID</b></td>
                        <td>Identifies the person or account being reviewed.</td>
                        <td>Creates traceability between identity and entitlement.</td>
                    </tr>
                    <tr>
                        <td><b>System / Application</b></td>
                        <td>Identifies the platform where access exists.</td>
                        <td>Supports system-by-system access certification.</td>
                    </tr>
                    <tr>
                        <td><b>Role / Entitlement</b></td>
                        <td>Defines what access the user has.</td>
                        <td>Allows review of least privilege and role appropriateness.</td>
                    </tr>
                    <tr>
                        <td><b>Request / Approval Reference</b></td>
                        <td>Links access to myAccess request, approval, or supporting evidence.</td>
                        <td>Proves that access was authorized before use.</td>
                    </tr>
                    <tr>
                        <td><b>Approver / System Owner</b></td>
                        <td>Identifies who approved or owns the access decision.</td>
                        <td>Creates accountability for access authorization.</td>
                    </tr>
                    <tr>
                        <td><b>Review Status</b></td>
                        <td>Approved, remove, modify, pending, or exception.</td>
                        <td>Supports quarterly access certification and remediation tracking.</td>
                    </tr>
                    <tr>
                        <td><b>Binder Evidence Reference</b></td>
                        <td>Links old paper or Excel evidence to digital governance record.</td>
                        <td>Prevents evidence loss during binder-to-digital transition.</td>
                    </tr>
                    <tr>
                        <td><b>Exception / Remediation</b></td>
                        <td>Captures access issues needing follow-up.</td>
                        <td>Supports audit defensibility and closure tracking.</td>
                    </tr>
                </table>
            </div>

            <section class="access-two-col">
                <div class="card">
                    <h2>Current-State Problem</h2>
                    <ul class="exception-list">
                        <li>Paper binders and Excel trackers can become informal sources of truth.</li>
                        <li>Approval records may exist separately from actual access state.</li>
                        <li>Access review evidence may be difficult to reconstruct during audit.</li>
                        <li>Terminated, transferred, or role-changed users may require manual reconciliation.</li>
                        <li>Reviewer decisions may not always be linked to supporting evidence.</li>
                    </ul>
                </div>

                <div class="card">
                    <h2>COBIT-Chain Value</h2>
                    <ul class="exception-list">
                        <li>Creates an evidence bridge between myAccess, binder records, and access reviews.</li>
                        <li>Supports cryptographic fingerprinting of uploaded access review evidence.</li>
                        <li>Highlights missing approvals, pending reviews, and entitlement exceptions.</li>
                        <li>Gives leadership a clean view of access certification readiness.</li>
                        <li>Prepares access evidence for audit without replacing myAccess.</li>
                    </ul>
                </div>
            </section>

            <div class="card">
                <h2>Access Governance Risk Rules</h2>
                <table class="exec-table">
                    <tr>
                        <th>Condition</th>
                        <th>Risk Level</th>
                        <th>Recommended Governance Action</th>
                    </tr>
                    <tr>
                        <td>Active access with no approval reference</td>
                        <td>High</td>
                        <td>Escalate to system owner and require approval evidence or removal decision.</td>
                    </tr>
                    <tr>
                        <td>User appears in binder but not in myAccess export</td>
                        <td>High</td>
                        <td>Investigate source-of-truth mismatch and document reconciliation outcome.</td>
                    </tr>
                    <tr>
                        <td>Quarterly access review pending past due date</td>
                        <td>Medium</td>
                        <td>Notify reviewer and track overdue certification to closure.</td>
                    </tr>
                    <tr>
                        <td>Privileged entitlement assigned without clear business justification</td>
                        <td>High</td>
                        <td>Require re-approval, role validation, or removal.</td>
                    </tr>
                    <tr>
                        <td>Access approved and review evidence complete</td>
                        <td>Low</td>
                        <td>Retain as audit-ready evidence.</td>
                    </tr>
                </table>
            </div>

            <div class="card">
                <h2>myAccess + Binder + COBIT-Chain Relationship</h2>
                <div class="access-grid">
                    <div class="access-mini">
                        <b>myAccess</b>
                        <p>System of record for access requests, approvals, entitlement workflow, and access governance ownership.</p>
                    </div>
                    <div class="access-mini">
                        <b>Binder / Excel Evidence</b>
                        <p>Legacy evidence source that may contain physical forms, signatures, manual trackers, or historical review records.</p>
                    </div>
                    <div class="access-mini">
                        <b>COBIT-Chain</b>
                        <p>Governance assurance layer that links evidence, verifies completeness, detects exceptions, and prepares audit-ready access packs.</p>
                    </div>
                </div>
            </div>

            <div class="note">
                <b>Next build step:</b> add a separate <b>access_reviews.csv</b> storage file for access governance records.
                This will allow Access Governance to save real review evidence without touching the Manufacturing/Manufacturing Core evidence chain.
            </div>
            {% elif page.route == "/audit-capa" %}
            <!-- AUDIT_CAPA_V1_ACTIVE -->
            <div class="card status-card-warning">
                <h2>⚠ Audit/CAPA v1</h2>
                <p><b>Purpose:</b> create a governed evidence chain from audit finding to deviation, CAPA, remediation proof, and effectiveness-check readiness.</p>
                <p>This page is currently a controlled enterprise module shell. It does not change the Manufacturing/Manufacturing Core dashboard, SOP comparison engine, or existing evidence logs.</p>
            </div>

            <section class="audit-grid">
                <div class="audit-card">
                    <div class="audit-label">Audit Finding</div>
                    <h3>Finding-to-Evidence Traceability</h3>
                    <p>Links each audit finding or observation to supporting evidence, responsible owner, system/process area, and remediation status.</p>
                    <span class="audit-badge">Audit traceability</span>
                </div>

                <div class="audit-card">
                    <div class="audit-label">CAPA Control</div>
                    <h3>CAPA Evidence Chain</h3>
                    <p>Connects CAPA actions to objective evidence, approval status, due dates, closure proof, and residual risk indicators.</p>
                    <span class="audit-badge">Remediation proof</span>
                </div>

                <div class="audit-card">
                    <div class="audit-label">Advanced Feature</div>
                    <h3>Effectiveness Readiness Gate</h3>
                    <p>Pre-validates whether linked evidence is complete before an effectiveness check is started, reducing avoidable review failures.</p>
                    <span class="audit-badge">Pre-validation</span>
                </div>
            </section>

            <div class="card">
                <h2>Audit/CAPA Governance Control Flow</h2>
                <div class="audit-flow">
                    <div class="audit-step">
                        <b>1. Audit Finding</b>
                        <span>Capture finding, source audit, process area, severity, owner, and required response.</span>
                    </div>
                    <div class="audit-arrow">→</div>
                    <div class="audit-step">
                        <b>2. Deviation / Issue Link</b>
                        <span>Link the finding to deviation, NCR, incident, or quality event where applicable.</span>
                    </div>
                    <div class="audit-arrow">→</div>
                    <div class="audit-step">
                        <b>3. CAPA Action</b>
                        <span>Define corrective/preventive actions, owners, target dates, and evidence expectations.</span>
                    </div>
                    <div class="audit-arrow">→</div>
                    <div class="audit-step">
                        <b>4. Remediation Evidence</b>
                        <span>Attach proof such as screenshots, reports, approvals, training records, system updates, or SOP revisions.</span>
                    </div>
                    <div class="audit-arrow">→</div>
                    <div class="audit-step">
                        <b>5. Effectiveness Readiness</b>
                        <span>Check whether all linked dependencies are complete before effectiveness review or audit reliance.</span>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Audit/CAPA Data Model</h2>
                <table class="exec-table">
                    <tr>
                        <th>Field</th>
                        <th>Purpose</th>
                        <th>Governance Value</th>
                    </tr>
                    <tr>
                        <td><b>Audit Finding ID</b></td>
                        <td>Unique finding, observation, NCR, or audit reference.</td>
                        <td>Creates traceability from issue to remediation evidence.</td>
                    </tr>
                    <tr>
                        <td><b>Finding Source</b></td>
                        <td>Internal audit, external audit, QA review, regulatory inspection, or process review.</td>
                        <td>Supports audit response prioritization and reporting.</td>
                    </tr>
                    <tr>
                        <td><b>Process / System Area</b></td>
                        <td>Identifies the affected process, system, equipment, SOP, or department.</td>
                        <td>Links CAPA to impacted operational area.</td>
                    </tr>
                    <tr>
                        <td><b>Deviation / CAPA Reference</b></td>
                        <td>Links finding to deviation, CAPA, NCR, or remediation workflow.</td>
                        <td>Prevents orphan audit findings with no controlled response.</td>
                    </tr>
                    <tr>
                        <td><b>CAPA Owner</b></td>
                        <td>Person accountable for action and closure.</td>
                        <td>Creates ownership and escalation accountability.</td>
                    </tr>
                    <tr>
                        <td><b>Required Evidence</b></td>
                        <td>Defines what proof is required before closure or effectiveness review.</td>
                        <td>Reduces subjective closure decisions.</td>
                    </tr>
                    <tr>
                        <td><b>Evidence Status</b></td>
                        <td>Missing, partial, uploaded, approved, rejected, or verified.</td>
                        <td>Shows whether remediation can be relied upon.</td>
                    </tr>
                    <tr>
                        <td><b>Effectiveness Status</b></td>
                        <td>Not started, blocked, ready, in review, passed, or failed.</td>
                        <td>Supports pre-validation before effectiveness check execution.</td>
                    </tr>
                </table>
            </div>

            <section class="audit-two-col">
                <div class="card">
                    <h2>Organizational Pain Points</h2>
                    <ul class="exception-list">
                        <li>Audit findings are tracked separately from remediation evidence.</li>
                        <li>CAPA closure sometimes depends on manual reconstruction of proof.</li>
                        <li>Effectiveness checks can fail because linked actions were not actually ready.</li>
                        <li>Owners, due dates, and evidence status may be scattered across systems.</li>
                        <li>Repeated findings are difficult to connect across SOP, access, shift, or manufacturing records.</li>
                        <li>Leadership sees CAPA status late, not before risk becomes visible to audit.</li>
                    </ul>
                </div>

                <div class="card">
                    <h2>COBIT-Chain Solution</h2>
                    <ul class="exception-list">
                        <li>Creates a finding-to-CAPA-to-evidence chain of custody.</li>
                        <li>Shows whether remediation evidence is complete before closure.</li>
                        <li>Pre-validates effectiveness-check readiness before review starts.</li>
                        <li>Highlights blocked CAPAs, overdue evidence, missing owners, and repeated failure themes.</li>
                        <li>Links CAPA issues back to SOP, manufacturing, access, or shift assurance modules.</li>
                        <li>Prepares an audit-ready remediation evidence pack.</li>
                    </ul>
                </div>
            </section>

            <div class="card">
                <h2>Advanced Feature: Effectiveness Readiness Gate</h2>
                <p>
                    This feature is designed to prevent premature effectiveness checks. Before a CAPA is marked ready,
                    COBIT-Chain checks whether prerequisite evidence, linked actions, approvals, training updates,
                    SOP revisions, and system corrections are complete.
                </p>

                <table class="exec-table">
                    <tr>
                        <th>Gate Condition</th>
                        <th>Risk Signal</th>
                        <th>Governance Action</th>
                    </tr>
                    <tr>
                        <td>CAPA action marked complete but required evidence missing</td>
                        <td>High</td>
                        <td>Block effectiveness readiness until evidence is uploaded and reviewed.</td>
                    </tr>
                    <tr>
                        <td>SOP update required but SOP Governance gap remains open</td>
                        <td>High</td>
                        <td>Link CAPA to SOP Governance and prevent premature closure.</td>
                    </tr>
                    <tr>
                        <td>Training required but training evidence missing</td>
                        <td>Medium</td>
                        <td>Require training proof before effectiveness check starts.</td>
                    </tr>
                    <tr>
                        <td>System change required but change evidence missing</td>
                        <td>High</td>
                        <td>Link to change control evidence or system owner signoff.</td>
                    </tr>
                    <tr>
                        <td>All dependencies complete and evidence verified</td>
                        <td>Low</td>
                        <td>Mark effectiveness check as ready for review.</td>
                    </tr>
                </table>
            </div>

            <div class="card">
                <h2>CAPA Failure-Risk Signals</h2>
                <section class="audit-grid">
                    <div class="audit-mini">
                        <b>Missing Evidence Signal</b>
                        <p>CAPA is approaching closure but the required proof is missing, partial, or not linked.</p>
                    </div>
                    <div class="audit-mini">
                        <b>Dependency Signal</b>
                        <p>CAPA depends on SOP update, training, access correction, equipment fix, or system change that remains incomplete.</p>
                    </div>
                    <div class="audit-mini">
                        <b>Repeat Finding Signal</b>
                        <p>Same issue type appears across multiple audits, suggesting weak root cause or ineffective remediation.</p>
                    </div>
                    <div class="audit-mini">
                        <b>Owner Risk Signal</b>
                        <p>CAPA has no clear owner, overdue owner action, or unclear QA/system owner accountability.</p>
                    </div>
                    <div class="audit-mini">
                        <b>Effectiveness Blocker Signal</b>
                        <p>Effectiveness review should not start because key evidence or dependencies are unresolved.</p>
                    </div>
                    <div class="audit-mini">
                        <b>Audit Pack Readiness Signal</b>
                        <p>Shows whether finding, root cause, action, evidence, approval, and effectiveness proof are complete.</p>
                    </div>
                </section>
            </div>

            <div class="card">
                <h2>Audit/CAPA Risk Rules</h2>
                <table class="exec-table">
                    <tr>
                        <th>Condition</th>
                        <th>Risk Level</th>
                        <th>Recommended Governance Action</th>
                    </tr>
                    <tr>
                        <td>Audit finding has no linked owner or remediation action</td>
                        <td>High</td>
                        <td>Escalate to QA/process owner and require controlled response.</td>
                    </tr>
                    <tr>
                        <td>CAPA action is closed but evidence is missing</td>
                        <td>High</td>
                        <td>Reopen or block closure until objective evidence is attached.</td>
                    </tr>
                    <tr>
                        <td>Effectiveness check started while dependencies remain incomplete</td>
                        <td>High</td>
                        <td>Pause effectiveness review and complete prerequisite evidence.</td>
                    </tr>
                    <tr>
                        <td>Repeated audit finding appears across process areas</td>
                        <td>Medium</td>
                        <td>Review root cause quality and consider systemic CAPA.</td>
                    </tr>
                    <tr>
                        <td>Finding, CAPA, evidence, approval, and effectiveness proof are complete</td>
                        <td>Low</td>
                        <td>Retain as audit-ready remediation evidence pack.</td>
                    </tr>
                </table>
            </div>

            <div class="card">
                <h2>Audit/CAPA Relationship Model</h2>
                <div class="audit-grid">
                    <div class="audit-mini">
                        <b>Audit / Observation</b>
                        <p>Source of finding, weakness, nonconformance, inspection observation, or internal review issue.</p>
                    </div>
                    <div class="audit-mini">
                        <b>Deviation / CAPA</b>
                        <p>Controlled quality response, corrective action, preventive action, and owner accountability.</p>
                    </div>
                    <div class="audit-mini">
                        <b>COBIT-Chain</b>
                        <p>Governance assurance layer that validates whether evidence, dependencies, and effectiveness readiness are complete.</p>
                    </div>
                </div>
            </div>

            <div class="note">
                <b>Next build step:</b> add a separate <b>audit_capa_register.csv</b> storage file for audit findings, CAPA records,
                remediation proof, and effectiveness readiness scoring. This will keep Audit/CAPA records separate from Manufacturing/Manufacturing Core logs.
            </div>
            {% elif page.route == "/clinical-trial-integrity" %}
            <!-- CLINICAL_TRIAL_INTEGRITY_V1_ACTIVE -->
            <div class="card status-card-warning">
                <h2>⚠ Clinical Trial Integrity v1</h2>
                <p><b>Purpose:</b> create a governance assurance layer for clinical trial evidence integrity, protocol-to-evidence traceability, ALCOA+ readiness, deviation linkage, and inspection preparedness.</p>
                <p>This page is currently a controlled enterprise module shell. It does not change Manufacturing/Manufacturing Core, SOP comparison, Access, Shift, or Audit/CAPA records.</p>
            </div>

            <section class="trial-grid">
                <div class="trial-card">
                    <div class="trial-label">Trial Evidence</div>
                    <h3>Protocol-to-Evidence Traceability</h3>
                    <p>Links protocol requirements, visit activities, consent records, monitoring evidence, deviations, and TMF artifacts into a governed evidence chain.</p>
                    <span class="trial-badge">Traceability layer</span>
                </div>

                <div class="trial-card">
                    <div class="trial-label">Data Integrity</div>
                    <h3>ALCOA+ Readiness</h3>
                    <p>Assesses whether trial evidence is attributable, legible, contemporaneous, original, accurate, complete, consistent, enduring, and available.</p>
                    <span class="trial-badge">Data integrity</span>
                </div>

                <div class="trial-card">
                    <div class="trial-label">Advanced Feature</div>
                    <h3>Protocol-to-Evidence Integrity Graph</h3>
                    <p>Future differentiator: map every protocol obligation to the evidence proving it was performed, reviewed, approved, and retained.</p>
                    <span class="trial-badge">Evidence graph</span>
                </div>
            </section>

            <div class="card">
                <h2>Clinical Trial Integrity Control Flow</h2>
                <div class="trial-flow">
                    <div class="trial-step">
                        <b>1. Protocol Requirement</b>
                        <span>Identify required study activity, visit, consent step, data capture Acquired Site, safety review, or monitoring obligation.</span>
                    </div>
                    <div class="trial-arrow">→</div>
                    <div class="trial-step">
                        <b>2. Evidence Capture</b>
                        <span>Link source document, eConsent, monitoring note, TMF artifact, data export, or system record.</span>
                    </div>
                    <div class="trial-arrow">→</div>
                    <div class="trial-step">
                        <b>3. Integrity Check</b>
                        <span>Confirm evidence completeness, ownership, timestamp, hash, version, and review status.</span>
                    </div>
                    <div class="trial-arrow">→</div>
                    <div class="trial-step">
                        <b>4. Deviation Linkage</b>
                        <span>Identify missing, late, inconsistent, or noncompliant evidence and link it to deviation/CAPA where needed.</span>
                    </div>
                    <div class="trial-arrow">→</div>
                    <div class="trial-step">
                        <b>5. Inspection-Ready Pack</b>
                        <span>Produce a defensible evidence pack showing requirement, proof, reviewer, exception, and remediation status.</span>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>Clinical Trial Evidence Data Model</h2>
                <table class="exec-table">
                    <tr>
                        <th>Field</th>
                        <th>Purpose</th>
                        <th>Governance Value</th>
                    </tr>
                    <tr>
                        <td><b>Study / Protocol ID</b></td>
                        <td>Identifies the trial, protocol, amendment, or study version.</td>
                        <td>Links evidence to the correct approved clinical requirement.</td>
                    </tr>
                    <tr>
                        <td><b>Site / Subject / Visit Reference</b></td>
                        <td>Identifies where and when the trial activity occurred.</td>
                        <td>Supports traceability across site, subject, visit, and evidence.</td>
                    </tr>
                    <tr>
                        <td><b>Evidence Type</b></td>
                        <td>eConsent, source data, monitoring report, lab data, TMF artifact, safety record, or data transfer file.</td>
                        <td>Classifies evidence for inspection readiness.</td>
                    </tr>
                    <tr>
                        <td><b>Protocol Obligation</b></td>
                        <td>Defines what the protocol or study plan required.</td>
                        <td>Creates the baseline for control-to-evidence verification.</td>
                    </tr>
                    <tr>
                        <td><b>Evidence Status</b></td>
                        <td>Missing, uploaded, verified, rejected, late, incomplete, or superseded.</td>
                        <td>Shows whether evidence can support inspection reliance.</td>
                    </tr>
                    <tr>
                        <td><b>ALCOA+ Status</b></td>
                        <td>Assesses evidence against data integrity principles.</td>
                        <td>Provides defensible data integrity readiness scoring.</td>
                    </tr>
                    <tr>
                        <td><b>Deviation / CAPA Link</b></td>
                        <td>Links missing or defective evidence to controlled remediation.</td>
                        <td>Prevents unresolved trial evidence gaps from being hidden.</td>
                    </tr>
                    <tr>
                        <td><b>Reviewer / Approver</b></td>
                        <td>Identifies who verified or approved the evidence.</td>
                        <td>Creates accountability and review traceability.</td>
                    </tr>
                </table>
            </div>

            <section class="trial-two-col">
                <div class="card">
                    <h2>Organizational Pain Points</h2>
                    <ul class="exception-list">
                        <li>Clinical evidence is spread across eTMF, EDC, eConsent, spreadsheets, emails, vendor files, and monitoring reports.</li>
                        <li>Teams often reconstruct evidence late during audit or inspection preparation.</li>
                        <li>Protocol obligations may not be clearly linked to proof that the activity was completed.</li>
                        <li>Evidence may exist but lack clear version, timestamp, owner, or review status.</li>
                        <li>Deviation and CAPA records may not clearly show the evidence gap that triggered them.</li>
                        <li>Inspection readiness depends on manual reconciliation across fragmented systems.</li>
                    </ul>
                </div>

                <div class="card">
                    <h2>COBIT-Chain Solution</h2>
                    <ul class="exception-list">
                        <li>Creates a governance map from protocol requirement to verified evidence.</li>
                        <li>Uses evidence hashing and status checks to support tamper-aware evidence integrity.</li>
                        <li>Highlights missing, late, incomplete, or inconsistent trial evidence.</li>
                        <li>Links evidence gaps to deviation/CAPA readiness.</li>
                        <li>Supports ALCOA+ readiness scoring for trial records.</li>
                        <li>Produces an inspection-ready evidence pack with requirement, proof, owner, reviewer, and exception status.</li>
                    </ul>
                </div>
            </section>

            <div class="card">
                <h2>Advanced Feature: Protocol-to-Evidence Integrity Graph</h2>
                <p>
                    This feature is designed as a future differentiator for COBIT-Chain. Instead of only storing evidence,
                    it models the relationship between trial obligations and the evidence proving those obligations were met.
                </p>

                <table class="exec-table">
                    <tr>
                        <th>Graph Node</th>
                        <th>Example</th>
                        <th>Governance Purpose</th>
                    </tr>
                    <tr>
                        <td><b>Protocol Obligation</b></td>
                        <td>Informed consent completed before trial procedure.</td>
                        <td>Defines what must be proven.</td>
                    </tr>
                    <tr>
                        <td><b>Evidence Artifact</b></td>
                        <td>Signed eConsent record, timestamp, version, and audit trail.</td>
                        <td>Shows proof of performance.</td>
                    </tr>
                    <tr>
                        <td><b>Review Event</b></td>
                        <td>CRA/QA/site monitor review and acceptance.</td>
                        <td>Shows independent verification.</td>
                    </tr>
                    <tr>
                        <td><b>Exception</b></td>
                        <td>Missing date, late consent, wrong version, incomplete signature, or unsupported correction.</td>
                        <td>Identifies inspection risk.</td>
                    </tr>
                    <tr>
                        <td><b>Remediation Link</b></td>
                        <td>Deviation, CAPA, retraining, or evidence correction.</td>
                        <td>Shows controlled response and closure pathway.</td>
                    </tr>
                </table>
            </div>

            <div class="card">
                <h2>Clinical Trial Risk Rules</h2>
                <table class="exec-table">
                    <tr>
                        <th>Condition</th>
                        <th>Risk Level</th>
                        <th>Recommended Governance Action</th>
                    </tr>
                    <tr>
                        <td>Protocol-required evidence is missing</td>
                        <td>High</td>
                        <td>Flag as inspection risk and link to deviation or remediation owner.</td>
                    </tr>
                    <tr>
                        <td>Consent evidence exists but version, date, or signature is unclear</td>
                        <td>High</td>
                        <td>Escalate for consent evidence review and site/QA assessment.</td>
                    </tr>
                    <tr>
                        <td>Evidence exists but no reviewer or approval is recorded</td>
                        <td>Medium</td>
                        <td>Require reviewer verification before treating as inspection-ready.</td>
                    </tr>
                    <tr>
                        <td>Data transfer evidence does not reconcile with expected record count</td>
                        <td>High</td>
                        <td>Block reliance until reconciliation is completed and documented.</td>
                    </tr>
                    <tr>
                        <td>Protocol obligation, evidence, reviewer, and exception status are complete</td>
                        <td>Low</td>
                        <td>Retain as inspection-ready evidence.</td>
                    </tr>
                </table>
            </div>

            <div class="card">
                <h2>Clinical Trial Integrity Domains</h2>
                <section class="trial-grid">
                    <div class="trial-mini">
                        <b>eConsent Integrity</b>
                        <p>Consent version, signature, timestamp, subject/site linkage, and audit-trail completeness.</p>
                    </div>
                    <div class="trial-mini">
                        <b>Source Data Verification</b>
                        <p>Traceability between source record, EDC entry, monitoring review, and issue resolution.</p>
                    </div>
                    <div class="trial-mini">
                        <b>TMF Completeness</b>
                        <p>Trial master file artifact completeness, version status, owner, and review readiness.</p>
                    </div>
                    <div class="trial-mini">
                        <b>Protocol Deviation Linkage</b>
                        <p>Connection between evidence gaps, deviation record, CAPA/remediation, and closure proof.</p>
                    </div>
                    <div class="trial-mini">
                        <b>Data Transfer Reconciliation</b>
                        <p>Vendor file, lab data, safety data, or system export count reconciliation and exception handling.</p>
                    </div>
                    <div class="trial-mini">
                        <b>Inspection Readiness</b>
                        <p>Evidence pack showing requirement, proof, reviewer, exception status, and governance decision.</p>
                    </div>
                </section>
            </div>

            <div class="note">
                <b>Next build step:</b> add a separate <b>clinical_trial_evidence.csv</b> storage file for protocol obligations,
                evidence artifacts, ALCOA+ readiness, deviation linkage, and inspection-readiness scoring. This will keep clinical records separate from Manufacturing/Manufacturing Core logs.
            </div>
            {% endif %}

            <div class="card">
                <h2>Current Manufacturing Dashboard</h2>
                <p>The existing Manufacturing Core Manufacturing Assurance dashboard remains available here:</p>
                <p><a href="/" style="font-weight:900;color:#2563eb;">Open Manufacturing Dashboard</a></p>
            </div>
        </section>
    </section>
</main>
</body>
</html>
    """
    return render_template_string(
        html,
        page=page,
        pages=ENTERPRISE_PAGES,
        metrics=metrics
    )


# ============================================================
# SOP GOVERNANCE V2 ACTIVE
# Dual SOP Harmonization + Reality Alignment Engine
# ============================================================

SOP_COMPARISON_FILE = "sop_comparisons.csv"


def prepare_sop_comparisons():
    df = load_csv(SOP_COMPARISON_FILE)
    return ensure_cols(df, [
        "comparison_id",
        "timestamp",
        "process_area",
        "reviewer",
        "sop_owner",
        "global_filename",
        "local_filename",
        "global_hash",
        "local_hash",
        "global_control_dna_score",
        "local_control_dna_score",
        "maturity_gap",
        "gap_count",
        "high_risk_gap_count",
        "outdated_sop_signals",
        "technology_gap_signals",
        "review_triggers",
        "recommended_decision",
        "previous_hash",
        "record_hash"
    ])


def sop_extract_text(upload):
    import zipfile
    import xml.etree.ElementTree as ET

    if not upload or not upload.filename:
        return {
            "filename": "",
            "bytes": b"",
            "hash": "",
            "text": "",
            "warning": "No file uploaded."
        }

    filename = clean(upload.filename)
    data = upload.read()
    file_hash = compute_hash(data)
    lower_name = filename.lower()
    warning = ""

    try:
        if lower_name.endswith((".txt", ".md", ".csv")):
            text_value = data.decode("utf-8", errors="ignore")

        elif lower_name.endswith((".xlsx", ".xls")):
            sheets = pd.read_excel(io.BytesIO(data), sheet_name=None, engine="openpyxl")
            parts = []
            for sheet_name, df in sheets.items():
                parts.append(f"Sheet: {sheet_name}")
                parts.append(" ".join([str(c) for c in df.columns]))
                parts.append(df.fillna("").astype(str).to_string(index=False))
            text_value = "\n".join(parts)

        elif lower_name.endswith(".docx"):
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                xml_content = z.read("word/document.xml")
            root = ET.fromstring(xml_content)
            text_nodes = []
            for node in root.iter():
                if node.text:
                    text_nodes.append(node.text)
            text_value = " ".join(text_nodes)

        else:
            text_value = ""
            warning = "Unsupported file type for text extraction. Use .txt, .csv, .xlsx, or .docx for this version."

    except Exception as e:
        text_value = ""
        warning = f"Text extraction error: {e}"

    return {
        "filename": filename,
        "bytes": data,
        "hash": file_hash,
        "text": clean(text_value),
        "warning": warning
    }


def sop_theme_library():
    return [
        {
            "theme": "Approval workflow",
            "category": "Approval control",
            "keywords": ["approval", "approve", "approved", "approver", "authorization", "authorisation", "sign-off", "signoff", "signature"],
            "risk": "HIGH",
            "cobit": "DSS06, MEA02",
            "recommendation": "Define explicit approval ownership, approval evidence, and escalation where approval is missing."
        },
        {
            "theme": "Audit trail",
            "category": "Evidence integrity",
            "keywords": ["audit trail", "audit log", "system log", "traceability", "record history", "event log"],
            "risk": "HIGH",
            "cobit": "MEA02, DSS06, MEA03",
            "recommendation": "Require system-generated audit trail or controlled equivalent evidence."
        },
        {
            "theme": "Electronic workflow / system control",
            "category": "Technology maturity",
            "keywords": ["system", "workflow", "electronic", "automated", "digital", "application", "platform", "service now", "servicenow", "myaccess"],
            "risk": "MEDIUM",
            "cobit": "BAI06, DSS01, DSS06",
            "recommendation": "Assess whether manual steps should be harmonized into the mature system-enabled process."
        },
        {
            "theme": "Manual paper or Excel dependency",
            "category": "Manual process weakness",
            "keywords": ["manual", "paper", "binder", "spreadsheet", "excel", "email approval", "printed", "wet signature"],
            "risk": "MEDIUM",
            "cobit": "DSS06, APO12, MEA02",
            "recommendation": "Reduce manual dependency or add compensating controls, ownership, evidence retention, and review frequency."
        },
        {
            "theme": "Deviation / CAPA linkage",
            "category": "Quality event linkage",
            "keywords": ["deviation", "capa", "corrective action", "preventive action", "investigation", "effectiveness check"],
            "risk": "HIGH",
            "cobit": "MEA02, MEA03, DSS06",
            "recommendation": "Link SOP exceptions to deviation/CAPA process where quality impact or repeated failure exists."
        },
        {
            "theme": "Training requirement",
            "category": "People and training",
            "keywords": ["training", "trained", "qualification", "competency", "read and understand", "curriculum"],
            "risk": "MEDIUM",
            "cobit": "APO07, DSS06",
            "recommendation": "Add training or retraining requirement where SOP changes affect execution responsibility."
        },
        {
            "theme": "Role and responsibility ownership",
            "category": "Accountability",
            "keywords": ["owner", "responsible", "accountable", "qa", "system owner", "process owner", "technician", "reviewer"],
            "risk": "MEDIUM",
            "cobit": "APO01, APO07, DSS06",
            "recommendation": "Clarify ownership, reviewer role, system owner responsibility, and escalation chain."
        },
        {
            "theme": "Periodic review frequency",
            "category": "Review control",
            "keywords": ["periodic review", "quarterly", "monthly", "annually", "annual", "review frequency", "recertification", "certification"],
            "risk": "MEDIUM",
            "cobit": "MEA01, MEA02",
            "recommendation": "Define review frequency and evidence required to prove review completion."
        },
        {
            "theme": "Access governance",
            "category": "Access control",
            "keywords": ["access", "entitlement", "user access", "permission", "role", "privilege", "segregation of duties", "sod"],
            "risk": "HIGH",
            "cobit": "DSS05, DSS06, MEA02",
            "recommendation": "Link SOP control to access approval, review, entitlement evidence, and segregation of duties."
        },
        {
            "theme": "Data integrity / ALCOA+",
            "category": "Data integrity",
            "keywords": ["data integrity", "alcoa", "accurate", "legible", "contemporaneous", "original", "attributable", "complete", "consistent", "enduring", "available"],
            "risk": "HIGH",
            "cobit": "MEA02, MEA03, DSS06",
            "recommendation": "Define data integrity requirements and evidence retention expectations."
        },
        {
            "theme": "Backup / recovery evidence",
            "category": "Operational resilience",
            "keywords": ["backup", "restore", "recovery", "disaster recovery", "archive", "retention"],
            "risk": "MEDIUM",
            "cobit": "DSS04, DSS01, MEA02",
            "recommendation": "Add backup, recovery, retention, and restoration evidence expectations where relevant."
        },
        {
            "theme": "Change control",
            "category": "Change governance",
            "keywords": ["change control", "change request", "configuration change", "system change", "validated change", "impact assessment"],
            "risk": "HIGH",
            "cobit": "BAI06, BAI07, MEA03",
            "recommendation": "Connect SOP changes or process changes to formal change control and impact assessment."
        },
        {
            "theme": "Escalation path",
            "category": "Escalation governance",
            "keywords": ["escalation", "escalate", "notify", "urgent", "critical", "manager", "qa notification"],
            "risk": "MEDIUM",
            "cobit": "DSS02, DSS06, APO12",
            "recommendation": "Define escalation threshold, notification path, and evidence required for closure."
        }
    ]


def sop_contains(text_value, keywords):
    haystack = clean(text_value).lower()
    return any(k.lower() in haystack for k in keywords)


def sop_control_dna(text_value):
    dimensions = [
        ("Approval Control", ["approval", "approved", "approver", "sign-off", "signature"]),
        ("Evidence Integrity", ["evidence", "record", "audit trail", "traceability", "log"]),
        ("Technology Enablement", ["system", "workflow", "electronic", "automated", "digital"]),
        ("Manual Dependency", ["manual", "paper", "binder", "excel", "spreadsheet"]),
        ("Data Integrity", ["data integrity", "alcoa", "accurate", "complete", "available"]),
        ("Review Frequency", ["periodic review", "quarterly", "monthly", "annual", "review frequency"]),
        ("Deviation/CAPA Linkage", ["deviation", "capa", "investigation", "effectiveness check"]),
        ("Access Governance", ["access", "entitlement", "permission", "role", "segregation"]),
        ("Training Control", ["training", "qualified", "competency", "curriculum"]),
        ("Change Control", ["change control", "impact assessment", "configuration change"])
    ]

    covered = []
    missing = []

    for name, keywords in dimensions:
        if sop_contains(text_value, keywords):
            covered.append(name)
        else:
            missing.append(name)

    score = round((len(covered) / len(dimensions)) * 100, 2) if dimensions else 0

    return {
        "score": score,
        "covered": covered,
        "missing": missing,
        "dimension_count": len(dimensions),
        "covered_count": len(covered)
    }


def run_sop_comparison(req):
    timestamp = datetime.datetime.utcnow().isoformat()

    process_area = clean(req.form.get("process_area"))
    reviewer = clean(req.form.get("reviewer"))
    sop_owner = clean(req.form.get("sop_owner"))
    reality_notes = clean(req.form.get("reality_notes"))

    global_doc = sop_extract_text(req.files.get("global_sop"))
    local_doc = sop_extract_text(req.files.get("local_sop"))

    if not global_doc["filename"] or not local_doc["filename"]:
        return {
            "error": "Please upload both the Enterprise Pharma/GPOS SOP and the Acquired Site/Local SOP."
        }

    if not global_doc["text"] or not local_doc["text"]:
        return {
            "error": "One or both SOP files could not be read. Use .txt, .csv, .xlsx, or .docx for this version."
        }

    global_text = global_doc["text"]
    local_text = local_doc["text"]
    reality_text = reality_notes

    themes = sop_theme_library()
    gaps = []
    pain_point_solutions = []

    for theme in themes:
        g_present = sop_contains(global_text, theme["keywords"])
        l_present = sop_contains(local_text, theme["keywords"])
        r_present = sop_contains(reality_text, theme["keywords"])

        if g_present and not l_present:
            gaps.append({
                "gap_type": "Enterprise Pharma/GPOS control missing in Acquired Site SOP",
                "theme": theme["theme"],
                "category": theme["category"],
                "risk": theme["risk"],
                "evidence": "Control theme appears in the mature/global SOP but is missing from the local/manual SOP.",
                "cobit": theme["cobit"],
                "recommendation": "Adopt or harmonize the Enterprise Pharma/GPOS control into the Acquired Site/local SOP. " + theme["recommendation"]
            })

        if r_present and not l_present:
            gaps.append({
                "gap_type": "Outdated SOP / reality mismatch signal",
                "theme": theme["theme"],
                "category": theme["category"],
                "risk": "HIGH" if theme["risk"] == "HIGH" else "MEDIUM",
                "evidence": "Operational reality notes mention this control theme, but the local SOP does not. This suggests the SOP may be outdated or incomplete.",
                "cobit": theme["cobit"],
                "recommendation": "Trigger SOP review. Determine whether the SOP should be updated to reflect the real process or whether the process is being executed outside procedure."
            })

        if l_present and not g_present:
            gaps.append({
                "gap_type": "Local-specific control not visible in Enterprise Pharma/GPOS SOP",
                "theme": theme["theme"],
                "category": theme["category"],
                "risk": "MEDIUM",
                "evidence": "Acquired Site/local SOP includes a control theme that is not detected in the Enterprise Pharma/GPOS SOP.",
                "cobit": theme["cobit"],
                "recommendation": "Review whether this is a legitimate site-specific control, a legacy requirement, or a candidate for harmonization."
            })

    tech_keywords = ["system", "workflow", "electronic", "automated", "digital", "audit trail", "platform"]
    manual_keywords = ["manual", "paper", "binder", "excel", "spreadsheet", "email approval", "printed"]

    global_tech = sop_contains(global_text, tech_keywords)
    local_manual = sop_contains(local_text, manual_keywords)

    if global_tech and local_manual:
        gaps.append({
            "gap_type": "Technology maturity gap",
            "theme": "Manual Acquired Site process vs mature Enterprise Pharma system-enabled process",
            "category": "Technology maturity",
            "risk": "HIGH",
            "evidence": "Enterprise Pharma/GPOS appears to reference system-enabled or digital control, while Acquired Site/local SOP appears to rely on manual, paper, Excel, or binder-based execution.",
            "cobit": "BAI06, DSS06, MEA02, APO12",
            "recommendation": "Assess whether Acquired Site should adopt the Enterprise Pharma system-enabled process, retain local process with compensating controls, or follow a phased harmonization plan."
        })

    global_dna = sop_control_dna(global_text)
    local_dna = sop_control_dna(local_text)
    maturity_gap = round(global_dna["score"] - local_dna["score"], 2)

    high_risk_count = len([g for g in gaps if g["risk"] == "HIGH"])
    outdated_count = len([g for g in gaps if "Outdated SOP" in g["gap_type"]])
    technology_gap_count = len([g for g in gaps if "Technology maturity" in g["gap_type"]])

    review_triggers = []

    reality_lower = reality_text.lower()
    combined_lower = (global_text + " " + local_text + " " + reality_text + " " + process_area).lower()

    if outdated_count > 0:
        review_triggers.append("Evidence mismatch-triggered SOP review")
    if technology_gap_count > 0 or "system change" in combined_lower or "technology" in combined_lower:
        review_triggers.append("System / technology change-triggered SOP review")
    if "audit" in reality_lower or "observation" in reality_lower or "finding" in reality_lower:
        review_triggers.append("Audit-triggered SOP review")
    if "recurring" in reality_lower or "repeated" in reality_lower or "repeat" in reality_lower:
        review_triggers.append("Recurring issue-triggered SOP review")
    if "acquisition" in combined_lower or "acquired" in combined_lower or "harmonization" in combined_lower or "Enterprise Pharma" in combined_lower or "Acquired Site" in combined_lower or "gpos" in combined_lower:
        review_triggers.append("M&A / harmonization-triggered SOP review")
    if "new product" in combined_lower or "expansion" in combined_lower or "business expansion" in combined_lower:
        review_triggers.append("Business expansion or new product-triggered SOP review")

    if not review_triggers and gaps:
        review_triggers.append("Governance gap-triggered SOP review")
    if not review_triggers:
        review_triggers.append("No major SOP review trigger detected from current comparison.")

    if high_risk_count >= 3 or technology_gap_count > 0:
        recommended_decision = "Adopt Enterprise Pharma/GPOS target-state controls or create a phased harmonization plan with QA/SOP owner review."
    elif outdated_count > 0:
        recommended_decision = "Update Acquired Site/local SOP to reflect validated operational reality, or correct the process if the reality is noncompliant."
    elif gaps:
        recommended_decision = "Review identified gaps and decide whether to harmonize, retain local controls, or document compensating controls."
    else:
        recommended_decision = "No major gap detected. Retain as aligned, but document reviewer decision and comparison evidence."

    pain_point_solutions = [
        {
            "pain_point": "Manual SOP comparison takes too long after acquisition.",
            "solution": "COBIT-Chain creates a structured gap table between Enterprise Pharma/GPOS and Acquired Site/local SOPs."
        },
        {
            "pain_point": "Teams cannot tell whether the SOP is wrong or the process is wrong.",
            "solution": "The SOP Obsolescence Signal separates outdated documentation from actual process noncompliance."
        },
        {
            "pain_point": "Mature global process and local manual process are hard to reconcile.",
            "solution": "Technology Maturity Gap logic highlights where Acquired Site manual controls differ from Enterprise Pharma system-enabled controls."
        },
        {
            "pain_point": "Audit evidence is reconstructed late and manually.",
            "solution": "The comparison record is stored in sop_comparisons.csv with file hashes and a record hash for audit traceability."
        },
        {
            "pain_point": "SOP harmonization recommendations are subjective.",
            "solution": "Control DNA Diff gives an objective control coverage score for each SOP and shows the maturity gap."
        },
        {
            "pain_point": "Review triggers are not always clear.",
            "solution": "The engine identifies audit-triggered, technology-triggered, M&A-triggered, recurring-issue, and evidence-mismatch review triggers."
        }
    ]

    comparison_id = "SOP-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    result = {
        "error": "",
        "comparison_id": comparison_id,
        "timestamp": timestamp,
        "process_area": process_area,
        "reviewer": reviewer,
        "sop_owner": sop_owner,
        "global_filename": global_doc["filename"],
        "local_filename": local_doc["filename"],
        "global_hash": global_doc["hash"],
        "local_hash": local_doc["hash"],
        "global_warning": global_doc["warning"],
        "local_warning": local_doc["warning"],
        "gap_count": len(gaps),
        "high_risk_gap_count": high_risk_count,
        "outdated_sop_signals": outdated_count,
        "technology_gap_signals": technology_gap_count,
        "gaps": gaps[:40],
        "control_dna": {
            "global_score": global_dna["score"],
            "local_score": local_dna["score"],
            "maturity_gap": maturity_gap,
            "global_covered": global_dna["covered"],
            "local_covered": local_dna["covered"],
            "global_missing": global_dna["missing"],
            "local_missing": local_dna["missing"]
        },
        "review_triggers": list(dict.fromkeys(review_triggers)),
        "recommended_decision": recommended_decision,
        "pain_point_solutions": pain_point_solutions
    }

    return result


def save_sop_comparison_result(result):
    df = prepare_sop_comparisons()

    previous_hash = "GENESIS"
    if not df.empty and "record_hash" in df.columns:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    trigger_text = " | ".join(result.get("review_triggers", []))
    record_basis = (
        result["comparison_id"] +
        result["global_hash"] +
        result["local_hash"] +
        result["timestamp"] +
        previous_hash
    )
    record_hash = sha256_text(record_basis)

    row = pd.DataFrame([{
        "comparison_id": result["comparison_id"],
        "timestamp": result["timestamp"],
        "process_area": result["process_area"],
        "reviewer": result["reviewer"],
        "sop_owner": result["sop_owner"],
        "global_filename": result["global_filename"],
        "local_filename": result["local_filename"],
        "global_hash": result["global_hash"],
        "local_hash": result["local_hash"],
        "global_control_dna_score": result["control_dna"]["global_score"],
        "local_control_dna_score": result["control_dna"]["local_score"],
        "maturity_gap": result["control_dna"]["maturity_gap"],
        "gap_count": result["gap_count"],
        "high_risk_gap_count": result["high_risk_gap_count"],
        "outdated_sop_signals": result["outdated_sop_signals"],
        "technology_gap_signals": result["technology_gap_signals"],
        "review_triggers": trigger_text,
        "recommended_decision": result["recommended_decision"],
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, SOP_COMPARISON_FILE)


def load_recent_sop_comparisons():
    df = prepare_sop_comparisons()
    if df.empty:
        return []
    return df.tail(10).to_dict("records")


def render_sop_governance_v2(page, result=None):
    recent = load_recent_sop_comparisons()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain™ SOP Governance</title>
<style>
:root {
    --bg:#f4f7fb; --navy:#071527; --blue:#2563eb; --cyan:#06b6d4;
    --green:#16a34a; --yellow:#f59e0b; --red:#dc2626; --muted:#64748b;
    --card:#ffffff; --border:#e5e7eb;
}
* { box-sizing:border-box; }
body {
    margin:0; font-family:Inter,Segoe UI,Arial,sans-serif;
    background:linear-gradient(135deg,#eef4ff,#f8fafc,#eefdf8);
    color:#0f172a;
}
.hero {
    background:radial-gradient(circle at top left,#1d4ed8 0%,#0f2745 42%,#071527 100%);
    color:white; padding:36px 42px 46px;
    border-bottom-left-radius:34px; border-bottom-right-radius:34px;
    box-shadow:0 18px 45px rgba(15,39,69,.25);
}
.hero-top { display:flex; align-items:center; justify-content:space-between; gap:20px; flex-wrap:wrap; }
.brand { display:flex; align-items:center; gap:14px; }
.logo {
    width:54px; height:54px; border-radius:18px;
    background:linear-gradient(135deg,#38bdf8,#22c55e);
    display:flex; align-items:center; justify-content:center;
    font-weight:900; font-size:22px;
}
.brand h1 { margin:0; font-size:34px; letter-spacing:-.8px; }
.brand p { margin:4px 0 0; color:#cbd5e1; }
.badge {
    padding:10px 15px; border-radius:999px;
    background:rgba(255,255,255,.12); border:1px solid rgba(255,255,255,.22);
    color:#e0f2fe; font-weight:800;
}
.container { max-width:1450px; margin:-28px auto 50px; padding:0 26px; }
.nav {
    background:white; border:1px solid #e5e7eb; border-radius:24px;
    padding:14px; box-shadow:0 14px 35px rgba(15,23,42,.08);
    display:flex; gap:10px; flex-wrap:wrap; margin-bottom:22px;
}
.nav a {
    text-decoration:none; color:#0f172a; background:#f8fafc; border:1px solid #e2e8f0;
    padding:10px 13px; border-radius:999px; font-weight:900; font-size:13px;
}
.nav a.active { background:#0f172a; color:white; border-color:#0f172a; }
.grid { display:grid; grid-template-columns:repeat(4,1fr); gap:18px; margin-bottom:20px; }
.main-layout { display:grid; grid-template-columns:380px 1fr; gap:22px; align-items:start; }
.panel, .card {
    background:white; border:1px solid #e5e7eb; border-radius:24px;
    padding:22px; box-shadow:0 14px 35px rgba(15,23,42,.08);
}
.panel { margin-bottom:20px; }
input, textarea, button {
    width:100%; border-radius:14px; border:1px solid #dbe3ef;
    padding:12px 13px; margin:7px 0; font-size:14px; background:white;
}
textarea { min-height:120px; resize:vertical; }
button {
    border:none; background:linear-gradient(135deg,#2563eb,#06b6d4);
    color:white; font-weight:900; cursor:pointer;
}
.notice {
    background:#f0fdf4; border-left:7px solid #16a34a; border-radius:18px;
    padding:17px; line-height:1.55; margin-bottom:20px;
}
.warning {
    background:#fff7ed; border-left:7px solid #f59e0b; border-radius:18px;
    padding:17px; line-height:1.55; margin-bottom:20px;
}
.error {
    background:#fee2e2; border-left:7px solid #dc2626; color:#991b1b;
    border-radius:18px; padding:17px; font-weight:900; margin-bottom:20px;
}
.metric {
    background:rgba(255,255,255,.96); border:1px solid rgba(226,232,240,.9);
    border-radius:22px; padding:22px; box-shadow:0 12px 32px rgba(15,23,42,.08);
}
.metric-label { color:#64748b; font-weight:800; font-size:13px; text-transform:uppercase; letter-spacing:.08em; }
.metric-value { margin-top:8px; font-size:34px; font-weight:900; }
.metric-sub { color:#64748b; font-size:13px; }
.sop-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:18px; margin-bottom:20px; }
.sop-two-col { display:grid; grid-template-columns:repeat(2,1fr); gap:18px; margin-bottom:20px; }
.sop-card, .sop-mini {
    background:white; border:1px solid #e2e8f0; border-radius:24px;
    padding:22px; box-shadow:0 14px 35px rgba(15,23,42,.08);
}
.sop-card p, .sop-mini p { color:#475569; line-height:1.5; }
.sop-label {
    color:#64748b; font-weight:900; font-size:12px;
    text-transform:uppercase; letter-spacing:.08em;
}
.sop-badge {
    display:inline-block; margin-top:10px; padding:7px 10px; border-radius:999px;
    background:#eff6ff; color:#1d4ed8; font-weight:900; font-size:12px;
    border:1px solid #bfdbfe;
}
.exec-table {
    width:100%; border-collapse:collapse; border-radius:16px; overflow:hidden; font-size:13px;
}
.exec-table th {
    background:#0f172a; color:white; text-align:left; padding:12px;
}
.exec-table td {
    border-bottom:1px solid #e5e7eb; padding:12px; vertical-align:top;
}
.risk-HIGH { color:#dc2626; font-weight:900; }
.risk-MEDIUM { color:#d97706; font-weight:900; }
.risk-LOW { color:#16a34a; font-weight:900; }
.page-link {
    display:block; text-decoration:none; color:#0f172a; padding:13px 14px;
    border:1px solid #e2e8f0; border-radius:16px; margin:9px 0; background:#f8fafc;
}
.page-link.active {
    background:linear-gradient(135deg,#eff6ff,#ecfeff);
    border-color:#93c5fd; box-shadow:0 8px 18px rgba(37,99,235,.12);
}
.page-link b { display:block; font-size:14px; }
.page-link small { color:#64748b; font-weight:700; }
.dna-box {
    background:linear-gradient(135deg,#eff6ff,#ecfeff);
    border:1px solid #bfdbfe; border-radius:20px; padding:18px;
}
.tag {
    display:inline-block; padding:6px 9px; border-radius:999px;
    background:#f1f5f9; color:#334155; font-size:12px; font-weight:800;
    margin:4px 4px 0 0;
}
@media(max-width:1000px){ .grid,.main-layout,.sop-grid,.sop-two-col{ grid-template-columns:1fr; } }
</style>
</head>

<body>
<section class="hero">
    <div class="hero-top">
        <div class="brand">
            <div class="logo">CC</div>
            <div>
                <h1>COBIT-Chain™</h1>
                <p>SOP Governance • SOP-to-Reality Alignment • Harmonization Engine</p>
            </div>
        </div>
        <div class="badge">SOP Governance v2</div>
    </div>
</section>

<main class="container">
    <nav class="nav">
        {% for p in pages %}
            <a class="{% if p.route == '/sop-governance' %}active{% endif %}" href="{{ p.route }}">{{ p.title }}</a>
        {% endfor %}
    </nav>

    {% if result and result.error %}
        <div class="error">{{ result.error }}</div>
    {% endif %}

    <section class="main-layout">
        <aside>
            <div class="panel">
                <h2>Dual SOP Upload</h2>
                <form method="POST" enctype="multipart/form-data" action="/sop-governance">
                    <label><b>Enterprise Pharma / GPOS / Mature SOP</b></label>
                    <input type="file" name="global_sop" required>

                    <label><b>Acquired Site / Local / Legacy SOP</b></label>
                    <input type="file" name="local_sop" required>

                    <input name="process_area" placeholder="Process Area e.g. User Access Review / Equipment Handoff">
                    <input name="reviewer" placeholder="Reviewer e.g. Integration Lead / Taiwo">
                    <input name="sop_owner" placeholder="SOP Owner / System Owner">

                    <textarea name="reality_notes" placeholder="Optional: describe actual operational reality, audit finding, manual binder/Excel process, system workflow, recurring issue, acquisition/harmonization context..."></textarea>

                    <button type="submit">Compare SOPs and Identify Gaps</button>
                </form>
            </div>

            <div class="panel">
                <h2>Enterprise Pages</h2>
                {% for p in pages %}
                <a class="page-link {% if p.route == '/sop-governance' %}active{% endif %}" href="{{ p.route }}">
                    <b>{{ p.number }} → {{ p.title }}</b>
                    <small>{{ p.purpose }}</small>
                </a>
                {% endfor %}
            </div>
        </aside>

        <section>
            <div class="notice">
                <b>Advanced SOP feature:</b> this page compares Enterprise Pharma/GPOS against Acquired Site/local SOPs, identifies control gaps,
                detects outdated SOP signals, highlights technology maturity differences, maps findings to COBIT, and creates
                a harmonization recommendation.
            </div>

            <section class="sop-grid">
                <div class="sop-card">
                    <div class="sop-label">M&A Pain Acquired Site</div>
                    <h3>Enterprise Pharma + Acquired Site Harmonization</h3>
                    <p>Supports acquisition scenarios where a mature global process must be compared against a local manual process.</p>
                    <span class="sop-badge">SOP harmonization</span>
                </div>
                <div class="sop-card">
                    <div class="sop-label">Manufacturing Core Insight</div>
                    <h3>Outdated SOP Detection</h3>
                    <p>Determines whether a gap is true process noncompliance or an outdated SOP that no longer reflects operational reality.</p>
                    <span class="sop-badge">Reality alignment</span>
                </div>
                <div class="sop-card">
                    <div class="sop-label">Advanced Feature</div>
                    <h3>Control DNA Diff</h3>
                    <p>Compares control maturity signals between SOPs and produces a governance maturity gap score.</p>
                    <span class="sop-badge">Novel governance engine</span>
                </div>
            </section>

            {% if result and not result.error %}
            <section class="grid">
                <div class="metric"><div class="metric-label">Total Gaps</div><div class="metric-value">{{ result.gap_count }}</div><div class="metric-sub">Detected comparison gaps</div></div>
                <div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ result.high_risk_gap_count }}</div><div class="metric-sub">Priority governance issues</div></div>
                <div class="metric"><div class="metric-label">Outdated SOP Signals</div><div class="metric-value" style="color:#f59e0b">{{ result.outdated_sop_signals }}</div><div class="metric-sub">SOP vs reality mismatch</div></div>
                <div class="metric"><div class="metric-label">Maturity Gap</div><div class="metric-value">{{ result.control_dna.maturity_gap }}%</div><div class="metric-sub">Global score minus local score</div></div>
            </section>

            <div class="card">
                <h2>Executive SOP Harmonization Decision</h2>
                <p><b>{{ result.recommended_decision }}</b></p>
                <p><b>Comparison ID:</b> {{ result.comparison_id }}</p>
                <p><b>Process Area:</b> {{ result.process_area }}</p>
                <p><b>Reviewer:</b> {{ result.reviewer }}</p>
                <p><b>SOP Owner:</b> {{ result.sop_owner }}</p>
            </div>

            <section class="sop-two-col">
                <div class="dna-box">
                    <h2>Enterprise Pharma / GPOS Control DNA</h2>
                    <p><b>Score:</b> {{ result.control_dna.global_score }}%</p>
                    <p><b>File:</b> {{ result.global_filename }}</p>
                    <p><b>Covered Controls:</b></p>
                    {% for c in result.control_dna.global_covered %}
                        <span class="tag">{{ c }}</span>
                    {% endfor %}
                </div>

                <div class="dna-box">
                    <h2>Acquired Site / Local Control DNA</h2>
                    <p><b>Score:</b> {{ result.control_dna.local_score }}%</p>
                    <p><b>File:</b> {{ result.local_filename }}</p>
                    <p><b>Missing Controls:</b></p>
                    {% for c in result.control_dna.local_missing %}
                        <span class="tag">{{ c }}</span>
                    {% endfor %}
                </div>
            </section>

            <div class="card">
                <h2>SOP Review Trigger Assessment</h2>
                <ul>
                {% for t in result.review_triggers %}
                    <li>{{ t }}</li>
                {% endfor %}
                </ul>
            </div>

            <div class="card">
                <h2>Gap Detection Table</h2>
                <table class="exec-table">
                    <tr>
                        <th>Gap Type</th>
                        <th>Theme</th>
                        <th>Risk</th>
                        <th>COBIT Mapping</th>
                        <th>Recommendation</th>
                    </tr>
                    {% for g in result.gaps %}
                    <tr>
                        <td>{{ g.gap_type }}</td>
                        <td><b>{{ g.theme }}</b><br><small>{{ g.evidence }}</small></td>
                        <td class="risk-{{ g.risk }}">{{ g.risk }}</td>
                        <td>{{ g.cobit }}</td>
                        <td>{{ g.recommendation }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>

            <div class="card">
                <h2>Organizational Pain Points Solved</h2>
                <table class="exec-table">
                    <tr>
                        <th>Pain Acquired Site</th>
                        <th>COBIT-Chain Solution</th>
                    </tr>
                    {% for p in result.pain_point_solutions %}
                    <tr>
                        <td>{{ p.pain_point }}</td>
                        <td>{{ p.solution }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            {% endif %}

            <div class="card">
                <h2>Recent SOP Comparisons</h2>
                {% if recent %}
                <table class="exec-table">
                    <tr>
                        <th>ID</th>
                        <th>Process Area</th>
                        <th>Global SOP</th>
                        <th>Local SOP</th>
                        <th>Gaps</th>
                        <th>Decision</th>
                    </tr>
                    {% for r in recent %}
                    <tr>
                        <td>{{ r.comparison_id }}</td>
                        <td>{{ r.process_area }}</td>
                        <td>{{ r.global_filename }}</td>
                        <td>{{ r.local_filename }}</td>
                        <td>{{ r.gap_count }}</td>
                        <td>{{ r.recommended_decision }}</td>
                    </tr>
                    {% endfor %}
                </table>
                {% else %}
                    <p>No SOP comparisons saved yet.</p>
                {% endif %}
            </div>

            <div class="warning">
                <b>Storage design:</b> SOP comparison records are saved separately in <b>sop_comparisons.csv</b>.
                This does not touch Manufacturing/Manufacturing Core <b>logs.csv</b> or <b>baseline_hashes.csv</b>.
            </div>
        </section>
    </section>
</main>
</body>
</html>
    """

    return render_template_string(
        html,
        page=page,
        pages=ENTERPRISE_PAGES,
        result=result,
        recent=recent
    )


# ============================================================
# CLINICAL TRIAL INTEGRITY V2 ACTIVE
# Purview + Protocol-to-Evidence Governance Engine
# ============================================================

def render_clinical_trial_integrity_v2(page):
    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain™ Clinical Trial Integrity</title>
<style>
:root {
    --bg:#f4f7fb; --navy:#071527; --blue:#2563eb; --cyan:#06b6d4;
    --green:#16a34a; --yellow:#f59e0b; --red:#dc2626; --muted:#64748b;
    --card:#ffffff; --border:#e5e7eb;
}
* { box-sizing:border-box; }
body {
    margin:0; font-family:Inter,Segoe UI,Arial,sans-serif;
    background:linear-gradient(135deg,#eef4ff,#f8fafc,#eefdf8);
    color:#0f172a;
}
.hero {
    background:radial-gradient(circle at top left,#1d4ed8 0%,#0f2745 42%,#071527 100%);
    color:white; padding:36px 42px 46px;
    border-bottom-left-radius:34px; border-bottom-right-radius:34px;
    box-shadow:0 18px 45px rgba(15,39,69,.25);
}
.hero-top { display:flex; align-items:center; justify-content:space-between; gap:20px; flex-wrap:wrap; }
.brand { display:flex; align-items:center; gap:14px; }
.logo {
    width:54px; height:54px; border-radius:18px;
    background:linear-gradient(135deg,#38bdf8,#22c55e);
    display:flex; align-items:center; justify-content:center;
    font-weight:900; font-size:22px;
}
.brand h1 { margin:0; font-size:34px; letter-spacing:-.8px; }
.brand p { margin:4px 0 0; color:#cbd5e1; }
.badge {
    padding:10px 15px; border-radius:999px;
    background:rgba(255,255,255,.12); border:1px solid rgba(255,255,255,.22);
    color:#e0f2fe; font-weight:800;
}
.container { max-width:1450px; margin:-28px auto 50px; padding:0 26px; }
.nav {
    background:white; border:1px solid #e5e7eb; border-radius:24px;
    padding:14px; box-shadow:0 14px 35px rgba(15,23,42,.08);
    display:flex; gap:10px; flex-wrap:wrap; margin-bottom:22px;
}
.nav a {
    text-decoration:none; color:#0f172a; background:#f8fafc; border:1px solid #e2e8f0;
    padding:10px 13px; border-radius:999px; font-weight:900; font-size:13px;
}
.nav a.active { background:#0f172a; color:white; border-color:#0f172a; }
.card {
    background:white; border:1px solid #e5e7eb; border-radius:24px;
    padding:22px; box-shadow:0 14px 35px rgba(15,23,42,.08);
    margin-bottom:20px;
}
.notice {
    background:#f0fdf4; border-left:7px solid #16a34a; border-radius:18px;
    padding:17px; line-height:1.55; margin-bottom:20px;
}
.warning {
    background:#fff7ed; border-left:7px solid #f59e0b; border-radius:18px;
    padding:17px; line-height:1.55; margin-bottom:20px;
}
.trial-grid {
    display:grid; grid-template-columns:repeat(3,1fr); gap:18px; margin-bottom:20px;
}
.trial-two-col {
    display:grid; grid-template-columns:repeat(2,1fr); gap:18px; margin-bottom:20px;
}
.trial-card, .trial-mini {
    background:white; border:1px solid #e2e8f0; border-radius:24px;
    padding:22px; box-shadow:0 14px 35px rgba(15,23,42,.08);
}
.trial-card h3 { margin:8px 0 10px; }
.trial-card p, .trial-mini p { color:#475569; line-height:1.5; }
.trial-label {
    color:#64748b; font-weight:900; font-size:12px;
    text-transform:uppercase; letter-spacing:.08em;
}
.trial-badge {
    display:inline-block; margin-top:10px; padding:7px 10px; border-radius:999px;
    background:#eff6ff; color:#1d4ed8; font-weight:900; font-size:12px;
    border:1px solid #bfdbfe;
}
.exec-table {
    width:100%; border-collapse:collapse; border-radius:16px; overflow:hidden; font-size:13px;
}
.exec-table th {
    background:#0f172a; color:white; text-align:left; padding:12px;
}
.exec-table td {
    border-bottom:1px solid #e5e7eb; padding:12px; vertical-align:top;
}
.flow {
    display:flex; gap:12px; flex-wrap:wrap; align-items:stretch; margin-top:14px;
}
.flow-step {
    flex:1; min-width:185px; background:linear-gradient(135deg,#eff6ff,#ecfeff);
    border:1px solid #bfdbfe; border-radius:18px; padding:15px;
}
.flow-step b { display:block; margin-bottom:7px; }
.flow-step span { display:block; color:#475569; line-height:1.45; font-size:13px; }
.flow-arrow {
    display:flex; align-items:center; justify-content:center;
    color:#94a3b8; font-weight:900; font-size:22px;
}
.tag {
    display:inline-block; padding:6px 9px; border-radius:999px;
    background:#f1f5f9; color:#334155; font-size:12px; font-weight:800;
    margin:4px 4px 0 0;
}
@media(max-width:1000px){
    .trial-grid,.trial-two-col{ grid-template-columns:1fr; }
    .flow-arrow{ display:none; }
}
</style>
</head>

<body>
<section class="hero">
    <div class="hero-top">
        <div class="brand">
            <div class="logo">CC</div>
            <div>
                <h1>COBIT-Chain™</h1>
                <p>Clinical Trial Integrity • Microsoft Purview • Protocol-to-Evidence Governance</p>
            </div>
        </div>
        <div class="badge">Clinical Trial Integrity v2</div>
    </div>
</section>

<main class="container">
    <nav class="nav">
        {% for p in pages %}
            <a class="{% if p.route == '/clinical-trial-integrity' %}active{% endif %}" href="{{ p.route }}">{{ p.title }}</a>
        {% endfor %}
    </nav>

    <div class="notice">
        <b>Clinical Trial Integrity v2 is active.</b>
        This page extends your earlier Microsoft Purview/eConsent governance work into a full clinical-trial evidence integrity model.
        The Manufacturing/Manufacturing Core dashboard, SOP comparison engine, Access, Shift, and Audit/CAPA modules remain untouched.
    </div>

    <section class="trial-grid">
        <div class="trial-card">
            <div class="trial-label">Your Prior Build</div>
            <h3>Microsoft Purview eConsent Governance</h3>
            <p>Tracks the earlier eConsent-DLP policy work, retention label plan, and SharePoint validation-pack direction.</p>
            <span class="trial-badge">Purview-connected</span>
        </div>

        <div class="trial-card">
            <div class="trial-label">Advanced Feature</div>
            <h3>Protocol-to-Purview Evidence Graph™</h3>
            <p>Maps protocol obligations to evidence artifacts, Purview compliance state, COBIT-Chain hash integrity, and inspection readiness.</p>
            <span class="trial-badge">Differentiated engine</span>
        </div>

        <div class="trial-card">
            <div class="trial-label">Trial Pain Acquired Site</div>
            <h3>Fragmented Evidence Control</h3>
            <p>Creates a single governance view across eConsent, eTMF, EDC, SharePoint, vendor files, monitoring evidence, and CSV validation packs.</p>
            <span class="trial-badge">Evidence control tower</span>
        </div>
    </section>

    <div class="card">
        <h2>What You Already Achieved / Started</h2>
        <table class="exec-table">
            <tr>
                <th>Workstream</th>
                <th>Status / Meaning</th>
                <th>How COBIT-Chain Extends It</th>
            </tr>
            <tr>
                <td><b>eConsent-DLP Policy</b></td>
                <td>Purview DLP policy was created, but detection still needed troubleshooting.</td>
                <td>Adds a DLP Readiness Gate: scope, rule logic, test document, sensitive data pattern, and SharePoint location must all pass.</td>
            </tr>
            <tr>
                <td><b>15-Year eConsent Retention</b></td>
                <td>Retention label/policy was planned for long-term clinical evidence preservation.</td>
                <td>Adds a Records Retention Gate: evidence cannot be inspection-ready unless expected retention label status is confirmed.</td>
            </tr>
            <tr>
                <td><b>CSV Validation Packs Library</b></td>
                <td>SharePoint library was planned for CSV validation evidence packs.</td>
                <td>Adds CSV Evidence Integrity: file hash, row/column checks, missing value checks, validation pack status, and audit trail readiness.</td>
            </tr>
            <tr>
                <td><b>Purview + COBIT-Chain Model</b></td>
                <td>Purview governs classification, DLP, retention, and records; COBIT-Chain governs evidence integrity and audit logic.</td>
                <td>Combines compliance state with cryptographic evidence verification and COBIT/ALCOA+ readiness scoring.</td>
            </tr>
        </table>
    </div>

    <div class="card">
        <h2>Protocol-to-Purview Evidence Graph™</h2>
        <div class="flow">
            <div class="flow-step">
                <b>1. Protocol Obligation</b>
                <span>Consent, visit, source data, monitoring, safety, TMF, or data-transfer requirement.</span>
            </div>
            <div class="flow-arrow">→</div>
            <div class="flow-step">
                <b>2. Evidence Artifact</b>
                <span>eConsent, CSV, TMF file, EDC export, monitoring report, vendor file, or SharePoint document.</span>
            </div>
            <div class="flow-arrow">→</div>
            <div class="flow-step">
                <b>3. Purview State</b>
                <span>DLP match, sensitivity label, retention label, record status, access/sharing risk, and policy alert.</span>
            </div>
            <div class="flow-arrow">→</div>
            <div class="flow-step">
                <b>4. COBIT-Chain Integrity</b>
                <span>SHA-256 hash, baseline match, evidence status, chain record, and tamper detection.</span>
            </div>
            <div class="flow-arrow">→</div>
            <div class="flow-step">
                <b>5. Inspection Readiness</b>
                <span>ALCOA+ score, deviation/CAPA linkage, reviewer signoff, and audit-ready evidence pack.</span>
            </div>
        </div>
    </div>

    <section class="trial-two-col">
        <div class="card">
            <h2>Global Clinical Trial Pain Points</h2>
            <ul>
                <li>Evidence scattered across eTMF, EDC, eConsent, SharePoint, labs, vendors, monitoring reports, and emails.</li>
                <li>Protocol requirements not clearly linked to proof that the required action happened.</li>
                <li>Manual inspection-readiness work and late evidence reconstruction.</li>
                <li>Data integrity risk from decentralized, remote, and vendor-generated evidence.</li>
                <li>Participant privacy risk when sensitive trial documents are shared or stored incorrectly.</li>
                <li>Retention uncertainty for long-lived clinical evidence such as eConsent records.</li>
                <li>Difficulty proving ALCOA+ readiness across multiple evidence sources.</li>
                <li>Weak linkage between evidence gaps, deviations, CAPA, and effectiveness checks.</li>
                <li>CSV and data-transfer reconciliation gaps.</li>
                <li>Inconsistent site/vendor visibility for sponsors and QA.</li>
            </ul>
        </div>

        <div class="card">
            <h2>COBIT-Chain Solution</h2>
            <ul>
                <li>Creates one clinical evidence control tower across fragmented evidence sources.</li>
                <li>Maps each protocol obligation to evidence, reviewer, status, hash, and Purview policy state.</li>
                <li>Pre-validates inspection readiness before audit pressure begins.</li>
                <li>Combines Purview DLP/retention status with COBIT-Chain cryptographic evidence integrity.</li>
                <li>Flags sensitive data exposure risk before evidence is shared incorrectly.</li>
                <li>Tracks retention readiness for eConsent and regulated trial records.</li>
                <li>Scores ALCOA+ readiness using evidence completeness, attribution, timestamp, originality, availability, and review state.</li>
                <li>Links missing or defective evidence to deviation/CAPA readiness.</li>
                <li>Validates CSV packs using file hash, missing values, duplicate rows, and expected record checks.</li>
                <li>Gives leadership a trial integrity status without replacing eTMF, EDC, or Purview.</li>
            </ul>
        </div>
    </section>

    <div class="card">
        <h2>Clinical Trial Integrity Data Model</h2>
        <table class="exec-table">
            <tr>
                <th>Field</th>
                <th>Purpose</th>
                <th>Governance Value</th>
            </tr>
            <tr>
                <td><b>Study / Protocol ID</b></td>
                <td>Identifies trial, protocol, amendment, or study version.</td>
                <td>Links evidence to the correct clinical requirement.</td>
            </tr>
            <tr>
                <td><b>Protocol Obligation</b></td>
                <td>Defines required action such as consent, visit, monitoring, safety review, or data transfer.</td>
                <td>Creates the baseline for evidence verification.</td>
            </tr>
            <tr>
                <td><b>Evidence Artifact</b></td>
                <td>eConsent, TMF artifact, EDC export, lab file, vendor CSV, monitoring report, or SharePoint file.</td>
                <td>Identifies the proof used for inspection readiness.</td>
            </tr>
            <tr>
                <td><b>Purview DLP Status</b></td>
                <td>No match, matched, alert, override, blocked, or policy exception.</td>
                <td>Shows participant-data protection risk.</td>
            </tr>
            <tr>
                <td><b>Retention Label Status</b></td>
                <td>Missing, applied, record, regulatory record, expired, or review required.</td>
                <td>Shows long-term evidence preservation readiness.</td>
            </tr>
            <tr>
                <td><b>Hash Integrity Status</b></td>
                <td>Green, yellow, or red based on baseline and current hash.</td>
                <td>Shows whether evidence changed after baseline creation.</td>
            </tr>
            <tr>
                <td><b>ALCOA+ Score</b></td>
                <td>Assesses attributable, legible, contemporaneous, original, accurate, complete, consistent, enduring, and available.</td>
                <td>Provides data-integrity readiness scoring.</td>
            </tr>
            <tr>
                <td><b>Deviation / CAPA Link</b></td>
                <td>Links evidence gaps to controlled remediation.</td>
                <td>Prevents unresolved trial evidence gaps from remaining hidden.</td>
            </tr>
        </table>
    </div>

    <div class="card">
        <h2>Purview + COBIT-Chain Control Gates</h2>
        <table class="exec-table">
            <tr>
                <th>Gate</th>
                <th>Failure Signal</th>
                <th>Recommended Action</th>
            </tr>
            <tr>
                <td><b>eConsent DLP Gate</b></td>
                <td>Policy does not trigger on expected eConsent test file.</td>
                <td>Check DLP scope, sensitive info type, test content, SharePoint location, policy mode, and alert configuration.</td>
            </tr>
            <tr>
                <td><b>Retention Gate</b></td>
                <td>eConsent evidence has no retention label or record status.</td>
                <td>Apply or auto-apply correct clinical retention label before declaring inspection readiness.</td>
            </tr>
            <tr>
                <td><b>CSV Validation Gate</b></td>
                <td>CSV pack has missing rows, duplicates, mismatch counts, or no validation evidence.</td>
                <td>Block reliance until validation pack is complete and hash baseline is generated.</td>
            </tr>
            <tr>
                <td><b>Protocol Evidence Gate</b></td>
                <td>Protocol obligation has no mapped evidence artifact.</td>
                <td>Create evidence mapping or raise deviation/remediation workflow.</td>
            </tr>
            <tr>
                <td><b>ALCOA+ Gate</b></td>
                <td>Evidence lacks owner, timestamp, original source, completeness, or availability.</td>
                <td>Escalate to study owner, QA, or site monitor before inspection reliance.</td>
            </tr>
            <tr>
                <td><b>CAPA Linkage Gate</b></td>
                <td>Evidence gap exists but no deviation/CAPA reference is linked.</td>
                <td>Route to Audit/CAPA module for controlled remediation and effectiveness readiness.</td>
            </tr>
        </table>
    </div>

    <div class="card">
        <h2>Clinical Trial Integrity Domains</h2>
        <section class="trial-grid">
            <div class="trial-mini">
                <b>eConsent Integrity</b>
                <p>Consent version, signature, timestamp, participant/site linkage, DLP status, retention status, and audit trail readiness.</p>
            </div>
            <div class="trial-mini">
                <b>Source Data Verification</b>
                <p>Traceability between source records, EDC entries, monitoring review, query resolution, and evidence status.</p>
            </div>
            <div class="trial-mini">
                <b>TMF Completeness</b>
                <p>TMF artifact completeness, owner, version, review status, filing status, and inspection readiness.</p>
            </div>
            <div class="trial-mini">
                <b>CSV Validation Packs</b>
                <p>CSV evidence packs with hash baseline, row count, duplicate checks, missing values, and validation signoff.</p>
            </div>
            <div class="trial-mini">
                <b>Vendor Data Transfer</b>
                <p>Lab, safety, imaging, or external vendor file reconciliation with exception and acceptance status.</p>
            </div>
            <div class="trial-mini">
                <b>Deviation / CAPA Readiness</b>
                <p>Evidence gaps linked to deviation, CAPA, remediation proof, and effectiveness-check readiness.</p>
            </div>
        </section>
    </div>

    <div class="warning">
        <b>Next build step:</b> add a separate <b>clinical_trial_evidence.csv</b> storage file for protocol obligations,
        evidence artifacts, Purview status, ALCOA+ scoring, CSV validation packs, deviation linkage, and inspection-readiness scoring.
        This must stay separate from Manufacturing/Manufacturing Core <b>logs.csv</b> and <b>baseline_hashes.csv</b>.
    </div>
</main>
</body>
</html>
    """

    return render_template_string(
        html,
        page=page,
        pages=ENTERPRISE_PAGES
    )


# ============================================================
# SHIFT ASSURANCE V2 TEST ACTIVE
# Functional test page only. Does not replace /shift-assurance.
# ============================================================

SHIFT_HANDOFF_FILE = "shift_handoffs.csv"


def prepare_shift_handoffs():
    df = load_csv(SHIFT_HANDOFF_FILE)
    return ensure_cols(df, [
        "handoff_id", "timestamp", "shift_date", "shift_type",
        "equipment_id", "equipment_name", "equipment_status",
        "servicenow_ticket", "ticket_priority",
        "outgoing_technician", "incoming_technician",
        "open_issue", "next_action",
        "escalation_required", "qa_engineering_followup",
        "readiness_status", "readiness_score", "risk_level",
        "previous_hash", "record_hash"
    ])


def calculate_shift_readiness(equipment_status, servicenow_ticket, open_issue, next_action,
                              escalation_required, qa_engineering_followup,
                              outgoing_technician, incoming_technician):
    score = 100
    signals = []

    if equipment_status in ["Out of Service", "Under Maintenance"]:
        score -= 35
        signals.append("Equipment is not fully available.")

    if equipment_status == "Degraded":
        score -= 20
        signals.append("Equipment is degraded and needs monitoring.")

    if clean(open_issue) and not clean(next_action):
        score -= 20
        signals.append("Open issue exists with no next action.")

    if clean(open_issue) and not clean(servicenow_ticket):
        score -= 15
        signals.append("Open issue exists without ServiceNow ticket reference.")

    if escalation_required == "Yes" and qa_engineering_followup == "No":
        score -= 20
        signals.append("Escalation required but QA/Engineering follow-up is not marked.")

    if not clean(outgoing_technician) or not clean(incoming_technician):
        score -= 15
        signals.append("Outgoing or incoming technician is missing.")

    if clean(outgoing_technician).lower() == clean(incoming_technician).lower():
        score -= 10
        signals.append("Outgoing and incoming technician are the same person; verify handoff accountability.")

    score = max(score, 0)

    if score >= 85:
        return "READY", score, "LOW", signals or ["No major shift handoff risk detected."]
    if score >= 60:
        return "CONDITIONALLY READY", score, "MEDIUM", signals
    return "NOT READY", score, "HIGH", signals


def save_shift_handoff_test(req):
    df = prepare_shift_handoffs()

    shift_date = clean(req.form.get("shift_date"))
    shift_type = clean(req.form.get("shift_type"))
    equipment_id = clean(req.form.get("equipment_id"))
    equipment_name = clean(req.form.get("equipment_name"))
    equipment_status = clean(req.form.get("equipment_status"))
    servicenow_ticket = clean(req.form.get("servicenow_ticket"))
    ticket_priority = clean(req.form.get("ticket_priority"))
    outgoing_technician = clean(req.form.get("outgoing_technician"))
    incoming_technician = clean(req.form.get("incoming_technician"))
    open_issue = clean(req.form.get("open_issue"))
    next_action = clean(req.form.get("next_action"))
    escalation_required = clean(req.form.get("escalation_required")) or "No"
    qa_engineering_followup = clean(req.form.get("qa_engineering_followup")) or "No"

    if not shift_date or not shift_type or not equipment_id or not equipment_name or not equipment_status:
        return {"error": "Shift Date, Shift Type, Equipment ID, Equipment Name, and Equipment Status are required."}

    if not outgoing_technician or not incoming_technician:
        return {"error": "Outgoing Technician and Incoming Technician are required."}

    readiness_status, readiness_score, risk_level, risk_signals = calculate_shift_readiness(
        equipment_status, servicenow_ticket, open_issue, next_action,
        escalation_required, qa_engineering_followup,
        outgoing_technician, incoming_technician
    )

    timestamp = datetime.datetime.utcnow().isoformat()
    handoff_id = "SHIFT-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    previous_hash = "GENESIS"
    if not df.empty:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    record_hash = sha256_text(
        handoff_id + timestamp + shift_date + shift_type + equipment_id +
        equipment_name + equipment_status + servicenow_ticket +
        outgoing_technician + incoming_technician + previous_hash
    )

    row = pd.DataFrame([{
        "handoff_id": handoff_id,
        "timestamp": timestamp,
        "shift_date": shift_date,
        "shift_type": shift_type,
        "equipment_id": equipment_id,
        "equipment_name": equipment_name,
        "equipment_status": equipment_status,
        "servicenow_ticket": servicenow_ticket,
        "ticket_priority": ticket_priority,
        "outgoing_technician": outgoing_technician,
        "incoming_technician": incoming_technician,
        "open_issue": open_issue,
        "next_action": next_action,
        "escalation_required": escalation_required,
        "qa_engineering_followup": qa_engineering_followup,
        "readiness_status": readiness_status,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, SHIFT_HANDOFF_FILE)

    return {
        "error": "",
        "handoff_id": handoff_id,
        "readiness_status": readiness_status,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "risk_signals": risk_signals
    }


def get_shift_test_metrics():
    df = prepare_shift_handoffs()
    if df.empty:
        return {"total": 0, "ready": 0, "conditional": 0, "not_ready": 0, "high": 0, "recent": []}

    df = df.fillna("")
    return {
        "total": len(df),
        "ready": len(df[df["readiness_status"] == "READY"]),
        "conditional": len(df[df["readiness_status"] == "CONDITIONALLY READY"]),
        "not_ready": len(df[df["readiness_status"] == "NOT READY"]),
        "high": len(df[df["risk_level"] == "HIGH"]),
        "recent": df.tail(15).to_dict("records")
    }


@app.route("/shift-assurance-v2-test", methods=["GET", "POST"])
def shift_assurance_v2_test():
    result = None
    if request.method == "POST":
        result = save_shift_handoff_test(request)

    metrics = get_shift_test_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain Shift Assurance v2 Test</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#1d4ed8);color:white;padding:34px 42px;border-bottom-left-radius:30px;border-bottom-right-radius:30px}
.container{max-width:1450px;margin:-20px auto 50px;padding:0 26px}
.nav,.card,.panel{background:white;border:1px solid #e5e7eb;border-radius:22px;padding:18px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:18px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block}
.nav a.active{background:#0f172a;color:white}
.layout{display:grid;grid-template-columns:390px 1fr;gap:20px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
input,select,textarea,button{width:100%;border-radius:13px;border:1px solid #dbe3ef;padding:11px;margin:6px 0;font-size:14px}
textarea{min-height:85px}
button{border:none;background:linear-gradient(135deg,#2563eb,#06b6d4);color:white;font-weight:900;cursor:pointer}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top}
.risk-HIGH{color:#dc2626;font-weight:900}.risk-MEDIUM{color:#d97706;font-weight:900}.risk-LOW{color:#16a34a;font-weight:900}
@media(max-width:1000px){.layout,.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ Shift Assurance v2 Test</h1>
<p>Functional test page only — stable /shift-assurance is untouched.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/executive-overview">Executive Overview</a>
<a href="/sop-governance">SOP Governance</a>
<a href="/shift-assurance">Shift v1 Stable</a>
<a class="active" href="/shift-assurance-v2-test">Shift v2 Test</a>
<a href="/access-governance">Access</a>
<a href="/audit-capa">Audit/CAPA</a>
<a href="/clinical-trial-integrity">Clinical Trial Integrity</a>
</nav>

{% if result and result.error %}
<div class="error">{{ result.error }}</div>
{% elif result %}
<div class="notice">
<b>Saved:</b> {{ result.handoff_id }} — <b>{{ result.readiness_status }}</b> — Score <b>{{ result.readiness_score }}%</b>
<ul>{% for s in result.risk_signals %}<li>{{ s }}</li>{% endfor %}</ul>
</div>
{% endif %}

<section class="grid">
<div class="metric"><div class="metric-label">Total Handoffs</div><div class="metric-value">{{ metrics.total }}</div></div>
<div class="metric"><div class="metric-label">Ready</div><div class="metric-value" style="color:#16a34a">{{ metrics.ready }}</div></div>
<div class="metric"><div class="metric-label">Conditional</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional }}</div></div>
<div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ metrics.high }}</div></div>
</section>

<section class="layout">
<aside class="panel">
<h2>Create Shift Handoff</h2>
<form method="POST" action="/shift-assurance-v2-test">
<input type="date" name="shift_date" required>
<select name="shift_type" required>
<option value="">Select Shift</option>
<option value="Day Shift">Day Shift</option>
<option value="Night Shift">Night Shift</option>
</select>
<input name="equipment_id" placeholder="Equipment ID e.g. EQP-1803" required>
<input name="equipment_name" placeholder="Equipment Name e.g. Speedy Glove Isolator" required>
<select name="equipment_status" required>
<option value="">Equipment Status</option>
<option value="Available">Available</option>
<option value="Degraded">Degraded</option>
<option value="Under Maintenance">Under Maintenance</option>
<option value="Out of Service">Out of Service</option>
<option value="Pending QA/Engineering Review">Pending QA/Engineering Review</option>
</select>
<input name="servicenow_ticket" placeholder="ServiceNow Ticket e.g. MWO-003753-2026">
<select name="ticket_priority">
<option value="">Ticket Priority</option>
<option value="Low">Low</option><option value="Medium">Medium</option><option value="High">High</option><option value="Critical">Critical</option>
</select>
<input name="outgoing_technician" placeholder="Outgoing Technician" required>
<input name="incoming_technician" placeholder="Incoming Technician" required>
<textarea name="open_issue" placeholder="Open Issue / Risk"></textarea>
<textarea name="next_action" placeholder="Next Action / Carryover Instruction"></textarea>
<select name="escalation_required"><option value="No">Escalation Required? No</option><option value="Yes">Escalation Required? Yes</option></select>
<select name="qa_engineering_followup"><option value="No">QA/Engineering Follow-up? No</option><option value="Yes">QA/Engineering Follow-up? Yes</option></select>
<button type="submit">Save Shift Handoff</button>
</form>
</aside>

<section class="card">
<h2>Recent Shift Handoffs</h2>
{% if metrics.recent %}
<table>
<tr><th>ID</th><th>Date</th><th>Shift</th><th>Equipment</th><th>Status</th><th>Ticket</th><th>Incoming</th><th>Readiness</th><th>Risk</th></tr>
{% for r in metrics.recent %}
<tr>
<td>{{ r.handoff_id }}</td>
<td>{{ r.shift_date }}</td>
<td>{{ r.shift_type }}</td>
<td><b>{{ r.equipment_id }}</b><br>{{ r.equipment_name }}</td>
<td>{{ r.equipment_status }}</td>
<td>{{ r.servicenow_ticket }}</td>
<td>{{ r.incoming_technician }}</td>
<td><b>{{ r.readiness_status }}</b><br>{{ r.readiness_score }}%</td>
<td class="risk-{{ r.risk_level }}">{{ r.risk_level }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No shift handoffs saved yet.</p>
{% endif %}
</section>
</section>

<div class="card">
<b>Storage design:</b> records are saved separately in <b>shift_handoffs.csv</b>. Manufacturing logs.csv and baseline_hashes.csv are untouched.
</div>
</main>
</body>
</html>
    """

    return render_template_string(html, metrics=metrics, result=result)


# ============================================================
# ACCESS GOVERNANCE V2 TEST ACTIVE
# Functional test page only. Does not replace /access-governance.
# ============================================================

ACCESS_REVIEW_FILE = "access_reviews.csv"


def prepare_access_reviews():
    df = load_csv(ACCESS_REVIEW_FILE)
    return ensure_cols(df, [
        "review_id", "timestamp", "review_cycle", "system_name",
        "user_id", "user_name", "role_entitlement", "access_source",
        "approval_reference", "approver", "system_owner",
        "review_decision", "privileged_access", "binder_reference",
        "remediation_action", "risk_level", "readiness_status",
        "readiness_score", "risk_signals", "previous_hash", "record_hash"
    ])


def calculate_access_readiness(access_source, approval_reference, approver, system_owner,
                               review_decision, privileged_access, binder_reference,
                               remediation_action):
    score = 100
    signals = []

    access_source = clean(access_source)
    approval_reference = clean(approval_reference)
    approver = clean(approver)
    system_owner = clean(system_owner)
    review_decision = clean(review_decision)
    privileged_access = clean(privileged_access)
    binder_reference = clean(binder_reference)
    remediation_action = clean(remediation_action)

    if not approval_reference:
        score -= 30
        signals.append("No approval reference is linked to the access record.")

    if not approver:
        score -= 20
        signals.append("No approver is recorded.")

    if not system_owner:
        score -= 15
        signals.append("No system owner is recorded.")

    if review_decision in ["Pending", "Exception"]:
        score -= 20
        signals.append("Review decision is pending or marked as exception.")

    if review_decision in ["Remove", "Modify"] and not remediation_action:
        score -= 20
        signals.append("Access requires removal/modification but no remediation action is documented.")

    if privileged_access == "Yes" and not approval_reference:
        score -= 25
        signals.append("Privileged access exists without approval reference.")

    if access_source in ["Binder", "Excel", "Manual"] and not binder_reference:
        score -= 15
        signals.append("Manual/binder/Excel source selected but no binder/evidence reference is provided.")

    score = max(score, 0)

    if score >= 85:
        readiness_status = "AUDIT-READY"
        risk_level = "LOW"
    elif score >= 60:
        readiness_status = "CONDITIONALLY READY"
        risk_level = "MEDIUM"
    else:
        readiness_status = "NOT AUDIT-READY"
        risk_level = "HIGH"

    if not signals:
        signals.append("No major access governance risk detected.")

    return readiness_status, score, risk_level, signals


def save_access_review_test(req):
    df = prepare_access_reviews()

    review_cycle = clean(req.form.get("review_cycle"))
    system_name = clean(req.form.get("system_name"))
    user_id = clean(req.form.get("user_id"))
    user_name = clean(req.form.get("user_name"))
    role_entitlement = clean(req.form.get("role_entitlement"))
    access_source = clean(req.form.get("access_source"))
    approval_reference = clean(req.form.get("approval_reference"))
    approver = clean(req.form.get("approver"))
    system_owner = clean(req.form.get("system_owner"))
    review_decision = clean(req.form.get("review_decision"))
    privileged_access = clean(req.form.get("privileged_access")) or "No"
    binder_reference = clean(req.form.get("binder_reference"))
    remediation_action = clean(req.form.get("remediation_action"))

    required = [review_cycle, system_name, user_id, user_name, role_entitlement, access_source, review_decision]
    if not all(required):
        return {"error": "Review Cycle, System Name, User ID, User Name, Role/Entitlement, Access Source, and Review Decision are required."}

    readiness_status, readiness_score, risk_level, risk_signals = calculate_access_readiness(
        access_source, approval_reference, approver, system_owner,
        review_decision, privileged_access, binder_reference, remediation_action
    )

    timestamp = datetime.datetime.utcnow().isoformat()
    review_id = "ACCESS-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    previous_hash = "GENESIS"
    if not df.empty:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    record_hash = sha256_text(
        review_id + timestamp + review_cycle + system_name + user_id +
        user_name + role_entitlement + access_source + approval_reference +
        review_decision + previous_hash
    )

    row = pd.DataFrame([{
        "review_id": review_id,
        "timestamp": timestamp,
        "review_cycle": review_cycle,
        "system_name": system_name,
        "user_id": user_id,
        "user_name": user_name,
        "role_entitlement": role_entitlement,
        "access_source": access_source,
        "approval_reference": approval_reference,
        "approver": approver,
        "system_owner": system_owner,
        "review_decision": review_decision,
        "privileged_access": privileged_access,
        "binder_reference": binder_reference,
        "remediation_action": remediation_action,
        "risk_level": risk_level,
        "readiness_status": readiness_status,
        "readiness_score": readiness_score,
        "risk_signals": " | ".join(risk_signals),
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, ACCESS_REVIEW_FILE)

    return {
        "error": "",
        "review_id": review_id,
        "readiness_status": readiness_status,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "risk_signals": risk_signals
    }


def get_access_test_metrics():
    df = prepare_access_reviews()
    if df.empty:
        return {"total": 0, "ready": 0, "conditional": 0, "not_ready": 0, "high": 0, "recent": []}

    df = df.fillna("")
    return {
        "total": len(df),
        "ready": len(df[df["readiness_status"] == "AUDIT-READY"]),
        "conditional": len(df[df["readiness_status"] == "CONDITIONALLY READY"]),
        "not_ready": len(df[df["readiness_status"] == "NOT AUDIT-READY"]),
        "high": len(df[df["risk_level"] == "HIGH"]),
        "recent": df.tail(15).to_dict("records")
    }


@app.route("/access-governance-v2-test", methods=["GET", "POST"])
def access_governance_v2_test():
    result = None
    if request.method == "POST":
        result = save_access_review_test(request)

    metrics = get_access_test_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain Access Governance v2 Test</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#1d4ed8);color:white;padding:34px 42px;border-bottom-left-radius:30px;border-bottom-right-radius:30px}
.container{max-width:1450px;margin:-20px auto 50px;padding:0 26px}
.nav,.card,.panel{background:white;border:1px solid #e5e7eb;border-radius:22px;padding:18px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:18px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block}
.nav a.active{background:#0f172a;color:white}
.layout{display:grid;grid-template-columns:390px 1fr;gap:20px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
input,select,textarea,button{width:100%;border-radius:13px;border:1px solid #dbe3ef;padding:11px;margin:6px 0;font-size:14px}
textarea{min-height:85px}
button{border:none;background:linear-gradient(135deg,#2563eb,#06b6d4);color:white;font-weight:900;cursor:pointer}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top}
.risk-HIGH{color:#dc2626;font-weight:900}.risk-MEDIUM{color:#d97706;font-weight:900}.risk-LOW{color:#16a34a;font-weight:900}
@media(max-width:1000px){.layout,.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ Access Governance v2 Test</h1>
<p>Functional test page only — stable /access-governance is untouched.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/executive-overview">Executive Overview</a>
<a href="/sop-governance">SOP Governance</a>
<a href="/shift-assurance">Shift Assurance</a>
<a href="/access-governance">Access v1 Stable</a>
<a class="active" href="/access-governance-v2-test">Access v2 Test</a>
<a href="/audit-capa">Audit/CAPA</a>
<a href="/clinical-trial-integrity">Clinical Trial Integrity</a>
</nav>

{% if result and result.error %}
<div class="error">{{ result.error }}</div>
{% elif result %}
<div class="notice">
<b>Saved:</b> {{ result.review_id }} — <b>{{ result.readiness_status }}</b> — Score <b>{{ result.readiness_score }}%</b>
<ul>{% for s in result.risk_signals %}<li>{{ s }}</li>{% endfor %}</ul>
</div>
{% endif %}

<section class="grid">
<div class="metric"><div class="metric-label">Total Reviews</div><div class="metric-value">{{ metrics.total }}</div></div>
<div class="metric"><div class="metric-label">Audit-Ready</div><div class="metric-value" style="color:#16a34a">{{ metrics.ready }}</div></div>
<div class="metric"><div class="metric-label">Conditional</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional }}</div></div>
<div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ metrics.high }}</div></div>
</section>

<section class="layout">
<aside class="panel">
<h2>Create Access Review Record</h2>
<form method="POST" action="/access-governance-v2-test">
<input name="review_cycle" placeholder="Review Cycle e.g. Q2-2026" required>
<input name="system_name" placeholder="System/Application e.g. Blue Mountain / myAccess / Speedy Glove" required>
<input name="user_id" placeholder="User ID / Account ID" required>
<input name="user_name" placeholder="User Name" required>
<input name="role_entitlement" placeholder="Role / Entitlement" required>

<select name="access_source" required>
<option value="">Access Source</option>
<option value="myAccess">myAccess</option>
<option value="Binder">Binder</option>
<option value="Excel">Excel</option>
<option value="Manual">Manual</option>
<option value="System Export">System Export</option>
</select>

<input name="approval_reference" placeholder="Approval Reference e.g. REQ123 / myAccess ID / form reference">
<input name="approver" placeholder="Approver">
<input name="system_owner" placeholder="System Owner">

<select name="review_decision" required>
<option value="">Review Decision</option>
<option value="Approved">Approved</option>
<option value="Remove">Remove</option>
<option value="Modify">Modify</option>
<option value="Pending">Pending</option>
<option value="Exception">Exception</option>
</select>

<select name="privileged_access">
<option value="No">Privileged Access? No</option>
<option value="Yes">Privileged Access? Yes</option>
</select>

<input name="binder_reference" placeholder="Binder / Excel Evidence Reference">
<textarea name="remediation_action" placeholder="Remediation Action / Follow-up"></textarea>

<button type="submit">Save Access Review</button>
</form>
</aside>

<section class="card">
<h2>Recent Access Review Records</h2>
{% if metrics.recent %}
<table>
<tr><th>ID</th><th>Cycle</th><th>System</th><th>User</th><th>Role</th><th>Source</th><th>Decision</th><th>Readiness</th><th>Risk</th></tr>
{% for r in metrics.recent %}
<tr>
<td>{{ r.review_id }}</td>
<td>{{ r.review_cycle }}</td>
<td>{{ r.system_name }}</td>
<td><b>{{ r.user_id }}</b><br>{{ r.user_name }}</td>
<td>{{ r.role_entitlement }}</td>
<td>{{ r.access_source }}</td>
<td>{{ r.review_decision }}</td>
<td><b>{{ r.readiness_status }}</b><br>{{ r.readiness_score }}%</td>
<td class="risk-{{ r.risk_level }}">{{ r.risk_level }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No access review records saved yet.</p>
{% endif %}
</section>
</section>

<div class="card">
<b>Storage design:</b> records are saved separately in <b>access_reviews.csv</b>. Manufacturing logs.csv, SOP comparisons, and shift handoffs are untouched.
</div>
</main>
</body>
</html>
    """

    return render_template_string(html, metrics=metrics, result=result)


# ============================================================
# AUDIT/CAPA V2 TEST ACTIVE
# Functional test page only. Does not replace /audit-capa.
# ============================================================

AUDIT_CAPA_FILE = "audit_capa_register.csv"


def prepare_audit_capa_register():
    df = load_csv(AUDIT_CAPA_FILE)
    return ensure_cols(df, [
        "audit_id", "timestamp", "finding_id", "finding_source", "process_area",
        "severity", "deviation_capa_ref", "capa_owner", "due_date",
        "required_evidence", "evidence_status", "effectiveness_status",
        "sop_update_required", "training_required", "system_change_required",
        "remediation_summary", "readiness_status", "readiness_score",
        "risk_level", "risk_signals", "previous_hash", "record_hash"
    ])


def calculate_audit_capa_readiness(severity, deviation_capa_ref, capa_owner, required_evidence,
                                   evidence_status, effectiveness_status, sop_update_required,
                                   training_required, system_change_required, remediation_summary):
    score = 100
    signals = []

    severity = clean(severity)
    deviation_capa_ref = clean(deviation_capa_ref)
    capa_owner = clean(capa_owner)
    required_evidence = clean(required_evidence)
    evidence_status = clean(evidence_status)
    effectiveness_status = clean(effectiveness_status)
    remediation_summary = clean(remediation_summary)

    if severity in ["High", "Critical"]:
        score -= 10
        signals.append("Finding severity is high or critical.")

    if severity in ["High", "Critical"] and not deviation_capa_ref:
        score -= 25
        signals.append("High/Critical issue has no linked deviation or CAPA reference.")

    if not capa_owner:
        score -= 20
        signals.append("No CAPA owner is assigned.")

    if not required_evidence:
        score -= 15
        signals.append("Required evidence is not defined.")

    if evidence_status in ["Missing", "Partial", "Rejected"]:
        score -= 30
        signals.append("Evidence is missing, partial, or rejected.")

    if effectiveness_status in ["Blocked", "Failed"]:
        score -= 25
        signals.append("Effectiveness readiness is blocked or failed.")

    if effectiveness_status == "Not Started" and evidence_status != "Approved":
        score -= 10
        signals.append("Effectiveness check has not started and evidence is not approved.")

    if sop_update_required == "Yes" and not remediation_summary:
        score -= 10
        signals.append("SOP update is required but remediation summary is missing.")

    if training_required == "Yes" and not remediation_summary:
        score -= 10
        signals.append("Training is required but remediation summary is missing.")

    if system_change_required == "Yes" and not remediation_summary:
        score -= 10
        signals.append("System change is required but remediation summary is missing.")

    score = max(score, 0)

    if score >= 85:
        readiness_status = "EFFECTIVENESS READY"
        risk_level = "LOW"
    elif score >= 60:
        readiness_status = "CONDITIONALLY READY"
        risk_level = "MEDIUM"
    else:
        readiness_status = "NOT READY"
        risk_level = "HIGH"

    if not signals:
        signals.append("No major Audit/CAPA readiness risk detected.")

    return readiness_status, score, risk_level, signals


def save_audit_capa_test(req):
    df = prepare_audit_capa_register()

    finding_id = clean(req.form.get("finding_id"))
    finding_source = clean(req.form.get("finding_source"))
    process_area = clean(req.form.get("process_area"))
    severity = clean(req.form.get("severity"))
    deviation_capa_ref = clean(req.form.get("deviation_capa_ref"))
    capa_owner = clean(req.form.get("capa_owner"))
    due_date = clean(req.form.get("due_date"))
    required_evidence = clean(req.form.get("required_evidence"))
    evidence_status = clean(req.form.get("evidence_status"))
    effectiveness_status = clean(req.form.get("effectiveness_status"))
    sop_update_required = clean(req.form.get("sop_update_required")) or "No"
    training_required = clean(req.form.get("training_required")) or "No"
    system_change_required = clean(req.form.get("system_change_required")) or "No"
    remediation_summary = clean(req.form.get("remediation_summary"))

    required = [finding_id, finding_source, process_area, severity, evidence_status, effectiveness_status]
    if not all(required):
        return {"error": "Finding ID, Finding Source, Process Area, Severity, Evidence Status, and Effectiveness Status are required."}

    readiness_status, readiness_score, risk_level, risk_signals = calculate_audit_capa_readiness(
        severity, deviation_capa_ref, capa_owner, required_evidence,
        evidence_status, effectiveness_status, sop_update_required,
        training_required, system_change_required, remediation_summary
    )

    timestamp = datetime.datetime.utcnow().isoformat()
    audit_id = "AUDITCAPA-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    previous_hash = "GENESIS"
    if not df.empty:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    record_hash = sha256_text(
        audit_id + timestamp + finding_id + finding_source + process_area +
        severity + deviation_capa_ref + capa_owner + evidence_status +
        effectiveness_status + previous_hash
    )

    row = pd.DataFrame([{
        "audit_id": audit_id,
        "timestamp": timestamp,
        "finding_id": finding_id,
        "finding_source": finding_source,
        "process_area": process_area,
        "severity": severity,
        "deviation_capa_ref": deviation_capa_ref,
        "capa_owner": capa_owner,
        "due_date": due_date,
        "required_evidence": required_evidence,
        "evidence_status": evidence_status,
        "effectiveness_status": effectiveness_status,
        "sop_update_required": sop_update_required,
        "training_required": training_required,
        "system_change_required": system_change_required,
        "remediation_summary": remediation_summary,
        "readiness_status": readiness_status,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "risk_signals": " | ".join(risk_signals),
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, AUDIT_CAPA_FILE)

    return {
        "error": "",
        "audit_id": audit_id,
        "readiness_status": readiness_status,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "risk_signals": risk_signals
    }


def get_audit_capa_test_metrics():
    df = prepare_audit_capa_register()
    if df.empty:
        return {"total": 0, "ready": 0, "conditional": 0, "not_ready": 0, "high": 0, "recent": []}

    df = df.fillna("")
    return {
        "total": len(df),
        "ready": len(df[df["readiness_status"] == "EFFECTIVENESS READY"]),
        "conditional": len(df[df["readiness_status"] == "CONDITIONALLY READY"]),
        "not_ready": len(df[df["readiness_status"] == "NOT READY"]),
        "high": len(df[df["risk_level"] == "HIGH"]),
        "recent": df.tail(15).to_dict("records")
    }


@app.route("/audit-capa-v2-test", methods=["GET", "POST"])
def audit_capa_v2_test():
    result = None
    if request.method == "POST":
        result = save_audit_capa_test(request)

    metrics = get_audit_capa_test_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain Audit/CAPA v2 Test</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#1d4ed8);color:white;padding:34px 42px;border-bottom-left-radius:30px;border-bottom-right-radius:30px}
.container{max-width:1450px;margin:-20px auto 50px;padding:0 26px}
.nav,.card,.panel{background:white;border:1px solid #e5e7eb;border-radius:22px;padding:18px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:18px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block}
.nav a.active{background:#0f172a;color:white}
.layout{display:grid;grid-template-columns:390px 1fr;gap:20px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
input,select,textarea,button{width:100%;border-radius:13px;border:1px solid #dbe3ef;padding:11px;margin:6px 0;font-size:14px}
textarea{min-height:85px}
button{border:none;background:linear-gradient(135deg,#2563eb,#06b6d4);color:white;font-weight:900;cursor:pointer}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top}
.risk-HIGH{color:#dc2626;font-weight:900}.risk-MEDIUM{color:#d97706;font-weight:900}.risk-LOW{color:#16a34a;font-weight:900}
@media(max-width:1000px){.layout,.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ Audit/CAPA v2 Test</h1>
<p>Functional test page only — stable /audit-capa is untouched.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/executive-overview">Executive Overview</a>
<a href="/sop-governance">SOP Governance</a>
<a href="/shift-assurance">Shift Assurance</a>
<a href="/access-governance">Access Governance</a>
<a href="/audit-capa">Audit/CAPA v1 Stable</a>
<a class="active" href="/audit-capa-v2-test">Audit/CAPA v2 Test</a>
<a href="/clinical-trial-integrity">Clinical Trial Integrity</a>
</nav>

{% if result and result.error %}
<div class="error">{{ result.error }}</div>
{% elif result %}
<div class="notice">
<b>Saved:</b> {{ result.audit_id }} — <b>{{ result.readiness_status }}</b> — Score <b>{{ result.readiness_score }}%</b>
<ul>{% for s in result.risk_signals %}<li>{{ s }}</li>{% endfor %}</ul>
</div>
{% endif %}

<section class="grid">
<div class="metric"><div class="metric-label">Total Records</div><div class="metric-value">{{ metrics.total }}</div></div>
<div class="metric"><div class="metric-label">Effectiveness Ready</div><div class="metric-value" style="color:#16a34a">{{ metrics.ready }}</div></div>
<div class="metric"><div class="metric-label">Conditional</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional }}</div></div>
<div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ metrics.high }}</div></div>
</section>

<section class="layout">
<aside class="panel">
<h2>Create Audit/CAPA Record</h2>
<form method="POST" action="/audit-capa-v2-test">
<input name="finding_id" placeholder="Finding ID e.g. AUD-2026-001 / NCR-001" required>

<select name="finding_source" required>
<option value="">Finding Source</option>
<option value="Internal Audit">Internal Audit</option>
<option value="External Audit">External Audit</option>
<option value="QA Review">QA Review</option>
<option value="Regulatory Inspection">Regulatory Inspection</option>
<option value="Process Review">Process Review</option>
</select>

<input name="process_area" placeholder="Process/System Area e.g. Speedy Glove / SOP Governance" required>

<select name="severity" required>
<option value="">Severity</option>
<option value="Low">Low</option>
<option value="Medium">Medium</option>
<option value="High">High</option>
<option value="Critical">Critical</option>
</select>

<input name="deviation_capa_ref" placeholder="Deviation / CAPA / NCR Reference">
<input name="capa_owner" placeholder="CAPA Owner">
<label><b>Due Date</b></label>
<input type="date" name="due_date">

<textarea name="required_evidence" placeholder="Required Evidence"></textarea>

<select name="evidence_status" required>
<option value="">Evidence Status</option>
<option value="Missing">Missing</option>
<option value="Partial">Partial</option>
<option value="Uploaded">Uploaded</option>
<option value="Approved">Approved</option>
<option value="Rejected">Rejected</option>
</select>

<select name="effectiveness_status" required>
<option value="">Effectiveness Status</option>
<option value="Not Started">Not Started</option>
<option value="Blocked">Blocked</option>
<option value="Ready">Ready</option>
<option value="In Review">In Review</option>
<option value="Passed">Passed</option>
<option value="Failed">Failed</option>
</select>

<select name="sop_update_required"><option value="No">SOP Update Required? No</option><option value="Yes">SOP Update Required? Yes</option></select>
<select name="training_required"><option value="No">Training Required? No</option><option value="Yes">Training Required? Yes</option></select>
<select name="system_change_required"><option value="No">System Change Required? No</option><option value="Yes">System Change Required? Yes</option></select>

<textarea name="remediation_summary" placeholder="Remediation Summary / Next Action"></textarea>

<button type="submit">Save Audit/CAPA Record</button>
</form>
</aside>

<section class="card">
<h2>Recent Audit/CAPA Records</h2>
{% if metrics.recent %}
<table>
<tr><th>ID</th><th>Finding</th><th>Area</th><th>Severity</th><th>CAPA Ref</th><th>Owner</th><th>Evidence</th><th>Effectiveness</th><th>Readiness</th><th>Risk</th></tr>
{% for r in metrics.recent %}
<tr>
<td>{{ r.audit_id }}</td>
<td><b>{{ r.finding_id }}</b><br>{{ r.finding_source }}</td>
<td>{{ r.process_area }}</td>
<td>{{ r.severity }}</td>
<td>{{ r.deviation_capa_ref }}</td>
<td>{{ r.capa_owner }}</td>
<td>{{ r.evidence_status }}</td>
<td>{{ r.effectiveness_status }}</td>
<td><b>{{ r.readiness_status }}</b><br>{{ r.readiness_score }}%</td>
<td class="risk-{{ r.risk_level }}">{{ r.risk_level }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No Audit/CAPA records saved yet.</p>
{% endif %}
</section>
</section>

<div class="card">
<b>Storage design:</b> records are saved separately in <b>audit_capa_register.csv</b>. Manufacturing, SOP, Shift, Access, and Clinical Trial records are untouched.
</div>
</main>
</body>
</html>
    """

    return render_template_string(html, metrics=metrics, result=result)


# ============================================================
# EXECUTIVE OVERVIEW V3 TEST ACTIVE
# Enterprise dashboard across all module registers.
# Does not replace /executive-overview yet.
# ============================================================

def safe_int(value):
    try:
        return int(float(clean(value)))
    except Exception:
        return 0


def safe_float(value):
    try:
        return float(clean(value))
    except Exception:
        return 0.0


def load_named_register(filename, columns):
    df = load_csv(filename)
    return ensure_cols(df, columns).fillna("")


def get_executive_v3_metrics():
    # Manufacturing
    manufacturing = prepare_logs()
    manufacturing = manufacturing.fillna("")

    m_total = len(manufacturing)
    m_batches = manufacturing["batch_id"].nunique() if not manufacturing.empty else 0
    m_green = len(manufacturing[manufacturing["status"] == "GREEN"]) if not manufacturing.empty else 0
    m_yellow = len(manufacturing[manufacturing["status"] == "YELLOW"]) if not manufacturing.empty else 0
    m_red = len(manufacturing[manufacturing["status"] == "RED"]) if not manufacturing.empty else 0

    # SOP
    sop = load_named_register("sop_comparisons.csv", [
        "comparison_id", "process_area", "gap_count", "high_risk_gap_count",
        "outdated_sop_signals", "technology_gap_signals", "recommended_decision"
    ])
    sop_total = len(sop)
    sop_gaps = sum(safe_int(x) for x in sop["gap_count"]) if not sop.empty else 0
    sop_high = sum(safe_int(x) for x in sop["high_risk_gap_count"]) if not sop.empty else 0

    # Shift
    shift = load_named_register("shift_handoffs.csv", [
        "handoff_id", "readiness_status", "risk_level", "equipment_status", "servicenow_ticket"
    ])
    shift_total = len(shift)
    shift_ready = len(shift[shift["readiness_status"] == "READY"]) if not shift.empty else 0
    shift_conditional = len(shift[shift["readiness_status"] == "CONDITIONALLY READY"]) if not shift.empty else 0
    shift_not_ready = len(shift[shift["readiness_status"] == "NOT READY"]) if not shift.empty else 0
    shift_high = len(shift[shift["risk_level"] == "HIGH"]) if not shift.empty else 0

    # Access
    access = load_named_register("access_reviews.csv", [
        "review_id", "readiness_status", "risk_level", "system_name", "review_decision"
    ])
    access_total = len(access)
    access_ready = len(access[access["readiness_status"] == "AUDIT-READY"]) if not access.empty else 0
    access_conditional = len(access[access["readiness_status"] == "CONDITIONALLY READY"]) if not access.empty else 0
    access_not_ready = len(access[access["readiness_status"] == "NOT AUDIT-READY"]) if not access.empty else 0
    access_high = len(access[access["risk_level"] == "HIGH"]) if not access.empty else 0

    # Audit/CAPA
    audit = load_named_register("audit_capa_register.csv", [
        "audit_id", "readiness_status", "risk_level", "severity", "evidence_status", "effectiveness_status"
    ])
    audit_total = len(audit)
    audit_ready = len(audit[audit["readiness_status"] == "EFFECTIVENESS READY"]) if not audit.empty else 0
    audit_conditional = len(audit[audit["readiness_status"] == "CONDITIONALLY READY"]) if not audit.empty else 0
    audit_not_ready = len(audit[audit["readiness_status"] == "NOT READY"]) if not audit.empty else 0
    audit_high = len(audit[audit["risk_level"] == "HIGH"]) if not audit.empty else 0

    # Clinical Trial future register
    clinical = load_named_register("clinical_trial_evidence.csv", [
        "evidence_id", "study_id", "protocol_obligation", "purview_status",
        "retention_status", "alcoa_score", "inspection_readiness"
    ])
    clinical_total = len(clinical)

    total_records = m_total + sop_total + shift_total + access_total + audit_total + clinical_total
    high_risk_total = m_red + sop_high + shift_high + access_high + audit_high
    conditional_total = m_yellow + shift_conditional + access_conditional + audit_conditional

    if high_risk_total > 0:
        enterprise_status = "CRITICAL GOVERNANCE ATTENTION REQUIRED"
        enterprise_icon = "❌"
        enterprise_class = "critical"
    elif conditional_total > 0:
        enterprise_status = "CONDITIONAL ENTERPRISE READINESS"
        enterprise_icon = "⚠"
        enterprise_class = "warning"
    elif total_records > 0:
        enterprise_status = "ENTERPRISE GOVERNANCE BASELINE HEALTHY"
        enterprise_icon = "✅"
        enterprise_class = "healthy"
    else:
        enterprise_status = "NO ENTERPRISE RECORDS YET"
        enterprise_icon = "ℹ"
        enterprise_class = "neutral"

    module_rows = [
        {
            "module": "Manufacturing Assurance",
            "route": "/",
            "register": "logs.csv",
            "records": m_total,
            "ready": m_green,
            "conditional": m_yellow,
            "not_ready": m_red,
            "high_risk": m_red,
            "status": "ACTIVE"
        },
        {
            "module": "SOP Governance",
            "route": "/sop-governance",
            "register": "sop_comparisons.csv",
            "records": sop_total,
            "ready": max(sop_total - sop_high, 0),
            "conditional": sop_gaps,
            "not_ready": sop_high,
            "high_risk": sop_high,
            "status": "ACTIVE"
        },
        {
            "module": "Shift Assurance",
            "route": "/shift-assurance",
            "register": "shift_handoffs.csv",
            "records": shift_total,
            "ready": shift_ready,
            "conditional": shift_conditional,
            "not_ready": shift_not_ready,
            "high_risk": shift_high,
            "status": "ACTIVE"
        },
        {
            "module": "Access Governance",
            "route": "/access-governance",
            "register": "access_reviews.csv",
            "records": access_total,
            "ready": access_ready,
            "conditional": access_conditional,
            "not_ready": access_not_ready,
            "high_risk": access_high,
            "status": "ACTIVE"
        },
        {
            "module": "Audit/CAPA",
            "route": "/audit-capa",
            "register": "audit_capa_register.csv",
            "records": audit_total,
            "ready": audit_ready,
            "conditional": audit_conditional,
            "not_ready": audit_not_ready,
            "high_risk": audit_high,
            "status": "ACTIVE"
        },
        {
            "module": "Clinical Trial Integrity",
            "route": "/clinical-trial-integrity",
            "register": "clinical_trial_evidence.csv",
            "records": clinical_total,
            "ready": 0,
            "conditional": 0,
            "not_ready": 0,
            "high_risk": 0,
            "status": "PURVIEW OVERVIEW ACTIVE / REGISTER FUTURE"
        }
    ]

    recommended_actions = []

    if m_red > 0:
        recommended_actions.append("Manufacturing: review RED hash/integrity records before audit reliance.")
    if sop_high > 0:
        recommended_actions.append("SOP Governance: review high-risk SOP harmonization gaps and outdated SOP signals.")
    if shift_high > 0:
        recommended_actions.append("Shift Assurance: review high-risk equipment handoffs and unresolved carryover items.")
    if access_high > 0:
        recommended_actions.append("Access Governance: remediate high-risk access review records and missing approvals.")
    if audit_high > 0:
        recommended_actions.append("Audit/CAPA: resolve high-risk CAPA readiness blockers before effectiveness review.")
    if clinical_total == 0:
        recommended_actions.append("Clinical Trial Integrity: next build should create clinical_trial_evidence.csv for Purview + ALCOA+ evidence tracking.")

    if not recommended_actions:
        recommended_actions.append("Maintain evidence upload discipline and continue expanding functional registers module by module.")

    return {
        "enterprise_status": enterprise_status,
        "enterprise_icon": enterprise_icon,
        "enterprise_class": enterprise_class,
        "total_records": total_records,
        "high_risk_total": high_risk_total,
        "conditional_total": conditional_total,
        "manufacturing_batches": m_batches,
        "module_rows": module_rows,
        "recommended_actions": recommended_actions
    }


@app.route("/executive-overview-v3-test")
def executive_overview_v3_test():
    metrics = get_executive_v3_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain Executive Overview v3 Test</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#1d4ed8);color:white;padding:34px 42px;border-bottom-left-radius:30px;border-bottom-right-radius:30px}
.container{max-width:1450px;margin:-20px auto 50px;padding:0 26px}
.nav,.card{background:white;border:1px solid #e5e7eb;border-radius:22px;padding:18px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:18px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
.status-card{border-left:8px solid #64748b}
.status-card.healthy{border-left-color:#16a34a;background:linear-gradient(135deg,#f0fdf4,#ffffff)}
.status-card.warning{border-left-color:#f59e0b;background:linear-gradient(135deg,#fffbeb,#ffffff)}
.status-card.critical{border-left-color:#dc2626;background:linear-gradient(135deg,#fef2f2,#ffffff)}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:13px}
th{background:#0f172a;color:white;text-align:left;padding:11px}
td{border-bottom:1px solid #e5e7eb;padding:11px;vertical-align:top}
.risk{font-weight:900}.high{color:#dc2626}.medium{color:#d97706}.low{color:#16a34a}
a.module-link{font-weight:900;color:#2563eb;text-decoration:none}
@media(max-width:1000px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ Executive Overview v3 Test</h1>
<p>Enterprise dashboard across Manufacturing, SOP, Shift, Access, Audit/CAPA, and Clinical Trial Integrity.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/executive-overview">Executive v2</a>
<a class="active" href="/executive-overview-v3-test">Executive v3 Test</a>
<a href="/sop-governance">SOP</a>
<a href="/shift-assurance">Shift</a>
<a href="/access-governance">Access</a>
<a href="/audit-capa">Audit/CAPA</a>
<a href="/clinical-trial-integrity">Clinical Trial</a>
</nav>

<div class="card status-card {{ metrics.enterprise_class }}">
<h2>{{ metrics.enterprise_icon }} {{ metrics.enterprise_status }}</h2>
<p>This page summarizes all active COBIT-Chain enterprise registers without replacing the current Executive Overview yet.</p>
</div>

<section class="grid">
<div class="metric"><div class="metric-label">Total Enterprise Records</div><div class="metric-value">{{ metrics.total_records }}</div></div>
<div class="metric"><div class="metric-label">High-Risk Items</div><div class="metric-value" style="color:#dc2626">{{ metrics.high_risk_total }}</div></div>
<div class="metric"><div class="metric-label">Conditional Items</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional_total }}</div></div>
<div class="metric"><div class="metric-label">Manufacturing Batches</div><div class="metric-value">{{ metrics.manufacturing_batches }}</div></div>
</section>

<div class="card">
<h2>Enterprise Module Register Board</h2>
<table>
<tr>
<th>Module</th><th>Register</th><th>Records</th><th>Ready</th><th>Conditional</th><th>Not Ready</th><th>High Risk</th><th>Status</th>
</tr>
{% for m in metrics.module_rows %}
<tr>
<td><a class="module-link" href="{{ m.route }}">{{ m.module }}</a></td>
<td>{{ m.register }}</td>
<td><b>{{ m.records }}</b></td>
<td class="risk low">{{ m.ready }}</td>
<td class="risk medium">{{ m.conditional }}</td>
<td class="risk high">{{ m.not_ready }}</td>
<td class="risk high">{{ m.high_risk }}</td>
<td>{{ m.status }}</td>
</tr>
{% endfor %}
</table>
</div>

<div class="card">
<h2>Recommended Leadership Actions</h2>
<ul>
{% for action in metrics.recommended_actions %}
<li>{{ action }}</li>
{% endfor %}
</ul>
</div>

<div class="card">
<h2>Governance Meaning</h2>
<p>
Executive Overview v3 turns COBIT-Chain from separate module pages into an enterprise governance control tower.
It reads each module register separately, summarizes readiness, identifies high-risk items, and keeps the original
Manufacturing/Manufacturing Core evidence chain protected.
</p>
</div>
</main>
</body>
</html>
    """

    return render_template_string(html, metrics=metrics)


# ============================================================
# CLINICAL TRIAL V3 TEST ACTIVE
# Functional clinical trial evidence register.
# Does not replace /clinical-trial-integrity.
# ============================================================

CLINICAL_TRIAL_FILE = "clinical_trial_evidence.csv"


def prepare_clinical_trial_evidence():
    df = load_csv(CLINICAL_TRIAL_FILE)
    return ensure_cols(df, [
        "evidence_id", "timestamp", "study_id", "protocol_id",
        "site_id", "subject_visit_ref", "protocol_obligation",
        "evidence_type", "evidence_artifact", "purview_dlp_status",
        "retention_label_status", "sensitivity_status",
        "evidence_owner", "reviewer", "deviation_capa_link",
        "alcoa_score", "inspection_readiness", "risk_level",
        "risk_signals", "previous_hash", "record_hash"
    ])


def calculate_clinical_readiness(purview_dlp_status, retention_label_status, sensitivity_status,
                                 evidence_owner, reviewer, deviation_capa_link,
                                 evidence_type, evidence_artifact, protocol_obligation):
    score = 100
    signals = []

    purview_dlp_status = clean(purview_dlp_status)
    retention_label_status = clean(retention_label_status)
    sensitivity_status = clean(sensitivity_status)
    evidence_owner = clean(evidence_owner)
    reviewer = clean(reviewer)
    deviation_capa_link = clean(deviation_capa_link)
    evidence_type = clean(evidence_type)
    evidence_artifact = clean(evidence_artifact)
    protocol_obligation = clean(protocol_obligation)

    if not protocol_obligation:
        score -= 20
        signals.append("Protocol obligation is missing.")

    if not evidence_artifact:
        score -= 25
        signals.append("Evidence artifact/reference is missing.")

    if purview_dlp_status in ["Not Tested", "Failed", "Policy Not Triggered"]:
        score -= 20
        signals.append("Purview DLP status is not confirmed or did not trigger as expected.")

    if retention_label_status in ["Missing", "Not Applied", "Unknown"]:
        score -= 20
        signals.append("Retention label/record status is missing or unknown.")

    if sensitivity_status in ["Unclassified", "Unknown"]:
        score -= 10
        signals.append("Sensitivity/classification status is not confirmed.")

    if not evidence_owner:
        score -= 10
        signals.append("Evidence owner is missing.")

    if not reviewer:
        score -= 10
        signals.append("Reviewer is missing.")

    if evidence_type in ["eConsent", "Subject Source Data"] and not deviation_capa_link and score < 80:
        score -= 10
        signals.append("High-value trial evidence has readiness issues but no deviation/CAPA link.")

    score = max(score, 0)

    if score >= 85:
        readiness = "INSPECTION READY"
        risk = "LOW"
    elif score >= 60:
        readiness = "CONDITIONALLY READY"
        risk = "MEDIUM"
    else:
        readiness = "NOT INSPECTION READY"
        risk = "HIGH"

    if not signals:
        signals.append("No major clinical trial evidence readiness risk detected.")

    return readiness, score, risk, signals


def save_clinical_trial_evidence_test(req):
    df = prepare_clinical_trial_evidence()

    study_id = clean(req.form.get("study_id"))
    protocol_id = clean(req.form.get("protocol_id"))
    site_id = clean(req.form.get("site_id"))
    subject_visit_ref = clean(req.form.get("subject_visit_ref"))
    protocol_obligation = clean(req.form.get("protocol_obligation"))
    evidence_type = clean(req.form.get("evidence_type"))
    evidence_artifact = clean(req.form.get("evidence_artifact"))
    purview_dlp_status = clean(req.form.get("purview_dlp_status"))
    retention_label_status = clean(req.form.get("retention_label_status"))
    sensitivity_status = clean(req.form.get("sensitivity_status"))
    evidence_owner = clean(req.form.get("evidence_owner"))
    reviewer = clean(req.form.get("reviewer"))
    deviation_capa_link = clean(req.form.get("deviation_capa_link"))

    required = [
        study_id, protocol_id, protocol_obligation, evidence_type,
        evidence_artifact, purview_dlp_status, retention_label_status
    ]

    if not all(required):
        return {
            "error": "Study ID, Protocol ID, Protocol Obligation, Evidence Type, Evidence Artifact, Purview DLP Status, and Retention Label Status are required."
        }

    readiness, alcoa_score, risk_level, risk_signals = calculate_clinical_readiness(
        purview_dlp_status, retention_label_status, sensitivity_status,
        evidence_owner, reviewer, deviation_capa_link,
        evidence_type, evidence_artifact, protocol_obligation
    )

    timestamp = datetime.datetime.utcnow().isoformat()
    evidence_id = "CTE-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    previous_hash = "GENESIS"
    if not df.empty:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    record_hash = sha256_text(
        evidence_id + timestamp + study_id + protocol_id + site_id +
        subject_visit_ref + protocol_obligation + evidence_type +
        evidence_artifact + purview_dlp_status + retention_label_status +
        previous_hash
    )

    row = pd.DataFrame([{
        "evidence_id": evidence_id,
        "timestamp": timestamp,
        "study_id": study_id,
        "protocol_id": protocol_id,
        "site_id": site_id,
        "subject_visit_ref": subject_visit_ref,
        "protocol_obligation": protocol_obligation,
        "evidence_type": evidence_type,
        "evidence_artifact": evidence_artifact,
        "purview_dlp_status": purview_dlp_status,
        "retention_label_status": retention_label_status,
        "sensitivity_status": sensitivity_status,
        "evidence_owner": evidence_owner,
        "reviewer": reviewer,
        "deviation_capa_link": deviation_capa_link,
        "alcoa_score": alcoa_score,
        "inspection_readiness": readiness,
        "risk_level": risk_level,
        "risk_signals": " | ".join(risk_signals),
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, CLINICAL_TRIAL_FILE)

    return {
        "error": "",
        "evidence_id": evidence_id,
        "inspection_readiness": readiness,
        "alcoa_score": alcoa_score,
        "risk_level": risk_level,
        "risk_signals": risk_signals
    }


def get_clinical_trial_test_metrics():
    df = prepare_clinical_trial_evidence()
    if df.empty:
        return {"total": 0, "ready": 0, "conditional": 0, "not_ready": 0, "high": 0, "recent": []}

    df = df.fillna("")
    return {
        "total": len(df),
        "ready": len(df[df["inspection_readiness"] == "INSPECTION READY"]),
        "conditional": len(df[df["inspection_readiness"] == "CONDITIONALLY READY"]),
        "not_ready": len(df[df["inspection_readiness"] == "NOT INSPECTION READY"]),
        "high": len(df[df["risk_level"] == "HIGH"]),
        "recent": df.tail(15).to_dict("records")
    }


@app.route("/clinical-trial-integrity-v3-test", methods=["GET", "POST"])
def clinical_trial_integrity_v3_test():
    result = None
    if request.method == "POST":
        result = save_clinical_trial_evidence_test(request)

    metrics = get_clinical_trial_test_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain Clinical Trial Integrity v3 Test</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#1d4ed8);color:white;padding:34px 42px;border-bottom-left-radius:30px;border-bottom-right-radius:30px}
.container{max-width:1450px;margin:-20px auto 50px;padding:0 26px}
.nav,.card,.panel{background:white;border:1px solid #e5e7eb;border-radius:22px;padding:18px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:18px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block}
.nav a.active{background:#0f172a;color:white}
.layout{display:grid;grid-template-columns:410px 1fr;gap:20px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
input,select,textarea,button{width:100%;border-radius:13px;border:1px solid #dbe3ef;padding:11px;margin:6px 0;font-size:14px}
textarea{min-height:85px}
button{border:none;background:linear-gradient(135deg,#2563eb,#06b6d4);color:white;font-weight:900;cursor:pointer}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top}
.risk-HIGH{color:#dc2626;font-weight:900}.risk-MEDIUM{color:#d97706;font-weight:900}.risk-LOW{color:#16a34a;font-weight:900}
@media(max-width:1000px){.layout,.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ Clinical Trial Integrity v3 Test</h1>
<p>Functional clinical-trial evidence register — Purview, retention, ALCOA+, and inspection readiness.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/executive-overview">Executive Overview</a>
<a href="/sop-governance">SOP</a>
<a href="/shift-assurance">Shift</a>
<a href="/access-governance">Access</a>
<a href="/audit-capa">Audit/CAPA</a>
<a href="/clinical-trial-integrity">Clinical v2 Stable</a>
<a class="active" href="/clinical-trial-integrity-v3-test">Clinical v3 Test</a>
</nav>

{% if result and result.error %}
<div class="error">{{ result.error }}</div>
{% elif result %}
<div class="notice">
<b>Saved:</b> {{ result.evidence_id }} —
<b>{{ result.inspection_readiness }}</b> —
ALCOA+ readiness score <b>{{ result.alcoa_score }}%</b>
<ul>{% for s in result.risk_signals %}<li>{{ s }}</li>{% endfor %}</ul>
</div>
{% endif %}

<section class="grid">
<div class="metric"><div class="metric-label">Total Evidence Records</div><div class="metric-value">{{ metrics.total }}</div></div>
<div class="metric"><div class="metric-label">Inspection Ready</div><div class="metric-value" style="color:#16a34a">{{ metrics.ready }}</div></div>
<div class="metric"><div class="metric-label">Conditional</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional }}</div></div>
<div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ metrics.high }}</div></div>
</section>

<section class="layout">
<aside class="panel">
<h2>Create Clinical Evidence Record</h2>
<form method="POST" action="/clinical-trial-integrity-v3-test">
<input name="study_id" placeholder="Study ID e.g. STUDY-001" required>
<input name="protocol_id" placeholder="Protocol ID / Amendment e.g. PROT-001-A2" required>
<input name="site_id" placeholder="Site ID e.g. SITE-IND-01">
<input name="subject_visit_ref" placeholder="Subject / Visit Reference e.g. SUBJ-001 / Visit 2">

<textarea name="protocol_obligation" placeholder="Protocol Obligation e.g. eConsent must be completed before trial procedure" required></textarea>

<select name="evidence_type" required>
<option value="">Evidence Type</option>
<option value="eConsent">eConsent</option>
<option value="Subject Source Data">Subject Source Data</option>
<option value="EDC Export">EDC Export</option>
<option value="TMF Artifact">TMF Artifact</option>
<option value="Monitoring Report">Monitoring Report</option>
<option value="Vendor CSV">Vendor CSV</option>
<option value="Safety Record">Safety Record</option>
</select>

<textarea name="evidence_artifact" placeholder="Evidence Artifact / SharePoint / File / Reference" required></textarea>

<select name="purview_dlp_status" required>
<option value="">Purview DLP Status</option>
<option value="Passed">Passed</option>
<option value="Matched">Matched</option>
<option value="Alerted">Alerted</option>
<option value="Policy Not Triggered">Policy Not Triggered</option>
<option value="Failed">Failed</option>
<option value="Not Tested">Not Tested</option>
</select>

<select name="retention_label_status" required>
<option value="">Retention Label Status</option>
<option value="Applied">Applied</option>
<option value="Record">Record</option>
<option value="Regulatory Record">Regulatory Record</option>
<option value="Missing">Missing</option>
<option value="Not Applied">Not Applied</option>
<option value="Unknown">Unknown</option>
</select>

<select name="sensitivity_status">
<option value="Classified">Sensitivity/Classified</option>
<option value="Unclassified">Unclassified</option>
<option value="Unknown">Unknown</option>
</select>

<input name="evidence_owner" placeholder="Evidence Owner">
<input name="reviewer" placeholder="Reviewer / QA / Monitor">
<input name="deviation_capa_link" placeholder="Deviation / CAPA Link if applicable">

<button type="submit">Save Clinical Evidence</button>
</form>
</aside>

<section class="card">
<h2>Recent Clinical Trial Evidence Records</h2>
{% if metrics.recent %}
<table>
<tr><th>ID</th><th>Study</th><th>Evidence</th><th>Purview</th><th>Retention</th><th>ALCOA+</th><th>Readiness</th><th>Risk</th></tr>
{% for r in metrics.recent %}
<tr>
<td>{{ r.evidence_id }}</td>
<td><b>{{ r.study_id }}</b><br>{{ r.protocol_id }}</td>
<td><b>{{ r.evidence_type }}</b><br>{{ r.evidence_artifact }}</td>
<td>{{ r.purview_dlp_status }}</td>
<td>{{ r.retention_label_status }}</td>
<td>{{ r.alcoa_score }}%</td>
<td><b>{{ r.inspection_readiness }}</b></td>
<td class="risk-{{ r.risk_level }}">{{ r.risk_level }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No clinical trial evidence records saved yet.</p>
{% endif %}
</section>
</section>

<div class="card">
<b>Storage design:</b> records are saved separately in <b>clinical_trial_evidence.csv</b>.
Manufacturing, SOP, Shift, Access, and Audit/CAPA registers are untouched.
</div>
</main>
</body>
</html>
    """

    return render_template_string(html, metrics=metrics, result=result)


# ============================================================
# COMPOUNDING PHARMACY V1 TEST ACTIVE
# Functional compounding pharmacy evidence register.
# Does not replace or modify existing modules.
# ============================================================

COMPOUNDING_PHARMACY_FILE = "compounding_pharmacy_evidence.csv"


def prepare_compounding_pharmacy_evidence():
    df = load_csv(COMPOUNDING_PHARMACY_FILE)
    return ensure_cols(df, [
        "compound_record_id", "timestamp", "order_id", "formula_name",
        "compound_type", "preparation_risk", "ingredient_lot_status",
        "operator_training_status", "environmental_monitoring_status",
        "cleaning_status", "garbing_status", "qa_review_status",
        "bud_status", "deviation_capa_link", "release_decision",
        "readiness_status", "readiness_score", "risk_level",
        "risk_signals", "previous_hash", "record_hash"
    ])


def calculate_compounding_readiness(preparation_risk, ingredient_lot_status,
                                    operator_training_status, environmental_monitoring_status,
                                    cleaning_status, garbing_status, qa_review_status,
                                    bud_status, deviation_capa_link, release_decision):
    score = 100
    signals = []

    preparation_risk = clean(preparation_risk)
    ingredient_lot_status = clean(ingredient_lot_status)
    operator_training_status = clean(operator_training_status)
    environmental_monitoring_status = clean(environmental_monitoring_status)
    cleaning_status = clean(cleaning_status)
    garbing_status = clean(garbing_status)
    qa_review_status = clean(qa_review_status)
    bud_status = clean(bud_status)
    deviation_capa_link = clean(deviation_capa_link)
    release_decision = clean(release_decision)

    if preparation_risk in ["High Risk", "Hazardous", "Sterile"]:
        score -= 10
        signals.append("Preparation has elevated compounding risk and requires strong evidence control.")

    if ingredient_lot_status in ["Missing", "Incomplete", "Unverified"]:
        score -= 25
        signals.append("Ingredient/lot evidence is missing, incomplete, or unverified.")

    if operator_training_status in ["Missing", "Expired", "Not Verified"]:
        score -= 20
        signals.append("Operator training or competency evidence is missing, expired, or not verified.")

    if environmental_monitoring_status in ["Missing", "Failed", "Out of Trend", "Not Reviewed"]:
        score -= 25
        signals.append("Environmental monitoring evidence is missing, failed, out of trend, or not reviewed.")

    if cleaning_status in ["Missing", "Failed", "Not Verified"]:
        score -= 20
        signals.append("Cleaning evidence is missing, failed, or not verified.")

    if garbing_status in ["Missing", "Failed", "Not Verified"]:
        score -= 15
        signals.append("Garbing/aseptic practice evidence is missing, failed, or not verified.")

    if qa_review_status in ["Missing", "Pending", "Rejected"]:
        score -= 20
        signals.append("QA review is missing, pending, or rejected.")

    if bud_status in ["Missing", "Unsupported", "Expired"]:
        score -= 20
        signals.append("Beyond-use-date evidence is missing, unsupported, or expired.")

    if release_decision == "Released" and score < 85:
        score -= 15
        signals.append("Preparation is marked released even though readiness evidence is incomplete.")

    if release_decision in ["Hold", "Rejected"] and not deviation_capa_link:
        score -= 10
        signals.append("Hold/rejection exists without deviation or CAPA linkage.")

    score = max(score, 0)

    if score >= 85:
        readiness = "RELEASE READY"
        risk = "LOW"
    elif score >= 60:
        readiness = "CONDITIONALLY READY"
        risk = "MEDIUM"
    else:
        readiness = "NOT RELEASE READY"
        risk = "HIGH"

    if not signals:
        signals.append("No major compounding release-readiness risk detected.")

    return readiness, score, risk, signals


def save_compounding_pharmacy_test(req):
    df = prepare_compounding_pharmacy_evidence()

    order_id = clean(req.form.get("order_id"))
    formula_name = clean(req.form.get("formula_name"))
    compound_type = clean(req.form.get("compound_type"))
    preparation_risk = clean(req.form.get("preparation_risk"))
    ingredient_lot_status = clean(req.form.get("ingredient_lot_status"))
    operator_training_status = clean(req.form.get("operator_training_status"))
    environmental_monitoring_status = clean(req.form.get("environmental_monitoring_status"))
    cleaning_status = clean(req.form.get("cleaning_status"))
    garbing_status = clean(req.form.get("garbing_status"))
    qa_review_status = clean(req.form.get("qa_review_status"))
    bud_status = clean(req.form.get("bud_status"))
    deviation_capa_link = clean(req.form.get("deviation_capa_link"))
    release_decision = clean(req.form.get("release_decision"))

    required = [
        order_id, formula_name, compound_type, preparation_risk,
        ingredient_lot_status, operator_training_status,
        environmental_monitoring_status, cleaning_status,
        garbing_status, qa_review_status, bud_status, release_decision
    ]

    if not all(required):
        return {
            "error": "Order ID, Formula Name, Compound Type, Risk, all evidence statuses, BUD Status, and Release Decision are required."
        }

    readiness, readiness_score, risk_level, risk_signals = calculate_compounding_readiness(
        preparation_risk, ingredient_lot_status, operator_training_status,
        environmental_monitoring_status, cleaning_status, garbing_status,
        qa_review_status, bud_status, deviation_capa_link, release_decision
    )

    timestamp = datetime.datetime.utcnow().isoformat()
    compound_record_id = "CP-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    previous_hash = "GENESIS"
    if not df.empty:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    record_hash = sha256_text(
        compound_record_id + timestamp + order_id + formula_name + compound_type +
        preparation_risk + ingredient_lot_status + operator_training_status +
        environmental_monitoring_status + cleaning_status + garbing_status +
        qa_review_status + bud_status + release_decision + previous_hash
    )

    row = pd.DataFrame([{
        "compound_record_id": compound_record_id,
        "timestamp": timestamp,
        "order_id": order_id,
        "formula_name": formula_name,
        "compound_type": compound_type,
        "preparation_risk": preparation_risk,
        "ingredient_lot_status": ingredient_lot_status,
        "operator_training_status": operator_training_status,
        "environmental_monitoring_status": environmental_monitoring_status,
        "cleaning_status": cleaning_status,
        "garbing_status": garbing_status,
        "qa_review_status": qa_review_status,
        "bud_status": bud_status,
        "deviation_capa_link": deviation_capa_link,
        "release_decision": release_decision,
        "readiness_status": readiness,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "risk_signals": " | ".join(risk_signals),
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, COMPOUNDING_PHARMACY_FILE)

    return {
        "error": "",
        "compound_record_id": compound_record_id,
        "readiness_status": readiness,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "risk_signals": risk_signals
    }


def get_compounding_pharmacy_test_metrics():
    df = prepare_compounding_pharmacy_evidence()
    if df.empty:
        return {"total": 0, "ready": 0, "conditional": 0, "not_ready": 0, "high": 0, "recent": []}

    df = df.fillna("")
    return {
        "total": len(df),
        "ready": len(df[df["readiness_status"] == "RELEASE READY"]),
        "conditional": len(df[df["readiness_status"] == "CONDITIONALLY READY"]),
        "not_ready": len(df[df["readiness_status"] == "NOT RELEASE READY"]),
        "high": len(df[df["risk_level"] == "HIGH"]),
        "recent": df.tail(15).to_dict("records")
    }


@app.route("/compounding-pharmacy-v1-test", methods=["GET", "POST"])
def compounding_pharmacy_v1_test():
    result = None
    if request.method == "POST":
        result = save_compounding_pharmacy_test(request)

    metrics = get_compounding_pharmacy_test_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain Compounding Pharmacy v1 Test</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#1d4ed8);color:white;padding:34px 42px;border-bottom-left-radius:30px;border-bottom-right-radius:30px}
.container{max-width:1450px;margin:-20px auto 50px;padding:0 26px}
.nav,.card,.panel{background:white;border:1px solid #e5e7eb;border-radius:22px;padding:18px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:18px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block}
.nav a.active{background:#0f172a;color:white}
.layout{display:grid;grid-template-columns:410px 1fr;gap:20px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
input,select,textarea,button{width:100%;border-radius:13px;border:1px solid #dbe3ef;padding:11px;margin:6px 0;font-size:14px}
button{border:none;background:linear-gradient(135deg,#2563eb,#06b6d4);color:white;font-weight:900;cursor:pointer}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top}
.risk-HIGH{color:#dc2626;font-weight:900}.risk-MEDIUM{color:#d97706;font-weight:900}.risk-LOW{color:#16a34a;font-weight:900}
@media(max-width:1000px){.layout,.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ Compounding Pharmacy v1 Test</h1>
<p>Sterility-to-Release Evidence Graph™ • Release Readiness • Inspection Evidence</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/executive-overview">Executive</a>
<a href="/sop-governance">SOP</a>
<a href="/shift-assurance">Shift</a>
<a href="/access-governance">Access</a>
<a href="/audit-capa">Audit/CAPA</a>
<a href="/clinical-trial-integrity">Clinical Trial</a>
<a class="active" href="/compounding-pharmacy-v1-test">Compounding Pharmacy</a>
</nav>

{% if result and result.error %}
<div class="error">{{ result.error }}</div>
{% elif result %}
<div class="notice">
<b>Saved:</b> {{ result.compound_record_id }} —
<b>{{ result.readiness_status }}</b> —
Readiness score <b>{{ result.readiness_score }}%</b>
<ul>{% for s in result.risk_signals %}<li>{{ s }}</li>{% endfor %}</ul>
</div>
{% endif %}

<section class="grid">
<div class="metric"><div class="metric-label">Total Records</div><div class="metric-value">{{ metrics.total }}</div></div>
<div class="metric"><div class="metric-label">Release Ready</div><div class="metric-value" style="color:#16a34a">{{ metrics.ready }}</div></div>
<div class="metric"><div class="metric-label">Conditional</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional }}</div></div>
<div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ metrics.high }}</div></div>
</section>

<section class="layout">
<aside class="panel">
<h2>Create Compounding Evidence Record</h2>
<form method="POST" action="/compounding-pharmacy-v1-test">
<input name="order_id" placeholder="Order / Batch / Prescription ID e.g. RX-CP-001" required>
<input name="formula_name" placeholder="Formula / Preparation Name" required>

<select name="compound_type" required>
<option value="">Compound Type</option>
<option value="Sterile">Sterile</option>
<option value="Non-Sterile">Non-Sterile</option>
<option value="Hazardous">Hazardous</option>
<option value="Patient-Specific">Patient-Specific</option>
<option value="Batch Preparation">Batch Preparation</option>
</select>

<select name="preparation_risk" required>
<option value="">Preparation Risk</option>
<option value="Low Risk">Low Risk</option>
<option value="Medium Risk">Medium Risk</option>
<option value="High Risk">High Risk</option>
<option value="Sterile">Sterile</option>
<option value="Hazardous">Hazardous</option>
</select>

<select name="ingredient_lot_status" required>
<option value="">Ingredient/Lot Evidence</option>
<option value="Verified">Verified</option>
<option value="Incomplete">Incomplete</option>
<option value="Missing">Missing</option>
<option value="Unverified">Unverified</option>
</select>

<select name="operator_training_status" required>
<option value="">Operator Training</option>
<option value="Verified">Verified</option>
<option value="Expired">Expired</option>
<option value="Missing">Missing</option>
<option value="Not Verified">Not Verified</option>
</select>

<select name="environmental_monitoring_status" required>
<option value="">Environmental Monitoring</option>
<option value="Reviewed">Reviewed</option>
<option value="Not Reviewed">Not Reviewed</option>
<option value="Out of Trend">Out of Trend</option>
<option value="Failed">Failed</option>
<option value="Missing">Missing</option>
</select>

<select name="cleaning_status" required>
<option value="">Cleaning Evidence</option>
<option value="Verified">Verified</option>
<option value="Not Verified">Not Verified</option>
<option value="Failed">Failed</option>
<option value="Missing">Missing</option>
</select>

<select name="garbing_status" required>
<option value="">Garbing / Aseptic Evidence</option>
<option value="Verified">Verified</option>
<option value="Not Verified">Not Verified</option>
<option value="Failed">Failed</option>
<option value="Missing">Missing</option>
</select>

<select name="qa_review_status" required>
<option value="">QA Review</option>
<option value="Approved">Approved</option>
<option value="Pending">Pending</option>
<option value="Rejected">Rejected</option>
<option value="Missing">Missing</option>
</select>

<select name="bud_status" required>
<option value="">Beyond-Use-Date Evidence</option>
<option value="Supported">Supported</option>
<option value="Unsupported">Unsupported</option>
<option value="Expired">Expired</option>
<option value="Missing">Missing</option>
</select>

<input name="deviation_capa_link" placeholder="Deviation / CAPA Link if applicable">

<select name="release_decision" required>
<option value="">Release Decision</option>
<option value="Released">Released</option>
<option value="Hold">Hold</option>
<option value="Rejected">Rejected</option>
<option value="Pending QA Review">Pending QA Review</option>
</select>

<button type="submit">Save Compounding Evidence</button>
</form>
</aside>

<section class="card">
<h2>Recent Compounding Pharmacy Records</h2>
{% if metrics.recent %}
<table>
<tr><th>ID</th><th>Order</th><th>Formula</th><th>Type</th><th>EM</th><th>QA</th><th>BUD</th><th>Decision</th><th>Readiness</th><th>Risk</th></tr>
{% for r in metrics.recent %}
<tr>
<td>{{ r.compound_record_id }}</td>
<td>{{ r.order_id }}</td>
<td>{{ r.formula_name }}</td>
<td>{{ r.compound_type }}</td>
<td>{{ r.environmental_monitoring_status }}</td>
<td>{{ r.qa_review_status }}</td>
<td>{{ r.bud_status }}</td>
<td>{{ r.release_decision }}</td>
<td><b>{{ r.readiness_status }}</b><br>{{ r.readiness_score }}%</td>
<td class="risk-{{ r.risk_level }}">{{ r.risk_level }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No compounding pharmacy evidence records saved yet.</p>
{% endif %}
</section>
</section>

<div class="card">
<b>Storage design:</b> records are saved separately in <b>compounding_pharmacy_evidence.csv</b>.
Manufacturing, SOP, Shift, Access, Audit/CAPA, and Clinical Trial registers are untouched.
</div>

<div class="card">
<h2>Advanced Feature Direction</h2>
<p><b>Sterility-to-Release Evidence Graph™</b> links order, formulation, ingredient lots, operator training, environmental monitoring, cleaning, garbing, QA review, deviations, BUD support, and final release decision into one inspection-ready chain.</p>
</div>
</main>
</body>
</html>
    """

    return render_template_string(html, metrics=metrics, result=result)


# ============================================================
# RLT-TRUST V1 TEST ACTIVE
# Radiopharma / RLT dose evidence register.
# Does not replace or modify existing modules.
# ============================================================

RLT_DOSE_FILE = "rlt_dose_evidence.csv"


def prepare_rlt_dose_evidence():
    df = load_csv(RLT_DOSE_FILE)
    return ensure_cols(df, [
        "rlt_record_id", "timestamp", "dose_id", "batch_id", "radionuclide",
        "product_name", "manufacturing_complete_time", "qa_release_status",
        "dose_calibration_time", "courier_pickup_time", "delivery_eta_time",
        "receiving_site", "patient_appointment_time", "administration_deadline_time",
        "temperature_status", "radiation_survey_status", "chain_of_custody_status",
        "site_receipt_status", "administration_status", "deviation_capa_link",
        "decay_window_status", "readiness_status", "readiness_score",
        "risk_level", "risk_signals", "previous_hash", "record_hash"
    ])


def rlt_parse_datetime(value):
    value = clean(value)
    if not value:
        return None
    try:
        return datetime.datetime.fromisoformat(value)
    except Exception:
        return None


def calculate_rlt_readiness(qa_release_status, dose_calibration_time, courier_pickup_time,
                            delivery_eta_time, patient_appointment_time, administration_deadline_time,
                            temperature_status, radiation_survey_status, chain_of_custody_status,
                            site_receipt_status, administration_status, deviation_capa_link):
    score = 100
    signals = []

    qa_release_status = clean(qa_release_status)
    temperature_status = clean(temperature_status)
    radiation_survey_status = clean(radiation_survey_status)
    chain_of_custody_status = clean(chain_of_custody_status)
    site_receipt_status = clean(site_receipt_status)
    administration_status = clean(administration_status)
    deviation_capa_link = clean(deviation_capa_link)

    calibration_dt = rlt_parse_datetime(dose_calibration_time)
    pickup_dt = rlt_parse_datetime(courier_pickup_time)
    eta_dt = rlt_parse_datetime(delivery_eta_time)
    appt_dt = rlt_parse_datetime(patient_appointment_time)
    deadline_dt = rlt_parse_datetime(administration_deadline_time)

    decay_window_status = "NOT ASSESSED"

    if qa_release_status in ["Pending", "Rejected", "Not Released"]:
        score -= 35
        signals.append("QA release is pending, rejected, or not released.")

    if not calibration_dt:
        score -= 15
        signals.append("Dose calibration time is missing or invalid.")

    if not pickup_dt:
        score -= 10
        signals.append("Courier pickup time is missing or invalid.")

    if not eta_dt:
        score -= 10
        signals.append("Delivery ETA is missing or invalid.")

    if not appt_dt:
        score -= 15
        signals.append("Patient appointment time is missing or invalid.")

    if not deadline_dt:
        score -= 20
        signals.append("Administration deadline / usable window is missing.")
    else:
        if appt_dt and appt_dt > deadline_dt:
            score -= 45
            decay_window_status = "EXPIRED / OUTSIDE ADMINISTRATION WINDOW"
            signals.append("Patient appointment is after the administration deadline.")
        elif appt_dt:
            minutes_to_deadline = (deadline_dt - appt_dt).total_seconds() / 60
            if minutes_to_deadline < 60:
                score -= 20
                decay_window_status = "AT RISK — LESS THAN 60 MINUTES BUFFER"
                signals.append("Patient appointment is close to dose administration deadline.")
            else:
                decay_window_status = "WITHIN ADMINISTRATION WINDOW"

    if eta_dt and appt_dt and eta_dt > appt_dt:
        score -= 30
        signals.append("Delivery ETA is after patient appointment time.")

    if temperature_status in ["Excursion", "Unknown", "Not Recorded"]:
        score -= 25
        signals.append("Temperature status is excursion, unknown, or not recorded.")

    if radiation_survey_status in ["Failed", "Missing", "Not Reviewed"]:
        score -= 25
        signals.append("Radiation survey evidence failed, missing, or not reviewed.")

    if chain_of_custody_status in ["Broken", "Incomplete", "Missing"]:
        score -= 30
        signals.append("Chain-of-custody status is broken, incomplete, or missing.")

    if site_receipt_status in ["Not Received", "Received With Exception", "Unknown"]:
        score -= 20
        signals.append("Receiving site status is not clean.")

    if administration_status in ["Not Administered", "Missed Window", "Unknown"]:
        score -= 30
        signals.append("Administration status indicates missed, unknown, or not administered.")

    if score < 85 and not deviation_capa_link:
        score -= 10
        signals.append("Readiness issues exist but no deviation/CAPA link is recorded.")

    score = max(score, 0)

    if score >= 85:
        readiness = "DOSE-TO-PATIENT READY"
        risk = "LOW"
    elif score >= 60:
        readiness = "CONDITIONALLY READY"
        risk = "MEDIUM"
    else:
        readiness = "NOT READY"
        risk = "HIGH"

    if not signals:
        signals.append("No major RLT dose readiness risk detected.")

    return readiness, score, risk, signals, decay_window_status


def save_rlt_dose_test(req):
    df = prepare_rlt_dose_evidence()

    dose_id = clean(req.form.get("dose_id"))
    batch_id = clean(req.form.get("batch_id"))
    radionuclide = clean(req.form.get("radionuclide"))
    product_name = clean(req.form.get("product_name"))
    manufacturing_complete_time = clean(req.form.get("manufacturing_complete_time"))
    qa_release_status = clean(req.form.get("qa_release_status"))
    dose_calibration_time = clean(req.form.get("dose_calibration_time"))
    courier_pickup_time = clean(req.form.get("courier_pickup_time"))
    delivery_eta_time = clean(req.form.get("delivery_eta_time"))
    receiving_site = clean(req.form.get("receiving_site"))
    patient_appointment_time = clean(req.form.get("patient_appointment_time"))
    administration_deadline_time = clean(req.form.get("administration_deadline_time"))
    temperature_status = clean(req.form.get("temperature_status"))
    radiation_survey_status = clean(req.form.get("radiation_survey_status"))
    chain_of_custody_status = clean(req.form.get("chain_of_custody_status"))
    site_receipt_status = clean(req.form.get("site_receipt_status"))
    administration_status = clean(req.form.get("administration_status"))
    deviation_capa_link = clean(req.form.get("deviation_capa_link"))

    required = [
        dose_id, batch_id, radionuclide, product_name, qa_release_status,
        receiving_site, temperature_status, radiation_survey_status,
        chain_of_custody_status, site_receipt_status, administration_status
    ]

    if not all(required):
        return {
            "error": "Dose ID, Batch ID, Radionuclide, Product Name, QA Release Status, Receiving Site, Temperature, Radiation Survey, Chain-of-Custody, Site Receipt, and Administration Status are required."
        }

    readiness, readiness_score, risk_level, risk_signals, decay_window_status = calculate_rlt_readiness(
        qa_release_status, dose_calibration_time, courier_pickup_time,
        delivery_eta_time, patient_appointment_time, administration_deadline_time,
        temperature_status, radiation_survey_status, chain_of_custody_status,
        site_receipt_status, administration_status, deviation_capa_link
    )

    timestamp = datetime.datetime.utcnow().isoformat()
    rlt_record_id = "RLT-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    previous_hash = "GENESIS"
    if not df.empty:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    record_hash = sha256_text(
        rlt_record_id + timestamp + dose_id + batch_id + radionuclide +
        product_name + qa_release_status + receiving_site + temperature_status +
        radiation_survey_status + chain_of_custody_status + site_receipt_status +
        administration_status + previous_hash
    )

    row = pd.DataFrame([{
        "rlt_record_id": rlt_record_id,
        "timestamp": timestamp,
        "dose_id": dose_id,
        "batch_id": batch_id,
        "radionuclide": radionuclide,
        "product_name": product_name,
        "manufacturing_complete_time": manufacturing_complete_time,
        "qa_release_status": qa_release_status,
        "dose_calibration_time": dose_calibration_time,
        "courier_pickup_time": courier_pickup_time,
        "delivery_eta_time": delivery_eta_time,
        "receiving_site": receiving_site,
        "patient_appointment_time": patient_appointment_time,
        "administration_deadline_time": administration_deadline_time,
        "temperature_status": temperature_status,
        "radiation_survey_status": radiation_survey_status,
        "chain_of_custody_status": chain_of_custody_status,
        "site_receipt_status": site_receipt_status,
        "administration_status": administration_status,
        "deviation_capa_link": deviation_capa_link,
        "decay_window_status": decay_window_status,
        "readiness_status": readiness,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "risk_signals": " | ".join(risk_signals),
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, RLT_DOSE_FILE)

    return {
        "error": "",
        "rlt_record_id": rlt_record_id,
        "readiness_status": readiness,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "decay_window_status": decay_window_status,
        "risk_signals": risk_signals
    }


def get_rlt_test_metrics():
    df = prepare_rlt_dose_evidence()
    if df.empty:
        return {"total": 0, "ready": 0, "conditional": 0, "not_ready": 0, "high": 0, "recent": []}

    df = df.fillna("")
    return {
        "total": len(df),
        "ready": len(df[df["readiness_status"] == "DOSE-TO-PATIENT READY"]),
        "conditional": len(df[df["readiness_status"] == "CONDITIONALLY READY"]),
        "not_ready": len(df[df["readiness_status"] == "NOT READY"]),
        "high": len(df[df["risk_level"] == "HIGH"]),
        "recent": df.tail(15).to_dict("records")
    }


@app.route("/rlt-trust-v1-test", methods=["GET", "POST"])
def rlt_trust_v1_test():
    result = None
    if request.method == "POST":
        result = save_rlt_dose_test(request)

    metrics = get_rlt_test_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain RLT-Trust v1 Test</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#7c3aed);color:white;padding:34px 42px;border-bottom-left-radius:30px;border-bottom-right-radius:30px}
.container{max-width:1450px;margin:-20px auto 50px;padding:0 26px}
.nav,.card,.panel{background:white;border:1px solid #e5e7eb;border-radius:22px;padding:18px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:18px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block}
.nav a.active{background:#0f172a;color:white}
.layout{display:grid;grid-template-columns:430px 1fr;gap:20px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
input,select,textarea,button{width:100%;border-radius:13px;border:1px solid #dbe3ef;padding:11px;margin:6px 0;font-size:14px}
button{border:none;background:linear-gradient(135deg,#7c3aed,#2563eb);color:white;font-weight:900;cursor:pointer}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top}
.risk-HIGH{color:#dc2626;font-weight:900}.risk-MEDIUM{color:#d97706;font-weight:900}.risk-LOW{color:#16a34a;font-weight:900}
@media(max-width:1000px){.layout,.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ RLT-Trust™</h1>
<p><span class="flagship-pill">FLAGSHIP TIER 1 RADIOPHARMA MODULE</span> Decay-Aware Governance Engine™ • Isotope-to-Patient Evidence Graph™ • Dose-to-Patient Readiness</p>
<div class="flagship-banner">
<b>Main Radiopharma Commercial Focus:</b> RLT-Trust™ is the primary COBIT-Chain module for enterprise radiopharma / acquired-site radiopharmaceutical operations, where dose timing, decay window, QA release, radiation survey, chain-of-custody, site receipt, and patient administration readiness matter.
</div>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/executive-overview">Executive</a>
<a href="/sop-governance">SOP</a>
<a href="/shift-assurance">Shift</a>
<a href="/access-governance">Access</a>
<a href="/audit-capa">Audit/CAPA</a>
<a href="/clinical-trial-integrity">Clinical Trial</a>
<a href="/compounding-pharmacy-v1-test">CompoundTrust</a>
<a class="active" href="/rlt-trust-v1-test">RLT-Trust</a>
</nav>

{% if result and result.error %}
<div class="error">{{ result.error }}</div>
{% elif result %}
<div class="notice">
<b>Saved:</b> {{ result.rlt_record_id }} —
<b>{{ result.readiness_status }}</b> —
Score <b>{{ result.readiness_score }}%</b> —
Decay Window: <b>{{ result.decay_window_status }}</b>
<ul>{% for s in result.risk_signals %}<li>{{ s }}</li>{% endfor %}</ul>
</div>
{% endif %}

<section class="grid">
<div class="metric"><div class="metric-label">Total Dose Records</div><div class="metric-value">{{ metrics.total }}</div></div>
<div class="metric"><div class="metric-label">Dose-to-Patient Ready</div><div class="metric-value" style="color:#16a34a">{{ metrics.ready }}</div></div>
<div class="metric"><div class="metric-label">Conditional</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional }}</div></div>
<div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ metrics.high }}</div></div>
</section>

<section class="layout">
<aside class="panel">
<h2>Create RLT Dose Evidence Record</h2>
<form method="POST" action="/rlt-trust-v1-test">
<input name="dose_id" placeholder="Dose ID e.g. DOSE-RLT-001" required>
<input name="batch_id" placeholder="Batch ID e.g. BATCH-RLT-001" required>
<input name="radionuclide" placeholder="Radionuclide / Isotope e.g. Lu-177 / Ac-225" required>
<input name="product_name" placeholder="Product / Therapy Name" required>

<label><b>Manufacturing Complete Time</b></label>
<input type="datetime-local" name="manufacturing_complete_time">

<select name="qa_release_status" required>
<option value="">QA Release Status</option>
<option value="Released">Released</option>
<option value="Pending">Pending</option>
<option value="Rejected">Rejected</option>
<option value="Not Released">Not Released</option>
</select>

<label><b>Dose Calibration Time</b></label>
<input type="datetime-local" name="dose_calibration_time">

<label><b>Courier Pickup Time</b></label>
<input type="datetime-local" name="courier_pickup_time">

<label><b>Delivery ETA</b></label>
<input type="datetime-local" name="delivery_eta_time">

<input name="receiving_site" placeholder="Receiving Site e.g. External RLT Business Integration Stakeholderchmark Site / Treatment Site" required>

<label><b>Patient Appointment Time</b></label>
<input type="datetime-local" name="patient_appointment_time">

<label><b>Administration Deadline / Usable Window</b></label>
<input type="datetime-local" name="administration_deadline_time">

<select name="temperature_status" required>
<option value="">Temperature Status</option>
<option value="Within Range">Within Range</option>
<option value="Excursion">Excursion</option>
<option value="Unknown">Unknown</option>
<option value="Not Recorded">Not Recorded</option>
</select>

<select name="radiation_survey_status" required>
<option value="">Radiation Survey Status</option>
<option value="Passed">Passed</option>
<option value="Failed">Failed</option>
<option value="Missing">Missing</option>
<option value="Not Reviewed">Not Reviewed</option>
</select>

<select name="chain_of_custody_status" required>
<option value="">Chain-of-Custody Status</option>
<option value="Complete">Complete</option>
<option value="Incomplete">Incomplete</option>
<option value="Broken">Broken</option>
<option value="Missing">Missing</option>
</select>

<select name="site_receipt_status" required>
<option value="">Site Receipt Status</option>
<option value="Received Clean">Received Clean</option>
<option value="Received With Exception">Received With Exception</option>
<option value="Not Received">Not Received</option>
<option value="Unknown">Unknown</option>
</select>

<select name="administration_status" required>
<option value="">Administration Status</option>
<option value="Administered">Administered</option>
<option value="Pending">Pending</option>
<option value="Not Administered">Not Administered</option>
<option value="Missed Window">Missed Window</option>
<option value="Unknown">Unknown</option>
</select>

<input name="deviation_capa_link" placeholder="Deviation / CAPA Link if applicable">

<button type="submit">Save RLT Dose Evidence</button>
</form>
</aside>

<section class="card">
<h2>Recent RLT Dose Evidence Records</h2>
{% if metrics.recent %}
<table>
<tr><th>ID</th><th>Dose</th><th>Isotope</th><th>QA</th><th>Site</th><th>Decay Window</th><th>Temp</th><th>COC</th><th>Readiness</th><th>Risk</th></tr>
{% for r in metrics.recent %}
<tr>
<td>{{ r.rlt_record_id }}</td>
<td><b>{{ r.dose_id }}</b><br>{{ r.batch_id }}</td>
<td>{{ r.radionuclide }}</td>
<td>{{ r.qa_release_status }}</td>
<td>{{ r.receiving_site }}</td>
<td>{{ r.decay_window_status }}</td>
<td>{{ r.temperature_status }}</td>
<td>{{ r.chain_of_custody_status }}</td>
<td><b>{{ r.readiness_status }}</b><br>{{ r.readiness_score }}%</td>
<td class="risk-{{ r.risk_level }}">{{ r.risk_level }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No RLT dose evidence records saved yet.</p>
{% endif %}
</section>
</section>

<div class="card">
<b>Storage design:</b> records are saved separately in <b>rlt_dose_evidence.csv</b>.
Manufacturing, SOP, Shift, Access, Audit/CAPA, Clinical Trial, and CompoundTrust registers are untouched.
</div>

<div class="card">
<h2>Advanced Feature Direction</h2>
<p><b>Isotope-to-Patient Evidence Graph™</b> links isotope production, radiolabeling/manufacturing, QA release, calibration, courier pickup, delivery, site receipt, patient appointment, administration window, radiation survey, deviation/CAPA, and final dose-to-patient readiness.</p>
</div>
</main>
</body>
</html>
    """

    return render_template_string(html, metrics=metrics, result=result)


# ============================================================
# RLT-TRUST V1 PROMOTED REDIRECT ACTIVE
# Clean production route for RLT-Trust.
# ============================================================

@app.route("/rlt-trust")
def rlt_trust_page():
    # RLT_TRUST_V1_PROMOTED_REDIRECT_ACTIVE
    return redirect("/rlt-trust-v1-test")


# ============================================================
# DSCSA TRUSTCHAIN V1 TEST ACTIVE
# Drug supply chain traceability evidence register.
# Does not replace or modify existing modules.
# ============================================================

DSCSA_FILE = "dscsa_traceability_evidence.csv"


def prepare_dscsa_evidence():
    df = load_csv(DSCSA_FILE)
    return ensure_cols(df, [
        "dscsa_record_id", "timestamp", "product_name", "product_identifier",
        "gtin", "serial_number", "lot_number", "expiration_date",
        "trading_partner", "partner_status", "transaction_info_status",
        "transaction_statement_status", "verification_status",
        "suspect_product_status", "quarantine_status", "fda_notification_status",
        "disposition_status", "recall_status", "investigation_summary",
        "readiness_status", "readiness_score", "risk_level",
        "risk_signals", "previous_hash", "record_hash"
    ])


def calculate_dscsa_readiness(partner_status, transaction_info_status,
                              transaction_statement_status, verification_status,
                              suspect_product_status, quarantine_status,
                              fda_notification_status, disposition_status,
                              recall_status, investigation_summary):
    score = 100
    signals = []

    partner_status = clean(partner_status)
    transaction_info_status = clean(transaction_info_status)
    transaction_statement_status = clean(transaction_statement_status)
    verification_status = clean(verification_status)
    suspect_product_status = clean(suspect_product_status)
    quarantine_status = clean(quarantine_status)
    fda_notification_status = clean(fda_notification_status)
    disposition_status = clean(disposition_status)
    recall_status = clean(recall_status)
    investigation_summary = clean(investigation_summary)

    if partner_status in ["Unknown", "Not Verified", "Invalid"]:
        score -= 25
        signals.append("Trading partner status is unknown, not verified, or invalid.")

    if transaction_info_status in ["Missing", "Incomplete", "Mismatch"]:
        score -= 25
        signals.append("Transaction information is missing, incomplete, or mismatched.")

    if transaction_statement_status in ["Missing", "Incomplete"]:
        score -= 20
        signals.append("Transaction statement is missing or incomplete.")

    if verification_status in ["Failed", "Not Verified", "Mismatch"]:
        score -= 30
        signals.append("Product verification failed, was not performed, or shows mismatch.")

    if suspect_product_status in ["Suspect", "Illegitimate", "Under Investigation"]:
        score -= 35
        signals.append("Product is suspect, illegitimate, or under investigation.")

    if suspect_product_status in ["Suspect", "Illegitimate", "Under Investigation"] and quarantine_status != "Quarantined":
        score -= 20
        signals.append("Suspect/illegitimate product is not marked as quarantined.")

    if suspect_product_status in ["Illegitimate"] and fda_notification_status != "Submitted":
        score -= 20
        signals.append("Illegitimate product signal exists but FDA notification is not submitted.")

    if disposition_status in ["Unknown", "Pending", "Not Documented"]:
        score -= 15
        signals.append("Product disposition is unknown, pending, or not documented.")

    if recall_status in ["Active Recall", "Recall Pending"] and not investigation_summary:
        score -= 15
        signals.append("Recall signal exists but investigation summary is missing.")

    if score < 85 and not investigation_summary:
        score -= 10
        signals.append("Readiness issues exist but investigation summary is missing.")

    score = max(score, 0)

    if score >= 85:
        readiness = "TRACEABILITY READY"
        risk = "LOW"
    elif score >= 60:
        readiness = "CONDITIONALLY READY"
        risk = "MEDIUM"
    else:
        readiness = "NOT TRACEABILITY READY"
        risk = "HIGH"

    if not signals:
        signals.append("No major DSCSA traceability readiness risk detected.")

    return readiness, score, risk, signals


def save_dscsa_test(req):
    df = prepare_dscsa_evidence()

    product_name = clean(req.form.get("product_name"))
    product_identifier = clean(req.form.get("product_identifier"))
    gtin = clean(req.form.get("gtin"))
    serial_number = clean(req.form.get("serial_number"))
    lot_number = clean(req.form.get("lot_number"))
    expiration_date = clean(req.form.get("expiration_date"))
    trading_partner = clean(req.form.get("trading_partner"))
    partner_status = clean(req.form.get("partner_status"))
    transaction_info_status = clean(req.form.get("transaction_info_status"))
    transaction_statement_status = clean(req.form.get("transaction_statement_status"))
    verification_status = clean(req.form.get("verification_status"))
    suspect_product_status = clean(req.form.get("suspect_product_status"))
    quarantine_status = clean(req.form.get("quarantine_status"))
    fda_notification_status = clean(req.form.get("fda_notification_status"))
    disposition_status = clean(req.form.get("disposition_status"))
    recall_status = clean(req.form.get("recall_status"))
    investigation_summary = clean(req.form.get("investigation_summary"))

    required = [
        product_name, product_identifier, lot_number, expiration_date,
        trading_partner, partner_status, transaction_info_status,
        transaction_statement_status, verification_status, suspect_product_status,
        quarantine_status, disposition_status
    ]

    if not all(required):
        return {
            "error": "Product Name, Product Identifier, Lot, Expiration, Trading Partner, Partner Status, Transaction Info, Transaction Statement, Verification, Suspect Product, Quarantine, and Disposition are required."
        }

    readiness, readiness_score, risk_level, risk_signals = calculate_dscsa_readiness(
        partner_status, transaction_info_status, transaction_statement_status,
        verification_status, suspect_product_status, quarantine_status,
        fda_notification_status, disposition_status, recall_status,
        investigation_summary
    )

    timestamp = datetime.datetime.utcnow().isoformat()
    dscsa_record_id = "DSCSA-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    previous_hash = "GENESIS"
    if not df.empty:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    record_hash = sha256_text(
        dscsa_record_id + timestamp + product_name + product_identifier +
        gtin + serial_number + lot_number + expiration_date + trading_partner +
        partner_status + transaction_info_status + transaction_statement_status +
        verification_status + suspect_product_status + quarantine_status +
        disposition_status + previous_hash
    )

    row = pd.DataFrame([{
        "dscsa_record_id": dscsa_record_id,
        "timestamp": timestamp,
        "product_name": product_name,
        "product_identifier": product_identifier,
        "gtin": gtin,
        "serial_number": serial_number,
        "lot_number": lot_number,
        "expiration_date": expiration_date,
        "trading_partner": trading_partner,
        "partner_status": partner_status,
        "transaction_info_status": transaction_info_status,
        "transaction_statement_status": transaction_statement_status,
        "verification_status": verification_status,
        "suspect_product_status": suspect_product_status,
        "quarantine_status": quarantine_status,
        "fda_notification_status": fda_notification_status,
        "disposition_status": disposition_status,
        "recall_status": recall_status,
        "investigation_summary": investigation_summary,
        "readiness_status": readiness,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "risk_signals": " | ".join(risk_signals),
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, DSCSA_FILE)

    return {
        "error": "",
        "dscsa_record_id": dscsa_record_id,
        "readiness_status": readiness,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "risk_signals": risk_signals
    }


def get_dscsa_test_metrics():
    df = prepare_dscsa_evidence()
    if df.empty:
        return {"total": 0, "ready": 0, "conditional": 0, "not_ready": 0, "high": 0, "recent": []}

    df = df.fillna("")
    return {
        "total": len(df),
        "ready": len(df[df["readiness_status"] == "TRACEABILITY READY"]),
        "conditional": len(df[df["readiness_status"] == "CONDITIONALLY READY"]),
        "not_ready": len(df[df["readiness_status"] == "NOT TRACEABILITY READY"]),
        "high": len(df[df["risk_level"] == "HIGH"]),
        "recent": df.tail(15).to_dict("records")
    }


@app.route("/dscsa-trustchain-v1-test", methods=["GET", "POST"])
def dscsa_trustchain_v1_test():
    result = None
    if request.method == "POST":
        result = save_dscsa_test(request)

    metrics = get_dscsa_test_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain DSCSA TrustChain v1 Test</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#0f766e);color:white;padding:34px 42px;border-bottom-left-radius:30px;border-bottom-right-radius:30px}
.container{max-width:1450px;margin:-20px auto 50px;padding:0 26px}
.nav,.card,.panel{background:white;border:1px solid #e5e7eb;border-radius:22px;padding:18px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:18px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block}
.nav a.active{background:#0f172a;color:white}
.layout{display:grid;grid-template-columns:430px 1fr;gap:20px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
input,select,textarea,button{width:100%;border-radius:13px;border:1px solid #dbe3ef;padding:11px;margin:6px 0;font-size:14px}
textarea{min-height:90px}
button{border:none;background:linear-gradient(135deg,#0f766e,#2563eb);color:white;font-weight:900;cursor:pointer}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top}
.risk-HIGH{color:#dc2626;font-weight:900}.risk-MEDIUM{color:#d97706;font-weight:900}.risk-LOW{color:#16a34a;font-weight:900}
@media(max-width:1000px){.layout,.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ DSCSA TrustChain™</h1>
<p><span class="supporting-pill">SUPPORTING PHARMA SUPPLY-CHAIN MODULE</span> Standard Prescription Drug Package Traceability • Suspect Product Evidence Graph™ • Transaction Evidence Readiness</p>
<div class="supporting-banner">
<b>Supporting Module:</b> DSCSA TrustChain™ is important for standard prescription drug package traceability, trading partner evidence, transaction information, suspect product workflow, quarantine, notification, and disposition. It is separate from the RLT-Trust™ radiopharma flagship.
</div>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/executive-overview">Executive</a>
<a href="/sop-governance">SOP</a>
<a href="/shift-assurance">Shift</a>
<a href="/access-governance">Access</a>
<a href="/audit-capa">Audit/CAPA</a>
<a href="/clinical-trial-integrity">Clinical Trial</a>
<a href="/compounding-pharmacy-v1-test">CompoundTrust</a>
<a href="/rlt-trust">RLT-Trust</a>
<a class="active" href="/dscsa-trustchain-v1-test">DSCSA TrustChain</a>
</nav>

<div class="notice">
<b>DSCSA TrustChain™ is a supporting supply-chain module, separate from the RLT-Trust™ flagship.</b>
Use DSCSA TrustChain™ for non-radioactive standard prescription drug package traceability, trading partner verification,
transaction information/statement evidence, suspect product investigation, quarantine, notification, and disposition.
<br><br>
<b>Do not use DSCSA TrustChain™ as the main radiopharma/RLT dose-readiness module. RLT-Trust™ remains the flagship for enterprise radiopharma / acquired-site radiopharma governance.</b>
Radiopharma dose timing, decay-window readiness, radiation survey, site receipt, and patient administration belong in RLT-Trust™.
</div>

{% if result and result.error %}
<div class="error">{{ result.error }}</div>
{% elif result %}
<div class="notice">
<b>Saved:</b> {{ result.dscsa_record_id }} —
<b>{{ result.readiness_status }}</b> —
Traceability score <b>{{ result.readiness_score }}%</b>
<ul>{% for s in result.risk_signals %}<li>{{ s }}</li>{% endfor %}</ul>
</div>
{% endif %}

<section class="grid">
<div class="metric"><div class="metric-label">Total Records</div><div class="metric-value">{{ metrics.total }}</div></div>
<div class="metric"><div class="metric-label">Traceability Ready</div><div class="metric-value" style="color:#16a34a">{{ metrics.ready }}</div></div>
<div class="metric"><div class="metric-label">Conditional</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional }}</div></div>
<div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ metrics.high }}</div></div>
</section>

<section class="layout">
<aside class="panel">
<h2>Create DSCSA Traceability Record</h2>
<form method="POST" action="/dscsa-trustchain-v1-test">
<input name="product_name" placeholder="Product Name" required>
<input name="product_identifier" placeholder="Product Identifier / NDC / Package ID" required>
<input name="gtin" placeholder="GTIN">
<input name="serial_number" placeholder="Serial Number">
<input name="lot_number" placeholder="Lot Number" required>
<label><b>Expiration Date</b></label>
<input type="date" name="expiration_date" required>
<input name="trading_partner" placeholder="Trading Partner" required>

<select name="partner_status" required>
<option value="">Trading Partner Status</option>
<option value="Verified">Verified</option>
<option value="Not Verified">Not Verified</option>
<option value="Unknown">Unknown</option>
<option value="Invalid">Invalid</option>
</select>

<select name="transaction_info_status" required>
<option value="">Transaction Information Status</option>
<option value="Complete">Complete</option>
<option value="Incomplete">Incomplete</option>
<option value="Missing">Missing</option>
<option value="Mismatch">Mismatch</option>
</select>

<select name="transaction_statement_status" required>
<option value="">Transaction Statement Status</option>
<option value="Complete">Complete</option>
<option value="Incomplete">Incomplete</option>
<option value="Missing">Missing</option>
</select>

<select name="verification_status" required>
<option value="">Verification Status</option>
<option value="Verified">Verified</option>
<option value="Not Verified">Not Verified</option>
<option value="Failed">Failed</option>
<option value="Mismatch">Mismatch</option>
</select>

<select name="suspect_product_status" required>
<option value="">Suspect Product Status</option>
<option value="No Suspect Signal">No Suspect Signal</option>
<option value="Suspect">Suspect</option>
<option value="Illegitimate">Illegitimate</option>
<option value="Under Investigation">Under Investigation</option>
</select>

<select name="quarantine_status" required>
<option value="">Quarantine Status</option>
<option value="Not Required">Not Required</option>
<option value="Quarantined">Quarantined</option>
<option value="Not Quarantined">Not Quarantined</option>
</select>

<select name="fda_notification_status">
<option value="Not Required">FDA Notification Status: Not Required</option>
<option value="Submitted">Submitted</option>
<option value="Not Submitted">Not Submitted</option>
<option value="Pending">Pending</option>
</select>

<select name="disposition_status" required>
<option value="">Disposition Status</option>
<option value="Released">Released</option>
<option value="Quarantined">Quarantined</option>
<option value="Destroyed">Destroyed</option>
<option value="Returned">Returned</option>
<option value="Pending">Pending</option>
<option value="Unknown">Unknown</option>
<option value="Not Documented">Not Documented</option>
</select>

<select name="recall_status">
<option value="No Recall">Recall Status: No Recall</option>
<option value="Active Recall">Active Recall</option>
<option value="Recall Pending">Recall Pending</option>
</select>

<textarea name="investigation_summary" placeholder="Investigation Summary / Traceability Notes"></textarea>

<button type="submit">Save DSCSA Traceability Evidence</button>
</form>
</aside>

<section class="card">
<h2>Recent DSCSA Traceability Records</h2>
{% if metrics.recent %}
<table>
<tr><th>ID</th><th>Product</th><th>Lot/Serial</th><th>Partner</th><th>Verification</th><th>Suspect Status</th><th>Quarantine</th><th>Readiness</th><th>Risk</th></tr>
{% for r in metrics.recent %}
<tr>
<td>{{ r.dscsa_record_id }}</td>
<td><b>{{ r.product_name }}</b><br>{{ r.product_identifier }}</td>
<td>{{ r.lot_number }}<br>{{ r.serial_number }}</td>
<td>{{ r.trading_partner }}</td>
<td>{{ r.verification_status }}</td>
<td>{{ r.suspect_product_status }}</td>
<td>{{ r.quarantine_status }}</td>
<td><b>{{ r.readiness_status }}</b><br>{{ r.readiness_score }}%</td>
<td class="risk-{{ r.risk_level }}">{{ r.risk_level }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No DSCSA traceability records saved yet.</p>
{% endif %}
</section>
</section>

<div class="card">
<b>Storage design:</b> records are saved separately in <b>dscsa_traceability_evidence.csv</b>.
Existing COBIT-Chain module registers are untouched.
</div>

<div class="card">
<h2>Advanced Feature Direction</h2>
<p><b>Suspect Product Evidence Graph™</b> links product identifier, transaction evidence, trading partner status, verification result, suspect/illegitimate product investigation, quarantine, notification, disposition, and final traceability readiness.</p>
</div>
</main>
</body>
</html>
    """

    return render_template_string(html, metrics=metrics, result=result)


# ============================================================
# DSCSA TRUSTCHAIN V1 PROMOTED REDIRECT ACTIVE
# Clean production route for DSCSA TrustChain.
# ============================================================

@app.route("/dscsa-trustchain")
def dscsa_trustchain_page():
    # DSCSA_TRUSTCHAIN_V1_PROMOTED_REDIRECT_ACTIVE
    return redirect("/dscsa-trustchain-v1-test")


# ============================================================
# RADIOPHARMA TRUST ALIAS ACTIVE
# Alias route for RLT-Trust.
# ============================================================

@app.route("/radiopharma-trust")
def radiopharma_trust_page():
    # RADIOPHARMA_TRUST_ALIAS_ACTIVE
    return redirect("/rlt-trust")


# ============================================================
# HOMECARE COMMAND V1 TEST ACTIVE
# Functional homecare delivery evidence register.
# Does not replace or modify existing modules.
# ============================================================

HOMECARE_FILE = "homecare_delivery_evidence.csv"


def prepare_homecare_delivery_evidence():
    df = load_csv(HOMECARE_FILE)
    return ensure_cols(df, [
        "homecare_record_id", "timestamp", "visit_id", "client_id",
        "care_plan_id", "payer_mco", "caregiver_id", "caregiver_name",
        "scheduled_start", "scheduled_end", "actual_start", "actual_end",
        "evv_status", "gps_status", "caregiver_credential_status",
        "task_completion_status", "client_confirmation_status",
        "incident_status", "missed_visit_status", "billing_status",
        "payroll_status", "family_visibility_status", "remediation_action",
        "readiness_status", "readiness_score", "risk_level",
        "risk_signals", "previous_hash", "record_hash"
    ])


def homecare_parse_datetime(value):
    value = clean(value)
    if not value:
        return None
    try:
        return datetime.datetime.fromisoformat(value)
    except Exception:
        return None


def calculate_homecare_readiness(evv_status, gps_status, caregiver_credential_status,
                                 task_completion_status, client_confirmation_status,
                                 incident_status, missed_visit_status, billing_status,
                                 payroll_status, family_visibility_status,
                                 scheduled_start, scheduled_end, actual_start, actual_end,
                                 remediation_action):
    score = 100
    signals = []

    evv_status = clean(evv_status)
    gps_status = clean(gps_status)
    caregiver_credential_status = clean(caregiver_credential_status)
    task_completion_status = clean(task_completion_status)
    client_confirmation_status = clean(client_confirmation_status)
    incident_status = clean(incident_status)
    missed_visit_status = clean(missed_visit_status)
    billing_status = clean(billing_status)
    payroll_status = clean(payroll_status)
    family_visibility_status = clean(family_visibility_status)
    remediation_action = clean(remediation_action)

    scheduled_start_dt = homecare_parse_datetime(scheduled_start)
    scheduled_end_dt = homecare_parse_datetime(scheduled_end)
    actual_start_dt = homecare_parse_datetime(actual_start)
    actual_end_dt = homecare_parse_datetime(actual_end)

    if evv_status in ["Missing", "Failed", "Not Verified"]:
        score -= 30
        signals.append("EVV verification is missing, failed, or not verified.")

    if gps_status in ["Mismatch", "Missing", "Unknown"]:
        score -= 20
        signals.append("GPS/location status is mismatched, missing, or unknown.")

    if caregiver_credential_status in ["Expired", "Missing", "Not Verified"]:
        score -= 25
        signals.append("Caregiver credential or eligibility is expired, missing, or not verified.")

    if task_completion_status in ["Incomplete", "Partial", "Not Documented"]:
        score -= 25
        signals.append("Care plan task completion is incomplete, partial, or not documented.")

    if client_confirmation_status in ["Missing", "Disputed", "Not Confirmed"]:
        score -= 20
        signals.append("Client/family confirmation is missing, disputed, or not confirmed.")

    if incident_status in ["Open Incident", "Unresolved", "Escalation Required"]:
        score -= 25
        signals.append("Incident exists and is open, unresolved, or requires escalation.")

    if missed_visit_status in ["Missed", "Late", "No Show"]:
        score -= 30
        signals.append("Visit was missed, late, or caregiver no-show was recorded.")

    if not actual_start_dt or not actual_end_dt:
        score -= 15
        signals.append("Actual visit start or end time is missing or invalid.")

    if scheduled_start_dt and actual_start_dt:
        late_minutes = (actual_start_dt - scheduled_start_dt).total_seconds() / 60
        if late_minutes > 15:
            score -= 10
            signals.append("Caregiver arrived more than 15 minutes after scheduled start.")

    if actual_start_dt and actual_end_dt:
        visit_minutes = (actual_end_dt - actual_start_dt).total_seconds() / 60
        if visit_minutes <= 0:
            score -= 20
            signals.append("Actual visit end time is not after start time.")
        elif visit_minutes < 15:
            score -= 10
            signals.append("Actual visit duration appears unusually short.")

    if billing_status in ["Submitted", "Ready for Billing"] and score < 85:
        score -= 20
        signals.append("Billing is marked ready/submitted even though care delivery evidence is incomplete.")

    if payroll_status in ["Approved", "Ready for Payroll"] and score < 85:
        score -= 15
        signals.append("Payroll is marked ready/approved even though visit evidence is incomplete.")

    if family_visibility_status in ["Not Shared", "Missing", "Unknown"]:
        score -= 5
        signals.append("Family/client visibility status is not confirmed.")

    if score < 85 and not remediation_action:
        score -= 10
        signals.append("Readiness issues exist but remediation action is not documented.")

    score = max(score, 0)

    if score >= 85:
        readiness = "CARE DELIVERY VERIFIED"
        risk = "LOW"
    elif score >= 60:
        readiness = "CONDITIONALLY VERIFIED"
        risk = "MEDIUM"
    else:
        readiness = "NOT VERIFIED"
        risk = "HIGH"

    if not signals:
        signals.append("No major homecare delivery evidence risk detected.")

    return readiness, score, risk, signals


def save_homecare_command_test(req):
    df = prepare_homecare_delivery_evidence()

    visit_id = clean(req.form.get("visit_id"))
    client_id = clean(req.form.get("client_id"))
    care_plan_id = clean(req.form.get("care_plan_id"))
    payer_mco = clean(req.form.get("payer_mco"))
    caregiver_id = clean(req.form.get("caregiver_id"))
    caregiver_name = clean(req.form.get("caregiver_name"))
    scheduled_start = clean(req.form.get("scheduled_start"))
    scheduled_end = clean(req.form.get("scheduled_end"))
    actual_start = clean(req.form.get("actual_start"))
    actual_end = clean(req.form.get("actual_end"))
    evv_status = clean(req.form.get("evv_status"))
    gps_status = clean(req.form.get("gps_status"))
    caregiver_credential_status = clean(req.form.get("caregiver_credential_status"))
    task_completion_status = clean(req.form.get("task_completion_status"))
    client_confirmation_status = clean(req.form.get("client_confirmation_status"))
    incident_status = clean(req.form.get("incident_status"))
    missed_visit_status = clean(req.form.get("missed_visit_status"))
    billing_status = clean(req.form.get("billing_status"))
    payroll_status = clean(req.form.get("payroll_status"))
    family_visibility_status = clean(req.form.get("family_visibility_status"))
    remediation_action = clean(req.form.get("remediation_action"))

    required = [
        visit_id, client_id, care_plan_id, caregiver_id, caregiver_name,
        evv_status, gps_status, caregiver_credential_status,
        task_completion_status, client_confirmation_status,
        incident_status, missed_visit_status, billing_status, payroll_status
    ]

    if not all(required):
        return {
            "error": "Visit ID, Client ID, Care Plan ID, Caregiver, EVV, GPS, credential, task, confirmation, incident, missed visit, billing, and payroll statuses are required."
        }

    readiness, readiness_score, risk_level, risk_signals = calculate_homecare_readiness(
        evv_status, gps_status, caregiver_credential_status,
        task_completion_status, client_confirmation_status,
        incident_status, missed_visit_status, billing_status,
        payroll_status, family_visibility_status,
        scheduled_start, scheduled_end, actual_start, actual_end,
        remediation_action
    )

    timestamp = datetime.datetime.utcnow().isoformat()
    homecare_record_id = "HC-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    previous_hash = "GENESIS"
    if not df.empty:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    record_hash = sha256_text(
        homecare_record_id + timestamp + visit_id + client_id + care_plan_id +
        payer_mco + caregiver_id + caregiver_name + evv_status + gps_status +
        task_completion_status + billing_status + payroll_status + previous_hash
    )

    row = pd.DataFrame([{
        "homecare_record_id": homecare_record_id,
        "timestamp": timestamp,
        "visit_id": visit_id,
        "client_id": client_id,
        "care_plan_id": care_plan_id,
        "payer_mco": payer_mco,
        "caregiver_id": caregiver_id,
        "caregiver_name": caregiver_name,
        "scheduled_start": scheduled_start,
        "scheduled_end": scheduled_end,
        "actual_start": actual_start,
        "actual_end": actual_end,
        "evv_status": evv_status,
        "gps_status": gps_status,
        "caregiver_credential_status": caregiver_credential_status,
        "task_completion_status": task_completion_status,
        "client_confirmation_status": client_confirmation_status,
        "incident_status": incident_status,
        "missed_visit_status": missed_visit_status,
        "billing_status": billing_status,
        "payroll_status": payroll_status,
        "family_visibility_status": family_visibility_status,
        "remediation_action": remediation_action,
        "readiness_status": readiness,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "risk_signals": " | ".join(risk_signals),
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, HOMECARE_FILE)

    return {
        "error": "",
        "homecare_record_id": homecare_record_id,
        "readiness_status": readiness,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "risk_signals": risk_signals
    }


def get_homecare_command_test_metrics():
    df = prepare_homecare_delivery_evidence()
    if df.empty:
        return {"total": 0, "ready": 0, "conditional": 0, "not_ready": 0, "high": 0, "recent": []}

    df = df.fillna("")
    return {
        "total": len(df),
        "ready": len(df[df["readiness_status"] == "CARE DELIVERY VERIFIED"]),
        "conditional": len(df[df["readiness_status"] == "CONDITIONALLY VERIFIED"]),
        "not_ready": len(df[df["readiness_status"] == "NOT VERIFIED"]),
        "high": len(df[df["risk_level"] == "HIGH"]),
        "recent": df.tail(15).to_dict("records")
    }


@app.route("/homecare-command-v1-test", methods=["GET", "POST"])
def homecare_command_v1_test():
    result = None
    if request.method == "POST":
        result = save_homecare_command_test(request)

    metrics = get_homecare_command_test_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain HomeCare Command v1 Test</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#9333ea);color:white;padding:34px 42px;border-bottom-left-radius:30px;border-bottom-right-radius:30px}
.container{max-width:1450px;margin:-20px auto 50px;padding:0 26px}
.nav,.card,.panel{background:white;border:1px solid #e5e7eb;border-radius:22px;padding:18px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:18px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block}
.nav a.active{background:#0f172a;color:white}
.layout{display:grid;grid-template-columns:430px 1fr;gap:20px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
input,select,textarea,button{width:100%;border-radius:13px;border:1px solid #dbe3ef;padding:11px;margin:6px 0;font-size:14px}
textarea{min-height:90px}
button{border:none;background:linear-gradient(135deg,#9333ea,#2563eb);color:white;font-weight:900;cursor:pointer}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top}
.risk-HIGH{color:#dc2626;font-weight:900}.risk-MEDIUM{color:#d97706;font-weight:900}.risk-LOW{color:#16a34a;font-weight:900}
@media(max-width:1000px){.layout,.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ HomeCare Command™ v1 Test</h1>
<p>Care Delivery Evidence Chain™ • EVV Integrity • Medicaid/MCO Audit Pack • Payroll/Billing Readiness</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/executive-overview">Executive</a>
<a href="/sop-governance">SOP</a>
<a href="/shift-assurance">Shift</a>
<a href="/access-governance">Access</a>
<a href="/audit-capa">Audit/CAPA</a>
<a href="/clinical-trial-integrity">Clinical Trial</a>
<a href="/compounding-pharmacy-v1-test">CompoundTrust</a>
<a href="/rlt-trust">RLT-Trust</a>
<a href="/dscsa-trustchain">DSCSA</a>
<a class="active" href="/homecare-command-v1-test">HomeCare Command</a>
</nav>

{% if result and result.error %}
<div class="error">{{ result.error }}</div>
{% elif result %}
<div class="notice">
<b>Saved:</b> {{ result.homecare_record_id }} —
<b>{{ result.readiness_status }}</b> —
Readiness score <b>{{ result.readiness_score }}%</b>
<ul>{% for s in result.risk_signals %}<li>{{ s }}</li>{% endfor %}</ul>
</div>
{% endif %}

<section class="grid">
<div class="metric"><div class="metric-label">Total Visits</div><div class="metric-value">{{ metrics.total }}</div></div>
<div class="metric"><div class="metric-label">Verified</div><div class="metric-value" style="color:#16a34a">{{ metrics.ready }}</div></div>
<div class="metric"><div class="metric-label">Conditional</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional }}</div></div>
<div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ metrics.high }}</div></div>
</section>

<section class="layout">
<aside class="panel">
<h2>Create Homecare Visit Evidence</h2>
<form method="POST" action="/homecare-command-v1-test">
<input name="visit_id" placeholder="Visit ID e.g. VISIT-001" required>
<input name="client_id" placeholder="Client ID e.g. CLIENT-001" required>
<input name="care_plan_id" placeholder="Care Plan ID e.g. CAREPLAN-001" required>
<input name="payer_mco" placeholder="Payer / MCO e.g. Medicaid / Anthem / MHS / CareSource">

<input name="caregiver_id" placeholder="Caregiver ID" required>
<input name="caregiver_name" placeholder="Caregiver Name" required>

<label><b>Scheduled Start</b></label>
<input type="datetime-local" name="scheduled_start">
<label><b>Scheduled End</b></label>
<input type="datetime-local" name="scheduled_end">
<label><b>Actual Start</b></label>
<input type="datetime-local" name="actual_start">
<label><b>Actual End</b></label>
<input type="datetime-local" name="actual_end">

<select name="evv_status" required>
<option value="">EVV Status</option>
<option value="Verified">Verified</option>
<option value="Not Verified">Not Verified</option>
<option value="Failed">Failed</option>
<option value="Missing">Missing</option>
</select>

<select name="gps_status" required>
<option value="">GPS / Location Status</option>
<option value="Matched">Matched</option>
<option value="Mismatch">Mismatch</option>
<option value="Missing">Missing</option>
<option value="Unknown">Unknown</option>
</select>

<select name="caregiver_credential_status" required>
<option value="">Caregiver Credential Status</option>
<option value="Verified">Verified</option>
<option value="Expired">Expired</option>
<option value="Missing">Missing</option>
<option value="Not Verified">Not Verified</option>
</select>

<select name="task_completion_status" required>
<option value="">Care Plan Task Completion</option>
<option value="Complete">Complete</option>
<option value="Partial">Partial</option>
<option value="Incomplete">Incomplete</option>
<option value="Not Documented">Not Documented</option>
</select>

<select name="client_confirmation_status" required>
<option value="">Client / Family Confirmation</option>
<option value="Confirmed">Confirmed</option>
<option value="Not Confirmed">Not Confirmed</option>
<option value="Missing">Missing</option>
<option value="Disputed">Disputed</option>
</select>

<select name="incident_status" required>
<option value="">Incident Status</option>
<option value="No Incident">No Incident</option>
<option value="Open Incident">Open Incident</option>
<option value="Unresolved">Unresolved</option>
<option value="Escalation Required">Escalation Required</option>
</select>

<select name="missed_visit_status" required>
<option value="">Missed Visit Status</option>
<option value="No Missed Visit">No Missed Visit</option>
<option value="Late">Late</option>
<option value="Missed">Missed</option>
<option value="No Show">No Show</option>
</select>

<select name="billing_status" required>
<option value="">Billing Status</option>
<option value="Not Ready">Not Ready</option>
<option value="Ready for Billing">Ready for Billing</option>
<option value="Submitted">Submitted</option>
<option value="Blocked">Blocked</option>
</select>

<select name="payroll_status" required>
<option value="">Payroll Status</option>
<option value="Not Ready">Not Ready</option>
<option value="Ready for Payroll">Ready for Payroll</option>
<option value="Approved">Approved</option>
<option value="Blocked">Blocked</option>
</select>

<select name="family_visibility_status">
<option value="Shared">Family Visibility: Shared</option>
<option value="Not Shared">Not Shared</option>
<option value="Missing">Missing</option>
<option value="Unknown">Unknown</option>
</select>

<textarea name="remediation_action" placeholder="Remediation Action / Follow-up"></textarea>

<button type="submit">Save Homecare Evidence</button>
</form>
</aside>

<section class="card">
<h2>Recent Homecare Delivery Evidence Records</h2>
{% if metrics.recent %}
<table>
<tr><th>ID</th><th>Visit</th><th>Client</th><th>Caregiver</th><th>EVV</th><th>GPS</th><th>Tasks</th><th>Billing</th><th>Readiness</th><th>Risk</th></tr>
{% for r in metrics.recent %}
<tr>
<td>{{ r.homecare_record_id }}</td>
<td><b>{{ r.visit_id }}</b><br>{{ r.care_plan_id }}</td>
<td>{{ r.client_id }}</td>
<td><b>{{ r.caregiver_id }}</b><br>{{ r.caregiver_name }}</td>
<td>{{ r.evv_status }}</td>
<td>{{ r.gps_status }}</td>
<td>{{ r.task_completion_status }}</td>
<td>{{ r.billing_status }}</td>
<td><b>{{ r.readiness_status }}</b><br>{{ r.readiness_score }}%</td>
<td class="risk-{{ r.risk_level }}">{{ r.risk_level }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No homecare delivery evidence records saved yet.</p>
{% endif %}
</section>
</section>

<div class="card">
<b>Storage design:</b> records are saved separately in <b>homecare_delivery_evidence.csv</b>.
Existing COBIT-Chain module registers are untouched.
</div>

<div class="card">
<h2>Advanced Feature Direction</h2>
<p><b>Care Delivery Evidence Chain™</b> links care plan, scheduled visit, caregiver identity, EVV, GPS/location, task completion, client/family confirmation, incident handling, billing, payroll, and Medicaid/MCO audit readiness into one governed evidence trail.</p>
</div>
</main>
</body>
</html>
    """

    return render_template_string(html, metrics=metrics, result=result)


# ============================================================
# HOMECARE COMMAND V1 PROMOTED REDIRECT ACTIVE
# Clean production route for HomeCare Command.
# ============================================================

@app.route("/homecare-command")
def homecare_command_page():
    # HOMECARE_COMMAND_V1_PROMOTED_REDIRECT_ACTIVE
    return redirect("/homecare-command-v1-test")


# ============================================================
# EXECUTIVE OVERVIEW V4 TEST ACTIVE
# Enterprise + vertical module dashboard.
# Does not replace /executive-overview yet.
# ============================================================

def exec_v4_int(value):
    try:
        return int(float(clean(value)))
    except Exception:
        return 0


def exec_v4_register(filename, columns):
    df = load_csv(filename)
    return ensure_cols(df, columns).fillna("")


def exec_v4_count(df, column, value):
    if df.empty or column not in df.columns:
        return 0
    return len(df[df[column] == value])


def get_executive_v4_metrics():
    manufacturing = prepare_logs().fillna("")
    sop = exec_v4_register("sop_comparisons.csv", ["comparison_id", "gap_count", "high_risk_gap_count"])
    shift = exec_v4_register("shift_handoffs.csv", ["handoff_id", "readiness_status", "risk_level"])
    access = exec_v4_register("access_reviews.csv", ["review_id", "readiness_status", "risk_level"])
    audit = exec_v4_register("audit_capa_register.csv", ["audit_id", "readiness_status", "risk_level"])
    clinical = exec_v4_register("clinical_trial_evidence.csv", ["evidence_id", "inspection_readiness", "risk_level"])
    compound = exec_v4_register("compounding_pharmacy_evidence.csv", ["compound_record_id", "readiness_status", "risk_level"])
    rlt = exec_v4_register("rlt_dose_evidence.csv", ["rlt_record_id", "readiness_status", "risk_level"])
    dscsa = exec_v4_register("dscsa_traceability_evidence.csv", ["dscsa_record_id", "readiness_status", "risk_level"])
    homecare = exec_v4_register("homecare_delivery_evidence.csv", ["homecare_record_id", "readiness_status", "risk_level"])

    m_total = len(manufacturing)
    m_green = exec_v4_count(manufacturing, "status", "GREEN")
    m_yellow = exec_v4_count(manufacturing, "status", "YELLOW")
    m_red = exec_v4_count(manufacturing, "status", "RED")

    sop_total = len(sop)
    sop_high = sum(exec_v4_int(x) for x in sop["high_risk_gap_count"]) if not sop.empty else 0
    sop_gaps = sum(exec_v4_int(x) for x in sop["gap_count"]) if not sop.empty else 0

    rows = [
        {"tier": "Core", "module": "Manufacturing Assurance", "route": "/", "register": "logs.csv", "records": m_total, "ready": m_green, "conditional": m_yellow, "not_ready": m_red, "high": m_red, "position": "Protected Manufacturing Core manufacturing core"},
        {"tier": "Core", "module": "SOP Governance / SOPTrust™", "route": "/sop-governance", "register": "sop_comparisons.csv", "records": sop_total, "ready": max(sop_total - sop_high, 0), "conditional": sop_gaps, "not_ready": sop_high, "high": sop_high, "position": "Dual SOP harmonization engine"},
        {"tier": "Core", "module": "Shift Assurance / ShiftTrust™", "route": "/shift-assurance", "register": "shift_handoffs.csv", "records": len(shift), "ready": exec_v4_count(shift, "readiness_status", "READY"), "conditional": exec_v4_count(shift, "readiness_status", "CONDITIONALLY READY"), "not_ready": exec_v4_count(shift, "readiness_status", "NOT READY"), "high": exec_v4_count(shift, "risk_level", "HIGH"), "position": "Equipment handoff and ServiceNow carryover"},
        {"tier": "Core", "module": "Access Governance / AccessTrust™", "route": "/access-governance", "register": "access_reviews.csv", "records": len(access), "ready": exec_v4_count(access, "readiness_status", "AUDIT-READY"), "conditional": exec_v4_count(access, "readiness_status", "CONDITIONALLY READY"), "not_ready": exec_v4_count(access, "readiness_status", "NOT AUDIT-READY"), "high": exec_v4_count(access, "risk_level", "HIGH"), "position": "myAccess, binder, entitlement review"},
        {"tier": "Core", "module": "Audit/CAPA / CAPATrust™", "route": "/audit-capa", "register": "audit_capa_register.csv", "records": len(audit), "ready": exec_v4_count(audit, "readiness_status", "EFFECTIVENESS READY"), "conditional": exec_v4_count(audit, "readiness_status", "CONDITIONALLY READY"), "not_ready": exec_v4_count(audit, "readiness_status", "NOT READY"), "high": exec_v4_count(audit, "risk_level", "HIGH"), "position": "Effectiveness readiness gate"},
        {"tier": "Tier 1 Life Sciences", "module": "TrialTrust™ / Clinical Trial Integrity", "route": "/clinical-trial-integrity", "register": "clinical_trial_evidence.csv", "records": len(clinical), "ready": exec_v4_count(clinical, "inspection_readiness", "INSPECTION READY"), "conditional": exec_v4_count(clinical, "inspection_readiness", "CONDITIONALLY READY"), "not_ready": exec_v4_count(clinical, "inspection_readiness", "NOT INSPECTION READY"), "high": exec_v4_count(clinical, "risk_level", "HIGH"), "position": "Microsoft Purview, eConsent, ALCOA+, inspection readiness"},
        {"tier": "Tier 1 Life Sciences", "module": "CompoundTrust™", "route": "/compounding-pharmacy-v1-test", "register": "compounding_pharmacy_evidence.csv", "records": len(compound), "ready": exec_v4_count(compound, "readiness_status", "RELEASE READY"), "conditional": exec_v4_count(compound, "readiness_status", "CONDITIONALLY READY"), "not_ready": exec_v4_count(compound, "readiness_status", "NOT RELEASE READY"), "high": exec_v4_count(compound, "risk_level", "HIGH"), "position": "Sterility-to-release evidence graph"},
        {"tier": "Tier 1 Flagship", "module": "RLT-Trust™ / RadiopharmaTrust™", "route": "/rlt-trust", "register": "rlt_dose_evidence.csv", "records": len(rlt), "ready": exec_v4_count(rlt, "readiness_status", "DOSE-TO-PATIENT READY"), "conditional": exec_v4_count(rlt, "readiness_status", "CONDITIONALLY READY"), "not_ready": exec_v4_count(rlt, "readiness_status", "NOT READY"), "high": exec_v4_count(rlt, "risk_level", "HIGH"), "position": "FLAGSHIP radiopharma/RLT dose-to-patient module"},
        {"tier": "Supporting Pharma", "module": "DSCSA TrustChain™", "route": "/dscsa-trustchain", "register": "dscsa_traceability_evidence.csv", "records": len(dscsa), "ready": exec_v4_count(dscsa, "readiness_status", "TRACEABILITY READY"), "conditional": exec_v4_count(dscsa, "readiness_status", "CONDITIONALLY READY"), "not_ready": exec_v4_count(dscsa, "readiness_status", "NOT TRACEABILITY READY"), "high": exec_v4_count(dscsa, "risk_level", "HIGH"), "position": "Supporting standard prescription drug traceability"},
        {"tier": "Commercial Expansion", "module": "HomeCare Command™ / CareTrust™", "route": "/homecare-command", "register": "homecare_delivery_evidence.csv", "records": len(homecare), "ready": exec_v4_count(homecare, "readiness_status", "CARE DELIVERY VERIFIED"), "conditional": exec_v4_count(homecare, "readiness_status", "CONDITIONALLY VERIFIED"), "not_ready": exec_v4_count(homecare, "readiness_status", "NOT VERIFIED"), "high": exec_v4_count(homecare, "risk_level", "HIGH"), "position": "EVV, care plan, billing/payroll readiness"}
    ]

    total_records = sum(r["records"] for r in rows)
    high_total = sum(r["high"] for r in rows)
    conditional_total = sum(r["conditional"] for r in rows)
    ready_total = sum(r["ready"] for r in rows)

    if high_total > 0:
        status = "CRITICAL ITEMS EXIST ACROSS THE ENTERPRISE"
        icon = "❌"
        css = "critical"
    elif conditional_total > 0:
        status = "CONDITIONAL ENTERPRISE READINESS"
        icon = "⚠"
        css = "warning"
    elif total_records > 0:
        status = "ENTERPRISE GOVERNANCE BASELINE HEALTHY"
        icon = "✅"
        css = "healthy"
    else:
        status = "NO MODULE RECORDS YET"
        icon = "ℹ"
        css = "neutral"

    actions = []
    for r in rows:
        if r["high"] > 0:
            actions.append(f"{r['module']}: review {r['high']} high-risk item(s).")
    if not actions:
        actions.append("No high-risk items detected. Continue expanding module evidence coverage.")

    return {
        "rows": rows,
        "total_records": total_records,
        "high_total": high_total,
        "conditional_total": conditional_total,
        "ready_total": ready_total,
        "status": status,
        "icon": icon,
        "css": css,
        "actions": actions
    }


@app.route("/executive-overview-v4-test")
def executive_overview_v4_test():
    metrics = get_executive_v4_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain Executive Overview v4 Test</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#1d4ed8);color:white;padding:34px 42px;border-bottom-left-radius:30px;border-bottom-right-radius:30px}
.container{max-width:1500px;margin:-20px auto 50px;padding:0 26px}
.nav,.card{background:white;border:1px solid #e5e7eb;border-radius:22px;padding:18px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:18px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:6px}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
.status-card{border-left:8px solid #64748b}
.status-card.healthy{border-left-color:#16a34a;background:linear-gradient(135deg,#f0fdf4,#fff)}
.status-card.warning{border-left-color:#f59e0b;background:linear-gradient(135deg,#fffbeb,#fff)}
.status-card.critical{border-left-color:#dc2626;background:linear-gradient(135deg,#fef2f2,#fff)}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top}
a.module-link{font-weight:900;color:#2563eb;text-decoration:none}
.high{color:#dc2626;font-weight:900}.medium{color:#d97706;font-weight:900}.low{color:#16a34a;font-weight:900}
.flagship{background:#fff7ed;font-weight:900}
@media(max-width:1000px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ Executive Overview v4 Test</h1>
<p>Enterprise + Life Sciences + Radiopharma + Homecare Governance Control Tower</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/executive-overview">Executive Current</a>
<a class="active" href="/executive-overview-v4-test">Executive v4 Test</a>
<a href="/modules">Modules</a>
<a href="/platform-health">Platform Health</a>
<a href="/architecture">Architecture</a>
<a href="/sop-governance">SOP</a>
<a href="/shift-assurance">Shift</a>
<a href="/access-governance">Access</a>
<a href="/audit-capa">Audit/CAPA</a>
<a href="/clinical-trial-integrity">Clinical Trial</a>
<a href="/compounding-pharmacy-v1-test">CompoundTrust</a>
<a href="/rlt-trust">RLT-Trust</a>
<a href="/dscsa-trustchain">DSCSA</a>
<a href="/homecare-command">HomeCare</a>
</nav>

<div class="card status-card {{ metrics.css }}">
<h2>{{ metrics.icon }} {{ metrics.status }}</h2>
<p>This page includes the original enterprise modules plus CompoundTrust™, RLT-Trust™, DSCSA TrustChain™, and HomeCare Command™.</p>
</div>

<section class="grid">
<div class="metric"><div class="metric-label">Total Records</div><div class="metric-value">{{ metrics.total_records }}</div></div>
<div class="metric"><div class="metric-label">Ready / Verified</div><div class="metric-value" style="color:#16a34a">{{ metrics.ready_total }}</div></div>
<div class="metric"><div class="metric-label">Conditional</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional_total }}</div></div>
<div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ metrics.high_total }}</div></div>
</section>

<div class="card">
<h2>Enterprise + Vertical Module Board</h2>
<table>
<tr>
<th>Tier</th><th>Module</th><th>Register</th><th>Records</th><th>Ready</th><th>Conditional</th><th>Not Ready</th><th>High Risk</th><th>Positioning</th>
</tr>
{% for r in metrics.rows %}
<tr class="{% if 'RLT-Trust' in r.module %}flagship{% endif %}">
<td>{{ r.tier }}</td>
<td><a class="module-link" href="{{ r.route }}">{{ r.module }}</a></td>
<td>{{ r.register }}</td>
<td><b>{{ r.records }}</b></td>
<td class="low">{{ r.ready }}</td>
<td class="medium">{{ r.conditional }}</td>
<td class="high">{{ r.not_ready }}</td>
<td class="high">{{ r.high }}</td>
<td>{{ r.position }}</td>
</tr>
{% endfor %}
</table>
</div>

<div class="card">
<h2>Leadership Actions</h2>
<ul>
{% for a in metrics.actions %}
<li>{{ a }}</li>
{% endfor %}
</ul>
</div>
</main>
</body>
</html>
    """

    return render_template_string(html, metrics=metrics)


# ============================================================
# MODULES DIRECTORY ACTIVE
# Product suite landing page for all COBIT-Chain modules.
# ============================================================

@app.route("/compoundtrust")
def compoundtrust_page():
    return redirect("/compounding-pharmacy-v1-test")


@app.route("/compounding-pharmacy")
def compounding_pharmacy_page():
    return redirect("/compounding-pharmacy-v1-test")


@app.route("/caretrust")
def caretrust_page():
    return redirect("/homecare-command")


@app.route("/modules")
def modules_directory_page():
    # MODULES_DIRECTORY_ACTIVE
    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain™ Modules Directory</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#1d4ed8);color:white;padding:36px 42px 48px;border-bottom-left-radius:34px;border-bottom-right-radius:34px}
.container{max-width:1500px;margin:-24px auto 50px;padding:0 26px}
.nav,.card,.section{background:white;border:1px solid #e5e7eb;border-radius:24px;padding:20px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:20px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:7px}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.module-card{border:1px solid #e2e8f0;border-radius:22px;padding:20px;background:#ffffff;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.module-card h3{margin:0 0 8px;font-size:19px}
.module-card p{color:#475569;line-height:1.5}
.module-card a{display:inline-block;margin-top:10px;text-decoration:none;background:#0f172a;color:white;padding:9px 12px;border-radius:999px;font-weight:900;font-size:13px}
.badge{display:inline-block;padding:6px 9px;border-radius:999px;font-size:12px;font-weight:900;margin-bottom:10px}
.core{background:#eff6ff;color:#1d4ed8}
.life{background:#ecfdf5;color:#047857}
.flagship{background:#fff7ed;color:#c2410c;border:2px solid #fb923c}
.support{background:#f1f5f9;color:#334155}
.future{background:#faf5ff;color:#7e22ce}
.flagship-card{border:3px solid #fb923c;background:linear-gradient(135deg,#fff7ed,#ffffff)}
.future-card{background:#fbfaff}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:18px;padding:16px;line-height:1.55;margin-bottom:20px}
@media(max-width:1000px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ Product Suite</h1>
<p>Enterprise governance, evidence integrity, regulated life sciences, radiopharma, supply chain, and commercial care-delivery assurance.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/executive-overview">Executive Overview</a>
<a class="active" href="/modules">Modules Directory</a>
<a href="/platform-health">Platform Health</a>
<a href="/architecture">Architecture</a>
<a href="/sop-governance">SOP</a>
<a href="/shift-assurance">Shift</a>
<a href="/access-governance">Access</a>
<a href="/audit-capa">Audit/CAPA</a>
<a href="/clinical-trial-integrity">Clinical Trial</a>
<a href="/rlt-trust">RLT-Trust</a>
<a href="/compoundtrust">CompoundTrust</a>
<a href="/dscsa-trustchain">DSCSA</a>
<a href="/homecare-command">HomeCare</a>
</nav>

<div class="notice">
<b>Platform positioning:</b> RLT-Trust™ is the flagship radiopharma module for enterprise radiopharma / acquired-site RLT operations. 
DSCSA TrustChain™ remains a separate supporting pharma supply-chain module. CompoundTrust™, TrialTrust™, Audit/CAPA, SOP, Access, and Shift Assurance share the same COBIT-Chain evidence integrity engine.
</div>

<div class="section">
<h2>Operational Lineage Demo Flow</h2>
<div class="grid">
<div class="card"><span class="badge strategy">INTAKE</span><h3>QC Ops Intake</h3><p>Upload sanitized Excel/CSV files and convert them into governed, fingerprinted operational datasets with shift, access, CI, and data-integrity signals.</p><a href="/qc-ops-intake">Open QC Ops Intake</a></div>
<div class="card"><span class="badge strategy">IDENTITY</span><h3>Technician Directory</h3><p>Shows Microsoft Entra ID approved technicians from the controlled security group. This proves technician assignment is not manually typed.</p><a href="/technicians">Open Technicians</a></div>
<div class="card"><span class="badge strategy">SHIFT</span><h3>Shift Enterprise</h3><p>Links ticket, CI, Entra-controlled technician, shift, evidence status, readiness score, and hash lineage.</p><a href="/shift-assurance-enterprise">Open Shift Enterprise</a></div>
<div class="card"><span class="badge strategy">HANDOFF</span><h3>Shift Handoff Lineage</h3><p>Formal outgoing-to-incoming technician handoff with acceptance status, evidence readiness, open risk, timestamp, and cryptographic record hash.</p><a href="/shift-handoff-lineage">Open Handoff Lineage</a></div>
<div class="card"><span class="badge strategy">SERVICENOW LIVE</span><h3>ServiceNow Live Tickets</h3><p>Live read-only pull from ServiceNow PDI incidents. Connects real PDI tickets to CI readiness, handoff, evidence, and knowledge governance.</p><a href="/servicenow-tickets-live">Open ServiceNow Live</a></div>
<div class="card"><span class="badge strategy">SERVICENOW</span><h3>ServiceNow CI Readiness</h3><p>Demo-safe ServiceNow-style ticket and CI readiness layer. Designed for ServiceNow PDI and enterprise ServiceNow API connection.</p><a href="/servicenow-ci-readiness">Open ServiceNow CI</a></div>
<div class="card"><span class="badge strategy">FUTURE API</span><h3>ServiceNow PDI Ready</h3><p>Current page uses demo records. Future version will pull incidents, CIs, assignment groups, and knowledge articles from a real ServiceNow PDI.</p><a href="/servicenow-ci-readiness">View API-Ready Model</a></div>
<div class="card"><span class="badge strategy">KNOWLEDGE</span><h3>Knowledge Governance</h3><p>Technician knowledge suggestion, CI/ticket linkage, evidence reference, and future ServiceNow PDI knowledge sync preparation.</p><a href="/knowledge-governance">Open Knowledge Governance</a></div>
<div class="card"><span class="badge strategy">REVIEW</span><h3>Knowledge Review Queue</h3><p>Supervisor review queue for approving, rejecting, requesting revision, or marking knowledge suggestions ready for ServiceNow PDI sync.</p><a href="/knowledge-review">Open Knowledge Review</a></div>
</div>
</div>

<div class="section">
<h2>Core Enterprise Modules</h2>
<div class="grid">
<div class="module-card"><span class="badge core">CORE</span><h3>Manufacturing Assurance / BatchTrust™</h3><p>Protected Manufacturing Core manufacturing dashboard, evidence hashing, Azure Blob records, and integrity verification.</p><a href="/">Open Module</a></div>
<div class="module-card"><span class="badge core">CORE</span><h3>Executive Overview / CommandTrust™</h3><p>Enterprise-wide control tower across all active registers and module readiness scores.</p><a href="/executive-overview">Open Module</a></div>
<div class="module-card"><span class="badge core">CORE</span><h3>SOP Governance / SOPTrust™</h3><p>Dual SOP comparison, SOP-to-reality gap detection, outdated SOP signals, and harmonization decisions.</p><a href="/sop-governance">Open Module</a></div>
<div class="module-card"><span class="badge core">CORE</span><h3>Shift Assurance / ShiftTrust™</h3><p>Equipment handoff, day/night carryover, ServiceNow linkage, and technician accountability.</p><a href="/shift-assurance">Open Module</a></div>
<div class="module-card"><span class="badge core">CORE</span><h3>Access Governance / AccessTrust™</h3><p>myAccess, binder/Excel reconciliation, entitlement review, approval evidence, and access readiness.</p><a href="/access-governance">Open Module</a></div>
<div class="module-card"><span class="badge core">CORE</span><h3>Audit/CAPA / CAPATrust™</h3><p>Audit finding, deviation/CAPA evidence, remediation proof, and effectiveness-readiness gate.</p><a href="/audit-capa">Open Module</a></div>
</div>
</div>

<div class="section">
<h2>Tier 1 Life Sciences Modules</h2>
<div class="grid">
<div class="module-card"><span class="badge life">LIFE SCIENCES</span><h3>TrialTrust™ / Clinical Trial Integrity</h3><p>Clinical evidence register, Microsoft Purview connection, eConsent, retention, ALCOA+, and inspection readiness.</p><a href="/clinical-trial-integrity">Open Module</a></div>
<div class="module-card"><span class="badge life">LIFE SCIENCES</span><h3>CompoundTrust™</h3><p>Sterility-to-release evidence graph for compounding pharmacy, BUD support, EM review, QA review, and release readiness.</p><a href="/compoundtrust">Open Module</a></div>
<div class="module-card flagship-card"><span class="badge flagship">FLAGSHIP RADIOPHARMA</span><h3>RLT-Trust™ / RadiopharmaTrust™</h3><p>Primary radiopharma module: decay-aware governance, isotope-to-patient evidence graph, dose readiness, chain-of-custody, site receipt, and administration window.</p><a href="/rlt-trust">Open Flagship</a></div>
</div>
</div>

<div class="section">
<h2>Supporting Pharma Supply Chain</h2>
<div class="grid">
<div class="module-card"><span class="badge support">SUPPORTING PHARMA</span><h3>DSCSA TrustChain™</h3><p>Standard prescription drug package traceability, trading partner verification, transaction evidence, suspect product workflow, quarantine, notification, and disposition.</p><a href="/dscsa-trustchain">Open Module</a></div>
</div>
</div>

<div class="section">
<h2>Commercial Expansion Modules</h2>
<div class="grid">
<div class="module-card"><span class="badge life">COMMERCIAL EXPANSION</span><h3>HomeCare Command™ / CareTrust™</h3><p>EVV integrity, care plan completion, caregiver credential match, Medicaid/MCO audit evidence, payroll/billing readiness, and family proof-of-care.</p><a href="/homecare-command">Open Module</a></div>
</div>
</div>

<div class="section">
<h2>Future Modules to Build Later</h2>
<div class="grid">
<div class="module-card future-card"><span class="badge future">FUTURE</span><h3>ValidationTrust™</h3><p>CSV validation packs, GxP validation evidence, test scripts, approval evidence, and periodic review.</p></div>
<div class="module-card future-card"><span class="badge future">FUTURE</span><h3>EnviroTrust™</h3><p>Environmental monitoring, room readiness, cleaning verification, excursions, and batch/release impact.</p></div>
<div class="module-card future-card"><span class="badge future">FUTURE</span><h3>CompetencyTrust™</h3><p>Training, qualification, operator competency, role-to-task readiness, and retraining triggers.</p></div>
<div class="module-card future-card"><span class="badge future">FUTURE</span><h3>SupplierTrust™</h3><p>Supplier qualification, quality agreements, vendor audit findings, and remediation evidence.</p></div>
<div class="module-card future-card"><span class="badge future">FUTURE</span><h3>DataTransferTrust™</h3><p>Vendor CSV exports, row-count validation, duplicate checks, reconciliation, and hash integrity.</p></div>
<div class="module-card future-card"><span class="badge future">FUTURE</span><h3>Inventory / Material Chain Trust™</h3><p>Ingredient lots, storage condition, usage, expiry/BUD, release blocking, and material traceability.</p></div>
</div>
</div>
</main>
</body>
</html>
    """
    return render_template_string(html)


# ============================================================
# PLATFORM HEALTH ACTIVE
# Route registry and register health dashboard.
# ============================================================

def get_platform_register_health(filename):
    try:
        df = load_csv(filename)
        if df is None:
            return {
                "exists": "UNKNOWN",
                "records": 0,
                "latest_timestamp": "",
                "columns": "",
                "status": "CHECK REQUIRED",
                "risk": "MEDIUM"
            }

        df = df.fillna("")
        records = len(df)
        latest_timestamp = ""

        if records > 0 and "timestamp" in df.columns:
            latest_timestamp = clean(df.tail(1).iloc[0].get("timestamp"))

        columns = ", ".join([str(c) for c in list(df.columns)[:8]])
        if len(df.columns) > 8:
            columns += " ..."

        if records > 0:
            status = "ACTIVE WITH RECORDS"
            risk = "LOW"
        else:
            status = "REGISTER READY / NO RECORDS YET"
            risk = "MEDIUM"

        return {
            "exists": "YES",
            "records": records,
            "latest_timestamp": latest_timestamp,
            "columns": columns,
            "status": status,
            "risk": risk
        }

    except Exception as e:
        return {
            "exists": "ERROR",
            "records": 0,
            "latest_timestamp": "",
            "columns": str(e),
            "status": "REGISTER ERROR",
            "risk": "HIGH"
        }


def get_platform_health_rows():
    modules = [
        {
            "tier": "Core Enterprise",
            "module": "Manufacturing Assurance / BatchTrust™",
            "route": "/",
            "test_route": "",
            "register": "logs.csv",
            "purpose": "Manufacturing evidence, hashing, Azure Blob records, and Manufacturing Core dashboard."
        },
        {
            "tier": "Core Enterprise",
            "module": "SOP Governance / SOPTrust™",
            "route": "/sop-governance",
            "test_route": "",
            "register": "sop_comparisons.csv",
            "purpose": "Dual SOP comparison, harmonization, SOP gap detection, and outdated SOP signals."
        },
        {
            "tier": "Core Enterprise",
            "module": "Shift Assurance / ShiftTrust™",
            "route": "/shift-assurance",
            "test_route": "/shift-assurance-v2-test",
            "register": "shift_handoffs.csv",
            "purpose": "Equipment handoff, ServiceNow carryover, technician accountability, and shift readiness."
        },
        {
            "tier": "Core Enterprise",
            "module": "Access Governance / AccessTrust™",
            "route": "/access-governance",
            "test_route": "/access-governance-v2-test",
            "register": "access_reviews.csv",
            "purpose": "myAccess, binder reconciliation, approval evidence, and access review readiness."
        },
        {
            "tier": "Core Enterprise",
            "module": "Audit/CAPA / CAPATrust™",
            "route": "/audit-capa",
            "test_route": "/audit-capa-v2-test",
            "register": "audit_capa_register.csv",
            "purpose": "Finding-to-CAPA evidence, remediation proof, and effectiveness readiness."
        },
        {
            "tier": "Life Sciences",
            "module": "TrialTrust™ / Clinical Trial Integrity",
            "route": "/clinical-trial-integrity",
            "test_route": "/clinical-trial-integrity-v3-test",
            "register": "clinical_trial_evidence.csv",
            "purpose": "Purview, eConsent, retention, ALCOA+, deviation/CAPA linkage, and inspection readiness."
        },
        {
            "tier": "Life Sciences",
            "module": "CompoundTrust™",
            "route": "/compoundtrust",
            "test_route": "/compounding-pharmacy-v1-test",
            "register": "compounding_pharmacy_evidence.csv",
            "purpose": "Sterility-to-release evidence, BUD, EM, cleaning, garbing, QA, and release readiness."
        },
        {
            "tier": "Flagship Radiopharma",
            "module": "RLT-Trust™ / RadiopharmaTrust™",
            "route": "/rlt-trust",
            "test_route": "/rlt-trust-v1-test",
            "register": "rlt_dose_evidence.csv",
            "purpose": "Decay-aware dose-to-patient readiness, chain-of-custody, QA release, site receipt, and administration window."
        },
        {
            "tier": "Supporting Pharma Supply Chain",
            "module": "DSCSA TrustChain™",
            "route": "/dscsa-trustchain",
            "test_route": "/dscsa-trustchain-v1-test",
            "register": "dscsa_traceability_evidence.csv",
            "purpose": "Standard prescription drug package traceability, trading partner evidence, suspect product workflow, and disposition."
        },
        {
            "tier": "Commercial Expansion",
            "module": "HomeCare Command™ / CareTrust™",
            "route": "/homecare-command",
            "test_route": "/homecare-command-v1-test",
            "register": "homecare_delivery_evidence.csv",
            "purpose": "EVV, GPS, care-plan completion, caregiver credential, billing, payroll, and Medicaid/MCO audit readiness."
        },
        {
            "tier": "Operational Lineage",
            "module": "QC Ops Intake",
            "route": "/qc-ops-intake",
            "test_route": "",
            "register": "qc_ops_intake_register.csv",
            "purpose": "Excel/CSV intake, dataset fingerprinting, governance classification, and CI/data-integrity signal detection."
        },
        {
            "tier": "Operational Lineage",
            "module": "ShiftTrust™ Enterprise / Entra Assignment",
            "route": "/shift-assurance-enterprise",
            "test_route": "/shift-assurance-entra-test",
            "register": "shift_entra_handoffs.csv",
            "purpose": "Ticket, CI, Microsoft Entra technician assignment, evidence status, readiness score, and shift hash lineage."
        },
        {
            "tier": "Operational Lineage",
            "module": "Formal Shift Handoff Lineage",
            "route": "/shift-handoff-lineage",
            "test_route": "",
            "register": "shift_handoff_lineage.csv",
            "purpose": "Outgoing technician to incoming technician handoff, acceptance, CI context, evidence status, risk, and record hash."
        },
        {
            "tier": "Service Management",
            "module": "ServiceNow CI Readiness",
            "route": "/servicenow-ci-readiness",
            "test_route": "",
            "register": "servicenow_ci_readiness.csv",
            "purpose": "Demo-safe ServiceNow-style ticket/CI readiness, SOP linkage, evidence readiness, data-integrity status, and pre-deviation risk."
        },
        {
            "tier": "Knowledge Governance",
            "module": "Knowledge Governance",
            "route": "/knowledge-governance",
            "test_route": "",
            "register": "knowledge_governance_register.csv",
            "purpose": "Technician knowledge suggestion, CI/ticket linkage, evidence reference, workflow action, and ServiceNow PDI sync readiness."
        },
        {
            "tier": "Knowledge Governance",
            "module": "Knowledge Review Queue",
            "route": "/knowledge-review",
            "test_route": "",
            "register": "knowledge_review_events.csv",
            "purpose": "Supervisor review events, approval/rejection/revision decisions, ServiceNow PDI sync readiness, and review hash lineage."
        }
    ]

    rows = []
    total_records = 0
    active_registers = 0
    high_risk = 0
    medium_risk = 0

    for m in modules:
        health = get_platform_register_health(m["register"])
        row = {**m, **health}
        rows.append(row)

        total_records += int(health.get("records", 0) or 0)

        if health.get("records", 0) > 0:
            active_registers += 1

        if health.get("risk") == "HIGH":
            high_risk += 1
        elif health.get("risk") == "MEDIUM":
            medium_risk += 1

    if high_risk > 0:
        platform_status = "REGISTER ERROR REQUIRES ATTENTION"
        platform_class = "critical"
        platform_icon = "❌"
    elif active_registers > 0:
        platform_status = "PLATFORM ACTIVE"
        platform_class = "healthy"
        platform_icon = "✅"
    else:
        platform_status = "PLATFORM ROUTES READY / NO RECORDS YET"
        platform_class = "warning"
        platform_icon = "⚠"

    return {
        "rows": rows,
        "total_modules": len(modules),
        "active_registers": active_registers,
        "total_records": total_records,
        "high_risk": high_risk,
        "medium_risk": medium_risk,
        "platform_status": platform_status,
        "platform_class": platform_class,
        "platform_icon": platform_icon
    }


@app.route("/platform-health")
def platform_health_page():
    # PLATFORM_HEALTH_ACTIVE
    metrics = get_platform_health_rows()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain™ Platform Health</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#0f766e);color:white;padding:36px 42px 48px;border-bottom-left-radius:34px;border-bottom-right-radius:34px}
.container{max-width:1550px;margin:-24px auto 50px;padding:0 26px}
.nav,.card{background:white;border:1px solid #e5e7eb;border-radius:24px;padding:20px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:20px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:7px}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
.status-card{border-left:8px solid #64748b}
.status-card.healthy{border-left-color:#16a34a;background:linear-gradient(135deg,#f0fdf4,#fff)}
.status-card.warning{border-left-color:#f59e0b;background:linear-gradient(135deg,#fffbeb,#fff)}
.status-card.critical{border-left-color:#dc2626;background:linear-gradient(135deg,#fef2f2,#fff)}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top}
a.module-link{font-weight:900;color:#2563eb;text-decoration:none}
.low{color:#16a34a;font-weight:900}
.medium{color:#d97706;font-weight:900}
.high{color:#dc2626;font-weight:900}
.flagship{background:#fff7ed}
small{color:#64748b}
@media(max-width:1000px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ Platform Health</h1>
<p>Route registry, register health, module storage validation, and enterprise evidence visibility.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/executive-overview">Executive Overview</a>
<a href="/modules">Modules Directory</a>
<a class="active" href="/platform-health">Platform Health</a>
<a href="/architecture">Architecture</a>
<a href="/sop-governance">SOP</a>
<a href="/shift-assurance">Shift</a>
<a href="/access-governance">Access</a>
<a href="/audit-capa">Audit/CAPA</a>
<a href="/clinical-trial-integrity">Clinical Trial</a>
<a href="/rlt-trust">RLT-Trust</a>
<a href="/compoundtrust">CompoundTrust</a>
<a href="/dscsa-trustchain">DSCSA</a>
<a href="/homecare-command">HomeCare</a>
</nav>

<div class="card status-card {{ metrics.platform_class }}">
<h2>{{ metrics.platform_icon }} {{ metrics.platform_status }}</h2>
<p>This page verifies that COBIT-Chain modules are mapped to separate evidence registers. It helps confirm that new modules did not disturb the protected Manufacturing/Manufacturing Core evidence chain.</p>
</div>

<section class="grid">
<div class="metric"><div class="metric-label">Total Modules</div><div class="metric-value">{{ metrics.total_modules }}</div></div>
<div class="metric"><div class="metric-label">Active Registers</div><div class="metric-value" style="color:#16a34a">{{ metrics.active_registers }}</div></div>
<div class="metric"><div class="metric-label">Total Records</div><div class="metric-value">{{ metrics.total_records }}</div></div>
<div class="metric"><div class="metric-label">Register Errors</div><div class="metric-value" style="color:#dc2626">{{ metrics.high_risk }}</div></div>
</section>

<div class="card">
<h2>Route Registry + Register Health Board</h2>
<table>
<tr>
<th>Tier</th>
<th>Module</th>
<th>Main Route</th>
<th>Test Route</th>
<th>Register</th>
<th>Records</th>
<th>Latest Timestamp</th>
<th>Status</th>
<th>Purpose</th>
</tr>
{% for r in metrics.rows %}
<tr class="{% if 'RLT-Trust' in r.module %}flagship{% endif %}">
<td>{{ r.tier }}</td>
<td><b>{{ r.module }}</b></td>
<td><a class="module-link" href="{{ r.route }}">{{ r.route }}</a></td>
<td>{% if r.test_route %}<a class="module-link" href="{{ r.test_route }}">{{ r.test_route }}</a>{% else %}<small>N/A</small>{% endif %}</td>
<td>{{ r.register }}</td>
<td><b>{{ r.records }}</b></td>
<td>{{ r.latest_timestamp }}</td>
<td class="{% if r.risk == 'LOW' %}low{% elif r.risk == 'MEDIUM' %}medium{% else %}high{% endif %}">{{ r.status }}</td>
<td>{{ r.purpose }}</td>
</tr>
{% endfor %}
</table>
</div>

<div class="card">
<h2>Register Separation Principle</h2>
<p>
Each module uses a separate CSV register. This protects the original Manufacturing/Manufacturing Core evidence chain while allowing COBIT-Chain™ to scale into SOP, Shift, Access, Audit/CAPA, Clinical Trial, CompoundTrust™, RLT-Trust™, DSCSA TrustChain™, and HomeCare Command™.
</p>
</div>
</main>
</body>
</html>
    """

    return render_template_string(html, metrics=metrics)


# ============================================================
# ARCHITECTURE PAGE ACTIVE
# COBIT-Chain platform architecture and innovation claims.
# ============================================================

@app.route("/architecture")
def architecture_page():
    # ARCHITECTURE_PAGE_ACTIVE
    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain™ Architecture</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#1d4ed8);color:white;padding:38px 44px 50px;border-bottom-left-radius:34px;border-bottom-right-radius:34px}
.container{max-width:1450px;margin:-24px auto 50px;padding:0 26px}
.nav,.card,.section{background:white;border:1px solid #e5e7eb;border-radius:24px;padding:20px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:20px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:7px}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.two{display:grid;grid-template-columns:repeat(2,1fr);gap:18px}
.card h3{margin:0 0 8px}
.card p,.section p,li{color:#475569;line-height:1.55}
.badge{display:inline-block;padding:7px 10px;border-radius:999px;font-size:12px;font-weight:900;margin-bottom:10px}
.core{background:#eff6ff;color:#1d4ed8}
.flagship{background:#fff7ed;color:#c2410c;border:2px solid #fb923c}
.support{background:#f1f5f9;color:#334155}
.novel{background:#ecfdf5;color:#047857}
.warning{background:#fff7ed;border-left:7px solid #f59e0b;border-radius:18px;padding:16px;line-height:1.55;margin-bottom:20px}
.flow{display:flex;gap:12px;flex-wrap:wrap;margin-top:14px}
.step{flex:1;min-width:190px;background:linear-gradient(135deg,#eff6ff,#ecfeff);border:1px solid #bfdbfe;border-radius:18px;padding:15px}
.step b{display:block;margin-bottom:7px}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:13px}
th{background:#0f172a;color:white;text-align:left;padding:11px}
td{border-bottom:1px solid #e5e7eb;padding:11px;vertical-align:top}
@media(max-width:1000px){.grid,.two{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ Platform Architecture</h1>
<p>Governance-first evidence integrity platform for regulated enterprise, life sciences, radiopharma, supply chain, and care-delivery assurance.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/executive-overview">Executive Overview</a>
<a href="/modules">Modules</a>
<a href="/platform-health">Platform Health</a>
<a class="active" href="/architecture">Architecture</a>
<a href="/sop-governance">SOP</a>
<a href="/clinical-trial-integrity">Clinical Trial</a>
<a href="/rlt-trust">RLT-Trust</a>
<a href="/compoundtrust">CompoundTrust</a>
<a href="/dscsa-trustchain">DSCSA</a>
<a href="/homecare-command">HomeCare</a>
</nav>

<div class="warning">
<b>Positioning:</b> COBIT-Chain™ is not just a dashboard. It is a modular governance assurance layer that links process evidence, cryptographic integrity, readiness scoring, and audit/inspection narratives across multiple regulated domains.
</div>

<div class="section">
<h2>1. What COBIT-Chain™ Is</h2>
<p>
COBIT-Chain™ is a governance-first evidence integrity platform. It helps organizations prove that operational evidence is complete,
traceable, risk-classified, and ready for audit, inspection, remediation, release, or leadership review.
</p>
<p>
The platform does not replace systems of record such as ServiceNow, myAccess, Microsoft Purview, eTMF, EDC, QA systems, or operational systems.
It acts as a governance assurance layer over them.
</p>
</div>

<div class="section">
<h2>2. Core Engine Architecture</h2>
<div class="flow">
<div class="step"><b>1. Evidence Capture</b><span>Users upload or enter process evidence through module-specific forms.</span></div>
<div class="step"><b>2. Hash Integrity</b><span>Evidence records are fingerprinted using SHA-256 or record-hash logic.</span></div>
<div class="step"><b>3. Separate Register</b><span>Each module writes to its own CSV register to avoid corrupting other workflows.</span></div>
<div class="step"><b>4. Risk Scoring</b><span>Module rules calculate readiness score, risk level, and governance signals.</span></div>
<div class="step"><b>5. Executive View</b><span>Executive Overview and Platform Health summarize all active registers.</span></div>
</div>
</div>

<div class="section">
<h2>3. Technical Foundation</h2>
<table>
<tr><th>Component</th><th>Current Role</th><th>Governance Value</th></tr>
<tr><td><b>Flask App</b></td><td>Single deployed web app with modular routes.</td><td>Allows rapid enterprise module expansion without rebuilding from scratch.</td></tr>
<tr><td><b>Azure Blob Storage</b></td><td>Stores CSV registers and evidence outputs.</td><td>Provides cloud-based persistence for evidence registers.</td></tr>
<tr><td><b>SHA-256 / Record Hashes</b></td><td>Creates cryptographic fingerprints for evidence and register records.</td><td>Supports tamper-aware evidence integrity and audit defensibility.</td></tr>
<tr><td><b>Separate CSV Registers</b></td><td>Each module writes to a separate evidence register.</td><td>Protects Manufacturing/Manufacturing Core core while enabling modular expansion.</td></tr>
<tr><td><b>Readiness Scoring</b></td><td>Each module applies domain-specific rules.</td><td>Transforms raw evidence into governance decisions.</td></tr>
</table>
</div>

<div class="section">
<h2>4. Module Register Architecture</h2>
<table>
<tr><th>Module</th><th>Register</th><th>Purpose</th></tr>
<tr><td>Manufacturing Assurance</td><td>logs.csv / baseline_hashes.csv</td><td>Protected Manufacturing Core manufacturing evidence integrity chain.</td></tr>
<tr><td>SOP Governance</td><td>sop_comparisons.csv</td><td>Dual SOP comparison, gap detection, and harmonization evidence.</td></tr>
<tr><td>Shift Assurance</td><td>shift_handoffs.csv</td><td>Equipment handoff, ServiceNow carryover, and technician accountability.</td></tr>
<tr><td>Access Governance</td><td>access_reviews.csv</td><td>myAccess/binder/Excel access review readiness.</td></tr>
<tr><td>Audit/CAPA</td><td>audit_capa_register.csv</td><td>Finding-to-CAPA evidence and effectiveness readiness.</td></tr>
<tr><td>Clinical Trial Integrity</td><td>clinical_trial_evidence.csv</td><td>Purview, eConsent, ALCOA+, and inspection readiness.</td></tr>
<tr><td>CompoundTrust™</td><td>compounding_pharmacy_evidence.csv</td><td>Sterility-to-release evidence and compounding pharmacy readiness.</td></tr>
<tr><td>RLT-Trust™</td><td>rlt_dose_evidence.csv</td><td>Flagship radiopharma dose-to-patient readiness.</td></tr>
<tr><td>DSCSA TrustChain™</td><td>dscsa_traceability_evidence.csv</td><td>Supporting pharma package traceability and suspect product workflow.</td></tr>
<tr><td>HomeCare Command™</td><td>homecare_delivery_evidence.csv</td><td>EVV, care plan, billing, payroll, and care-delivery verification.</td></tr>
</table>
</div>

<div class="section">
<h2>5. RLT-Trust™ Flagship Positioning</h2>
<div class="grid">
<div class="card"><span class="badge flagship">FLAGSHIP</span><h3>RLT-Trust™</h3><p>Main radiopharma module for enterprise radiopharma / acquired-site RLT operations.</p></div>
<div class="card"><span class="badge flagship">ADVANCED ENGINE</span><h3>Decay-Aware Governance Engine™</h3><p>Assesses timing, delivery, appointment, administration deadline, QA release, and readiness risk.</p></div>
<div class="card"><span class="badge flagship">EVIDENCE GRAPH</span><h3>Isotope-to-Patient Evidence Graph™</h3><p>Links isotope/manufacturing, QA release, courier, site receipt, radiation survey, and patient administration evidence.</p></div>
</div>
</div>

<div class="section">
<h2>6. DSCSA Separation</h2>
<p>
DSCSA TrustChain™ is deliberately separate from RLT-Trust™. DSCSA TrustChain™ supports standard prescription drug package
traceability, trading partner evidence, transaction information, suspect product investigation, quarantine, notification, and disposition.
</p>
<p>
RLT-Trust™ remains the flagship for radiopharma dose readiness because RLT risk includes decay timing, release timing,
chain-of-custody, radiation survey, site receipt, and patient administration window.
</p>
</div>

<div class="section">
<h2>7. Innovation / Novelty Claims</h2>
<div class="grid">
<div class="card"><span class="badge novel">NOVELTY</span><h3>Governance Evidence Integrity Engine™</h3><p>Combines governance scoring with cryptographic evidence fingerprinting and module-specific readiness gates.</p></div>
<div class="card"><span class="badge novel">NOVELTY</span><h3>Protocol-to-Purview Evidence Graph™</h3><p>Connects protocol obligations, Microsoft Purview state, retention, DLP, ALCOA+, and inspection readiness.</p></div>
<div class="card"><span class="badge novel">NOVELTY</span><h3>Sterility-to-Release Evidence Graph™</h3><p>Connects compounding evidence from ingredient lot to QA release decision.</p></div>
<div class="card"><span class="badge novel">NOVELTY</span><h3>Isotope-to-Patient Evidence Graph™</h3><p>Connects RLT evidence from isotope/manufacturing through patient administration readiness.</p></div>
<div class="card"><span class="badge novel">NOVELTY</span><h3>Care Delivery Evidence Chain™</h3><p>Connects EVV, GPS, care plan tasks, caregiver credentials, billing, payroll, and family proof-of-care.</p></div>
<div class="card"><span class="badge novel">NOVELTY</span><h3>Cross-Domain Governance Reuse</h3><p>Same core assurance pattern reused across pharma, RLT, compounding, access, audit/CAPA, and homecare.</p></div>
</div>
</div>

<div class="section">
<h2>8. Commercial Roadmap</h2>
<table>
<tr><th>Priority</th><th>Module</th><th>Commercial Rationale</th></tr>
<tr><td><b>Tier 1</b></td><td>RLT-Trust™</td><td>Best aligned to enterprise pharma / acquired-site and External RLT Business Integration Stakeholderchmark Site radiopharma opportunity.</td></tr>
<tr><td><b>Tier 1</b></td><td>CompoundTrust™</td><td>Strong inspection-readiness use case for sterile and compounding pharmacy operations.</td></tr>
<tr><td><b>Tier 1</b></td><td>TrialTrust™</td><td>Supports dissertation, clinical trial governance, Purview, eConsent, and ALCOA+ readiness.</td></tr>
<tr><td><b>Tier 1</b></td><td>SOP / Audit / Access</td><td>Strong enterprise governance modules for regulated IT and QA operations.</td></tr>
<tr><td><b>Expansion</b></td><td>HomeCare Command™</td><td>Commercially useful for homecare owners, Medicaid/MCO audit evidence, billing, and payroll governance.</td></tr>
<tr><td><b>Supporting</b></td><td>DSCSA TrustChain™</td><td>Pharma package traceability and suspect product workflow, separate from RLT dose readiness.</td></tr>
</table>
</div>

<div class="section">
<h2>9. One-Sentence Platform Pitch</h2>
<p>
<b>COBIT-Chain™ is a modular evidence integrity and governance assurance platform that transforms fragmented operational records into cryptographically traceable, risk-scored, audit-ready evidence across regulated enterprise, life sciences, radiopharma, supply chain, and care-delivery environments.</b>
</p>
</div>
</main>
</body>
</html>
    """
    return render_template_string(html)


# ============================================================
# DEMO SCRIPT PAGE ACTIVE
# Stakeholder narrative and guided demo page.
# ============================================================

@app.route("/demo-script")
def demo_script_page():
    # DEMO_SCRIPT_PAGE_ACTIVE
    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain™ Demo Script</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#1d4ed8);color:white;padding:38px 44px 50px;border-bottom-left-radius:34px;border-bottom-right-radius:34px}
.container{max-width:1450px;margin:-24px auto 50px;padding:0 26px}
.nav,.card,.section{background:white;border:1px solid #e5e7eb;border-radius:24px;padding:20px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:20px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:7px}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.two{display:grid;grid-template-columns:repeat(2,1fr);gap:18px}
.card h3{margin:0 0 8px}
.card p,.section p,li{color:#475569;line-height:1.55}
.badge{display:inline-block;padding:7px 10px;border-radius:999px;font-size:12px;font-weight:900;margin-bottom:10px}
.core{background:#eff6ff;color:#1d4ed8}
.flagship{background:#fff7ed;color:#c2410c;border:2px solid #fb923c}
.life{background:#ecfdf5;color:#047857}
.commercial{background:#faf5ff;color:#7e22ce}
.script{background:#f8fafc;border-left:7px solid #2563eb;border-radius:18px;padding:16px;line-height:1.6}
.warning{background:#fff7ed;border-left:7px solid #f59e0b;border-radius:18px;padding:16px;line-height:1.55;margin-bottom:20px}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:13px}
th{background:#0f172a;color:white;text-align:left;padding:11px}
td{border-bottom:1px solid #e5e7eb;padding:11px;vertical-align:top}
@media(max-width:1000px){.grid,.two{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ Stakeholder Demo Script</h1>
<p>Guided narrative for leadership, dissertation, ISACA, USCIS, enterprise pharma / acquired-site, External RLT Business Integration Stakeholderchmark, compounding pharmacy, and homecare audiences.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/executive-overview">Executive Overview</a>
<a href="/modules">Modules</a>
<a href="/platform-health">Platform Health</a>
<a href="/architecture">Architecture</a>
<a class="active" href="/demo-script">Demo Script</a>
<a href="/sop-governance">SOP</a>
<a href="/clinical-trial-integrity">Clinical Trial</a>
<a href="/rlt-trust">RLT-Trust</a>
<a href="/compoundtrust">CompoundTrust</a>
<a href="/dscsa-trustchain">DSCSA</a>
<a href="/homecare-command">HomeCare</a>
</nav>

<div class="warning">
<b>Demo rule:</b> Position COBIT-Chain™ as a governance assurance layer, not as a replacement for enterprise systems.
It connects evidence, integrity, risk scoring, audit readiness, and module-specific decision gates.
</div>

<div class="section">
<h2>1. Opening Pitch</h2>
<div class="script">
COBIT-Chain™ is a modular governance assurance platform that turns fragmented operational evidence into traceable,
risk-scored, audit-ready records. It uses separate evidence registers, SHA-256 style integrity logic, and domain-specific
readiness gates to help regulated organizations prove whether work is complete, controlled, and ready for audit, inspection,
release, or leadership review.
</div>
</div>

<div class="section">
<h2>2. What Problem It Solves</h2>
<div class="grid">
<div class="card"><span class="badge core">PAIN Acquired Site</span><h3>Evidence is fragmented</h3><p>Records sit across binders, Excel, ServiceNow, myAccess, SharePoint, Purview, QA systems, logs, and emails.</p></div>
<div class="card"><span class="badge core">PAIN Acquired Site</span><h3>Audit readiness is manual</h3><p>Teams reconstruct evidence late, often under audit pressure, instead of validating readiness continuously.</p></div>
<div class="card"><span class="badge core">PAIN Acquired Site</span><h3>Approvals do not prove reality</h3><p>A workflow approval may exist, but it does not always prove the actual system, equipment, SOP, or evidence state.</p></div>
</div>
</div>

<div class="section">
<h2>3. Demo Sequence</h2>
<table>
<tr><th>Step</th><th>Page</th><th>What to Say</th></tr>
<tr><td>1</td><td><b>/</b></td><td>Start with the protected Manufacturing/Manufacturing Core dashboard. Emphasize that existing functionality was preserved.</td></tr>
<tr><td>2</td><td><b>/modules</b></td><td>Show that COBIT-Chain™ is now a product suite, not a single dashboard.</td></tr>
<tr><td>3</td><td><b>/platform-health</b></td><td>Show every module, route, evidence register, record count, and health status.</td></tr>
<tr><td>4</td><td><b>/executive-overview</b></td><td>Show the enterprise control tower summarizing all module records and high-risk signals.</td></tr>
<tr><td>5</td><td><b>/sop-governance</b></td><td>Show enterprise pharma / acquired-site-style SOP harmonization and outdated SOP detection.</td></tr>
<tr><td>6</td><td><b>/clinical-trial-integrity</b></td><td>Show Microsoft Purview, eConsent, retention, ALCOA+, and inspection-readiness connection.</td></tr>
<tr><td>7</td><td><b>/rlt-trust</b></td><td>Show RLT-Trust™ as the flagship radiopharma module for dose-to-patient readiness.</td></tr>
<tr><td>8</td><td><b>/architecture</b></td><td>Close with the architecture, novelty claims, and commercialization roadmap.</td></tr>
</table>
</div>

<div class="section">
<h2>4. RLT-Trust™ Flagship Narrative</h2>
<div class="script">
RLT-Trust™ is the flagship radiopharma module because radioligand therapy is not only a cold-chain problem.
It is a decay-window, QA-release, radiation-survey, chain-of-custody, site-receipt, patient-appointment, and administration-readiness problem.
The module is designed to show whether a dose is truly ready to move from isotope/manufacturing to patient administration.
</div>
<br>
<div class="grid">
<div class="card"><span class="badge flagship">FLAGSHIP</span><h3>Decay-Aware Governance Engine™</h3><p>Scores readiness based on timing, QA release, delivery ETA, patient appointment, and administration deadline.</p></div>
<div class="card"><span class="badge flagship">FLAGSHIP</span><h3>Isotope-to-Patient Evidence Graph™</h3><p>Links dose manufacturing, release, courier custody, site receipt, radiation survey, and administration evidence.</p></div>
<div class="card"><span class="badge flagship">FLAGSHIP</span><h3>enterprise pharma / acquired-site/External RLT Business Integration Stakeholderchmark Fit</h3><p>Best aligned with Acquired Radiopharma Site/Enterprise Pharma RLT operations and External RLT Business Integration Stakeholderchmark-style radiopharma manufacturing environments.</p></div>
</div>
</div>

<div class="section">
<h2>5. Clinical Trial + Microsoft Purview Narrative</h2>
<div class="script">
The Clinical Trial Integrity module connects Microsoft Purview compliance logic with COBIT-Chain™ evidence integrity.
Purview can support DLP, sensitivity, retention, and records governance. COBIT-Chain™ adds protocol-to-evidence mapping,
ALCOA+ readiness scoring, deviation/CAPA linkage, and inspection-readiness logic.
</div>
<br>
<table>
<tr><th>Capability</th><th>Purview Role</th><th>COBIT-Chain™ Role</th></tr>
<tr><td>eConsent DLP</td><td>Detect sensitive content and policy matches.</td><td>Track whether the evidence is inspection-ready and linked to protocol obligations.</td></tr>
<tr><td>Retention Labels</td><td>Apply long-term retention or record status.</td><td>Score whether evidence is ready for audit reliance.</td></tr>
<tr><td>CSV Validation Packs</td><td>Store governed validation evidence in SharePoint/Purview ecosystem.</td><td>Hash, validate, score, and connect evidence to governance decisions.</td></tr>
</table>
</div>

<div class="section">
<h2>6. SOP / Audit / Access / Shift Narrative</h2>
<div class="grid">
<div class="card"><span class="badge core">SOP</span><h3>SOPTrust™</h3><p>Compares global/mature SOPs against local/manual SOPs and determines whether the issue is noncompliance, outdated SOP, or harmonization gap.</p></div>
<div class="card"><span class="badge core">AUDIT/CAPA</span><h3>CAPATrust™</h3><p>Connects audit finding, CAPA owner, required evidence, remediation proof, and effectiveness-readiness gate.</p></div>
<div class="card"><span class="badge core">ACCESS</span><h3>AccessTrust™</h3><p>Connects myAccess, binders, Excel, approvals, entitlements, and access-review audit readiness.</p></div>
<div class="card"><span class="badge core">SHIFT</span><h3>ShiftTrust™</h3><p>Captures shift handoff evidence, equipment state, ServiceNow carryover, and technician accountability.</p></div>
</div>
</div>

<div class="section">
<h2>7. Expansion Modules Narrative</h2>
<div class="grid">
<div class="card"><span class="badge life">LIFE SCIENCES</span><h3>CompoundTrust™</h3><p>Compounding pharmacy module for sterility-to-release evidence, BUD, EM, cleaning, garbing, QA review, and release readiness.</p></div>
<div class="card"><span class="badge core">SUPPLY CHAIN</span><h3>DSCSA TrustChain™</h3><p>Supporting module for standard prescription drug package traceability, trading partner evidence, suspect product, quarantine, notification, and disposition.</p></div>
<div class="card"><span class="badge commercial">COMMERCIAL</span><h3>HomeCare Command™</h3><p>Commercial expansion module for EVV, GPS, care-plan completion, caregiver credentials, billing, payroll, and Medicaid/MCO audit readiness.</p></div>
</div>
</div>

<div class="section">
<h2>8. USCIS / Innovation Evidence Narrative</h2>
<div class="script">
The platform demonstrates original applied work in governance engineering: a working prototype, deployed to Azure, with multiple regulated-domain modules,
separate evidence registers, cryptographic evidence integrity logic, domain-specific readiness scoring, and productized concepts such as
Protocol-to-Purview Evidence Graph™, Sterility-to-Release Evidence Graph™, Isotope-to-Patient Evidence Graph™, and Care Delivery Evidence Chain™.
</div>
<br>
<ul>
<li>Shows practical implementation, not only theory.</li>
<li>Supports dissertation novelty and future research direction.</li>
<li>Creates evidence of technical contribution, product thinking, and regulated-industry relevance.</li>
<li>Can support future ISACA, whitepaper, partnership, PhD, or commercialization narrative.</li>
</ul>
</div>

<div class="section">
<h2>9. Closing Statement</h2>
<div class="script">
COBIT-Chain™ is a reusable governance assurance engine. The same core model — evidence capture, integrity fingerprinting,
separate registers, readiness scoring, and executive visibility — can be applied across regulated manufacturing, clinical trials,
radiopharma, compounding pharmacy, supply chain, access governance, Audit/CAPA, and care-delivery operations.
</div>
</div>
</main>
</body>
</html>
    """
    return render_template_string(html)


# ============================================================
# ROADMAP PAGE ACTIVE
# Product roadmap, commercialization, partnership, and research path.
# ============================================================

@app.route("/roadmap")
def roadmap_page():
    # ROADMAP_PAGE_ACTIVE
    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain™ Roadmap</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#1d4ed8);color:white;padding:38px 44px 50px;border-bottom-left-radius:34px;border-bottom-right-radius:34px}
.container{max-width:1450px;margin:-24px auto 50px;padding:0 26px}
.nav,.card,.section{background:white;border:1px solid #e5e7eb;border-radius:24px;padding:20px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:20px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:7px}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.two{display:grid;grid-template-columns:repeat(2,1fr);gap:18px}
.card h3{margin:0 0 8px}
.card p,.section p,li{color:#475569;line-height:1.55}
.badge{display:inline-block;padding:7px 10px;border-radius:999px;font-size:12px;font-weight:900;margin-bottom:10px}
.flagship{background:#fff7ed;color:#c2410c;border:2px solid #fb923c}
.tier1{background:#ecfdf5;color:#047857}
.enterprise{background:#eff6ff;color:#1d4ed8}
.commercial{background:#faf5ff;color:#7e22ce}
.future{background:#f1f5f9;color:#334155}
.research{background:#fef2f2;color:#b91c1c}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:18px;padding:16px;line-height:1.55;margin-bottom:20px}
.warning{background:#fff7ed;border-left:7px solid #f59e0b;border-radius:18px;padding:16px;line-height:1.55;margin-bottom:20px}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:13px}
th{background:#0f172a;color:white;text-align:left;padding:11px}
td{border-bottom:1px solid #e5e7eb;padding:11px;vertical-align:top}
.timeline{border-left:5px solid #2563eb;padding-left:18px}
.milestone{background:#f8fafc;border:1px solid #e2e8f0;border-radius:18px;padding:16px;margin-bottom:14px}
@media(max-width:1000px){.grid,.two{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ Roadmap & Commercialization Strategy</h1>
<p>Product suite roadmap for regulated enterprise, life sciences, radiopharma, supply chain, and care-delivery governance.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/executive-overview">Executive Overview</a>
<a href="/modules">Modules</a>
<a href="/platform-health">Platform Health</a>
<a href="/architecture">Architecture</a>
<a href="/demo-script">Demo Script</a>
<a class="active" href="/roadmap">Roadmap</a>
<a href="/rlt-trust">RLT-Trust</a>
<a href="/clinical-trial-integrity">Clinical Trial</a>
<a href="/compoundtrust">CompoundTrust</a>
<a href="/homecare-command">HomeCare</a>
</nav>

<div class="notice">
<b>Roadmap position:</b> COBIT-Chain™ is being shaped as a reusable governance assurance platform. 
The flagship commercial wedge is <b>RLT-Trust™</b> for radiopharma/RLT operations, while TrialTrust™, CompoundTrust™, SOPTrust™, CAPATrust™, AccessTrust™, and HomeCare Command™ expand the same evidence-integrity engine into adjacent regulated markets.
</div>

<div class="section">
<h2>1. Tier 1 Product Priorities</h2>
<div class="grid">
<div class="card"><span class="badge flagship">FLAGSHIP</span><h3>RLT-Trust™ / RadiopharmaTrust™</h3><p>Main radiopharma/RLT product for dose-to-patient readiness, decay-aware governance, QA release, site receipt, radiation survey, chain-of-custody, and administration window.</p></div>
<div class="card"><span class="badge tier1">TIER 1</span><h3>TrialTrust™</h3><p>Clinical trial integrity module connecting Microsoft Purview, eConsent, retention, CSV validation packs, ALCOA+, deviation/CAPA, and inspection readiness.</p></div>
<div class="card"><span class="badge tier1">TIER 1</span><h3>CompoundTrust™</h3><p>Compounding pharmacy module for sterility-to-release evidence, BUD, environmental monitoring, cleaning, garbing, QA review, and release readiness.</p></div>
<div class="card"><span class="badge tier1">TIER 1</span><h3>SOPTrust™</h3><p>Dual SOP comparison and process-reality gap detection for acquisition integration, harmonization, and outdated SOP identification.</p></div>
<div class="card"><span class="badge tier1">TIER 1</span><h3>CAPATrust™</h3><p>Audit finding, CAPA, remediation evidence, and effectiveness-readiness logic for QA and regulated operations.</p></div>
<div class="card"><span class="badge tier1">TIER 1</span><h3>AccessTrust™</h3><p>Access review, myAccess, binder/Excel reconciliation, approval evidence, and entitlement readiness.</p></div>
</div>
</div>

<div class="section">
<h2>2. Flagship Strategy: RLT-Trust™</h2>
<div class="warning">
<b>Primary commercial thesis:</b> Radiopharma/RLT operations have a unique governance burden because evidence must prove not only product quality, but also timing, decay-window readiness, site receipt, radiation survey, chain-of-custody, and patient administration readiness.
</div>
<table>
<tr><th>RLT Pain Acquired Site</th><th>RLT-Trust™ Response</th><th>Commercial Value</th></tr>
<tr><td>Radioactive decay window</td><td>Decay-Aware Governance Engine™</td><td>Shows whether dose timing remains usable and operationally safe.</td></tr>
<tr><td>QA release timing</td><td>Release-to-delivery readiness scoring</td><td>Helps prevent dose movement before release evidence is complete.</td></tr>
<tr><td>Courier and site handoffs</td><td>Isotope-to-Patient Evidence Graph™</td><td>Creates dose chain-of-custody from production to treatment site.</td></tr>
<tr><td>Patient appointment alignment</td><td>Dose-to-patient readiness gate</td><td>Connects logistics timing with patient administration window.</td></tr>
<tr><td>Inspection evidence</td><td>RLT evidence register and record hash</td><td>Supports audit/inspection traceability and leadership visibility.</td></tr>
</table>
</div>

<div class="section">
<h2>3. Life Sciences Expansion Strategy</h2>
<div class="grid">
<div class="card"><span class="badge tier1">TRIALS</span><h3>TrialTrust™</h3><p>Use dissertation and Purview/eConsent work as the research-backed clinical trial governance module.</p></div>
<div class="card"><span class="badge tier1">COMPOUNDING</span><h3>CompoundTrust™</h3><p>Use sterile/compounding pharmacy inspection pressure as a product wedge for smaller regulated operators.</p></div>
<div class="card"><span class="badge future">SUPPLY CHAIN</span><h3>DSCSA TrustChain™</h3><p>Keep as supporting supply-chain traceability for standard prescription drug package movement and suspect product investigation.</p></div>
</div>
</div>

<div class="section">
<h2>4. Enterprise Governance Expansion</h2>
<table>
<tr><th>Module</th><th>Current Value</th><th>Next Upgrade</th></tr>
<tr><td>SOPTrust™</td><td>Dual SOP comparison and SOP gap detection.</td><td>Add structured gap export, decision history, and SOP maturity scoring.</td></tr>
<tr><td>ShiftTrust™</td><td>Equipment handoff and ServiceNow carryover readiness.</td><td>Add technician trend analytics and recurring equipment issue detection.</td></tr>
<tr><td>AccessTrust™</td><td>Access review readiness and approval evidence scoring.</td><td>Add privileged access review, orphan account detection, and myAccess import logic.</td></tr>
<tr><td>CAPATrust™</td><td>Finding-to-CAPA evidence and effectiveness readiness.</td><td>Add CAPA aging, repeat finding clustering, and effectiveness blocker dashboard.</td></tr>
<tr><td>CommandTrust™</td><td>Executive module dashboard.</td><td>Add exportable leadership summary and PDF-ready evidence pack view.</td></tr>
</table>
</div>

<div class="section">
<h2>5. Commercial Expansion: HomeCare Command™</h2>
<div class="script">
HomeCare Command™ extends the COBIT-Chain™ evidence engine into care-delivery operations. 
The core market problem is proving that a visit happened correctly, the caregiver was qualified, the care plan was completed, the client/family can confirm care, and billing/payroll are supported by verified evidence.
</div>
<br>
<table>
<tr><th>Homecare Pain Acquired Site</th><th>HomeCare Command™ Feature</th><th>Buyer Value</th></tr>
<tr><td>EVV disputes</td><td>EVV Integrity Monitor</td><td>Reduces disputed visits and audit risk.</td></tr>
<tr><td>Billing without proof</td><td>Billing Readiness Gate</td><td>Helps prevent unsupported claims.</td></tr>
<tr><td>Payroll mismatch</td><td>Payroll vs Verified Visit Readiness</td><td>Aligns caregiver pay with verified care evidence.</td></tr>
<tr><td>Family visibility</td><td>Proof-of-Care Evidence Chain™</td><td>Improves trust and transparency.</td></tr>
</table>
</div>

<div class="section">
<h2>6. Future Modules</h2>
<div class="grid">
<div class="card"><span class="badge future">FUTURE</span><h3>ValidationTrust™</h3><p>CSV validation packs, GxP validation evidence, test scripts, approvals, and periodic review.</p></div>
<div class="card"><span class="badge future">FUTURE</span><h3>EnviroTrust™</h3><p>Environmental monitoring, room readiness, excursions, cleaning verification, and release impact.</p></div>
<div class="card"><span class="badge future">FUTURE</span><h3>CompetencyTrust™</h3><p>Training, qualification, operator competency, role-to-task readiness, and retraining triggers.</p></div>
<div class="card"><span class="badge future">FUTURE</span><h3>SupplierTrust™</h3><p>Supplier qualification, quality agreements, vendor audits, and remediation evidence.</p></div>
<div class="card"><span class="badge future">FUTURE</span><h3>DataTransferTrust™</h3><p>CSV/vendor exports, row-count validation, duplicate checks, reconciliation, and hash integrity.</p></div>
<div class="card"><span class="badge future">FUTURE</span><h3>Inventory / Material Chain Trust™</h3><p>Ingredient lots, storage conditions, expiry/BUD, usage, release blocking, and material traceability.</p></div>
</div>
</div>

<div class="section">
<h2>7. Partnership Path</h2>
<div class="two">
<div class="card"><span class="badge research">ACADEMIC</span><h3>University / PhD Path</h3><p>Use COBIT-Chain™ as a governance engineering research program across clinical trials, radiopharma, compounding pharmacy, and regulated digital assurance.</p></div>
<div class="card"><span class="badge research">PROFESSIONAL</span><h3>ISACA / Governance Community</h3><p>Publish control-to-evidence framework, governance assurance model, and COBIT 2019 operationalization pattern.</p></div>
<div class="card"><span class="badge tier1">PHARMA</span><h3>Pharma / RLT Partners</h3><p>Position RLT-Trust™ for RLT manufacturing, dose release, chain-of-custody, and dose-to-patient readiness.</p></div>
<div class="card"><span class="badge commercial">COMMERCIAL</span><h3>Homecare / Compounding Operators</h3><p>Productize smaller-market versions where audit evidence, billing, release, and operational trust are painful.</p></div>
</div>
</div>

<div class="section">
<h2>8. USCIS / Innovation Narrative</h2>
<ul>
<li><b>Working prototype:</b> deployed Flask/Azure app with multiple active modules.</li>
<li><b>Technical contribution:</b> evidence hashing, separate registers, readiness scoring, and modular governance architecture.</li>
<li><b>Regulated industry relevance:</b> clinical trials, radiopharma, compounding pharmacy, access governance, CAPA, SOP, and homecare.</li>
<li><b>Commercial direction:</b> RLT-Trust™ flagship plus adjacent life sciences and care-delivery modules.</li>
<li><b>Research path:</b> COBIT 2019-aligned governance assurance framework with future PhD and publication potential.</li>
</ul>
</div>

<div class="section">
<h2>9. Implementation Roadmap</h2>
<div class="timeline">
<div class="milestone"><b>Phase 1 — Stabilize Platform</b><br>Protect Manufacturing/Manufacturing Core, lock tags, maintain routes, and validate all registers.</div>
<div class="milestone"><b>Phase 2 — Strengthen RLT-Trust™</b><br>Add decay buffer logic, time-window visuals, RLT evidence pack, and flagship visual hierarchy.</div>
<div class="milestone"><b>Phase 3 — Strengthen Clinical Trial/Purview</b><br>Add eConsent DLP test checklist, retention label status, and CSV validation pack readiness.</div>
<div class="milestone"><b>Phase 4 — Commercial Modules</b><br>Improve CompoundTrust™ and HomeCare Command™ for external demos and buyer conversations.</div>
<div class="milestone"><b>Phase 5 — Publish / Partner / Protect</b><br>Create whitepaper, ISACA article draft, invention disclosure package, GitHub evidence, and partner pitch deck.</div>
</div>
</div>

<div class="section">
<h2>10. One-Line Roadmap Summary</h2>
<p>
<b>COBIT-Chain™ will evolve from a working governance prototype into a product suite, led by RLT-Trust™ as the flagship radiopharma assurance module and expanded through clinical trials, compounding pharmacy, enterprise governance, supply chain, and homecare evidence integrity modules.</b>
</p>
</div>
</main>
</body>
</html>
    """
    return render_template_string(html)


# ============================================================
# COMMAND CENTER PAGE ACTIVE
# Main navigation hub for COBIT-Chain platform.
# ============================================================

@app.route("/command-center")
def command_center_page():
    # COMMAND_CENTER_PAGE_ACTIVE
    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain™ Command Center</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:radial-gradient(circle at top left,#2563eb 0%,#0f2745 42%,#071527 100%);color:white;padding:40px 44px 52px;border-bottom-left-radius:34px;border-bottom-right-radius:34px}
.container{max-width:1500px;margin:-26px auto 50px;padding:0 26px}
.nav,.section,.card{background:white;border:1px solid #e5e7eb;border-radius:24px;padding:20px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:20px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:7px}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.card h3{margin:0 0 8px;font-size:19px}
.card p{color:#475569;line-height:1.5}
.card a{display:inline-block;margin-top:10px;text-decoration:none;background:#0f172a;color:white;padding:9px 12px;border-radius:999px;font-weight:900;font-size:13px}
.badge{display:inline-block;padding:7px 10px;border-radius:999px;font-size:12px;font-weight:900;margin-bottom:10px}
.strategy{background:#eff6ff;color:#1d4ed8}
.core{background:#ecfdf5;color:#047857}
.flagship{background:#fff7ed;color:#c2410c;border:2px solid #fb923c}
.support{background:#f1f5f9;color:#334155}
.commercial{background:#faf5ff;color:#7e22ce}
.flagship-card{border:3px solid #fb923c;background:linear-gradient(135deg,#fff7ed,#ffffff)}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:18px;padding:16px;line-height:1.55;margin-bottom:20px}
.warning{background:#fff7ed;border-left:7px solid #f59e0b;border-radius:18px;padding:16px;line-height:1.55;margin-bottom:20px}
.quick-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:20px}
.quick-grid a{text-align:center;text-decoration:none;background:#0f172a;color:white;padding:12px;border-radius:16px;font-weight:900;font-size:13px}
@media(max-width:1100px){.grid{grid-template-columns:1fr}.quick-grid{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<section class="hero">
<h1>COBIT-Chain™ Command Center</h1>
<p>One navigation hub for the full governance assurance platform: executive dashboard, product suite, architecture, roadmap, and all active modules.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/command-center" class="active">Command Center</a>
<a href="/executive-overview">Executive Overview</a>
<a href="/modules">Modules</a>
<a href="/platform-health">Platform Health</a>
<a href="/architecture">Architecture</a>
<a href="/demo-script">Demo Script</a>
<a href="/roadmap">Roadmap</a>
<a href="/qc-ops-intake">QC Ops Intake</a>
<a href="/technicians">Technicians</a>
<a href="/shift-assurance-enterprise">Shift Enterprise</a>
<a href="/shift-handoff-lineage">Handoff Lineage</a>
<a href="/servicenow-tickets-live">ServiceNow Live</a>
<a href="/servicenow-tickets-live">ServiceNow Live</a>
<a href="/servicenow-ci-readiness">ServiceNow CI</a>
<a href="/knowledge-governance">Knowledge Governance</a>
<a href="/knowledge-review">Knowledge Review</a>
</nav>

<div class="notice">
<b>Use this page for demos.</b> Start here, then move to Executive Overview, Modules Directory, Platform Health, Architecture, Demo Script, Roadmap, and the flagship RLT-Trust™ module.
</div>

<div class="quick-grid">
<a href="/executive-overview">Executive</a>
<a href="/modules">Modules</a>
<a href="/platform-health">Health</a>
<a href="/architecture">Architecture</a>
<a href="/demo-script">Demo</a>
<a href="/roadmap">Roadmap</a>
<a href="/qc-ops-intake">QC Intake</a>
<a href="/shift-handoff-lineage">Handoff</a>
<a href="/servicenow-ci-readiness">SN CI</a>
</div>

<div class="section">
<h2>Strategic Platform Pages</h2>
<div class="grid">
<div class="card"><span class="badge strategy">CONTROL TOWER</span><h3>Executive Overview</h3><p>Full enterprise + vertical dashboard showing module records, readiness, conditional items, and high-risk signals.</p><a href="/executive-overview">Open Executive Overview</a></div>
<div class="card"><span class="badge strategy">PRODUCT SUITE</span><h3>Modules Directory</h3><p>Clean product-suite page showing core enterprise modules, life sciences modules, RLT flagship, DSCSA, and HomeCare.</p><a href="/modules">Open Modules</a></div>
<div class="card"><span class="badge strategy">SYSTEM HEALTH</span><h3>Platform Health</h3><p>Route registry and register-health page showing each module, route, CSV register, record count, and status.</p><a href="/platform-health">Open Platform Health</a></div>
<div class="card"><span class="badge strategy">ARCHITECTURE</span><h3>Architecture & Innovation Claims</h3><p>Explains the COBIT-Chain™ engine, Azure Blob, SHA-256, module registers, novelty claims, and RLT positioning.</p><a href="/architecture">Open Architecture</a></div>
<div class="card"><span class="badge strategy">PRESENTATION</span><h3>Stakeholder Demo Script</h3><p>Guided narrative for IT Leadership, Integration Lead, dissertation reviewers, ISACA, USCIS, partners, and future customers.</p><a href="/demo-script">Open Demo Script</a></div>
<div class="card"><span class="badge strategy">COMMERCIALIZATION</span><h3>Roadmap</h3><p>Commercialization, partnership, PhD, USCIS, ISACA, and product-suite roadmap with RLT-Trust™ as the flagship.</p><a href="/roadmap">Open Roadmap</a></div>
</div>
</div>

<div class="section">
<h2>Flagship Module</h2>
<div class="grid">
<div class="card flagship-card"><span class="badge flagship">FLAGSHIP RADIOPHARMA</span><h3>RLT-Trust™ / RadiopharmaTrust™</h3><p>Main radiopharma/RLT module for dose-to-patient readiness, decay-aware governance, isotope-to-patient evidence graph, QA release, courier chain-of-custody, site receipt, radiation survey, and administration window.</p><a href="/rlt-trust">Open RLT-Trust™</a></div>
<div class="card"><span class="badge flagship">ALIAS</span><h3>Radiopharma Trust</h3><p>Clean alias route pointing to the same RLT-Trust™ flagship module.</p><a href="/radiopharma-trust">Open Radiopharma Trust</a></div>
<div class="card"><span class="badge flagship">EVIDENCE REGISTER</span><h3>RLT Dose Evidence</h3><p>Uses rlt_dose_evidence.csv to track dose ID, batch ID, isotope, QA release, delivery, site receipt, administration, decay window, risk, and readiness.</p><a href="/platform-health">View Register Health</a></div>
</div>
</div>

<div class="section">
<h2>Core Enterprise Modules</h2>
<div class="grid">
<div class="card"><span class="badge core">PROTECTED CORE</span><h3>Manufacturing Assurance / BatchTrust™</h3><p>Protected Manufacturing/Manufacturing Core dashboard, evidence hashing, Azure Blob records, and verification engine.</p><a href="/">Open Manufacturing</a></div>
<div class="card"><span class="badge core">SOP</span><h3>SOP Governance / SOPTrust™</h3><p>Dual SOP comparison, SOP-to-reality gap detection, outdated SOP signals, and harmonization decisions.</p><a href="/sop-governance">Open SOP Governance</a></div>
<div class="card"><span class="badge core">SHIFT</span><h3>Shift Assurance / ShiftTrust™</h3><p>Equipment handoff, day/night carryover, ServiceNow linkage, technician accountability, and shift readiness.</p><a href="/shift-assurance">Open Shift Assurance</a></div>
<div class="card"><span class="badge core">ACCESS</span><h3>Access Governance / AccessTrust™</h3><p>myAccess, binder/Excel access evidence, approval references, system owner review, and audit readiness.</p><a href="/access-governance">Open Access Governance</a></div>
<div class="card"><span class="badge core">AUDIT/CAPA</span><h3>Audit/CAPA / CAPATrust™</h3><p>Audit finding, deviation/CAPA evidence, remediation proof, effectiveness readiness, and risk scoring.</p><a href="/audit-capa">Open Audit/CAPA</a></div>
<div class="card"><span class="badge core">EXECUTIVE</span><h3>CommandTrust™</h3><p>Leadership control tower summarizing active registers, risk levels, and module readiness.</p><a href="/executive-overview">Open CommandTrust™</a></div>
</div>
</div>

<div class="section">
<h2>Life Sciences Modules</h2>
<div class="grid">
<div class="card"><span class="badge core">CLINICAL</span><h3>TrialTrust™ / Clinical Trial Integrity</h3><p>Microsoft Purview, eConsent DLP, retention labels, ALCOA+, CSV validation packs, deviation/CAPA, and inspection readiness.</p><a href="/clinical-trial-integrity">Open TrialTrust™</a></div>
<div class="card"><span class="badge core">COMPOUNDING</span><h3>CompoundTrust™</h3><p>Sterility-to-release evidence graph, BUD support, environmental monitoring, cleaning, garbing, QA review, and release readiness.</p><a href="/compoundtrust">Open CompoundTrust™</a></div>
<div class="card"><span class="badge support">SUPPLY CHAIN</span><h3>DSCSA TrustChain™</h3><p>Supporting supply-chain module for standard prescription package traceability, trading partner verification, suspect product, quarantine, and disposition.</p><a href="/dscsa-trustchain">Open DSCSA TrustChain™</a></div>
</div>
</div>

<div class="section">
<h2>Commercial Expansion Module</h2>
<div class="grid">
<div class="card"><span class="badge commercial">HOMECARE</span><h3>HomeCare Command™ / CareTrust™</h3><p>EVV, GPS, care plan completion, caregiver credential matching, client/family confirmation, billing, payroll, and Medicaid/MCO audit readiness.</p><a href="/homecare-command">Open HomeCare Command™</a></div>
<div class="card"><span class="badge commercial">ALIAS</span><h3>CareTrust™</h3><p>Clean alias route for the HomeCare Command™ module.</p><a href="/caretrust">Open CareTrust™</a></div>
<div class="card"><span class="badge commercial">EVIDENCE REGISTER</span><h3>Homecare Delivery Evidence</h3><p>Uses homecare_delivery_evidence.csv to track visit verification, evidence readiness, billing/payroll readiness, and risk signals.</p><a href="/platform-health">View Register Health</a></div>
</div>
</div>

<div class="warning">
<b>Suggested demo path:</b> Command Center → QC Ops Intake → Technicians → Shift Enterprise → Handoff Lineage → ServiceNow Live Tickets → ServiceNow CI Readiness → Knowledge Governance → Knowledge Review → Executive Overview → Architecture → Roadmap.
</div>
</main>
</body>
</html>
    """
    return render_template_string(html)


# ============================================================
# DEMO LANDING ALIASES ACTIVE
# Clean demo URLs. Protected / homepage remains Manufacturing/Manufacturing Core.
# ============================================================

@app.route("/home")
def home_alias_page():
    # DEMO_LANDING_ALIASES_ACTIVE
    return redirect("/command-center")


@app.route("/start")
def start_alias_page():
    return redirect("/command-center")


@app.route("/suite")
def suite_alias_page():
    return redirect("/modules")


# ============================================================
# QC OPS INTAKE ACTIVE
# Excel/CSV to governed operational dataset intake page.
# ============================================================

QC_OPS_INTAKE_FILE = "qc_ops_intake_register.csv"


def prepare_qc_ops_intake_register():
    df = load_csv(QC_OPS_INTAKE_FILE)
    return ensure_cols(df, [
        "intake_id", "timestamp", "filename", "file_type", "file_hash",
        "rows", "columns", "missing_cells", "duplicate_rows",
        "detected_dataset_type", "recommended_module",
        "servicenow_ci_readiness", "shift_relevance",
        "access_relevance", "data_integrity_relevance",
        "governance_score", "risk_level", "governance_signals",
        "previous_hash", "record_hash"
    ])


def qc_safe_text(value):
    return str(value or "").strip()


def qc_hash_bytes(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def qc_read_uploaded_table(file_storage):
    from io import BytesIO
    import pandas as pd

    filename = qc_safe_text(file_storage.filename)
    content = file_storage.read()

    if not content:
        raise ValueError("Uploaded file is empty.")

    lower = filename.lower()

    if lower.endswith(".csv"):
        df = pd.read_csv(BytesIO(content))
        file_type = "CSV"
    elif lower.endswith(".xlsx") or lower.endswith(".xls"):
        df = pd.read_excel(BytesIO(content))
        file_type = "Excel"
    else:
        raise ValueError("Only .csv, .xlsx, or .xls files are supported for this intake page.")

    df = df.fillna("")
    return filename, file_type, content, df


def qc_detect_dataset_type(df):
    columns = [str(c).lower() for c in df.columns]
    joined_cols = " ".join(columns)
    sample_text = ""

    try:
        sample_text = " ".join(df.head(25).astype(str).values.flatten()).lower()
    except Exception:
        sample_text = ""

    combined = joined_cols + " " + sample_text

    scores = {
        "Shift / Day-in-the-Life Dataset": 0,
        "Access Governance Dataset": 0,
        "Work Order / Equipment Matrix": 0,
        "ServiceNow CI Preparation Dataset": 0,
        "Data Integrity / CMMS Evidence Dataset": 0,
        "General Operational Governance Dataset": 1
    }

    shift_terms = ["shift", "task", "handoff", "day in the life", "production manager", "teams", "email", "hours", "owner", "assigned"]
    access_terms = ["access", "user", "role", "system list", "removed", "left site", "disable", "employee", "custodian", "approver"]
    work_order_terms = ["work order", "workorder", "cmms", "eqp", "equipment", "matrix", "daylight", "spring", "fall", "bms", "calibration"]
    ci_terms = ["ci", "cmdb", "configuration item", "service", "dependency", "system owner", "business owner", "support group"]
    di_terms = ["audit trail", "event log", "backup", "system image", "data integrity", "alcoa", "spreadsheet", "validated", "review"]

    for term in shift_terms:
        if term in combined:
            scores["Shift / Day-in-the-Life Dataset"] += 1

    for term in access_terms:
        if term in combined:
            scores["Access Governance Dataset"] += 1

    for term in work_order_terms:
        if term in combined:
            scores["Work Order / Equipment Matrix"] += 1

    for term in ci_terms:
        if term in combined:
            scores["ServiceNow CI Preparation Dataset"] += 1

    for term in di_terms:
        if term in combined:
            scores["Data Integrity / CMMS Evidence Dataset"] += 1

    detected = max(scores, key=scores.get)

    if scores[detected] <= 1:
        detected = "General Operational Governance Dataset"

    return detected, scores


def qc_recommend_module(detected_type):
    mapping = {
        "Shift / Day-in-the-Life Dataset": "ShiftTrust™ / Shift Assurance",
        "Access Governance Dataset": "AccessTrust™ / Access Governance",
        "Work Order / Equipment Matrix": "Data Integrity Assurance + ShiftTrust™",
        "ServiceNow CI Preparation Dataset": "ServiceNow CI Readiness / Platform Health",
        "Data Integrity / CMMS Evidence Dataset": "Data Integrity Assurance / Audit-CAPA",
        "General Operational Governance Dataset": "QC Ops Governance Intake"
    }
    return mapping.get(detected_type, "QC Ops Governance Intake")


def qc_score_dataset(df, detected_type):
    rows = len(df)
    columns = len(df.columns)
    missing_cells = int((df == "").sum().sum()) if rows > 0 else 0
    duplicate_rows = int(df.duplicated().sum()) if rows > 0 else 0

    score = 100
    signals = []

    if rows == 0:
        score -= 50
        signals.append("Dataset has no rows.")

    if columns < 3:
        score -= 20
        signals.append("Dataset has very few columns for governance extraction.")

    if missing_cells > 0:
        score -= min(25, missing_cells)
        signals.append(f"Dataset contains {missing_cells} missing or blank cells.")

    if duplicate_rows > 0:
        score -= min(20, duplicate_rows * 5)
        signals.append(f"Dataset contains {duplicate_rows} duplicate row(s).")

    col_text = " ".join([str(c).lower() for c in df.columns])

    if detected_type == "Access Governance Dataset":
        required_terms = ["user", "system", "access"]
        for term in required_terms:
            if term not in col_text:
                score -= 8
                signals.append(f"Access dataset may be missing a clear '{term}' field.")

    if detected_type in ["Work Order / Equipment Matrix", "ServiceNow CI Preparation Dataset"]:
        if "eqp" not in col_text and "equipment" not in col_text and "system" not in col_text:
            score -= 15
            signals.append("Equipment/system identifier field is not clearly detected.")

    if detected_type == "Shift / Day-in-the-Life Dataset":
        if "task" not in col_text and "owner" not in col_text and "shift" not in col_text:
            score -= 15
            signals.append("Shift/task ownership fields are not clearly detected.")

    if not signals:
        signals.append("Dataset appears suitable for governance intake and fingerprinting.")

    score = max(score, 0)

    if score >= 85:
        risk = "LOW"
    elif score >= 60:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    return score, risk, signals, rows, columns, missing_cells, duplicate_rows


def qc_flag_relevance(detected_type, scores):
    shift = "YES" if detected_type == "Shift / Day-in-the-Life Dataset" or scores.get("Shift / Day-in-the-Life Dataset", 0) >= 2 else "POSSIBLE"
    access = "YES" if detected_type == "Access Governance Dataset" or scores.get("Access Governance Dataset", 0) >= 2 else "POSSIBLE"
    data_integrity = "YES" if detected_type in ["Data Integrity / CMMS Evidence Dataset", "Work Order / Equipment Matrix"] or scores.get("Data Integrity / CMMS Evidence Dataset", 0) >= 2 else "POSSIBLE"
    ci_ready = "YES" if detected_type in ["ServiceNow CI Preparation Dataset", "Work Order / Equipment Matrix"] or scores.get("ServiceNow CI Preparation Dataset", 0) >= 2 else "POSSIBLE"

    return shift, access, data_integrity, ci_ready


def save_qc_ops_intake_result(filename, file_type, file_hash, rows, columns, missing_cells,
                              duplicate_rows, detected_type, recommended_module,
                              ci_ready, shift_rel, access_rel, di_rel,
                              governance_score, risk_level, signals):
    df = prepare_qc_ops_intake_register()

    timestamp = datetime.datetime.utcnow().isoformat()
    intake_id = "QCOPS-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    previous_hash = "GENESIS"
    if not df.empty:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    record_hash = sha256_text(
        intake_id + timestamp + filename + file_hash + detected_type +
        recommended_module + str(governance_score) + previous_hash
    )

    row = pd.DataFrame([{
        "intake_id": intake_id,
        "timestamp": timestamp,
        "filename": filename,
        "file_type": file_type,
        "file_hash": file_hash,
        "rows": rows,
        "columns": columns,
        "missing_cells": missing_cells,
        "duplicate_rows": duplicate_rows,
        "detected_dataset_type": detected_type,
        "recommended_module": recommended_module,
        "servicenow_ci_readiness": ci_ready,
        "shift_relevance": shift_rel,
        "access_relevance": access_rel,
        "data_integrity_relevance": di_rel,
        "governance_score": governance_score,
        "risk_level": risk_level,
        "governance_signals": " | ".join(signals),
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, QC_OPS_INTAKE_FILE)

    return intake_id, record_hash


def get_qc_ops_intake_metrics():
    df = prepare_qc_ops_intake_register()
    if df.empty:
        return {"total": 0, "low": 0, "medium": 0, "high": 0, "recent": []}

    df = df.fillna("")
    return {
        "total": len(df),
        "low": len(df[df["risk_level"] == "LOW"]),
        "medium": len(df[df["risk_level"] == "MEDIUM"]),
        "high": len(df[df["risk_level"] == "HIGH"]),
        "recent": df.tail(12).to_dict("records")
    }


@app.route("/qc-ops-intake", methods=["GET", "POST"])
def qc_ops_intake_page():
    # QC_OPS_INTAKE_ACTIVE
    result = None

    if request.method == "POST":
        try:
            uploaded = request.files.get("governance_file")
            if not uploaded or not uploaded.filename:
                raise ValueError("Please upload an Excel or CSV file.")

            filename, file_type, content, df = qc_read_uploaded_table(uploaded)
            file_hash = qc_hash_bytes(content)
            detected_type, detection_scores = qc_detect_dataset_type(df)
            recommended_module = qc_recommend_module(detected_type)
            governance_score, risk_level, signals, rows, columns, missing_cells, duplicate_rows = qc_score_dataset(df, detected_type)
            shift_rel, access_rel, di_rel, ci_ready = qc_flag_relevance(detected_type, detection_scores)

            intake_id, record_hash = save_qc_ops_intake_result(
                filename, file_type, file_hash, rows, columns, missing_cells,
                duplicate_rows, detected_type, recommended_module,
                ci_ready, shift_rel, access_rel, di_rel,
                governance_score, risk_level, signals
            )

            preview = df.head(8).to_dict("records")
            preview_columns = [str(c) for c in df.columns]

            result = {
                "error": "",
                "intake_id": intake_id,
                "filename": filename,
                "file_type": file_type,
                "file_hash": file_hash,
                "record_hash": record_hash,
                "rows": rows,
                "columns": columns,
                "missing_cells": missing_cells,
                "duplicate_rows": duplicate_rows,
                "detected_type": detected_type,
                "recommended_module": recommended_module,
                "governance_score": governance_score,
                "risk_level": risk_level,
                "signals": signals,
                "shift_rel": shift_rel,
                "access_rel": access_rel,
                "di_rel": di_rel,
                "ci_ready": ci_ready,
                "preview": preview,
                "preview_columns": preview_columns
            }

        except Exception as e:
            result = {"error": str(e)}

    metrics = get_qc_ops_intake_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>AssuranceLayer™ QC Ops Intake</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#0f766e);color:white;padding:38px 44px 50px;border-bottom-left-radius:34px;border-bottom-right-radius:34px}
.container{max-width:1500px;margin:-24px auto 50px;padding:0 26px}
.nav,.card,.panel{background:white;border:1px solid #e5e7eb;border-radius:24px;padding:20px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:20px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:7px}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.layout{display:grid;grid-template-columns:430px 1fr;gap:20px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
input,button{width:100%;border-radius:13px;border:1px solid #dbe3ef;padding:12px;margin:8px 0;font-size:14px}
button{border:none;background:linear-gradient(135deg,#0f766e,#2563eb);color:white;font-weight:900;cursor:pointer}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
.warning{background:#fff7ed;border-left:7px solid #f59e0b;border-radius:16px;padding:14px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top;max-width:260px;word-break:break-word}
.low{color:#16a34a;font-weight:900}.medium{color:#d97706;font-weight:900}.high{color:#dc2626;font-weight:900}
.hash{font-family:Consolas,monospace;font-size:11px;word-break:break-all;color:#334155}
@media(max-width:1000px){.grid,.layout{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>AssuranceLayer™ QC Ops Intake</h1>
<p>Excel / CSV → Governed Operational Dataset → Fingerprint → Shift, Access, CI, CMMS, and Data Integrity Signals</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/command-center">Command Center</a>
<a href="/executive-overview">Executive</a>
<a href="/modules">Modules</a>
<a href="/platform-health">Platform Health</a>
<a href="/architecture">Architecture</a>
<a href="/demo-script">Demo Script</a>
<a href="/roadmap">Roadmap</a>
<a class="active" href="/qc-ops-intake">QC Ops Intake</a>
</nav>

<div class="warning">
<b>Demo caution:</b> upload sanitized/demo files only. Do not upload real employee identifiers, proprietary equipment lists, or company-specific confidential records into a public demo environment.
</div>

{% if result and result.error %}
<div class="error">{{ result.error }}</div>
{% elif result %}
<div class="notice">
<b>Governed dataset created:</b> {{ result.intake_id }}<br>
<b>Detected Type:</b> {{ result.detected_type }}<br>
<b>Recommended Module:</b> {{ result.recommended_module }}<br>
<b>Governance Score:</b> {{ result.governance_score }}% —
<b class="{% if result.risk_level == 'LOW' %}low{% elif result.risk_level == 'MEDIUM' %}medium{% else %}high{% endif %}">{{ result.risk_level }}</b>
<ul>{% for s in result.signals %}<li>{{ s }}</li>{% endfor %}</ul>
</div>
{% endif %}

<section class="grid">
<div class="metric"><div class="metric-label">Total Intakes</div><div class="metric-value">{{ metrics.total }}</div></div>
<div class="metric"><div class="metric-label">Low Risk</div><div class="metric-value" style="color:#16a34a">{{ metrics.low }}</div></div>
<div class="metric"><div class="metric-label">Medium Risk</div><div class="metric-value" style="color:#f59e0b">{{ metrics.medium }}</div></div>
<div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ metrics.high }}</div></div>
</section>

<section class="layout">
<aside class="panel">
<h2>Upload Operational Dataset</h2>
<p>Use this for sanitized Excel or CSV files such as shift task lists, access lists, work order matrices, equipment owner lists, and CI preparation files.</p>
<form method="POST" action="/qc-ops-intake" enctype="multipart/form-data">
<input type="file" name="governance_file" accept=".xlsx,.xls,.csv" required>
<button type="submit">Analyze & Fingerprint Dataset</button>
</form>

<div class="card">
<h3>What this produces</h3>
<ul>
<li>SHA-256 file fingerprint</li>
<li>Rows, columns, blanks, duplicates</li>
<li>Detected governance dataset type</li>
<li>Shift/access/data-integrity relevance</li>
<li>ServiceNow CI readiness signal</li>
<li>Recommended target module</li>
</ul>
</div>
</aside>

<section class="card">
{% if result and not result.error %}
<h2>Governance Analysis Result</h2>
<table>
<tr><th>Field</th><th>Value</th></tr>
<tr><td>Filename</td><td>{{ result.filename }}</td></tr>
<tr><td>File Type</td><td>{{ result.file_type }}</td></tr>
<tr><td>Rows / Columns</td><td>{{ result.rows }} / {{ result.columns }}</td></tr>
<tr><td>Missing Cells</td><td>{{ result.missing_cells }}</td></tr>
<tr><td>Duplicate Rows</td><td>{{ result.duplicate_rows }}</td></tr>
<tr><td>Shift Relevance</td><td>{{ result.shift_rel }}</td></tr>
<tr><td>Access Relevance</td><td>{{ result.access_rel }}</td></tr>
<tr><td>Data Integrity Relevance</td><td>{{ result.di_rel }}</td></tr>
<tr><td>ServiceNow CI Readiness</td><td>{{ result.ci_ready }}</td></tr>
<tr><td>File Fingerprint</td><td class="hash">{{ result.file_hash }}</td></tr>
<tr><td>Register Record Hash</td><td class="hash">{{ result.record_hash }}</td></tr>
</table>

<h2>Preview</h2>
<table>
<tr>{% for c in result.preview_columns %}<th>{{ c }}</th>{% endfor %}</tr>
{% for row in result.preview %}
<tr>{% for c in result.preview_columns %}<td>{{ row.get(c, "") }}</td>{% endfor %}</tr>
{% endfor %}
</table>
{% else %}
<h2>Recent QC Ops Intakes</h2>
{% if metrics.recent %}
<table>
<tr><th>ID</th><th>Filename</th><th>Type</th><th>Detected Dataset</th><th>Recommended Module</th><th>Score</th><th>Risk</th></tr>
{% for r in metrics.recent %}
<tr>
<td>{{ r.intake_id }}</td>
<td>{{ r.filename }}</td>
<td>{{ r.file_type }}</td>
<td>{{ r.detected_dataset_type }}</td>
<td>{{ r.recommended_module }}</td>
<td>{{ r.governance_score }}%</td>
<td class="{% if r.risk_level == 'LOW' %}low{% elif r.risk_level == 'MEDIUM' %}medium{% else %}high{% endif %}">{{ r.risk_level }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No QC Ops intake records yet.</p>
{% endif %}
{% endif %}
</section>
</section>

<div class="card">
<h2>Monday Demo Message</h2>
<p><b>“We are not replacing operational spreadsheets. We are converting them into governed, fingerprinted operational datasets that can support shift continuity, access governance, CMMS/data-integrity reviews, and ServiceNow CI readiness.”</b></p>
</div>
</main>
</body>
</html>
    """

    return render_template_string(html, result=result, metrics=metrics)


# ============================================================
# TECHNICIANS GRAPH PAGE ACTIVE
# Reads approved shift technicians from Microsoft Entra ID group.
# ============================================================

def get_graph_access_token():
    import os
    import json
    import urllib.parse
    import urllib.request

    tenant_id = os.environ.get("AZURE_TENANT_ID", "").strip()
    client_id = os.environ.get("AZURE_CLIENT_ID", "").strip()
    client_secret = os.environ.get("AZURE_CLIENT_SECRET", "").strip()

    if not tenant_id or not client_id or not client_secret:
        raise RuntimeError("Missing AZURE_TENANT_ID, AZURE_CLIENT_ID, or AZURE_CLIENT_SECRET in Azure App Service settings.")

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    data = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials"
    }).encode("utf-8")

    req = urllib.request.Request(
        token_url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    with urllib.request.urlopen(req, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))

    token = payload.get("access_token")
    if not token:
        raise RuntimeError("Microsoft Graph token was not returned.")

    return token


def get_entra_shift_technicians():
    import os
    import json
    import urllib.parse
    import urllib.request

    group_id = os.environ.get("TECHNICIAN_GROUP_ID", "").strip()
    technician_domain = os.environ.get("TECHNICIAN_DOMAIN", "").strip() or "configured demo domain"

    if not group_id:
        raise RuntimeError("Missing TECHNICIAN_GROUP_ID in Azure App Service settings. Use the Object ID of the security group, not the group name.")

    token = get_graph_access_token()

    select_fields = "id,displayName,userPrincipalName,jobTitle,department,accountEnabled,mail"
    url = f"https://graph.microsoft.com/v1.0/groups/{group_id}/members/microsoft.graph.user?$select={urllib.parse.quote(select_fields)}"

    users = []

    while url:
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json"
            }
        )

        with urllib.request.urlopen(req, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))

        for user in payload.get("value", []):
            if user.get("accountEnabled") is True:
                users.append({
                    "id": user.get("id", ""),
                    "displayName": user.get("displayName", ""),
                    "userPrincipalName": user.get("userPrincipalName", ""),
                    "jobTitle": user.get("jobTitle", ""),
                    "department": user.get("department", ""),
                    "mail": user.get("mail", ""),
                    "domain": technician_domain
                })

        url = payload.get("@odata.nextLink")

    users = sorted(users, key=lambda x: x.get("displayName", ""))
    return users


@app.route("/technicians")
def technicians_page():
    # TECHNICIANS_GRAPH_PAGE_ACTIVE
    technicians = []
    error = ""

    try:
        technicians = get_entra_shift_technicians()
    except Exception as e:
        error = str(e)

    html = """
<!DOCTYPE html>
<html>
<head>
<title>AssuranceLayer™ Technician Directory</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#2563eb);color:white;padding:38px 44px 50px;border-bottom-left-radius:34px;border-bottom-right-radius:34px}
.container{max-width:1400px;margin:-24px auto 50px;padding:0 26px}
.nav,.card,.panel{background:white;border:1px solid #e5e7eb;border-radius:24px;padding:20px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:20px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:7px}
.nav a.active{background:#0f172a;color:white}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
select{width:100%;border-radius:13px;border:1px solid #dbe3ef;padding:12px;margin:8px 0;font-size:14px}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:13px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top}
.badge{display:inline-block;background:#eff6ff;color:#1d4ed8;padding:6px 9px;border-radius:999px;font-size:12px;font-weight:900}
.hash{font-family:Consolas,monospace;font-size:11px;color:#334155;word-break:break-all}
</style>
</head>
<body>
<section class="hero">
<h1>AssuranceLayer™ Technician Directory</h1>
<p>Microsoft Entra ID controlled technician eligibility for ShiftTrust™ assignment dropdown.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/command-center">Command Center</a>
<a href="/shift-assurance">Shift Assurance</a>
<a class="active" href="/technicians">Technicians</a>
<a href="/platform-health">Platform Health</a>
<a href="/qc-ops-intake">QC Ops Intake</a>
</nav>

{% if error %}
<div class="error">
<b>Microsoft Graph connection issue:</b><br>
{{ error }}
<br><br>
Check Azure App Service settings: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, TECHNICIAN_GROUP_ID.
</div>
{% else %}
<div class="notice">
<b>Connected to Microsoft Entra ID.</b>
{{ technicians|length }} active technician(s) found in the approved technician security group.
</div>
{% endif %}

<div class="card">
<h2>Shift Assignment Dropdown Preview</h2>
<p>This is the commercial pattern: technician names are not manually typed. They are controlled by Microsoft Entra ID group membership.</p>
<select>
<option value="">Select approved technician</option>
{% for t in technicians %}
<option value="{{ t.id }}">{{ t.displayName }} | {{ t.jobTitle }} | {{ t.userPrincipalName }}</option>
{% endfor %}
</select>
</div>

<div class="card">
<h2>Approved Shift Technicians</h2>
{% if technicians %}
<table>
<tr>
<th>Display Name</th>
<th>User Principal Name</th>
<th>Job Title</th>
<th>Department</th>
<th>Account</th>
<th>Graph Object ID</th>
</tr>
{% for t in technicians %}
<tr>
<td><b>{{ t.displayName }}</b></td>
<td>{{ t.userPrincipalName }}</td>
<td>{{ t.jobTitle }}</td>
<td>{{ t.department }}</td>
<td><span class="badge">Active</span></td>
<td class="hash">{{ t.id }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No active technicians returned yet.</p>
{% endif %}
</div>

<div class="card">
<h2>Governance Meaning</h2>
<p>
ServiceNow can provide tickets and CIs. Microsoft Entra ID provides controlled technician eligibility.
AssuranceLayer™ connects the ticket, CI, technician, shift, evidence, hash, and audit lineage into one governed operational record.
</p>
</div>
</main>
</body>
</html>
    """

    return render_template_string(html, technicians=technicians, error=error)


# ============================================================
# SHIFT ASSURANCE ENTRA TEST ACTIVE
# ShiftTrust page using Microsoft Entra technician dropdown.
# Does not replace /shift-assurance yet.
# ============================================================

SHIFT_ENTRA_FILE = "shift_entra_handoffs.csv"


def prepare_shift_entra_handoffs():
    df = load_csv(SHIFT_ENTRA_FILE)
    return ensure_cols(df, [
        "handoff_id", "timestamp", "ticket_number", "ci_reference",
        "equipment_name", "shift_name", "shift_status", "risk_level",
        "technician_id", "technician_name", "technician_upn", "technician_role",
        "evidence_status", "handoff_status", "open_issue_risk",
        "next_action", "readiness_status", "readiness_score",
        "governance_signals", "previous_hash", "record_hash"
    ])


def parse_selected_technician(value):
    value = clean(value)
    parts = value.split("||")
    while len(parts) < 4:
        parts.append("")
    return {
        "id": parts[0],
        "displayName": parts[1],
        "userPrincipalName": parts[2],
        "jobTitle": parts[3]
    }


def calculate_shift_entra_readiness(ticket_number, ci_reference, shift_status,
                                    risk_level, technician_name, evidence_status,
                                    handoff_status, open_issue_risk, next_action):
    score = 100
    signals = []

    ticket_number = clean(ticket_number)
    ci_reference = clean(ci_reference)
    shift_status = clean(shift_status)
    risk_level = clean(risk_level)
    technician_name = clean(technician_name)
    evidence_status = clean(evidence_status)
    handoff_status = clean(handoff_status)
    open_issue_risk = clean(open_issue_risk)
    next_action = clean(next_action)

    if not ticket_number:
        score -= 20
        signals.append("Ticket/work item reference is missing.")

    if not ci_reference:
        score -= 20
        signals.append("CI/equipment reference is missing.")

    if not technician_name:
        score -= 30
        signals.append("No approved Entra technician selected.")

    if shift_status in ["Blocked", "Incomplete"]:
        score -= 25
        signals.append("Shift status indicates blocked or incomplete work.")

    if risk_level == "HIGH":
        score -= 25
        signals.append("High-risk shift item requires leadership or QA visibility.")
    elif risk_level == "MEDIUM":
        score -= 10
        signals.append("Medium-risk shift item requires monitored follow-up.")

    if evidence_status in ["Missing", "Not Verified", "Rejected"]:
        score -= 30
        signals.append("Evidence is missing, not verified, or rejected.")

    if handoff_status in ["Not Started", "Incomplete"]:
        score -= 25
        signals.append("Shift handoff is not complete.")

    if open_issue_risk in ["Unresolved", "Escalation Required", "Potential Deviation"]:
        score -= 25
        signals.append("Open issue may require escalation or pre-deviation review.")

    if score < 85 and not next_action:
        score -= 10
        signals.append("Readiness issue exists but next action/carryover instruction is missing.")

    score = max(score, 0)

    if score >= 85:
        readiness = "SHIFT READY"
        final_risk = "LOW"
    elif score >= 60:
        readiness = "CONDITIONALLY READY"
        final_risk = "MEDIUM"
    else:
        readiness = "NOT READY"
        final_risk = "HIGH"

    if not signals:
        signals.append("No major shift governance risk detected.")

    return readiness, score, final_risk, signals


def save_shift_entra_handoff(req):
    df = prepare_shift_entra_handoffs()

    ticket_number = clean(req.form.get("ticket_number"))
    ci_reference = clean(req.form.get("ci_reference"))
    equipment_name = clean(req.form.get("equipment_name"))
    shift_name = clean(req.form.get("shift_name"))
    shift_status = clean(req.form.get("shift_status"))
    risk_level = clean(req.form.get("risk_level"))
    selected_technician = parse_selected_technician(req.form.get("selected_technician"))
    evidence_status = clean(req.form.get("evidence_status"))
    handoff_status = clean(req.form.get("handoff_status"))
    open_issue_risk = clean(req.form.get("open_issue_risk"))
    next_action = clean(req.form.get("next_action"))

    required = [
        ticket_number, ci_reference, equipment_name, shift_name,
        shift_status, risk_level, selected_technician["displayName"],
        evidence_status, handoff_status, open_issue_risk
    ]

    if not all(required):
        return {
            "error": "Ticket, CI/equipment, shift, risk, approved technician, evidence status, handoff status, and open issue risk are required."
        }

    readiness_status, readiness_score, calculated_risk, signals = calculate_shift_entra_readiness(
        ticket_number, ci_reference, shift_status, risk_level,
        selected_technician["displayName"], evidence_status,
        handoff_status, open_issue_risk, next_action
    )

    timestamp = datetime.datetime.utcnow().isoformat()
    handoff_id = "SENTRA-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    previous_hash = "GENESIS"
    if not df.empty:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    record_hash = sha256_text(
        handoff_id + timestamp + ticket_number + ci_reference + equipment_name +
        shift_name + selected_technician["id"] + selected_technician["displayName"] +
        evidence_status + handoff_status + readiness_status + previous_hash
    )

    row = pd.DataFrame([{
        "handoff_id": handoff_id,
        "timestamp": timestamp,
        "ticket_number": ticket_number,
        "ci_reference": ci_reference,
        "equipment_name": equipment_name,
        "shift_name": shift_name,
        "shift_status": shift_status,
        "risk_level": calculated_risk,
        "technician_id": selected_technician["id"],
        "technician_name": selected_technician["displayName"],
        "technician_upn": selected_technician["userPrincipalName"],
        "technician_role": selected_technician["jobTitle"],
        "evidence_status": evidence_status,
        "handoff_status": handoff_status,
        "open_issue_risk": open_issue_risk,
        "next_action": next_action,
        "readiness_status": readiness_status,
        "readiness_score": readiness_score,
        "governance_signals": " | ".join(signals),
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, SHIFT_ENTRA_FILE)

    return {
        "error": "",
        "handoff_id": handoff_id,
        "readiness_status": readiness_status,
        "readiness_score": readiness_score,
        "risk_level": calculated_risk,
        "signals": signals,
        "record_hash": record_hash
    }


def get_shift_entra_metrics():
    df = prepare_shift_entra_handoffs()
    if df.empty:
        return {"total": 0, "ready": 0, "conditional": 0, "not_ready": 0, "high": 0, "recent": []}

    df = df.fillna("")
    return {
        "total": len(df),
        "ready": len(df[df["readiness_status"] == "SHIFT READY"]),
        "conditional": len(df[df["readiness_status"] == "CONDITIONALLY READY"]),
        "not_ready": len(df[df["readiness_status"] == "NOT READY"]),
        "high": len(df[df["risk_level"] == "HIGH"]),
        "recent": df.tail(12).to_dict("records")
    }


@app.route("/shift-assurance-entra-test", methods=["GET", "POST"])
def shift_assurance_entra_test():
    # SHIFT_ASSURANCE_ENTRA_TEST_ACTIVE
    result = None
    technician_error = ""
    technicians = []

    try:
        technicians = get_entra_shift_technicians()
    except Exception as e:
        technician_error = str(e)

    if request.method == "POST":
        result = save_shift_entra_handoff(request)

    metrics = get_shift_entra_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>AssuranceLayer™ ShiftTrust Entra Test</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#2563eb);color:white;padding:38px 44px 50px;border-bottom-left-radius:34px;border-bottom-right-radius:34px}
.container{max-width:1500px;margin:-24px auto 50px;padding:0 26px}
.nav,.card,.panel{background:white;border:1px solid #e5e7eb;border-radius:24px;padding:20px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:20px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:7px}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.layout{display:grid;grid-template-columns:430px 1fr;gap:20px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
input,select,textarea,button{width:100%;border-radius:13px;border:1px solid #dbe3ef;padding:11px;margin:6px 0;font-size:14px}
textarea{min-height:90px}
button{border:none;background:linear-gradient(135deg,#2563eb,#0f766e);color:white;font-weight:900;cursor:pointer}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
.warning{background:#fff7ed;border-left:7px solid #f59e0b;border-radius:16px;padding:14px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top;word-break:break-word}
.low{color:#16a34a;font-weight:900}.medium{color:#d97706;font-weight:900}.high{color:#dc2626;font-weight:900}
.hash{font-family:Consolas,monospace;font-size:11px;word-break:break-all;color:#334155}
@media(max-width:1000px){.grid,.layout{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>AssuranceLayer™ ShiftTrust™ — Entra-Controlled Assignment</h1>
<p>ServiceNow-style ticket + CI reference + Microsoft Entra technician dropdown + evidence readiness + handoff lineage.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/command-center">Command Center</a>
<a href="/shift-assurance">Shift Current</a>
<a class="active" href="/shift-assurance-entra-test">Shift Entra Test</a>
<a href="/technicians">Technicians</a>
<a href="/qc-ops-intake">QC Ops Intake</a>
<a href="/platform-health">Platform Health</a>
</nav>

{% if technician_error %}
<div class="error">
<b>Technician directory connection issue:</b><br>
{{ technician_error }}
</div>
{% else %}
<div class="notice">
<b>Microsoft Entra connected.</b>
{{ technicians|length }} approved active technician(s) available for assignment.
</div>
{% endif %}

{% if result and result.error %}
<div class="error">{{ result.error }}</div>
{% elif result %}
<div class="notice">
<b>Saved:</b> {{ result.handoff_id }} —
<b>{{ result.readiness_status }}</b> —
Score <b>{{ result.readiness_score }}%</b> —
Risk <b>{{ result.risk_level }}</b>
<ul>{% for s in result.signals %}<li>{{ s }}</li>{% endfor %}</ul>
<div class="hash"><b>Record Hash:</b> {{ result.record_hash }}</div>
</div>
{% endif %}

<section class="grid">
<div class="metric"><div class="metric-label">Total Handoffs</div><div class="metric-value">{{ metrics.total }}</div></div>
<div class="metric"><div class="metric-label">Ready</div><div class="metric-value" style="color:#16a34a">{{ metrics.ready }}</div></div>
<div class="metric"><div class="metric-label">Conditional</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional }}</div></div>
<div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ metrics.high }}</div></div>
</section>

<section class="layout">
<aside class="panel">
<h2>Create Entra-Controlled Shift Handoff</h2>
<form method="POST" action="/shift-assurance-entra-test">
<input name="ticket_number" placeholder="Ticket / Work Item e.g. INC-DEMO-0001 or WO-DEMO-0001" required>
<input name="ci_reference" placeholder="CI Reference e.g. CI-DEMO-1803" required>
<input name="equipment_name" placeholder="Equipment / System Name e.g. Demo Isolator Integrity Tester" required>

<select name="shift_name" required>
<option value="">Select Shift</option>
<option value="Morning Shift">Morning Shift</option>
<option value="Night Shift">Night Shift</option>
<option value="Weekend Coverage">Weekend Coverage</option>
<option value="Critical Handoff Queue">Critical Handoff Queue</option>
</select>

<select name="selected_technician" required>
<option value="">Select approved Entra technician</option>
{% for t in technicians %}
<option value="{{ t.id }}||{{ t.displayName }}||{{ t.userPrincipalName }}||{{ t.jobTitle }}">{{ t.displayName }} | {{ t.jobTitle }} | {{ t.userPrincipalName }}</option>
{% endfor %}
</select>

<select name="shift_status" required>
<option value="">Shift Status</option>
<option value="Complete">Complete</option>
<option value="In Progress">In Progress</option>
<option value="Incomplete">Incomplete</option>
<option value="Blocked">Blocked</option>
</select>

<select name="risk_level" required>
<option value="">Initial Risk Level</option>
<option value="LOW">LOW</option>
<option value="MEDIUM">MEDIUM</option>
<option value="HIGH">HIGH</option>
</select>

<select name="evidence_status" required>
<option value="">Evidence Status</option>
<option value="Verified">Verified</option>
<option value="Pending Review">Pending Review</option>
<option value="Missing">Missing</option>
<option value="Not Verified">Not Verified</option>
<option value="Rejected">Rejected</option>
</select>

<select name="handoff_status" required>
<option value="">Handoff Status</option>
<option value="Complete">Complete</option>
<option value="In Progress">In Progress</option>
<option value="Incomplete">Incomplete</option>
<option value="Not Started">Not Started</option>
</select>

<select name="open_issue_risk" required>
<option value="">Open Issue / Risk</option>
<option value="No Open Issue">No Open Issue</option>
<option value="Unresolved">Unresolved</option>
<option value="Escalation Required">Escalation Required</option>
<option value="Potential Deviation">Potential Deviation</option>
</select>

<textarea name="next_action" placeholder="Next action / carryover instruction"></textarea>

<button type="submit">Save Shift Handoff</button>
</form>
</aside>

<section class="card">
<h2>Recent Entra-Controlled Shift Handoffs</h2>
{% if metrics.recent %}
<table>
<tr>
<th>ID</th><th>Ticket</th><th>CI / Equipment</th><th>Shift</th><th>Technician</th><th>Evidence</th><th>Readiness</th><th>Risk</th>
</tr>
{% for r in metrics.recent %}
<tr>
<td>{{ r.handoff_id }}</td>
<td><b>{{ r.ticket_number }}</b></td>
<td><b>{{ r.ci_reference }}</b><br>{{ r.equipment_name }}</td>
<td>{{ r.shift_name }}</td>
<td><b>{{ r.technician_name }}</b><br>{{ r.technician_role }}<br>{{ r.technician_upn }}</td>
<td>{{ r.evidence_status }}</td>
<td><b>{{ r.readiness_status }}</b><br>{{ r.readiness_score }}%</td>
<td class="{% if r.risk_level == 'LOW' %}low{% elif r.risk_level == 'MEDIUM' %}medium{% else %}high{% endif %}">{{ r.risk_level }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No Entra-controlled shift handoffs saved yet.</p>
{% endif %}
</section>
</section>

<div class="card">
<h2>Commercial Meaning</h2>
<p>
Technician names are not typed manually. Microsoft Entra ID controls who is eligible for shift assignment.
AssuranceLayer™ then links technician, ticket, CI, shift, evidence status, handoff status, readiness score, and record hash into one governed operational lineage.
</p>
</div>
</main>
</body>
</html>
    """

    return render_template_string(
        html,
        technicians=technicians,
        technician_error=technician_error,
        result=result,
        metrics=metrics
    )


# ============================================================
# SHIFT ENTERPRISE ALIAS ACTIVE
# Clean enterprise demo route for ShiftTrust with Entra dropdown.
# Protected /shift-assurance remains unchanged.
# ============================================================

@app.route("/shift-assurance-enterprise")
def shift_assurance_enterprise_page():
    # SHIFT_ENTERPRISE_ALIAS_ACTIVE
    return redirect("/shift-assurance-entra-test")


# ============================================================
# SERVICENOW CI READINESS ACTIVE
# Demo-safe ServiceNow-style CI/ticket governance readiness layer.
# ============================================================

SERVICENOW_CI_FILE = "servicenow_ci_readiness.csv"


def prepare_servicenow_ci_readiness():
    df = load_csv(SERVICENOW_CI_FILE)
    return ensure_cols(df, [
        "ci_readiness_id", "timestamp", "ticket_number", "ticket_type",
        "ci_reference", "ci_name", "ci_class", "assignment_group",
        "service_owner", "system_owner", "operational_status",
        "regulatory_status", "cmdb_mapping_status", "sop_linkage_status",
        "evidence_status", "shift_handoff_status", "technician_assignment_status",
        "impact_assessment_status", "data_integrity_status", "deviation_risk",
        "servicenow_api_mode", "readiness_status", "readiness_score",
        "risk_level", "governance_signals", "previous_hash", "record_hash"
    ])


def calculate_servicenow_ci_readiness(cmdb_mapping_status, sop_linkage_status,
                                      evidence_status, shift_handoff_status,
                                      technician_assignment_status,
                                      impact_assessment_status, data_integrity_status,
                                      deviation_risk, regulatory_status,
                                      operational_status):
    score = 100
    signals = []

    cmdb_mapping_status = clean(cmdb_mapping_status)
    sop_linkage_status = clean(sop_linkage_status)
    evidence_status = clean(evidence_status)
    shift_handoff_status = clean(shift_handoff_status)
    technician_assignment_status = clean(technician_assignment_status)
    impact_assessment_status = clean(impact_assessment_status)
    data_integrity_status = clean(data_integrity_status)
    deviation_risk = clean(deviation_risk)
    regulatory_status = clean(regulatory_status)
    operational_status = clean(operational_status)

    if cmdb_mapping_status in ["Missing", "Incomplete", "Mismatch"]:
        score -= 25
        signals.append("CMDB/CI mapping is missing, incomplete, or mismatched.")

    if sop_linkage_status in ["Missing", "Not Linked", "Outdated"]:
        score -= 20
        signals.append("SOP linkage is missing, not linked, or outdated.")

    if evidence_status in ["Missing", "Not Verified", "Rejected"]:
        score -= 30
        signals.append("Supporting evidence is missing, not verified, or rejected.")

    if shift_handoff_status in ["Missing", "Incomplete", "Not Required But Recommended"]:
        score -= 15
        signals.append("Shift handoff linkage is missing or incomplete.")

    if technician_assignment_status in ["Missing", "Manual Entry", "Not Entra-Controlled"]:
        score -= 20
        signals.append("Technician assignment is not controlled through approved identity source.")

    if impact_assessment_status in ["Missing", "Incomplete", "Not Reviewed"]:
        score -= 20
        signals.append("Impact assessment is missing, incomplete, or not reviewed.")

    if data_integrity_status in ["Missing", "At Risk", "Not Reviewed"]:
        score -= 25
        signals.append("Data integrity status is missing, at risk, or not reviewed.")

    if regulatory_status in ["GxP Impact Unknown", "Quality Impact Unknown", "Not Classified"]:
        score -= 15
        signals.append("Regulatory/quality impact classification is not clear.")

    if operational_status in ["Out of Service", "Removed By Vendor", "Unavailable", "Blocked"]:
        score -= 25
        signals.append("CI/equipment operational status indicates availability or continuity risk.")

    if deviation_risk in ["Potential Deviation", "Escalation Required", "Deviation Opened"]:
        score -= 30
        signals.append("Pre-deviation/deviation signal exists for this CI/ticket.")

    score = max(score, 0)

    if score >= 85:
        readiness = "SERVICENOW CI READY"
        risk = "LOW"
    elif score >= 60:
        readiness = "CONDITIONALLY READY"
        risk = "MEDIUM"
    else:
        readiness = "NOT READY"
        risk = "HIGH"

    if not signals:
        signals.append("No major CI governance readiness risk detected.")

    return readiness, score, risk, signals


def save_servicenow_ci_readiness(req):
    df = prepare_servicenow_ci_readiness()

    ticket_number = clean(req.form.get("ticket_number"))
    ticket_type = clean(req.form.get("ticket_type"))
    ci_reference = clean(req.form.get("ci_reference"))
    ci_name = clean(req.form.get("ci_name"))
    ci_class = clean(req.form.get("ci_class"))
    assignment_group = clean(req.form.get("assignment_group"))
    service_owner = clean(req.form.get("service_owner"))
    system_owner = clean(req.form.get("system_owner"))
    operational_status = clean(req.form.get("operational_status"))
    regulatory_status = clean(req.form.get("regulatory_status"))
    cmdb_mapping_status = clean(req.form.get("cmdb_mapping_status"))
    sop_linkage_status = clean(req.form.get("sop_linkage_status"))
    evidence_status = clean(req.form.get("evidence_status"))
    shift_handoff_status = clean(req.form.get("shift_handoff_status"))
    technician_assignment_status = clean(req.form.get("technician_assignment_status"))
    impact_assessment_status = clean(req.form.get("impact_assessment_status"))
    data_integrity_status = clean(req.form.get("data_integrity_status"))
    deviation_risk = clean(req.form.get("deviation_risk"))
    servicenow_api_mode = clean(req.form.get("servicenow_api_mode")) or "Demo ServiceNow-style record"

    required = [
        ticket_number, ticket_type, ci_reference, ci_name, ci_class,
        assignment_group, operational_status, regulatory_status,
        cmdb_mapping_status, sop_linkage_status, evidence_status,
        shift_handoff_status, technician_assignment_status,
        impact_assessment_status, data_integrity_status, deviation_risk
    ]

    if not all(required):
        return {"error": "Ticket, CI, assignment group, status, regulatory classification, mapping, SOP, evidence, handoff, technician, impact, data integrity, and deviation risk fields are required."}

    readiness_status, readiness_score, risk_level, signals = calculate_servicenow_ci_readiness(
        cmdb_mapping_status, sop_linkage_status, evidence_status,
        shift_handoff_status, technician_assignment_status,
        impact_assessment_status, data_integrity_status, deviation_risk,
        regulatory_status, operational_status
    )

    timestamp = datetime.datetime.utcnow().isoformat()
    ci_readiness_id = "SNCI-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    previous_hash = "GENESIS"
    if not df.empty:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    record_hash = sha256_text(
        ci_readiness_id + timestamp + ticket_number + ticket_type +
        ci_reference + ci_name + ci_class + operational_status +
        regulatory_status + cmdb_mapping_status + evidence_status +
        readiness_status + previous_hash
    )

    row = pd.DataFrame([{
        "ci_readiness_id": ci_readiness_id,
        "timestamp": timestamp,
        "ticket_number": ticket_number,
        "ticket_type": ticket_type,
        "ci_reference": ci_reference,
        "ci_name": ci_name,
        "ci_class": ci_class,
        "assignment_group": assignment_group,
        "service_owner": service_owner,
        "system_owner": system_owner,
        "operational_status": operational_status,
        "regulatory_status": regulatory_status,
        "cmdb_mapping_status": cmdb_mapping_status,
        "sop_linkage_status": sop_linkage_status,
        "evidence_status": evidence_status,
        "shift_handoff_status": shift_handoff_status,
        "technician_assignment_status": technician_assignment_status,
        "impact_assessment_status": impact_assessment_status,
        "data_integrity_status": data_integrity_status,
        "deviation_risk": deviation_risk,
        "servicenow_api_mode": servicenow_api_mode,
        "readiness_status": readiness_status,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "governance_signals": " | ".join(signals),
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, SERVICENOW_CI_FILE)

    return {
        "error": "",
        "ci_readiness_id": ci_readiness_id,
        "readiness_status": readiness_status,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "signals": signals,
        "record_hash": record_hash
    }


def get_servicenow_ci_metrics():
    df = prepare_servicenow_ci_readiness()
    if df.empty:
        return {"total": 0, "ready": 0, "conditional": 0, "not_ready": 0, "high": 0, "recent": []}

    df = df.fillna("")
    return {
        "total": len(df),
        "ready": len(df[df["readiness_status"] == "SERVICENOW CI READY"]),
        "conditional": len(df[df["readiness_status"] == "CONDITIONALLY READY"]),
        "not_ready": len(df[df["readiness_status"] == "NOT READY"]),
        "high": len(df[df["risk_level"] == "HIGH"]),
        "recent": df.tail(12).to_dict("records")
    }


@app.route("/servicenow-ci-readiness", methods=["GET", "POST"])
def servicenow_ci_readiness_page():
    # SERVICENOW_CI_READINESS_ACTIVE
    result = None

    if request.method == "POST":
        result = save_servicenow_ci_readiness(request)

    metrics = get_servicenow_ci_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>AssuranceLayer™ ServiceNow CI Readiness</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#334155);color:white;padding:38px 44px 50px;border-bottom-left-radius:34px;border-bottom-right-radius:34px}
.container{max-width:1500px;margin:-24px auto 50px;padding:0 26px}
.nav,.card,.panel{background:white;border:1px solid #e5e7eb;border-radius:24px;padding:20px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:20px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:7px}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.layout{display:grid;grid-template-columns:430px 1fr;gap:20px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
input,select,textarea,button{width:100%;border-radius:13px;border:1px solid #dbe3ef;padding:11px;margin:6px 0;font-size:14px}
textarea{min-height:90px}
button{border:none;background:linear-gradient(135deg,#334155,#2563eb);color:white;font-weight:900;cursor:pointer}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
.warning{background:#fff7ed;border-left:7px solid #f59e0b;border-radius:16px;padding:14px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top;word-break:break-word}
.low{color:#16a34a;font-weight:900}.medium{color:#d97706;font-weight:900}.high{color:#dc2626;font-weight:900}
.hash{font-family:Consolas,monospace;font-size:11px;word-break:break-all;color:#334155}
@media(max-width:1000px){.grid,.layout{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>AssuranceLayer™ ServiceNow CI Readiness</h1>
<p>Ticket → CI → owner → SOP → evidence → shift handoff → data integrity → pre-deviation readiness.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/command-center">Command Center</a>
<a href="/shift-assurance-enterprise">Shift Enterprise</a>
<a href="/technicians">Technicians</a>
<a href="/qc-ops-intake">QC Ops Intake</a>
<a class="active" href="/servicenow-ci-readiness">ServiceNow CI</a>
<a href="/platform-health">Platform Health</a>
</nav>

<div class="warning">
<b>Demo-safe mode:</b> this page uses ServiceNow-style records now. Later, the same model can be connected to a ServiceNow PDI or enterprise ServiceNow API.
</div>

{% if result and result.error %}
<div class="error">{{ result.error }}</div>
{% elif result %}
<div class="notice">
<b>Saved:</b> {{ result.ci_readiness_id }} —
<b>{{ result.readiness_status }}</b> —
Score <b>{{ result.readiness_score }}%</b> —
Risk <b>{{ result.risk_level }}</b>
<ul>{% for s in result.signals %}<li>{{ s }}</li>{% endfor %}</ul>
<div class="hash"><b>Record Hash:</b> {{ result.record_hash }}</div>
</div>
{% endif %}

<section class="grid">
<div class="metric"><div class="metric-label">Total CI Records</div><div class="metric-value">{{ metrics.total }}</div></div>
<div class="metric"><div class="metric-label">CI Ready</div><div class="metric-value" style="color:#16a34a">{{ metrics.ready }}</div></div>
<div class="metric"><div class="metric-label">Conditional</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional }}</div></div>
<div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ metrics.high }}</div></div>
</section>

<section class="layout">
<aside class="panel">
<h2>Create ServiceNow-Style CI Readiness Record</h2>
<form method="POST" action="/servicenow-ci-readiness">
<input name="ticket_number" placeholder="Ticket e.g. INC-DEMO-0001 / WO-DEMO-0001" required>

<select name="ticket_type" required>
<option value="">Ticket Type</option>
<option value="Incident">Incident</option>
<option value="Work Order">Work Order</option>
<option value="Change Request">Change Request</option>
<option value="Task">Task</option>
</select>

<input name="ci_reference" placeholder="CI Reference e.g. CI-DEMO-1803" required>
<input name="ci_name" placeholder="CI Name e.g. Demo Isolator Integrity Tester" required>

<select name="ci_class" required>
<option value="">CI Class</option>
<option value="Controlled Equipment">Controlled Equipment</option>
<option value="Computerized System">Computerized System</option>
<option value="Validated Workstation">Validated Workstation</option>
<option value="Application Service">Application Service</option>
<option value="Lab Instrument">Lab Instrument</option>
</select>

<input name="assignment_group" placeholder="Assignment Group e.g. Demo GMP IT Support" required>
<input name="service_owner" placeholder="Service Owner / Business Owner">
<input name="system_owner" placeholder="System Owner / Process Owner">

<select name="operational_status" required>
<option value="">Operational Status</option>
<option value="In Service">In Service</option>
<option value="Out of Service">Out of Service</option>
<option value="Removed By Vendor">Removed By Vendor</option>
<option value="Unavailable">Unavailable</option>
<option value="Blocked">Blocked</option>
</select>

<select name="regulatory_status" required>
<option value="">Regulatory / Quality Status</option>
<option value="GxP Classified">GxP Classified</option>
<option value="Non-GxP">Non-GxP</option>
<option value="GxP Impact Unknown">GxP Impact Unknown</option>
<option value="Quality Impact Unknown">Quality Impact Unknown</option>
<option value="Not Classified">Not Classified</option>
</select>

<select name="cmdb_mapping_status" required>
<option value="">CMDB Mapping Status</option>
<option value="Complete">Complete</option>
<option value="Incomplete">Incomplete</option>
<option value="Missing">Missing</option>
<option value="Mismatch">Mismatch</option>
</select>

<select name="sop_linkage_status" required>
<option value="">SOP Linkage Status</option>
<option value="Linked Current">Linked Current</option>
<option value="Outdated">Outdated</option>
<option value="Not Linked">Not Linked</option>
<option value="Missing">Missing</option>
</select>

<select name="evidence_status" required>
<option value="">Evidence Status</option>
<option value="Verified">Verified</option>
<option value="Pending Review">Pending Review</option>
<option value="Missing">Missing</option>
<option value="Not Verified">Not Verified</option>
<option value="Rejected">Rejected</option>
</select>

<select name="shift_handoff_status" required>
<option value="">Shift Handoff Status</option>
<option value="Linked Complete">Linked Complete</option>
<option value="Incomplete">Incomplete</option>
<option value="Missing">Missing</option>
<option value="Not Required But Recommended">Not Required But Recommended</option>
</select>

<select name="technician_assignment_status" required>
<option value="">Technician Assignment Status</option>
<option value="Entra-Controlled">Entra-Controlled</option>
<option value="Manual Entry">Manual Entry</option>
<option value="Not Entra-Controlled">Not Entra-Controlled</option>
<option value="Missing">Missing</option>
</select>

<select name="impact_assessment_status" required>
<option value="">Impact Assessment Status</option>
<option value="Reviewed">Reviewed</option>
<option value="Not Reviewed">Not Reviewed</option>
<option value="Incomplete">Incomplete</option>
<option value="Missing">Missing</option>
</select>

<select name="data_integrity_status" required>
<option value="">Data Integrity Status</option>
<option value="Reviewed">Reviewed</option>
<option value="At Risk">At Risk</option>
<option value="Not Reviewed">Not Reviewed</option>
<option value="Missing">Missing</option>
</select>

<select name="deviation_risk" required>
<option value="">Deviation Risk</option>
<option value="No Deviation Signal">No Deviation Signal</option>
<option value="Potential Deviation">Potential Deviation</option>
<option value="Escalation Required">Escalation Required</option>
<option value="Deviation Opened">Deviation Opened</option>
</select>

<input name="servicenow_api_mode" value="Demo ServiceNow-style record">

<button type="submit">Save CI Readiness Record</button>
</form>
</aside>

<section class="card">
<h2>Recent ServiceNow-Style CI Readiness Records</h2>
{% if metrics.recent %}
<table>
<tr>
<th>ID</th><th>Ticket</th><th>CI</th><th>Operational</th><th>Regulatory</th><th>Evidence</th><th>Shift</th><th>Readiness</th><th>Risk</th>
</tr>
{% for r in metrics.recent %}
<tr>
<td>{{ r.ci_readiness_id }}</td>
<td><b>{{ r.ticket_number }}</b><br>{{ r.ticket_type }}</td>
<td><b>{{ r.ci_reference }}</b><br>{{ r.ci_name }}</td>
<td>{{ r.operational_status }}</td>
<td>{{ r.regulatory_status }}</td>
<td>{{ r.evidence_status }}</td>
<td>{{ r.shift_handoff_status }}</td>
<td><b>{{ r.readiness_status }}</b><br>{{ r.readiness_score }}%</td>
<td class="{% if r.risk_level == 'LOW' %}low{% elif r.risk_level == 'MEDIUM' %}medium{% else %}high{% endif %}">{{ r.risk_level }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No ServiceNow CI readiness records saved yet.</p>
{% endif %}
</section>
</section>

<div class="card">
<h2>Monday Demo Message</h2>
<p>
<b>ServiceNow can manage the ticket and CI. AssuranceLayer™ verifies whether the CI context, SOP linkage, technician assignment, shift handoff, evidence, data-integrity status, and deviation risk are governance-ready.</b>
</p>
</div>
</main>
</body>
</html>
    """

    return render_template_string(html, result=result, metrics=metrics)


# ============================================================
# SHIFT HANDOFF LINEAGE ACTIVE
# Two-person Entra-controlled outgoing/incoming shift handoff.
# ============================================================

SHIFT_HANDOFF_LINEAGE_FILE = "shift_handoff_lineage.csv"


def prepare_shift_handoff_lineage():
    df = load_csv(SHIFT_HANDOFF_LINEAGE_FILE)
    return ensure_cols(df, [
        "lineage_id", "timestamp", "ticket_number", "ci_reference", "equipment_name",
        "outgoing_shift", "incoming_shift", "handoff_reason",
        "outgoing_technician_id", "outgoing_technician_name", "outgoing_technician_upn", "outgoing_technician_role",
        "incoming_technician_id", "incoming_technician_name", "incoming_technician_upn", "incoming_technician_role",
        "handoff_summary", "evidence_status", "open_issue_risk", "acceptance_status",
        "readiness_status", "readiness_score", "risk_level", "governance_signals",
        "previous_hash", "record_hash"
    ])


def parse_lineage_technician(value):
    value = clean(value)
    parts = value.split("||")
    while len(parts) < 4:
        parts.append("")
    return {
        "id": parts[0],
        "displayName": parts[1],
        "userPrincipalName": parts[2],
        "jobTitle": parts[3]
    }


def calculate_handoff_lineage_readiness(ticket_number, ci_reference, outgoing_tech, incoming_tech,
                                        evidence_status, open_issue_risk, acceptance_status,
                                        handoff_summary):
    score = 100
    signals = []

    if not clean(ticket_number):
        score -= 20
        signals.append("Ticket/work item reference is missing.")

    if not clean(ci_reference):
        score -= 20
        signals.append("CI/equipment reference is missing.")

    if not outgoing_tech.get("displayName"):
        score -= 25
        signals.append("Outgoing technician is missing.")

    if not incoming_tech.get("displayName"):
        score -= 25
        signals.append("Incoming technician is missing.")

    if outgoing_tech.get("id") and incoming_tech.get("id") and outgoing_tech.get("id") == incoming_tech.get("id"):
        score -= 25
        signals.append("Outgoing and incoming technician cannot be the same person for a formal handoff.")

    if evidence_status in ["Missing", "Not Verified", "Rejected"]:
        score -= 30
        signals.append("Handoff evidence is missing, not verified, or rejected.")
    elif evidence_status == "Pending Review":
        score -= 15
        signals.append("Handoff evidence is pending review.")

    if open_issue_risk in ["Unresolved", "Escalation Required", "Potential Deviation"]:
        score -= 25
        signals.append("Open issue may require escalation or pre-deviation review.")

    if acceptance_status in ["Not Accepted", "Pending Acceptance"]:
        score -= 25
        signals.append("Incoming technician has not formally accepted the handoff.")

    if not clean(handoff_summary):
        score -= 15
        signals.append("Handoff summary/carryover instruction is missing.")

    score = max(score, 0)

    if score >= 85:
        readiness = "HANDOFF ACCEPTED / READY"
        risk = "LOW"
    elif score >= 60:
        readiness = "CONDITIONALLY ACCEPTED"
        risk = "MEDIUM"
    else:
        readiness = "HANDOFF NOT READY"
        risk = "HIGH"

    if not signals:
        signals.append("Formal two-person handoff lineage appears complete.")

    return readiness, score, risk, signals


def save_shift_handoff_lineage(req):
    df = prepare_shift_handoff_lineage()

    ticket_number = clean(req.form.get("ticket_number"))
    ci_reference = clean(req.form.get("ci_reference"))
    equipment_name = clean(req.form.get("equipment_name"))
    outgoing_shift = clean(req.form.get("outgoing_shift"))
    incoming_shift = clean(req.form.get("incoming_shift"))
    handoff_reason = clean(req.form.get("handoff_reason"))

    outgoing_tech = parse_lineage_technician(req.form.get("outgoing_technician"))
    incoming_tech = parse_lineage_technician(req.form.get("incoming_technician"))

    handoff_summary = clean(req.form.get("handoff_summary"))
    evidence_status = clean(req.form.get("evidence_status"))
    open_issue_risk = clean(req.form.get("open_issue_risk"))
    acceptance_status = clean(req.form.get("acceptance_status"))

    required = [
        ticket_number, ci_reference, equipment_name, outgoing_shift, incoming_shift,
        handoff_reason, outgoing_tech["displayName"], incoming_tech["displayName"],
        evidence_status, open_issue_risk, acceptance_status
    ]

    if not all(required):
        return {"error": "Ticket, CI, equipment, shifts, reason, outgoing technician, incoming technician, evidence, risk, and acceptance status are required."}

    readiness_status, readiness_score, risk_level, signals = calculate_handoff_lineage_readiness(
        ticket_number, ci_reference, outgoing_tech, incoming_tech,
        evidence_status, open_issue_risk, acceptance_status, handoff_summary
    )

    timestamp = datetime.datetime.utcnow().isoformat()
    lineage_id = "HLIN-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    previous_hash = "GENESIS"
    if not df.empty:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    record_hash = sha256_text(
        lineage_id + timestamp + ticket_number + ci_reference + equipment_name +
        outgoing_tech["id"] + incoming_tech["id"] + outgoing_shift + incoming_shift +
        evidence_status + open_issue_risk + acceptance_status + readiness_status + previous_hash
    )

    row = pd.DataFrame([{
        "lineage_id": lineage_id,
        "timestamp": timestamp,
        "ticket_number": ticket_number,
        "ci_reference": ci_reference,
        "equipment_name": equipment_name,
        "outgoing_shift": outgoing_shift,
        "incoming_shift": incoming_shift,
        "handoff_reason": handoff_reason,
        "outgoing_technician_id": outgoing_tech["id"],
        "outgoing_technician_name": outgoing_tech["displayName"],
        "outgoing_technician_upn": outgoing_tech["userPrincipalName"],
        "outgoing_technician_role": outgoing_tech["jobTitle"],
        "incoming_technician_id": incoming_tech["id"],
        "incoming_technician_name": incoming_tech["displayName"],
        "incoming_technician_upn": incoming_tech["userPrincipalName"],
        "incoming_technician_role": incoming_tech["jobTitle"],
        "handoff_summary": handoff_summary,
        "evidence_status": evidence_status,
        "open_issue_risk": open_issue_risk,
        "acceptance_status": acceptance_status,
        "readiness_status": readiness_status,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "governance_signals": " | ".join(signals),
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, SHIFT_HANDOFF_LINEAGE_FILE)

    return {
        "error": "",
        "lineage_id": lineage_id,
        "readiness_status": readiness_status,
        "readiness_score": readiness_score,
        "risk_level": risk_level,
        "signals": signals,
        "record_hash": record_hash
    }


def get_shift_handoff_lineage_metrics():
    df = prepare_shift_handoff_lineage()
    if df.empty:
        return {"total": 0, "ready": 0, "conditional": 0, "not_ready": 0, "high": 0, "recent": []}

    df = df.fillna("")
    return {
        "total": len(df),
        "ready": len(df[df["readiness_status"] == "HANDOFF ACCEPTED / READY"]),
        "conditional": len(df[df["readiness_status"] == "CONDITIONALLY ACCEPTED"]),
        "not_ready": len(df[df["readiness_status"] == "HANDOFF NOT READY"]),
        "high": len(df[df["risk_level"] == "HIGH"]),
        "recent": df.tail(12).to_dict("records")
    }


@app.route("/shift-handoff-lineage", methods=["GET", "POST"])
def shift_handoff_lineage_page():
    # SHIFT_HANDOFF_LINEAGE_ACTIVE
    result = None
    technician_error = ""
    technicians = []

    try:
        technicians = get_entra_shift_technicians()
    except Exception as e:
        technician_error = str(e)

    if request.method == "POST":
        result = save_shift_handoff_lineage(request)

    metrics = get_shift_handoff_lineage_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>AssuranceLayer™ Shift Handoff Lineage</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#0f766e);color:white;padding:38px 44px 50px;border-bottom-left-radius:34px;border-bottom-right-radius:34px}
.container{max-width:1500px;margin:-24px auto 50px;padding:0 26px}
.nav,.card,.panel{background:white;border:1px solid #e5e7eb;border-radius:24px;padding:20px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:20px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:7px}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.layout{display:grid;grid-template-columns:450px 1fr;gap:20px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
input,select,textarea,button{width:100%;border-radius:13px;border:1px solid #dbe3ef;padding:11px;margin:6px 0;font-size:14px}
textarea{min-height:100px}
button{border:none;background:linear-gradient(135deg,#0f766e,#2563eb);color:white;font-weight:900;cursor:pointer}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
.warning{background:#fff7ed;border-left:7px solid #f59e0b;border-radius:16px;padding:14px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top;word-break:break-word}
.low{color:#16a34a;font-weight:900}.medium{color:#d97706;font-weight:900}.high{color:#dc2626;font-weight:900}
.hash{font-family:Consolas,monospace;font-size:11px;word-break:break-all;color:#334155}
@media(max-width:1000px){.grid,.layout{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>AssuranceLayer™ Shift Handoff Lineage</h1>
<p>Formal outgoing-to-incoming technician handoff with Entra-controlled identity, CI context, evidence status, acceptance, and hash lineage.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/command-center">Command Center</a>
<a href="/shift-assurance-enterprise">Shift Enterprise</a>
<a href="/shift-assurance-entra-test">Shift Entra Test</a>
<a class="active" href="/shift-handoff-lineage">Handoff Lineage</a>
<a href="/technicians">Technicians</a>
<a href="/servicenow-ci-readiness">ServiceNow CI</a>
</nav>

{% if technician_error %}
<div class="error"><b>Technician directory connection issue:</b><br>{{ technician_error }}</div>
{% else %}
<div class="notice"><b>Microsoft Entra connected.</b> {{ technicians|length }} approved technician(s) available for outgoing/incoming handoff.</div>
{% endif %}

{% if result and result.error %}
<div class="error">{{ result.error }}</div>
{% elif result %}
<div class="notice">
<b>Saved Lineage:</b> {{ result.lineage_id }} —
<b>{{ result.readiness_status }}</b> —
Score <b>{{ result.readiness_score }}%</b> —
Risk <b>{{ result.risk_level }}</b>
<ul>{% for s in result.signals %}<li>{{ s }}</li>{% endfor %}</ul>
<div class="hash"><b>Record Hash:</b> {{ result.record_hash }}</div>
</div>
{% endif %}

<section class="grid">
<div class="metric"><div class="metric-label">Total Lineage Records</div><div class="metric-value">{{ metrics.total }}</div></div>
<div class="metric"><div class="metric-label">Accepted / Ready</div><div class="metric-value" style="color:#16a34a">{{ metrics.ready }}</div></div>
<div class="metric"><div class="metric-label">Conditional</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional }}</div></div>
<div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ metrics.high }}</div></div>
</section>

<section class="layout">
<aside class="panel">
<h2>Submit Formal Handoff</h2>
<form method="POST" action="/shift-handoff-lineage">
<input name="ticket_number" placeholder="Ticket / Work Item e.g. INC-DEMO-0001" required>
<input name="ci_reference" placeholder="CI Reference e.g. CI-DEMO-1803" required>
<input name="equipment_name" placeholder="Equipment / System Name" required>

<select name="outgoing_shift" required>
<option value="">Outgoing Shift</option>
<option value="Morning Shift">Morning Shift</option>
<option value="Night Shift">Night Shift</option>
<option value="Weekend Coverage">Weekend Coverage</option>
<option value="Critical Handoff Queue">Critical Handoff Queue</option>
</select>

<select name="incoming_shift" required>
<option value="">Incoming Shift</option>
<option value="Morning Shift">Morning Shift</option>
<option value="Night Shift">Night Shift</option>
<option value="Weekend Coverage">Weekend Coverage</option>
<option value="Critical Handoff Queue">Critical Handoff Queue</option>
</select>

<select name="handoff_reason" required>
<option value="">Handoff Reason</option>
<option value="Open Ticket Carryover">Open Ticket Carryover</option>
<option value="Evidence Pending">Evidence Pending</option>
<option value="Equipment Readiness Risk">Equipment Readiness Risk</option>
<option value="Potential Deviation">Potential Deviation</option>
<option value="Routine Shift Transfer">Routine Shift Transfer</option>
</select>

<select name="outgoing_technician" required>
<option value="">Outgoing Technician</option>
{% for t in technicians %}
<option value="{{ t.id }}||{{ t.displayName }}||{{ t.userPrincipalName }}||{{ t.jobTitle }}">{{ t.displayName }} | {{ t.jobTitle }} | {{ t.userPrincipalName }}</option>
{% endfor %}
</select>

<select name="incoming_technician" required>
<option value="">Incoming Technician</option>
{% for t in technicians %}
<option value="{{ t.id }}||{{ t.displayName }}||{{ t.userPrincipalName }}||{{ t.jobTitle }}">{{ t.displayName }} | {{ t.jobTitle }} | {{ t.userPrincipalName }}</option>
{% endfor %}
</select>

<select name="evidence_status" required>
<option value="">Evidence Status</option>
<option value="Verified">Verified</option>
<option value="Pending Review">Pending Review</option>
<option value="Missing">Missing</option>
<option value="Not Verified">Not Verified</option>
<option value="Rejected">Rejected</option>
</select>

<select name="open_issue_risk" required>
<option value="">Open Issue / Risk</option>
<option value="No Open Issue">No Open Issue</option>
<option value="Unresolved">Unresolved</option>
<option value="Escalation Required">Escalation Required</option>
<option value="Potential Deviation">Potential Deviation</option>
</select>

<select name="acceptance_status" required>
<option value="">Incoming Acceptance Status</option>
<option value="Accepted">Accepted</option>
<option value="Pending Acceptance">Pending Acceptance</option>
<option value="Not Accepted">Not Accepted</option>
</select>

<textarea name="handoff_summary" placeholder="Handoff summary / carryover instruction"></textarea>

<button type="submit">Submit Handoff Lineage</button>
</form>
</aside>

<section class="card">
<h2>Recent Formal Handoff Lineage Records</h2>
{% if metrics.recent %}
<table>
<tr>
<th>ID</th><th>Ticket</th><th>CI / Equipment</th><th>Outgoing</th><th>Incoming</th><th>Evidence</th><th>Acceptance</th><th>Readiness</th><th>Risk</th>
</tr>
{% for r in metrics.recent %}
<tr>
<td>{{ r.lineage_id }}</td>
<td><b>{{ r.ticket_number }}</b></td>
<td><b>{{ r.ci_reference }}</b><br>{{ r.equipment_name }}</td>
<td><b>{{ r.outgoing_technician_name }}</b><br>{{ r.outgoing_shift }}</td>
<td><b>{{ r.incoming_technician_name }}</b><br>{{ r.incoming_shift }}</td>
<td>{{ r.evidence_status }}</td>
<td>{{ r.acceptance_status }}</td>
<td><b>{{ r.readiness_status }}</b><br>{{ r.readiness_score }}%</td>
<td class="{% if r.risk_level == 'LOW' %}low{% elif r.risk_level == 'MEDIUM' %}medium{% else %}high{% endif %}">{{ r.risk_level }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No formal handoff lineage records saved yet.</p>
{% endif %}
</section>
</section>

<div class="card">
<h2>Commercial Meaning</h2>
<p>
This creates a real audit lineage record for the transfer of operational responsibility: outgoing technician, incoming technician,
ticket, CI, evidence state, open risk, acceptance, timestamp, readiness score, and cryptographic record hash.
</p>
</div>
</main>
</body>
</html>
    """

    return render_template_string(
        html,
        technicians=technicians,
        technician_error=technician_error,
        result=result,
        metrics=metrics
    )


# ============================================================
# KNOWLEDGE GOVERNANCE ACTIVE
# Technician knowledge suggestion + supervisor review lineage.
# ServiceNow PDI-ready, demo-safe local governance register.
# ============================================================

KNOWLEDGE_GOVERNANCE_FILE = "knowledge_governance_register.csv"


def prepare_knowledge_governance_register():
    df = load_csv(KNOWLEDGE_GOVERNANCE_FILE)
    return ensure_cols(df, [
        "knowledge_lineage_id", "timestamp", "related_ticket", "ci_reference",
        "knowledge_title", "current_article_ref", "knowledge_type",
        "problem_observed", "suggested_update", "evidence_reference",
        "technician_id", "technician_name", "technician_upn", "technician_role",
        "reviewer_id", "reviewer_name", "reviewer_upn", "reviewer_role",
        "workflow_action", "workflow_status", "review_comment",
        "service_now_sync_status", "knowledge_integrity_score", "risk_level",
        "governance_signals", "previous_hash", "record_hash"
    ])


def parse_knowledge_person(value):
    value = clean(value)
    parts = value.split("||")
    while len(parts) < 4:
        parts.append("")
    return {
        "id": parts[0],
        "displayName": parts[1],
        "userPrincipalName": parts[2],
        "jobTitle": parts[3]
    }


def calculate_knowledge_integrity(related_ticket, ci_reference, knowledge_title,
                                  current_article_ref, problem_observed,
                                  suggested_update, evidence_reference,
                                  technician, reviewer, workflow_action,
                                  review_comment, service_now_sync_status):
    score = 100
    signals = []

    related_ticket = clean(related_ticket)
    ci_reference = clean(ci_reference)
    knowledge_title = clean(knowledge_title)
    current_article_ref = clean(current_article_ref)
    problem_observed = clean(problem_observed)
    suggested_update = clean(suggested_update)
    evidence_reference = clean(evidence_reference)
    workflow_action = clean(workflow_action)
    review_comment = clean(review_comment)
    service_now_sync_status = clean(service_now_sync_status)

    if not related_ticket:
        score -= 15
        signals.append("Knowledge suggestion is not linked to a ticket/work item.")

    if not ci_reference:
        score -= 15
        signals.append("Knowledge suggestion is not linked to a CI/equipment/system.")

    if not knowledge_title:
        score -= 20
        signals.append("Knowledge title is missing.")

    if not problem_observed:
        score -= 20
        signals.append("Problem observed / operational gap is missing.")

    if not suggested_update:
        score -= 25
        signals.append("Suggested knowledge update is missing.")

    if not technician.get("displayName"):
        score -= 20
        signals.append("Submitting technician is not selected from approved Entra technician list.")

    if workflow_action in ["Approve", "Reject", "Request Revision", "Publish Candidate"]:
        if not reviewer.get("displayName"):
            score -= 25
            signals.append("Reviewer/supervisor is required for review actions.")
        if not review_comment:
            score -= 15
            signals.append("Review comment is missing for the selected workflow action.")

    if workflow_action == "Approve" and not evidence_reference:
        score -= 15
        signals.append("Approved knowledge should reference supporting evidence or lineage.")

    if service_now_sync_status in ["Sync Failed", "Not Ready for Sync"]:
        score -= 15
        signals.append("ServiceNow knowledge sync status is not ready.")

    if current_article_ref and workflow_action == "Draft Submitted":
        signals.append("Existing article reference detected; this may be an article improvement rather than a new article.")

    if "workaround" in suggested_update.lower() or "bypass" in suggested_update.lower():
        score -= 10
        signals.append("Suggested update may describe a workaround; supervisor should verify SOP alignment.")

    score = max(score, 0)

    if score >= 85:
        risk = "LOW"
    elif score >= 60:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    if not signals:
        signals.append("Knowledge governance record appears complete and review-ready.")

    return score, risk, signals


def determine_knowledge_workflow_status(workflow_action):
    workflow_action = clean(workflow_action)

    if workflow_action == "Draft Submitted":
        return "DRAFT SUBMITTED / AWAITING REVIEW"
    if workflow_action == "Request Revision":
        return "REVISION REQUIRED"
    if workflow_action == "Approve":
        return "APPROVED BY REVIEWER"
    if workflow_action == "Reject":
        return "REJECTED BY REVIEWER"
    if workflow_action == "Publish Candidate":
        return "APPROVED / READY FOR SERVICENOW PDI SYNC"

    return "DRAFT SUBMITTED / AWAITING REVIEW"


def save_knowledge_governance(req):
    df = prepare_knowledge_governance_register()

    related_ticket = clean(req.form.get("related_ticket"))
    ci_reference = clean(req.form.get("ci_reference"))
    knowledge_title = clean(req.form.get("knowledge_title"))
    current_article_ref = clean(req.form.get("current_article_ref"))
    knowledge_type = clean(req.form.get("knowledge_type"))
    problem_observed = clean(req.form.get("problem_observed"))
    suggested_update = clean(req.form.get("suggested_update"))
    evidence_reference = clean(req.form.get("evidence_reference"))

    technician = parse_knowledge_person(req.form.get("technician"))
    reviewer = parse_knowledge_person(req.form.get("reviewer"))

    workflow_action = clean(req.form.get("workflow_action"))
    review_comment = clean(req.form.get("review_comment"))
    service_now_sync_status = clean(req.form.get("service_now_sync_status")) or "Demo local governance / future ServiceNow PDI sync"

    required = [
        related_ticket, ci_reference, knowledge_title, knowledge_type,
        problem_observed, suggested_update, technician["displayName"],
        workflow_action
    ]

    if not all(required):
        return {"error": "Ticket, CI, title, type, problem observed, suggested update, submitting technician, and workflow action are required."}

    workflow_status = determine_knowledge_workflow_status(workflow_action)

    integrity_score, risk_level, signals = calculate_knowledge_integrity(
        related_ticket, ci_reference, knowledge_title, current_article_ref,
        problem_observed, suggested_update, evidence_reference,
        technician, reviewer, workflow_action, review_comment,
        service_now_sync_status
    )

    timestamp = datetime.datetime.utcnow().isoformat()
    knowledge_lineage_id = "KLIN-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    previous_hash = "GENESIS"
    if not df.empty:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    record_hash = sha256_text(
        knowledge_lineage_id + timestamp + related_ticket + ci_reference +
        knowledge_title + knowledge_type + technician["id"] + reviewer["id"] +
        workflow_action + workflow_status + service_now_sync_status + previous_hash
    )

    row = pd.DataFrame([{
        "knowledge_lineage_id": knowledge_lineage_id,
        "timestamp": timestamp,
        "related_ticket": related_ticket,
        "ci_reference": ci_reference,
        "knowledge_title": knowledge_title,
        "current_article_ref": current_article_ref,
        "knowledge_type": knowledge_type,
        "problem_observed": problem_observed,
        "suggested_update": suggested_update,
        "evidence_reference": evidence_reference,
        "technician_id": technician["id"],
        "technician_name": technician["displayName"],
        "technician_upn": technician["userPrincipalName"],
        "technician_role": technician["jobTitle"],
        "reviewer_id": reviewer["id"],
        "reviewer_name": reviewer["displayName"],
        "reviewer_upn": reviewer["userPrincipalName"],
        "reviewer_role": reviewer["jobTitle"],
        "workflow_action": workflow_action,
        "workflow_status": workflow_status,
        "review_comment": review_comment,
        "service_now_sync_status": service_now_sync_status,
        "knowledge_integrity_score": integrity_score,
        "risk_level": risk_level,
        "governance_signals": " | ".join(signals),
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, KNOWLEDGE_GOVERNANCE_FILE)

    return {
        "error": "",
        "knowledge_lineage_id": knowledge_lineage_id,
        "workflow_status": workflow_status,
        "knowledge_integrity_score": integrity_score,
        "risk_level": risk_level,
        "signals": signals,
        "record_hash": record_hash
    }


def get_knowledge_governance_metrics():
    df = prepare_knowledge_governance_register()
    if df.empty:
        return {"total": 0, "approved": 0, "revision": 0, "high": 0, "recent": []}

    df = df.fillna("")
    return {
        "total": len(df),
        "approved": len(df[df["workflow_status"].str.contains("APPROVED", case=False, na=False)]),
        "revision": len(df[df["workflow_status"] == "REVISION REQUIRED"]),
        "high": len(df[df["risk_level"] == "HIGH"]),
        "recent": df.tail(12).to_dict("records")
    }


@app.route("/knowledge-governance", methods=["GET", "POST"])
def knowledge_governance_page():
    # KNOWLEDGE_GOVERNANCE_ACTIVE
    result = None
    technician_error = ""
    technicians = []

    try:
        technicians = get_entra_shift_technicians()
    except Exception as e:
        technician_error = str(e)

    if request.method == "POST":
        result = save_knowledge_governance(request)

    metrics = get_knowledge_governance_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>AssuranceLayer™ Knowledge Governance</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#7c3aed);color:white;padding:38px 44px 50px;border-bottom-left-radius:34px;border-bottom-right-radius:34px}
.container{max-width:1500px;margin:-24px auto 50px;padding:0 26px}
.nav,.card,.panel{background:white;border:1px solid #e5e7eb;border-radius:24px;padding:20px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:20px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:7px}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.layout{display:grid;grid-template-columns:460px 1fr;gap:20px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
input,select,textarea,button{width:100%;border-radius:13px;border:1px solid #dbe3ef;padding:11px;margin:6px 0;font-size:14px}
textarea{min-height:95px}
button{border:none;background:linear-gradient(135deg,#7c3aed,#2563eb);color:white;font-weight:900;cursor:pointer}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
.warning{background:#fff7ed;border-left:7px solid #f59e0b;border-radius:16px;padding:14px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top;word-break:break-word}
.low{color:#16a34a;font-weight:900}.medium{color:#d97706;font-weight:900}.high{color:#dc2626;font-weight:900}
.hash{font-family:Consolas,monospace;font-size:11px;word-break:break-all;color:#334155}
@media(max-width:1000px){.grid,.layout{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>AssuranceLayer™ Knowledge Governance</h1>
<p>Technician knowledge suggestion → supervisor review → CI/ticket linkage → evidence reference → ServiceNow PDI-ready knowledge lineage.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/command-center">Command Center</a>
<a href="/shift-assurance-enterprise">Shift Enterprise</a>
<a href="/shift-handoff-lineage">Handoff Lineage</a>
<a href="/servicenow-ci-readiness">ServiceNow CI</a>
<a href="/technicians">Technicians</a>
<a class="active" href="/knowledge-governance">Knowledge Governance</a>
</nav>

<div class="warning">
<b>Enterprise model:</b> ServiceNow remains the future knowledge system of record. AssuranceLayer™ governs how knowledge is suggested, reviewed, linked to tickets/CIs, supported by evidence, and prepared for future ServiceNow PDI sync.
</div>

{% if technician_error %}
<div class="error"><b>Technician directory connection issue:</b><br>{{ technician_error }}</div>
{% else %}
<div class="notice"><b>Microsoft Entra connected.</b> {{ technicians|length }} approved user(s) available for technician/reviewer workflow.</div>
{% endif %}

{% if result and result.error %}
<div class="error">{{ result.error }}</div>
{% elif result %}
<div class="notice">
<b>Saved Knowledge Lineage:</b> {{ result.knowledge_lineage_id }} —
<b>{{ result.workflow_status }}</b> —
Integrity Score <b>{{ result.knowledge_integrity_score }}%</b> —
Risk <b>{{ result.risk_level }}</b>
<ul>{% for s in result.signals %}<li>{{ s }}</li>{% endfor %}</ul>
<div class="hash"><b>Record Hash:</b> {{ result.record_hash }}</div>
</div>
{% endif %}

<section class="grid">
<div class="metric"><div class="metric-label">Total Knowledge Records</div><div class="metric-value">{{ metrics.total }}</div></div>
<div class="metric"><div class="metric-label">Approved / Ready</div><div class="metric-value" style="color:#16a34a">{{ metrics.approved }}</div></div>
<div class="metric"><div class="metric-label">Revision Required</div><div class="metric-value" style="color:#f59e0b">{{ metrics.revision }}</div></div>
<div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ metrics.high }}</div></div>
</section>

<section class="layout">
<aside class="panel">
<h2>Create Knowledge Governance Record</h2>
<form method="POST" action="/knowledge-governance">
<input name="related_ticket" placeholder="Related Ticket e.g. INC-DEMO-0001" required>
<input name="ci_reference" placeholder="CI Reference e.g. CI-DEMO-1803" required>
<input name="knowledge_title" placeholder="Knowledge Title e.g. Audit trail export recovery steps" required>
<input name="current_article_ref" placeholder="Existing Article Ref e.g. KB-DEMO-0001, or leave blank for new article">

<select name="knowledge_type" required>
<option value="">Knowledge Type</option>
<option value="New Article Suggestion">New Article Suggestion</option>
<option value="Article Improvement">Article Improvement</option>
<option value="SOP / Reality Drift">SOP / Reality Drift</option>
<option value="Known Failure Mode">Known Failure Mode</option>
<option value="Evidence Handling Instruction">Evidence Handling Instruction</option>
</select>

<select name="technician" required>
<option value="">Submitting Technician</option>
{% for t in technicians %}
<option value="{{ t.id }}||{{ t.displayName }}||{{ t.userPrincipalName }}||{{ t.jobTitle }}">{{ t.displayName }} | {{ t.jobTitle }} | {{ t.userPrincipalName }}</option>
{% endfor %}
</select>

<textarea name="problem_observed" placeholder="Problem observed / gap discovered during ticket, CI review, handoff, or evidence collection" required></textarea>
<textarea name="suggested_update" placeholder="Suggested knowledge article content or update" required></textarea>
<input name="evidence_reference" placeholder="Evidence Reference e.g. EV-DEMO-0001 / file hash / screenshot ref">

<select name="workflow_action" required>
<option value="">Workflow Action</option>
<option value="Draft Submitted">Draft Submitted</option>
<option value="Request Revision">Request Revision</option>
<option value="Approve">Approve</option>
<option value="Reject">Reject</option>
<option value="Publish Candidate">Publish Candidate</option>
</select>

<select name="reviewer">
<option value="">Reviewer / Supervisor Optional for Draft, Required for Review</option>
{% for t in technicians %}
<option value="{{ t.id }}||{{ t.displayName }}||{{ t.userPrincipalName }}||{{ t.jobTitle }}">{{ t.displayName }} | {{ t.jobTitle }} | {{ t.userPrincipalName }}</option>
{% endfor %}
</select>

<textarea name="review_comment" placeholder="Supervisor / reviewer comment"></textarea>

<select name="service_now_sync_status">
<option value="Demo local governance / future ServiceNow PDI sync">ServiceNow Sync: Demo local governance / future ServiceNow PDI sync</option>
<option value="Not Ready for Sync">Not Ready for Sync</option>
<option value="Ready for PDI Sync">Ready for PDI Sync</option>
<option value="Sync Failed">Sync Failed</option>
<option value="Synced to ServiceNow PDI">Synced to ServiceNow PDI</option>
</select>

<button type="submit">Save Knowledge Governance Lineage</button>
</form>
</aside>

<section class="card">
<h2>Recent Knowledge Governance Records</h2>
{% if metrics.recent %}
<table>
<tr>
<th>ID</th><th>Ticket / CI</th><th>Title</th><th>Technician</th><th>Reviewer</th><th>Status</th><th>Score</th><th>Risk</th>
</tr>
{% for r in metrics.recent %}
<tr>
<td>{{ r.knowledge_lineage_id }}</td>
<td><b>{{ r.related_ticket }}</b><br>{{ r.ci_reference }}</td>
<td><b>{{ r.knowledge_title }}</b><br>{{ r.knowledge_type }}</td>
<td>{{ r.technician_name }}<br>{{ r.technician_role }}</td>
<td>{{ r.reviewer_name }}<br>{{ r.reviewer_role }}</td>
<td><b>{{ r.workflow_status }}</b><br>{{ r.service_now_sync_status }}</td>
<td>{{ r.knowledge_integrity_score }}%</td>
<td class="{% if r.risk_level == 'LOW' %}low{% elif r.risk_level == 'MEDIUM' %}medium{% else %}high{% endif %}">{{ r.risk_level }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No knowledge governance records saved yet.</p>
{% endif %}
</section>
</section>

<div class="card">
<h2>Commercial Meaning</h2>
<p>
This is not just a knowledge base. It is a governed knowledge lineage workflow:
ticket → CI → technician observation → knowledge suggestion → supervisor review → evidence reference → approval status → future ServiceNow PDI sync → hash-backed audit lineage.
</p>
</div>
</main>
</body>
</html>
    """

    return render_template_string(
        html,
        technicians=technicians,
        technician_error=technician_error,
        result=result,
        metrics=metrics
    )


# ============================================================
# KNOWLEDGE REVIEW QUEUE ACTIVE
# Supervisor review queue for technician knowledge suggestions.
# Append-only review event register.
# ============================================================

KNOWLEDGE_REVIEW_FILE = "knowledge_review_events.csv"


def prepare_knowledge_review_events():
    df = load_csv(KNOWLEDGE_REVIEW_FILE)
    return ensure_cols(df, [
        "review_event_id", "timestamp", "knowledge_lineage_id",
        "related_ticket", "ci_reference", "knowledge_title", "knowledge_type",
        "technician_name", "technician_upn", "reviewer_id", "reviewer_name",
        "reviewer_upn", "reviewer_role", "review_action", "review_status",
        "review_comment", "service_now_sync_status", "review_score",
        "risk_level", "governance_signals", "previous_hash", "record_hash"
    ])


def get_knowledge_suggestion_by_id(knowledge_lineage_id):
    df = prepare_knowledge_governance_register().fillna("")
    if df.empty:
        return None

    matches = df[df["knowledge_lineage_id"] == knowledge_lineage_id]
    if matches.empty:
        return None

    return matches.tail(1).iloc[0].to_dict()


def calculate_knowledge_review_score(suggestion, reviewer, review_action, review_comment, service_now_sync_status):
    score = 100
    signals = []

    if not suggestion:
        score -= 50
        signals.append("Original knowledge suggestion could not be found.")

    if not reviewer.get("displayName"):
        score -= 30
        signals.append("Reviewer/supervisor is missing.")

    if not clean(review_action):
        score -= 25
        signals.append("Review action is missing.")

    if review_action in ["Approve", "Reject", "Request Revision", "Ready for ServiceNow PDI Sync"] and not clean(review_comment):
        score -= 20
        signals.append("Review comment is required for the selected action.")

    if suggestion:
        if not clean(suggestion.get("related_ticket")):
            score -= 10
            signals.append("Suggestion is not linked to a ticket.")
        if not clean(suggestion.get("ci_reference")):
            score -= 10
            signals.append("Suggestion is not linked to a CI/equipment/system.")
        if not clean(suggestion.get("evidence_reference")) and review_action in ["Approve", "Ready for ServiceNow PDI Sync"]:
            score -= 15
            signals.append("Approved or sync-ready knowledge should have an evidence reference.")

    if service_now_sync_status in ["Sync Failed", "Not Ready for Sync"]:
        score -= 15
        signals.append("ServiceNow sync status is not ready.")

    score = max(score, 0)

    if score >= 85:
        risk = "LOW"
    elif score >= 60:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    if not signals:
        signals.append("Knowledge review event appears complete and governance-ready.")

    return score, risk, signals


def determine_knowledge_review_status(review_action):
    review_action = clean(review_action)

    if review_action == "Approve":
        return "APPROVED BY SUPERVISOR"
    if review_action == "Reject":
        return "REJECTED BY SUPERVISOR"
    if review_action == "Request Revision":
        return "REVISION REQUESTED"
    if review_action == "Ready for ServiceNow PDI Sync":
        return "READY FOR SERVICENOW PDI SYNC"

    return "UNDER REVIEW"


def save_knowledge_review_event(req):
    df = prepare_knowledge_review_events()

    knowledge_lineage_id = clean(req.form.get("knowledge_lineage_id"))
    reviewer = parse_knowledge_person(req.form.get("reviewer"))
    review_action = clean(req.form.get("review_action"))
    review_comment = clean(req.form.get("review_comment"))
    service_now_sync_status = clean(req.form.get("service_now_sync_status")) or "Demo local review / future ServiceNow PDI sync"

    if not knowledge_lineage_id or not reviewer["displayName"] or not review_action:
        return {"error": "Knowledge lineage ID, reviewer, and review action are required."}

    suggestion = get_knowledge_suggestion_by_id(knowledge_lineage_id)
    if not suggestion:
        return {"error": "Selected knowledge suggestion was not found in knowledge_governance_register.csv."}

    review_status = determine_knowledge_review_status(review_action)

    review_score, risk_level, signals = calculate_knowledge_review_score(
        suggestion, reviewer, review_action, review_comment, service_now_sync_status
    )

    timestamp = datetime.datetime.utcnow().isoformat()
    review_event_id = "KREV-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    previous_hash = "GENESIS"
    if not df.empty:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    record_hash = sha256_text(
        review_event_id + timestamp + knowledge_lineage_id +
        clean(suggestion.get("related_ticket")) + clean(suggestion.get("ci_reference")) +
        clean(suggestion.get("knowledge_title")) + reviewer["id"] +
        review_action + review_status + service_now_sync_status + previous_hash
    )

    row = pd.DataFrame([{
        "review_event_id": review_event_id,
        "timestamp": timestamp,
        "knowledge_lineage_id": knowledge_lineage_id,
        "related_ticket": clean(suggestion.get("related_ticket")),
        "ci_reference": clean(suggestion.get("ci_reference")),
        "knowledge_title": clean(suggestion.get("knowledge_title")),
        "knowledge_type": clean(suggestion.get("knowledge_type")),
        "technician_name": clean(suggestion.get("technician_name")),
        "technician_upn": clean(suggestion.get("technician_upn")),
        "reviewer_id": reviewer["id"],
        "reviewer_name": reviewer["displayName"],
        "reviewer_upn": reviewer["userPrincipalName"],
        "reviewer_role": reviewer["jobTitle"],
        "review_action": review_action,
        "review_status": review_status,
        "review_comment": review_comment,
        "service_now_sync_status": service_now_sync_status,
        "review_score": review_score,
        "risk_level": risk_level,
        "governance_signals": " | ".join(signals),
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, KNOWLEDGE_REVIEW_FILE)

    return {
        "error": "",
        "review_event_id": review_event_id,
        "review_status": review_status,
        "review_score": review_score,
        "risk_level": risk_level,
        "signals": signals,
        "record_hash": record_hash
    }


def get_latest_knowledge_review_map():
    df = prepare_knowledge_review_events().fillna("")
    latest = {}

    if df.empty:
        return latest

    for _, row in df.iterrows():
        latest[clean(row.get("knowledge_lineage_id"))] = row.to_dict()

    return latest


def get_knowledge_review_queue_metrics():
    suggestions = prepare_knowledge_governance_register().fillna("")
    reviews = prepare_knowledge_review_events().fillna("")
    latest_reviews = get_latest_knowledge_review_map()

    queue = []
    if not suggestions.empty:
        for _, row in suggestions.tail(30).iterrows():
            item = row.to_dict()
            lid = clean(item.get("knowledge_lineage_id"))
            latest = latest_reviews.get(lid, {})
            item["latest_review_status"] = clean(latest.get("review_status")) or clean(item.get("workflow_status")) or "AWAITING REVIEW"
            item["latest_reviewer"] = clean(latest.get("reviewer_name"))
            item["latest_review_comment"] = clean(latest.get("review_comment"))
            item["latest_review_score"] = clean(latest.get("review_score"))
            item["latest_review_risk"] = clean(latest.get("risk_level")) or clean(item.get("risk_level"))
            queue.append(item)

    approved = 0
    revision = 0
    rejected = 0

    for item in queue:
        status = clean(item.get("latest_review_status"))
        if "APPROVED" in status or "SYNC" in status:
            approved += 1
        if "REVISION" in status:
            revision += 1
        if "REJECTED" in status:
            rejected += 1

    return {
        "total_suggestions": len(queue),
        "review_events": len(reviews),
        "approved": approved,
        "revision": revision,
        "rejected": rejected,
        "queue": list(reversed(queue))
    }


@app.route("/knowledge-review", methods=["GET", "POST"])
def knowledge_review_page():
    # KNOWLEDGE_REVIEW_QUEUE_ACTIVE
    result = None
    technician_error = ""
    technicians = []

    try:
        technicians = get_entra_shift_technicians()
    except Exception as e:
        technician_error = str(e)

    if request.method == "POST":
        result = save_knowledge_review_event(request)

    metrics = get_knowledge_review_queue_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>AssuranceLayer™ Knowledge Review Queue</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#4c1d95);color:white;padding:38px 44px 50px;border-bottom-left-radius:34px;border-bottom-right-radius:34px}
.container{max-width:1500px;margin:-24px auto 50px;padding:0 26px}
.nav,.card,.panel{background:white;border:1px solid #e5e7eb;border-radius:24px;padding:20px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:20px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:7px}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.layout{display:grid;grid-template-columns:460px 1fr;gap:20px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
select,textarea,button{width:100%;border-radius:13px;border:1px solid #dbe3ef;padding:11px;margin:6px 0;font-size:14px}
textarea{min-height:95px}
button{border:none;background:linear-gradient(135deg,#4c1d95,#2563eb);color:white;font-weight:900;cursor:pointer}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
.warning{background:#fff7ed;border-left:7px solid #f59e0b;border-radius:16px;padding:14px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top;word-break:break-word}
.low{color:#16a34a;font-weight:900}.medium{color:#d97706;font-weight:900}.high{color:#dc2626;font-weight:900}
.hash{font-family:Consolas,monospace;font-size:11px;word-break:break-all;color:#334155}
@media(max-width:1000px){.grid,.layout{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>AssuranceLayer™ Knowledge Review Queue</h1>
<p>Supervisor review for technician knowledge suggestions, revision requests, approval, and future ServiceNow PDI sync readiness.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/command-center">Command Center</a>
<a href="/knowledge-governance">Knowledge Governance</a>
<a class="active" href="/knowledge-review">Knowledge Review</a>
<a href="/servicenow-ci-readiness">ServiceNow CI</a>
<a href="/shift-handoff-lineage">Handoff Lineage</a>
<a href="/technicians">Technicians</a>
</nav>

<div class="warning">
<b>Enterprise model:</b> technician knowledge suggestions are reviewed by a supervisor/knowledge owner before they become publish candidates for ServiceNow PDI or enterprise knowledge management.
</div>

{% if technician_error %}
<div class="error"><b>Technician directory connection issue:</b><br>{{ technician_error }}</div>
{% else %}
<div class="notice"><b>Microsoft Entra connected.</b> {{ technicians|length }} approved reviewer/technician user(s) available.</div>
{% endif %}

{% if result and result.error %}
<div class="error">{{ result.error }}</div>
{% elif result %}
<div class="notice">
<b>Saved Review Event:</b> {{ result.review_event_id }} —
<b>{{ result.review_status }}</b> —
Score <b>{{ result.review_score }}%</b> —
Risk <b>{{ result.risk_level }}</b>
<ul>{% for s in result.signals %}<li>{{ s }}</li>{% endfor %}</ul>
<div class="hash"><b>Record Hash:</b> {{ result.record_hash }}</div>
</div>
{% endif %}

<section class="grid">
<div class="metric"><div class="metric-label">Suggestions</div><div class="metric-value">{{ metrics.total_suggestions }}</div></div>
<div class="metric"><div class="metric-label">Review Events</div><div class="metric-value">{{ metrics.review_events }}</div></div>
<div class="metric"><div class="metric-label">Approved / Sync Ready</div><div class="metric-value" style="color:#16a34a">{{ metrics.approved }}</div></div>
<div class="metric"><div class="metric-label">Revision Required</div><div class="metric-value" style="color:#f59e0b">{{ metrics.revision }}</div></div>
</section>

<section class="layout">
<aside class="panel">
<h2>Review Knowledge Suggestion</h2>
<form method="POST" action="/knowledge-review">
<select name="knowledge_lineage_id" required>
<option value="">Select knowledge suggestion</option>
{% for q in metrics.queue %}
<option value="{{ q.knowledge_lineage_id }}">{{ q.knowledge_lineage_id }} | {{ q.knowledge_title }} | {{ q.related_ticket }} | {{ q.ci_reference }}</option>
{% endfor %}
</select>

<select name="reviewer" required>
<option value="">Reviewer / Supervisor</option>
{% for t in technicians %}
<option value="{{ t.id }}||{{ t.displayName }}||{{ t.userPrincipalName }}||{{ t.jobTitle }}">{{ t.displayName }} | {{ t.jobTitle }} | {{ t.userPrincipalName }}</option>
{% endfor %}
</select>

<select name="review_action" required>
<option value="">Review Action</option>
<option value="Approve">Approve</option>
<option value="Request Revision">Request Revision</option>
<option value="Reject">Reject</option>
<option value="Ready for ServiceNow PDI Sync">Ready for ServiceNow PDI Sync</option>
</select>

<textarea name="review_comment" placeholder="Supervisor / reviewer comment"></textarea>

<select name="service_now_sync_status">
<option value="Demo local review / future ServiceNow PDI sync">ServiceNow Sync: Demo local review / future ServiceNow PDI sync</option>
<option value="Not Ready for Sync">Not Ready for Sync</option>
<option value="Ready for PDI Sync">Ready for PDI Sync</option>
<option value="Sync Failed">Sync Failed</option>
<option value="Synced to ServiceNow PDI">Synced to ServiceNow PDI</option>
</select>

<button type="submit">Submit Supervisor Review</button>
</form>
</aside>

<section class="card">
<h2>Knowledge Review Queue</h2>
{% if metrics.queue %}
<table>
<tr>
<th>ID</th><th>Ticket / CI</th><th>Title</th><th>Technician</th><th>Current Status</th><th>Latest Reviewer</th><th>Score / Risk</th>
</tr>
{% for q in metrics.queue %}
<tr>
<td>{{ q.knowledge_lineage_id }}</td>
<td><b>{{ q.related_ticket }}</b><br>{{ q.ci_reference }}</td>
<td><b>{{ q.knowledge_title }}</b><br>{{ q.knowledge_type }}</td>
<td>{{ q.technician_name }}<br>{{ q.technician_role }}</td>
<td><b>{{ q.latest_review_status }}</b><br>{{ q.service_now_sync_status }}</td>
<td>{{ q.latest_reviewer }}<br>{{ q.latest_review_comment }}</td>
<td>{{ q.latest_review_score or q.knowledge_integrity_score }}%<br><span class="{% if q.latest_review_risk == 'LOW' %}low{% elif q.latest_review_risk == 'MEDIUM' %}medium{% else %}high{% endif %}">{{ q.latest_review_risk }}</span></td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No knowledge suggestions found. Create one first in Knowledge Governance.</p>
{% endif %}
</section>
</section>

<div class="card">
<h2>Commercial Meaning</h2>
<p>
This creates a governed review layer over field knowledge: technician observation, ticket, CI, evidence reference, supervisor comment,
approval/revision decision, ServiceNow sync readiness, timestamp, and cryptographic record hash.
</p>
</div>
</main>
</body>
</html>
    """

    return render_template_string(
        html,
        technicians=technicians,
        technician_error=technician_error,
        result=result,
        metrics=metrics
    )


# ============================================================
# MONDAY DEMO PAGE ACTIVE
# Guided presentation mode for leadership demo.
# ============================================================

@app.route("/monday-demo")
def monday_demo_page():
    # MONDAY_DEMO_PAGE_ACTIVE
    html = """
<!DOCTYPE html>
<html>
<head>
<title>AssuranceLayer™ Monday Demo Mode</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#1d4ed8);color:white;padding:40px 44px 54px;border-bottom-left-radius:34px;border-bottom-right-radius:34px}
.container{max-width:1500px;margin:-26px auto 50px;padding:0 26px}
.nav,.section,.card{background:white;border:1px solid #e5e7eb;border-radius:24px;padding:20px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:20px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:7px}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}
.two{display:grid;grid-template-columns:repeat(2,1fr);gap:18px}
.card h3{margin:0 0 8px}
.card p,.section p,li{color:#475569;line-height:1.55}
.card a{display:inline-block;margin-top:10px;text-decoration:none;background:#0f172a;color:white;padding:9px 12px;border-radius:999px;font-weight:900;font-size:13px}
.badge{display:inline-block;padding:7px 10px;border-radius:999px;font-size:12px;font-weight:900;margin-bottom:10px}
.opening{background:#eff6ff;color:#1d4ed8}
.demo{background:#ecfdf5;color:#047857}
.risk{background:#fff7ed;color:#c2410c}
.ask{background:#faf5ff;color:#7e22ce}
.warning{background:#fff7ed;border-left:7px solid #f59e0b;border-radius:18px;padding:16px;line-height:1.55;margin-bottom:20px}
.script{background:#f8fafc;border-left:7px solid #2563eb;border-radius:18px;padding:16px;line-height:1.65;margin-bottom:16px}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:13px}
th{background:#0f172a;color:white;text-align:left;padding:11px}
td{border-bottom:1px solid #e5e7eb;padding:11px;vertical-align:top}
.stepno{font-size:22px;font-weight:1000;color:#1d4ed8}
@media(max-width:1000px){.grid,.two{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>AssuranceLayer™ Monday Demo Mode</h1>
<p>Guided presentation path for operational governance, shift continuity, ServiceNow CI readiness, knowledge governance, evidence integrity, and executive visibility.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/command-center">Command Center</a>
<a class="active" href="/monday-demo">Monday Demo</a>
<a href="/qc-ops-intake">QC Ops Intake</a>
<a href="/technicians">Technicians</a>
<a href="/shift-assurance-enterprise">Shift Enterprise</a>
<a href="/shift-handoff-lineage">Handoff Lineage</a>
<a href="/servicenow-ci-readiness">ServiceNow CI</a>
<a href="/knowledge-governance">Knowledge Governance</a>
<a href="/knowledge-review">Knowledge Review</a>
<a href="/executive-overview">Executive</a>
<a href="/architecture">Architecture</a>
</nav>

<div class="warning">
<b>Presentation rule:</b> Do not present this as a replacement for existing validated systems. Present it as a governance assurance layer that strengthens continuity between existing systems, operational datasets, tickets, CIs, technician identity, evidence, and review decisions.
</div>

<div class="section">
<h2>1. Opening Message</h2>
<div class="script">
AssuranceLayer™ is a governance assurance workspace designed to convert fragmented operational records into traceable, fingerprinted, audit-ready governance evidence. 
The goal is not to replace existing enterprise systems. The goal is to strengthen operational continuity between them.
</div>
<div class="script">
The platform demonstrates how operational datasets, technician identity, ticket/CI context, shift handoff, evidence readiness, pre-deviation risk, and knowledge review can be connected into one governed lineage model.
</div>
</div>

<div class="section">
<h2>2. The Operational Challenge</h2>
<div class="grid">
<div class="card"><span class="badge opening">PAIN POINT</span><h3>Fragmented evidence</h3><p>Operational evidence exists across spreadsheets, tickets, handoffs, binders, SOP references, work orders, and local files.</p></div>
<div class="card"><span class="badge opening">PAIN POINT</span><h3>Manual continuity</h3><p>Shift transfer and task ownership often depend on manual notes, memory, or separate communication channels.</p></div>
<div class="card"><span class="badge opening">PAIN POINT</span><h3>Reactive governance</h3><p>Risks are often discovered after escalation, audit preparation, or deviation review instead of during work execution.</p></div>
</div>
</div>

<div class="section">
<h2>3. Live Demo Path</h2>
<table>
<tr><th>Step</th><th>Open Page</th><th>What It Proves</th><th>What To Say</th></tr>

<tr>
<td class="stepno">1</td>
<td><a href="/command-center">Command Center</a></td>
<td>Full platform navigation hub.</td>
<td>“This is the governed workspace that connects the modules into one operational assurance flow.”</td>
</tr>

<tr>
<td class="stepno">2</td>
<td><a href="/qc-ops-intake">QC Ops Intake</a></td>
<td>Excel/CSV becomes governed operational dataset.</td>
<td>“We are not replacing spreadsheets. We are fingerprinting and transforming them into governed datasets.”</td>
</tr>

<tr>
<td class="stepno">3</td>
<td><a href="/technicians">Technicians</a></td>
<td>Technician dropdown is controlled by Microsoft Entra ID.</td>
<td>“Technician names are not typed manually. Eligibility comes from a controlled identity group.”</td>
</tr>

<tr>
<td class="stepno">4</td>
<td><a href="/shift-assurance-enterprise">Shift Enterprise</a></td>
<td>Ticket + CI + approved technician + readiness score.</td>
<td>“Shift work now links work context, CI reference, identity, evidence state, and governance readiness.”</td>
</tr>

<tr>
<td class="stepno">5</td>
<td><a href="/shift-handoff-lineage">Handoff Lineage</a></td>
<td>Outgoing-to-incoming handoff lineage.</td>
<td>“Operational responsibility transfer becomes a governed record with acceptance, risk, timestamp, and hash.”</td>
</tr>

<tr>
<td class="stepno">6</td>
<td><a href="/servicenow-tickets-live">ServiceNow Live Tickets</a></td>
<td>Live read-only pull from ServiceNow PDI.</td>
<td>“This is no longer only a mockup. AssuranceLayer is reading live PDI tickets and preparing them for CI readiness, handoff, evidence, and knowledge governance.”</td>
</tr>

<tr>
<td class="stepno">7</td>
<td><a href="/servicenow-ci-readiness">ServiceNow CI Readiness</a></td>
<td>Ticket/CI governance readiness model.</td>
<td>“ServiceNow owns the ticket and CI. AssuranceLayer verifies whether the CI context is governance-ready.”</td>
</tr>

<tr>
<td class="stepno">8</td>
<td><a href="/knowledge-governance">Knowledge Governance</a></td>
<td>Technician field knowledge becomes governed.</td>
<td>“Field learning becomes linked to ticket, CI, technician, evidence, and future ServiceNow knowledge sync.”</td>
</tr>

<tr>
<td class="stepno">9</td>
<td><a href="/knowledge-review">Knowledge Review</a></td>
<td>Supervisor review and approval lineage.</td>
<td>“Knowledge is not published informally. It goes through review, comment, approval, revision, and hash lineage.”</td>
</tr>

<tr>
<td class="stepno">10</td>
<td><a href="/platform-health">Platform Health</a></td>
<td>All module registers and record counts.</td>
<td>“Each workflow has a separate evidence register, which protects modularity and traceability.”</td>
</tr>

<tr>
<td class="stepno">11</td>
<td><a href="/executive-overview">Executive Overview</a></td>
<td>Leadership-level risk/readiness view.</td>
<td>“This gives leaders visibility into operational governance posture, not only task status.”</td>
</tr>

<tr>
<td class="stepno">12</td>
<td><a href="/architecture">Architecture</a></td>
<td>Architecture and innovation explanation.</td>
<td>“This is a non-invasive assurance layer over existing enterprise systems.”</td>
</tr>
</table>
</div>

<div class="section">
<h2>4. Core Message By Audience</h2>
<div class="grid">
<div class="card"><span class="badge demo">Operations</span><h3>Shift continuity</h3><p>Ticket, CI, technician, evidence, open risk, and carryover instructions are connected into one lineage.</p></div>
<div class="card"><span class="badge demo">IT / Service Management</span><h3>CI governance readiness</h3><p>ServiceNow remains the work and CI source. AssuranceLayer adds evidence readiness, lineage, and governance scoring.</p></div>
<div class="card"><span class="badge demo">Quality / Governance</span><h3>Pre-deviation visibility</h3><p>The system flags missing evidence, unclear impact, SOP gaps, and handoff risks before they become bigger governance issues.</p></div>
<div class="card"><span class="badge demo">Leadership</span><h3>Operational assurance</h3><p>Leaders see readiness posture, high-risk items, and governance continuity across modules.</p></div>
<div class="card"><span class="badge demo">Knowledge Owners</span><h3>Controlled field learning</h3><p>Technician knowledge suggestions become reviewable, approvable, evidence-linked, and ServiceNow PDI-ready.</p></div>
<div class="card"><span class="badge demo">Integration Team</span><h3>System-safe architecture</h3><p>The design preserves existing systems and adds a governance assurance layer around them.</p></div>
</div>
</div>

<div class="section">
<h2>5. ServiceNow PDI Future Integration Note</h2>
<div class="script">
The current ServiceNow CI page uses demo-safe ServiceNow-style records. The architecture is ready for a real ServiceNow PDI connection. 
The next integration stage will pull incidents, CIs, assignment groups, and knowledge articles from a ServiceNow PDI through API, then connect those records to Entra technicians, shift handoff, evidence fingerprinting, and governance review.
</div>
</div>

<div class="section">
<h2>6. What This Demonstrates</h2>
<table>
<tr><th>Capability</th><th>Demonstrated By</th><th>Strategic Value</th></tr>
<tr><td>Governed dataset intake</td><td>QC Ops Intake</td><td>Transforms Excel/CSV into fingerprinted governance assets.</td></tr>
<tr><td>Controlled identity</td><td>Technicians page</td><td>Technician dropdown is controlled by Microsoft Entra ID group membership.</td></tr>
<tr><td>Operational continuity</td><td>Shift Enterprise</td><td>Connects ticket, CI, technician, evidence, risk, and readiness.</td></tr>
<tr><td>Formal handoff</td><td>Handoff Lineage</td><td>Creates outgoing-to-incoming accountability with hash lineage.</td></tr>
<tr><td>ServiceNow readiness</td><td>ServiceNow CI Readiness</td><td>Prepares ticket/CI governance model for real ServiceNow PDI integration.</td></tr>
<tr><td>Knowledge governance</td><td>Knowledge Governance + Review</td><td>Converts field learning into reviewed, approved, evidence-linked operational knowledge.</td></tr>
<tr><td>Executive visibility</td><td>Executive Overview + Platform Health</td><td>Shows readiness, risk, and register health across modules.</td></tr>
</table>
</div>

<div class="section">
<h2>7. Final Leadership Ask</h2>
<div class="two">
<div class="card"><span class="badge ask">ASK 1</span><h3>Allow a controlled demo pilot</h3><p>Use sanitized/demo data first. Keep the platform read-only and non-invasive while evaluating governance value.</p></div>
<div class="card"><span class="badge ask">ASK 2</span><h3>Select one pilot workflow</h3><p>Best candidate: shift handoff + ticket/CI readiness + knowledge suggestion review.</p></div>
<div class="card"><span class="badge ask">ASK 3</span><h3>Connect ServiceNow PDI next</h3><p>Use a PDI first, then evaluate enterprise API integration only after governance and security review.</p></div>
<div class="card"><span class="badge ask">ASK 4</span><h3>Review IP and disclosure boundaries</h3><p>Keep company-specific data out of the demo and protect the architecture as an independent governance assurance concept.</p></div>
</div>
</div>

<div class="section">
<h2>8. Closing Statement</h2>
<div class="script">
AssuranceLayer™ shows how operational governance can move from fragmented records and manual reconstruction to continuous, identity-controlled, evidence-backed, reviewable, and audit-ready lineage.
</div>
<div class="script">
The strongest next step is a small controlled pilot using sanitized data, ServiceNow PDI records, Microsoft Entra technician identity, and one operational workflow such as shift handoff and knowledge governance.
</div>
</div>

</main>
</body>
</html>
    """
    return render_template_string(html)


# ============================================================
# SERVICENOW LIVE INTEGRATION ACTIVE
# Pulls real incidents from ServiceNow PDI into AssuranceLayer.
# Demo-safe, read-only integration.
# ============================================================

def get_servicenow_live_config():
    import os

    instance = os.environ.get("SERVICENOW_INSTANCE", "").strip().rstrip("/")
    username = os.environ.get("SERVICENOW_USERNAME", "").strip()
    password = os.environ.get("SERVICENOW_PASSWORD", "").strip()
    assignment_group = os.environ.get("SERVICENOW_ASSIGNMENT_GROUP", "").strip()

    missing = []
    if not instance:
        missing.append("SERVICENOW_INSTANCE")
    if not username:
        missing.append("SERVICENOW_USERNAME")
    if not password:
        missing.append("SERVICENOW_PASSWORD")

    if missing:
        raise RuntimeError("Missing ServiceNow app settings: " + ", ".join(missing))

    return instance, username, password, assignment_group


def recommend_servicenow_live_kb(short_description):
    text = (short_description or "").lower()

    if "backup" in text:
        return "KB-DEMO-002 - Monthly backup review evidence checklist"
    if "access" in text:
        return "KB-DEMO-003 - Quarterly access review remediation process"
    if "audit trail" in text or "audit" in text:
        return "KB-DEMO-001 - How to verify audit trail export evidence"

    return "KB-DEMO-000 - General GMP IT evidence handling guidance"


def fetch_servicenow_live_incidents(limit=20):
    import json
    import urllib.parse
    import urllib.request
    import base64

    instance, username, password, assignment_group = get_servicenow_live_config()

    query = "active=true^ORDERBYDESCsys_updated_on"

    fields = ",".join([
        "number", "sys_id", "short_description", "description", "state",
        "priority", "impact", "urgency", "assignment_group", "assigned_to",
        "cmdb_ci", "opened_at", "sys_created_on", "sys_updated_on"
    ])

    params = {
        "sysparm_limit": str(limit),
        "sysparm_display_value": "true",
        "sysparm_exclude_reference_link": "true",
        "sysparm_query": query,
        "sysparm_fields": fields
    }

    url = instance + "/api/now/table/incident?" + urllib.parse.urlencode(params)

    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("utf-8")

    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "Authorization": f"Basic {token}"
        }
    )

    with urllib.request.urlopen(req, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))

    incidents = payload.get("result", [])
    cleaned = []

    for item in incidents:
        short_desc = item.get("short_description", "")
        ticket_no = item.get("number", "")
        ci_name = item.get("cmdb_ci", "")
        priority = item.get("priority", "")

        evidence_status = "Evidence Pending"
        governance_status = "Pending AssuranceLayer Evidence Review"
        recommended_kb = recommend_servicenow_live_kb(short_desc)

        cleaned.append({
            "number": ticket_no,
            "sys_id": item.get("sys_id", ""),
            "short_description": short_desc,
            "description": item.get("description", ""),
            "state": item.get("state", ""),
            "priority": priority,
            "impact": item.get("impact", ""),
            "urgency": item.get("urgency", ""),
            "assignment_group": item.get("assignment_group", ""),
            "assigned_to": item.get("assigned_to", ""),
            "cmdb_ci": ci_name,
            "opened_at": item.get("opened_at", ""),
            "sys_created_on": item.get("sys_created_on", ""),
            "sys_updated_on": item.get("sys_updated_on", ""),
            "recommended_kb": recommended_kb,
            "evidence_status": evidence_status,
            "governance_status": governance_status
        })

    return cleaned


@app.route("/api/servicenow/tickets-live")
def api_servicenow_tickets_live():
    # SERVICENOW_LIVE_INTEGRATION_ACTIVE
    import json
    import os

    try:
        tickets = fetch_servicenow_live_incidents(limit=20)
        payload = {
            "source": "ServiceNow PDI Live",
            "instance": os.environ.get("SERVICENOW_INSTANCE", ""),
            "count": len(tickets),
            "tickets": tickets
        }

        return app.response_class(
            json.dumps(payload, indent=2),
            mimetype="application/json"
        )

    except Exception as e:
        payload = {
            "source": "ServiceNow PDI Live",
            "status": "error",
            "message": str(e)
        }

        return app.response_class(
            json.dumps(payload, indent=2),
            status=500,
            mimetype="application/json"
        )


@app.route("/servicenow-tickets-live")
def servicenow_tickets_live_page():
    # SERVICENOW_LIVE_INTEGRATION_ACTIVE
    error = ""
    tickets = []

    try:
        tickets = fetch_servicenow_live_incidents(limit=20)
    except Exception as e:
        error = str(e)

    html = """
<!DOCTYPE html>
<html>
<head>
<title>AssuranceLayer™ ServiceNow Live Tickets</title>
<style>
body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#0f172a}
.hero{background:linear-gradient(135deg,#071527,#1f2937);color:white;padding:38px 44px 50px;border-bottom-left-radius:34px;border-bottom-right-radius:34px}
.container{max-width:1500px;margin:-24px auto 50px;padding:0 26px}
.nav,.card{background:white;border:1px solid #e5e7eb;border-radius:24px;padding:20px;box-shadow:0 12px 30px rgba(15,23,42,.08);margin-bottom:20px}
.nav a{text-decoration:none;color:#0f172a;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 13px;border-radius:999px;font-weight:900;font-size:13px;margin-right:8px;display:inline-block;margin-bottom:7px}
.nav a.active{background:#0f172a;color:white}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
.metric{background:white;border:1px solid #e5e7eb;border-radius:20px;padding:18px;box-shadow:0 10px 24px rgba(15,23,42,.06)}
.metric-label{color:#64748b;font-weight:900;font-size:12px;text-transform:uppercase}
.metric-value{font-size:32px;font-weight:900;margin-top:6px}
.notice{background:#f0fdf4;border-left:7px solid #16a34a;border-radius:16px;padding:14px;margin-bottom:16px}
.error{background:#fee2e2;border-left:7px solid #dc2626;color:#991b1b;border-radius:16px;padding:14px;margin-bottom:16px;font-weight:900}
.warning{background:#fff7ed;border-left:7px solid #f59e0b;border-radius:16px;padding:14px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden;font-size:12px}
th{background:#0f172a;color:white;text-align:left;padding:10px}
td{border-bottom:1px solid #e5e7eb;padding:10px;vertical-align:top;word-break:break-word}
.badge{display:inline-block;padding:6px 9px;border-radius:999px;font-size:11px;font-weight:900}
.warn{background:#fef3c7;color:#92400e}
.risk{background:#fee2e2;color:#991b1b}
.ok{background:#dcfce7;color:#166534}
.action a{display:inline-block;text-decoration:none;background:#0f172a;color:white;padding:8px 10px;border-radius:999px;font-weight:900;font-size:12px;margin-bottom:5px}
@media(max-width:1000px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<section class="hero">
<h1>AssuranceLayer™ ServiceNow Live Ticket Command Center</h1>
<p>Live read-only pull from ServiceNow PDI: ticket → CI → knowledge recommendation → evidence readiness → handoff/governance action.</p>
</section>

<main class="container">
<nav class="nav">
<a href="/">Manufacturing</a>
<a href="/command-center">Command Center</a>
<a href="/monday-demo">Monday Demo</a>
<a class="active" href="/servicenow-tickets-live">ServiceNow Live</a>
<a href="/servicenow-ci-readiness">ServiceNow CI Readiness</a>
<a href="/shift-assurance-enterprise">Shift Enterprise</a>
<a href="/shift-handoff-lineage">Handoff Lineage</a>
<a href="/knowledge-governance">Knowledge Governance</a>
<a href="/knowledge-review">Knowledge Review</a>
</nav>

{% if error %}
<div class="error">
<b>ServiceNow PDI connection issue:</b><br>{{ error }}
<br><br>
Check Azure App Service settings: SERVICENOW_INSTANCE, SERVICENOW_USERNAME, SERVICENOW_PASSWORD, and PDI availability.
</div>
{% else %}
<div class="notice">
<b>Connected to ServiceNow PDI.</b> {{ tickets|length }} active incident ticket(s) imported.
</div>
{% endif %}

<div class="warning">
<b>Enterprise model:</b> ServiceNow owns the ticket and CI. AssuranceLayer™ adds governance readiness, Entra-controlled technician assignment, shift handoff, knowledge recommendation, evidence verification, and audit lineage.
</div>

<section class="grid">
<div class="metric"><div class="metric-label">Imported Tickets</div><div class="metric-value">{{ tickets|length }}</div></div>
<div class="metric"><div class="metric-label">Evidence Pending</div><div class="metric-value" style="color:#f59e0b">{{ tickets|length }}</div></div>
<div class="metric"><div class="metric-label">Knowledge Recommendations</div><div class="metric-value">{{ tickets|length }}</div></div>
<div class="metric"><div class="metric-label">Mode</div><div class="metric-value" style="font-size:22px;color:#16a34a">LIVE PDI</div></div>
</section>

<div class="card">
<h2>Imported ServiceNow PDI Tickets</h2>
{% if tickets %}
<table>
<tr>
<th>Ticket</th>
<th>CI</th>
<th>Description</th>
<th>Priority</th>
<th>State</th>
<th>Assignment Group</th>
<th>Recommended Knowledge</th>
<th>Evidence</th>
<th>Governance</th>
<th>Action</th>
</tr>
{% for t in tickets %}
<tr>
<td><b>{{ t.number }}</b><br>{{ t.opened_at }}</td>
<td>{{ t.cmdb_ci }}</td>
<td><b>{{ t.short_description }}</b><br>{{ t.description }}</td>
<td><span class="badge {% if '1' in t.priority or 'High' in t.priority %}risk{% else %}warn{% endif %}">{{ t.priority }}</span></td>
<td>{{ t.state }}</td>
<td>{{ t.assignment_group }}</td>
<td>{{ t.recommended_kb }}</td>
<td><span class="badge warn">{{ t.evidence_status }}</span></td>
<td>{{ t.governance_status }}</td>
<td class="action">
<a href="/shift-assurance-enterprise">Assign Shift</a><br>
<a href="/shift-handoff-lineage">Create Handoff</a><br>
<a href="/knowledge-governance">Suggest KB</a>
</td>
</tr>
{% endfor %}
</table>
{% else %}
<p>No active ServiceNow tickets returned yet.</p>
{% endif %}
</div>

<div class="card">
<h2>What This Proves</h2>
<p>
This page proves the platform is no longer only using demo-local records. It can read live ServiceNow PDI tickets and prepare them for Entra-controlled shift assignment, CI readiness review, knowledge recommendation, handoff lineage, evidence verification, and governance scoring.
</p>
</div>
</main>
</body>
</html>
    """

    return render_template_string(html, tickets=tickets, error=error)

if __name__ == "__main__":
    app.run(debug=True)
