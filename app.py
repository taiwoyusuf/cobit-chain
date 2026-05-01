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
# These pages are added beside the existing Manufacturing/Wole
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
        "purpose": "Preserved Wole manufacturing assurance dashboard with evidence upload, hashing, verification, Excel analytics, process-chain validation, and audit report download.",
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
            {"module": "Manufacturing", "status": "LIVE", "maturity": "Wole evidence hashing and audit logic active"},
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
                <b>Safe enterprise expansion:</b> This page was added beside the existing Manufacturing/Wole dashboard.
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
                <p>This page is currently a controlled enterprise module shell. It does not change the Manufacturing/Wole dashboard or write to the existing manufacturing evidence logs.</p>
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
                <b>shift_handoffs.csv</b>. That will allow this page to save real day/night shift records without touching the current Wole manufacturing evidence chain.
            </div>
            {% elif page.route == "/sop-governance" %}
            <!-- SOP_GOVERNANCE_V1_ACTIVE -->
            <div class="card status-card-warning">
                <h2>⚠ SOP Governance v1</h2>
                <p><b>Purpose:</b> create a controlled governance view for SOP-to-reality alignment, process drift, SOP gaps, review triggers, and audit-ready recommendations.</p>
                <p>This page is currently a controlled enterprise module shell. It does not change the Manufacturing/Wole dashboard or write to the existing manufacturing evidence logs.</p>
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
                    <p>Future linkage point for SOP gap files, SOP summaries, control mappings, exception narratives, and recommendation outputs.</p>
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
                This will allow SOP Governance to save real SOP mismatch evidence without touching the Manufacturing/Wole evidence chain.
            </div>
            {% elif page.route == "/access-governance" %}
            <!-- ACCESS_GOVERNANCE_V1_ACTIVE -->
            <div class="card status-card-warning">
                <h2>⚠ Access Governance v1</h2>
                <p><b>Purpose:</b> provide a controlled governance view for myAccess, access review evidence, binder-to-digital reconciliation, entitlement approval, and quarterly certification readiness.</p>
                <p>This page is currently a controlled enterprise module shell. It does not write to the existing Manufacturing/Wole evidence logs and does not change the homepage dashboard.</p>
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
                This will allow Access Governance to save real review evidence without touching the Manufacturing/Wole evidence chain.
            </div>
            {% elif page.route == "/audit-capa" %}
            <!-- AUDIT_CAPA_V1_ACTIVE -->
            <div class="card status-card-warning">
                <h2>⚠ Audit/CAPA v1</h2>
                <p><b>Purpose:</b> create a governed evidence chain from audit finding to deviation, CAPA, remediation proof, and effectiveness-check readiness.</p>
                <p>This page is currently a controlled enterprise module shell. It does not change the Manufacturing/Wole dashboard, SOP comparison engine, or existing evidence logs.</p>
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
                remediation proof, and effectiveness readiness scoring. This will keep Audit/CAPA records separate from Manufacturing/Wole logs.
            </div>
            {% elif page.route == "/clinical-trial-integrity" %}
            <!-- CLINICAL_TRIAL_INTEGRITY_V1_ACTIVE -->
            <div class="card status-card-warning">
                <h2>⚠ Clinical Trial Integrity v1</h2>
                <p><b>Purpose:</b> create a governance assurance layer for clinical trial evidence integrity, protocol-to-evidence traceability, ALCOA+ readiness, deviation linkage, and inspection preparedness.</p>
                <p>This page is currently a controlled enterprise module shell. It does not change Manufacturing/Wole, SOP comparison, Access, Shift, or Audit/CAPA records.</p>
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
                        <span>Identify required study activity, visit, consent step, data capture point, safety review, or monitoring obligation.</span>
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
                evidence artifacts, ALCOA+ readiness, deviation linkage, and inspection-readiness scoring. This will keep clinical records separate from Manufacturing/Wole logs.
            </div>
            {% endif %}

            <div class="card">
                <h2>Current Manufacturing Dashboard</h2>
                <p>The existing Wole Manufacturing Assurance dashboard remains available here:</p>
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
            "error": "Please upload both the Lilly/GPOS SOP and the Point/Local SOP."
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
                "gap_type": "Lilly/GPOS control missing in Point SOP",
                "theme": theme["theme"],
                "category": theme["category"],
                "risk": theme["risk"],
                "evidence": "Control theme appears in the mature/global SOP but is missing from the local/manual SOP.",
                "cobit": theme["cobit"],
                "recommendation": "Adopt or harmonize the Lilly/GPOS control into the Point/local SOP. " + theme["recommendation"]
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
                "gap_type": "Local-specific control not visible in Lilly/GPOS SOP",
                "theme": theme["theme"],
                "category": theme["category"],
                "risk": "MEDIUM",
                "evidence": "Point/local SOP includes a control theme that is not detected in the Lilly/GPOS SOP.",
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
            "theme": "Manual Point process vs mature Lilly system-enabled process",
            "category": "Technology maturity",
            "risk": "HIGH",
            "evidence": "Lilly/GPOS appears to reference system-enabled or digital control, while Point/local SOP appears to rely on manual, paper, Excel, or binder-based execution.",
            "cobit": "BAI06, DSS06, MEA02, APO12",
            "recommendation": "Assess whether Point should adopt the Lilly system-enabled process, retain local process with compensating controls, or follow a phased harmonization plan."
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
    if "acquisition" in combined_lower or "acquired" in combined_lower or "harmonization" in combined_lower or "lilly" in combined_lower or "point" in combined_lower or "gpos" in combined_lower:
        review_triggers.append("M&A / harmonization-triggered SOP review")
    if "new product" in combined_lower or "expansion" in combined_lower or "business expansion" in combined_lower:
        review_triggers.append("Business expansion or new product-triggered SOP review")

    if not review_triggers and gaps:
        review_triggers.append("Governance gap-triggered SOP review")
    if not review_triggers:
        review_triggers.append("No major SOP review trigger detected from current comparison.")

    if high_risk_count >= 3 or technology_gap_count > 0:
        recommended_decision = "Adopt Lilly/GPOS target-state controls or create a phased harmonization plan with QA/SOP owner review."
    elif outdated_count > 0:
        recommended_decision = "Update Point/local SOP to reflect validated operational reality, or correct the process if the reality is noncompliant."
    elif gaps:
        recommended_decision = "Review identified gaps and decide whether to harmonize, retain local controls, or document compensating controls."
    else:
        recommended_decision = "No major gap detected. Retain as aligned, but document reviewer decision and comparison evidence."

    pain_point_solutions = [
        {
            "pain_point": "Manual SOP comparison takes too long after acquisition.",
            "solution": "COBIT-Chain creates a structured gap table between Lilly/GPOS and Point/local SOPs."
        },
        {
            "pain_point": "Teams cannot tell whether the SOP is wrong or the process is wrong.",
            "solution": "The SOP Obsolescence Signal separates outdated documentation from actual process noncompliance."
        },
        {
            "pain_point": "Mature global process and local manual process are hard to reconcile.",
            "solution": "Technology Maturity Gap logic highlights where Point manual controls differ from Lilly system-enabled controls."
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
                    <label><b>Lilly / GPOS / Mature SOP</b></label>
                    <input type="file" name="global_sop" required>

                    <label><b>Point / Local / Legacy SOP</b></label>
                    <input type="file" name="local_sop" required>

                    <input name="process_area" placeholder="Process Area e.g. User Access Review / Equipment Handoff">
                    <input name="reviewer" placeholder="Reviewer e.g. Sree / Taiwo">
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
                <b>Advanced SOP feature:</b> this page compares Lilly/GPOS against Point/local SOPs, identifies control gaps,
                detects outdated SOP signals, highlights technology maturity differences, maps findings to COBIT, and creates
                a harmonization recommendation.
            </div>

            <section class="sop-grid">
                <div class="sop-card">
                    <div class="sop-label">M&A Pain Point</div>
                    <h3>Lilly + Point Harmonization</h3>
                    <p>Supports acquisition scenarios where a mature global process must be compared against a local manual process.</p>
                    <span class="sop-badge">SOP harmonization</span>
                </div>
                <div class="sop-card">
                    <div class="sop-label">Wole Insight</div>
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
                    <h2>Lilly / GPOS Control DNA</h2>
                    <p><b>Score:</b> {{ result.control_dna.global_score }}%</p>
                    <p><b>File:</b> {{ result.global_filename }}</p>
                    <p><b>Covered Controls:</b></p>
                    {% for c in result.control_dna.global_covered %}
                        <span class="tag">{{ c }}</span>
                    {% endfor %}
                </div>

                <div class="dna-box">
                    <h2>Point / Local Control DNA</h2>
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
                        <th>Pain Point</th>
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
                This does not touch Manufacturing/Wole <b>logs.csv</b> or <b>baseline_hashes.csv</b>.
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
        The Manufacturing/Wole dashboard, SOP comparison engine, Access, Shift, and Audit/CAPA modules remain untouched.
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
            <div class="trial-label">Trial Pain Point</div>
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
        This must stay separate from Manufacturing/Wole <b>logs.csv</b> and <b>baseline_hashes.csv</b>.
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
Manufacturing/Wole evidence chain protected.
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
<b>Main Radiopharma Commercial Focus:</b> RLT-Trust™ is the primary COBIT-Chain module for Lilly/Point/Novartis-style radiopharmaceutical operations, where dose timing, decay window, QA release, radiation survey, chain-of-custody, site receipt, and patient administration readiness matter.
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

<input name="receiving_site" placeholder="Receiving Site e.g. Novartis Indy / Treatment Site" required>

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
<b>Do not use DSCSA TrustChain™ as the main radiopharma/RLT dose-readiness module. RLT-Trust™ remains the flagship for Lilly/Point/Novartis-style radiopharma governance.</b>
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

if __name__ == "__main__":
    app.run(debug=True)
