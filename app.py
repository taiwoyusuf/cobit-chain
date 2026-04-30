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
        "open_exceptions": []
    }

    if logs.empty:
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

    return metrics


@app.route("/manufacturing")
def manufacturing_alias():
    return redirect("/")


@app.route("/executive-overview")
def executive_overview_page():
    metrics = get_enterprise_overview_metrics()
    page = get_enterprise_page("/executive-overview")
    return render_enterprise_shell_page(page, metrics=metrics)


@app.route("/sop-governance")
def sop_governance_page():
    page = get_enterprise_page("/sop-governance")
    return render_enterprise_shell_page(page)


@app.route("/shift-assurance")
def shift_assurance_page():
    page = get_enterprise_page("/shift-assurance")
    return render_enterprise_shell_page(page)


@app.route("/access-governance")
def access_governance_page():
    page = get_enterprise_page("/access-governance")
    return render_enterprise_shell_page(page)


@app.route("/audit-capa")
def audit_capa_page():
    page = get_enterprise_page("/audit-capa")
    return render_enterprise_shell_page(page)


@app.route("/clinical-trial-integrity")
def clinical_trial_integrity_page():
    page = get_enterprise_page("/clinical-trial-integrity")
    return render_enterprise_shell_page(page)


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
            <div class="card">
                <h2>Audit Readiness Summary</h2>
                <section class="grid">
                    <div class="metric"><div class="metric-label">Audit Ready</div><div class="metric-value" style="color:#16a34a">{{ metrics.audit_ready }}</div><div class="metric-sub">Batches ready</div></div>
                    <div class="metric"><div class="metric-label">Conditional</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional }}</div><div class="metric-sub">Need follow-up</div></div>
                    <div class="metric"><div class="metric-label">Not Ready</div><div class="metric-value" style="color:#dc2626">{{ metrics.not_ready }}</div><div class="metric-sub">Critical issues</div></div>
                    <div class="metric"><div class="metric-label">Yellow Records</div><div class="metric-value" style="color:#f59e0b">{{ metrics.yellow_total }}</div><div class="metric-sub">Baseline or review gaps</div></div>
                </section>

                <h3>Open Exceptions</h3>
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
            <div class="note">
                <b>Shift Assurance design direction:</b> this page will later connect ServiceNow ticket exports,
                equipment status, technician ownership, handoff notes, unresolved risks, and day/night carryover logic.
            </div>
            {% elif page.route == "/sop-governance" %}
            <div class="note">
                <b>SOP Governance design direction:</b> this page will later connect SOP_Gap, SOP_Summary,
                procedure review triggers, and SOP-to-reality exception scoring.
            </div>
            {% elif page.route == "/access-governance" %}
            <div class="note">
                <b>Access Governance design direction:</b> this page will later connect myAccess exports,
                binder evidence, user access review logs, and entitlement approval evidence.
            </div>
            {% elif page.route == "/audit-capa" %}
            <div class="note">
                <b>Audit/CAPA design direction:</b> this page will later connect audit observations,
                deviation records, CAPA evidence, remediation proof, and effectiveness-check readiness.
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

if __name__ == "__main__":
    app.run(debug=True)
