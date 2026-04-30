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
    metrics = get_enterprise_overview_metrics()
    page = get_enterprise_page("/executive-overview")
    return render_enterprise_shell_page(page, metrics=metrics)


@app.route("/sop-governance", methods=["GET", "POST"])
def sop_governance_page():
    page = get_enterprise_page("/sop-governance")

    if request.method == "POST":
        result = run_sop_comparison(request)
        if not result.get("error"):
            save_sop_comparison_result(result)
        return render_sop_governance_v2(page, result=result)

    return render_sop_governance_v2(page)



@app.route("/shift-assurance", methods=["GET", "POST"])
def shift_assurance_page():
    page = get_enterprise_page("/shift-assurance")

    if request.method == "POST":
        result = save_shift_handoff(request)
        return render_shift_assurance_v2(page, result=result)

    return render_shift_assurance_v2(page)


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
    return render_clinical_trial_integrity_v2(page)


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
# SHIFT ASSURANCE V2 ACTIVE
# Functional Shift Handoff Register
# ============================================================

SHIFT_HANDOFF_FILE = "shift_handoffs.csv"


def prepare_shift_handoffs():
    df = load_csv(SHIFT_HANDOFF_FILE)
    return ensure_cols(df, [
        "handoff_id",
        "timestamp",
        "shift_date",
        "shift_type",
        "equipment_id",
        "equipment_name",
        "equipment_status",
        "servicenow_ticket",
        "ticket_priority",
        "outgoing_technician",
        "incoming_technician",
        "open_issue",
        "next_action",
        "escalation_required",
        "qa_engineering_followup",
        "readiness_status",
        "readiness_score",
        "risk_level",
        "previous_hash",
        "record_hash"
    ])


def calculate_shift_readiness(equipment_status, servicenow_ticket, open_issue, next_action, escalation_required, qa_engineering_followup, outgoing_technician, incoming_technician):
    score = 100
    risk_signals = []

    equipment_status = clean(equipment_status)
    servicenow_ticket = clean(servicenow_ticket)
    open_issue = clean(open_issue)
    next_action = clean(next_action)
    escalation_required = clean(escalation_required)
    qa_engineering_followup = clean(qa_engineering_followup)
    outgoing_technician = clean(outgoing_technician)
    incoming_technician = clean(incoming_technician)

    if equipment_status in ["Out of Service", "Under Maintenance"]:
        score -= 35
        risk_signals.append("Equipment is not fully available.")

    if equipment_status == "Degraded":
        score -= 20
        risk_signals.append("Equipment is degraded and requires monitoring.")

    if open_issue and not next_action:
        score -= 20
        risk_signals.append("Open issue exists with no next action.")

    if open_issue and not servicenow_ticket:
        score -= 15
        risk_signals.append("Open issue exists without ServiceNow ticket reference.")

    if escalation_required == "Yes" and qa_engineering_followup == "No":
        score -= 20
        risk_signals.append("Escalation required but QA/Engineering follow-up not marked.")

    if not outgoing_technician or not incoming_technician:
        score -= 15
        risk_signals.append("Outgoing or incoming technician is missing.")

    if outgoing_technician and incoming_technician and outgoing_technician.lower() == incoming_technician.lower():
        score -= 10
        risk_signals.append("Outgoing and incoming technician are the same person; verify handoff accountability.")

    if score < 0:
        score = 0

    if score >= 85:
        readiness_status = "READY"
        risk_level = "LOW"
    elif score >= 60:
        readiness_status = "CONDITIONALLY READY"
        risk_level = "MEDIUM"
    else:
        readiness_status = "NOT READY"
        risk_level = "HIGH"

    if not risk_signals:
        risk_signals.append("No major shift handoff risk detected.")

    return {
        "score": score,
        "readiness_status": readiness_status,
        "risk_level": risk_level,
        "risk_signals": risk_signals
    }


def save_shift_handoff(req):
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
    escalation_required = clean(req.form.get("escalation_required"))
    qa_engineering_followup = clean(req.form.get("qa_engineering_followup"))

    if not shift_date or not shift_type or not equipment_id or not equipment_name or not equipment_status:
        return {
            "error": "Shift Date, Shift Type, Equipment ID, Equipment Name, and Equipment Status are required."
        }

    if not outgoing_technician or not incoming_technician:
        return {
            "error": "Outgoing Technician and Incoming Technician are required."
        }

    readiness = calculate_shift_readiness(
        equipment_status,
        servicenow_ticket,
        open_issue,
        next_action,
        escalation_required,
        qa_engineering_followup,
        outgoing_technician,
        incoming_technician
    )

    timestamp = datetime.datetime.utcnow().isoformat()
    handoff_id = "SHIFT-" + datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")

    previous_hash = "GENESIS"
    if not df.empty and "record_hash" in df.columns:
        previous_hash = clean(df.iloc[-1].get("record_hash")) or "GENESIS"

    record_basis = (
        handoff_id +
        timestamp +
        shift_date +
        shift_type +
        equipment_id +
        equipment_name +
        equipment_status +
        servicenow_ticket +
        outgoing_technician +
        incoming_technician +
        previous_hash
    )

    record_hash = sha256_text(record_basis)

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
        "readiness_status": readiness["readiness_status"],
        "readiness_score": readiness["score"],
        "risk_level": readiness["risk_level"],
        "previous_hash": previous_hash,
        "record_hash": record_hash
    }])

    df = pd.concat([df, row], ignore_index=True)
    save_csv(df, SHIFT_HANDOFF_FILE)

    return {
        "error": "",
        "handoff_id": handoff_id,
        "readiness_status": readiness["readiness_status"],
        "readiness_score": readiness["score"],
        "risk_level": readiness["risk_level"],
        "risk_signals": readiness["risk_signals"]
    }


def get_shift_dashboard_metrics():
    df = prepare_shift_handoffs()

    metrics = {
        "total_handoffs": 0,
        "ready": 0,
        "conditional": 0,
        "not_ready": 0,
        "high_risk": 0,
        "recent": []
    }

    if df.empty:
        return metrics

    df = df.fillna("")
    metrics["total_handoffs"] = len(df)
    metrics["ready"] = len(df[df["readiness_status"] == "READY"])
    metrics["conditional"] = len(df[df["readiness_status"] == "CONDITIONALLY READY"])
    metrics["not_ready"] = len(df[df["readiness_status"] == "NOT READY"])
    metrics["high_risk"] = len(df[df["risk_level"] == "HIGH"])
    metrics["recent"] = df.tail(15).to_dict("records")

    return metrics


def render_shift_assurance_v2(page, result=None):
    metrics = get_shift_dashboard_metrics()

    html = """
<!DOCTYPE html>
<html>
<head>
<title>COBIT-Chain™ Shift Assurance</title>
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
.main-layout { display:grid; grid-template-columns:390px 1fr; gap:22px; align-items:start; }
.panel, .card {
    background:white; border:1px solid #e5e7eb; border-radius:24px;
    padding:22px; box-shadow:0 14px 35px rgba(15,23,42,.08);
    margin-bottom:20px;
}
input, select, textarea, button {
    width:100%; border-radius:14px; border:1px solid #dbe3ef;
    padding:12px 13px; margin:7px 0; font-size:14px; background:white;
}
textarea { min-height:100px; resize:vertical; }
button {
    border:none; background:linear-gradient(135deg,#2563eb,#06b6d4);
    color:white; font-weight:900; cursor:pointer;
}
.notice {
    background:#f0fdf4; border-left:7px solid #16a34a; border-radius:18px;
    padding:17px; line-height:1.55; margin-bottom:20px;
}
.error {
    background:#fee2e2; border-left:7px solid #dc2626; color:#991b1b;
    border-radius:18px; padding:17px; font-weight:900; margin-bottom:20px;
}
.warning {
    background:#fff7ed; border-left:7px solid #f59e0b; border-radius:18px;
    padding:17px; line-height:1.55; margin-bottom:20px;
}
.metric {
    background:rgba(255,255,255,.96); border:1px solid rgba(226,232,240,.9);
    border-radius:22px; padding:22px; box-shadow:0 12px 32px rgba(15,23,42,.08);
}
.metric-label { color:#64748b; font-weight:800; font-size:13px; text-transform:uppercase; letter-spacing:.08em; }
.metric-value { margin-top:8px; font-size:34px; font-weight:900; }
.metric-sub { color:#64748b; font-size:13px; }
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
.status-READY { color:#16a34a; font-weight:900; }
.status-CONDITIONALLY { color:#d97706; font-weight:900; }
.status-NOT { color:#dc2626; font-weight:900; }
@media(max-width:1000px){ .grid,.main-layout{ grid-template-columns:1fr; } }
</style>
</head>

<body>
<section class="hero">
    <div class="hero-top">
        <div class="brand">
            <div class="logo">CC</div>
            <div>
                <h1>COBIT-Chain™</h1>
                <p>Shift Assurance • Equipment Handoff • ServiceNow Carryover</p>
            </div>
        </div>
        <div class="badge">Shift Assurance v2</div>
    </div>
</section>

<main class="container">
    <nav class="nav">
        {% for p in pages %}
            <a class="{% if p.route == '/shift-assurance' %}active{% endif %}" href="{{ p.route }}">{{ p.title }}</a>
        {% endfor %}
    </nav>

    {% if result and result.error %}
        <div class="error">{{ result.error }}</div>
    {% elif result %}
        <div class="notice">
            <b>Shift handoff saved:</b> {{ result.handoff_id }} —
            <b>{{ result.readiness_status }}</b> with readiness score <b>{{ result.readiness_score }}%</b>.
            <ul>
            {% for signal in result.risk_signals %}
                <li>{{ signal }}</li>
            {% endfor %}
            </ul>
        </div>
    {% endif %}

    <section class="grid">
        <div class="metric"><div class="metric-label">Total Handoffs</div><div class="metric-value">{{ metrics.total_handoffs }}</div><div class="metric-sub">Saved shift records</div></div>
        <div class="metric"><div class="metric-label">Ready</div><div class="metric-value" style="color:#16a34a">{{ metrics.ready }}</div><div class="metric-sub">Clean handoffs</div></div>
        <div class="metric"><div class="metric-label">Conditional</div><div class="metric-value" style="color:#f59e0b">{{ metrics.conditional }}</div><div class="metric-sub">Needs follow-up</div></div>
        <div class="metric"><div class="metric-label">High Risk</div><div class="metric-value" style="color:#dc2626">{{ metrics.high_risk }}</div><div class="metric-sub">Critical carryover risk</div></div>
    </section>

    <section class="main-layout">
        <aside>
            <div class="panel">
                <h2>Create Shift Handoff</h2>
                <form method="POST" action="/shift-assurance">
                    <label><b>Shift Date</b></label>
                    <input type="date" name="shift_date" required>

                    <label><b>Shift Type</b></label>
                    <select name="shift_type" required>
                        <option value="">Select Shift</option>
                        <option value="Day Shift">Day Shift</option>
                        <option value="Night Shift">Night Shift</option>
                    </select>

                    <input name="equipment_id" placeholder="Equipment ID e.g. EQP-1803" required>
                    <input name="equipment_name" placeholder="Equipment Name e.g. Speedy Glove Isolator" required>

                    <label><b>Equipment Status</b></label>
                    <select name="equipment_status" required>
                        <option value="">Select Status</option>
                        <option value="Available">Available</option>
                        <option value="Degraded">Degraded</option>
                        <option value="Under Maintenance">Under Maintenance</option>
                        <option value="Out of Service">Out of Service</option>
                        <option value="Pending QA/Engineering Review">Pending QA/Engineering Review</option>
                    </select>

                    <input name="servicenow_ticket" placeholder="ServiceNow Ticket e.g. INC123456 / MWO-003753-2026">

                    <label><b>Ticket Priority</b></label>
                    <select name="ticket_priority">
                        <option value="">Select Priority</option>
                        <option value="Low">Low</option>
                        <option value="Medium">Medium</option>
                        <option value="High">High</option>
                        <option value="Critical">Critical</option>
                    </select>

                    <input name="outgoing_technician" placeholder="Outgoing Technician" required>
                    <input name="incoming_technician" placeholder="Incoming Technician" required>

                    <textarea name="open_issue" placeholder="Open Issue / Risk"></textarea>
                    <textarea name="next_action" placeholder="Next Action / Carryover Instruction"></textarea>

                    <label><b>Escalation Required?</b></label>
                    <select name="escalation_required">
                        <option value="No">No</option>
                        <option value="Yes">Yes</option>
                    </select>

                    <label><b>QA / Engineering Follow-up Required?</b></label>
                    <select name="qa_engineering_followup">
                        <option value="No">No</option>
                        <option value="Yes">Yes</option>
                    </select>

                    <button type="submit">Save Shift Handoff</button>
                </form>
            </div>
        </aside>

        <section>
            <div class="warning">
                <b>Storage design:</b> Shift handoffs are saved in <b>shift_handoffs.csv</b>.
                This does not touch Manufacturing/Wole <b>logs.csv</b> or <b>baseline_hashes.csv</b>.
            </div>

            <div class="card">
                <h2>Recent Shift Handoffs</h2>
                {% if metrics.recent %}
                <table class="exec-table">
                    <tr>
                        <th>ID</th>
                        <th>Date</th>
                        <th>Shift</th>
                        <th>Equipment</th>
                        <th>Status</th>
                        <th>Ticket</th>
                        <th>Incoming</th>
                        <th>Readiness</th>
                        <th>Risk</th>
                    </tr>
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
            </div>

            <div class="card">
                <h2>Governance Logic</h2>
                <table class="exec-table">
                    <tr>
                        <th>Condition</th>
                        <th>Impact</th>
                    </tr>
                    <tr>
                        <td>Equipment out of service or under maintenance</td>
                        <td>Reduces readiness score and may create high-risk carryover.</td>
                    </tr>
                    <tr>
                        <td>Open issue with no ServiceNow ticket</td>
                        <td>Flags missing system-of-record linkage.</td>
                    </tr>
                    <tr>
                        <td>Open issue with no next action</td>
                        <td>Flags weak handoff accountability.</td>
                    </tr>
                    <tr>
                        <td>Escalation required but QA/Engineering follow-up missing</td>
                        <td>Flags governance escalation weakness.</td>
                    </tr>
                    <tr>
                        <td>Outgoing and incoming technicians completed</td>
                        <td>Supports chain-of-custody and shift accountability.</td>
                    </tr>
                </table>
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
        metrics=metrics,
        result=result
    )

if __name__ == "__main__":
    app.run(debug=True)
