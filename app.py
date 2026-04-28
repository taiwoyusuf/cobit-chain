from flask import Flask, request, render_template_string, redirect
import os
import io
import hashlib
import datetime
import pandas as pd
from azure.storage.blob import BlobServiceClient

app = Flask(__name__)

# ================================
# CONFIG
# ================================
AZURE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")

if not AZURE_CONNECTION_STRING:
    raise ValueError("AZURE_STORAGE_CONNECTION_STRING not set")

CONTAINER_NAME = "cobitchain-evidence"

blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
container_client = blob_service_client.get_container_client(CONTAINER_NAME)

BASELINE_FILE = "baseline_hashes.csv"
LOG_FILE = "logs.csv"

# ================================
# HASH FUNCTIONS
# ================================
def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def compute_bytes_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

# ================================
# CSV HANDLING
# ================================
def load_csv(filename):
    try:
        data = container_client.get_blob_client(filename).download_blob().readall()
        df = pd.read_csv(io.BytesIO(data), keep_default_na=False)
        return df.fillna("")
    except Exception:
        return pd.DataFrame()

def save_csv(df, filename):
    df = df.fillna("")
    container_client.get_blob_client(filename).upload_blob(
        df.to_csv(index=False),
        overwrite=True
    )

def ensure_columns(df, columns):
    for c in columns:
        if c not in df.columns:
            df[c] = ""
    return df.fillna("")

def clean_value(value):
    if value is None:
        return ""
    value = str(value)
    if value.lower() == "nan":
        return ""
    return value.strip()

# ================================
# EXCEL ANALYTICS
# ================================
def analyze_excel(file_bytes, filename):
    result = {
        "file_type": "Non-Excel",
        "excel_rows": "",
        "excel_columns": "",
        "missing_cells": "",
        "duplicate_rows": "",
        "columns_detected": "",
        "analysis_summary": "No structured Excel analysis performed."
    }

    if not filename.lower().endswith((".xlsx", ".xls")):
        return result

    try:
        df = pd.read_excel(io.BytesIO(file_bytes), engine="openpyxl")
        df.columns = [str(c).strip() for c in df.columns]

        rows = int(df.shape[0])
        cols = int(df.shape[1])
        missing = int(df.isna().sum().sum())
        duplicates = int(df.duplicated().sum())
        columns_detected = ", ".join(df.columns)

        if rows == 0:
            summary = "Excel analyzed. No data rows found."
        elif missing > 0 or duplicates > 0:
            summary = (
                f"Excel analyzed. Rows: {rows}, Columns: {cols}, "
                f"Missing cells: {missing}, Duplicate rows: {duplicates}. "
                "Data quality review recommended."
            )
        else:
            summary = (
                f"Excel analyzed. Rows: {rows}, Columns: {cols}. "
                "No missing cells or duplicate rows detected."
            )

        result = {
            "file_type": "Excel",
            "excel_rows": rows,
            "excel_columns": cols,
            "missing_cells": missing,
            "duplicate_rows": duplicates,
            "columns_detected": columns_detected,
            "analysis_summary": summary
        }

    except Exception as e:
        result = {
            "file_type": "Excel",
            "excel_rows": "",
            "excel_columns": "",
            "missing_cells": "",
            "duplicate_rows": "",
            "columns_detected": "",
            "analysis_summary": f"Excel analysis failed: {str(e)}"
        }

    return result

# ================================
# STATUS LOGIC
# ================================
def get_status(expected, current):
    expected = clean_value(expected)
    current = clean_value(current)

    if not expected:
        return "YELLOW"
    elif expected == current:
        return "GREEN"
    else:
        return "RED"

# ================================
# MAIN ROUTE
# ================================
@app.route("/", methods=["GET", "POST"])
def index():

    baseline_df = load_csv(BASELINE_FILE)
    logs_df = load_csv(LOG_FILE)

    baseline_df = ensure_columns(baseline_df, ["filename", "baseline_hash"])

    logs_df = ensure_columns(logs_df, [
        "filename", "batch_id", "timestamp", "current_hash", "expected_hash", "status",
        "process_stage", "evidence_category", "uploaded_by",
        "signed_by", "approval_status",
        "previous_hash", "record_hash",
        "file_type", "excel_rows", "excel_columns", "missing_cells",
        "duplicate_rows", "columns_detected", "analysis_summary"
    ])

    if request.method == "POST":

        file = request.files.get("file")

        if not file or file.filename == "":
            return redirect("/")

        filename = clean_value(file.filename)

        batch_id = clean_value(request.form.get("batch_id", ""))
        stage = clean_value(request.form.get("process_stage", ""))
        category = clean_value(request.form.get("evidence_category", ""))
        user = clean_value(request.form.get("uploaded_by", ""))
        signed_by = clean_value(request.form.get("signed_by", ""))
        approval = clean_value(request.form.get("approval_status", ""))

        file_bytes = file.read()
        file_hash = compute_bytes_hash(file_bytes)
        timestamp = datetime.datetime.utcnow().isoformat()

        excel_analysis = analyze_excel(file_bytes, filename)

        existing = baseline_df[baseline_df["filename"] == filename]

        if existing.empty:
            expected_hash = ""
            status = "YELLOW"

            baseline_df = pd.concat([baseline_df, pd.DataFrame([{
                "filename": filename,
                "baseline_hash": file_hash
            }])], ignore_index=True)

            save_csv(baseline_df, BASELINE_FILE)

        else:
            expected_hash = clean_value(existing.iloc[0]["baseline_hash"])
            status = get_status(expected_hash, file_hash)

        if logs_df.empty or logs_df["record_hash"].dropna().astype(str).str.strip().eq("").all():
            previous_hash = "GENESIS"
        else:
            previous_hash = clean_value(logs_df.iloc[-1]["record_hash"])

        record_string = (
            str(filename) +
            str(batch_id) +
            str(file_hash) +
            str(previous_hash) +
            str(timestamp)
        )

        record_hash = sha256_text(record_string)

        new_log = pd.DataFrame([{
            "filename": filename,
            "batch_id": batch_id,
            "timestamp": timestamp,
            "current_hash": file_hash,
            "expected_hash": expected_hash,
            "status": status,
            "process_stage": stage,
            "evidence_category": category,
            "uploaded_by": user,
            "signed_by": signed_by,
            "approval_status": approval,
            "previous_hash": previous_hash,
            "record_hash": record_hash,
            "file_type": excel_analysis["file_type"],
            "excel_rows": excel_analysis["excel_rows"],
            "excel_columns": excel_analysis["excel_columns"],
            "missing_cells": excel_analysis["missing_cells"],
            "duplicate_rows": excel_analysis["duplicate_rows"],
            "columns_detected": excel_analysis["columns_detected"],
            "analysis_summary": excel_analysis["analysis_summary"]
        }])

        logs_df = pd.concat([logs_df, new_log], ignore_index=True)
        logs_df = logs_df.fillna("")
        save_csv(logs_df, LOG_FILE)

        return redirect("/")

    # ================================
    # CLEAN DISPLAY VALUES
    # ================================
    logs_df = logs_df.fillna("")
    for col in logs_df.columns:
        logs_df[col] = logs_df[col].astype(str).replace("nan", "")

    # ================================
    # BATCH / CHAIN SUMMARY
    # ================================
    chains = []

    if not logs_df.empty:
        for batch, group in logs_df.groupby("batch_id", dropna=False):

            batch_name = clean_value(batch) if clean_value(batch) else "NO-BATCH-ID"

            total = len(group)
            green = len(group[group["status"] == "GREEN"])
            red = len(group[group["status"] == "RED"])
            yellow = len(group[group["status"] == "YELLOW"])

            if red > 0:
                batch_status = "RED"
            elif yellow > 0:
                batch_status = "YELLOW"
            else:
                batch_status = "GREEN"

            integrity = round((green / total) * 100, 2) if total else 0

            chains.append({
                "batch": batch_name,
                "status": batch_status,
                "integrity": integrity,
                "total": total,
                "green": green,
                "yellow": yellow,
                "red": red,
                "records": group.tail(10).to_dict(orient="records")
            })

    # ================================
    # UI
    # ================================
    html = """
    <html>
    <head>
    <title>COBIT-Chain™ Evidence Integrity System</title>
    <style>
    body {
        font-family: Arial, sans-serif;
        margin: 40px;
        background: #f5f7fb;
    }
    h1, h2 {
        color: #111827;
    }
    p {
        color: #374151;
    }
    .form-box {
        background: white;
        padding: 20px;
        border-radius: 12px;
        margin-bottom: 25px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    }
    input, select, button {
        width: 100%;
        padding: 10px;
        margin-top: 8px;
        margin-bottom: 8px;
        box-sizing: border-box;
    }
    button {
        background: #1f6feb;
        color: white;
        border: none;
        border-radius: 8px;
        cursor: pointer;
        font-weight: bold;
    }
    .batch {
        margin-top: 20px;
        padding: 15px;
        border-radius: 10px;
    }
    .GREEN {
        background: #2ecc71;
        color: white;
    }
    .YELLOW {
        background: #f1c40f;
        color: black;
    }
    .RED {
        background: #e74c3c;
        color: white;
    }
    table {
        width: 100%;
        margin-top: 10px;
        border-collapse: collapse;
        background: white;
        color: #111827;
    }
    th, td {
        padding: 8px;
        border: 1px solid #ddd;
        font-size: 13px;
        vertical-align: top;
    }
    th {
        background: black;
        color: white;
    }
    .bad {
        background: #ffdddd;
    }
    .warn {
        background: #fff5cc;
    }
    .good {
        background: #ddffdd;
    }
    .small {
        font-size: 12px;
        color: #374151;
    }
    .meta {
        font-size: 13px;
        margin-top: 5px;
    }
    </style>
    </head>

    <body>

    <h1>COBIT-Chain™ Evidence Integrity System</h1>
    <p>
        Upload operational evidence, generate cryptographic hash, compare against baseline,
        detect tampering, analyze Excel data, and build an audit-ready chain.
    </p>

    <div class="form-box">
    <form method="POST" enctype="multipart/form-data">

    <input type="file" name="file" required>

    <input type="text" name="batch_id" placeholder="Batch ID e.g. WOLE-BATCH-001" required>

    <input type="text" name="process_stage" placeholder="Process Stage e.g. Weighbridge / Dispatch / Invoice">

    <input type="text" name="evidence_category" placeholder="Evidence Category e.g. Operational / Financial / QA">

    <input type="text" name="uploaded_by" placeholder="Uploaded By">

    <input type="text" name="signed_by" placeholder="Signed By (QA / IT / Auditor)">

    <select name="approval_status">
        <option value="">Approval Status</option>
        <option value="Approved">Approved</option>
        <option value="Pending">Pending</option>
        <option value="Rejected">Rejected</option>
    </select>

    <button type="submit">Upload and Verify</button>
    </form>
    </div>

    <h2>Batch Chain Summary</h2>

    {% for b in chains %}
        <div class="batch {{b.status}}">
            <h3>{{b.batch}} → {{b.status}}</h3>

            <div class="meta">
                <b>Integrity:</b> {{b.integrity}}% |
                <b>Total:</b> {{b.total}} |
                <b>Green:</b> {{b.green}} |
                <b>Yellow:</b> {{b.yellow}} |
                <b>Red:</b> {{b.red}}
            </div>

            <table>
            <tr>
                <th>Stage</th>
                <th>File</th>
                <th>Status</th>
                <th>Category</th>
                <th>Uploaded By</th>
                <th>Signed By</th>
                <th>Approval</th>
                <th>Excel Rows</th>
                <th>Excel Columns</th>
                <th>Missing Cells</th>
                <th>Duplicates</th>
                <th>Columns Detected</th>
                <th>Analysis</th>
            </tr>

            {% for r in b.records %}
            <tr class="{% if r.status == 'RED' %}bad{% elif r.status == 'YELLOW' %}warn{% else %}good{% endif %}">
                <td>{{r.process_stage}}</td>
                <td>{{r.filename}}</td>
                <td>{{r.status}}</td>
                <td>{{r.evidence_category}}</td>
                <td>{{r.uploaded_by}}</td>
                <td>{{r.signed_by}}</td>
                <td>{{r.approval_status}}</td>
                <td>{{r.excel_rows}}</td>
                <td>{{r.excel_columns}}</td>
                <td>{{r.missing_cells}}</td>
                <td>{{r.duplicate_rows}}</td>
                <td class="small">{{r.columns_detected}}</td>
                <td class="small">{{r.analysis_summary}}</td>
            </tr>
            {% endfor %}
            </table>
        </div>
    {% endfor %}

    </body>
    </html>
    """

    return render_template_string(html, chains=chains)

if __name__ == "__main__":
    app.run(debug=True)
