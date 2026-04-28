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
# HELPERS
# ================================
def clean(val):
    if val is None:
        return ""
    val = str(val)
    return "" if val.lower() == "nan" else val.strip()

def sha256_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

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
    except:
        return pd.DataFrame()

def save_csv(df, filename):
    df = df.fillna("")
    container_client.get_blob_client(filename).upload_blob(
        df.to_csv(index=False),
        overwrite=True
    )

def ensure_columns(df, cols):
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    return df.fillna("")

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
        "analysis_summary": ""
    }

    if not filename.lower().endswith((".xlsx", ".xls")):
        return result

    try:
        df = pd.read_excel(io.BytesIO(file_bytes), engine="openpyxl")

        rows = len(df)
        cols = len(df.columns)
        missing = int(df.isna().sum().sum())
        duplicates = int(df.duplicated().sum())

        result.update({
            "file_type": "Excel",
            "excel_rows": rows,
            "excel_columns": cols,
            "missing_cells": missing,
            "duplicate_rows": duplicates,
            "columns_detected": ", ".join(df.columns),
            "analysis_summary": f"{rows} rows | {cols} cols | {missing} missing | {duplicates} duplicates"
        })

    except Exception as e:
        result["analysis_summary"] = f"Excel error: {str(e)}"

    return result

# ================================
# STATUS
# ================================
def get_status(expected, current):
    if not expected:
        return "YELLOW"
    elif expected == current:
        return "GREEN"
    else:
        return "RED"

# ================================
# MAIN
# ================================
@app.route("/", methods=["GET", "POST"])
def index():

    baseline_df = load_csv(BASELINE_FILE)
    logs_df = load_csv(LOG_FILE)

    baseline_df = ensure_columns(baseline_df, ["filename", "baseline_hash"])

    logs_df = ensure_columns(logs_df, [
        "filename","batch_id","timestamp","current_hash","expected_hash","status",
        "process_stage","evidence_category","uploaded_by",
        "signed_by","approval_status",
        "previous_hash","record_hash",
        "file_type","excel_rows","excel_columns",
        "missing_cells","duplicate_rows",
        "columns_detected","analysis_summary"
    ])

    error_msg = ""

    if request.method == "POST":

        file = request.files.get("file")

        filename = clean(file.filename)
        batch_id = clean(request.form.get("batch_id"))
        stage = clean(request.form.get("process_stage"))
        category = clean(request.form.get("evidence_category"))
        user = clean(request.form.get("uploaded_by"))
        signed_by = clean(request.form.get("signed_by"))
        approval = clean(request.form.get("approval_status"))

        # ================================
        # GOVERNANCE VALIDATION
        # ================================
        if signed_by and not approval:
            error_msg = "❌ Approval is required when 'Signed By' is filled."
            return render_page(logs_df, error_msg)

        if user and signed_by and user == signed_by:
            error_msg = "❌ Segregation of Duties violation (Uploader = Signer)."
            return render_page(logs_df, error_msg)

        if not batch_id:
            error_msg = "❌ Batch ID is required."
            return render_page(logs_df, error_msg)

        file_bytes = file.read()
        file_hash = compute_bytes_hash(file_bytes)
        timestamp = datetime.datetime.utcnow().isoformat()

        excel = analyze_excel(file_bytes, filename)

        existing = baseline_df[baseline_df["filename"] == filename]

        if existing.empty:
            expected = ""
            status = "YELLOW"

            baseline_df = pd.concat([baseline_df, pd.DataFrame([{
                "filename": filename,
                "baseline_hash": file_hash
            }])])

            save_csv(baseline_df, BASELINE_FILE)
        else:
            expected = existing.iloc[0]["baseline_hash"]
            status = get_status(expected, file_hash)

        prev = "GENESIS" if logs_df.empty else logs_df.iloc[-1]["record_hash"]

        record_hash = sha256_text(filename + batch_id + file_hash + prev + timestamp)

        new = pd.DataFrame([{
            "filename": filename,
            "batch_id": batch_id,
            "timestamp": timestamp,
            "current_hash": file_hash,
            "expected_hash": expected,
            "status": status,
            "process_stage": stage,
            "evidence_category": category,
            "uploaded_by": user,
            "signed_by": signed_by,
            "approval_status": approval,
            "previous_hash": prev,
            "record_hash": record_hash,
            **excel
        }])

        logs_df = pd.concat([logs_df, new])
        save_csv(logs_df, LOG_FILE)

        return redirect("/")

    return render_page(logs_df, error_msg)

# ================================
# UI RENDER
# ================================
def render_page(logs_df, error_msg):

    exceptions = []

    if not logs_df.empty:
        if (logs_df["signed_by"] != "") & (logs_df["approval_status"] == ""):
            exceptions.append("Missing approvals detected")

        if (logs_df["uploaded_by"] == logs_df["signed_by"]).any():
            exceptions.append("Segregation of Duties violation detected")

        if (logs_df["status"] == "RED").any():
            exceptions.append("Tampered files detected")

    html = """
    <html><body style="font-family:Arial; margin:30px">

    <h1>COBIT-Chain™ Evidence Integrity System</h1>

    {% if error %}
        <div style="color:red; font-weight:bold">{{error}}</div>
    {% endif %}

    {% if exceptions %}
        <div style="background:#ffe0e0; padding:10px; margin-bottom:20px">
            <b>⚠ Exceptions:</b>
            <ul>
            {% for e in exceptions %}
                <li>{{e}}</li>
            {% endfor %}
            </ul>
        </div>
    {% endif %}

    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" required><br><br>
        <input name="batch_id" placeholder="Batch ID" required><br><br>
        <input name="process_stage" placeholder="Stage"><br><br>
        <input name="evidence_category" placeholder="Category"><br><br>
        <input name="uploaded_by" placeholder="Uploaded By"><br><br>
        <input name="signed_by" placeholder="Signed By"><br><br>

        <select name="approval_status">
            <option value="">Approval</option>
            <option value="Approved">Approved</option>
            <option value="Pending">Pending</option>
        </select><br><br>

        <button type="submit">Upload</button>
    </form>

    <hr>

    <table border="1" cellpadding="5">
    <tr>
        <th>Batch</th><th>Stage</th><th>Status</th>
        <th>Uploader</th><th>Signer</th><th>Approval</th>
        <th>Rows</th><th>Missing</th><th>Dup</th>
    </tr>

    {% for _, r in logs.iterrows() %}
    <tr>
        <td>{{r.batch_id}}</td>
        <td>{{r.process_stage}}</td>
        <td>{{r.status}}</td>
        <td>{{r.uploaded_by}}</td>
        <td>{{r.signed_by}}</td>
        <td>{{r.approval_status}}</td>
        <td>{{r.excel_rows}}</td>
        <td>{{r.missing_cells}}</td>
        <td>{{r.duplicate_rows}}</td>
    </tr>
    {% endfor %}
    </table>

    </body></html>
    """

    return render_template_string(html, logs=logs_df, error=error_msg, exceptions=exceptions)

if __name__ == "__main__":
    app.run(debug=True)
