import os
import io
import hashlib
import datetime
import pandas as pd
from flask import Flask, request, render_template_string, redirect, url_for
from azure.storage.blob import BlobServiceClient

app = Flask(__name__)

AZURE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
CONTAINER_NAME = "cobitchain-evidence"

BASELINE_FILE = "baseline_hashes.csv"
LOG_FILE = "logs.csv"

blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
container_client = blob_service_client.get_container_client(CONTAINER_NAME)

# ================================
# HASH FUNCTIONS
# ================================
def sha256_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def compute_file_hash(file):
    sha256 = hashlib.sha256()
    file.seek(0)
    sha256.update(file.read())
    file.seek(0)
    return sha256.hexdigest()

def generate_signature_hash(file_hash, signed_by):
    return sha256_text(file_hash + signed_by + str(datetime.datetime.utcnow()))

# ================================
# CSV FUNCTIONS
# ================================
def load_csv(filename):
    try:
        blob = container_client.get_blob_client(filename).download_blob().readall()
        return pd.read_csv(io.BytesIO(blob))
    except:
        return pd.DataFrame()

def save_csv(df, filename):
    container_client.get_blob_client(filename).upload_blob(df.to_csv(index=False), overwrite=True)

def ensure_columns(df, columns):
    for col in columns:
        if col not in df.columns:
            df[col] = ""
    return df

# ================================
# STATUS
# ================================
def get_status(expected, current):
    if not expected:
        return "YELLOW"
    if expected == current:
        return "GREEN"
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
        "filename","batch_id","timestamp","current_hash","expected_hash","status",
        "process_stage","evidence_category","uploaded_by",
        "signed_by","signature_hash","approval_status",
        "previous_hash","record_hash"
    ])

    if request.method == "POST":

        file = request.files["file"]
        filename = file.filename

        batch_id = request.form.get("batch_id")
        stage = request.form.get("process_stage")
        category = request.form.get("evidence_category")
        user = request.form.get("uploaded_by")
        signed_by = request.form.get("signed_by")
        approval = request.form.get("approval_status")

        file_hash = compute_file_hash(file)
        timestamp = datetime.datetime.utcnow().isoformat()

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
            expected_hash = existing.iloc[0]["baseline_hash"]
            status = get_status(expected_hash, file_hash)

        # SIGNATURE
        signature_hash = generate_signature_hash(file_hash, signed_by if signed_by else "UNKNOWN")

        # LEDGER CHAIN
        if logs_df.empty:
            previous_hash = "GENESIS"
        else:
            previous_hash = logs_df.iloc[-1]["record_hash"]

        record_string = file_hash + previous_hash + signature_hash + timestamp
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
            "signature_hash": signature_hash,
            "approval_status": approval,
            "previous_hash": previous_hash,
            "record_hash": record_hash
        }])

        logs_df = pd.concat([logs_df, new_log], ignore_index=True)
        save_csv(logs_df, LOG_FILE)

        return redirect("/")

    # ================================
    # BATCH SUMMARY
    # ================================
    batch_summary = []

    if not logs_df.empty:
        for batch, group in logs_df.groupby("batch_id"):

            total = len(group)
            green = len(group[group["status"]=="GREEN"])
            red = len(group[group["status"]=="RED"])
            yellow = len(group[group["status"]=="YELLOW"])

            if red>0:
                status="RED"
            elif yellow>0:
                status="YELLOW"
            else:
                status="GREEN"

            integrity = round((green/total)*100,2)

            batch_summary.append({
                "batch": batch,
                "total": total,
                "green": green,
                "yellow": yellow,
                "red": red,
                "status": status,
                "integrity": integrity
            })

    # ================================
    # HTML
    # ================================
    html = """
    <html>
    <head>
    <title>COBIT-Chain™</title>
    <style>
    body{font-family:Arial;margin:40px;background:#f5f7fb;}
    .card{padding:15px;margin:10px;border-radius:10px;color:white;display:inline-block;width:250px;}
    .GREEN{background:#2ecc71;}
    .YELLOW{background:#f1c40f;color:black;}
    .RED{background:#e74c3c;}
    table{width:100%;margin-top:20px;border-collapse:collapse;}
    th,td{padding:8px;border:1px solid #ddd;}
    th{background:black;color:white;}
    .row-GREEN{background:#eafaf1;}
    .row-YELLOW{background:#fcf3cf;}
    .row-RED{background:#fdecea;}
    </style>
    </head>

    <body>

    <h1>COBIT-Chain™ Evidence Integrity + Ledger</h1>

    <form method="POST" enctype="multipart/form-data">
    <input type="file" name="file" required><br><br>

    <input type="text" name="batch_id" placeholder="Batch ID" required><br><br>

    <input type="text" name="process_stage" placeholder="Process Stage"><br><br>

    <input type="text" name="evidence_category" placeholder="Evidence Category"><br><br>

    <input type="text" name="uploaded_by" placeholder="Uploaded By"><br><br>

    <input type="text" name="signed_by" placeholder="Signed By (QA / IT / Auditor)"><br><br>

    <select name="approval_status">
        <option value="">Approval Status</option>
        <option value="Approved">Approved</option>
        <option value="Pending">Pending</option>
        <option value="Rejected">Rejected</option>
    </select><br><br>

    <button type="submit">Upload</button>
    </form>

    <h2>Batch Summary</h2>
    {% for b in batch_summary %}
        <div class="card {{b.status}}">
            <b>{{b.batch}}</b><br>
            Integrity: {{b.integrity}}%<br>
            Green: {{b.green}} | Yellow: {{b.yellow}} | Red: {{b.red}}
        </div>
    {% endfor %}

    <h2>Ledger Chain (Audit Log)</h2>
    <table>
    <tr>
    <th>File</th><th>Batch</th><th>Status</th>
    <th>Signed By</th><th>Approval</th>
    <th>Record Hash</th><th>Prev Hash</th>
    </tr>

    {% for r in logs %}
    <tr class="row-{{r.status}}">
        <td>{{r.filename}}</td>
        <td>{{r.batch_id}}</td>
        <td>{{r.status}}</td>
        <td>{{r.signed_by}}</td>
        <td>{{r.approval_status}}</td>
        <td>{{r.record_hash[:10]}}...</td>
        <td>{{r.previous_hash[:10]}}...</td>
    </tr>
    {% endfor %}
    </table>

    </body>
    </html>
    """

    return render_template_string(html,
        logs=logs_df.to_dict(orient="records"),
        batch_summary=batch_summary
    )

if __name__ == "__main__":
    app.run(debug=True)
