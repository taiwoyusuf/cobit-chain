from flask import Flask, request, render_template_string
import os
import io
import csv
import json
import hashlib
import uuid
import datetime
from azure.storage.blob import BlobServiceClient

# ---------------- BASELINE STORAGE ----------------

BASELINE_FILE = "baseline_hashes.json"

def load_baseline():
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)
    return {}

def save_baseline(data):
    with open(BASELINE_FILE, "w") as f:
        json.dump(data, f)

app = Flask(__name__)

connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
container_name = "cobitchain-evidence"
log_blob_name = "logs.csv"
baseline_blob_name = "baseline_hashes.csv"

blob_service_client = BlobServiceClient.from_connection_string(connection_string)
container_client = blob_service_client.get_container_client(container_name)
log_blob_client = container_client.get_blob_client(log_blob_name)
baseline_blob_client = container_client.get_blob_client(baseline_blob_name)

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>COBIT-Chain™ Evidence Integrity Verifier</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f4f6f9;
            margin: 0;
            padding: 0;
        }
        .container {
            width: 700px;
            margin: 40px auto;
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        h1 {
            margin-top: 0;
        }
        label {
            display: block;
            margin-top: 15px;
            margin-bottom: 6px;
            font-weight: bold;
        }
        input[type="text"], input[type="file"] {
            width: 100%;
            padding: 10px;
            box-sizing: border-box;
        }
        button {
            margin-top: 20px;
            padding: 12px 18px;
            border: none;
            border-radius: 8px;
            background: #1f6feb;
            color: white;
            cursor: pointer;
            font-size: 14px;
        }
        .card {
            margin-top: 25px;
            padding: 20px;
            border-radius: 10px;
            background: #fafafa;
            border-left: 10px solid #999;
        }
        .green { border-left-color: #28a745; }
        .yellow { border-left-color: #ffc107; }
        .red { border-left-color: #dc3545; }

        .status {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .small {
            color: #666;
            font-size: 13px;
        }
        .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px 20px;
            margin-top: 12px;
        }
        .mono {
            font-family: Consolas, monospace;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>COBIT-Chain™ Evidence Integrity Verifier</h1>
        <p class="small">Upload a file. The system will auto-generate a hash, compare against the trusted baseline, and log the result.</p>

        <form method="post" enctype="multipart/form-data">
            <label for="file">Upload Evidence File</label>
            <input type="file" name="file" required>

            <label for="system">System</label>
            <input type="text" name="system" placeholder="e.g. Niagara_BMS">

            <label for="verified_by">Verified By</label>
            <input type="text" name="verified_by" placeholder="e.g. Taiwo">

            <button type="submit">Verify File</button>
        </form>

        {% if status %}
        <div class="card {{ color }}">
            <div class="status">{{ status }}</div>
            <div class="grid">
                <div><b>Evidence ID:</b> {{ evidence_id }}</div>
                <div><b>RAG:</b> {{ rag }}</div>
                <div><b>System:</b> {{ system }}</div>
                <div><b>Verified By:</b> {{ verified_by }}</div>
                <div><b>File:</b> {{ filename }}</div>
                <div><b>Integrity Score:</b> {{ score }}%</div>
                <div><b>Timestamp:</b> {{ timestamp }}</div>
                <div><b>Action:</b> {{ action_taken }}</div>
            </div>

            <p><b>Current Hash:</b></p>
            <p class="mono">{{ current_hash }}</p>

            <p><b>Baseline Hash:</b></p>
            <p class="mono">{{ baseline_hash }}</p>

            <p><b>Audit Message:</b> {{ audit_message }}</p>
        </div>
        {% endif %}
    </div>
</body>
</html>
"""
        


def ensure_blob_with_header(blob_client, header_row):
    try:
        blob_client.download_blob().readall()
    except Exception:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(header_row)
        blob_client.upload_blob(output.getvalue(), overwrite=True)

def read_csv_blob(blob_client):
    try:
        content = blob_client.download_blob().readall().decode("utf-8")
        return list(csv.DictReader(io.StringIO(content)))
    except Exception:
        return []

def write_csv_blob(blob_client, fieldnames, rows):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    blob_client.upload_blob(output.getvalue(), overwrite=True)

def get_file_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

@app.route("/", methods=["GET", "POST"])
def verify():
    status = None
    color = "yellow"
    rag = ""
    score = 0
    evidence_id = ""
    filename = ""
    system = ""
    verified_by = ""
    timestamp = ""
    current_hash = ""
    baseline_hash = ""
    audit_message = ""
    action_taken = ""

    ensure_blob_with_header(
        log_blob_client,
        [
            "evidence_id", "filename", "system", "verified_by", "status", "rag",
            "baseline_hash", "current_hash", "timestamp", "score", "action_taken", "audit_message"
        ]
    )

    ensure_blob_with_header(
        baseline_blob_client,
        ["filename", "baseline_hash", "created_on", "last_verified_on"]
    )

    if request.method == "POST":
        uploaded_file = request.files.get("file")
        system = request.form.get("system", "").strip()
        verified_by = request.form.get("verified_by", "").strip()
        evidence_id = str(uuid.uuid4())
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        if uploaded_file and uploaded_file.filename:
            filename = uploaded_file.filename
            file_bytes = uploaded_file.read()
            current_hash = get_file_hash(file_bytes)

            baseline_rows = read_csv_blob(baseline_blob_client)
            baseline_map = {row["filename"]: row for row in baseline_rows}

           if filename not in baseline_map:
    # FIRST TIME → CREATE BASELINE
    baseline_hash = current_hash

    baseline_rows.append({
        "filename": filename,
        "baseline_hash": baseline_hash,
        "created_on": timestamp,
        "last_verified_on": timestamp
    })

    write_csv_blob(
        baseline_blob_client,
        ["filename", "baseline_hash", "created_on", "last_verified_on"],
        baseline_rows
    )

    # Metadata check
    if not system or not verified_by:
        status = "WARNING — BASELINE CREATED WITH INCOMPLETE METADATA"
        rag = "YELLOW"
        color = "yellow"
        score = 70
        audit_message = "Trusted baseline created, but metadata is incomplete."
    else:
        status = "BASELINE CREATED"
        rag = "GREEN"
        color = "green"
        score = 100
        audit_message = "Trusted baseline created successfully for future verification."

    action_taken = "Stored new baseline hash"

else:
    baseline_hash = baseline_map[filename]["baseline_hash"]

    if current_hash == baseline_hash:
        # MATCH
        if not system or not verified_by:
            status = "WARNING — INCOMPLETE METADATA"
            rag = "YELLOW"
            color = "yellow"
            score = 70
            audit_message = "File integrity verified, but metadata is incomplete."
        else:
            status = "VERIFIED"
            rag = "GREEN"
            color = "green"
            score = 100
            audit_message = "File matches the trusted baseline hash."

        action_taken = "Compared against stored baseline"

        # Update last verified timestamp
        for row in baseline_rows:
            if row["filename"] == filename:
                row["last_verified_on"] = timestamp

        write_csv_blob(
            baseline_blob_client,
            ["filename", "baseline_hash", "created_on", "last_verified_on"],
            baseline_rows
        )

    else:
        # MISMATCH
        status = "TAMPER DETECTED"
        rag = "RED"
        color = "red"
        score = 0
        audit_message = "Current file hash does not match the trusted baseline hash."
        action_taken = "Tamper detected during verification"

            log_rows = read_csv_blob(log_blob_client)
            log_rows.append({
                "evidence_id": evidence_id,
                "filename": filename,
                "system": system,
                "verified_by": verified_by,
                "status": status,
                "rag": rag,
                "baseline_hash": baseline_hash,
                "current_hash": current_hash,
                "timestamp": timestamp,
                "score": score,
                "action_taken": action_taken,
                "audit_message": audit_message
            })
            write_csv_blob(
                log_blob_client,
                [
                    "evidence_id", "filename", "system", "verified_by", "status", "rag",
                    "baseline_hash", "current_hash", "timestamp", "score", "action_taken", "audit_message"
                ],
                log_rows
            )

        else:
            status = "ERROR — NO FILE PROVIDED"
            rag = "YELLOW"
            color = "yellow"
            score = 0
            timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            audit_message = "No file was uploaded."
            action_taken = "Verification failed"

    return render_template_string(
        HTML,
        status=status,
        color=color,
        rag=rag,
        score=score,
        evidence_id=evidence_id,
        filename=filename,
        system=system,
        verified_by=verified_by,
        timestamp=timestamp,
        current_hash=current_hash,
        baseline_hash=baseline_hash,
        audit_message=audit_message,
        action_taken=action_taken
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
