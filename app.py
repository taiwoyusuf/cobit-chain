from flask import Flask, request, render_template_string
import os
import io
import csv
import hashlib
import uuid
import datetime
from azure.storage.blob import BlobServiceClient

app = Flask(__name__)

# ---------------- CONFIG ----------------

connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
container_name = "cobitchain-evidence"

log_blob_name = "logs.csv"
baseline_blob_name = "baseline_hashes.csv"

blob_service_client = BlobServiceClient.from_connection_string(connection_string)
container_client = blob_service_client.get_container_client(container_name)

log_blob_client = container_client.get_blob_client(log_blob_name)
baseline_blob_client = container_client.get_blob_client(baseline_blob_name)

# ---------------- MODERN UI ----------------

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>COBIT-Chain™</title>
    <style>
        body {
            font-family: Arial;
            background: #f4f6f9;
            margin: 0;
            padding: 0;
        }

        .container {
            width: 700px;
            margin: 40px auto;
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 2px 12px rgba(0,0,0,0.1);
        }

        h1 {
            margin-top: 0;
        }

        input, button {
            width: 100%;
            padding: 10px;
            margin-top: 10px;
        }

        button {
            background: #1f6feb;
            color: white;
            border: none;
            border-radius: 8px;
        }

        .card {
            margin-top: 25px;
            padding: 20px;
            border-radius: 10px;
            border-left: 8px solid #999;
            background: #fafafa;
        }

        .green { border-left-color: #28a745; }
        .yellow { border-left-color: #ffc107; }
        .red { border-left-color: #dc3545; }

        .status {
            font-size: 22px;
            font-weight: bold;
        }

        .mono {
            font-family: monospace;
            word-break: break-all;
        }

        .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }

        .small {
            color: #666;
            font-size: 13px;
        }
    </style>
</head>

<body>

<div class="container">
    <h1>COBIT-Chain™ Evidence Integrity</h1>
    <p class="small">Upload file → auto baseline → verify integrity</p>

    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <input type="text" name="system" placeholder="System (e.g. BMS)">
        <input type="text" name="verified_by" placeholder="Verified By">
        <button type="submit">Verify File</button>
    </form>

    {% if status %}
    <div class="card {{ color }}">
        <div class="status">{{ status }}</div>

        <div class="grid">
            <div><b>File:</b> {{ filename }}</div>
            <div><b>RAG:</b> {{ rag }}</div>
            <div><b>System:</b> {{ system }}</div>
            <div><b>Verified By:</b> {{ verified_by }}</div>
            <div><b>Score:</b> {{ score }}%</div>
            <div><b>Timestamp:</b> {{ timestamp }}</div>
        </div>

        <p><b>Current Hash:</b></p>
        <p class="mono">{{ current_hash }}</p>

        <p><b>Baseline Hash:</b></p>
        <p class="mono">{{ baseline_hash }}</p>

        <p><b>Audit:</b> {{ audit_message }}</p>
    </div>
    {% endif %}
</div>

</body>
</html>
"""

# ---------------- HELPERS ----------------

def ensure_blob_with_header(blob_client, header):
    try:
        blob_client.download_blob().readall()
    except:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(header)
        blob_client.upload_blob(output.getvalue(), overwrite=True)

def read_csv_blob(blob_client):
    try:
        data = blob_client.download_blob().readall().decode("utf-8")
        return list(csv.DictReader(io.StringIO(data)))
    except:
        return []

def write_csv_blob(blob_client, headers, rows):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=headers)
    writer.writeheader()
    writer.writerows(rows)
    blob_client.upload_blob(output.getvalue(), overwrite=True)

def get_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

# ---------------- ROUTE ----------------

@app.route("/", methods=["GET", "POST"])
def verify():

    status = None
    color = "yellow"
    rag = ""
    score = 0
    filename = ""
    system = ""
    verified_by = ""
    timestamp = ""
    current_hash = ""
    baseline_hash = ""
    audit_message = ""

    ensure_blob_with_header(
        baseline_blob_client,
        ["filename", "baseline_hash", "created_on", "last_verified_on"]
    )

    ensure_blob_with_header(
        log_blob_client,
        [
            "evidence_id", "filename", "system", "verified_by", "status", "rag",
            "baseline_hash", "current_hash", "timestamp", "score", "audit_message"
        ]
    )

    if request.method == "POST":

        file = request.files.get("file")
        system = request.form.get("system", "").strip()
        verified_by = request.form.get("verified_by", "").strip()

        if file and file.filename:

            filename = file.filename
            file_bytes = file.read()
            current_hash = get_hash(file_bytes)

            rows = read_csv_blob(baseline_blob_client)
            baseline_map = {r["filename"]: r for r in rows}

            timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            if filename not in baseline_map:

                baseline_hash = current_hash

                rows.append({
                    "filename": filename,
                    "baseline_hash": baseline_hash,
                    "created_on": timestamp,
                    "last_verified_on": timestamp
                })

                write_csv_blob(
                    baseline_blob_client,
                    ["filename", "baseline_hash", "created_on", "last_verified_on"],
                    rows
                )

                status = "BASELINE CREATED"
                color = "yellow"
                rag = "YELLOW"
                score = 70
                audit_message = "Baseline created for future verification"

            else:

                baseline_hash = baseline_map[filename]["baseline_hash"]

                if current_hash == baseline_hash:

                    status = "VERIFIED"
                    color = "green"
                    rag = "GREEN"
                    score = 100
                    audit_message = "File matches trusted baseline"

                else:

                    status = "TAMPER DETECTED"
                    color = "red"
                    rag = "RED"
                    score = 0
                    audit_message = "File does NOT match baseline"

    return render_template_string(
        HTML,
        status=status,
        color=color,
        rag=rag,
        score=score,
        filename=filename,
        system=system,
        verified_by=verified_by,
        timestamp=timestamp,
        current_hash=current_hash,
        baseline_hash=baseline_hash,
        audit_message=audit_message
    )

# ---------------- RUN ----------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
