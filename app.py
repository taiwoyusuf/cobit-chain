from flask import Flask, request, render_template_string
import os
import io
import csv
import hashlib
import uuid
import datetime
from azure.storage.blob import BlobServiceClient

app = Flask(__name__)

connection_string = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
container_name = "cobitchain-evidence"

log_blob_name = "logs.csv"
baseline_blob_name = "baseline_hashes.csv"

blob_service_client = BlobServiceClient.from_connection_string(connection_string)
container_client = blob_service_client.get_container_client(container_name)

log_blob_client = container_client.get_blob_client(log_blob_name)
baseline_blob_client = container_client.get_blob_client(baseline_blob_name)

LOG_HEADERS = [
    "evidence_id", "filename", "system", "verified_by", "status", "rag",
    "baseline_hash", "current_hash", "timestamp", "score",
    "action_taken", "audit_message"
]

BASELINE_HEADERS = [
    "filename", "baseline_hash", "created_on", "last_verified_on"
]

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>COBIT-Chain™</title>
    <style>
        body { font-family: Arial; background:#f4f6f9; margin:0; padding:0; }
        .container { width:900px; margin:40px auto; background:white; padding:25px; border-radius:12px; box-shadow:0 2px 12px rgba(0,0,0,0.08); }
        h1 { margin-top:0; }
        input, button { width:100%; padding:10px; margin-top:10px; box-sizing:border-box; }
        button { background:#1f6feb; color:white; border:none; border-radius:8px; cursor:pointer; }
        .card { margin-top:25px; padding:20px; border-radius:10px; border-left:8px solid #999; background:#fafafa; }
        .green { border-left-color:#28a745; }
        .yellow { border-left-color:#ffc107; }
        .red { border-left-color:#dc3545; }
        .status { font-size:22px; font-weight:bold; }
        .mono { font-family:monospace; word-break:break-all; }
        table { width:100%; border-collapse:collapse; margin-top:20px; }
        th, td { padding:8px; border-bottom:1px solid #ddd; font-size:13px; text-align:left; }
        th { background:#eee; }
    </style>
</head>
<body>
<div class="container">
    <h1>COBIT-Chain™ Evidence Integrity</h1>
    <p>Upload file → auto-baseline → verify integrity → log audit trail</p>

    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <input type="text" name="system" placeholder="System e.g. BMS, ERP, Weighbridge">
        <input type="text" name="verified_by" placeholder="Verified By">
        <button type="submit">Verify File</button>
    </form>

    {% if status %}
    <div class="card {{ color }}">
        <div class="status">{{ status }}</div>
        <p><b>File:</b> {{ filename }}</p>
        <p><b>RAG:</b> {{ rag }}</p>
        <p><b>Score:</b> {{ score }}%</p>
        <p><b>Current Hash:</b></p>
        <p class="mono">{{ current_hash }}</p>
        <p><b>Baseline Hash:</b></p>
        <p class="mono">{{ baseline_hash }}</p>
        <p><b>Audit Message:</b> {{ audit_message }}</p>
    </div>
    {% endif %}

    <h2>Audit Log</h2>
    <table>
        <tr>
            <th>Time</th>
            <th>File</th>
            <th>System</th>
            <th>User</th>
            <th>Status</th>
            <th>RAG</th>
            <th>Score</th>
        </tr>
        {% for row in logs %}
        <tr>
            <td>{{ row.timestamp }}</td>
            <td>{{ row.filename }}</td>
            <td>{{ row.system }}</td>
            <td>{{ row.verified_by }}</td>
            <td>{{ row.status }}</td>
            <td>{{ row.rag }}</td>
            <td>{{ row.score }}</td>
        </tr>
        {% endfor %}
    </table>
</div>
</body>
</html>
"""

def ensure_blob_with_header(blob_client, headers):
    try:
        blob_client.download_blob().readall()
    except Exception:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=headers)
        writer.writeheader()
        blob_client.upload_blob(output.getvalue(), overwrite=True)

def read_csv_blob(blob_client):
    try:
        data = blob_client.download_blob().readall().decode("utf-8")
        return list(csv.DictReader(io.StringIO(data)))
    except Exception:
        return []

def normalize_rows(rows, headers):
    clean_rows = []
    for row in rows:
        clean_rows.append({h: row.get(h, "") for h in headers})
    return clean_rows

def write_csv_blob(blob_client, headers, rows):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=headers, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(normalize_rows(rows, headers))
    blob_client.upload_blob(output.getvalue(), overwrite=True)

def get_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()

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
    action_taken = ""

    ensure_blob_with_header(baseline_blob_client, BASELINE_HEADERS)
    ensure_blob_with_header(log_blob_client, LOG_HEADERS)

    if request.method == "POST":
        file = request.files.get("file")
        system = request.form.get("system", "").strip()
        verified_by = request.form.get("verified_by", "").strip()
        timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        evidence_id = str(uuid.uuid4())

        if file and file.filename:
            filename = file.filename
            file_bytes = file.read()
            current_hash = get_hash(file_bytes)

            baseline_rows = read_csv_blob(baseline_blob_client)
            baseline_rows = normalize_rows(baseline_rows, BASELINE_HEADERS)
            baseline_map = {r["filename"]: r for r in baseline_rows if r.get("filename")}

            if filename not in baseline_map:
                baseline_hash = current_hash

                baseline_rows.append({
                    "filename": filename,
                    "baseline_hash": baseline_hash,
                    "created_on": timestamp,
                    "last_verified_on": timestamp
                })

                write_csv_blob(baseline_blob_client, BASELINE_HEADERS, baseline_rows)

                status = "BASELINE CREATED"
                rag = "YELLOW"
                color = "yellow"
                score = 70
                audit_message = "Trusted baseline created for future verification."
                action_taken = "Stored new baseline hash"

            else:
                baseline_hash = baseline_map[filename]["baseline_hash"]

                if current_hash == baseline_hash:
                    status = "VERIFIED"
                    rag = "GREEN"
                    color = "green"
                    score = 100
                    audit_message = "File matches trusted baseline."
                    action_taken = "Compared against stored baseline"

                    for row in baseline_rows:
                        if row["filename"] == filename:
                            row["last_verified_on"] = timestamp

                    write_csv_blob(baseline_blob_client, BASELINE_HEADERS, baseline_rows)

                else:
                    status = "TAMPER DETECTED"
                    rag = "RED"
                    color = "red"
                    score = 0
                    audit_message = "Current file hash does not match trusted baseline."
                    action_taken = "Tamper detected"

            log_rows = read_csv_blob(log_blob_client)
            log_rows = normalize_rows(log_rows, LOG_HEADERS)

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

            write_csv_blob(log_blob_client, LOG_HEADERS, log_rows)

        else:
            status = "ERROR — NO FILE PROVIDED"
            rag = "YELLOW"
            color = "yellow"
            score = 0
            audit_message = "No file was uploaded."

    logs = read_csv_blob(log_blob_client)
    logs = normalize_rows(logs, LOG_HEADERS)
    logs = list(reversed(logs[-20:]))

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
        audit_message=audit_message,
        action_taken=action_taken,
        logs=logs
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
