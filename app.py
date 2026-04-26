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

# ---------------- UI ----------------

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>COBIT-Chain™</title>
    <style>
        body { font-family: Arial; background:#f4f6f9; }
        .container { width: 800px; margin:40px auto; background:white; padding:25px; border-radius:12px; }
        input, button { width:100%; padding:10px; margin-top:10px; }
        button { background:#1f6feb; color:white; border:none; border-radius:8px; }
        .card { margin-top:20px; padding:15px; border-left:8px solid #999; background:#fafafa; }
        .green { border-left-color:#28a745; }
        .yellow { border-left-color:#ffc107; }
        .red { border-left-color:#dc3545; }
        table { width:100%; border-collapse:collapse; margin-top:20px; }
        th, td { padding:8px; border-bottom:1px solid #ddd; font-size:13px; }
        th { background:#eee; }
    </style>
</head>

<body>
<div class="container">

<h2>COBIT-Chain™ Evidence Integrity</h2>

<form method="post" enctype="multipart/form-data">
    <input type="file" name="file" required>
    <input type="text" name="system" placeholder="System">
    <input type="text" name="verified_by" placeholder="Verified By">
    <button type="submit">Verify</button>
</form>

{% if status %}
<div class="card {{ color }}">
    <b>Status:</b> {{ status }}<br>
    <b>File:</b> {{ filename }}<br>
    <b>Hash:</b> {{ current_hash }}<br>
</div>
{% endif %}

<h3>Audit Log</h3>

<table>
<tr>
    <th>File</th>
    <th>Status</th>
    <th>System</th>
    <th>User</th>
    <th>Time</th>
</tr>

{% for row in logs %}
<tr>
    <td>{{ row.filename }}</td>
    <td>{{ row.status }}</td>
    <td>{{ row.system }}</td>
    <td>{{ row.verified_by }}</td>
    <td>{{ row.timestamp }}</td>
</tr>
{% endfor %}

</table>

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
    filename = ""
    current_hash = ""

    ensure_blob_with_header(
        log_blob_client,
        ["filename", "system", "verified_by", "status", "timestamp"]
    )

    if request.method == "POST":

        file = request.files.get("file")
        system = request.form.get("system", "")
        verified_by = request.form.get("verified_by", "")

        if file and file.filename:

            filename = file.filename
            file_bytes = file.read()
            current_hash = get_hash(file_bytes)

            timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            status = "VERIFIED"
            color = "green"

            logs = read_csv_blob(log_blob_client)

            logs.append({
                "filename": filename,
                "system": system,
                "verified_by": verified_by,
                "status": status,
                "timestamp": timestamp
            })

            write_csv_blob(
                log_blob_client,
                ["filename", "system", "verified_by", "status", "timestamp"],
                logs
            )

    logs = read_csv_blob(log_blob_client)

    return render_template_string(
        HTML,
        status=status,
        color=color,
        filename=filename,
        current_hash=current_hash,
        logs=logs
    )

# ---------------- RUN ----------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
