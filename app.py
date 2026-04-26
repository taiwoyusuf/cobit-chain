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

# ---------------- HTML ----------------

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>COBIT-Chain™</title>
</head>
<body>
    <h2>COBIT-Chain™ Evidence Integrity</h2>

    <form method="post" enctype="multipart/form-data">
        <input type="file" name="file" required><br><br>
        <input type="text" name="system" placeholder="System"><br><br>
        <input type="text" name="verified_by" placeholder="Verified By"><br><br>
        <button type="submit">Verify</button>
    </form>

    {% if status %}
        <h3 style="color: {{ color }}">{{ status }}</h3>
        <p><b>File:</b> {{ filename }}</p>
        <p><b>Current Hash:</b> {{ current_hash }}</p>
        <p><b>Baseline Hash:</b> {{ baseline_hash }}</p>
    {% endif %}
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
    color = "black"
    filename = ""
    current_hash = ""
    baseline_hash = ""

    ensure_blob_with_header(
        baseline_blob_client,
        ["filename", "baseline_hash", "created_on", "last_verified_on"]
    )

    ensure_blob_with_header(
        log_blob_client,
        ["filename", "status", "timestamp"]
    )

    if request.method == "POST":

        file = request.files.get("file")

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
                color = "orange"

            else:

                baseline_hash = baseline_map[filename]["baseline_hash"]

                if current_hash == baseline_hash:

                    status = "VERIFIED"
                    color = "green"

                else:

                    status = "TAMPER DETECTED"
                    color = "red"

            # LOG
            log_rows = read_csv_blob(log_blob_client)

            log_rows.append({
                "filename": filename,
                "status": status,
                "timestamp": timestamp
            })

            write_csv_blob(
                log_blob_client,
                ["filename", "status", "timestamp"],
                log_rows
            )

    return render_template_string(
        HTML,
        status=status,
        color=color,
        filename=filename,
        current_hash=current_hash,
        baseline_hash=baseline_hash
    )

# ---------------- RUN ----------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
