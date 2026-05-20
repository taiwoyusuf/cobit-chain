from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "RLTTRUST_EVIDENCE_VAULT_HASH_VERIFICATION_ENGINE_V1_ACTIVE"

if MARKER in text:
    print("Evidence Vault already exists.")
    raise SystemExit()

INSERT = r"""

# ============================================================
# RLTTRUST_EVIDENCE_VAULT_HASH_VERIFICATION_ENGINE_V1_ACTIVE
# ============================================================

import hashlib
import os
import uuid
from datetime import datetime
from flask import request, jsonify, render_template_string
from werkzeug.utils import secure_filename

RLT_EVIDENCE_FOLDER = "uploads/rlttrust_evidence"

os.makedirs(RLT_EVIDENCE_FOLDER, exist_ok=True)

RLT_EVIDENCE_RECORDS = []

def rlt_sha256(path):
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


@app.route("/irlt-commercial-readiness/evidence-vault", methods=["GET", "POST"])
def irlt_evidence_vault():

    message = ""

    if request.method == "POST":

        if "evidence_file" in request.files:

            file = request.files["evidence_file"]

            if file.filename:

                evidence_id = "EV-" + str(uuid.uuid4())[:8].upper()

                filename = secure_filename(file.filename)

                save_path = os.path.join(
                    RLT_EVIDENCE_FOLDER,
                    evidence_id + "_" + filename
                )

                file.save(save_path)

                evidence_hash = rlt_sha256(save_path)

                record = {
                    "evidence_id": evidence_id,
                    "filename": filename,
                    "hash": evidence_hash,
                    "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
                    "status": "Integrity Verified"
                }

                RLT_EVIDENCE_RECORDS.append(record)

                message = "Evidence uploaded successfully."

    html = """
    <!doctype html>
    <html>
    <head>

        <title>RLTTrust Evidence Vault</title>

        <style>

            body {
                font-family: Arial;
                background: #0b0f16;
                color: white;
                margin: 0;
                padding: 40px;
            }

            .panel {
                background: #141b24;
                border-radius: 20px;
                padding: 30px;
                margin-bottom: 24px;
            }

            h1 {
                color: orange;
                font-size: 52px;
            }

            input,button {
                padding: 12px;
                border-radius: 10px;
                margin-top: 10px;
            }

            button {
                background: orange;
                border: none;
                font-weight: bold;
            }

            table {
                width: 100%;
                border-collapse: collapse;
            }

            th,td {
                padding: 12px;
                border-bottom: 1px solid #333;
            }

            th {
                color: orange;
            }

        </style>

    </head>

    <body>

        <div class="panel">

            <h1>Evidence Vault + Hash Verification Engine™</h1>

            <p>{{ message }}</p>

            <form method="POST" enctype="multipart/form-data">

                <input type="file" name="evidence_file" required>

                <br>

                <button type="submit">
                    Generate Governance Fingerprint
                </button>

            </form>

        </div>

        <div class="panel">

            <h2>Evidence Records</h2>

            <table>

                <tr>
                    <th>Evidence ID</th>
                    <th>Filename</th>
                    <th>SHA256</th>
                    <th>Timestamp</th>
                    <th>Status</th>
                </tr>

                {% for row in records %}

                <tr>
                    <td>{{ row.evidence_id }}</td>
                    <td>{{ row.filename }}</td>
                    <td style="font-size:11px;">{{ row.hash }}</td>
                    <td>{{ row.timestamp }}</td>
                    <td>{{ row.status }}</td>
                </tr>

                {% endfor %}

            </table>

        </div>

    </body>
    </html>
    """

    return render_template_string(
        html,
        message=message,
        records=list(reversed(RLT_EVIDENCE_RECORDS))
    )


@app.route("/irlt-commercial-readiness/evidence-vault/api")
def irlt_evidence_vault_api():
    return jsonify(RLT_EVIDENCE_RECORDS)

# ============================================================
# END RLTTRUST_EVIDENCE_VAULT_HASH_VERIFICATION_ENGINE
# ============================================================

"""

needle = '\nif __name__ == "__main__":'

if needle not in text:
    needle = "\nif __name__ == '__main__':"

text = text.replace(
    needle,
    "\n" + INSERT + "\n" + needle,
    1
)

APP.write_text(text, encoding="utf-8")

print("Inserted IRLT Evidence Vault successfully.")
