from flask import Flask, request, render_template_string, redirect
import os, io, hashlib, datetime
import pandas as pd
from azure.storage.blob import BlobServiceClient

app = Flask(__name__)

# CONFIG
AZURE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
CONTAINER_NAME = "cobitchain-evidence"

blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
container_client = blob_service_client.get_container_client(CONTAINER_NAME)

BASELINE_FILE = "baseline_hashes.csv"
LOG_FILE = "logs.csv"

REQUIRED_STAGES = ["Weighbridge", "Dispatch", "Invoice"]

def clean(x):
    if x is None: return ""
    x = str(x).strip()
    return "" if x.lower() == "nan" else x

def sha256_text(x): return hashlib.sha256(x.encode()).hexdigest()
def compute_hash(b): return hashlib.sha256(b).hexdigest()

def load_csv(name):
    try:
        data = container_client.get_blob_client(name).download_blob().readall()
        return pd.read_csv(io.BytesIO(data), keep_default_na=False).fillna("")
    except:
        return pd.DataFrame()

def save_csv(df, name):
    container_client.get_blob_client(name).upload_blob(df.to_csv(index=False), overwrite=True)

def ensure_cols(df, cols):
    for c in cols:
        if c not in df.columns: df[c] = ""
    return df.fillna("")

# EXCEL ANALYTICS
def analyze_excel(bytes_data, filename):
    result = {"excel_rows":"","excel_columns":"","missing_cells":"","duplicate_rows":"","analysis_summary":"","data_quality":"N/A"}

    if not filename.lower().endswith((".xlsx",".xls")):
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
            "excel_rows":rows,
            "excel_columns":cols,
            "missing_cells":missing,
            "duplicate_rows":dup,
            "analysis_summary":f"{rows} rows | {cols} cols | {missing} missing | {dup} dup",
            "data_quality":quality
        })
    except Exception as e:
        result["analysis_summary"] = f"Error: {e}"

    return result

def get_status(expected,current):
    if not expected: return "YELLOW"
    return "GREEN" if expected == current else "RED"

# MAIN
@app.route("/", methods=["GET","POST"])
def index():

    baseline = load_csv(BASELINE_FILE)
    logs = load_csv(LOG_FILE)

    baseline = ensure_cols(baseline,["filename","baseline_hash"])
    logs = ensure_cols(logs,[
        "filename","batch_id","timestamp","current_hash","expected_hash","status",
        "process_stage","evidence_category","uploaded_by","signed_by","approval_status",
        "previous_hash","record_hash","excel_rows","excel_columns","missing_cells","duplicate_rows","analysis_summary","data_quality"
    ])

    error = ""

    if request.method == "POST":
        file = request.files.get("file")
        if not file: return redirect("/")

        filename = clean(file.filename)
        batch = clean(request.form.get("batch_id"))
        stage = clean(request.form.get("process_stage"))
        category = clean(request.form.get("evidence_category"))
        user = clean(request.form.get("uploaded_by"))
        signed = clean(request.form.get("signed_by"))
        approval = clean(request.form.get("approval_status"))

        # GOVERNANCE RULES
        if signed and not approval:
            return render_page(logs,"Approval required when Signed By is filled")

        if user and signed and user == signed:
            return render_page(logs,"SoD violation (Uploader = Signer)")

        file_bytes = file.read()
        h = compute_hash(file_bytes)
        ts = datetime.datetime.utcnow().isoformat()

        excel = analyze_excel(file_bytes, filename)

        existing = baseline[baseline["filename"] == filename]

        if existing.empty:
            expected = ""
            status = "YELLOW"
            baseline = pd.concat([baseline,pd.DataFrame([{"filename":filename,"baseline_hash":h}])])
            save_csv(baseline,BASELINE_FILE)
        else:
            expected = existing.iloc[0]["baseline_hash"]
            status = get_status(expected,h)

        prev = "GENESIS" if logs.empty else logs.iloc[-1]["record_hash"]
        record_hash = sha256_text(filename+batch+h+prev+ts)

        new = pd.DataFrame([{
            "filename":filename,
            "batch_id":batch,
            "timestamp":ts,
            "current_hash":h,
            "expected_hash":expected,
            "status":status,
            "process_stage":stage,
            "evidence_category":category,
            "uploaded_by":user,
            "signed_by":signed,
            "approval_status":approval,
            "previous_hash":prev,
            "record_hash":record_hash,
            **excel
        }])

        logs = pd.concat([logs,new])
        save_csv(logs,LOG_FILE)

        return redirect("/")

    return render_page(logs,error)

# RENDER
def render_page(logs, error):

    exceptions = []

    if not logs.empty:

        if ((logs["signed_by"] != "") & (logs["approval_status"] == "")).any():
            exceptions.append("Missing approvals")

        if ((logs["uploaded_by"] != "") &
            (logs["signed_by"] != "") &
            (logs["uploaded_by"] == logs["signed_by"])).any():
            exceptions.append("SoD violation")

        if (logs["status"] == "RED").any():
            exceptions.append("Tampered files")

    batches = []

    for b,grp in logs.groupby("batch_id"):

        stages = grp["process_stage"].tolist()
        missing = [s for s in REQUIRED_STAGES if s not in stages]

        seq_issue = False
        order_map = {"Weighbridge":1,"Dispatch":2,"Invoice":3}
        last = 0
        for s in stages:
            if s in order_map:
                if order_map[s] < last:
                    seq_issue = True
                last = order_map[s]

        risk = "LOW"
        if (grp["status"]=="RED").any() or seq_issue:
            risk = "HIGH"
        elif missing:
            risk = "MEDIUM"

        batches.append({
            "name":b,
            "risk":risk,
            "missing":missing,
            "seq":seq_issue,
            "records":grp.to_dict("records")
        })

    html = """
    <html><body style="font-family:Arial;margin:30px">

    <h1>COBIT-Chain™</h1>

    {% if error %}<div style="color:red">{{error}}</div>{% endif %}

    {% if exceptions %}
    <div style="background:#ffe0e0;padding:10px">
    <b>Exceptions:</b>
    <ul>{% for e in exceptions %}<li>{{e}}</li>{% endfor %}</ul>
    </div>
    {% endif %}

    <form method="POST" enctype="multipart/form-data">
    <input type="file" name="file" required><br>
    <input name="batch_id" placeholder="Batch ID" required><br>
    <input name="process_stage" placeholder="Stage"><br>
    <input name="evidence_category" placeholder="Category"><br>
    <input name="uploaded_by" placeholder="Uploader"><br>
    <input name="signed_by" placeholder="Signer"><br>
    <select name="approval_status">
    <option value="">Approval</option>
    <option value="Approved">Approved</option>
    </select>
    <button>Upload</button>
    </form>

    <hr>

    {% for b in batches %}
    <h3>{{b.name}} | Risk: {{b.risk}}</h3>

    {% if b.missing %}
    Missing: {{b.missing}}
    {% endif %}

    {% if b.seq %}
    <div style="color:red">Sequence issue detected</div>
    {% endif %}

    <table border=1>
    <tr><th>Stage</th><th>Status</th><th>Rows</th><th>Missing</th><th>Dup</th></tr>
    {% for r in b.records %}
    <tr>
    <td>{{r.process_stage}}</td>
    <td>{{r.status}}</td>
    <td>{{r.excel_rows}}</td>
    <td>{{r.missing_cells}}</td>
    <td>{{r.duplicate_rows}}</td>
    </tr>
    {% endfor %}
    </table>
    {% endfor %}

    </body></html>
    """

    return render_template_string(html, logs=logs, error=error, exceptions=exceptions, batches=batches)

if __name__ == "__main__":
    app.run(debug=True)
