from pathlib import Path

APP = Path("app.py")

text = APP.read_text(encoding="utf-8")

MARKER = "IRLT_DYNAMIC_MODULE_REGISTRY_V1_ACTIVE"

if MARKER in text:
    print("IRLT Dynamic Registry already exists.")
    raise SystemExit()

insert = r"""

# ============================================================
# IRLT_DYNAMIC_MODULE_REGISTRY_V1_ACTIVE
# ============================================================

IRLT_DYNAMIC_MODULES = {

    "cold-chain-gate": {
        "title": "Cold Chain Gate",
        "summary": "Governed cold-chain readiness layer for IRLT operations.",
        "score": 96,
        "status": "Stable",
        "gates": [
            "Temperature control",
            "Courier readiness",
            "Dose viability",
            "Excursion response",
            "Chain of custody",
            "Inspection defensibility"
        ]
    },

    "dose-traceability-gate": {
        "title": "Dose Traceability Gate",
        "summary": "Governed dose traceability and lineage assurance.",
        "score": 98,
        "status": "Certified",
        "gates": [
            "Dose identity",
            "Chain-of-custody",
            "Treatment timing",
            "Release linkage",
            "Deviation linkage",
            "Inspection defensibility"
        ]
    },

    "shipment-gate": {
        "title": "Shipment Gate",
        "summary": "Governed shipment readiness and logistics assurance.",
        "score": 95,
        "status": "Controlled",
        "gates": [
            "Shipment authorization",
            "Courier handoff",
            "Route timing",
            "Evidence capture",
            "Exception escalation",
            "Delivery confirmation"
        ]
    },

    "qc-release-gate": {
        "title": "QC Release Gate",
        "summary": "Governed QC release readiness for commercial IRLT operations.",
        "score": 96,
        "status": "Verified",
        "gates": [
            "QC result review",
            "Specification confirmation",
            "OOS monitoring",
            "QC evidence",
            "Release dependencies",
            "Inspection defensibility"
        ]
    },

    "access-gate": {
        "title": "Access Governance Gate",
        "summary": "Governed identity and access readiness layer.",
        "score": 94,
        "status": "Controlled",
        "gates": [
            "Role-based access",
            "Privileged access",
            "JML governance",
            "GMP access traceability",
            "Orphaned account detection",
            "Approval lineage"
        ]
    },

    "backup-restore-gate": {
        "title": "Backup Restore Gate",
        "summary": "Governed backup and recovery assurance layer.",
        "score": 93,
        "status": "Monitored",
        "gates": [
            "Backup completion",
            "Restore readiness",
            "Recovery priority",
            "Evidence retention",
            "Failure escalation",
            "Dependency mapping"
        ]
    },

    "disaster-recovery-gate": {
        "title": "Disaster Recovery Gate",
        "summary": "Governed disaster recovery and GMP restart assurance.",
        "score": 94,
        "status": "Defensible",
        "gates": [
            "DR activation",
            "RTO/RPO governance",
            "Recovery ownership",
            "Dependency mapping",
            "GMP restart",
            "Recovery evidence"
        ]
    },

    "manufacturing-readiness-gate": {
        "title": "Manufacturing Readiness Gate",
        "summary": "Governed manufacturing scale-up readiness.",
        "score": 96,
        "status": "Ready",
        "gates": [
            "Schedule readiness",
            "Material readiness",
            "Operator readiness",
            "Manufacturing evidence",
            "Process monitoring",
            "Commercial scale-up"
        ]
    }

}

@app.route("/irlt-commercial-readiness/modules")
def irlt_dynamic_module_registry():

    overall_score = round(
        sum(x["score"] for x in IRLT_DYNAMIC_MODULES.values())
        / len(IRLT_DYNAMIC_MODULES)
    )

    return render_template_string("""

    <html>

    <head>

        <title>IRLT Dynamic Registry</title>

        <style>

            body{
                margin:0;
                padding:40px;
                font-family:Arial;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.18), transparent 30%),
                    linear-gradient(135deg,#050608,#10151d,#050608);
                color:white;
            }

            h1{
                font-size:78px;
                color:#ff9f1c;
                margin-bottom:10px;
            }

            .score{
                font-size:120px;
                color:#ff9f1c;
                margin:30px 0;
            }

            .grid{
                display:grid;
                grid-template-columns:repeat(2,1fr);
                gap:24px;
                margin-top:30px;
            }

            .card{
                background:#151c27;
                border-radius:24px;
                padding:30px;
                border:1px solid rgba(255,255,255,0.08);
            }

            h2{
                color:#ff9f1c;
                margin-top:0;
            }

            ul{
                color:#d4d9e2;
                line-height:1.8;
            }

            .pill{
                display:inline-block;
                margin-top:14px;
                padding:8px 14px;
                border-radius:999px;
                background:rgba(255,122,24,0.15);
                border:1px solid rgba(255,122,24,0.35);
            }

            a{
                color:#ff9f1c;
                text-decoration:none;
            }

        </style>

    </head>

    <body>

        <h1>IRLT Dynamic Module Registry</h1>

        <p>
            Registry-driven enterprise governance architecture for IRLT commercialization readiness.
        </p>

        <div class="score">{{ overall_score }}%</div>

        <p>Overall Governance Readiness</p>

        <div class="grid">

            {% for slug, module in modules.items() %}

            <div class="card">

                <h2>{{ module.title }}</h2>

                <p>{{ module.summary }}</p>

                <p><strong>Score:</strong> {{ module.score }}%</p>

                <div class="pill">{{ module.status }}</div>

                <ul>

                    {% for item in module.gates %}

                    <li>{{ item }}</li>

                    {% endfor %}

                </ul>

                <p>
                    <a href="/irlt-commercial-readiness/module/{{ slug }}">
                        Open Module
                    </a>
                </p>

            </div>

            {% endfor %}

        </div>

    </body>

    </html>

    """,
    modules=IRLT_DYNAMIC_MODULES,
    overall_score=overall_score
    )


@app.route("/irlt-commercial-readiness/module/<module_slug>")
def irlt_dynamic_module_page(module_slug):

    module = IRLT_DYNAMIC_MODULES.get(module_slug)

    if not module:
        return "Module not found", 404

    return render_template_string("""

    <html>

    <head>

        <title>{{ module.title }}</title>

        <style>

            body{
                margin:0;
                padding:40px;
                font-family:Arial;
                background:
                    radial-gradient(circle at top left, rgba(255,122,24,0.18), transparent 30%),
                    linear-gradient(135deg,#050608,#10151d,#050608);
                color:white;
            }

            h1{
                font-size:74px;
                color:#ff9f1c;
            }

            .score{
                font-size:120px;
                color:#ff9f1c;
                margin:20px 0;
            }

            .card{
                margin-top:30px;
                background:#151c27;
                border-radius:24px;
                padding:30px;
                border:1px solid rgba(255,255,255,0.08);
            }

            li{
                line-height:2;
                color:#d4d9e2;
            }

            .pill{
                display:inline-block;
                margin-top:14px;
                padding:8px 14px;
                border-radius:999px;
                background:rgba(255,122,24,0.15);
                border:1px solid rgba(255,122,24,0.35);
            }

        </style>

    </head>

    <body>

        <h1>{{ module.title }}</h1>

        <p>{{ module.summary }}</p>

        <div class="score">{{ module.score }}%</div>

        <div class="pill">{{ module.status }}</div>

        <div class="card">

            <h2>Governance Controls</h2>

            <ul>

                {% for item in module.gates %}

                <li>{{ item }}</li>

                {% endfor %}

            </ul>

        </div>

    </body>

    </html>

    """,
    module=module
    )


@app.route("/irlt-commercial-readiness/modules/api")
def irlt_dynamic_registry_api():

    return jsonify({
        "overall_score": round(
            sum(x["score"] for x in IRLT_DYNAMIC_MODULES.values())
            / len(IRLT_DYNAMIC_MODULES)
        ),
        "modules": IRLT_DYNAMIC_MODULES
    })

# ============================================================
# END IRLT_DYNAMIC_MODULE_REGISTRY_V1
# ============================================================

"""

target = 'if __name__ == "__main__":'

idx = text.rfind(target)

if idx == -1:
    print("Could not locate app runner.")
    raise SystemExit()

text = text[:idx] + insert + "\n\n" + text[idx:]

APP.write_text(text, encoding="utf-8")

print("IRLT Dynamic Registry appended successfully.")
