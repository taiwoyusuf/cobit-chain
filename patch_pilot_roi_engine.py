from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_PILOT_READINESS_ROI_ENGINE_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("Pilot Readiness & ROI Justification Engine already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_PILOT_READINESS_ROI_ENGINE_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Pilot Readiness & ROI Justification Engine™
# Purpose: Convert RLTTrust™ into a practical pilot proposal with scope,
#          phases, evidence inputs, success metrics, ROI justification,
#          buyer value, and executive decision narrative.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify, request

def _rlttrust_pilot_num(value, default, minimum=0, maximum=1000000):
    try:
        parsed = float(value)
    except Exception:
        parsed = float(default)
    return max(float(minimum), min(float(maximum), parsed))


def _rlttrust_pilot_int(value, default, minimum=0, maximum=1000000):
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    return max(int(minimum), min(int(maximum), parsed))


def _rlttrust_pilot_roi_data(payload=None):
    payload = payload or {}

    pilot_sites = _rlttrust_pilot_int(payload.get("pilot_sites"), 1, 1, 25)
    dose_journeys = _rlttrust_pilot_int(payload.get("dose_journeys"), 10, 1, 10000)
    release_events = _rlttrust_pilot_int(payload.get("release_events"), 10, 1, 10000)
    audit_questions = _rlttrust_pilot_int(payload.get("audit_questions"), 25, 1, 10000)
    evidence_packets = _rlttrust_pilot_int(payload.get("evidence_packets"), 60, 1, 100000)
    source_systems = _rlttrust_pilot_int(payload.get("source_systems"), 6, 1, 50)
    pilot_weeks = _rlttrust_pilot_int(payload.get("pilot_weeks"), 8, 2, 52)

    current_manual_hours_per_week = _rlttrust_pilot_num(payload.get("current_manual_hours_per_week"), 45, 0, 10000)
    expected_time_reduction_percent = _rlttrust_pilot_num(payload.get("expected_time_reduction_percent"), 35, 0, 95)
    hourly_loaded_cost = _rlttrust_pilot_num(payload.get("hourly_loaded_cost"), 125, 1, 5000)

    avoided_rework_events = _rlttrust_pilot_int(payload.get("avoided_rework_events"), 4, 0, 10000)
    cost_per_rework_event = _rlttrust_pilot_num(payload.get("cost_per_rework_event"), 6500, 0, 1000000)

    avoided_inspection_findings = _rlttrust_pilot_int(payload.get("avoided_inspection_findings"), 2, 0, 10000)
    value_per_avoided_finding = _rlttrust_pilot_num(payload.get("value_per_avoided_finding"), 25000, 0, 10000000)

    pilot_cost = _rlttrust_pilot_num(payload.get("pilot_cost"), 150000, 0, 10000000)

    readiness_baseline = _rlttrust_pilot_num(payload.get("readiness_baseline"), 72, 0, 100)
    target_readiness = _rlttrust_pilot_num(payload.get("target_readiness"), 88, 0, 100)
    evidence_maturity_baseline = _rlttrust_pilot_num(payload.get("evidence_maturity_baseline"), 60, 0, 100)
    target_evidence_maturity = _rlttrust_pilot_num(payload.get("target_evidence_maturity"), 90, 0, 100)

    weekly_time_savings_hours = current_manual_hours_per_week * (expected_time_reduction_percent / 100.0)
    pilot_time_savings_value = weekly_time_savings_hours * pilot_weeks * hourly_loaded_cost
    annualized_time_savings_value = weekly_time_savings_hours * 52 * hourly_loaded_cost

    rework_avoidance_value = avoided_rework_events * cost_per_rework_event
    inspection_avoidance_value = avoided_inspection_findings * value_per_avoided_finding

    pilot_value = pilot_time_savings_value + rework_avoidance_value + inspection_avoidance_value
    annualized_value = annualized_time_savings_value + rework_avoidance_value + inspection_avoidance_value

    net_pilot_value = pilot_value - pilot_cost
    roi_percent = 0
    if pilot_cost > 0:
        roi_percent = round((net_pilot_value / pilot_cost) * 100)

    readiness_delta = target_readiness - readiness_baseline
    evidence_delta = target_evidence_maturity - evidence_maturity_baseline

    complexity_score = min(100, round((pilot_sites * 8) + (source_systems * 5) + (dose_journeys * 0.8) + (evidence_packets * 0.25)))
    value_score = min(100, round((pilot_value / max(pilot_cost, 1)) * 55))
    readiness_lift_score = min(100, round((readiness_delta + evidence_delta) * 2.2))
    adoption_score = max(0, min(100, 100 - (complexity_score * 0.35) + (pilot_weeks * 1.5)))
    executive_case_score = round((value_score * 0.30) + (readiness_lift_score * 0.25) + (adoption_score * 0.20) + (min(100, source_systems * 12) * 0.10) + (min(100, audit_questions * 2) * 0.15))
    executive_case_score = max(0, min(100, executive_case_score))

    if executive_case_score >= 88 and roi_percent >= 0:
        recommendation = "GO — strong pilot candidate"
        status_class = "ready"
        executive_answer = "The pilot is commercially compelling because it targets high-value readiness, release, evidence, inspection, and patient-slot pain points with measurable ROI."
    elif executive_case_score >= 78:
        recommendation = "GO WITH FOCUSED SCOPE"
        status_class = "warning"
        executive_answer = "The pilot is credible, but scope should be controlled around one site, one dose journey, and the highest-value evidence outputs."
    elif executive_case_score >= 65:
        recommendation = "REFINE — value case needs sharpening"
        status_class = "gap"
        executive_answer = "The pilot has potential, but leadership should narrow scope, increase evidence maturity targets, or improve measurable ROI assumptions."
    else:
        recommendation = "HOLD — pilot case not strong enough yet"
        status_class = "blocked"
        executive_answer = "The pilot should be redesigned before buyer presentation because the value case, scope, or readiness lift is not sufficiently defensible."

    pilot_scope = {
        "recommended_scope": "One site, one product/dose journey, one release pathway, one shipment path, one treatment-site readiness scenario, and one inspection-readiness evidence pack.",
        "starting_modules": [
            "Release Defensibility Engine™",
            "Isotope-to-Patient Evidence Graph™",
            "Radioactive Material Accountability Ledger™",
            "Patient Slot Protection Engine™",
            "Auditor Question-to-Evidence Engine™",
            "Executive Governance Passport Factory™"
        ],
        "defer_until_later": [
            "Full multi-site production deployment",
            "Deep real-time integrations",
            "Automated regulated decisions",
            "Clinical decision workflows",
            "PHI-bearing workflows",
            "Full enterprise replacement of source systems"
        ],
        "why_this_scope": "This scope proves the core buyer value without trying to replace Veeva, MES, LIMS, ERP, ServiceNow, logistics platforms, or scheduling systems."
    }

    pilot_phases = [
        {
            "phase": "Phase 0 — Executive Alignment",
            "duration": "1 week",
            "objective": "Confirm buyer pain points, pilot owner, governance boundaries, source systems, and non-replacement positioning.",
            "outputs": [
                "Pilot charter",
                "Executive success criteria",
                "System boundary map",
                "Governance approval model"
            ],
            "success_metric": "Named business owner, QA sponsor, and agreed pilot scope."
        },
        {
            "phase": "Phase 1 — Evidence Mapping",
            "duration": "1–2 weeks",
            "objective": "Map one dose journey and one release pathway to evidence packets, owners, systems, and governance controls.",
            "outputs": [
                "Evidence inventory",
                "Owner map",
                "Release evidence model",
                "Isotope-to-patient journey map"
            ],
            "success_metric": "At least 80% of critical evidence packets identified and assigned."
        },
        {
            "phase": "Phase 2 — Engine Configuration",
            "duration": "2 weeks",
            "objective": "Configure readiness scoring, release gates, material accountability, patient-slot protection, and auditor evidence mapping.",
            "outputs": [
                "Configured readiness engine",
                "Release gate model",
                "Material accountability ledger",
                "Auditor question map"
            ],
            "success_metric": "Pilot engines produce repeatable readiness and evidence outputs."
        },
        {
            "phase": "Phase 3 — Passport Generation",
            "duration": "1 week",
            "objective": "Generate executive passports for release, dose journey, material accountability, inspection readiness, and commercial readiness.",
            "outputs": [
                "Release Defensibility Passport",
                "Dose Journey Passport",
                "Material Accountability Passport",
                "Inspection Survivability Passport",
                "Commercial Readiness Passport"
            ],
            "success_metric": "Leadership can review one artifact instead of scattered evidence sources."
        },
        {
            "phase": "Phase 4 — Stress Test and Inspection Simulation",
            "duration": "1 week",
            "objective": "Run what-if scenarios and simulated inspection questions to test pilot defensibility.",
            "outputs": [
                "Commercialization stress test",
                "Inspection Tomorrow output",
                "War-room action plan",
                "Risk closure register"
            ],
            "success_metric": "At least three high-risk failure scenarios tested with documented recovery actions."
        },
        {
            "phase": "Phase 5 — Executive ROI Review",
            "duration": "1 week",
            "objective": "Present value realized, readiness improvement, evidence maturity lift, reduced manual effort, and expansion recommendation.",
            "outputs": [
                "Pilot ROI summary",
                "Executive decision memo",
                "Expansion roadmap",
                "Buyer success story"
            ],
            "success_metric": "Leadership decision on expansion, integration, or enterprise rollout."
        }
    ]

    success_metrics = [
        {
            "metric": "Evidence retrieval time reduction",
            "baseline": "Manual search across systems, trackers, folders, and emails.",
            "target": f"{expected_time_reduction_percent:.0f}% reduction in evidence search and readiness preparation effort.",
            "proof": "Auditor Question-to-Evidence Engine™ and Passport Factory outputs."
        },
        {
            "metric": "Readiness score improvement",
            "baseline": f"{readiness_baseline:.0f}%",
            "target": f"{target_readiness:.0f}%",
            "proof": "Command Center, Can We Treat Tomorrow? Engine™, and Governance Passport results."
        },
        {
            "metric": "Evidence maturity improvement",
            "baseline": f"{evidence_maturity_baseline:.0f}%",
            "target": f"{target_evidence_maturity:.0f}%",
            "proof": "AuditVault™ evidence verification and Governance Black Box Recorder™."
        },
        {
            "metric": "Release defensibility",
            "baseline": "Release evidence scattered across QC, QA, CAPA, EM, SOP, access, custody, and material records.",
            "target": "One release defensibility passport for the pilot release pathway.",
            "proof": "Release Defensibility Engine™."
        },
        {
            "metric": "Dose journey traceability",
            "baseline": "Dose journey evidence split across isotope source, manufacturing, QC, QA, shipment, receipt, and site readiness.",
            "target": "One isotope-to-patient evidence graph for pilot journey.",
            "proof": "Isotope-to-Patient Evidence Graph™."
        },
        {
            "metric": "Inspection response readiness",
            "baseline": "Manual response preparation.",
            "target": f"{audit_questions} mapped auditor questions with evidence packets and owners.",
            "proof": "Auditor Question-to-Evidence Engine™."
        }
    ]

    evidence_inputs = [
        {
            "input": "QC result packet",
            "source": "LIMS / QC records / controlled evidence repository",
            "owner": "QC / QA",
            "pilot_use": "Release defensibility and inspection readiness."
        },
        {
            "input": "QA release rationale",
            "source": "Veeva / QMS / release workflow",
            "owner": "QA Release",
            "pilot_use": "Release Defensibility Passport."
        },
        {
            "input": "Batch manufacturing record",
            "source": "MES / batch record system / controlled document repository",
            "owner": "Manufacturing / QA",
            "pilot_use": "Dose journey and release evidence."
        },
        {
            "input": "CAPA / deviation / EM records",
            "source": "QMS / Veeva / EM records",
            "owner": "QA / CAPA / EM",
            "pilot_use": "Release impact and inspection survivability."
        },
        {
            "input": "Radioactive material receipt/use/waste/decay/reconciliation",
            "source": "Radiation safety records / controlled logs",
            "owner": "Radiation Safety / QA",
            "pilot_use": "Radioactive Material Accountability Ledger™."
        },
        {
            "input": "Shipment and custody evidence",
            "source": "Courier records / logistics systems / cold-chain files",
            "owner": "Supply Chain / Logistics",
            "pilot_use": "Isotope-to-patient graph and patient-slot protection."
        },
        {
            "input": "Treatment-site readiness evidence",
            "source": "Treatment coordination records / site readiness attestations",
            "owner": "Treatment Coordination / Nuclear Medicine",
            "pilot_use": "Patient Slot Protection Passport."
        },
        {
            "input": "SOP and training alignment",
            "source": "Veeva / LMS / training systems",
            "owner": "Training / SOP Governance / QA",
            "pilot_use": "SOPTrust™ and release defensibility."
        },
        {
            "input": "Access governance evidence",
            "source": "IAM / access review / system-owner attestation",
            "owner": "IAM / System Owner",
            "pilot_use": "AccessTrust™ and audit trail accountability."
        },
        {
            "input": "Evidence hashes and approval lineage",
            "source": "AuditVault™ / controlled files / evidence repository",
            "owner": "QA / Compliance / System Owners",
            "pilot_use": "Evidence integrity, black box recorder, and passports."
        }
    ]

    roi_breakdown = [
        {
            "category": "Time savings during pilot",
            "calculation": f"{weekly_time_savings_hours:.1f} saved hours/week × {pilot_weeks} weeks × ${hourly_loaded_cost:,.0f}/hour",
            "value": round(pilot_time_savings_value)
        },
        {
            "category": "Annualized time savings",
            "calculation": f"{weekly_time_savings_hours:.1f} saved hours/week × 52 weeks × ${hourly_loaded_cost:,.0f}/hour",
            "value": round(annualized_time_savings_value)
        },
        {
            "category": "Avoided rework",
            "calculation": f"{avoided_rework_events} avoided rework events × ${cost_per_rework_event:,.0f}",
            "value": round(rework_avoidance_value)
        },
        {
            "category": "Avoided inspection findings",
            "calculation": f"{avoided_inspection_findings} avoided findings × ${value_per_avoided_finding:,.0f}",
            "value": round(inspection_avoidance_value)
        },
        {
            "category": "Total pilot value",
            "calculation": "Time savings + avoided rework + avoided inspection exposure",
            "value": round(pilot_value)
        },
        {
            "category": "Estimated pilot cost",
            "calculation": "Configured pilot cost assumption",
            "value": round(pilot_cost)
        },
        {
            "category": "Net pilot value",
            "calculation": "Total pilot value minus pilot cost",
            "value": round(net_pilot_value)
        }
    ]

    buyer_value = [
        {
            "buyer": "QA Leadership",
            "value": "Release decisions become easier to defend with governed evidence packets and human approval lineage.",
            "module": "Release Defensibility Engine™"
        },
        {
            "buyer": "Radiopharma Operations",
            "value": "Dose journeys become traceable from isotope source to treatment readiness.",
            "module": "Isotope-to-Patient Evidence Graph™"
        },
        {
            "buyer": "Radiation Safety",
            "value": "Radioactive material receipt, use, decay, waste, residual, transfer, and reconciliation become passported.",
            "module": "Radioactive Material Accountability Ledger™"
        },
        {
            "buyer": "Commercialization Leadership",
            "value": "Launch readiness can be reviewed through one evidence-backed executive command layer.",
            "module": "Command Center + Passport Factory"
        },
        {
            "buyer": "Compliance / Audit",
            "value": "Inspection questions map directly to evidence owners, packets, gaps, source engines, and passports.",
            "module": "Auditor Question-to-Evidence Engine™"
        },
        {
            "buyer": "Supply Chain / Treatment Coordination",
            "value": "Courier/custody timing, site readiness, appointment readiness, and dose-to-slot alignment become governed.",
            "module": "Patient Slot Protection Engine™"
        }
    ]

    risk_controls = [
        {
            "risk": "Pilot becomes too broad",
            "control": "Limit pilot to one site, one product/dose journey, one release pathway, and one evidence pack.",
            "owner": "Pilot Sponsor"
        },
        {
            "risk": "Buyer thinks platform replaces existing systems",
            "control": "Position RLTTrust™ as an overlay that consumes evidence from Veeva, MES, LIMS, ERP, ServiceNow, and logistics systems.",
            "owner": "Executive Sponsor / Product Owner"
        },
        {
            "risk": "AI regulatory concern",
            "control": "Show Governance Black Box Recorder™ and state that AI is advisory only; human approval remains authoritative.",
            "owner": "QA / Compliance"
        },
        {
            "risk": "No measurable ROI",
            "control": "Measure evidence retrieval time, readiness score lift, evidence maturity lift, reduced rework, and inspection-response improvement.",
            "owner": "Pilot PMO"
        },
        {
            "risk": "Evidence quality is poor",
            "control": "Use the pilot to expose evidence gaps and generate closure actions rather than pretending readiness is already perfect.",
            "owner": "QA / Evidence Owners"
        }
    ]

    executive_narrative = {
        "headline": "RLTTrust™ pilot proves whether commercial IRLT readiness can be defended with governed evidence.",
        "why_now": "IRLT commercialization requires more than operational activity tracking. Leadership needs defensible evidence that release, material accountability, shipment, treatment-site readiness, inspection response, and patient-slot protection are governed.",
        "pilot_thesis": "A focused pilot can prove value without replacing existing systems by creating one governed assurance layer across one real dose journey and release pathway.",
        "decision_request": "Approve a focused pilot to validate release defensibility, isotope-to-patient traceability, radioactive material accountability, auditor evidence mapping, and executive passport generation.",
        "best_first_pilot": "Release Defensibility + Isotope-to-Patient Evidence Graph + Radioactive Material Accountability Ledger + Auditor Question-to-Evidence + Passport Factory."
    }

    expansion_path = [
        {
            "stage": "Pilot",
            "scope": "One site, one dose journey, one release pathway.",
            "goal": "Prove evidence mapping, readiness scoring, passports, and inspection response value."
        },
        {
            "stage": "Site Rollout",
            "scope": "One full site across multiple release pathways.",
            "goal": "Expand readiness assurance across QA, QC, manufacturing, supply chain, and treatment coordination."
        },
        {
            "stage": "Network Rollout",
            "scope": "Multiple sites and treatment hubs.",
            "goal": "Enable cross-site network readiness, fallback planning, and commercial scale-up assurance."
        },
        {
            "stage": "Enterprise Governance Layer",
            "scope": "Multiple products, sites, systems, and inspection programs.",
            "goal": "Create enterprise operational trust layer across commercial radiopharma operations."
        }
    ]

    return {
        "executive_case_score": executive_case_score,
        "recommendation": recommendation,
        "status_class": status_class,
        "executive_answer": executive_answer,
        "roi_percent": roi_percent,
        "pilot_value": round(pilot_value),
        "annualized_value": round(annualized_value),
        "net_pilot_value": round(net_pilot_value),
        "pilot_cost": round(pilot_cost),
        "weekly_time_savings_hours": round(weekly_time_savings_hours, 1),
        "readiness_delta": round(readiness_delta, 1),
        "evidence_delta": round(evidence_delta, 1),
        "complexity_score": complexity_score,
        "pilot_scope": pilot_scope,
        "pilot_phases": pilot_phases,
        "success_metrics": success_metrics,
        "evidence_inputs": evidence_inputs,
        "roi_breakdown": roi_breakdown,
        "buyer_value": buyer_value,
        "risk_controls": risk_controls,
        "executive_narrative": executive_narrative,
        "expansion_path": expansion_path,
        "inputs": {
            "pilot_sites": pilot_sites,
            "dose_journeys": dose_journeys,
            "release_events": release_events,
            "audit_questions": audit_questions,
            "evidence_packets": evidence_packets,
            "source_systems": source_systems,
            "pilot_weeks": pilot_weeks,
            "current_manual_hours_per_week": current_manual_hours_per_week,
            "expected_time_reduction_percent": expected_time_reduction_percent,
            "hourly_loaded_cost": hourly_loaded_cost,
            "avoided_rework_events": avoided_rework_events,
            "cost_per_rework_event": cost_per_rework_event,
            "avoided_inspection_findings": avoided_inspection_findings,
            "value_per_avoided_finding": value_per_avoided_finding,
            "pilot_cost": pilot_cost,
            "readiness_baseline": readiness_baseline,
            "target_readiness": target_readiness,
            "evidence_maturity_baseline": evidence_maturity_baseline,
            "target_evidence_maturity": target_evidence_maturity
        },
        "governance_note": "Pilot Readiness & ROI Justification Engine™ is an advisory commercial planning layer. Financial estimates are directional and must be validated by the buyer, finance, QA, compliance, and operational leadership."
    }


@app.route("/irlt-commercial-readiness/pilot-roi")
@app.route("/rlttrust/pilot-roi")
@app.route("/rlttrust/pilot-readiness-roi")
def rlttrust_pilot_readiness_roi_engine():
    payload = {
        "pilot_sites": request.args.get("pilot_sites", 1),
        "dose_journeys": request.args.get("dose_journeys", 10),
        "release_events": request.args.get("release_events", 10),
        "audit_questions": request.args.get("audit_questions", 25),
        "evidence_packets": request.args.get("evidence_packets", 60),
        "source_systems": request.args.get("source_systems", 6),
        "pilot_weeks": request.args.get("pilot_weeks", 8),
        "current_manual_hours_per_week": request.args.get("current_manual_hours_per_week", 45),
        "expected_time_reduction_percent": request.args.get("expected_time_reduction_percent", 35),
        "hourly_loaded_cost": request.args.get("hourly_loaded_cost", 125),
        "avoided_rework_events": request.args.get("avoided_rework_events", 4),
        "cost_per_rework_event": request.args.get("cost_per_rework_event", 6500),
        "avoided_inspection_findings": request.args.get("avoided_inspection_findings", 2),
        "value_per_avoided_finding": request.args.get("value_per_avoided_finding", 25000),
        "pilot_cost": request.args.get("pilot_cost", 150000),
        "readiness_baseline": request.args.get("readiness_baseline", 72),
        "target_readiness": request.args.get("target_readiness", 88),
        "evidence_maturity_baseline": request.args.get("evidence_maturity_baseline", 60),
        "target_evidence_maturity": request.args.get("target_evidence_maturity", 90),
    }

    result = _rlttrust_pilot_roi_data(payload)

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Pilot Readiness & ROI Justification Engine™ | RLTTrust™</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            :root {
                --orange: #ff7a18;
                --orange2: #ff9f1c;
                --amber: #ffd166;
                --charcoal: #07080c;
                --panel: rgba(20, 24, 33, 0.88);
                --line: rgba(255,255,255,0.12);
                --text: #f4f7fb;
                --muted: #aeb6c6;
                --green: #37d67a;
                --red: #ff5c7a;
            }

            body {
                margin: 0;
                font-family: Inter, Segoe UI, Arial, sans-serif;
                color: var(--text);
                background:
                    radial-gradient(circle at 10% 0%, rgba(255,122,24,0.24), transparent 30%),
                    radial-gradient(circle at 92% 8%, rgba(255,159,28,0.16), transparent 34%),
                    radial-gradient(circle at 50% 32%, rgba(255,255,255,0.055), transparent 30%),
                    linear-gradient(135deg, #050608 0%, #11151f 46%, #06070b 100%);
            }

            .wrap {
                max-width: 1920px;
                margin: 0 auto;
                padding: 34px 46px;
            }

            .hero {
                position: relative;
                overflow: hidden;
                border: 1px solid rgba(255,122,24,0.32);
                border-radius: 36px;
                padding: 36px;
                background:
                    linear-gradient(135deg, rgba(255,122,24,0.20), rgba(20,24,33,0.93) 38%, rgba(7,8,12,0.96)),
                    repeating-linear-gradient(90deg, rgba(255,255,255,0.025) 0 1px, transparent 1px 76px);
                box-shadow: 0 34px 120px rgba(0,0,0,0.56);
            }

            .hero:after {
                content: "";
                position: absolute;
                right: -150px;
                top: -190px;
                width: 600px;
                height: 600px;
                border-radius: 50%;
                border: 1px solid rgba(255,122,24,0.25);
                box-shadow: inset 0 0 80px rgba(255,122,24,0.10), 0 0 100px rgba(255,122,24,0.12);
            }

            .hero-grid {
                position: relative;
                z-index: 2;
                display: grid;
                grid-template-columns: minmax(0, 1.65fr) minmax(380px, 0.72fr);
                gap: 30px;
                align-items: stretch;
            }

            .eyebrow {
                color: var(--orange2);
                text-transform: uppercase;
                font-size: 12px;
                letter-spacing: .16em;
                font-weight: 950;
                text-shadow: 0 0 18px rgba(255,122,24,0.28);
            }

            h1 {
                margin: 12px 0;
                font-size: clamp(42px, 4.8vw, 84px);
                line-height: .92;
                letter-spacing: -.06em;
            }

            h2 {
                font-size: clamp(24px, 2vw, 36px);
                letter-spacing: -.03em;
                margin: 0 0 16px;
            }

            h3 {
                margin: 0 0 8px;
                letter-spacing: -.02em;
            }

            p {
                color: var(--muted);
                line-height: 1.55;
            }

            .score-card {
                border-radius: 30px;
                padding: 26px;
                background: linear-gradient(180deg, rgba(255,122,24,0.12), rgba(15,18,26,0.92));
                border: 1px solid rgba(255,122,24,0.34);
                box-shadow: 0 22px 80px rgba(0,0,0,0.42);
            }

            .score {
                font-size: clamp(76px, 7vw, 132px);
                line-height: .85;
                font-weight: 950;
                letter-spacing: -.07em;
                color: var(--orange2);
                text-shadow: 0 0 35px rgba(255,122,24,0.34);
                margin: 18px 0;
            }

            .decision {
                display: inline-block;
                padding: 10px 14px;
                border-radius: 999px;
                font-size: 13px;
                font-weight: 950;
                text-transform: uppercase;
                letter-spacing: .08em;
            }

            .ready {
                background: rgba(55,214,122,0.12);
                border: 1px solid rgba(55,214,122,0.40);
                color: #b9ffd0;
            }

            .warning, .gap {
                background: rgba(255,209,102,0.12);
                border: 1px solid rgba(255,209,102,0.40);
                color: #ffe6a8;
            }

            .blocked {
                background: rgba(255,92,122,0.12);
                border: 1px solid rgba(255,92,122,0.40);
                color: #ffc2c2;
            }

            .nav {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-top: 22px;
            }

            .nav a {
                text-decoration: none;
                color: #f4f7fb;
                padding: 10px 14px;
                border-radius: 999px;
                background: rgba(255,255,255,0.06);
                border: 1px solid rgba(255,122,24,0.25);
                transition: transform .18s ease, border-color .18s ease, background .18s ease;
            }

            .nav a:hover {
                transform: translateY(-2px);
                border-color: rgba(255,122,24,0.72);
                background: rgba(255,122,24,0.13);
            }

            .section {
                margin-top: 32px;
            }

            .grid {
                display: grid;
                grid-template-columns: minmax(420px, .55fr) minmax(0, 1fr);
                gap: 22px;
                align-items: start;
            }

            .grid-2 {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 18px;
            }

            .grid-3 {
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 16px;
            }

            .grid-4 {
                display: grid;
                grid-template-columns: repeat(4, minmax(0, 1fr));
                gap: 16px;
            }

            .panel, .form-panel, .metric, .phase-card {
                border: 1px solid rgba(255,255,255,0.12);
                border-radius: 28px;
                padding: 22px;
                background:
                    linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.025)),
                    rgba(20,24,33,0.88);
                box-shadow: 0 24px 70px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.05);
                backdrop-filter: blur(14px);
            }

            .metric strong {
                display: block;
                font-size: 34px;
                color: #fff2e6;
                letter-spacing: -.04em;
                margin-bottom: 8px;
            }

            .metric span {
                color: var(--muted);
                font-size: 13px;
            }

            label {
                display: block;
                color: #d8dde8;
                font-weight: 850;
                font-size: 12px;
                margin-bottom: 7px;
            }

            input {
                width: 100%;
                box-sizing: border-box;
                border: 1px solid rgba(255,122,24,0.25);
                background: rgba(5,6,8,0.72);
                color: white;
                border-radius: 14px;
                padding: 11px 12px;
                font-size: 14px;
                outline: none;
            }

            .form-grid {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 14px;
            }

            .button {
                margin-top: 18px;
                width: 100%;
                border: 0;
                border-radius: 18px;
                padding: 14px 16px;
                font-weight: 950;
                color: #1b1008;
                background: linear-gradient(135deg, var(--orange), var(--amber));
                cursor: pointer;
                box-shadow: 0 16px 45px rgba(255,122,24,0.26);
            }

            .bar {
                height: 10px;
                border-radius: 999px;
                overflow: hidden;
                background: rgba(255,255,255,0.08);
                border: 1px solid rgba(255,255,255,0.06);
                margin: 12px 0;
            }

            .bar span {
                display: block;
                height: 100%;
                border-radius: 999px;
                background: linear-gradient(90deg, #ff4d4d, #ff7a18, #ffd166, #37d67a);
                box-shadow: 0 0 18px rgba(255,122,24,0.30);
            }

            .phase-flow {
                display: grid;
                grid-template-columns: repeat(6, minmax(300px, 1fr));
                gap: 16px;
                overflow-x: auto;
                padding-bottom: 10px;
            }

            .phase-card {
                min-height: 360px;
                position: relative;
            }

            .phase-card:after {
                content: "→";
                position: absolute;
                right: -22px;
                top: 50%;
                transform: translateY(-50%);
                color: var(--orange2);
                font-size: 34px;
                font-weight: 950;
                text-shadow: 0 0 20px rgba(255,122,24,0.40);
                z-index: 4;
            }

            .phase-card:last-child:after {
                display: none;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                overflow: hidden;
                border-radius: 24px;
                background: rgba(20,24,33,0.88);
                border: 1px solid rgba(255,255,255,0.12);
            }

            th, td {
                padding: 15px;
                border-bottom: 1px solid rgba(255,255,255,0.10);
                text-align: left;
                vertical-align: top;
                color: var(--muted);
                font-size: 14px;
            }

            th {
                color: #fff2e6;
                background: rgba(255,122,24,0.10);
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: .09em;
            }

            td strong {
                color: #fff2e6;
            }

            ul {
                margin: 10px 0 0 20px;
                padding: 0;
                color: var(--muted);
                line-height: 1.65;
            }

            .pill {
                display: inline-block;
                margin: 5px 6px 5px 0;
                padding: 8px 10px;
                border-radius: 999px;
                background: rgba(255,122,24,0.10);
                border: 1px solid rgba(255,122,24,0.30);
                color: #ffd7ad;
                font-size: 12px;
                font-weight: 850;
            }

            .note {
                color: #ffd7ad;
                border: 1px solid rgba(255,122,24,0.30);
                background: rgba(255,122,24,0.08);
                border-radius: 18px;
                padding: 14px;
                margin-top: 18px;
            }

            @media (max-width: 1250px) {
                .hero-grid, .grid, .grid-2, .grid-3, .grid-4, .form-grid {
                    grid-template-columns: 1fr;
                }
                .wrap {
                    padding: 24px;
                }
            }
        </style>
    </head>
    <body>
        <div class="wrap">
            <section class="hero">
                <div class="hero-grid">
                    <div>
                        <div class="eyebrow">RLTTrust™ Commercial Pilot Justification</div>
                        <h1>Pilot Readiness & ROI Justification Engine™</h1>
                        <p>
                            Converts RLTTrust™ from a product demo into a buyer-ready pilot proposal.
                            It defines pilot scope, implementation phases, evidence inputs, success metrics,
                            ROI narrative, buyer value, risk controls, and executive expansion path.
                        </p>
                        <p>
                            This gives leadership a practical reason to approve a focused pilot instead of treating the platform as only a concept demo.
                        </p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness">Command Center</a>
                            <a href="/irlt-commercial-readiness/buyer-demo">Buyer Demo</a>
                            <a href="/irlt-commercial-readiness/passport-factory">Passport Factory</a>
                            <a href="/irlt-commercial-readiness/release-defensibility">Release Defensibility</a>
                            <a href="/irlt-commercial-readiness/pilot-roi/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Executive Pilot Case Score</div>
                        <div class="score">{{ result.executive_case_score }}%</div>
                        <span class="decision {{ result.status_class }}">{{ result.recommendation }}</span>
                        <p>{{ result.executive_answer }}</p>
                    </div>
                </div>
            </section>

            <section class="section grid">
                <div class="form-panel">
                    <h2>Pilot Assumptions</h2>
                    <p>Adjust the pilot assumptions and recalculate the business case.</p>

                    <form method="get">
                        <div class="form-grid">
                            <div><label>Pilot Sites</label><input name="pilot_sites" type="number" min="1" max="25" value="{{ result.inputs.pilot_sites }}"></div>
                            <div><label>Dose Journeys</label><input name="dose_journeys" type="number" min="1" value="{{ result.inputs.dose_journeys }}"></div>
                            <div><label>Release Events</label><input name="release_events" type="number" min="1" value="{{ result.inputs.release_events }}"></div>
                            <div><label>Auditor Questions</label><input name="audit_questions" type="number" min="1" value="{{ result.inputs.audit_questions }}"></div>
                            <div><label>Evidence Packets</label><input name="evidence_packets" type="number" min="1" value="{{ result.inputs.evidence_packets }}"></div>
                            <div><label>Source Systems</label><input name="source_systems" type="number" min="1" max="50" value="{{ result.inputs.source_systems }}"></div>
                            <div><label>Pilot Weeks</label><input name="pilot_weeks" type="number" min="2" max="52" value="{{ result.inputs.pilot_weeks }}"></div>
                            <div><label>Manual Hours / Week</label><input name="current_manual_hours_per_week" type="number" step="0.1" min="0" value="{{ result.inputs.current_manual_hours_per_week }}"></div>
                            <div><label>Expected Time Reduction %</label><input name="expected_time_reduction_percent" type="number" min="0" max="95" value="{{ result.inputs.expected_time_reduction_percent }}"></div>
                            <div><label>Loaded Hourly Cost $</label><input name="hourly_loaded_cost" type="number" min="1" value="{{ result.inputs.hourly_loaded_cost }}"></div>
                            <div><label>Avoided Rework Events</label><input name="avoided_rework_events" type="number" min="0" value="{{ result.inputs.avoided_rework_events }}"></div>
                            <div><label>Cost / Rework Event $</label><input name="cost_per_rework_event" type="number" min="0" value="{{ result.inputs.cost_per_rework_event }}"></div>
                            <div><label>Avoided Inspection Findings</label><input name="avoided_inspection_findings" type="number" min="0" value="{{ result.inputs.avoided_inspection_findings }}"></div>
                            <div><label>Value / Avoided Finding $</label><input name="value_per_avoided_finding" type="number" min="0" value="{{ result.inputs.value_per_avoided_finding }}"></div>
                            <div><label>Pilot Cost $</label><input name="pilot_cost" type="number" min="0" value="{{ result.inputs.pilot_cost }}"></div>
                            <div><label>Readiness Baseline %</label><input name="readiness_baseline" type="number" min="0" max="100" value="{{ result.inputs.readiness_baseline }}"></div>
                            <div><label>Target Readiness %</label><input name="target_readiness" type="number" min="0" max="100" value="{{ result.inputs.target_readiness }}"></div>
                            <div><label>Evidence Maturity Baseline %</label><input name="evidence_maturity_baseline" type="number" min="0" max="100" value="{{ result.inputs.evidence_maturity_baseline }}"></div>
                            <div><label>Target Evidence Maturity %</label><input name="target_evidence_maturity" type="number" min="0" max="100" value="{{ result.inputs.target_evidence_maturity }}"></div>
                        </div>
                        <button class="button" type="submit">Recalculate Pilot ROI</button>
                    </form>
                </div>

                <div>
                    <h2>Pilot Business Case Summary</h2>
                    <div class="grid-3">
                        <div class="metric"><strong>${{ "{:,}".format(result.pilot_value) }}</strong><span>Total Pilot Value</span></div>
                        <div class="metric"><strong>${{ "{:,}".format(result.net_pilot_value) }}</strong><span>Net Pilot Value</span></div>
                        <div class="metric"><strong>{{ result.roi_percent }}%</strong><span>Directional Pilot ROI</span></div>
                        <div class="metric"><strong>${{ "{:,}".format(result.annualized_value) }}</strong><span>Annualized Value</span></div>
                        <div class="metric"><strong>{{ result.weekly_time_savings_hours }}</strong><span>Saved Hours / Week</span></div>
                        <div class="metric"><strong>{{ result.readiness_delta }}%</strong><span>Readiness Lift Target</span></div>
                    </div>

                    <div class="panel" style="margin-top:18px;">
                        <h2>Recommended Pilot Scope</h2>
                        <p>{{ result.pilot_scope.recommended_scope }}</p>
                        <h3>Start With</h3>
                        {% for module in result.pilot_scope.starting_modules %}
                        <span class="pill">{{ module }}</span>
                        {% endfor %}
                        <h3 style="margin-top:18px;">Defer Until Later</h3>
                        {% for item in result.pilot_scope.defer_until_later %}
                        <span class="pill">{{ item }}</span>
                        {% endfor %}
                        <div class="note">{{ result.pilot_scope.why_this_scope }}</div>
                    </div>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <div class="eyebrow">Pilot Implementation Roadmap</div>
                    <h2>Six-Phase Pilot Plan</h2>
                    <div class="phase-flow">
                        {% for phase in result.pilot_phases %}
                        <div class="phase-card">
                            <div class="eyebrow">{{ phase.duration }}</div>
                            <h3>{{ phase.phase }}</h3>
                            <p>{{ phase.objective }}</p>
                            <h4>Outputs</h4>
                            <ul>
                                {% for output in phase.outputs %}
                                <li>{{ output }}</li>
                                {% endfor %}
                            </ul>
                            <div class="note"><strong>Success Metric:</strong> {{ phase.success_metric }}</div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>ROI Breakdown</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Category</th>
                                <th>Calculation</th>
                                <th>Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for item in result.roi_breakdown %}
                            <tr>
                                <td><strong>{{ item.category }}</strong></td>
                                <td>{{ item.calculation }}</td>
                                <td>${{ "{:,}".format(item.value) }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Success Metrics</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Metric</th>
                                <th>Baseline</th>
                                <th>Target</th>
                                <th>Proof</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for metric in result.success_metrics %}
                            <tr>
                                <td><strong>{{ metric.metric }}</strong></td>
                                <td>{{ metric.baseline }}</td>
                                <td>{{ metric.target }}</td>
                                <td>{{ metric.proof }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Evidence Inputs Required</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Evidence Input</th>
                                <th>Source</th>
                                <th>Owner</th>
                                <th>Pilot Use</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for item in result.evidence_inputs %}
                            <tr>
                                <td><strong>{{ item.input }}</strong></td>
                                <td>{{ item.source }}</td>
                                <td>{{ item.owner }}</td>
                                <td>{{ item.pilot_use }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Buyer Value by Stakeholder</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Buyer</th>
                                <th>Value</th>
                                <th>Module</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for value in result.buyer_value %}
                            <tr>
                                <td><strong>{{ value.buyer }}</strong></td>
                                <td>{{ value.value }}</td>
                                <td>{{ value.module }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Pilot Risk Controls</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Risk</th>
                                <th>Control</th>
                                <th>Owner</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for risk in result.risk_controls %}
                            <tr>
                                <td><strong>{{ risk.risk }}</strong></td>
                                <td>{{ risk.control }}</td>
                                <td>{{ risk.owner }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Executive Narrative</h2>
                    <p><strong style="color:#fff2e6;">Headline:</strong> {{ result.executive_narrative.headline }}</p>
                    <p><strong style="color:#fff2e6;">Why Now:</strong> {{ result.executive_narrative.why_now }}</p>
                    <p><strong style="color:#fff2e6;">Pilot Thesis:</strong> {{ result.executive_narrative.pilot_thesis }}</p>
                    <p><strong style="color:#fff2e6;">Decision Request:</strong> {{ result.executive_narrative.decision_request }}</p>
                    <div class="note"><strong>Best First Pilot:</strong> {{ result.executive_narrative.best_first_pilot }}</div>
                </div>

                <div class="panel">
                    <h2>Expansion Path</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Stage</th>
                                <th>Scope</th>
                                <th>Goal</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for stage in result.expansion_path %}
                            <tr>
                                <td><strong>{{ stage.stage }}</strong></td>
                                <td>{{ stage.scope }}</td>
                                <td>{{ stage.goal }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    <div class="note">{{ result.governance_note }}</div>
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, result=result)


@app.route("/irlt-commercial-readiness/pilot-roi/api")
@app.route("/rlttrust/pilot-roi/api")
@app.route("/rlttrust/pilot-readiness-roi/api")
def rlttrust_pilot_readiness_roi_engine_api():
    payload = {
        "pilot_sites": request.args.get("pilot_sites", 1),
        "dose_journeys": request.args.get("dose_journeys", 10),
        "release_events": request.args.get("release_events", 10),
        "audit_questions": request.args.get("audit_questions", 25),
        "evidence_packets": request.args.get("evidence_packets", 60),
        "source_systems": request.args.get("source_systems", 6),
        "pilot_weeks": request.args.get("pilot_weeks", 8),
        "current_manual_hours_per_week": request.args.get("current_manual_hours_per_week", 45),
        "expected_time_reduction_percent": request.args.get("expected_time_reduction_percent", 35),
        "hourly_loaded_cost": request.args.get("hourly_loaded_cost", 125),
        "avoided_rework_events": request.args.get("avoided_rework_events", 4),
        "cost_per_rework_event": request.args.get("cost_per_rework_event", 6500),
        "avoided_inspection_findings": request.args.get("avoided_inspection_findings", 2),
        "value_per_avoided_finding": request.args.get("value_per_avoided_finding", 25000),
        "pilot_cost": request.args.get("pilot_cost", 150000),
        "readiness_baseline": request.args.get("readiness_baseline", 72),
        "target_readiness": request.args.get("target_readiness", 88),
        "evidence_maturity_baseline": request.args.get("evidence_maturity_baseline", 60),
        "target_evidence_maturity": request.args.get("target_evidence_maturity", 90),
    }
    return jsonify(_rlttrust_pilot_roi_data(payload))

# ============================================================
# End Pilot Readiness & ROI Justification Engine™
# ============================================================

'''

    # Add Pilot ROI link to the main command center navigation if available.
    nav_marker = "RLTTRUST_NAV_PILOT_ROI_ENGINE_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/buyer-demo">Buyer Demo</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_PILOT_ROI_ENGINE_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/pilot-roi">Pilot ROI</a>',
            1
        )
        print("Added Pilot Readiness & ROI Engine link to command center navigation.")
    else:
        print("Command center navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted Pilot Readiness & ROI Justification Engine successfully.")

