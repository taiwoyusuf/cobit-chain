from pathlib import Path

APP_PATH = Path("app.py")
text = APP_PATH.read_text(encoding="utf-8")

ACTIVE_MARKER = "RLTTRUST_CROSS_SITE_NETWORK_READINESS_MESH_V1_ACTIVE"

if ACTIVE_MARKER in text:
    print("Cross-Site RLT Network Readiness Mesh already installed. No duplicate insertion made.")
else:
    insert = r'''

# ============================================================
# RLTTRUST_CROSS_SITE_NETWORK_READINESS_MESH_V1_ACTIVE
# COBIT-Chain™ / AssuranceLayer™ Platform A
# Module: RLTTrust™ / IRLT Commercial Readiness Governance Command Center™
# Feature: Cross-Site RLT Network Readiness Mesh™
# Purpose: Multi-site commercial radiopharma readiness, capacity, redundancy,
#          release, logistics, treatment hub, and evidence-governance intelligence.
# AI is advisory only. Human governance remains authoritative.
# ============================================================

from flask import render_template_string, jsonify, request

def _rlttrust_mesh_num(value, default, minimum=0, maximum=1000):
    try:
        parsed = float(value)
    except Exception:
        parsed = float(default)
    return max(float(minimum), min(float(maximum), parsed))


def _rlttrust_mesh_int(value, default, minimum=0, maximum=1000):
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    return max(int(minimum), min(int(maximum), parsed))


def _rlttrust_cross_site_network_mesh_assessment(payload=None):
    payload = payload or {}

    primary_site = _rlttrust_mesh_num(payload.get("primary_site"), 88, 0, 100)
    secondary_site = _rlttrust_mesh_num(payload.get("secondary_site"), 82, 0, 100)
    tertiary_site = _rlttrust_mesh_num(payload.get("tertiary_site"), 76, 0, 100)
    qc_release_capacity = _rlttrust_mesh_num(payload.get("qc_release_capacity"), 81, 0, 100)
    qa_release_capacity = _rlttrust_mesh_num(payload.get("qa_release_capacity"), 79, 0, 100)
    hot_cell_capacity = _rlttrust_mesh_num(payload.get("hot_cell_capacity"), 74, 0, 100)
    isotope_supply_resilience = _rlttrust_mesh_num(payload.get("isotope_supply_resilience"), 83, 0, 100)
    courier_network = _rlttrust_mesh_num(payload.get("courier_network"), 86, 0, 100)
    treatment_hub_readiness = _rlttrust_mesh_num(payload.get("treatment_hub_readiness"), 80, 0, 100)
    fallback_capacity = _rlttrust_mesh_num(payload.get("fallback_capacity"), 68, 0, 100)
    evidence_integrity = _rlttrust_mesh_num(payload.get("evidence_integrity"), 91, 0, 100)
    regulatory_packet = _rlttrust_mesh_num(payload.get("regulatory_packet"), 84, 0, 100)
    network_data_integrity = _rlttrust_mesh_num(payload.get("network_data_integrity"), 87, 0, 100)

    daily_demand_pressure = _rlttrust_mesh_num(payload.get("daily_demand_pressure"), 72, 0, 100)
    open_network_risks = _rlttrust_mesh_int(payload.get("open_network_risks"), 3, 0, 50)
    cold_chain_exceptions = _rlttrust_mesh_int(payload.get("cold_chain_exceptions"), 1, 0, 50)
    release_bottlenecks = _rlttrust_mesh_int(payload.get("release_bottlenecks"), 2, 0, 50)
    treatment_hub_constraints = _rlttrust_mesh_int(payload.get("treatment_hub_constraints"), 2, 0, 50)
    evidence_gaps = _rlttrust_mesh_int(payload.get("evidence_gaps"), 3, 0, 100)
    site_variance = _rlttrust_mesh_num(payload.get("site_variance"), 12, 0, 100)

    manufacturing_average = (primary_site + secondary_site + tertiary_site) / 3
    release_average = (qc_release_capacity + qa_release_capacity) / 2
    logistics_average = (courier_network + treatment_hub_readiness) / 2
    governance_average = (evidence_integrity + regulatory_packet + network_data_integrity) / 3

    risk_penalty = min(open_network_risks * 3, 24)
    cold_chain_penalty = min(cold_chain_exceptions * 7, 35)
    release_penalty = min(release_bottlenecks * 6, 36)
    hub_penalty = min(treatment_hub_constraints * 5, 30)
    evidence_penalty = min(evidence_gaps * 3, 30)
    variance_penalty = min(site_variance * 0.7, 25)

    manufacturing_mesh_score = max(0, manufacturing_average - variance_penalty)
    release_mesh_score = max(0, release_average - release_penalty)
    logistics_mesh_score = max(0, logistics_average - cold_chain_penalty - hub_penalty)
    governance_mesh_score = max(0, governance_average - evidence_penalty)
    resilience_score = max(0, ((fallback_capacity + isotope_supply_resilience + hot_cell_capacity) / 3) - risk_penalty)

    # Demand stress: higher demand pressure reduces resilience unless fallback capacity and release capacity are strong.
    demand_absorption = (fallback_capacity + release_average + courier_network) / 3
    demand_gap = max(0, daily_demand_pressure - demand_absorption)
    demand_penalty = min(demand_gap * 0.8, 24)

    mesh_score = round(
        manufacturing_mesh_score * 0.18 +
        release_mesh_score * 0.17 +
        logistics_mesh_score * 0.16 +
        treatment_hub_readiness * 0.10 +
        resilience_score * 0.15 +
        governance_mesh_score * 0.14 +
        network_data_integrity * 0.05 +
        isotope_supply_resilience * 0.05 -
        demand_penalty
    )

    mesh_score = max(0, min(100, mesh_score))

    blockers = []
    warnings = []

    if primary_site < 75:
        blockers.append("Primary manufacturing site readiness is below commercial network threshold.")
    elif primary_site < 88:
        warnings.append("Primary manufacturing site has governance warnings.")

    if secondary_site < 70 and fallback_capacity < 70:
        blockers.append("Secondary site and fallback capacity are both weak; network redundancy is not defensible.")
    elif secondary_site < 80:
        warnings.append("Secondary site readiness needs strengthening for commercial redundancy.")

    if tertiary_site < 70:
        warnings.append("Tertiary/future capacity node is not yet mature enough for commercial relief.")

    if hot_cell_capacity < 70:
        blockers.append("Hot-cell capacity is below commercial scale-up threshold.")
    elif hot_cell_capacity < 82:
        warnings.append("Hot-cell capacity may become a scale-up bottleneck.")

    if qc_release_capacity < 75 or qa_release_capacity < 75:
        blockers.append("QC/QA release capacity is too weak for defensible network throughput.")
    elif qc_release_capacity < 85 or qa_release_capacity < 85:
        warnings.append("QC/QA release capacity may constrain commercial demand.")

    if isotope_supply_resilience < 75:
        blockers.append("Isotope supply resilience is below commercial continuity threshold.")
    elif isotope_supply_resilience < 85:
        warnings.append("Isotope supply resilience requires contingency planning.")

    if courier_network < 75 or cold_chain_exceptions >= 3:
        blockers.append("Courier/cold-chain network is not defensible under commercial demand.")
    elif courier_network < 85 or cold_chain_exceptions > 0:
        warnings.append("Courier/cold-chain network requires close monitoring.")

    if treatment_hub_readiness < 75 or treatment_hub_constraints >= 3:
        blockers.append("Treatment hub network is not sufficiently ready.")
    elif treatment_hub_readiness < 85 or treatment_hub_constraints > 0:
        warnings.append("Treatment hub constraints may affect patient-slot protection.")

    if fallback_capacity < 60:
        warnings.append("Fallback capacity is weak if a manufacturing or release node fails.")

    if evidence_integrity < 80 or evidence_gaps >= 6:
        blockers.append("Cross-site evidence integrity is below defensible threshold.")
    elif evidence_integrity < 90 or evidence_gaps > 0:
        warnings.append("Cross-site evidence package has gaps or stale records.")

    if regulatory_packet < 80:
        warnings.append("Regulatory/commercial readiness packet needs stronger cross-site evidence.")

    if site_variance > 20:
        warnings.append("Site-to-site readiness variance is high and may create inconsistent commercialization confidence.")

    if open_network_risks >= 6:
        blockers.append("Too many open network risks remain unresolved.")
    elif open_network_risks > 0:
        warnings.append("Open network risks require owner assignment and closure evidence.")

    if blockers:
        decision = "NETWORK NOT READY — commercial scale-up blocked"
        status_class = "blocked"
        executive_answer = "The RLT network should not be represented as commercially ready until critical site, release, logistics, evidence, or redundancy blockers are closed."
    elif mesh_score >= 90 and len(warnings) <= 2:
        decision = "NETWORK READY — inspection-defensible scale-up"
        status_class = "ready"
        executive_answer = "The network appears commercially ready with strong site readiness, release capacity, logistics resilience, evidence integrity, and fallback coverage."
    elif mesh_score >= 82:
        decision = "NETWORK READY WITH WARNINGS"
        status_class = "warning"
        executive_answer = "The network may support commercial scale-up, but leadership should review warnings before claiming full defensibility."
    elif mesh_score >= 70:
        decision = "NETWORK AT RISK — gaps remain"
        status_class = "gap"
        executive_answer = "The network has a credible foundation, but site, release, logistics, fallback, or evidence gaps remain."
    else:
        decision = "NETWORK NOT DEFENSIBLE"
        status_class = "blocked"
        executive_answer = "The RLT commercial network is not currently defensible under scale-up pressure."

    network_nodes = [
        {
            "node": "Primary Manufacturing Node",
            "score": round(primary_site),
            "status": "Strong" if primary_site >= 88 else "Warning" if primary_site >= 75 else "Blocked",
            "role": "Primary commercial RLT production site.",
            "risk": "If primary site weakens, commercial supply confidence drops immediately.",
            "control": "Run readiness passport, release defensibility, and manufacturing evidence review."
        },
        {
            "node": "Secondary Manufacturing Node",
            "score": round(secondary_site),
            "status": "Strong" if secondary_site >= 85 else "Warning" if secondary_site >= 70 else "Blocked",
            "role": "Redundancy and surge-capacity support.",
            "risk": "Weak secondary site limits recovery from primary site disruption.",
            "control": "Strengthen fallback manufacturing evidence and cross-site dependency readiness."
        },
        {
            "node": "Tertiary / Future Capacity Node",
            "score": round(tertiary_site),
            "status": "Strong" if tertiary_site >= 85 else "Warning" if tertiary_site >= 70 else "Maturing",
            "role": "Future expansion, geographic coverage, or relief capacity.",
            "risk": "Immature capacity node creates long-term commercial scale pressure.",
            "control": "Track validation, SOP, training, facility, release, and evidence readiness."
        },
        {
            "node": "QC Release Network",
            "score": round(qc_release_capacity),
            "status": "Strong" if qc_release_capacity >= 85 else "Warning" if qc_release_capacity >= 75 else "Blocked",
            "role": "QC throughput and method/result readiness.",
            "risk": "QC bottleneck can consume isotope window and delay release.",
            "control": "Run QC readiness governance and release timing analysis."
        },
        {
            "node": "QA Release Network",
            "score": round(qa_release_capacity),
            "status": "Strong" if qa_release_capacity >= 85 else "Warning" if qa_release_capacity >= 75 else "Blocked",
            "role": "Release review, release rationale, and batch disposition.",
            "risk": "QA release bottleneck compresses patient delivery window.",
            "control": "Run Release Defensibility Engine™ and QA release capacity review."
        },
        {
            "node": "Hot Cell / Production Capacity",
            "score": round(hot_cell_capacity),
            "status": "Strong" if hot_cell_capacity >= 85 else "Warning" if hot_cell_capacity >= 70 else "Blocked",
            "role": "Radiopharma production throughput and constrained equipment capacity.",
            "risk": "Hot-cell constraint can cap commercial growth regardless of demand.",
            "control": "Track equipment readiness, maintenance, validation, and scheduling constraints."
        },
        {
            "node": "Isotope Supply Resilience",
            "score": round(isotope_supply_resilience),
            "status": "Strong" if isotope_supply_resilience >= 85 else "Warning" if isotope_supply_resilience >= 75 else "Blocked",
            "role": "Source continuity and isotope availability.",
            "risk": "Supply interruption can affect all downstream readiness.",
            "control": "Track supplier readiness, receipt evidence, and contingency supply routes."
        },
        {
            "node": "Courier / Cold-Chain Mesh",
            "score": round(logistics_mesh_score),
            "status": "Strong" if logistics_mesh_score >= 85 else "Warning" if logistics_mesh_score >= 70 else "Blocked",
            "role": "Controlled movement from production to treatment hubs.",
            "risk": "Cold-chain or courier failure affects patient-slot protection.",
            "control": "Run custody governance, ETA confidence, exception tracking, and shipment passports."
        },
        {
            "node": "Treatment Hub Network",
            "score": round(treatment_hub_readiness),
            "status": "Strong" if treatment_hub_readiness >= 85 else "Warning" if treatment_hub_readiness >= 75 else "Blocked",
            "role": "Treatment-site readiness and appointment capacity.",
            "risk": "Treatment hub constraint can waste released product or delay patient care.",
            "control": "Run Patient Slot Protection Engine™ and treatment-site readiness attestation."
        },
        {
            "node": "Evidence Command Layer",
            "score": round(governance_mesh_score),
            "status": "Strong" if governance_mesh_score >= 88 else "Warning" if governance_mesh_score >= 75 else "Blocked",
            "role": "Cross-site evidence integrity, passports, audit response, and leadership confidence.",
            "risk": "Evidence gaps make readiness hard to defend across the network.",
            "control": "Run AuditVault™, Governance Passport™, and Inspection Tomorrow Simulator™."
        }
    ]

    network_scenarios = [
        {
            "scenario": "Primary Site Delay",
            "trigger": "Primary site cannot release within target window.",
            "propagation": "Primary production delay → QC/QA compression → courier re-routing → treatment slot exposure.",
            "network_response": "Activate secondary site fallback readiness, QA release prioritization, and patient-slot protection review.",
            "severity": "Critical" if fallback_capacity < 70 else "High"
        },
        {
            "scenario": "QC Bottleneck",
            "trigger": "QC release capacity below commercial demand.",
            "propagation": "QC queue → QA release delay → isotope decay pressure → patient treatment window risk.",
            "network_response": "Trigger QC readiness surge review, method capacity check, and release timing governance.",
            "severity": "High"
        },
        {
            "scenario": "Courier / Cold-Chain Exception",
            "trigger": "Courier route or cold-chain evidence exception.",
            "propagation": "Shipment delay → treatment site uncertainty → dose activity margin pressure → slot risk.",
            "network_response": "Activate custody escalation, alternate route assessment, and treatment hub notification.",
            "severity": "Critical" if cold_chain_exceptions >= 3 else "High"
        },
        {
            "scenario": "Treatment Hub Constraint",
            "trigger": "Treatment hub staffing, authorized-user, or appointment capacity issue.",
            "propagation": "Site readiness gap → appointment mismatch → viable dose may become unusable.",
            "network_response": "Run Patient Slot Protection Engine™ and evaluate backup slot or alternate hub.",
            "severity": "High"
        },
        {
            "scenario": "Evidence Gap Across Sites",
            "trigger": "Cross-site evidence missing, stale, or disconnected.",
            "propagation": "Evidence gap → inspection response weakness → leadership confidence reduction.",
            "network_response": "Run AuditVault™ verification and generate cross-site Commercial Readiness Passport.",
            "severity": "Major"
        }
    ]

    executive_domains = [
        {
            "name": "Manufacturing Mesh",
            "score": round(manufacturing_mesh_score),
            "description": "Primary, secondary, and tertiary production readiness with site-variance adjustment."
        },
        {
            "name": "QC/QA Release Mesh",
            "score": round(release_mesh_score),
            "description": "Release capacity, QC throughput, QA review, and bottleneck exposure."
        },
        {
            "name": "Logistics / Cold-Chain Mesh",
            "score": round(logistics_mesh_score),
            "description": "Courier network, cold-chain control, custody movement, and treatment-hub constraints."
        },
        {
            "name": "Resilience / Fallback Mesh",
            "score": round(resilience_score),
            "description": "Fallback capacity, isotope supply resilience, hot-cell capacity, and unresolved network risks."
        },
        {
            "name": "Evidence Governance Mesh",
            "score": round(governance_mesh_score),
            "description": "AuditVault™, Governance Passport™, regulatory packet, cross-site evidence integrity."
        },
        {
            "name": "Commercial Demand Absorption",
            "score": round(max(0, 100 - demand_penalty)),
            "description": "Ability to absorb commercial dose demand without overwhelming release, logistics, or fallback capacity."
        }
    ]

    actions = []
    for b in blockers:
        actions.append("Resolve blocker: " + b)
    for w in warnings[:7]:
        actions.append("Review warning: " + w)

    if mesh_score < 85:
        actions.append("Generate a Cross-Site Commercial Readiness Passport before leadership signoff.")
    if release_bottlenecks > 0:
        actions.append("Run Release Defensibility Engine™ across QC/QA release lanes.")
    if cold_chain_exceptions > 0:
        actions.append("Run Isotope-to-Patient Evidence Graph™ for affected courier routes.")
    if treatment_hub_constraints > 0:
        actions.append("Run Patient Slot Protection Engine™ for constrained hubs.")
    if evidence_gaps > 0:
        actions.append("Run AuditVault™ verification and close cross-site evidence gaps.")

    if not actions:
        actions.append("Proceed to final executive readiness review and export the Cross-Site Network Readiness Passport.")

    passport_outputs = [
        "Cross-Site Commercial Readiness Passport",
        "Network Release Capacity Passport",
        "Manufacturing Redundancy Passport",
        "QC/QA Throughput Passport",
        "Courier / Cold-Chain Mesh Passport",
        "Treatment Hub Readiness Passport",
        "Fallback Capacity Passport",
        "Cross-Site Inspection Survivability Packet",
        "Executive Commercial Scale-Up Readiness Packet"
    ]

    leadership_questions = [
        {
            "question": "Can the network support commercial demand if the primary site is delayed?",
            "answer": "Partially defensible" if fallback_capacity < 80 else "Defensible with fallback coverage",
            "evidence": "Manufacturing redundancy score, fallback capacity, secondary site readiness, release capacity, and cross-site passport."
        },
        {
            "question": "Where is the biggest commercial scale-up bottleneck?",
            "answer": "Hot-cell capacity and QA/QC release throughput are the current pressure points.",
            "evidence": "Hot-cell score, QC release capacity, QA release capacity, release bottleneck count, and demand pressure."
        },
        {
            "question": "Can dose delivery continue if cold-chain risk increases?",
            "answer": "Warning" if cold_chain_exceptions > 0 else "Currently stable",
            "evidence": "Courier network score, cold-chain exceptions, custody evidence, and treatment hub readiness."
        },
        {
            "question": "Can leadership defend cross-site readiness tomorrow?",
            "answer": "Yes with warnings" if mesh_score >= 82 else "Not fully defensible yet",
            "evidence": "Network readiness score, AuditVault™ evidence integrity, Governance Passport™, and Inspection Tomorrow Simulator™."
        }
    ]

    return {
        "mesh_score": mesh_score,
        "decision": decision,
        "status_class": status_class,
        "executive_answer": executive_answer,
        "manufacturing_mesh_score": round(manufacturing_mesh_score),
        "release_mesh_score": round(release_mesh_score),
        "logistics_mesh_score": round(logistics_mesh_score),
        "governance_mesh_score": round(governance_mesh_score),
        "resilience_score": round(resilience_score),
        "demand_penalty": round(demand_penalty),
        "blockers": blockers,
        "warnings": warnings,
        "network_nodes": network_nodes,
        "network_scenarios": network_scenarios,
        "executive_domains": executive_domains,
        "actions": actions,
        "passport_outputs": passport_outputs,
        "leadership_questions": leadership_questions,
        "inputs": {
            "primary_site": primary_site,
            "secondary_site": secondary_site,
            "tertiary_site": tertiary_site,
            "qc_release_capacity": qc_release_capacity,
            "qa_release_capacity": qa_release_capacity,
            "hot_cell_capacity": hot_cell_capacity,
            "isotope_supply_resilience": isotope_supply_resilience,
            "courier_network": courier_network,
            "treatment_hub_readiness": treatment_hub_readiness,
            "fallback_capacity": fallback_capacity,
            "evidence_integrity": evidence_integrity,
            "regulatory_packet": regulatory_packet,
            "network_data_integrity": network_data_integrity,
            "daily_demand_pressure": daily_demand_pressure,
            "open_network_risks": open_network_risks,
            "cold_chain_exceptions": cold_chain_exceptions,
            "release_bottlenecks": release_bottlenecks,
            "treatment_hub_constraints": treatment_hub_constraints,
            "evidence_gaps": evidence_gaps,
            "site_variance": site_variance
        },
        "governance_note": "This mesh is an advisory governance layer. It does not replace MES, LIMS, ERP, Veeva, ServiceNow, CTMS, logistics platforms, treatment scheduling, QA authority, radiation safety authority, or human leadership decision-making."
    }


@app.route("/irlt-commercial-readiness/network-readiness-mesh")
@app.route("/rlttrust/network-readiness-mesh")
@app.route("/rlttrust/cross-site-network-readiness-mesh")
def rlttrust_cross_site_network_readiness_mesh():
    payload = {
        "primary_site": request.args.get("primary_site", 88),
        "secondary_site": request.args.get("secondary_site", 82),
        "tertiary_site": request.args.get("tertiary_site", 76),
        "qc_release_capacity": request.args.get("qc_release_capacity", 81),
        "qa_release_capacity": request.args.get("qa_release_capacity", 79),
        "hot_cell_capacity": request.args.get("hot_cell_capacity", 74),
        "isotope_supply_resilience": request.args.get("isotope_supply_resilience", 83),
        "courier_network": request.args.get("courier_network", 86),
        "treatment_hub_readiness": request.args.get("treatment_hub_readiness", 80),
        "fallback_capacity": request.args.get("fallback_capacity", 68),
        "evidence_integrity": request.args.get("evidence_integrity", 91),
        "regulatory_packet": request.args.get("regulatory_packet", 84),
        "network_data_integrity": request.args.get("network_data_integrity", 87),
        "daily_demand_pressure": request.args.get("daily_demand_pressure", 72),
        "open_network_risks": request.args.get("open_network_risks", 3),
        "cold_chain_exceptions": request.args.get("cold_chain_exceptions", 1),
        "release_bottlenecks": request.args.get("release_bottlenecks", 2),
        "treatment_hub_constraints": request.args.get("treatment_hub_constraints", 2),
        "evidence_gaps": request.args.get("evidence_gaps", 3),
        "site_variance": request.args.get("site_variance", 12),
    }

    result = _rlttrust_cross_site_network_mesh_assessment(payload)

    html = """
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Cross-Site RLT Network Readiness Mesh™ | RLTTrust™</title>
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

            .panel, .form-panel, .metric, .node-card, .domain-card {
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
                font-size: 32px;
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

            .mesh-map {
                position: relative;
                min-height: 540px;
                border: 1px solid rgba(255,122,24,0.25);
                border-radius: 34px;
                overflow: hidden;
                background:
                    radial-gradient(circle at 50% 45%, rgba(255,122,24,0.20), transparent 18%),
                    radial-gradient(circle at 20% 20%, rgba(255,255,255,0.06), transparent 24%),
                    radial-gradient(circle at 82% 18%, rgba(255,159,28,0.12), transparent 26%),
                    rgba(15,18,26,0.90);
                box-shadow: 0 28px 90px rgba(0,0,0,0.42);
            }

            .mesh-core {
                position: absolute;
                left: 50%;
                top: 50%;
                width: 190px;
                height: 190px;
                transform: translate(-50%, -50%);
                border-radius: 50%;
                display: grid;
                place-items: center;
                text-align: center;
                background: radial-gradient(circle, rgba(255,122,24,0.34), rgba(22,24,31,0.94) 64%);
                border: 1px solid rgba(255,122,24,0.50);
                box-shadow: 0 0 90px rgba(255,122,24,0.22), inset 0 0 32px rgba(255,255,255,0.08);
            }

            .mesh-core b {
                display: block;
                font-size: 24px;
                color: white;
                letter-spacing: -.04em;
            }

            .mesh-core small {
                color: #ffd7ad;
                font-weight: 900;
                font-size: 10px;
                letter-spacing: .08em;
                text-transform: uppercase;
            }

            .mesh-node {
                position: absolute;
                width: 210px;
                border-radius: 22px;
                padding: 14px;
                border: 1px solid rgba(255,122,24,0.30);
                background: rgba(8,10,15,0.76);
                box-shadow: 0 18px 45px rgba(0,0,0,0.34);
            }

            .mesh-node b {
                display: block;
                color: #ffd7ad;
                margin-bottom: 4px;
            }

            .mesh-node span {
                color: var(--muted);
                font-size: 12px;
                line-height: 1.4;
            }

            .m1 { left: 5%; top: 10%; }
            .m2 { left: 38%; top: 6%; }
            .m3 { right: 5%; top: 10%; }
            .m4 { left: 4%; top: 42%; }
            .m5 { right: 4%; top: 42%; }
            .m6 { left: 16%; bottom: 8%; }
            .m7 { right: 16%; bottom: 8%; }

            .status-pill {
                display: inline-block;
                padding: 7px 10px;
                border-radius: 999px;
                font-size: 11px;
                font-weight: 950;
                text-transform: uppercase;
                margin-bottom: 10px;
            }

            .strong {
                color: #b9ffd0;
                border: 1px solid rgba(55,214,122,0.40);
                background: rgba(55,214,122,0.12);
            }

            .node-warning, .maturing {
                color: #ffe6a8;
                border: 1px solid rgba(255,209,102,0.40);
                background: rgba(255,209,102,0.12);
            }

            .node-blocked {
                color: #ffc2c2;
                border: 1px solid rgba(255,92,122,0.40);
                background: rgba(255,92,122,0.12);
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

            .passport {
                display: inline-block;
                margin: 6px;
                padding: 10px 12px;
                border-radius: 14px;
                background: rgba(255,122,24,0.10);
                border: 1px solid rgba(255,122,24,0.32);
                color: #ffd7ad;
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
                .mesh-map {
                    min-height: auto;
                    padding: 18px;
                }
                .mesh-core, .mesh-node {
                    position: relative;
                    left: auto !important;
                    right: auto !important;
                    top: auto !important;
                    bottom: auto !important;
                    transform: none;
                    width: auto;
                    height: auto;
                    margin: 12px 0;
                    border-radius: 22px;
                }
                .mesh-core {
                    padding: 28px;
                }
            }
        </style>
    </head>
    <body>
        <div class="wrap">
            <section class="hero">
                <div class="hero-grid">
                    <div>
                        <div class="eyebrow">RLTTrust™ Enterprise Scale-Up Intelligence</div>
                        <h1>Cross-Site RLT Network Readiness Mesh™</h1>
                        <p>
                            A multi-site commercial readiness engine for regulated radiopharma scale-up. It connects manufacturing sites,
                            QC/QA release lanes, hot-cell capacity, isotope supply, courier/cold-chain routes, treatment hubs,
                            fallback capacity, and cross-site evidence integrity into one executive governance mesh.
                        </p>
                        <p>
                            This is how RLTTrust™ moves from single-site readiness to enterprise commercial launch assurance.
                        </p>
                        <div class="nav">
                            <a href="/irlt-commercial-readiness">Command Center</a>
                            <a href="/irlt-commercial-readiness/can-we-treat-tomorrow">Can We Treat Tomorrow?</a>
                            <a href="/irlt-commercial-readiness/isotope-to-patient">Isotope-to-Patient Graph</a>
                            <a href="/irlt-commercial-readiness/inspection-tomorrow">Inspection Tomorrow</a>
                            <a href="/irlt-commercial-readiness/radioactive-material-ledger">Material Ledger</a>
                            <a href="/irlt-commercial-readiness/release-defensibility">Release Defensibility</a>
                            <a href="/irlt-commercial-readiness/patient-slot-protection">Patient Slot Protection</a>
                            <a href="/irlt-commercial-readiness/network-readiness-mesh/api">API Output</a>
                        </div>
                    </div>

                    <div class="score-card">
                        <div class="eyebrow">Network Readiness Mesh Score</div>
                        <div class="score">{{ result.mesh_score }}%</div>
                        <span class="decision {{ result.status_class }}">{{ result.decision }}</span>
                        <p>{{ result.executive_answer }}</p>
                    </div>
                </div>
            </section>

            <section class="section grid">
                <div class="form-panel">
                    <h2>Network Scenario Inputs</h2>
                    <p>Adjust cross-site readiness, demand pressure, redundancy, logistics, and evidence governance.</p>

                    <form method="get">
                        <div class="form-grid">
                            <div><label>Primary Site %</label><input name="primary_site" type="number" min="0" max="100" value="{{ result.inputs.primary_site }}"></div>
                            <div><label>Secondary Site %</label><input name="secondary_site" type="number" min="0" max="100" value="{{ result.inputs.secondary_site }}"></div>
                            <div><label>Tertiary / Future Site %</label><input name="tertiary_site" type="number" min="0" max="100" value="{{ result.inputs.tertiary_site }}"></div>
                            <div><label>QC Release Capacity %</label><input name="qc_release_capacity" type="number" min="0" max="100" value="{{ result.inputs.qc_release_capacity }}"></div>
                            <div><label>QA Release Capacity %</label><input name="qa_release_capacity" type="number" min="0" max="100" value="{{ result.inputs.qa_release_capacity }}"></div>
                            <div><label>Hot Cell Capacity %</label><input name="hot_cell_capacity" type="number" min="0" max="100" value="{{ result.inputs.hot_cell_capacity }}"></div>
                            <div><label>Isotope Supply Resilience %</label><input name="isotope_supply_resilience" type="number" min="0" max="100" value="{{ result.inputs.isotope_supply_resilience }}"></div>
                            <div><label>Courier Network %</label><input name="courier_network" type="number" min="0" max="100" value="{{ result.inputs.courier_network }}"></div>
                            <div><label>Treatment Hub Readiness %</label><input name="treatment_hub_readiness" type="number" min="0" max="100" value="{{ result.inputs.treatment_hub_readiness }}"></div>
                            <div><label>Fallback Capacity %</label><input name="fallback_capacity" type="number" min="0" max="100" value="{{ result.inputs.fallback_capacity }}"></div>
                            <div><label>Evidence Integrity %</label><input name="evidence_integrity" type="number" min="0" max="100" value="{{ result.inputs.evidence_integrity }}"></div>
                            <div><label>Regulatory Packet %</label><input name="regulatory_packet" type="number" min="0" max="100" value="{{ result.inputs.regulatory_packet }}"></div>
                            <div><label>Network Data Integrity %</label><input name="network_data_integrity" type="number" min="0" max="100" value="{{ result.inputs.network_data_integrity }}"></div>
                            <div><label>Daily Demand Pressure %</label><input name="daily_demand_pressure" type="number" min="0" max="100" value="{{ result.inputs.daily_demand_pressure }}"></div>
                            <div><label>Open Network Risks</label><input name="open_network_risks" type="number" min="0" max="50" value="{{ result.inputs.open_network_risks }}"></div>
                            <div><label>Cold-Chain Exceptions</label><input name="cold_chain_exceptions" type="number" min="0" max="50" value="{{ result.inputs.cold_chain_exceptions }}"></div>
                            <div><label>Release Bottlenecks</label><input name="release_bottlenecks" type="number" min="0" max="50" value="{{ result.inputs.release_bottlenecks }}"></div>
                            <div><label>Treatment Hub Constraints</label><input name="treatment_hub_constraints" type="number" min="0" max="50" value="{{ result.inputs.treatment_hub_constraints }}"></div>
                            <div><label>Evidence Gaps</label><input name="evidence_gaps" type="number" min="0" max="100" value="{{ result.inputs.evidence_gaps }}"></div>
                            <div><label>Site Variance %</label><input name="site_variance" type="number" min="0" max="100" value="{{ result.inputs.site_variance }}"></div>
                        </div>
                        <button class="button" type="submit">Recalculate Network Mesh Readiness</button>
                    </form>
                </div>

                <div>
                    <h2>Executive Mesh Domains</h2>
                    <div class="grid-3">
                        {% for d in result.executive_domains %}
                        <div class="metric">
                            <strong>{{ d.score }}%</strong>
                            <span>{{ d.name }}</span>
                            <div class="bar"><span style="width: {{ d.score }}%;"></span></div>
                            <p>{{ d.description }}</p>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </section>

            <section class="section">
                <div class="mesh-map">
                    <div class="mesh-core">
                        <div>
                            <small>RLTTrust™</small>
                            <b>Commercial Network Mesh</b>
                        </div>
                    </div>

                    <div class="mesh-node m1"><b>Primary Site</b><span>Manufacturing readiness, batch evidence, release dependency.</span></div>
                    <div class="mesh-node m2"><b>QC / QA Release</b><span>Throughput, release defensibility, bottleneck control.</span></div>
                    <div class="mesh-node m3"><b>Secondary Site</b><span>Fallback production, redundancy, surge readiness.</span></div>
                    <div class="mesh-node m4"><b>Isotope / Hot Cell</b><span>Supply resilience, capacity, constrained operations.</span></div>
                    <div class="mesh-node m5"><b>Courier / Cold Chain</b><span>Custody, ETA, exception handling, route confidence.</span></div>
                    <div class="mesh-node m6"><b>Treatment Hubs</b><span>Site readiness, authorized user readiness, patient-slot protection.</span></div>
                    <div class="mesh-node m7"><b>AuditVault™ Evidence</b><span>Cross-site passports, inspection evidence, governance lineage.</span></div>
                </div>
            </section>

            <section class="section">
                <h2>Network Nodes</h2>
                <div class="grid-4">
                    {% for node in result.network_nodes %}
                    <div class="node-card">
                        {% if node.status == "Strong" %}
                            <span class="status-pill strong">{{ node.status }}</span>
                        {% elif node.status == "Blocked" %}
                            <span class="status-pill node-blocked">{{ node.status }}</span>
                        {% else %}
                            <span class="status-pill node-warning">{{ node.status }}</span>
                        {% endif %}
                        <h3>{{ node.node }}</h3>
                        <div class="metric" style="padding:14px; margin:12px 0;">
                            <strong>{{ node.score }}%</strong>
                            <span>{{ node.role }}</span>
                            <div class="bar"><span style="width: {{ node.score }}%;"></span></div>
                        </div>
                        <p><strong style="color:#fff2e6;">Risk:</strong> {{ node.risk }}</p>
                        <p><strong style="color:#fff2e6;">Control:</strong> {{ node.control }}</p>
                    </div>
                    {% endfor %}
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Blockers and Warnings</h2>
                    {% if result.blockers %}
                    <h3>Blockers</h3>
                    <ul>
                        {% for b in result.blockers %}
                        <li>{{ b }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}

                    {% if result.warnings %}
                    <h3 style="margin-top:18px;">Warnings</h3>
                    <ul>
                        {% for w in result.warnings %}
                        <li>{{ w }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}

                    {% if not result.blockers and not result.warnings %}
                    <p>No blockers or warnings detected in this scenario.</p>
                    {% endif %}
                </div>

                <div class="panel">
                    <h2>Recommended Network Actions</h2>
                    <ul>
                        {% for action in result.actions %}
                        <li>{{ action }}</li>
                        {% endfor %}
                    </ul>
                    <div class="note">{{ result.governance_note }}</div>
                </div>
            </section>

            <section class="section">
                <div class="panel">
                    <h2>Commercial Scale-Up Stress Scenarios</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Scenario</th>
                                <th>Trigger</th>
                                <th>Propagation</th>
                                <th>Network Response</th>
                                <th>Severity</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for s in result.network_scenarios %}
                            <tr>
                                <td><strong>{{ s.scenario }}</strong></td>
                                <td>{{ s.trigger }}</td>
                                <td>{{ s.propagation }}</td>
                                <td>{{ s.network_response }}</td>
                                <td>{{ s.severity }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </section>

            <section class="section grid-2">
                <div class="panel">
                    <h2>Leadership Question-to-Evidence Layer</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Leadership Question</th>
                                <th>Answer</th>
                                <th>Evidence</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for q in result.leadership_questions %}
                            <tr>
                                <td><strong>{{ q.question }}</strong></td>
                                <td>{{ q.answer }}</td>
                                <td>{{ q.evidence }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>Network Passport Outputs</h2>
                    <p>These are the executive and inspection artifacts this mesh can generate.</p>
                    {% for p in result.passport_outputs %}
                    <span class="passport">{{ p }}</span>
                    {% endfor %}
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    return render_template_string(html, result=result)


@app.route("/irlt-commercial-readiness/network-readiness-mesh/api")
@app.route("/rlttrust/network-readiness-mesh/api")
@app.route("/rlttrust/cross-site-network-readiness-mesh/api")
def rlttrust_cross_site_network_readiness_mesh_api():
    payload = {
        "primary_site": request.args.get("primary_site", 88),
        "secondary_site": request.args.get("secondary_site", 82),
        "tertiary_site": request.args.get("tertiary_site", 76),
        "qc_release_capacity": request.args.get("qc_release_capacity", 81),
        "qa_release_capacity": request.args.get("qa_release_capacity", 79),
        "hot_cell_capacity": request.args.get("hot_cell_capacity", 74),
        "isotope_supply_resilience": request.args.get("isotope_supply_resilience", 83),
        "courier_network": request.args.get("courier_network", 86),
        "treatment_hub_readiness": request.args.get("treatment_hub_readiness", 80),
        "fallback_capacity": request.args.get("fallback_capacity", 68),
        "evidence_integrity": request.args.get("evidence_integrity", 91),
        "regulatory_packet": request.args.get("regulatory_packet", 84),
        "network_data_integrity": request.args.get("network_data_integrity", 87),
        "daily_demand_pressure": request.args.get("daily_demand_pressure", 72),
        "open_network_risks": request.args.get("open_network_risks", 3),
        "cold_chain_exceptions": request.args.get("cold_chain_exceptions", 1),
        "release_bottlenecks": request.args.get("release_bottlenecks", 2),
        "treatment_hub_constraints": request.args.get("treatment_hub_constraints", 2),
        "evidence_gaps": request.args.get("evidence_gaps", 3),
        "site_variance": request.args.get("site_variance", 12),
    }
    return jsonify(_rlttrust_cross_site_network_mesh_assessment(payload))

# ============================================================
# End Cross-Site RLT Network Readiness Mesh™
# ============================================================

'''

    # Add Cross-Site Network Mesh link to the main command center navigation if available.
    nav_marker = "RLTTRUST_NAV_NETWORK_READINESS_MESH_LINK_V1"
    nav_anchor = '<a href="/irlt-commercial-readiness/patient-slot-protection">Patient Slot Protection</a>'
    if nav_marker not in text and nav_anchor in text:
        text = text.replace(
            nav_anchor,
            nav_anchor + '\n                            <!-- RLTTRUST_NAV_NETWORK_READINESS_MESH_LINK_V1 -->\n                            <a href="/irlt-commercial-readiness/network-readiness-mesh">Network Readiness Mesh</a>',
            1
        )
        print("Added Cross-Site Network Readiness Mesh link to command center navigation.")
    else:
        print("Command center navigation link skipped or already present.")

    needle = '\nif __name__ == "__main__":'
    if needle not in text:
        needle = "\nif __name__ == '__main__':"

    if needle not in text:
        raise RuntimeError('Could not find Flask app entry point: if __name__ == "__main__":')

    text = text.replace(needle, "\n" + insert + "\n" + needle, 1)
    APP_PATH.write_text(text, encoding="utf-8")
    print("Inserted Cross-Site RLT Network Readiness Mesh successfully.")

