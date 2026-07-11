# Azure Enterprise Capability Registry — Platform B1 / MVP2

## Registry Status

Status: PLANNING LOCK  
Workstream: Platform B1 — Advanced Assurance Preview MVP  
Companion workstream: Thread D2 — RAMAT Vision Advanced Assurance Preview  
Future roadmap: Platform MVP3 / D3 Later  

This registry lists the Azure, Microsoft, security, AI, networking, identity, observability, and enterprise services that may be leveraged for Platform B1 / MVP2 and later Platform MVP3 / D3.

This file is documentation only.

No Azure resources are provisioned by this file.

---

# Core Boundary

Platform B1 thinks.

Thread D2 shows.

Azure Enterprise Assurance Fabric supports the assurance engine.

Platform B v1 remains validated and closed.

Thread D v1 remains validated and closed.

No Platform B v1 architecture is reopened.

No Thread D v1 connector is changed.

No real Halo hardware integration is required.

No real ServiceNow, LIS, middleware, eQMS, PHI, GMP production data, or company production data is required for MVP2.

Use mock data first.

Use simulator-first implementation.

---

# Depth Legend

| Depth | Meaning |
|---|---|
| Deep now | Build active MVP2 logic, inputs, outputs, mock evidence object, and dashboard/API result. |
| Medium now | Build simplified MVP2 logic or UI placeholder with deeper backend later. |
| Shallow now | Build preview card/demo output only. |
| MVP3 later | Roadmap only. Do not build now. |
| Azure foundation | Enterprise capability that supports multiple MVP2 features. |
| Licensing check | Useful, but may require Microsoft 365, Defender, Purview, Copilot, or tenant licensing beyond Azure credit. |

---

# Platform B1 / MVP2 Feature Dependency Summary

## Deep MVP2 Features

1. SERAPH Lite — Evidence Integrity Seal
2. Evidence Reconstruction Lite
3. Assurance Black Box Lite
4. AI-GMP Content Review Passport
5. AI-Generated Content Disclosure Lens
6. Human Oversight Effectiveness Assurance
7. Living SOP Assurance Lite
8. Action-to-SOP Admissibility
9. Workflow Dependency Assurance Lens
10. Regulatory AI Inspection Passport Lite
11. Claim-to-Proof Scanner
12. Source-of-Truth Compass
13. Assurance Persona & Role-Based Interface Passport

## Medium MVP2 Features

1. CAPA-to-SOP Impact Oracle
2. Deviation-to-SOP Truth Check
3. CAPA Effectiveness Mode Lite
4. Change Control Reconstruction Lite
5. GxP AI Boundary Assurance
6. Service Workflow No-Bind Lens
7. AI Artifact Transition Seal
8. Artifact-to-Action Bridge
9. Gesture-to-Intent Control Layer

## Shallow MVP2 Preview Cards

1. Evidence Weather
2. Regulatory Question Simulator
3. Regulatory Response Passport
4. Executive AI Governance Dashboard

## MVP3 Later Features

1. ARCHANGEL Full Assurance Ledger
2. CAPA Covenant Chain
3. Deviation Truth Timeline Full
4. Regulated Object Identity Full
5. Autopilot Agent Assurance Passport
6. Always-On Agent Black Box
7. Work Context Boundary Passport
8. Digital Twin-to-GMP Action Lens
9. Bioprocess Scale-Up Assurance Passport
10. Reimbursement Evidence Passport
11. Compliant Engagement Passport
12. Knowledge Graph Evidence Assurance
13. Private AI Runtime Control Passport
14. AI RMF-to-Assurance Evidence Bridge
15. Audit Trail Lens Full
16. Microsoft Scout-to-Assurance Gateway
17. Agent 365 Governance Bridge
18. Work IQ Boundary Assurance

---

# Special MVP2 Priority — Prakriti Feature

## Feature Name

Workflow Dependency Assurance Lens

## MVP2 Depth

Deep now.

## Purpose

Detect when a regulated workflow appears complete in one system but is actually blocked, incomplete, delayed, mismatched, or not defensible because of hidden dependencies across connected systems.

## Plain-English Problem

One screen says complete, but the full workflow is not truly complete.

## Applies To

- LIS
- middleware
- instruments
- instrument servers
- mapped fields
- manual result entry
- patient ID
- accession number
- order/result mapping
- mandatory audit/accountability fields
- interface latency
- communication failures
- firewall/time-out dependencies
- shift handoffs
- site-to-site process differences
- unofficial workarounds
- root-cause traceability

## MVP2 Components

1. Dependency Chain Map
2. Hidden Blocker Detector
3. LIS/Middleware Hold Check
4. Mandatory Field Gate
5. Mapping Conflict Check
6. Identity Match Check
7. Interface Latency Signal
8. Communication Path Check
9. Shift/Site Drift Signal
10. Manual Entry Risk Check
11. Secondary Review Gate
12. Audit Evidence Readiness
13. Root Cause Trace Path

## Outputs

- WORKFLOW COMPLETE
- WORKFLOW APPEARS COMPLETE BUT BLOCKED
- DEPENDENCY MISSING
- LIS HOLD DETECTED
- MIDDLEWARE VERIFIED ONLY
- MANDATORY FIELD MISSING
- MAPPING CONFLICT
- IDENTITY MISMATCH
- INTERFACE LATENCY DETECTED
- COMMUNICATION PATH BLOCKED
- SHIFT/SITE PROCESS DRIFT
- MANUAL ENTRY REVIEW REQUIRED
- SECONDARY REVIEW REQUIRED
- RESULT RELEASE NOT ADMISSIBLE
- DEPENDENCY CHAIN RECONSTRUCTED
- AUDIT EVIDENCE READY

## Azure Services Supporting This Feature

| Azure / Microsoft Service | Use |
|---|---|
| Cosmos DB | Store dependency graph and workflow state objects. |
| Azure AI Search | Retrieve supporting SOP/evidence/source records. |
| Document Intelligence | Extract fields from SOPs, reports, work instructions, forms, and evidence PDFs. |
| Event Grid | Publish workflow blocked/review required events. |
| Application Insights / Log Analytics | Capture latency, error, interface, and assurance-check telemetry. |
| Purview | Data owner, classification, lineage, source-of-truth governance. |
| Defender / Sentinel | Security and communication-path risk signals. |
| Private Link | Protect backend access to data/services. |
| API Management | Control APIs, rate limits, policies, versions. |
| Front Door / WAF | Protect public app routes where applicable. |
| Azure Digital Twins | MVP3 later: full dependency-chain graph model. |

---

# Azure Enterprise Capability Registry

## 1. Identity and Role-Based Access

| Capability | Azure / Microsoft Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| User authentication | Microsoft Entra ID | Sign in user before role-specific glasses view loads. | Azure foundation | User session passport | Mock first; live Entra later. |
| Role-based interface | Entra App Roles / Groups | Operator, Production Manager, QA, Auditor, Maintenance, IT/LCM, Vendor, Admin views. | Deep now | Role-based interface passport | Voice may request role; voice cannot grant role. |
| Conditional access readiness | Entra Conditional Access | Future MFA, device compliance, location/session policy. | Medium now | Access policy record | Do not block local MVP2 before mock role logic works. |
| Privileged access | Entra PIM readiness | Future elevated admin/QA/security role activation. | MVP3 later | Privileged role activation record | Do not implement privilege escalation in MVP2. |
| Credential-free access | Managed Identities | Allow Azure resources to call other Azure services without secrets in code. | Azure foundation | Managed identity access record | No secrets in browser, repo, or logs. |
| Authorization | Azure RBAC | Resource-level access control. | Azure foundation | RBAC mapping record | Least privilege by default. |

## 2. Secrets, Keys, and Configuration

| Capability | Azure / Microsoft Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| Secret storage | Key Vault | Store AI keys, function keys, connection strings, certificates. | Azure foundation | Secret reference record | No secrets in GitHub or browser. |
| Feature flags | Azure App Configuration | Deep/medium/shallow/MVP3 feature toggles. | Azure foundation | Feature flag record | MVP3 features remain locked. |
| App settings | Azure App Configuration | Centralized configuration for B1/D2. | Medium now | Configuration state record | Local mock config first. |
| Key governance | Key Vault logging | Track secret access and rotation readiness. | Medium now | Key access audit record | No secret values printed. |

## 3. Security Posture and Cloud Protection

| Capability | Azure / Microsoft Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| Cloud posture | Defender for Cloud | Security recommendations, secure score style tracking. | Azure foundation | Cloud posture record | Review recommendations before remediation. |
| Storage protection | Defender for Storage | Protect Blob/Table evidence stores. | Medium now | Storage protection record | Do not store PHI/GMP real data in MVP2. |
| Key protection | Defender for Key Vault | Monitor suspicious key/secret access. | Medium now | Key Vault security signal | No secrets exposed to app UI. |
| Function/App protection | Defender for App Service / Functions | Protect API/app workloads. | Medium now | Workload protection record | Keep B1 separate from B v1. |
| API protection | Defender for APIs where available | Monitor API security posture. | MVP3 later | API security posture record | Activate after API Management stabilizes. |
| Container protection | Defender for Containers | Later if Container Apps/AKS used. | MVP3 later | Container security record | Do not add AKS unless justified. |
| DevSecOps | Defender for DevOps / GitHub security where available | Secret scanning/code scanning/dependency scanning. | Medium now | DevSecOps scan record | No secrets committed. |

## 4. Security Operations

| Capability | Azure / Microsoft Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| SIEM/SOAR | Microsoft Sentinel | Security event monitoring and incident visibility. | Azure foundation | Sentinel incident record | Start with demo/security lab data. |
| Security analytics | Sentinel analytics rules | Detect suspicious platform activity. | Medium now | Analytics rule record | Do not create noisy rules blindly. |
| Workbooks | Sentinel / Azure Monitor Workbooks | Dashboards for security assurance. | Medium now | Security workbook record | Keep dashboards readable. |
| Playbooks | Logic Apps / Sentinel automation | Future automated response workflow. | MVP3 later | Security response playbook | Human approval for consequential actions. |
| XDR alignment | Microsoft Defender XDR | Future unified security operations. | Licensing check | XDR signal record | Depends on tenant licensing. |
| Security Copilot readiness | Security Copilot | Future AI-assisted security operations. | Licensing check | Security Copilot readiness record | Do not assume available by Azure credit alone. |

## 5. Network Security and Private Access

| Capability | Azure / Microsoft Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| Private access | Private Link / Private Endpoints | Keep Storage, Cosmos, Key Vault, Search off public network where practical. | Azure foundation | Private endpoint record | Configure carefully to avoid breaking local dev. |
| Virtual network | Azure Virtual Network | Controlled network boundary for enterprise lab. | Azure foundation | VNet design record | Start with architecture plan before deployment. |
| DNS | Private DNS Zones | Resolve private endpoints. | Medium now | Private DNS record | Document DNS dependencies. |
| Firewall | Azure Firewall | Central network inspection and egress control. | Medium now | Firewall policy record | Deploy after VNet plan is clear. |
| NSGs | Network Security Groups | Subnet and NIC traffic rules. | Medium now | NSG rule record | Least privilege. |
| NAT | NAT Gateway | Stable outbound IP where needed. | Medium now | Egress identity record | Use when external allowlisting is needed. |
| Bastion | Azure Bastion | Secure admin access to VMs if VMs are later used. | MVP3 later | Admin access record | Avoid VMs unless needed. |

## 6. Load Balancing, WAF, and API Gateway

| Capability | Azure / Microsoft Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| Global entry | Azure Front Door | Global routing and public edge entry for app/API. | Medium now | Front door route record | Add after local/API routes stabilize. |
| Web protection | WAF with Front Door | Protect public routes. | Medium now | WAF policy record | Start in detection mode before prevention. |
| Regional L7 routing | Application Gateway WAF | Regional load balancing and WAF inside VNet. | MVP3 later | App gateway route record | Not needed until VNet deployment matures. |
| API gateway | API Management | API policies, versioning, subscription keys, rate limits, analytics. | Medium now | API policy record | Add after B1 APIs are stable. |
| Rate limiting | API Management policies | Prevent abuse and prove control. | Medium now | Rate limit policy record | Do not block demos accidentally. |
| Health probes | Front Door / App Gateway | Monitor endpoint health. | Medium now | Health probe record | Use for resilience readiness. |
| Public endpoint protection | WAF + API Management | Protect D2/B1 public-facing routes. | Medium now | Public exposure record | Avoid exposing admin or secret endpoints. |

## 7. DDoS, Resilience, Backup, and Recovery

| Capability | Azure / Microsoft Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| DDoS protection | Azure DDoS Protection | Protect public workloads where applicable. | Medium now | DDoS protection record | Apply to VNet/public workloads where justified. |
| Backups | Azure Backup / Recovery Services Vault | Backup configuration and evidence. | Medium now | Backup readiness record | Start with storage/export backup plan. |
| Disaster recovery | Azure Site Recovery | Future DR for VM-based workloads. | MVP3 later | DR plan record | Avoid VMs unless required. |
| Zone redundancy | Zone-redundant services where practical | Resilience for production-like architecture. | Medium now | Resilience configuration record | Do not overbuild before B1 stabilizes. |
| Load testing | Azure Load Testing | Stress test APIs and UI routes. | Medium now | Load test evidence record | Use against test endpoints only. |
| Chaos testing | Azure Chaos Studio | Future resilience experiments. | MVP3 later | Chaos experiment record | Never test against production systems. |

## 8. Governance, Compliance, and FinOps

| Capability | Azure / Microsoft Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| Policy enforcement | Azure Policy | Enforce tags, locations, diagnostic settings, no public exposure where needed. | Azure foundation | Policy compliance record | Start with audit mode before deny. |
| Initiatives | Azure Policy initiatives | Group related governance controls. | Medium now | Policy initiative record | Keep policies understandable. |
| Resource inventory | Azure Resource Graph | Query Azure resources and compliance state. | Medium now | Resource inventory record | Use for dashboard evidence. |
| Tagging | Azure Tags / Policy | Owner, project, environment, data class, cost center. | Azure foundation | Tagging record | Require tags for B1 resources. |
| Cost governance | Cost Management / Budgets | Track spend, service usage, annual credit utilization. | Azure foundation | FinOps evidence record | Governance evidence, not cost fear. |
| Landing zone readiness | Azure Landing Zone pattern | Structure subscriptions/resource groups/networking. | MVP3 later | Landing zone design record | MVP2 can use smaller architecture first. |

## 9. Data Governance and Data Protection

| Capability | Azure / Microsoft Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| Data catalog | Microsoft Purview | Catalog evidence sources and data owners. | Medium now | Data catalog record | May require licensing/configuration. |
| Data classification | Purview | Classify evidence records and sensitive data. | Medium now | Data classification record | No real PHI/GMP production data in MVP2. |
| Data lineage | Purview | Show where evidence came from and how it moved. | Medium now | Lineage record | Start with mock lineage. |
| Retention | Purview / Storage lifecycle | Retention and disposition rules. | Medium now | Retention rule record | Do not delete evidence without policy. |
| Source of truth | Purview + Platform B1 | Strengthen Source-of-Truth Compass. | Deep now | Source-of-truth record | Official record remains in source system. |

## 10. Data Stores and Records

| Capability | Azure / Microsoft Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| JSON record store | Cosmos DB | Role passports, evidence seals, workflow graphs, inspection passports. | Azure foundation | JSON assurance object | Use mock data first. |
| Evidence files | Blob Storage | Evidence package files and mock uploads. | Already leveraged | Evidence file record | No PHI/GMP real data. |
| Tabular metadata | Table Storage | Lightweight metadata and registry records. | Already leveraged | Metadata record | Keep schema documented. |
| Relational option | Azure SQL Database | Future controlled relational evidence model. | MVP3 later | Relational evidence record | Only if Cosmos/Table are insufficient. |
| Cache | Azure Cache for Redis | Future session/performance cache. | MVP3 later | Cache state record | Not needed until load increases. |

## 11. AI Services and Evidence Intelligence

| Capability | Azure / Microsoft Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| AI orchestration | Azure AI Foundry | Build assurance assistants and evaluation workflows. | Azure foundation | AI project record | No unreviewed AI output as final authority. |
| LLM reasoning | Azure OpenAI | Summaries, explanations, inspection questions, evidence gap reasoning. | Medium now | AI reasoning record | AI suggests; Platform B decides. |
| Agent framework | Foundry Agent Service | Inspection readiness agent, workflow explanation agent. | MVP3 later | Agent run record | Agent actions require authority checks. |
| Search/RAG | Azure AI Search | SOP/evidence retrieval and source-of-truth search. | Azure foundation | Search retrieval record | Cite source records. |
| Document extraction | Document Intelligence | Extract SOP/report/form/evidence content. | Azure foundation | Extraction record | Low-confidence extraction requires review. |
| Speech | Azure AI Speech | Voice commands, dictated notes, translation preparation. | Medium now | Voice intent record | Voice command does not approve action. |
| Vision | Azure AI Vision | Asset label, equipment, document photo, gesture candidate. | Medium now | Visual context record | Visual match is candidate, not proof. |
| Content moderation | Azure AI Content Safety | Safety check prompts, notes, generated text/images. | Medium now | Content safety record | Unsafe output requires review/block. |
| Translation/language | Azure AI Translator / Language | Multilingual notes and interpretation support. | Medium now | Translation review record | Translation does not replace controlled document. |
| Model governance | Azure Machine Learning / Responsible AI Dashboard | Future model evaluation and governance. | MVP3 later | Model evaluation record | Use only when custom ML model exists. |

## 12. Eventing, Messaging, and Workflow Orchestration

| Capability | Azure / Microsoft Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| Event routing | Event Grid | Workflow blocked, evidence uploaded, review required events. | Medium now | Assurance event record | Events do not approve actions. |
| Reliable messaging | Service Bus | Queue review requests and assurance tasks. | Medium now | Message queue record | Avoid lost events. |
| Streaming | Event Hubs | Future high-volume telemetry/events. | MVP3 later | Event stream record | Not needed for low-volume MVP2. |
| Durable workflows | Durable Functions | Multi-step review/reconstruction workflows. | Medium now | Workflow instance record | Human approvals remain explicit. |
| Lightweight queue | Storage Queue | Simple background tasks. | Medium now | Queue task record | Use only for non-critical mock tasks. |
| Workflow integration | Logic Apps | Future approvals/notifications/security playbooks. | MVP3 later | Workflow automation record | Consequential actions require human approval. |

## 13. Real-Time Display and Glasses Interface

| Capability | Azure / Microsoft Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| Live updates | Azure SignalR Service | Live RAMAT Vision dashboard/session updates. | Medium now | Live session event | Do not show unauthorized data. |
| WebSocket messaging | Azure Web PubSub | Alternative live session transport. | Medium now | Realtime message record | Use one realtime service first. |
| Role-based D2 UI | Entra + Platform B1 mock role model | Production Manager, QA, Operator, Vendor views. | Deep now | Role view session record | Role verified before interface change. |
| Gesture simulation | D2 simulator | Gesture-to-Intent Control Layer. | Medium now | Intent signal record | Gesture does not approve GMP work. |

## 14. Device, Edge, and Wearable Readiness

| Capability | Azure / Microsoft Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| Device registry | IoT Hub | Future device registration and telemetry. | MVP3 later | Device identity record | D2 simulator first. |
| Device provisioning | Device Provisioning Service | Future zero-touch wearable/device onboarding. | MVP3 later | Device provisioning record | No real Halo dependency in MVP2. |
| Edge compute | IoT Edge | Future JEFERY relay/edge gateway pattern. | MVP3 later | Edge witness record | Edge does not decide. |
| Device update | Device Update for IoT Hub | Future firmware/software update posture. | MVP3 later | Device update record | Update must not change regulated behavior without review. |
| Local relay | JEFERY relay pattern | Simulated bridge between wearable and Platform B1. | Medium now | Relay event record | Relay sends context only. |

## 15. Microsoft 365, Scout, Agent 365, and Work Context

| Capability | Microsoft Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| Scout readiness | Microsoft Scout | Future personal desktop/local/M365 agent assurance. | MVP3 later | Scout action review record | Scout cannot approve GMP work. |
| Agent control plane | Microsoft Agent 365 | Future agent governance, inventory, risk, activity. | MVP3 later / licensing check | Agent passport record | Depends on availability/licensing. |
| Work context | Work IQ APIs | Future controlled access to Microsoft 365 work context. | MVP3 later / licensing check | Work context boundary record | Work context must be authorized and bounded. |
| Low-code agents | Copilot Studio | Possible assurance assistant prototype. | MVP3 later / licensing check | Copilot agent record | Agent output requires review. |
| M365 compliance | Purview / M365 compliance | Future email/document/retention integration. | Licensing check | Compliance evidence record | Do not ingest private mailbox data into MVP2 without explicit scope. |

## 16. Developer Experience and DevSecOps

| Capability | Tool / Service | MVP2 Use | Depth | Evidence Object | Guardrail |
|---|---|---|---|---|---|
| Source control | GitHub | Branches, PRs, tags, releases. | Already leveraged | Git evidence record | No secrets. |
| CI/CD | GitHub Actions / Azure DevOps | Test and deploy discipline. | Medium now | CI run record | Build before deploy. |
| Secret scanning | GitHub / Defender for DevOps | Catch accidental secrets. | Medium now | Secret scan record | Stop on secret findings. |
| Dependency scanning | GitHub / Defender for DevOps | Dependency risk. | Medium now | Dependency scan record | Review before merge. |
| Load tests in CI | Azure Load Testing + GitHub Actions | Performance evidence. | MVP3 later | Load test run record | Test non-production endpoints only. |

---

# Enterprise Capability Status Dashboard

| Build Wave | Capability Group | MVP2 Status |
|---|---|---|
| Wave 1 | Entra role model | Planned |
| Wave 1 | Managed Identity | Planned |
| Wave 1 | Cosmos DB | Planned |
| Wave 1 | App Configuration | Planned |
| Wave 1 | Key Vault updates | Planned |
| Wave 1 | Application Insights / Log Analytics | Planned |
| Wave 1 | Defender for Cloud | Planned |
| Wave 1 | Azure Policy | Planned |
| Wave 2 | Private Link / Private Endpoints | Planned |
| Wave 2 | Front Door + WAF | Planned |
| Wave 2 | API Management | Planned |
| Wave 2 | Load Testing | Planned |
| Wave 2 | Sentinel | Planned |
| Wave 3 | AI Search | Planned |
| Wave 3 | Document Intelligence | Planned |
| Wave 3 | Speech | Planned |
| Wave 3 | Vision | Planned |
| Wave 3 | Content Safety | Planned |
| Wave 3 | AI Foundry | Planned |
| Wave 4 | Event Grid | Planned |
| Wave 4 | Service Bus | Planned |
| Wave 4 | SignalR / Web PubSub | Planned |
| Wave 4 | IoT Hub / edge readiness | Planned |
| Wave 5 | Scout / Agent 365 / Work IQ readiness | MVP3 later |
| Wave 5 | Azure Digital Twins | MVP3 later |
| Wave 5 | ARCHANGEL Full Assurance Ledger | MVP3 later |

---

# D2 Display Mapping

Thread D2 should display Azure-backed assurance signals from Platform B1.

| Signal Group | D2 Example Outputs |
|---|---|
| Identity | USER SIGN-IN REQUIRED; ROLE VERIFIED; PRODUCTION MANAGER VIEW ACTIVE |
| Security posture | DEFENDER RECOMMENDATION OPEN; SECURITY MISCONFIGURATION FOUND |
| Security operations | SENTINEL INCIDENT FOUND; SECURITY RESPONSE REQUIRED |
| Network | PRIVATE ENDPOINT ACTIVE; PUBLIC EXPOSURE REVIEW REQUIRED |
| WAF/API | WAF POLICY ACTIVE; API POLICY ACTIVE; RATE LIMIT ACTIVE |
| Data governance | DATA OWNER IDENTIFIED; LINEAGE GAP FOUND |
| AI search | SUPPORTING EVIDENCE FOUND; EVIDENCE NOT FOUND |
| Document extraction | DOCUMENT EXTRACTED; REQUIRED FIELD MISSING |
| Speech | VOICE COMMAND RECEIVED; DICTATED NOTE CAPTURED |
| Vision | ASSET CANDIDATE DETECTED; LABEL CONFIDENCE LOW |
| Content safety | CONTENT SAFETY PASSED; CONTENT SAFETY REVIEW REQUIRED |
| Events | ASSURANCE EVENT PUBLISHED; WORKFLOW BLOCK EVENT CREATED |
| Realtime | LIVE ASSURANCE SIGNAL SENT; SESSION RECONNECTED |
| Device/edge | DEVICE REGISTERED; EDGE WITNESS ONLINE |
| Scout/Agent | SCOUT ACTION REVIEW REQUIRED; AGENT ACTION NOT ADMISSIBLE |

---

# Guardrail Registry

1. No Platform B v1 modification.
2. No Thread D v1 modification.
3. No secrets in GitHub.
4. No `.env` commits.
5. No Function keys in browser JavaScript.
6. No PHI or real GMP production data in MVP2.
7. AI may summarize, explain, retrieve, classify, or propose.
8. AI does not approve GMP work.
9. Voice may request a role; voice does not grant a role.
10. Gesture may express intent; gesture does not approve GMP work.
11. Glasses display state; Platform B1 evaluates state.
12. Official records remain in source systems.
13. MVP3 features remain locked until explicitly opened.
14. Enterprise Azure services must map to a purpose, evidence object, output, guardrail, owner, and wave.
15. Provisioning must happen in controlled waves, not all at once.

---

# Next Steps

## Step 2

Review this registry and confirm it captures:

- identity and role
- security
- load balancing
- private networking
- Defender
- Sentinel
- Purview
- Azure AI services
- Event Grid
- API Management
- telemetry
- device/edge readiness
- Microsoft Scout / Agent 365 / Work IQ readiness
- Prakriti Workflow Dependency Assurance Lens

## Step 3

After review, commit this registry as a planning artifact.

## Step 4

Create the Platform B1 / MVP2 file structure and feature registry.

## Step 5

Begin local mock implementation only.

Do not provision Azure services until the architecture and registry are committed.

