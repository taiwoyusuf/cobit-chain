# Step 158 - Azure, On-Premises, Edge, Wearable, and Offline Deployment Plan

**Step 158 defines a deployment plan only. It does not deploy Azure resources, configure production integrations, connect real source systems, configure wearables, authorize PHI use, validate production systems, or execute regulated work.**

Foundation name: **Azure Enterprise Assurance Fabric Plus**

## Locked deployment doctrine

- Platform B v1 remains ARCHITECTURE LOCKED.
- Thread D v1 remains ARCHITECTURE LOCKED.
- Platform B1 remains the advanced assurance evaluation layer.
- Thread D, Thread D2, and RAMAT Vision remain DISPLAY / WITNESS ONLY.
- RAMAT Vision cannot approve, release, override, resolve No-Bind, execute actions, edit source records, or create authority.
- Qualified humans and authorized organizational roles remain accountable.
- Official records and executed actions remain in governed source systems.
- Action admissibility is not execution.
- No browser-exposed secrets.
- Managed identities, Key Vault, least privilege, private access, and same-origin delivery are preferred.
- Offline, stale, delayed, cached, and unknown states remain explicit.
- Step 158 authorizes synthetic and mock data only.

## Planned Azure enterprise services

- Azure Functions
- Azure Storage Account
- Azure Table Storage
- Azure Blob Storage
- Azure Key Vault
- Application Insights
- Log Analytics
- Microsoft Entra ID
- Entra app roles
- Managed Identities
- RBAC
- Conditional Access readiness
- Privileged Identity Management readiness
- Cosmos DB
- Azure AI Search
- Azure Document Intelligence
- Event Grid
- API Management readiness
- Front Door and WAF readiness
- Private Link readiness
- Microsoft Purview readiness
- Microsoft Defender readiness
- Microsoft Sentinel readiness
- Digital Twins future readiness
- Agent 365 and Scout future readiness

## Deployment profiles

| Profile | Purpose | Included components | Production use allowed |
|---|---|---|---|
| PROFILE-001 - Local Demonstration Profile | Local synthetic validation using the repository, mock APIs, simulated source systems, simulated edge devices, and simulated RAMAT displays. | DEP-016; simulated DEP-003; simulated DEP-013; simulated DEP-014 | False |
| PROFILE-002 - Azure Non-Production Assurance Lab | Non-production Azure deployment of Platform B1, controlled data services, eventing, observability, identity, and Thread D2 delivery. | DEP-001; DEP-003; DEP-004; DEP-006; DEP-007; DEP-008; DEP-009; DEP-010; DEP-012 | False |
| PROFILE-003 - Hybrid On-Premises Demonstration Profile | Non-production hybrid demonstration using bounded private connectors, Azure assurance evaluation, and simulated source-system references. | DEP-003; DEP-004; DEP-005; DEP-006; DEP-008; DEP-010; DEP-012 | False |
| PROFILE-004 - Edge and Wearable Demonstration Profile | Synthetic device-witness, QR, NFC, BLE, sensor, and wearable display demonstration. | DEP-003; DEP-006; DEP-012; DEP-013; DEP-014 | False |
| PROFILE-005 - Controlled Offline Demonstration Profile | Disconnected synthetic demonstration using expiring signed packages, explicit stale state, local integrity checking, and later reconciliation. | DEP-013; DEP-014; DEP-015; DEP-016 | False |

## Controlled deployment flows

| Flow | Path | Rule |
|---|---|---|
| FLOW-001 - Governed Use-Case Registration | Platform A -> Platform B v1 or Platform B1 | Governance context may inform assurance but does not create binding authority. |
| FLOW-002 - Source-State Observation | Governed source system -> Connector boundary -> Platform B1 | Source system remains authoritative; connector transmits bounded observed state. |
| FLOW-003 - Evidence Integrity Processing | Evidence reference -> Integrity store -> Hash/Rehash evaluation -> Platform B1 | Integrity metadata does not replace the official evidence record. |
| FLOW-004 - Advanced Assurance Evaluation | Identity + Evidence + Dependencies + Authority + Timing -> Platform B1 | Platform B1 evaluates state and may activate No-Bind or admissibility. |
| FLOW-005 - RAMAT Display Delivery | Platform B1 -> Thread D2 gateway -> RAMAT Vision | Only bounded, expiring, redacted display-contract fields may be delivered. |
| FLOW-006 - Authorized Source-System Execution | Platform admissibility -> Authorized human decision -> Governed source system | Admissibility is not execution; official execution remains in the source system. |
| FLOW-007 - Edge Witness Event | Device witness -> Edge gateway -> Event fabric -> Platform B1 | Device witness evidence is non-binding and requires identity and integrity verification. |
| FLOW-008 - Offline Reconciliation | Offline package -> Reauthentication -> Rehash -> Conflict review -> Platform B1 | Offline state is stale until reconciled; conflicts create a hold. |

## Deployment invariants

| ID | Invariant | Rule |
|---|---|---|
| DEP-INV-001 | Platform B v1 Remains Locked | Step 158 does not reopen or extend the frozen Platform B v1 architecture. |
| DEP-INV-002 | Thread D v1 Remains Locked | Step 158 does not reopen or extend the locked Thread D v1 connector. |
| DEP-INV-003 | Platform B1 Evaluates | Advanced assurance, identity, dependency, authority, No-Bind, and admissibility evaluation belongs to Platform B1. |
| DEP-INV-004 | RAMAT Displays Only | Thread D2 and RAMAT Vision remain DISPLAY / WITNESS ONLY. |
| DEP-INV-005 | No Browser-Exposed Secrets | Browsers and wearable clients must not receive storage keys, function keys, database secrets, or source-system credentials. |
| DEP-INV-006 | Managed Identity Preferred | Azure service-to-service access uses managed identity where supported. |
| DEP-INV-007 | Private Access Preferred | Data services and sensitive APIs use private endpoints, Private Link, or equivalent controlled network paths where supported. |
| DEP-INV-008 | Official Source Systems Remain Authoritative | COBIT-Chain references and evaluates evidence but does not replace official source-system records. |
| DEP-INV-009 | Admissibility Is Not Execution | Authorized humans and governed source systems remain responsible for binding action and execution. |
| DEP-INV-010 | Offline State Is Explicit | Offline, stale, cached, disconnected, delayed, and unknown states are never presented as current approval or authority. |
| DEP-INV-011 | Minimum Necessary Display | Wearables and dashboards receive only redacted, expiring, minimum-necessary display-contract fields. |
| DEP-INV-012 | Edge Witness Is Non-Binding | QR, NFC, BLE, sensors, gateways, and wearable observations provide witness evidence only. |
| DEP-INV-013 | No-Bind Survives Connectivity Loss | Loss of connectivity, telemetry, authority state, or source-state verification cannot silently clear a No-Bind hold. |
| DEP-INV-014 | Synthetic Data Boundary | Step 158 authorizes synthetic and mock data only. |
| DEP-INV-015 | Observability Without Secret Leakage | Logs and traces exclude credentials, tokens, full sensitive evidence, and unauthorized personal data. |
| DEP-INV-016 | Security State May Create Hold | Material security compromise, monitoring loss, or integrity uncertainty may activate a hold or No-Bind state. |

## Deployment-component register

| ID | Component | Deployment zone | Hosting model | Implementation status |
|---|---|---|---|---|
| DEP-001 | Platform A Governance and Use-Case Intake | AZURE GOVERNANCE PLANE | AZURE WEB AND GOVERNANCE SERVICES | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |
| DEP-002 | Platform B v1 Locked Assurance Core | AZURE LOCKED CORE PLANE | EXISTING PLATFORM B v1 DEPLOYMENT BOUNDARY | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |
| DEP-003 | Platform B1 Advanced Assurance Services | AZURE ADVANCED ASSURANCE PLANE | NEW PLATFORM B1 / MVP2 AZURE WORKSTREAM | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |
| DEP-004 | Assurance Evidence and Integrity Store | AZURE CONTROLLED DATA PLANE | AZURE STORAGE AND DATABASE SERVICES | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |
| DEP-005 | Source-System Connector Boundary | ON-PREMISES AND PRIVATE ENTERPRISE CONNECTOR ZONE | ON-PREMISES OR PRIVATE-NETWORK CONNECTOR SERVICES | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |
| DEP-006 | Azure Event and Assurance Signal Fabric | AZURE EVENT-DRIVEN ASSURANCE PLANE | AZURE EVENT SERVICES | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |
| DEP-007 | Azure AI Evidence Intelligence Services | AZURE AI EVIDENCE PLANE | AZURE AI SERVICES WITH GOVERNED ACCESS | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |
| DEP-008 | Identity, Role, and Privileged Access Fabric | AZURE IDENTITY AND ACCESS PLANE | MICROSOFT ENTRA AND GOVERNED ENTERPRISE ACCESS | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |
| DEP-009 | Enterprise Security Monitoring and Governance Signals | AZURE SECURITY OPERATIONS PLANE | AZURE AND ENTERPRISE SECURITY SERVICES | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |
| DEP-010 | Observability and Assurance Audit Telemetry | AZURE OBSERVABILITY PLANE | CENTRALIZED AZURE MONITORING SERVICES | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |
| DEP-011 | Thread D v1 Locked Context-Witness Connector | LOCKED DISPLAY CONNECTOR PLANE | EXISTING THREAD D v1 BOUNDARY | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |
| DEP-012 | Thread D2 and RAMAT Vision Delivery Gateway | AZURE ADVANCED DISPLAY DELIVERY PLANE | THREAD D2 / MVP2 SAME-ORIGIN DELIVERY WORKSTREAM | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |
| DEP-013 | Edge Assurance Gateway | SITE EDGE AND DEVICE-INGRESS PLANE | LOCAL EDGE SERVICE OR CONTROLLED GATEWAY DEVICE | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |
| DEP-014 | RAMAT Vision Wearable and Glasses Client | WEARABLE DISPLAY PLANE | GLASSES, MOBILE, OR WEARABLE SIMULATOR CLIENT | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |
| DEP-015 | Controlled Offline Assurance Package | OFFLINE AND DISCONNECTED OPERATIONS PLANE | ENCRYPTED LOCAL PACKAGE OR FIELD DEVICE CACHE | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |
| DEP-016 | Local Simulation and Validation Sandbox | LOCAL NON-PRODUCTION VALIDATION PLANE | WINDOWS LOCALHOST, PYTHON VIRTUAL ENVIRONMENT, AND MOCK SERVICES | DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED |

## Deployment-component details

### DEP-001 - Platform A Governance and Use-Case Intake

- Deployment zone: **AZURE GOVERNANCE PLANE**
- Hosting model: AZURE WEB AND GOVERNANCE SERVICES
- Purpose: Register regulated AI and assurance use cases, ownership, risk context, system inventory, governance classification, and commercialization track.
- Primary services: Azure Functions; Azure Storage; Microsoft Entra ID; managed identity; Application Insights; Log Analytics; governed API layer.
- Allowed data: Synthetic use-case metadata, mock owners, risk classifications, system references, control mappings, and governance status.
- Prohibited data: PHI, production credentials, raw company production records, classified data, or executable approval instructions.
- Identity and access: Entra sign-in, app roles, least privilege, managed identities, RBAC, Conditional Access readiness, and PIM readiness.
- Network boundary: HTTPS-only application boundary behind governed ingress and WAF readiness.
- Connectivity: Uses approved APIs and governed references; no direct uncontrolled browser access to source systems.
- Offline behavior: No binding offline operation. Cached governance context must be marked stale.
- Source-of-truth role: Governance registry only; not the official operational or regulated source record.
- Assurance role: Registers context but has no independent assurance-decision authority.
- Display role: May provide governed context to Platform B, Platform B1, Thread C, and authorized dashboards.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Define identity hardening, privileged administration, threat monitoring, and compromise response.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

### DEP-002 - Platform B v1 Locked Assurance Core

- Deployment zone: **AZURE LOCKED CORE PLANE**
- Hosting model: EXISTING PLATFORM B v1 DEPLOYMENT BOUNDARY
- Purpose: Preserve the frozen six-capability assurance core without architectural reopening.
- Primary services: Existing Platform B v1 application services and approved Azure dependencies only.
- Allowed data: Governed use-case records, synthetic evidence, trust scores, assurance-check inputs, admissibility records, and simulator messages.
- Prohibited data: Unapproved new Platform B v1 capabilities, direct production execution, browser secrets, PHI, or real regulated production records.
- Identity and access: Existing approved identity model; server-side secrets; managed identity readiness; least privilege.
- Network boundary: Frozen Platform B v1 application and API boundary.
- Connectivity: Receives governed inputs and emits bounded assurance state through approved interfaces.
- Offline behavior: No new offline capability introduced by Step 158.
- Source-of-truth role: Assurance record layer only; does not replace official source systems.
- Assurance role: Performs the locked Platform B v1 assurance evaluation functions.
- Display role: Supplies bounded state to the locked Thread D v1 connector.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Confirm frozen-core security baseline, failover boundary, logging, and trusted-update controls.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

### DEP-003 - Platform B1 Advanced Assurance Services

- Deployment zone: **AZURE ADVANCED ASSURANCE PLANE**
- Hosting model: NEW PLATFORM B1 / MVP2 AZURE WORKSTREAM
- Purpose: Evaluate evidence integrity, regulated-object identity, workflow dependencies, authority, human accountability, No-Bind state, admissibility, and reconstruction.
- Primary services: Azure Functions; Event Grid; Cosmos DB; Azure AI Search; Document Intelligence; Storage; Key Vault; Application Insights.
- Allowed data: Synthetic evidence metadata, hashes, rehash results, canonical mock identities, dependency states, authority states, No-Bind states, and display contracts.
- Prohibited data: Unapproved production source records, PHI, browser-exposed credentials, autonomous regulated execution, or hidden human-approval substitution.
- Identity and access: Managed identities, Entra app roles, RBAC, service-to-service authentication, Key Vault, Conditional Access readiness, and PIM readiness.
- Network boundary: Private endpoint and Private Link readiness; controlled API Management boundary; no public data-store access.
- Connectivity: Event-driven and API-mediated assurance evaluation using governed source references.
- Offline behavior: May queue synthetic events locally, but unresolved or stale state must remain unknown or held.
- Source-of-truth role: Evaluates referenced evidence and state; does not become the official operational record.
- Assurance role: Advanced assurance decision-support and No-Bind evaluation layer.
- Display role: Produces bounded state for Thread D2 and RAMAT Vision display contracts.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Define secure event ingestion, fail-closed behavior, replay protection, compromise holds, and recovery.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

### DEP-004 - Assurance Evidence and Integrity Store

- Deployment zone: **AZURE CONTROLLED DATA PLANE**
- Hosting model: AZURE STORAGE AND DATABASE SERVICES
- Purpose: Store synthetic evidence objects, governed references, hashes, rehash results, identity bindings, assurance snapshots, and reconstruction metadata.
- Primary services: Azure Blob Storage; Azure Table Storage; Cosmos DB; Storage Account; Key Vault.
- Allowed data: Synthetic files, mock records, integrity values, metadata, lifecycle state, object references, provenance links, and assurance-event records.
- Prohibited data: Unapproved production exports, PHI, plaintext secrets, uncontrolled source-system replicas, or classified data.
- Identity and access: Managed identity access, least privilege, separate read/write roles, and auditable administrative access.
- Network boundary: Private endpoint readiness, public-access restriction, storage firewall, and network-segment controls.
- Connectivity: Accessible only through approved server-side services and controlled administrative paths.
- Offline behavior: Offline packages use encrypted local cache and must reconcile before being treated as current.
- Source-of-truth role: Stores assurance evidence references and integrity metadata; official records remain in source systems.
- Assurance role: Supports hashing, rehashing, provenance, identity, and reconstruction.
- Display role: No direct wearable or browser access; display receives minimum necessary evaluated state.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Define backup, immutable retention readiness, key compromise handling, restore testing, and evidence-tamper response.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

### DEP-005 - Source-System Connector Boundary

- Deployment zone: **ON-PREMISES AND PRIVATE ENTERPRISE CONNECTOR ZONE**
- Hosting model: ON-PREMISES OR PRIVATE-NETWORK CONNECTOR SERVICES
- Purpose: Provide bounded read-only or simulation-safe access to governed source-system references without exposing source credentials or replacing official systems.
- Primary services: Private connector service; approved APIs; service accounts; managed gateway; API Management; Private Link or private network path where applicable.
- Allowed data: Governed record identifiers, status metadata, synthetic payloads, approved event metadata, and verification timestamps.
- Prohibited data: Direct browser database access, unrestricted production extracts, shared credentials, unapproved write-back, PHI, or uncontrolled source-system replication.
- Identity and access: Dedicated service identity, least privilege, read-only default, credential vaulting, certificate or managed-identity authentication where supported.
- Network boundary: Enterprise private network boundary with explicit firewall, proxy, route, and allow-list controls.
- Connectivity: Pull or event-based integration through controlled connectors; no ambient trust.
- Offline behavior: Connector outage produces UNKNOWN, STALE, DELAYED, or DEPENDENCY UNSATISFIED state.
- Source-of-truth role: Source systems remain authoritative; connector transmits governed references and observed state.
- Assurance role: Supplies source-state evidence to Platform B1 without making assurance decisions.
- Display role: No direct display authority.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Define connector authentication, network compromise detection, circuit breaking, fail-closed behavior, and recovery.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

### DEP-006 - Azure Event and Assurance Signal Fabric

- Deployment zone: **AZURE EVENT-DRIVEN ASSURANCE PLANE**
- Hosting model: AZURE EVENT SERVICES
- Purpose: Route synthetic assurance events, evidence changes, dependency-state changes, identity alerts, No-Bind events, and display-contract refresh signals.
- Primary services: Azure Event Grid; Azure Functions; Application Insights; Log Analytics; future service-bus readiness.
- Allowed data: Synthetic event envelopes, object IDs, event types, timestamps, correlation IDs, integrity references, and state changes.
- Prohibited data: Full uncontrolled source records, secrets, PHI, executable approvals, or unsigned privileged commands.
- Identity and access: Managed service identities, scoped event publishers and subscribers, and auditable authorization.
- Network boundary: Private event endpoints and governed subscriptions where supported.
- Connectivity: Event-driven, idempotent, correlated, and replay-aware assurance messaging.
- Offline behavior: Disconnected publishers queue only bounded synthetic events; delayed events are marked delayed and revalidated.
- Source-of-truth role: Transport only; not the official event or operational source of truth.
- Assurance role: Triggers evaluation and refresh but does not determine final assurance state.
- Display role: May trigger expiration or refresh of RAMAT display contracts.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Define signing, replay protection, dead-letter handling, poison-event quarantine, and recovery sequencing.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

### DEP-007 - Azure AI Evidence Intelligence Services

- Deployment zone: **AZURE AI EVIDENCE PLANE**
- Hosting model: AZURE AI SERVICES WITH GOVERNED ACCESS
- Purpose: Extract, index, compare, and retrieve synthetic evidence content for human-reviewed assurance and claim-to-proof demonstrations.
- Primary services: Azure AI Search; Azure Document Intelligence; governed model endpoint readiness; Cosmos DB; Storage.
- Allowed data: Synthetic documents, mock evidence packages, extracted metadata, controlled embeddings, and claim-to-proof links.
- Prohibited data: Unapproved proprietary production documents, PHI, model-training reuse without authorization, autonomous approval, or unsupported regulatory conclusions.
- Identity and access: Managed identities, private access readiness, restricted indexes, and explicit role separation.
- Network boundary: Private endpoint readiness and no direct public client access to evidence indexes.
- Connectivity: Server-side retrieval and extraction through controlled Platform B1 services.
- Offline behavior: No claim may be treated as verified when retrieval or extraction services are unavailable.
- Source-of-truth role: Evidence intelligence and retrieval support only; extracted content does not replace source documents.
- Assurance role: Supports evidence discovery and comparison; Platform B1 evaluates assurance.
- Display role: Only summarized, attributed, redacted results may enter display contracts.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Define prompt-injection resistance, document quarantine, model endpoint compromise response, and index recovery.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

### DEP-008 - Identity, Role, and Privileged Access Fabric

- Deployment zone: **AZURE IDENTITY AND ACCESS PLANE**
- Hosting model: MICROSOFT ENTRA AND GOVERNED ENTERPRISE ACCESS
- Purpose: Provide user, service, role, privileged-access, and application identity controls.
- Primary services: Microsoft Entra ID; Entra app roles; Managed Identities; RBAC; Conditional Access readiness; PIM readiness; Key Vault.
- Allowed data: Mock identities, role assignments, service principals, authorization metadata, and audit events.
- Prohibited data: Shared administrator credentials, browser-stored secrets, ungoverned local accounts, or silent privilege elevation.
- Identity and access: Zero-standing-privilege objective, least privilege, managed identities, role separation, and privileged activation readiness.
- Network boundary: Identity provider boundary with explicit application registration and redirect restrictions.
- Connectivity: Token-based user and service authentication with explicit audience and role validation.
- Offline behavior: Offline clients cannot create new authority. Cached identity state must be marked stale and non-binding.
- Source-of-truth role: Entra or the governed enterprise identity source remains authoritative for identity and role state.
- Assurance role: Provides identity and role evidence; Platform B1 evaluates authority sufficiency.
- Display role: RAMAT may display bounded role and authority state without exposing sensitive identity data.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Define credential compromise, token theft, emergency access, role-revocation propagation, and privileged-session review.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

### DEP-009 - Enterprise Security Monitoring and Governance Signals

- Deployment zone: **AZURE SECURITY OPERATIONS PLANE**
- Hosting model: AZURE AND ENTERPRISE SECURITY SERVICES
- Purpose: Provide security posture, threat, WAF, API, identity, endpoint, and incident signals that may create assurance holds or No-Bind states.
- Primary services: Microsoft Defender readiness; Microsoft Sentinel readiness; Log Analytics; Application Insights; Front Door/WAF readiness; API Management.
- Allowed data: Synthetic alerts, security-state metadata, policy outcomes, incident references, and assurance hold signals.
- Prohibited data: Unredacted production security secrets, exploit payloads in displays, unrestricted logs, or automatic approval bypass.
- Identity and access: Security-role separation, least privilege, managed identities, and controlled incident-response access.
- Network boundary: Security-monitoring plane separated from end-user display and application data planes.
- Connectivity: Security findings enter Platform B1 as governed evidence and dependency signals.
- Offline behavior: Loss of required security telemetry may create UNKNOWN, STALE, SECURITY HOLD, or NO-BIND state.
- Source-of-truth role: Security platforms remain authoritative for their own alerts and incident records.
- Assurance role: Provides security evidence; Platform B1 determines assurance consequences.
- Display role: RAMAT displays only bounded security assurance states and required human escalation.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Define compromise-state taxonomy, automatic containment boundaries, security No-Bind rules, and forensic preservation.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

### DEP-010 - Observability and Assurance Audit Telemetry

- Deployment zone: **AZURE OBSERVABILITY PLANE**
- Hosting model: CENTRALIZED AZURE MONITORING SERVICES
- Purpose: Capture application telemetry, evaluation traces, connector health, display-contract issuance, No-Bind events, failures, latency, and audit-support metadata.
- Primary services: Application Insights; Log Analytics; Azure Monitor readiness; diagnostic settings.
- Allowed data: Correlation IDs, synthetic object IDs, service health, event timing, errors, audit metadata, and security-safe diagnostics.
- Prohibited data: Secrets, tokens, full evidence payloads, PHI, sensitive proprietary content, or uncontrolled personal data.
- Identity and access: Separate telemetry writers and readers, least privilege, controlled analyst access, and retention governance.
- Network boundary: Central telemetry boundary with governed ingestion and restricted query access.
- Connectivity: All deployment zones emit structured, correlated, minimum-necessary telemetry.
- Offline behavior: Edge devices buffer bounded telemetry locally and mark upload gaps explicitly.
- Source-of-truth role: Observability evidence only; not the official regulated operational record.
- Assurance role: Supports health, failure, chronology, and reconstruction assurance.
- Display role: May provide service-health and freshness signals to authorized displays.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Define log integrity, retention, alert routing, tamper detection, monitoring blind-spot handling, and recovery.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

### DEP-011 - Thread D v1 Locked Context-Witness Connector

- Deployment zone: **LOCKED DISPLAY CONNECTOR PLANE**
- Hosting model: EXISTING THREAD D v1 BOUNDARY
- Purpose: Preserve the locked connector that displays or witnesses bounded Platform B v1 state.
- Primary services: Existing Thread D v1 connector and validated same-origin proxy pattern.
- Allowed data: Bounded Platform B v1 display state and synthetic simulator context.
- Prohibited data: New decision logic, Platform B1 advanced state, approval controls, execution controls, or exposed secrets.
- Identity and access: Existing approved access model with no browser-exposed secrets.
- Network boundary: Locked Thread D v1 connector boundary.
- Connectivity: Consumes only approved Platform B v1 state.
- Offline behavior: No new offline capability; unavailable state must not appear current.
- Source-of-truth role: Not a source system and not evidence authority.
- Assurance role: No assurance-decision authority.
- Display role: DISPLAY / WITNESS ONLY for Platform B v1.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Verify connector integrity, same-origin proxy security, fail-closed behavior, and trusted-update controls.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

### DEP-012 - Thread D2 and RAMAT Vision Delivery Gateway

- Deployment zone: **AZURE ADVANCED DISPLAY DELIVERY PLANE**
- Hosting model: THREAD D2 / MVP2 SAME-ORIGIN DELIVERY WORKSTREAM
- Purpose: Deliver expiring, redacted Platform B1 display contracts to RAMAT Vision, authorized browsers, and wearable simulators.
- Primary services: Thread D2 application; Azure Functions; same-origin proxy; API Management readiness; Front Door/WAF readiness; Application Insights.
- Allowed data: Approved display-contract fields, synthetic object identity, assurance state, No-Bind state, human prompts, expiry, and source references.
- Prohibited data: Approval controls, release controls, execution controls, No-Bind resolution controls, source-record editing, secrets, PHI, or unrestricted evidence payloads.
- Identity and access: Entra-authenticated sessions, role-based glasses interface, short-lived tokens, server-side secret access, and minimum-necessary authorization.
- Network boundary: WAF and API gateway readiness with same-origin browser delivery and no direct data-store access.
- Connectivity: Pulls only signed or governed Platform B1 display contracts.
- Offline behavior: Cached contracts are marked stale or unknown after expiry or connectivity loss.
- Source-of-truth role: Not a source system and not evidence authority.
- Assurance role: No assurance-decision authority.
- Display role: DISPLAY / WITNESS ONLY for Platform B1 evaluated state.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Define contract signing, token revocation, WAF policy, session compromise response, and display rollback.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

### DEP-013 - Edge Assurance Gateway

- Deployment zone: **SITE EDGE AND DEVICE-INGRESS PLANE**
- Hosting model: LOCAL EDGE SERVICE OR CONTROLLED GATEWAY DEVICE
- Purpose: Collect synthetic QR, NFC, BLE, sensor, equipment, custody, and wearable-witness events before governed transmission to Platform B1.
- Primary services: M5Stack or ESP32 simulator devices; local gateway service; secure event queue; certificate readiness; approved outbound API.
- Allowed data: Synthetic tag IDs, mock equipment IDs, sensor values, timestamps, device identity, custody events, local integrity values, and connectivity state.
- Prohibited data: PHI, production credentials, uncontrolled production sensor feeds, autonomous release commands, or shared device secrets.
- Identity and access: Unique device identity, certificate or per-device credential readiness, device registration, revocation readiness, and least-privileged outbound access.
- Network boundary: Outbound-only preferred; segmented site network; no direct inbound internet control path.
- Connectivity: Store-and-forward synthetic events with sequence, timestamp, correlation, and integrity metadata.
- Offline behavior: Queues bounded events; marks clock uncertainty, connectivity loss, stale state, and upload delay.
- Source-of-truth role: Device witness only; does not become official equipment, clinical, manufacturing, or custody record.
- Assurance role: Provides device-witness evidence; Platform B1 evaluates trust and admissibility.
- Display role: May show local connection and witness status only; no approval authority.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Define device identity, secure boot readiness, signed firmware, trusted update, revocation, loss, theft, cloning, and compromise handling.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

### DEP-014 - RAMAT Vision Wearable and Glasses Client

- Deployment zone: **WEARABLE DISPLAY PLANE**
- Hosting model: GLASSES, MOBILE, OR WEARABLE SIMULATOR CLIENT
- Purpose: Present minimum-necessary assurance, identity, dependency, authority, timing, No-Bind, and human-action prompts at the point of work.
- Primary services: Brilliant Labs Halo readiness; future Ray-Ban Meta, Vuzix, or RealWear readiness; mobile companion or simulator client.
- Allowed data: Expiring display-contract fields, synthetic object IDs, assurance state, human prompts, source references, and connection freshness.
- Prohibited data: Approval, release, override, No-Bind resolution, source-system editing, unredacted PHI, secrets, full evidence files, or uncontrolled recording.
- Identity and access: Role-based user session, paired-device trust, short-lived access, remote revocation readiness, and minimum-necessary display.
- Network boundary: No direct access to Azure data stores or source systems; communicates only through the delivery gateway.
- Connectivity: Receives bounded display contracts and may send non-binding acknowledgement or witness telemetry.
- Offline behavior: Displays STALE, UNKNOWN, or DISCONNECTED; never presents cached state as current approval or authority.
- Source-of-truth role: Not a source system and not evidence authority.
- Assurance role: No assurance-decision authority.
- Display role: DISPLAY / WITNESS ONLY.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Define device loss, screen privacy, recording restrictions, revocation, jailbreak/root detection readiness, and secure wipe.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

### DEP-015 - Controlled Offline Assurance Package

- Deployment zone: **OFFLINE AND DISCONNECTED OPERATIONS PLANE**
- Hosting model: ENCRYPTED LOCAL PACKAGE OR FIELD DEVICE CACHE
- Purpose: Support controlled disconnected demonstration of object identity, evidence integrity, display state, and later reconciliation without claiming current authority.
- Primary services: Encrypted local cache; signed manifest readiness; local hash verification; bounded event journal; reconciliation service.
- Allowed data: Synthetic object manifests, approved display fields, hashes, timestamps, sequence numbers, offline witness events, and explicit expiry metadata.
- Prohibited data: Current approval claims, autonomous regulated execution, unrestricted source records, PHI, production secrets, or unencrypted evidence packages.
- Identity and access: Pre-authorized device and user identities, local unlock control, package signature verification, expiry, and later online reauthentication.
- Network boundary: Disconnected boundary with no assumption of current source-system or authority state.
- Connectivity: No live dependency; reconciliation is required before offline evidence can affect current assurance state.
- Offline behavior: All authority, source, dependency, and timing states are marked OFFLINE, STALE, UNKNOWN, or HELD as applicable.
- Source-of-truth role: Offline package is not the official source record.
- Assurance role: Supports local integrity checks and witness collection only; no final admissibility decision.
- Display role: May display explicit offline and stale states with human escalation instructions.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Define package signing, expiry, encryption, anti-rollback, reconciliation conflicts, device loss, and secure destruction.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

### DEP-016 - Local Simulation and Validation Sandbox

- Deployment zone: **LOCAL NON-PRODUCTION VALIDATION PLANE**
- Hosting model: WINDOWS LOCALHOST, PYTHON VIRTUAL ENVIRONMENT, AND MOCK SERVICES
- Purpose: Provide a safe local environment for synthetic end-to-end tests, schema validation, wearable simulation, edge simulation, API testing, and evidence reconstruction.
- Primary services: Local repository; Python virtual environment; PowerShell 5.1; mock APIs; synthetic fixtures; local storage; simulator clients.
- Allowed data: Synthetic fixtures, mock identities, fictional AURORA-17 records, local hashes, test logs, and generated validation evidence.
- Prohibited data: PHI, company production data, production credentials, real regulated execution, or production network access.
- Identity and access: Local developer access with no production credentials and explicit separation from enterprise systems.
- Network boundary: Localhost or isolated development network only.
- Connectivity: Mock and simulator integrations only unless a separately governed non-production connector is approved.
- Offline behavior: Fully local simulation is permitted; all outputs remain local non-production evidence.
- Source-of-truth role: Local test output only; not production or regulatory validation evidence.
- Assurance role: Supports repeatable local validation of planned controls.
- Display role: May simulate Thread D2 and RAMAT Vision display contracts.
- Secret handling: NO BROWSER-EXPOSED SECRETS. USE MANAGED IDENTITIES, KEY VAULT, SERVER-SIDE SECRET RETRIEVAL, FUNCTION-KEY PROTECTION, AND THE APPROVED SAME-ORIGIN PROXY PATTERN.
- Encryption: ENCRYPT DATA IN TRANSIT AND AT REST. USE GOVERNED KEY MANAGEMENT, EXPLICIT KEY OWNERSHIP, ROTATION READINESS, AND AUDITABLE ACCESS.
- Data minimization: STORE OR TRANSMIT ONLY THE MINIMUM AUTHORIZED ASSURANCE METADATA, GOVERNED REFERENCES, SYNTHETIC DEMONSTRATION DATA, INTEGRITY VALUES, AND DISPLAY-CONTRACT FIELDS REQUIRED FOR THE USE CASE.
- Authority boundary: THE DEPLOYMENT COMPONENT DOES NOT CREATE INDEPENDENT APPROVAL, RELEASE, OVERRIDE, NO-BIND RESOLUTION, EXECUTION, OR BINDING AUTHORITY.
- Human accountability: QUALIFIED HUMANS AND AUTHORIZED ORGANIZATIONAL ROLES REMAIN ACCOUNTABLE FOR BINDING DECISIONS.
- Architecture boundary: PLATFORM B v1 AND THREAD D v1 REMAIN ARCHITECTURE LOCKED. PLATFORM B1 AND THREAD D2 ARE SEPARATE MVP2 WORKSTREAMS.
- Data boundary: PLAN-ONLY, SIMULATOR-FIRST, MOCK-DATA-FIRST, LOCAL-VALIDATION-FIRST. NO PHI, COMPANY PRODUCTION DATA, CLASSIFIED DATA, PAYMENT-CARD DATA, OR REAL REGULATED PRODUCTION INTEGRATION IS AUTHORIZED BY STEP 158.
- Step 159 dependency: Define development-environment hardening, dependency integrity, package trust, secret scanning, and test-evidence protection.
- Implementation status: **DEPLOYMENT PLAN ONLY - NOT IMPLEMENTED**

## Step 159 review gate

Before Step 159 begins, review all 16 deployment components, 5 deployment profiles, 8 controlled flows, and 16 invariants. Confirm identity, secret, network, private-access, encryption, telemetry, source-system, offline, edge, wearable, data-minimization, and human-authority boundaries.

Confirm that no component creates browser-exposed secrets, production approval, release, override, No-Bind resolution, autonomous execution, source-record editing, or official-record authority.

Step 159 will define security hardening, threat and compromise states, failover, backup and recovery, trusted updates, device revocation, event replay protection, offline reconciliation, evidence preservation, and compromise governance.

**STEP 158 AZURE, ON-PREMISES, EDGE, WEARABLE, AND OFFLINE DEPLOYMENT PLAN COMPLETE**

**STEP 159: READY AFTER REVIEW**

