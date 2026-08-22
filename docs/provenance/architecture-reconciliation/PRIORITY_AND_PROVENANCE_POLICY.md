# COBIT-Chain™ Priority and Provenance Policy

## Objective
Create a defensible chronology for COBIT-Chain concepts, implementations, and verification evidence.

## Evidence hierarchy
1. public commit/tag/release with immutable Git object identity;
2. submitted or published manuscript / DOI / repository deposit;
3. signed or independently transmitted document;
4. dated controlled project artifact with SHA-256;
5. private development artifact with verifiable filesystem/history evidence;
6. retrospective narrative only.

## Classification
- `PRIOR_COBIT_CHAIN_CONCEPT` — supported by dated COBIT-Chain evidence.
- `ROADMAP_ONLY` — accepted direction, not implemented.
- `CANDIDATE` — constructed but not accepted/frozen.
- `IMPLEMENTED_UNVERIFIED` — code exists but governed acceptance is absent.
- `VERIFIED_IMPLEMENTATION` — implementation and governed evidence support the claim.

## Anti-overclaim rule
Never use a later GitHub commit to claim an earlier invention date. A later commit may document and hash earlier evidence, but the earlier evidence itself must support the priority claim.

## Attribution and ownership chronology
Capability and priority statements must be supported by the project's own dated evidence. Public-facing provenance records should identify what COBIT-Chain evidence establishes and avoid unnecessary comparative working notes. This policy is evidentiary, not argumentative.
