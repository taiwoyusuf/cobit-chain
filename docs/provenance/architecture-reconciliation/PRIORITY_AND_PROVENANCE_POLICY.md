# COBIT-Chain™ Priority and Provenance Policy

## Objective
Create a defensible chronology for concepts, architecture comparisons, refinements, implementations, and verification evidence.

## Evidence hierarchy
1. public commit/tag/release with immutable Git object identity;
2. submitted or published manuscript / DOI / repository deposit;
3. signed or independently transmitted document;
4. dated controlled project artifact with SHA-256;
5. private development artifact with verifiable filesystem/history evidence;
6. retrospective narrative only.

## Classification
- `PRIOR_COBIT_CHAIN_CONCEPT` — supported by COBIT-Chain evidence dated before the compared source.
- `PARALLEL_CONVERGENCE` — independently developed with insufficient evidence to establish priority.
- `SOURCE_INFORMED_REFINEMENT` — a later comparison materially sharpened or added a mechanism.
- `ROADMAP_ONLY` — accepted direction, not implemented.
- `CANDIDATE` — constructed but not accepted/frozen.
- `IMPLEMENTED_UNVERIFIED` — code exists but governed acceptance is absent.
- `VERIFIED_IMPLEMENTATION` — implementation and governed evidence support the claim.

## Anti-overclaim rule
Never use a later GitHub commit to claim an earlier invention date. A later commit may document and hash earlier evidence, but the earlier evidence itself must support the priority claim.

## Attribution and ownership chronology
Where earlier COBIT-Chain evidence establishes the concept, preserve it explicitly as COBIT-Chain chronology. Where another published source materially contributes a distinct refinement, preserve factual provenance rather than claiming unsupported authorship. This policy is evidentiary, not argumentative.