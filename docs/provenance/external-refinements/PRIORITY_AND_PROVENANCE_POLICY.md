# COBIT-Chain™ Priority and Provenance Policy

## Objective
Create a defensible chronology for concepts, refinements, implementations, and verification evidence.

## Evidence hierarchy
1. public commit/tag/release with immutable Git object identity;
2. submitted or published manuscript / DOI / repository deposit;
3. signed or independently transmitted document;
4. dated controlled project artifact with SHA-256;
5. private development artifact with verifiable filesystem/history evidence;
6. retrospective narrative only.

## Classification
- PRIOR_INTERNAL_CONCEPT — supported by COBIT-Chain evidence dated before the compared external source.
- PARALLEL_CONVERGENCE — independently developed with insufficient evidence to establish priority.
- EXTERNAL_REFINEMENT — external source materially sharpened or added the concept.
- ROADMAP_ONLY — accepted direction, not implemented.
- CANDIDATE — constructed but not accepted/frozen.
- IMPLEMENTED_UNVERIFIED — code exists but governed acceptance is absent.
- VERIFIED_IMPLEMENTATION — implementation and governed evidence support the claim.

## Anti-overclaim rule
Never use a later GitHub commit to claim an earlier invention date. A later commit may document and hash earlier evidence, but the earlier evidence itself must support the priority claim.

## Attribution rule
External contributors remain attributed wherever their material caused a genuine refinement. Prior internal concepts should be supported with pre-existing COBIT-Chain artifacts rather than by minimizing external attribution.
