# COBIT-Chain™ GitHub Synchronization Policy

## Objective

Keep the public repository chronologically useful without allowing GitHub publication to overstate implementation maturity or alter frozen governed artifacts.

## Synchronization rule

After every material governed milestone, add or update a repository state/provenance record as soon as the milestone evidence is available.

Material milestones include:
- architecture/doctrine acceptance;
- roadmap family acceptance;
- requirements/schema freeze;
- implementation candidate construction;
- independent/static review;
- governed execution;
- PASS/STOP reconciliation;
- publication submission or acceptance state;
- research-gate state;
- productization/reconciliation state;
- deprecation, rejection, revocation, or supersession of earlier authority.

## Status separation

GitHub records must distinguish:
- `DOCUMENTED_DOCTRINE`
- `ROADMAP_ONLY`
- `RECONCILIATION_ONLY`
- `CANDIDATE`
- `REVIEWED_NOT_FROZEN`
- `APPROVED_AND_FROZEN`
- `IMPLEMENTED_UNVERIFIED`
- `SYNTHETICALLY_VERIFIED`
- `VERIFIED_IMPLEMENTATION`
- `GOVERNED_STOP`
- `EXECUTED_AND_CONSUMED`
- `NOT_AUTHORIZED`

A documentation commit is not implementation evidence.

## Frozen-artifact rule

Frozen Canonical Audit and other sealed artifacts must never be modified merely to make GitHub appear current. Current-state ledgers may reference their exact identities and controlling statuses.

## Public-safety / disclosure rule

Before mirroring local implementation artifacts:
1. confirm exact current Git inventory;
2. inspect for credentials, secrets, tokens, keys, private URLs, employer/proprietary data, participant/PHI data, or other restricted content;
3. preserve hashes and provenance;
4. select only authorized paths;
5. commit with an explicit governed-status message.

## Chronology rule

GitHub commit time proves public repository presence from the commit onward. Earlier priority claims must cite earlier controlled artifacts, hashes, submissions, publications, or commits rather than backdating a later GitHub commit.

## Reconciliation rule

Public architecture comparisons must not erase attribution or create duplicate COBIT-Chain engines. Where earlier COBIT-Chain evidence establishes a concept, preserve that chronology. Where a comparison materially sharpens an existing family, integrate the delta into the existing family unless a genuinely distinct capability is justified.

## Operational target

`GITHUB_DOCUMENTARY_STATE_LAG_TARGET <= 1 GOVERNED_MILESTONE`

Byte-level implementation synchronization remains separately governed and requires exact local repository evidence.