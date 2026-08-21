# TA-14 / Greggory Butler bounded live evidence protocol

Status: **CONTROLLED CHALLENGE PROTOCOL — R1 READ-ONLY**

Challenge ID: `TA14-VSA-GREG-R1-001`

## Bounded question

Can the deployed COBIT-Chain Azure MCP Gateway R1 exercise only its frozen, verified read-only Azure MCP surface while refusing prohibited write, RBAC, secret, and key routes before those routes reach the upstream Azure MCP endpoint?

## Frozen positive surface

Exactly three live tools are eligible:

1. `subscription_list`
2. `group_list`
3. `group_resource_list`

No wildcard is permitted. The existing deny-by-default policy remains authoritative.

## Negative restraint challenges

The challenge also submits the following names to the local authorization policy only:

- `group_create`
- `role_assignment_create`
- `keyvault_secret_get`
- `storage_account_listkeys`

A negative challenge passes only when the gateway rejects it locally and records `upstream_request_sent: false`.

These negative probes are intentionally **not** sent to Azure MCP. The demonstration therefore proves restraint at the gateway boundary; it does not claim Azure itself would deny those operations.

## Live protocol evidence

After a user completes the existing OAuth Authorization Code + PKCE S256 flow, the challenge endpoint:

1. initializes an authenticated MCP session;
2. captures a SHA-256 digest of the initialization response and a digest of server information;
3. retrieves the live `tools/list` catalog;
4. confirms the three frozen tools are present;
5. records a digest of each live input schema and selected MCP annotations;
6. invokes the three frozen tools;
7. records only response hashes and structural summaries, not raw Azure inventory;
8. performs the four local negative restraint challenges;
9. returns one canonical JSON evidence record with a final SHA-256 digest.

## Evidence minimization

The returned evidence record does **not** contain:

- OAuth access tokens;
- OAuth refresh tokens;
- browser session IDs;
- raw Azure subscription inventory;
- raw resource-group inventory;
- raw resource inventory;
- secrets, keys, credentials, or connection strings.

The `group_resource_list` target is the controlled Gateway R1 resource group. The returned record notes only the argument names and that the resource-group value was redacted.

## Pass criteria

`overall_pass` is true only if all of the following are true in the same challenge execution:

- all three frozen tools are present in the authenticated live catalog;
- all three live read-only tool calls return a non-error MCP response;
- all four prohibited names are denied locally;
- every negative record states `upstream_request_sent: false`;
- no protocol or safe-parameter-resolution error is recorded.

## Claims supported by a PASS

A PASS supports only the following bounded findings:

- the deployed gateway can establish an authenticated MCP session using the already activated PKCE flow;
- the live Azure MCP catalog contains the frozen R1 tools at the time of the demonstration;
- the gateway can execute those three read-only calls at the time of the demonstration;
- the gateway can refuse the specified prohibited routes before upstream dispatch;
- the evidence record can be independently integrity-checked using its SHA-256 digest.

## Non-claims

A PASS does **not** establish:

- authority to perform Azure writes;
- that every possible read operation is contextually appropriate;
- that future changed conditions preserve the same standing;
- that Azure itself would deny the four negative operations;
- that this R1 process-local OAuth session store is suitable for multi-replica production use;
- that human authority has been delegated to the gateway.

## Changed-condition rule

Any change to the allow-list, Azure MCP tool annotations/schema, OAuth client/scope, gateway image, target resource boundary, or relevant Azure authorization state invalidates automatic reuse of this finding and requires reassessment/replay.

## Execution route

After successful OAuth sign-in, issue an authenticated browser-session `POST` to:

`/challenge/ta14-greg`

The JSON response is the bounded evidence object intended for TA-14 exchange review.
