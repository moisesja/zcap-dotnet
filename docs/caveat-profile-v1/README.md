# Caveat profile v1 fixtures

Known-answer fixtures for [the caveat extension profile](../CAVEAT-PROFILE.md). They are
generated and checked byte-for-byte by
`tests/ZcapLd.Core.Tests/Caveats/CaveatProfileFixtureTests.cs`. Ed25519 is deterministic, so
any change means signing or canonicalization drifted. Regenerate them only on purpose, with
`ZCAP_REGENERATE_CAVEAT_FIXTURES=1 dotnet test`.

| File | Content |
| --- | --- |
| `epsilon-budget-context.jsonld` | Generated context `urn:zcap-dotnet:caveat-context:v1:EpsilonBudget` (one parameter, `maxEpsilon`) |
| `root.json` | Root capability for `https://clinical.example/fhir/Observation` |
| `orchestrator-grant.json` | Patient → orchestrator, `EpsilonBudget` 8 |
| `agent-grant.json` | Orchestrator → agent, `EpsilonBudget` 3 |
| `invocation.json` | Agent's Data Integrity invocation, action `query`, id `urn:uuid:9b7e3c1a-0d4f-4c41-8f0a-3a52c0e1b003` |
| `agent-grant-document.nquads` | RDFC-1.0 N-Quads of the agent grant without its proof |

Keys are `did:key` Ed25519 identities derived from fixed 32-byte seeds (test-only):

- patient: seed bytes `1…32`;
- orchestrator: seed bytes `33…64`;
- agent: seed bytes `65…96`.

All proofs are created `2026-10-27T00:00:00.000000Z`, and delegations expire
`2099-01-01T00:00:00.000000Z`.

Expected results:

- The agent grant's chain verifies as `CaveatEnforcementRequired`, with budgets 8 then 3.
- The invocation verifies as `Valid` once an `EpsilonBudget` handler allows it. Freshness must be
  widened to check the 2026 signature.
- Changing `maxEpsilon` anywhere breaks a signature.
