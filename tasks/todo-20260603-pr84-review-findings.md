# PR #84 review findings — severity-aware fail-closed logging + nits

Branch: `64-verification-logging` (PR #84). Plan approved at
`/Users/moises/.claude/plans/smooth-crafting-wozniak.md`.

## Findings & status

- [x] **Finding 1 (medium)** — Warning-level logging amplifies on attacker-controlled input.
  - [x] Added `LogFailedClosed(ex, template, args)` — Debug for expected validation/parse
        exceptions (`CapabilityValidationException`, `DelegationException`, `InvocationException`,
        `CaveatException`, `FormatException`, `JsonException`); Warning for everything else
        (incl. `CryptographicException` = missing-canonicalizer config fault).
  - [x] Routed all 6 fail-closed log sites through it.
  - [x] Added `DecodeProofValue` — retypes a malformed `proofValue` (`CryptographicException`
        from `MultibaseCodec.Decode`) as `CapabilityValidationException` so it classifies as
        Debug, without colliding with the missing-canonicalizer `CryptographicException`. Used
        at both decode sites.
- [x] **Finding 2 (low)** — CS0419 ambiguous cref → qualified `VerifyInvocationAsync(Invocation, Capability)`.
- [x] **Finding 3a (low)** — reworded `IsRevokerAuthorizedAsync` catch comment (dropped the
      inaccurate "crashing callers" framing; the outer `RevokeCapabilityAsync` catch already
      fails closed). Real value = locality + cause attributed to this step.
- [x] **Finding 3b (low)** — strengthened the revocation test to assert the specific
      `IsRevokerAuthorizedAsync` message (was satisfiable by the outer catch).
- [x] **Finding 4 (nit)** — informational (cumulative-branch non-compiling hazard); captured in
      `tasks/lessons.md`.

## Tests

- [x] `VerifyCapabilityChain_WhenItFailsClosed_LogsTheCause` → asserts Debug + "VerifyCapabilityChainAsync".
- [x] `RevokeCapability_WhenAuthorizationChainWalkFaults_FailsClosedAndLogs` → asserts Debug + "IsRevokerAuthorizedAsync".
- [x] **New** `VerifyCapabilityChain_WhenUnexpectedFaultOccurs_LogsAtWarning` → `ThrowingRevocationService`
      (InvalidOperationException) → asserts Warning. Guards the seam's Warning direction.

## Docs

- [x] CHANGELOG #64 entry refined (severity-aware logging; dropped overstated framing).
- [x] `tasks/lessons.md` updated.

## Verify

- [x] `dotnet build ZcapLd.sln --no-incremental` → CS0419 gone; remaining 7 warnings are all
      pre-existing `examples/ZcapLd.Examples/Program.cs` nullable warnings (untouched).
- [x] `dotnet test ZcapLd.sln` → 382 Core + 6 AspNetCore green (+1 net new test).

## Review

- All 4 findings addressed. The severity seam is guarded in both directions (Debug for expected
  attacker-drivable input, Warning for an injected non-library fault).
- Net behavior unchanged for callers: every path still fails closed (`false`); only log level and
  one internal exception type (`proofValue` decode → `CapabilityValidationException`) changed.
  Confirmed no test asserts an exception *type* from a verify path.
- `CryptographicException` deliberately stays at Warning so the missing-canonicalizer config fault
  (#64's flagship case) remains visible; the lone attacker vector sharing that type (bad
  `proofValue`) is retyped to Debug via `DecodeProofValue`.
