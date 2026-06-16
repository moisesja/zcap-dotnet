# Security Scan Remediation — 2026-06-16

Branch: `security-scan-remediation`

Driven by a multi-agent security + W3C ZCAP-LD compliance scan (28 confirmed findings,
5 refuted, 0 uncertain after adversarial per-finding verification). This branch fixes every
confirmed finding that required a code change.

## Fixes (all complete)

- [x] **H1 — ValidWhileTrue SSRF**: new `SsrfGuard` (pre-flight host check + rebind-safe
  `ConnectCallback`); `HttpValidWhileTrueHandler` pre-flights every URI; `AddZcapValidWhileTrueSupport`
  configures the named client with no auto-redirect, connect-time guard, 10 s timeout, 64 KB cap.
- [x] **H2 — delegated `expires` MUST on verify path**: `VerifyBuiltChainAsync` rejects a delegated
  link with no `expires` (`MalformedCapability`), gated `requireDelegatedExpires` (default on; `false`
  on the revocation-auth path so non-expiring delegations stay revocable). Closes the attenuation gap
  (a child could outlive a short-lived parent by omitting `expires`).
- [x] **M1 — offsetless timestamps**: `ZcapTimestamps.Parse` uses `AssumeUniversal | AdjustToUniversal`;
  `ParseOrNull` is total (`TryParse`).
- [x] **M3 — chain length bounded during build**: `BuildCapabilityChainAsync` returns early at
  `> MaxChainLength` (bounds work, still surfaces the precise `ChainTooLong` outcome).
- [x] **M4 — UsageCountCaveat enforceable / fail-closed**: count read from
  `InvocationContext.Properties["zcap:usageCount"]`; denies when absent.
- [x] **M5 — RDFC oracle caveat converter**: `RdfcDocumentCanonicalizer` reuses `ZcapJsonOptions.Default`.
- [x] **Low — standalone caveat compatibility**: `VerifySingleDelegationProofAsync` now checks it.
- [x] **Low — invocation-target `..` rejection** in `IsValidInvocationTarget`.
- [x] **Low — revocation GET minimal disclosure** + 1 MB revoke body cap.
- [x] **Low — `AllowDuplicateProperties = false`** in `ZcapJsonOptions.Default`.
- [x] **Low — remove dead `RemoveProofField`/`CanonicalizeWithoutProof`**.
- [x] **Low — sign-time self-verify** in `SigningService`.
- [x] **Low — time caveats evaluate against `InvocationContext.InvocationTime`**.

## Deliberately NOT changed (documented gaps)

- **per-instance nonce/revocation stores** (convenience ctors): inherent to in-memory dev stores;
  already documented in XML comments. Production multi-instance must supply shared stores.
- The refuted findings (JCS null-strip differential, ConcatenateHashes naming, the High "unbounded
  chain DoS", case-variant keys, malformed-`expires` classification) — disproven by the skeptics.

## Verification (review)

- `dotnet build ZcapLd.sln` — succeeds.
- `dotnet test ZcapLd.sln` — **520 passing, 0 failing** (487 Core + 33 ASP.NET), incl. 41 new
  regression tests: `SsrfGuardTests` (27), `ZcapTimestampsTests`, dot-segment cases,
  `UsageCountCaveat_NoContextCount_FailsClosed`, `SignedRevoke_DelegatedWithoutExpires_*`.
- `dotnet run --project examples/ZcapLd.Examples` — full demo runs clean (expected ALLOWED/DENIED).
- Existing tests updated to assert the new (correct) behavior: UsageCount via context, no-expires
  chain rejection, anonymous GET trim.
