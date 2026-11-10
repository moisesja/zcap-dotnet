# Issue #154: native AOT, trimming and .NET 10 file-based apps (source-generated JSON)

Branch: `154-native-aot`, rebased onto `origin/main` @ d6b860b (PR #167 merged).

## Context

#154 (owner's work plan, updated 2026-11-09 against 6.0.0) is the spec. ZcapLd serializes every
wire model through reflection-based `System.Text.Json` (`ZcapJsonOptions.Default`), so under native
AOT, trimming, or a .NET 10 file-based app (`dotnet run app.cs`, which disables reflection-based
serialization by default) the first delegation throws `InvalidOperationException` in
`CanonicalIri.SignedForm`, and `CaveatTypeRegistry.Register<T>` throws inside
`NetCid.JcsCanonicalizer.Canonicalize(JsonNode)`. An AOT publish of 6.0.0 reports 34 IL2026/IL3050
pairs in ZcapLd.Core and NetCid. Nothing is wrongly authorized (fails closed), but the library cannot
operate, and `CapabilityProfile` reports the failure as "could not be inspected safely", which reads
like a rejected capability.

Hard constraints (from the issue and the orchestrator brief):

- Signed bytes, `RevocationScope.KeyFor` digests and generated caveat context documents must be
  byte-identical to 6.0.0; golden vectors, the payload oracle, profile/caveat/revocation-scope tests
  and the live interop harness pass unchanged.
- Additive only; the one new public member is `CaveatTypeRegistry.Register<TCaveat>(string,
  JsonTypeInfo<TCaveat>)`. The reflection overload stays, annotated.
- `IsAotCompatible=true` on both packages, IL2xxx/IL3xxx as errors there, zero IL warnings from
  ZcapLd.*, DataProofs and NetCid in an AOT publish.
- NetCid stays at 1.6.0 (no release fixes the reflection path); resolve ZcapLd-side and file an
  upstream issue.
- No version bump (release PRs do that); CHANGELOG under `[Unreleased]`.

## Human decisions

- 2026-10-25: the owner widened #154 from "clearer error" to full AOT/trimming support.
- 2026-11-09: the owner re-measured the issue against 6.0.0 and set the target to the next 6.x minor.
- 2026-11-10: the user was unavailable; the orchestrator was instructed to make routine decisions
  autonomously, implement through sub-agents, red-team the serialization changes, open the PR and get
  CI green. Every decision below was taken on that basis and is recorded with its rationale.

## Decisions taken autonomously (2026-11-10)

- **D1. `ZcapJsonOptions.Default` resolver.** `TypeInfoResolver` is the generated `ZcapJsonContext`
  first; when `JsonSerializer.IsReflectionEnabledByDefault` is true (every JIT app that has not opted
  out) a `DefaultJsonTypeInfoResolver` is combined after it so consumers who serialize their own types
  with the shared options see no change. Under AOT/trimming/file-based apps the context is the only
  resolver. The guarded reflection branch carries `UnconditionalSuppressMessage` for IL2026/IL3050 with
  the justification, which is the pattern the runtime itself uses for `JsonSerializerOptions.Default`.
  Rationale: the acceptance criteria require "JIT consumers see no behaviour change".
- **D2. NetCid.** `JcsCanonicalizer.Canonicalize(JsonElement)` is reflection-free (it walks the
  element); only the `JsonNode` overloads call `JsonSerializer.SerializeToDocument(node)`. ZcapLd
  routes every call through the element overload, converting a `JsonNode` with
  `JsonNode.WriteTo(Utf8JsonWriter)` + `JsonDocument.Parse` (both AOT-safe). The bytes are identical
  because the node overload itself serializes to a document and then walks the element. Pinned tests
  prove `KeyFor` and caveat context bytes. One upstream issue in moisesja/net-cid describes the
  reflection call sites and the AOT-safe API NetCid would need (annotate the node overloads, or make
  them use `WriteTo`). No NetCid bump.
- **D3. Caveat registration overload.** `Register<TCaveat>(string type, JsonTypeInfo<TCaveat>
  typeInfo)` as the issue asks. A generated context's `JsonTypeInfo` is frozen, so the registration
  does not use it directly: it takes its `OriginatingResolver` (falling back to
  `Options.TypeInfoResolver`) and builds the strict caveat options (`UnmappedMemberHandling =
  Disallow`, `RespectNullableAnnotations`, `RespectRequiredConstructorParameters`, strict numbers,
  `WhenWritingNull`) with that resolver plus the existing "drop the overriding `Type` property"
  modifier, then resolves a fresh, modifiable `JsonTypeInfo<TCaveat>` from it. The reflection overload
  does the same with `DefaultJsonTypeInfoResolver` and is annotated `[RequiresUnreferencedCode]` /
  `[RequiresDynamicCode]`. Every caveat (de)serialization and comparison goes through the
  registration's type info; `Caveat.IsAttenuationOf` (no registry in scope) uses a process-wide
  `Type -> JsonTypeInfo` metadata cache filled by both overloads, and in a reflection-disabled app a
  type that was never registered fails with an exception naming the cause. The cache holds serializer
  metadata, not accepted types; the no-global-registry rule is unchanged.
- **D4. Union converters.** `Capability.Context` (`object`) and `Proof.CapabilityChain` (`object[]`)
  keep their types and gain `[JsonConverter]`s. Read yields `JsonElement` (what the reflection object
  converter produced). Write handles `string`, `JsonElement`, `JsonNode`, `Capability` (chain only),
  and `IEnumerable` of those; any other runtime type resolves `options.GetTypeInfo(runtimeType)`,
  which works in JIT through D1 and throws a `NotSupportedException` naming the type and the cause
  under AOT. Rationale: no public API change; today's JIT behaviour (any CLR shape serializes, the
  profile then rejects inline contexts) is preserved.
- **D5. Remaining reflection-disabled failures name their cause.** `CapabilityProfile.Validate`'s
  catch keeps its outcome but appends the exception message, so an operator sees "Reflection-based
  serialization has been disabled…" (or the converter's message) instead of only "could not be
  inspected safely".
- **D6. AspNetCore.** A generated `ZcapAspNetCoreJsonContext` for `SignedRevocationHttpRequest` and
  `RevocationStatusHttpResponse`, combined before `ZcapJsonOptions.Default.TypeInfoResolver` in an
  options instance that otherwise copies the shared settings. Core's three converters are internal,
  so Core adds `InternalsVisibleTo("ZcapLd.AspNetCore")` if the generator needs to instantiate them.
  The endpoint deserializes and responds with `JsonTypeInfo` overloads. `ZcapJsonContext` stays
  internal (smallest new surface; a consumer embeds `Capability` in its own source-generated DTO as
  `JsonElement` and converts with `ZcapJsonOptions.Default.GetTypeInfo(typeof(Capability))`, which the
  README documents). Widening to public later is additive.
- **D7. Enforcement.** `IsAotCompatible=true` on both package projects and `src/.editorconfig`
  escalating the `Trimming`, `SingleFile` and `AOT` analyzer categories to errors (revised from an
  explicit 115-code `WarningsAsErrors` list, which was correct but unreadable; proven by injecting a
  reflection call and watching the build fail). Not `TreatWarningsAsErrors`, which would also turn
  NuGet audit warnings into build breaks.
- **D8. NU1903 (ILCompiler 10.0.100 advisory GHSA-p3jp-9v83-76w9).** CI uses `dotnet-version:
  10.0.x` (latest patch). The AOT sample carries a scoped `<NuGetAuditSuppress>` for that one advisory
  with a comment, so a developer on the 10.0.100 SDK can publish locally; no global NoWarn.
- **D9. Sample layout.** `examples/ZcapLd.AotSample` (Web SDK, `PublishAot`, in the solution) runs
  the issue's section-7 list in-process, including the `ZcapLd.AspNetCore` revocation endpoint in a
  `CreateSlimBuilder` host driven over loopback, with a source-generated context for its custom
  caveat. `examples/ZcapLd.AotFileBasedApp/app.cs` is the file-based smoke (`#:project` to Core, not
  in the solution). Both reference the projects, not published packages (the packages do not exist
  yet; CI covers the same assemblies).
- **D10. CHANGELOG.** One `[Unreleased]` "Added/Changed/Fixed" entry for #154; the 6.0.0 "Known
  limitations" bullet stays as history.

## Plan

### Phase 2: implementation (one sub-agent per task, sequenced where files are shared)

- [x] T1. Core: `ZcapJsonContext` (`JsonSerializerContext`, settings mirroring
  `ZcapJsonOptions.Default`), `ZcapJsonOptions.Default` resolver (D1), `ContextJsonConverter` and
  `CapabilityChainJsonConverter` (D4), byte-identity tests (reflection-only options vs context-only
  options over rich fixtures).
- [x] T2. Core: every reflection `JsonSerializer` call (issue table + `ProofSigningPayloadBuilder`,
  `RdfcDocumentCanonicalizer`, `CanonicalIri`, `SigningService`, `CapabilityService`,
  `VerificationService`, `LegacyProofCrypto`, `CapabilityProfile`, converters) to `JsonTypeInfo`
  overloads; profile message (D5).
- [x] T3. Core: NetCid element path (D2) with pinned `KeyFor`/`GrantKey`/context-document tests;
  caveat registration overload and metadata plumbing (D3); upstream issue filed.
- [x] T4. AspNetCore context and endpoint (D6); existing ASP.NET tests green.
- [x] T5. `IsAotCompatible` + IL warnings-as-errors (D7); fix what the analyzers report; AOT sample
  + file-based app (D8, D9); `ci-aot.yml`.
- [x] T6. Docs: README, both package READMEs, CHANGELOG, architecture.md "Serialization", AGENTS.md
  serialization bullet, docs/CAVEAT-PROFILE.md.
- [x] T7. Red team on the serialization changes (reflection vs source-gen differences, dropped signed
  terms, silent reflection fallbacks under AOT). Fix real findings.

### Phase 3: verification and PR

- [x] `dotnet build ZcapLd.sln` with 0 warnings; `dotnet test ZcapLd.sln` green.
- [x] `bash interop/run-interop.sh` passes unchanged.
- [x] Local native AOT publish of the sample on macOS: zero IL warnings from ZcapLd.*, DataProofs,
  NetCid; the binary runs the full round trip.
- [x] `dotnet run examples/ZcapLd.AotFileBasedApp/app.cs` passes.
- [ ] No untracked artifacts; PR opened with `Closes #154`; CI green.

## Results

Commits on `154-native-aot` (one per task): ae4eece (T1), 919472f (T2), 6fa38e9 (T3), ac279da (T4),
527fa23 (T5), 5de836c (T6), 5f6a9a9 (T7 fixes). Upstream: moisesja/net-cid#65 filed (D2).

- **Build:** `dotnet build ZcapLd.sln -c Release --no-incremental` 0 warnings, 0 errors (four
  pre-existing cref warnings fixed on the way). The IL gate was proven by injecting a reflection call.
- **Tests:** Core 889 (was 783; +106), AspNetCore 89 (was 56; +33), 0 failures. No existing test or
  fixture changed except two assertions in the new AspNetCore `SourceGeneratedJsonTests` that had pinned
  the regressed 200 body (T7/F3). Byte identity pinned against 6.0.0 (4f0cc8e): wire fixtures via a
  reflection-only oracle, 20 `RevocationScope.KeyFor` digests, 4 grant keys, 4 caveat context
  documents and 3 caveat wire forms, all computed from a 4f0cc8e worktree.
- **Interop:** `bash interop/run-interop.sh` ALL 12 CHECKS + ALL 118 PROFILE CHECKS passed.
- **Native AOT (macOS arm64):** `dotnet publish examples/ZcapLd.AotSample -c Release -r osx-arm64
  -p:TrimmerSingleWarn=false`: 10 IL warnings, all Newtonsoft.Json 13.0.4 (`JObject/JToken/JValue.
  GetMetaObject`, `JValue.IConvertible.ToType`, five IL2026/IL3050 pairs; dotNetRDF's `dynamic`
  support, unreachable from RDFC); zero from ZcapLd.*, DataProofsDotnet.*, NetCid, NetDid, NetCrypto.
  The 22 MB binary runs all 15 checks (round trip, non-controller denial, custom caveat through the
  typed overload, signed revocation, the revocation endpoint in a slim host: 200, replay 403,
  duplicate key 400).
- **File-based app:** `dotnet run examples/ZcapLd.AotFileBasedApp/app.cs` prints `Dynamic code
  supported: False; STJ reflection enabled: False` and passes all 9 checks; `dotnet publish app.cs`
  also produces a working native binary. NU1903 (ILCompiler advisory) is a warning there on SDK
  10.0.100; CI uses the latest 10.0.x.
- **Reflection-disabled test sweep** (`JsonSerializerIsReflectionEnabledByDefault=false` on the Core
  test project, then reverted): every remaining failure is test-only reflection (test helpers calling
  option-less `JsonSerializer`, registrations through the reflection overload) or a JIT-state
  assertion; zero failures inside library code.
- **Red team (T7):** no Critical/High. Six findings, all fixed in 5f6a9a9: F1 Medium, a context with
  `UseStringEnumConverter` made the two `Register` overloads write different enum bytes (now probed at
  registration; member- and type-level `[JsonConverter]` stay accepted); F2 Low, `Jcs` mapped lone
  surrogates to U+FFFD so two malformed ids could share a `KeyFor` digest where 6.0.0 threw (NetCid's
  validation walk ported); F3 Low, the endpoint's 200 body had lost its null members (6.0.0 shape
  restored and pinned, including its relaxed escaping); F4 Low, the `RequestDelegate` mapping lost
  `IAcceptsMetadata`/`IDisableCookieRedirectMetadata` (declared explicitly, pinned); F5 Low,
  `object`-typed caveat parameters failed at first delegation under a caveat-only context (Core's
  context combined as fallback); F6 Info, the union writer lacked the 64-deep cycle guard (added).
  Not reproduced: any dropped/duplicated/moved signed term, any duplicate-key acceptance, any silent
  reflection fallback, any wire-byte divergence over 85 fixtures, endpoint route/body matrix changes.
- **Decisions revised during the work:** D7 (editorconfig gate). D6's resolver order: the adapter's
  context is inserted right after Core's context in the chain (not appended), or the JIT reflection
  resolver would answer first for the contract types.

### Review round 1 (PR #168, comment 6766170401, reviewed a70b4b9)

- **P2 confirmed:** both sample `RateLimitLedger`s chose the minute bucket from `context.Created`,
  the holder-signed proof time, and kept only the last `(Minute, Count)` per grant; signing at minute
  offsets `[0, 0, -1, 0, -1, 0]` gave `Valid, CaveatNotSatisfied, Valid, Valid, Valid, Valid`. Example
  handler defect, not a Core bypass.
- **Fix:** both ledgers take an injected `TimeProvider` (the host registers `TimeProvider.System`
  before `AddZcapCaveatHandler<RateLimitLedger>()`; the in-process verifier passes it directly) and
  bucket on `clock.GetUtcNow()`; a grant's entry is only replaced when the clock has moved past it, so
  an earlier reading can never erase a consumed minute. `docs/CAVEAT-PROFILE.md` now says `Created` is
  for audit, never for choosing a window.
- **Regression (both samples' self-checks, run by ci-aot and `dotnet run`):** a still `StillClock`
  with signed minutes alternating `[0, 0, 1, 0, 1, 0]` ago must give
  `Valid, CaveatNotSatisfied ×5`; advancing the clock one minute gives `Valid` then
  `CaveatNotSatisfied`. Proven red against the original semantics (rebuilt, exact reviewer sequence
  reproduced in both samples: 2 of 18 / 2 of 12 checks failed), then green (18/18, 12/12).
