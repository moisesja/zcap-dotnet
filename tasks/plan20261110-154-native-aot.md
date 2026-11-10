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
- **D7. Enforcement.** `IsAotCompatible=true` on both package projects and an explicit
  `WarningsAsErrors` list of the IL2xxx/IL3xxx codes (not `TreatWarningsAsErrors`, which would also
  turn NuGet audit warnings into build breaks).
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

- [ ] T1. Core: `ZcapJsonContext` (`JsonSerializerContext`, settings mirroring
  `ZcapJsonOptions.Default`), `ZcapJsonOptions.Default` resolver (D1), `ContextJsonConverter` and
  `CapabilityChainJsonConverter` (D4), byte-identity tests (reflection-only options vs context-only
  options over rich fixtures).
- [ ] T2. Core: every reflection `JsonSerializer` call (issue table + `ProofSigningPayloadBuilder`,
  `RdfcDocumentCanonicalizer`, `CanonicalIri`, `SigningService`, `CapabilityService`,
  `VerificationService`, `LegacyProofCrypto`, `CapabilityProfile`, converters) to `JsonTypeInfo`
  overloads; profile message (D5).
- [ ] T3. Core: NetCid element path (D2) with pinned `KeyFor`/`GrantKey`/context-document tests;
  caveat registration overload and metadata plumbing (D3); upstream issue filed.
- [ ] T4. AspNetCore context and endpoint (D6); existing ASP.NET tests green.
- [ ] T5. `IsAotCompatible` + IL warnings-as-errors (D7); fix what the analyzers report; AOT sample
  + file-based app (D8, D9); `ci-aot.yml`.
- [ ] T6. Docs: README, both package READMEs, CHANGELOG, architecture.md "Serialization", AGENTS.md
  serialization bullet, docs/CAVEAT-PROFILE.md.
- [ ] T7. Red team on the serialization changes (reflection vs source-gen differences, dropped signed
  terms, silent reflection fallbacks under AOT). Fix real findings.

### Phase 3: verification and PR

- [ ] `dotnet build ZcapLd.sln` with 0 warnings; `dotnet test ZcapLd.sln` green.
- [ ] `bash interop/run-interop.sh` passes unchanged.
- [ ] Local native AOT publish of the sample on macOS: zero IL warnings from ZcapLd.*, DataProofs,
  NetCid; the binary runs the full round trip.
- [ ] `dotnet run examples/ZcapLd.AotFileBasedApp/app.cs` passes.
- [ ] No untracked artifacts; PR opened with `Closes #154`; CI green.

## Results

(filled in as work lands)
