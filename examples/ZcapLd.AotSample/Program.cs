using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using ZcapLd.AotSample;
using ZcapLd.AspNetCore.DependencyInjection;
using ZcapLd.AspNetCore.Endpoints;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

// Native AOT consumer of ZcapLd.Core and ZcapLd.AspNetCore (#154). Every outcome below is checked
// against the expected value; a mismatch exits non-zero. CI publishes this program with ILCompiler
// and runs the native binary; it must also pass under the JIT (`dotnet run`).
var checks = 0;
var failures = 0;
void Check<T>(string label, T expected, T actual)
{
    checks++;
    if (EqualityComparer<T>.Default.Equals(expected, actual))
    {
        Console.WriteLine($"{label}: {actual}");
        return;
    }

    failures++;
    Console.WriteLine($"FAIL {label}: {actual} (expected {expected})");
}

Console.WriteLine($"Dynamic code supported: {RuntimeFeature.IsDynamicCodeSupported}; " +
                  $"STJ reflection enabled: {JsonSerializer.IsReflectionEnabledByDefault}");

// ─── Keys and resolution ───────────────────────────────────────────────────────────────────────
// The keyring only signs (did:key). Resolution and controller authorization go through a
// CompositeDidResolver that routes did:key to the library's DidKeyResolver, as a deployment that
// mixes DID methods would.
var keyring = new SampleKeyring();
var owner = keyring.GenerateDidKey();
var agent = keyring.GenerateDidKey();
var stranger = keyring.GenerateDidKey();

var resolver = new CompositeDidResolver();
resolver.Register("did:key:", new DidKeyResolver());

// The custom caveat is registered with source-generated metadata: the only registration path that
// works where reflection-based serialization is disabled.
var caveatTypes = new CaveatTypeRegistry().Register(RateLimitCaveat.TypeName, SampleJsonContext.Default.RateLimitCaveat);

var signing = new SigningService(keyring, resolver, caveatTypes);
var capabilities = new CapabilityService(signing, caveatTypes);
var roots = new InMemoryRootCapabilityResolver();
var revocations = new RevocationService(new InMemoryRevocationStore());
var verifier = new VerificationService(resolver, revocations, new InMemoryNonceStore(),
    rootResolver: roots, caveats: caveatTypes, caveatHandlers: new ICaveatHandler[] { new RateLimitLedger(TimeProvider.System) });

// ─── Root -> delegate -> invoke ────────────────────────────────────────────────────────────────
const string target = "https://example.com/documents";
var root = roots.Register(await capabilities.CreateRootCapabilityAsync(owner, target, new[] { "read", "write" }));
Console.WriteLine($"Root: {root.Id}");

var delegated = await capabilities.DelegateCapabilityAsync(root, agent, new[] { "read" }, DateTime.UtcNow.AddDays(1));
Check("Delegation chain", VerificationOutcome.Valid,
    (await verifier.VerifyCapabilityChainDetailedAsync(delegated)).Outcome);

// The in-stack envelope: the delegated capability is embedded in the invocation.
var invocation = capabilities.CreateInvocation(delegated, "read");
invocation.Proof = await signing.SignInvocationAsync(invocation, agent);
Check("Envelope invocation", VerificationOutcome.Valid,
    (await verifier.VerifyInvocationDetailedAsync(invocation, delegated)).Outcome);

// The interoperable Data Integrity application document: a JSON object carrying a
// capabilityInvocation proof. The relying party supplies the expected action and targets.
var document = await signing.SignCapabilityInvocationAsync(
    InvocationCapability.FromCapability(delegated), "read", delegated.InvocationTarget, agent);
Check("DI application document", VerificationOutcome.Valid,
    (await verifier.VerifyCapabilityInvocationDetailedAsync(document, "read", new[] { delegated.InvocationTarget })).Outcome);

// A key that is not a controller of the capability cannot invoke it, however valid its signature.
var intrusion = capabilities.CreateInvocation(delegated, "read");
intrusion.Proof = await signing.SignInvocationAsync(intrusion, stranger);
Check("Non-controller invocation", VerificationOutcome.UnauthorizedController,
    (await verifier.VerifyInvocationDetailedAsync(intrusion, delegated)).Outcome);

// ─── Custom caveat (#157) through the source-generated registration ────────────────────────────
var limited = await capabilities.DelegateCapabilityAsync(root, agent, new[] { "read" }, DateTime.UtcNow.AddHours(1),
    caveats: new Caveat[] { new RateLimitCaveat { MaxPerMinute = 2 } });
var narrowed = await capabilities.DelegateCapabilityAsync(limited, stranger, new[] { "read" }, DateTime.UtcNow.AddMinutes(30),
    caveats: new Caveat[] { new RateLimitCaveat { MaxPerMinute = 1 } });

// Chain verification authenticates caveats but never authorizes them; only invocation enforces.
var chain = await verifier.VerifyCapabilityChainDetailedAsync(narrowed);
Check("Caveat chain", VerificationOutcome.CaveatEnforcementRequired, chain.Outcome);
Check("Caveat chain limits", "2 > 1",
    string.Join(" > ", chain.Caveats!.Select(g => ((RateLimitCaveat)g.Caveat).MaxPerMinute)));

async Task<VerificationOutcome> InvokeAsync(Capability grant, string invoker)
{
    var request = capabilities.CreateInvocation(grant, "read");
    request.Proof = await signing.SignInvocationAsync(request, invoker);
    return (await verifier.VerifyInvocationDetailedAsync(request, grant)).Outcome;
}

Check("Caveat invocation 1 of 1", VerificationOutcome.Valid, await InvokeAsync(narrowed, stranger));
Check("Caveat invocation 2 of 1", VerificationOutcome.CaveatNotSatisfied, await InvokeAsync(narrowed, stranger));

// The ledger buckets on the resource's clock, never on the holder-signed `created`: a holder may sign
// any time inside the freshness window, so a bucket chosen from it could be reset by alternating two
// minutes (PR #168 review). Here resource time stands still while the signed minute alternates.
var clock = new StillClock(DateTimeOffset.UtcNow);
var clocked = new VerificationService(resolver, revocations, new InMemoryNonceStore(),
    rootResolver: roots, caveats: caveatTypes, caveatHandlers: new ICaveatHandler[] { new RateLimitLedger(clock) });

async Task<VerificationOutcome> InvokeSignedAtAsync(Capability grant, string invoker, int minutesAgo)
{
    var request = capabilities.CreateInvocation(grant, "read");
    request.Proof = await signing.SignInvocationAsync(request, invoker, DateTime.UtcNow.AddMinutes(-minutesAgo));
    return (await clocked.VerifyInvocationDetailedAsync(request, grant)).Outcome;
}

var alternating = new List<VerificationOutcome>();
foreach (var minutesAgo in new[] { 0, 0, 1, 0, 1, 0 })
    alternating.Add(await InvokeSignedAtAsync(narrowed, stranger, minutesAgo));
Check("Alternating signed minutes, resource clock still",
    "Valid, CaveatNotSatisfied, CaveatNotSatisfied, CaveatNotSatisfied, CaveatNotSatisfied, CaveatNotSatisfied",
    string.Join(", ", alternating));
clock.Advance(TimeSpan.FromMinutes(1));
Check("Resource clock rolled over", VerificationOutcome.Valid, await InvokeSignedAtAsync(narrowed, stranger, 0));
Check("Rolled-over minute exhausted", VerificationOutcome.CaveatNotSatisfied, await InvokeSignedAtAsync(narrowed, stranger, 0));

// ─── Signed revocation ────────────────────────────────────────────────────────────────────────
var revocation = await signing.SignRevocationAsync(delegated.Id, owner, delegated.InvocationTarget, reason: "access withdrawn");
Check("Owner revocation accepted", true, await verifier.RevokeCapabilityAsync(delegated, revocation));
Check("Chain after revocation", VerificationOutcome.Revoked,
    (await verifier.VerifyCapabilityChainDetailedAsync(delegated)).Outcome);

// ─── The ZcapLd.AspNetCore revocation endpoint in a slim, AOT-published host ──────────────────
var builder = WebApplication.CreateSlimBuilder(args);
builder.WebHost.UseUrls("http://127.0.0.1:0");
builder.Logging.SetMinimumLevel(LogLevel.Warning);
builder.Services.AddZcapServices();
builder.Services.AddZcapDidResolver(_ => resolver);
builder.Services.AddZcapRootCapabilityResolver(_ => roots);
builder.Services.AddZcapRevocationSupport(_ => new InMemoryRevocationStore());
// The DI sibling of the typed registration above, plus the resource's handler and its clock.
builder.Services.AddZcapCaveatType(RateLimitCaveat.TypeName, SampleJsonContext.Default.RateLimitCaveat);
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddZcapCaveatHandler<RateLimitLedger>();

var app = builder.Build();
app.MapZcapRevocationEndpoints();
await app.StartAsync();
try
{
    using var http = new HttpClient { BaseAddress = new Uri(app.Urls.First()) };
    Console.WriteLine($"Revocation endpoint host: {http.BaseAddress}");

    var second = await capabilities.DelegateCapabilityAsync(root, agent, new[] { "write" }, DateTime.UtcNow.AddDays(1));
    var path = $"/zcaps/revocations/{Uri.EscapeDataString(second.Id)}";
    var body = RevocationBody(second, await signing.SignRevocationAsync(second.Id, owner, second.InvocationTarget));

    using var accepted = await PostAsync(http, path, body);
    Check("POST signed revocation", HttpStatusCode.OK, accepted.StatusCode);
    using var status = JsonDocument.Parse(await accepted.Content.ReadAsStringAsync());
    Check("Response capabilityId", second.Id, status.RootElement.GetProperty("capabilityId").GetString());
    Check("Response isRevoked", true, status.RootElement.GetProperty("isRevoked").GetBoolean());

    // The same signed request again: its nonce was consumed and the capability is already revoked.
    using var replayed = await PostAsync(http, path, body);
    Check("POST replayed revocation", HttpStatusCode.Forbidden, replayed.StatusCode);

    // A duplicate JSON property is malformed input, rejected before any verification: 400, not 500.
    using var duplicate = await PostAsync(http, "/zcaps/revocations/urn:uuid:a",
        """{"capability":{"id":"urn:uuid:a","id":"urn:uuid:b"},"signedRevocation":{}}""");
    Check("POST duplicate-key body", HttpStatusCode.BadRequest, duplicate.StatusCode);
}
finally
{
    await app.StopAsync();
}

Console.WriteLine(failures == 0 ? $"All {checks} checks passed" : $"{failures} of {checks} check(s) FAILED");
return failures == 0 ? 0 : 1;

// The endpoint's body: { "capability": <the capability with its chain>, "signedRevocation": <the
// signed request> }. The adapter's contract type has no public serializer metadata, so the body is
// assembled as a JsonObject from the two models' own metadata in ZcapJsonOptions.Default, which is
// generated and so works without reflection.
static string RevocationBody(Capability capability, Invocation signedRevocation)
{
    var body = new JsonObject
    {
        ["capability"] = JsonSerializer.SerializeToNode(capability, (JsonTypeInfo<Capability>)ZcapJsonOptions.Default.GetTypeInfo(typeof(Capability))),
        ["signedRevocation"] = JsonSerializer.SerializeToNode(signedRevocation, (JsonTypeInfo<Invocation>)ZcapJsonOptions.Default.GetTypeInfo(typeof(Invocation))),
    };
    return body.ToJsonString(ZcapJsonOptions.Default);
}

static async Task<HttpResponseMessage> PostAsync(HttpClient http, string path, string json)
{
    using var content = new StringContent(json, Encoding.UTF8, "application/json");
    return await http.PostAsync(path, content);
}

/// <summary>A resource clock the self-checks hold still and advance by hand.</summary>
sealed class StillClock(DateTimeOffset now) : TimeProvider
{
    private DateTimeOffset _now = now;

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;
}
