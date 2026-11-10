#:project ../../src/ZcapLd.Core/ZcapLd.Core.csproj
#:property TrimmerSingleWarn=false

// A .NET 10 file-based app (#154): `dotnet run examples/ZcapLd.AotFileBasedApp/app.cs` from the repo
// root. File-based apps use native AOT settings by default, so reflection-based System.Text.Json is
// disabled even under `dotnet run`; the two values printed first record that. Every outcome below is
// checked against the expected value and a mismatch exits non-zero. Not part of ZcapLd.sln.

using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetCrypto;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

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

var keyring = new Keyring();
var owner = keyring.GenerateDidKey();
var agent = keyring.GenerateDidKey();
var stranger = keyring.GenerateDidKey();

var resolver = new CompositeDidResolver();
resolver.Register("did:key:", new DidKeyResolver());

// Source-generated metadata is the only caveat registration path where reflection is disabled.
var caveatTypes = new CaveatTypeRegistry().Register(RateLimitCaveat.TypeName, AppJsonContext.Default.RateLimitCaveat);

var signing = new SigningService(keyring, resolver, caveatTypes);
var capabilities = new CapabilityService(signing, caveatTypes);
var roots = new InMemoryRootCapabilityResolver();
var verifier = new VerificationService(resolver, new RevocationService(new InMemoryRevocationStore()), new InMemoryNonceStore(),
    rootResolver: roots, caveats: caveatTypes, caveatHandlers: new ICaveatHandler[] { new RateLimitLedger() });

var root = roots.Register(await capabilities.CreateRootCapabilityAsync(owner, "https://example.com/documents", new[] { "read" }));
Console.WriteLine($"Root: {root.Id}");

var delegated = await capabilities.DelegateCapabilityAsync(root, agent, new[] { "read" }, DateTime.UtcNow.AddDays(1));
Check("Delegation chain", VerificationOutcome.Valid, (await verifier.VerifyCapabilityChainDetailedAsync(delegated)).Outcome);

var invocation = capabilities.CreateInvocation(delegated, "read");
invocation.Proof = await signing.SignInvocationAsync(invocation, agent);
Check("Envelope invocation", VerificationOutcome.Valid, (await verifier.VerifyInvocationDetailedAsync(invocation, delegated)).Outcome);

var document = await signing.SignCapabilityInvocationAsync(
    InvocationCapability.FromCapability(delegated), "read", delegated.InvocationTarget, agent);
Check("DI application document", VerificationOutcome.Valid,
    (await verifier.VerifyCapabilityInvocationDetailedAsync(document, "read", new[] { delegated.InvocationTarget })).Outcome);

var intrusion = capabilities.CreateInvocation(delegated, "read");
intrusion.Proof = await signing.SignInvocationAsync(intrusion, stranger);
Check("Non-controller invocation", VerificationOutcome.UnauthorizedController,
    (await verifier.VerifyInvocationDetailedAsync(intrusion, delegated)).Outcome);

var limited = await capabilities.DelegateCapabilityAsync(root, agent, new[] { "read" }, DateTime.UtcNow.AddHours(1),
    caveats: new Caveat[] { new RateLimitCaveat { MaxPerMinute = 1 } });
Check("Caveat chain", VerificationOutcome.CaveatEnforcementRequired, (await verifier.VerifyCapabilityChainDetailedAsync(limited)).Outcome);
var allowed = capabilities.CreateInvocation(limited, "read");
allowed.Proof = await signing.SignInvocationAsync(allowed, agent);
Check("Caveat invocation 1 of 1", VerificationOutcome.Valid, (await verifier.VerifyInvocationDetailedAsync(allowed, limited)).Outcome);
var denied = capabilities.CreateInvocation(limited, "read");
denied.Proof = await signing.SignInvocationAsync(denied, agent);
Check("Caveat invocation 2 of 1", VerificationOutcome.CaveatNotSatisfied, (await verifier.VerifyInvocationDetailedAsync(denied, limited)).Outcome);

var revocation = await signing.SignRevocationAsync(delegated.Id, owner, delegated.InvocationTarget, reason: "access withdrawn");
Check("Owner revocation accepted", true, await verifier.RevokeCapabilityAsync(delegated, revocation));
Check("Chain after revocation", VerificationOutcome.Revoked, (await verifier.VerifyCapabilityChainDetailedAsync(delegated)).Outcome);

Console.WriteLine(failures == 0 ? $"All {checks} checks passed" : $"{failures} of {checks} check(s) FAILED");
return failures == 0 ? 0 : 1;

/// <summary>Sample-only Ed25519 keyring behind real did:key identifiers. NOT FOR PRODUCTION.</summary>
sealed class Keyring : IDidSigner
{
    private static readonly DefaultCryptoProvider Crypto = new();
    private static readonly DefaultKeyGenerator KeyGen = new();
    private readonly ConcurrentDictionary<string, byte[]> _privateKeys = new(StringComparer.Ordinal);

    public string GenerateDidKey()
    {
        var keyPair = KeyGen.Generate(KeyType.Ed25519);
        var did = $"did:key:{keyPair.MultibasePublicKey}";
        _privateKeys[did] = keyPair.PrivateKey;
        return did;
    }

    public Task<SignatureResult> SignAsync(string did, byte[] data)
    {
        if (!_privateKeys.TryGetValue(did, out var privateKey))
            throw new InvalidOperationException($"This keyring holds no key for {did}.");
        return Task.FromResult(new SignatureResult(Crypto.Sign(KeyType.Ed25519, privateKey, data), "Ed25519Signature2020"));
    }
}

/// <summary>A custom caveat (#157): the most invocations per minute. The resource enforces it.</summary>
sealed class RateLimitCaveat : Caveat
{
    public const string TypeName = "RateLimit";

    public override string Type => TypeName;

    [JsonPropertyName("maxPerMinute")]
    public required int MaxPerMinute { get; init; }

    public override void Validate()
    {
        if (MaxPerMinute is < 1 or > 10_000)
            throw new CapabilityValidationException("maxPerMinute must be between 1 and 10000.");
    }

    public override bool IsAttenuationOf(Caveat parent)
        => parent is RateLimitCaveat limit && MaxPerMinute <= limit.MaxPerMinute;
}

[JsonSerializable(typeof(RateLimitCaveat))]
sealed partial class AppJsonContext : JsonSerializerContext
{
}

sealed class RateLimitLedger : ICaveatHandler
{
    private readonly Dictionary<string, (long Minute, int Count)> _counts = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public string CaveatType => RateLimitCaveat.TypeName;

    public Task<CaveatDecision> EnforceAsync(CaveatEnforcementContext context)
    {
        var minute = context.Created.Ticks / TimeSpan.TicksPerMinute;
        lock (_gate)
        {
            foreach (var grant in context.Grants)
            {
                var limit = ((RateLimitCaveat)grant.Caveat).MaxPerMinute;
                var current = _counts.TryGetValue(grant.GrantKey, out var entry) && entry.Minute == minute ? entry.Count : 0;
                if (current + 1 > limit)
                    return Task.FromResult(CaveatDecision.Deny($"{grant.CapabilityId} exceeded {limit} invocations this minute."));
            }

            foreach (var grant in context.Grants)
            {
                var current = _counts.TryGetValue(grant.GrantKey, out var entry) && entry.Minute == minute ? entry.Count : 0;
                _counts[grant.GrantKey] = (minute, current + 1);
            }

            return Task.FromResult(CaveatDecision.Satisfied);
        }
    }
}
