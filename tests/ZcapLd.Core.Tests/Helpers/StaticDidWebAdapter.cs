using NetCid;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using ZcapLd.Core.Exceptions;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.Core.Tests.Helpers;

/// <summary>
/// Test-only <em>non-did:key</em> method adapter (Issue #148): a zcap <see cref="IDidResolver"/> that
/// also implements NetDid's <see cref="IVerificationRelationshipResolver"/>, backed by hand-built
/// <c>did:web</c> documents. Key resolution decodes the named verification method's
/// <c>publicKeyMultibase</c>; relationship authorization runs NetDid's real
/// <see cref="DefaultVerificationRelationshipResolver"/> over the same documents. Both paths record
/// their calls so tests can prove which composite child answered, and
/// <see cref="AsKeyOnly"/> exposes a key-resolution-only view to exercise the composite's
/// fail-closed branch.
/// </summary>
internal sealed class StaticDidWebAdapter : IDidResolver, IVerificationRelationshipResolver
{
    public const string MethodPrefix = "did:web:";

    private readonly Dictionary<string, DidDocument> _documents;
    private readonly DefaultVerificationRelationshipResolver _relationships;

    public StaticDidWebAdapter(params DidDocument[] documents)
    {
        _documents = documents.ToDictionary(d => d.Id.Value, d => d, StringComparer.Ordinal);
        _relationships = new DefaultVerificationRelationshipResolver(
            new StaticDidDocumentResolver(documents.Select(d => (d.Id.Value, d)).ToArray()));
    }

    /// <summary>Number of <see cref="ResolvePublicKeyAsync"/> calls (through this adapter or its key-only view).</summary>
    public int KeyResolutions { get; private set; }

    /// <summary>Every relationship-authorization call routed to this adapter.</summary>
    public List<(string Controller, string VerificationMethod, VerificationRelationship Relationship)> RelationshipCalls { get; } = new();

    public Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod)
    {
        KeyResolutions++;

        var hashIndex = didOrVerificationMethod.IndexOf('#');
        var did = hashIndex < 0 ? didOrVerificationMethod : didOrVerificationMethod[..hashIndex];
        if (!_documents.TryGetValue(did, out var document))
            throw new CapabilityValidationException($"Unknown did:web document: {did}");

        var method = hashIndex < 0
            ? document.VerificationMethod?.FirstOrDefault()
            : document.VerificationMethod?.FirstOrDefault(m =>
                string.Equals(m.Id, didOrVerificationMethod, StringComparison.Ordinal));
        if (method?.PublicKeyMultibase is null)
            throw new CapabilityValidationException($"No verification method with key material: {didOrVerificationMethod}");

        var (codec, rawKey) = Multicodec.Decode(Multibase.Decode(method.PublicKeyMultibase));
        var keyType = KeyTypeExtensions.FromMulticodec(codec) switch
        {
            KeyType.Ed25519 => "Ed25519VerificationKey2020",
            KeyType.P256 => "EcdsaSecp256r1VerificationKey2019",
            var other => throw new CapabilityValidationException($"Unsupported test key type: {other}")
        };
        return Task.FromResult(new ResolvedKey(rawKey, keyType));
    }

    // Mirrors InMemoryDidProvider's convention for non-did:key DIDs so the signer and verifier
    // agree on the method id without a document lookup.
    public Task<string> GetVerificationMethodAsync(string did) => Task.FromResult($"{did}#key-1");

    public Task<VerificationRelationshipAuthorizationResult> IsAuthorizedForRelationshipAsync(
        string controllerDid, string verificationMethodDidUrl,
        VerificationRelationship relationship, CancellationToken ct = default)
    {
        RelationshipCalls.Add((controllerDid, verificationMethodDidUrl, relationship));
        return _relationships.IsAuthorizedForRelationshipAsync(
            controllerDid, verificationMethodDidUrl, relationship, ct);
    }

    /// <summary>
    /// A view that resolves keys through this adapter but does NOT implement
    /// <see cref="IVerificationRelationshipResolver"/> — the misconfiguration the composite must
    /// fail closed on rather than inferring authority from key resolution.
    /// </summary>
    public IDidResolver AsKeyOnly() => new KeyOnlyView(this);

    private sealed class KeyOnlyView(StaticDidWebAdapter inner) : IDidResolver
    {
        public Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod) =>
            inner.ResolvePublicKeyAsync(didOrVerificationMethod);

        public Task<string> GetVerificationMethodAsync(string did) => inner.GetVerificationMethodAsync(did);
    }
}

/// <summary>A did:web identity: its DID, its single verification-method id and the controller document.</summary>
internal sealed record DidWebIdentity(string Did, string MethodId, DidDocument Document);

/// <summary>Builds did:web identities whose Ed25519 key is registered with an <see cref="InMemoryDidProvider"/> for signing.</summary>
internal static class DidWebIdentities
{
    private static readonly DefaultKeyGenerator KeyGen = new();

    /// <summary>
    /// Creates <paramref name="did"/> with one Ed25519 key (<c>{did}#key-1</c>), registered with
    /// <paramref name="signer"/> so it can sign, and listed under the requested relationships so tests
    /// can model per-purpose key separation (e.g. a key authorized to invoke but not to delegate).
    /// </summary>
    public static DidWebIdentity Create(
        InMemoryDidProvider signer, string did,
        bool capabilityInvocation = true, bool capabilityDelegation = true)
    {
        var keyPair = KeyGen.Generate(KeyType.Ed25519);
        signer.RegisterKey(did, keyPair.PrivateKey);

        var methodId = $"{did}#key-1";
        var method = new VerificationMethod
        {
            Id = methodId,
            Type = "Ed25519VerificationKey2020",
            Controller = did,
            PublicKeyMultibase = keyPair.MultibasePublicKey
        };
        var document = new DidDocument
        {
            Id = did,
            VerificationMethod = new[] { method },
            CapabilityInvocation = capabilityInvocation ? new[] { VerificationRelationshipEntry.FromReference(methodId) } : null,
            CapabilityDelegation = capabilityDelegation ? new[] { VerificationRelationshipEntry.FromReference(methodId) } : null
        };
        return new DidWebIdentity(did, methodId, document);
    }

    /// <summary>
    /// A controller document with no key of its own that references an external verification method
    /// (cross-DID reference, e.g. a did:web organisation authorizing a did:key device).
    /// </summary>
    public static DidDocument Referencing(
        string did, string methodId,
        bool capabilityInvocation = true, bool capabilityDelegation = true) => new()
    {
        Id = did,
        CapabilityInvocation = capabilityInvocation ? new[] { VerificationRelationshipEntry.FromReference(methodId) } : null,
        CapabilityDelegation = capabilityDelegation ? new[] { VerificationRelationshipEntry.FromReference(methodId) } : null
    };
}
