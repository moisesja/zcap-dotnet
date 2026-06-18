using System.Collections.Concurrent;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.Interop;

/// <summary>
/// Harness-only IDidSigner + IDidResolver (+ IVerificationRelationshipResolver + IRootCapabilityResolver),
/// a near-verbatim copy of the test project's <c>InMemoryDidProvider</c> (so cross-stack verification
/// behaves identically to the proven RDFC end-to-end tests) plus a <see cref="RegisterDeterministicDidKey"/>
/// helper that derives a real <c>did:key</c> from a fixed 32-byte Ed25519 seed — making the generated
/// vectors reproducible. NOT for production use: private keys live in plaintext memory.
///
/// Registered keys are resolved locally (public derived from the stored private); any other did:key
/// (e.g. one minted by @digitalbazaar/zcap on the JS side) falls back to the real did:key resolver,
/// so this provider can verify JS-produced capabilities purely from their did:key controller strings.
/// </summary>
public sealed class DeterministicDidProvider
    : IDidSigner, IDidResolver, IVerificationRelationshipResolver, IRootCapabilityResolver
{
    private static readonly DefaultCryptoProvider Crypto = new();
    private static readonly DefaultKeyGenerator KeyGen = new();
    private readonly ConcurrentDictionary<string, byte[]> _keyStore = new();
    private readonly ConcurrentDictionary<string, Capability> _rootStore = new(StringComparer.Ordinal);
    private readonly DidKeyResolver _didKeyResolver = new();

    // --- IDidSigner ---

    public Task<SignatureResult> SignAsync(string did, byte[] data)
    {
        if (string.IsNullOrEmpty(did))
            throw new ArgumentException("DID cannot be null or empty", nameof(did));
        ArgumentNullException.ThrowIfNull(data);

        if (!_keyStore.TryGetValue(did, out var privateKey))
            throw new InvalidOperationException($"No private key registered for DID: {did}");

        var signatureBytes = Crypto.Sign(KeyType.Ed25519, privateKey, data);
        return Task.FromResult(new SignatureResult(signatureBytes, "Ed25519Signature2020"));
    }

    // --- IDidResolver ---

    public Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod)
    {
        if (string.IsNullOrEmpty(didOrVerificationMethod))
            throw new ArgumentException("DID cannot be null or empty", nameof(didOrVerificationMethod));

        var baseDid = didOrVerificationMethod.Split('#')[0];
        if (_keyStore.TryGetValue(baseDid, out var privateKey))
        {
            var publicKey = KeyGen.FromPrivateKey(KeyType.Ed25519, privateKey).PublicKey;
            return Task.FromResult(new ResolvedKey(publicKey, "Ed25519VerificationKey2020"));
        }

        // Fall back to the real did:key resolver — lets us verify externally-minted capabilities.
        return _didKeyResolver.ResolvePublicKeyAsync(didOrVerificationMethod);
    }

    public Task<string> GetVerificationMethodAsync(string did)
    {
        if (string.IsNullOrEmpty(did))
            throw new ArgumentException("DID cannot be null or empty", nameof(did));

        if (did.StartsWith("did:key:", StringComparison.Ordinal))
            return _didKeyResolver.GetVerificationMethodAsync(did);

        return Task.FromResult($"{did}#key-1");
    }

    // --- IVerificationRelationshipResolver ---

    public Task<VerificationRelationshipAuthorizationResult> IsAuthorizedForRelationshipAsync(
        string controllerDid, string verificationMethodDidUrl,
        VerificationRelationship relationship, CancellationToken ct = default)
    {
        var vmBaseDid = verificationMethodDidUrl.Split('#')[0];
        return Task.FromResult(string.Equals(vmBaseDid, controllerDid, StringComparison.Ordinal)
            ? VerificationRelationshipAuthorizationResult.Authorized()
            : VerificationRelationshipAuthorizationResult.NotAuthorized());
    }

    // --- IRootCapabilityResolver ---

    public Task<Capability?> ResolveRootAsync(string rootCapabilityId)
    {
        if (string.IsNullOrEmpty(rootCapabilityId))
            return Task.FromResult<Capability?>(null);

        return Task.FromResult(_rootStore.TryGetValue(rootCapabilityId, out var root) ? root : null);
    }

    // --- Convenience ---

    public Capability RegisterRoot(Capability root)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (!string.IsNullOrEmpty(root.Id))
            _rootStore[root.Id] = root;
        return root;
    }

    public void RegisterKey(string did, byte[] privateKey)
    {
        if (string.IsNullOrEmpty(did))
            throw new ArgumentException("DID cannot be null or empty", nameof(did));
        if (privateKey is null || privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes for Ed25519", nameof(privateKey));

        _keyStore[did] = privateKey;
    }

    /// <summary>
    /// Derives a real <c>did:key</c> from a fixed 32-byte Ed25519 seed and registers it, so the same
    /// seed always yields the same did:key (and therefore reproducible golden vectors).
    /// </summary>
    public string RegisterDeterministicDidKey(byte[] seed)
    {
        if (seed is null || seed.Length != 32)
            throw new ArgumentException("Seed must be 32 bytes for Ed25519", nameof(seed));

        var keyPair = KeyGen.FromPrivateKey(KeyType.Ed25519, seed);
        var did = $"did:key:{keyPair.MultibasePublicKey}";
        RegisterKey(did, seed);
        return did;
    }
}
