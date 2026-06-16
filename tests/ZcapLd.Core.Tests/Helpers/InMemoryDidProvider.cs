using System.Collections.Concurrent;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.Core.Tests.Helpers;

/// <summary>
/// Test-only IDidSigner + IDidResolver (+ IVerificationRelationshipResolver + IRootCapabilityResolver)
/// backed by in-memory Ed25519 keys. NOT for production use — private keys are stored in plaintext
/// memory. Because <see cref="VerificationService"/> auto-detects an <see cref="IDidResolver"/> that
/// also implements <see cref="IRootCapabilityResolver"/>, registering a root via
/// <see cref="RegisterRoot"/> makes the verifier resolve spec-exact (root-by-id) chains without
/// passing the root on each call.
/// </summary>
public class InMemoryDidProvider : IDidSigner, IDidResolver, IVerificationRelationshipResolver, IRootCapabilityResolver
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
        if (data == null)
            throw new ArgumentNullException(nameof(data));

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

        // Try registered keys first (derive public from stored private)
        var baseDid = didOrVerificationMethod.Split('#')[0];
        if (_keyStore.TryGetValue(baseDid, out var privateKey))
        {
            var publicKey = KeyGen.FromPrivateKey(KeyType.Ed25519, privateKey).PublicKey;
            return Task.FromResult(new ResolvedKey(publicKey, "Ed25519VerificationKey2020"));
        }

        // Fall back to did:key resolver for public-key-in-DID resolution
        return _didKeyResolver.ResolvePublicKeyAsync(didOrVerificationMethod);
    }

    public Task<string> GetVerificationMethodAsync(string did)
    {
        if (string.IsNullOrEmpty(did))
            throw new ArgumentException("DID cannot be null or empty", nameof(did));

        if (did.StartsWith("did:key:"))
        {
            return _didKeyResolver.GetVerificationMethodAsync(did);
        }

        // For other DID methods, return with a standard key fragment
        return Task.FromResult($"{did}#key-1");
    }

    // --- IVerificationRelationshipResolver ---

    /// <summary>
    /// did:key-equivalent authorization for this in-memory backend: the DID <em>is</em> the key
    /// identity, so a verification method is authorized for every relationship of the controller
    /// whose DID it belongs to (controller == the VM's base DID). This mirrors a real did:key
    /// document, which lists its single key under all verification relationships — and lets tests
    /// use synthetic <c>did:key:…</c> identifiers that a standalone <c>DidKeyMethod</c> could not decode.
    /// </summary>
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

    /// <summary>
    /// Resolves a root capability previously registered via <see cref="RegisterRoot"/>. Returns null
    /// for an unknown id so the verifier fails closed, exactly as a production resolver would.
    /// </summary>
    public Task<Capability?> ResolveRootAsync(string rootCapabilityId)
    {
        if (string.IsNullOrEmpty(rootCapabilityId))
            return Task.FromResult<Capability?>(null);

        return Task.FromResult(_rootStore.TryGetValue(rootCapabilityId, out var root) ? root : null);
    }

    // --- Convenience methods ---

    /// <summary>
    /// Registers a root capability so the verifier (which auto-detects this provider as an
    /// <see cref="IRootCapabilityResolver"/>) can resolve the root a spec-exact chain references by id.
    /// Returns the same capability for fluent use: <c>var root = provider.RegisterRoot(await create...)</c>.
    /// </summary>
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
        if (privateKey == null || privateKey.Length != 32)
            throw new ArgumentException("Private key must be 32 bytes for Ed25519", nameof(privateKey));

        _keyStore[did] = privateKey;
    }

    public (byte[] PrivateKey, byte[] PublicKey) GenerateAndRegisterKeyPair(string did)
    {
        var kp = KeyGen.Generate(KeyType.Ed25519);
        RegisterKey(did, kp.PrivateKey);
        return (kp.PrivateKey, kp.PublicKey);
    }

    public string GenerateDidKey()
    {
        var keyPair = KeyGen.Generate(KeyType.Ed25519);
        var did = $"did:key:{keyPair.MultibasePublicKey}";

        RegisterKey(did, keyPair.PrivateKey);
        return did;
    }
}
