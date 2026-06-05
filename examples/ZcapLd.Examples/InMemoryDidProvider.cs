using System.Collections.Concurrent;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.Examples;

/// <summary>
/// Example IDidSigner + IDidResolver (+ IVerificationRelationshipResolver) for demonstration
/// purposes. Stores Ed25519 private keys in plaintext memory — NOT for production use.
///
/// In production, implement IDidSigner backed by your secure key management system
/// (HSM, Azure Key Vault, AWS KMS, etc.) and IDidResolver backed by a
/// universal resolver or DID method-specific resolver. A resolver that also implements
/// IVerificationRelationshipResolver lets the verifier authorize controllers by resolving
/// their DID document (capabilityInvocation / capabilityDelegation) — Issue #65.
/// </summary>
public class InMemoryDidProvider : IDidSigner, IDidResolver, IVerificationRelationshipResolver, IRootCapabilityResolver
{
    private static readonly DefaultCryptoProvider Crypto = new();
    private static readonly DefaultKeyGenerator KeyGen = new();
    private readonly ConcurrentDictionary<string, byte[]> _keyStore = new();
    private readonly ConcurrentDictionary<string, Capability> _rootStore = new(StringComparer.Ordinal);
    private readonly DidKeyResolver _didKeyResolver = new();

    public Task<SignatureResult> SignAsync(string did, byte[] data)
    {
        if (!_keyStore.TryGetValue(did, out var privateKey))
            throw new InvalidOperationException($"No private key registered for DID: {did}");

        var signatureBytes = Crypto.Sign(KeyType.Ed25519, privateKey, data);
        return Task.FromResult(new SignatureResult(signatureBytes, "Ed25519Signature2020"));
    }

    public Task<ResolvedKey> ResolvePublicKeyAsync(string didOrVerificationMethod)
    {
        var baseDid = didOrVerificationMethod.Split('#')[0];
        if (_keyStore.TryGetValue(baseDid, out var privateKey))
        {
            var publicKey = KeyGen.FromPrivateKey(KeyType.Ed25519, privateKey).PublicKey;
            return Task.FromResult(new ResolvedKey(publicKey, "Ed25519VerificationKey2020"));
        }

        return _didKeyResolver.ResolvePublicKeyAsync(didOrVerificationMethod);
    }

    public Task<string> GetVerificationMethodAsync(string did)
    {
        if (did.StartsWith("did:key:"))
            return _didKeyResolver.GetVerificationMethodAsync(did);

        return Task.FromResult($"{did}#key-1");
    }

    /// <summary>
    /// did:key-equivalent authorization for this demo backend: the DID is the key identity, so a
    /// verification method is authorized for every relationship of the controller whose DID it
    /// belongs to (controller == the VM's base DID), mirroring a real did:key document. A real
    /// resolver would resolve the controller's document and check the named relationship list.
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

    public void GenerateAndRegisterKeyPair(string did)
    {
        // Notice that this is unsecured. Make sure to use a secure key management solution in production.
        var kp = KeyGen.Generate(KeyType.Ed25519);
        _keyStore[did] = kp.PrivateKey;
    }

    /// <summary>
    /// Registers a root capability so the verifier — which auto-detects this provider as an
    /// <see cref="IRootCapabilityResolver"/> — can resolve the root a spec-exact delegation chain
    /// references by id only (Issue #50). Returns the same capability for fluent use. A real verifier
    /// would resolve roots from its own root-capability store.
    /// </summary>
    public Capability RegisterRoot(Capability root)
    {
        if (root is not null && !string.IsNullOrEmpty(root.Id))
            _rootStore[root.Id] = root;
        return root!;
    }

    /// <inheritdoc />
    public Task<Capability?> ResolveRootAsync(string rootCapabilityId)
    {
        if (string.IsNullOrEmpty(rootCapabilityId))
            return Task.FromResult<Capability?>(null);

        return Task.FromResult(_rootStore.TryGetValue(rootCapabilityId, out var root) ? root : null);
    }
}
