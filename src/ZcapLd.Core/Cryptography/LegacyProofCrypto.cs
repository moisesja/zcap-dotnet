using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using NetCid;
using NetCrypto;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using DataProofsRdfc = DataProofsDotnet.Rdfc;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Bridges ZCAP-LD signing and verification to DataProofs' legacy Linked-Data-Signature
/// cryptosuites (<c>Ed25519Signature2020</c>, <c>EcdsaSecp256r1Signature2019</c>) — the upstream,
/// byte-compatible implementations of zcap's 2020-era embedded-proof convention. zcap keeps its own
/// proof model, chain walking, and authorization policy; only the canonicalization + sign/verify
/// crypto is delegated here. The legacy suites emit <c>type</c> with no <c>cryptosuite</c> and a
/// base58-btc <c>proofValue</c>, identical to what zcap produced before the delegation.
/// </summary>
internal sealed class LegacyProofCrypto
{
    private const string ZcapContext = "https://w3id.org/zcap/v1";

    /// <summary>RFC 8785 JSON Canonicalization Scheme — the default.</summary>
    public const string JcsCanonicalization = "JCS";

    /// <summary>W3C RDF Dataset Canonicalization (RDFC-1.0).</summary>
    public const string RdfcCanonicalization = "RDFC-1.0";

    /// <summary>
    /// Validates a caller-supplied canonicalization method against the supported set
    /// (<see cref="JcsCanonicalization"/> / <see cref="RdfcCanonicalization"/>), returning it on
    /// success. Fails fast at construction so a typo (e.g. <c>"rdfc-1.0"</c>) cannot silently fall
    /// through to JCS in <see cref="Resolve"/> and hand the consumer the wrong algorithm.
    /// </summary>
    public static string ValidateCanonicalizationMethod(string canonicalizationMethod)
    {
        ArgumentNullException.ThrowIfNull(canonicalizationMethod);
        if (canonicalizationMethod is not (JcsCanonicalization or RdfcCanonicalization))
        {
            throw new ArgumentException(
                $"Unsupported canonicalization method '{canonicalizationMethod}'. " +
                $"Expected \"{JcsCanonicalization}\" or \"{RdfcCanonicalization}\" (case-sensitive).",
                nameof(canonicalizationMethod));
        }

        return canonicalizationMethod;
    }

    // RDFC canonicalizer wired with zcap's offline context loader (serves zcap/v1 + ed25519-2020/v1),
    // used by the RDFC variant and the RDFC verify fallback. Shared, immutable, thread-safe.
    private static readonly DataProofsRdfc.RdfcDocumentCanonicalizer RdfCanonicalizer =
        new(RdfcContextDocumentLoader.Instance);

    // Suites are immutable + thread-safe; cache per (proofType, canonicalization) so the RDFC
    // variant's canonicalizer is built once.
    private readonly ConcurrentDictionary<(string ProofType, LegacyCanonicalization Canon), ICryptosuite> _suites = new();

    /// <summary>
    /// Signs <paramref name="documentWithoutProof"/> under <paramref name="proofOptions"/> via the
    /// legacy suite for the proof's type, returning the base58-btc multibase <c>proofValue</c>.
    /// </summary>
    public async Task<string> CreateProofValueAsync(
        object documentWithoutProof, Proof proofOptions, ISigner signer, string canonicalizationMethod)
    {
        var suite = Resolve(proofOptions.Type, canonicalizationMethod)
            ?? throw new CryptographicException($"No legacy cryptosuite for proof type: {proofOptions.Type}");

        var document = BuildDocumentElement(documentWithoutProof, canonicalizationMethod);
        var diProofOptions = ToDataIntegrityProof(proofOptions);

        var proof = await suite.CreateProofAsync(document, diProofOptions, signer).ConfigureAwait(false);
        return proof.ProofValue
            ?? throw new CryptographicException("Legacy cryptosuite returned a proof without a proofValue.");
    }

    /// <summary>
    /// Verifies <paramref name="proof"/> over <paramref name="documentWithoutProof"/> with the
    /// supplied key via the legacy suite for the proof's type. Returns <c>false</c> on any
    /// failure (never throws for invalid input — mirrors the prior <c>suite.Verify</c> contract).
    /// </summary>
    public bool Verify(
        object documentWithoutProof, Proof proof, ResolvedKey resolvedKey, string canonicalizationMethod)
    {
        var suite = Resolve(proof.Type, canonicalizationMethod);
        if (suite is null)
        {
            return false;
        }

        PublicKeyMaterial publicKey;
        try
        {
            publicKey = PublicKeyMaterial.FromRaw(
                ResolvedKeyTypeMap.ToNetCryptoKeyType(resolvedKey.KeyType), resolvedKey.PublicKeyBytes);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            // Unknown/invalid resolved key material — fail closed (never throw on the verify path).
            return false;
        }

        var document = BuildDocumentElement(documentWithoutProof, canonicalizationMethod);
        var diProof = ToDataIntegrityProof(proof);
        return suite.VerifyProof(document, diProof, publicKey).Verified;
    }

    private ICryptosuite? Resolve(string? proofType, string canonicalizationMethod)
    {
        if (string.IsNullOrEmpty(proofType))
        {
            return null;
        }

        var canon = string.Equals(canonicalizationMethod, RdfcCanonicalization, StringComparison.Ordinal)
            ? LegacyCanonicalization.Rdfc
            : LegacyCanonicalization.Jcs;

        return proofType switch
        {
            Ed25519Signature2020Cryptosuite.ProofType or EcdsaSecp256r1Signature2019Cryptosuite.ProofType
                => _suites.GetOrAdd((proofType, canon), static k => Create(k.ProofType, k.Canon)),
            _ => null,
        };
    }

    private static ICryptosuite Create(string proofType, LegacyCanonicalization canon)
        => proofType == Ed25519Signature2020Cryptosuite.ProofType
            ? new Ed25519Signature2020Cryptosuite(canon, RdfCanonicalizer)
            : new EcdsaSecp256r1Signature2019Cryptosuite(canon, RdfCanonicalizer);

    // Serializes the document with zcap's JSON options (the exact bytes the prior payload builder
    // fed to canonicalization). For RDFC over a context-less document (invocations), inject the
    // ZCAP-LD context so JSON-LD expansion matches the prior RdfcInvocation path.
    //
    // Invariant: the only zcap documents that arrive here with an "@context" already present are
    // Capabilities, and zcap controls the model so that context is always zcap/v1 — so when the
    // guard finds an existing "@context" it is correct to leave it as-is (re-injecting would be a
    // no-op). Invocations never set "@context" in the model; this handles the serialized-without-
    // context case. A foreign/non-zcap "@context" cannot occur for a model-built document; if the
    // model ever gains one, this guard must be revisited (a different context would make RDFC
    // expansion silently produce the wrong N-Quads).
    private static JsonElement BuildDocumentElement(object documentWithoutProof, string canonicalizationMethod)
    {
        var element = JsonSerializer.SerializeToElement(documentWithoutProof, ZcapJsonOptions.Default);

        if (string.Equals(canonicalizationMethod, RdfcCanonicalization, StringComparison.Ordinal)
            && element.ValueKind == JsonValueKind.Object
            && !element.TryGetProperty("@context", out _))
        {
            var node = JsonObject.Create(element)!;
            node["@context"] = ZcapContext;
            return JsonSerializer.SerializeToElement(node, ZcapJsonOptions.Default);
        }

        return element;
    }

    // Maps zcap's Proof to DataProofs' DataIntegrityProof by round-tripping through JSON: modeled
    // members map by name (same camelCase), and the ZCAP-specific members (capabilityChain,
    // capability, capabilityAction, invocationTarget, signed extensions) ride in AdditionalProperties.
    // Both options use the same wire names and omit nulls, so the round trip is byte-preserving.
    //
    // This mapping is load-bearing: every zcap-specific proof field MUST survive into
    // AdditionalProperties so DataProofs includes it in the signing payload. If DataProofs ever
    // models one of those names (dropping it from AdditionalProperties), the field would silently
    // vanish from signed bytes — invisibly, because sign and verify share this method symmetrically.
    // LegacyProofCryptoMappingTests pins the survival of capabilityChain (incl. an embedded
    // capability object), capability, capabilityAction, and invocationTarget against that drift.
    // internal (not private) so that test can assert the real mapping rather than a copy.
    internal static DataIntegrityProof ToDataIntegrityProof(Proof proof)
    {
        var element = JsonSerializer.SerializeToElement(proof, ZcapJsonOptions.Default);
        return element.Deserialize<DataIntegrityProof>(DataProofsJsonOptions.Default)
            ?? throw new CryptographicException("Failed to map the ZCAP proof to a DataIntegrity proof.");
    }
}

/// <summary>
/// Adapts a ZCAP <see cref="IDidSigner"/> to the NetCrypto <see cref="ISigner"/> the DataProofs
/// cryptosuites consume. Sign-only: the legacy suites build the signing input and call
/// <see cref="SignAsync"/>. Reshapes the S-03 signer-type guard — the signer's declared signature
/// type must match the suite's proof type.
/// </summary>
internal sealed class DidSignerAdapter : ISigner
{
    private readonly IDidSigner _signer;
    private readonly string _did;
    private readonly string _expectedProofType;
    private readonly byte[] _publicKey;

    public DidSignerAdapter(IDidSigner signer, string did, KeyType keyType, string expectedProofType, byte[] publicKey)
    {
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
        _did = did ?? throw new ArgumentNullException(nameof(did));
        _expectedProofType = expectedProofType ?? throw new ArgumentNullException(nameof(expectedProofType));
        _publicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        KeyType = keyType;
    }

    public KeyType KeyType { get; }

    public ReadOnlyMemory<byte> PublicKey => _publicKey;

    public string MultibasePublicKey => Multikey.Encode(KeyType.GetMulticodec(), _publicKey);

    public async Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        var result = await _signer.SignAsync(_did, data.ToArray()).ConfigureAwait(false);

        // S-03 guard (reshaped from SigningService.ValidateSignatureType): a misconfigured signer
        // that declares the wrong algorithm must fail closed rather than emit a mismatched proof.
        if (!string.Equals(result.SignatureType, _expectedProofType, StringComparison.Ordinal))
        {
            throw new CryptographicException(
                $"Signer returned signature type '{result.SignatureType}' but expected '{_expectedProofType}'.");
        }

        return result.Signature;
    }
}

/// <summary>
/// Maps a resolved W3C verification-method key-type string (the vocabulary an
/// <see cref="IDidResolver"/> emits) to the NetCrypto <see cref="KeyType"/> the DataProofs
/// cryptosuites consume. The inverse of <c>DidKeyResolver.MapKeyType</c>.
/// </summary>
internal static class ResolvedKeyTypeMap
{
    public static KeyType ToNetCryptoKeyType(string keyType) => keyType switch
    {
        "Ed25519VerificationKey2020" => KeyType.Ed25519,
        "EcdsaSecp256r1VerificationKey2019" => KeyType.P256,
        "EcdsaSecp384r1VerificationKey2019" => KeyType.P384,
        "EcdsaSecp256k1VerificationKey2019" => KeyType.Secp256k1,
        "X25519KeyAgreementKey2020" => KeyType.X25519,
        _ => throw new CryptographicException($"Unsupported resolved key type: {keyType}"),
    };
}
