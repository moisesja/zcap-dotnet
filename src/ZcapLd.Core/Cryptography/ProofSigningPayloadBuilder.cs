using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using ZcapLd.Core.Models;

namespace ZcapLd.Core.Cryptography;

/// <summary>
/// Builds deterministic signing payloads for capabilities and invocations.
///
/// W3C Verifiable Credentials Data Integrity convention: the verification payload
/// is the document's own top-level fields plus a "proof" field containing every
/// proof field except "proofValue". Cross-stack interop (zcap-py, JS, Rust)
/// relies on this exact shape — any wrapper or hand-picked proof-field whitelist
/// breaks signature compatibility silently.
///
/// Two canonicalization strategies are supported:
/// - JCS: serialize the flat verification payload through JSON-then-canonicalize
///   (RFC 8785 — alphabetically sorted keys, no whitespace).
/// - RDFC-1.0: canonicalize document and proof options separately, SHA-256 each,
///   concatenate (per W3C Data Integrity spec).
/// </summary>
internal static class ProofSigningPayloadBuilder
{
    private static readonly JcsDocumentCanonicalizer DefaultJcs = new();

    /// <summary>
    /// Round-trips Capability / Proof / Invocation through System.Text.Json so that
    /// model properties contribute only the field names and value shapes their
    /// [JsonPropertyName] / [JsonIgnore(WhenWritingNull)] / [JsonConverter] attributes
    /// dictate. The result matches the on-the-wire JSON byte-for-byte (after JCS
    /// alphabetic sort), which is what every other Data Integrity verifier sees.
    /// </summary>
    private static readonly JsonSerializerOptions ModelSerializerOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = null,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static Capability CloneCapabilityWithoutProof(Capability capability)
    {
        ArgumentNullException.ThrowIfNull(capability);

        return new Capability
        {
            Context = capability.Context,
            Id = capability.Id,
            ParentCapability = capability.ParentCapability,
            Controller = capability.Controller,
            InvocationTarget = capability.InvocationTarget,
            Expires = capability.Expires,
            AllowedAction = capability.AllowedAction,
            Caveat = capability.Caveat,
            Proof = null
        };
    }

    public static Invocation CloneInvocationWithoutProof(Invocation invocation)
    {
        ArgumentNullException.ThrowIfNull(invocation);

        return new Invocation
        {
            Id = invocation.Id,
            Capability = invocation.Capability,
            CapabilityAction = invocation.CapabilityAction,
            InvocationTarget = invocation.InvocationTarget,
            Proof = null
        };
    }

    public static byte[] CanonicalizeCapabilityPayload(
        Capability capabilityWithoutProof,
        Proof proof,
        IDocumentCanonicalizer? canonicalizer = null)
    {
        ArgumentNullException.ThrowIfNull(capabilityWithoutProof);
        ArgumentNullException.ThrowIfNull(proof);

        canonicalizer ??= DefaultJcs;

        if (canonicalizer.Method == "RDFC-1.0")
        {
            return CanonicalizeCapabilityRdfc(capabilityWithoutProof, proof, canonicalizer);
        }

        return CanonicalizeCapabilityJcs(capabilityWithoutProof, proof, canonicalizer);
    }

    public static byte[] CanonicalizeInvocationPayload(
        Invocation invocationWithoutProof,
        Proof proof,
        IDocumentCanonicalizer? canonicalizer = null)
    {
        ArgumentNullException.ThrowIfNull(invocationWithoutProof);
        ArgumentNullException.ThrowIfNull(proof);

        canonicalizer ??= DefaultJcs;

        if (canonicalizer.Method == "RDFC-1.0")
        {
            return CanonicalizeInvocationRdfc(invocationWithoutProof, proof, canonicalizer);
        }

        return CanonicalizeInvocationJcs(invocationWithoutProof, proof, canonicalizer);
    }

    // ─── JCS — W3C Data Integrity flat shape ───────────────────────────

    private static byte[] CanonicalizeCapabilityJcs(
        Capability capabilityWithoutProof, Proof proof, IDocumentCanonicalizer canonicalizer)
    {
        var doc = ToFieldDictionary(capabilityWithoutProof);
        doc["proof"] = ToFieldDictionary(proof, exclude: "proofValue");
        return canonicalizer.Canonicalize(doc);
    }

    private static byte[] CanonicalizeInvocationJcs(
        Invocation invocationWithoutProof, Proof proof, IDocumentCanonicalizer canonicalizer)
    {
        var doc = ToFieldDictionary(invocationWithoutProof);
        doc["proof"] = ToFieldDictionary(proof, exclude: "proofValue");
        return canonicalizer.Canonicalize(doc);
    }

    // ─── RDFC-1.0 — W3C Data Integrity hash-concat shape ───────────────
    // Per spec: canonicalize document and proof options separately,
    // SHA-256 hash each, concatenate hashes → signing input.

    private static byte[] CanonicalizeCapabilityRdfc(
        Capability capabilityWithoutProof, Proof proof, IDocumentCanonicalizer canonicalizer)
    {
        // Proof options carry every proof field except proofValue, plus the document's @context
        // so JSON-LD processing has the same vocabulary the document uses.
        var proofOptions = ToFieldDictionary(proof, exclude: "proofValue");
        proofOptions["@context"] = JsonSerializer.SerializeToElement(
            capabilityWithoutProof.Context, ModelSerializerOptions);

        return ConcatenateHashes(
            canonicalizer.Canonicalize(capabilityWithoutProof),
            canonicalizer.Canonicalize(proofOptions));
    }

    private static byte[] CanonicalizeInvocationRdfc(
        Invocation invocationWithoutProof, Proof proof, IDocumentCanonicalizer canonicalizer)
    {
        // Invocations don't carry @context on the model, so add the ZCAP-LD default for JSON-LD processing.
        const string ZcapContext = "https://w3id.org/zcap/v1";

        var invocationDoc = ToFieldDictionary(invocationWithoutProof);
        invocationDoc["@context"] = JsonSerializer.SerializeToElement(ZcapContext, ModelSerializerOptions);

        var proofOptions = ToFieldDictionary(proof, exclude: "proofValue");
        proofOptions["@context"] = JsonSerializer.SerializeToElement(ZcapContext, ModelSerializerOptions);

        return ConcatenateHashes(
            canonicalizer.Canonicalize(invocationDoc),
            canonicalizer.Canonicalize(proofOptions));
    }

    /// <summary>
    /// Per W3C Data Integrity: SHA-256(proofOptionsCanonical) || SHA-256(documentCanonical).
    /// </summary>
    private static byte[] ConcatenateHashes(byte[] documentCanonical, byte[] proofOptionsCanonical)
    {
        var proofHash = SHA256.HashData(proofOptionsCanonical);
        var docHash = SHA256.HashData(documentCanonical);

        var result = new byte[proofHash.Length + docHash.Length];
        proofHash.CopyTo(result, 0);
        docHash.CopyTo(result, proofHash.Length);
        return result;
    }

    /// <summary>
    /// Round-trips a model object to a string-keyed dictionary of JSON elements,
    /// honoring [JsonPropertyName], [JsonIgnore(WhenWritingNull)], and [JsonConverter]
    /// on the model. The dictionary is what gets fed into the canonicalizer; key order
    /// is irrelevant because JCS sorts alphabetically.
    /// </summary>
    private static Dictionary<string, object> ToFieldDictionary<T>(T value, string? exclude = null)
    {
        var element = JsonSerializer.SerializeToElement(value, ModelSerializerOptions);
        var dict = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var prop in element.EnumerateObject())
        {
            if (exclude is not null && prop.Name == exclude) continue;
            dict[prop.Name] = prop.Value;
        }
        return dict;
    }
}
