using System.Text;
using FluentAssertions;
using NetDid.Core.Crypto;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Compliance;

/// <summary>
/// End-to-end signed-capability KNOWN-ANSWER vectors (Phase 0 of the NetCrypto/DataProofs
/// migration — issue #108). Unlike <see cref="CrossLanguageJcsInteropTests"/>, which pins only
/// the JCS signing <em>payload</em>, these lock the full signing stack output — canonicalization
/// → Ed25519 → base58-btc multibase — to an exact <c>proofValue</c> for a FIXED key and a FIXED
/// <c>created</c>.
///
/// Why this matters: the migration swaps the raw-crypto provider from NetDid's
/// <c>DefaultCryptoProvider</c> to NetCrypto's (Stage A), and later the canonicalizer/multibase to
/// NetCid/DataProofs (Stage B). Each swap MUST be byte-for-byte transparent or every previously
/// issued capability stops verifying. Ed25519 is deterministic (RFC 8032), so a fixed key + fixed
/// payload yields a stable signature — making this the only test that catches a silent signature
/// drift across those swaps (an in-process round-trip would still pass with the wrong-but-consistent
/// bytes on both sides). If a vector here changes, a swap broke wire compatibility — do not "update
/// the golden", investigate.
/// </summary>
public class ProofGoldenVectorTests
{
    // A FIXED Ed25519 seed (bytes 1..32). Test-only; never a real key.
    private static readonly byte[] FixedPrivateKey =
        Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();

    // Golden values derived from FixedPrivateKey (locked on first green run).
    private const string ExpectedPublicKeyMultibase = "z6MkneMkZqwqRiU5mJzSG3kDwzt9P8C59N4NGTfBLfSGE7c7";
    private const string ExpectedCreated = "2026-06-13T00:00:00.000000Z";

    [Fact(DisplayName = "Golden: key derivation from the fixed Ed25519 seed is stable")]
    public void FixedSeed_DerivesExpectedDidKey()
    {
        var kp = new DefaultKeyGenerator().FromPrivateKey(KeyType.Ed25519, FixedPrivateKey);

        kp.MultibasePublicKey.Should().Be(ExpectedPublicKeyMultibase,
            "key derivation must stay byte-stable across the NetDid→NetCrypto swap (Stage A) — " +
            "this multibase encodes the public key other parties resolve the verificationMethod to");
    }

    [Fact(DisplayName = "Golden: deterministic delegated-capability proofValue (locks the full signing stack)")]
    public async Task DelegatedCapability_DeterministicProofValue_MatchesGolden()
    {
        var kp = new DefaultKeyGenerator().FromPrivateKey(KeyType.Ed25519, FixedPrivateKey);
        var did = $"did:key:{kp.MultibasePublicKey}";

        var provider = new InMemoryDidProvider();
        provider.RegisterKey(did, FixedPrivateKey);
        var signingService = new SigningService(provider, provider);

        // A fully-specified delegated capability — every signed field is fixed so the
        // canonical payload (and therefore the signature) is reproducible.
        var capability = new Capability
        {
            Context = "https://w3id.org/zcap/v1",
            Id = "urn:uuid:00000000-0000-0000-0000-0000000000de",
            ParentCapability = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi%2Fresource",
            Controller = did,
            InvocationTarget = "https://example.com/api/resource",
            AllowedAction = new[] { "read" },
            Expires = "2027-01-01T00:00:00.000000Z",
        };

        var proof = await signingService.SignCapabilityAsync(
            capability,
            signerDid: did,
            proofPurpose: "capabilityDelegation",
            capabilityChain: new object[] { "urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi%2Fresource" },
            createdOverride: new DateTime(2026, 6, 13, 0, 0, 0, DateTimeKind.Utc));

        // 1. Proof metadata is deterministic.
        proof.Type.Should().Be("Ed25519Signature2020");
        proof.ProofPurpose.Should().Be("capabilityDelegation");
        proof.Created.Should().Be(ExpectedCreated);
        proof.VerificationMethod.Should().Be($"{did}#{kp.MultibasePublicKey}");

        // 2. The exact signature — the byte-compatibility lock for Stage A / Stage B.
        proof.ProofValue.Should().Be(
            "z5vKNNJVDziWyjoSSxFCNXJ6ZL4FSfrA7TbWDwhkBmkHCgN4448kTMJTUoK3pW35dNrGbyWP1moBSCb4nsYAc5fx8",
            "the end-to-end Ed25519 signature over the JCS payload must be byte-identical before and " +
            "after the NetDid→NetCrypto / NetCid swaps — a changed value means a swap broke the wire format");

        // 3. The golden is a REAL, valid signature over the exact JCS payload (not just a frozen string).
        var canonicalBytes = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(
            ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(capability),
            new Proof
            {
                Type = proof.Type,
                Created = proof.Created,
                ProofPurpose = proof.ProofPurpose,
                VerificationMethod = proof.VerificationMethod,
                CapabilityChain = proof.CapabilityChain,
                ProofValue = string.Empty,
            });
        var signature = MultibaseCodec.Decode(proof.ProofValue);
        new DefaultCryptoProvider()
            .Verify(KeyType.Ed25519, kp.PublicKey, canonicalBytes, signature)
            .Should().BeTrue("the golden proofValue must verify against the public key over the JCS payload");

        // Surface the canonical payload in test output for cross-stack diffing.
        _ = Encoding.UTF8.GetString(canonicalBytes);
    }
}
