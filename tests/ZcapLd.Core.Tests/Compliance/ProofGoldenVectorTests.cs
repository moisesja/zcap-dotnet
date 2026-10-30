using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using NetCrypto;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Compliance;

/// <summary>
/// End-to-end signed-capability KNOWN-ANSWER vectors (Phase 0 of the NetCrypto/DataProofs
/// migration — issue #108). These lock the full signing stack output — RDFC-1.0 canonicalization
/// → Ed25519 → base58-btc multibase — to an exact <c>proofValue</c> for a FIXED key and a FIXED
/// <c>created</c>. RDFC-1.0 is the only canonicalization ZCAP-LD supports (the interop format).
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
            // The context CapabilityService emits. With zcap/v1 alone the suite's proof terms were
            // never signed, and DataProofs 1.5.0 refuses to canonicalize it.
            Context = new object[] { "https://w3id.org/zcap/v1", "https://w3id.org/security/suites/ed25519-2020/v1" },
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

        // 2. The exact signature — the byte-compatibility lock for the RDFC-1.0 signing stack.
        proof.ProofValue.Should().Be(
            "z3zjEx6aEWsyw5sAxGHXsDCQk85vcNT25saZSGSpMwNSR8rHnwoBx6EFEhnW673pgx2quErTfpuxjct4Q6cFNrX4n",
            "the end-to-end Ed25519 signature over the RDFC-1.0 payload must be byte-stable — a changed " +
            "value means a canonicalizer/crypto swap broke the wire format");

        // 3. The golden is a REAL, valid signature over the exact RDFC-1.0 payload (not just a frozen string).
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
            .Should().BeTrue("the golden proofValue must verify against the public key over the RDFC-1.0 payload");

        // Surface the canonical payload in test output for cross-stack diffing.
        _ = Encoding.UTF8.GetString(canonicalBytes);
    }

    // ─── P-256 / EcdsaSecp256r1Signature2019 (#159) ──────────────────────────────────────────
    // ECDSA signatures are randomized, so a fresh P-256 proofValue is never byte-reproducible. These
    // vectors pin what is deterministic (the did:key for the fixed scalar and the RDFC-1.0 signing
    // payload) and verify a proofValue frozen from one signing run, which is the byte-compatibility
    // lock for the suite: a canonicalizer, context or crypto swap that changes the payload breaks it.
    private const string ExpectedP256PublicKeyMultibase = "zDnaeVuZeVRqvscGkiEoR9PFFra2xZUMp97ZPuGFK1VLU7iYN";
    private const string ExpectedP256PayloadSha256 = "6FE7C1E0E5554CA0E2CB43B16CE6CDA5E7989413CF7393FB45C6A919CDF8BE21";
    private const string FrozenP256ProofValue =
        "z38qrvaTyGrUjStLEorTzEWfYcos2pWcsaGfkcXWMr6bSGoLWwP9zp6wRTfLocdJjpU6nhbriaUvPCwmdBPnrPF1w";

    [Fact(DisplayName = "Golden: key derivation from the fixed P-256 scalar is stable")]
    public void FixedSeed_DerivesExpectedP256DidKey()
    {
        var kp = new DefaultKeyGenerator().FromPrivateKey(KeyType.P256, FixedPrivateKey);

        kp.MultibasePublicKey.Should().Be(ExpectedP256PublicKeyMultibase,
            "the compressed P-256 point and its p256-pub multicodec must stay byte-stable");
        kp.PublicKey.Should().HaveCount(33);
    }

    [Fact(DisplayName = "Golden: P-256 delegated-capability signing payload and frozen proofValue (locks the suite's bytes)")]
    public async Task DelegatedCapability_P256_PayloadAndFrozenProofValue_MatchGolden()
    {
        var kp = new DefaultKeyGenerator().FromPrivateKey(KeyType.P256, FixedPrivateKey);
        var did = $"did:key:{kp.MultibasePublicKey}";

        var provider = new InMemoryDidProvider();
        provider.RegisterKey(did, FixedPrivateKey, KeyType.P256);
        var signingService = new SigningService(provider, provider);

        var capability = new Capability
        {
            // The context CapabilityService emits for a P-256 signer (#159).
            Context = new object[] { "https://w3id.org/zcap/v1", ZcapSuiteCatalog.P256ContextUrl },
            Id = "urn:uuid:00000000-0000-0000-0000-0000000000de",
            ParentCapability = "urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi%2Fresource",
            Controller = did,
            InvocationTarget = "https://example.com/api/resource",
            AllowedAction = new[] { "read" },
            Expires = "2027-01-01T00:00:00.000000Z",
        };
        var chain = new object[] { "urn:zcap:root:https%3A%2F%2Fexample.com%2Fapi%2Fresource" };

        var proof = await signingService.SignCapabilityAsync(
            capability, did, "capabilityDelegation", chain,
            createdOverride: new DateTime(2026, 6, 13, 0, 0, 0, DateTimeKind.Utc));

        proof.Type.Should().Be("EcdsaSecp256r1Signature2019");
        proof.Created.Should().Be(ExpectedCreated);
        proof.VerificationMethod.Should().Be($"{did}#{kp.MultibasePublicKey}");
        MultibaseCodec.Decode(proof.ProofValue).Should().HaveCount(64, "IEEE P1363 r||s for P-256");

        // 1. The RDFC-1.0 signing payload (proof options hash || document hash) is deterministic and pinned.
        var options = new Proof
        {
            Type = proof.Type,
            Created = proof.Created,
            ProofPurpose = proof.ProofPurpose,
            VerificationMethod = proof.VerificationMethod,
            CapabilityChain = proof.CapabilityChain,
            ProofValue = string.Empty,
        };
        var withoutProof = ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(capability);
        var payload = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(withoutProof, options);
        Convert.ToHexString(SHA256.HashData(payload)).Should().Be(ExpectedP256PayloadSha256,
            "the P-256 RDFC-1.0 signing payload must stay byte-stable");

        // 2. The fresh (randomized) signature verifies over that payload.
        var crypto = new DefaultCryptoProvider();
        crypto.Verify(KeyType.P256, kp.PublicKey, payload, MultibaseCodec.Decode(proof.ProofValue), EcdsaSignatureFormat.IeeeP1363)
            .Should().BeTrue();

        // 3. The proofValue frozen from one signing run still verifies, at the raw-crypto layer and through
        //    the production dispatch: previously issued P-256 capabilities keep verifying.
        crypto.Verify(KeyType.P256, kp.PublicKey, payload, MultibaseCodec.Decode(FrozenP256ProofValue), EcdsaSignatureFormat.IeeeP1363)
            .Should().BeTrue("the frozen P-256 proofValue must verify over the pinned RDFC-1.0 payload");
        var frozen = new Proof
        {
            Type = options.Type,
            Created = options.Created,
            ProofPurpose = options.ProofPurpose,
            VerificationMethod = options.VerificationMethod,
            CapabilityChain = options.CapabilityChain,
            ProofValue = FrozenP256ProofValue,
        };
        new LegacyProofCrypto()
            .Verify(withoutProof, frozen, new ResolvedKey(kp.PublicKey, "EcdsaSecp256r1VerificationKey2019"))
            .Should().BeTrue();
    }
}
