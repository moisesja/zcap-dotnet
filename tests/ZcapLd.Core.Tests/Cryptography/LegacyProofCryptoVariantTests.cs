using System.Text.Json;
using DataProofsDotnet.DataIntegrity;
using DataProofsDotnet.Legacy.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Cryptography;

/// <summary>
/// Pins which legacy-suite variants zcap's verifier accepts (#159, acceptance criterion 2). zcap signs
/// RDFC-1.0 only, but DataProofs 1.5.0's legacy suites verify the construction-time variant first and then
/// fall back to the other, because the JCS and RDFC variants share a proof <c>type</c> and carry no
/// <c>cryptosuite</c>. A proof produced with DataProofs' JCS variant over a zcap capability is therefore
/// accepted today. That is not a forgery path (JCS binds every member verbatim) but it is wider than the
/// documented RDFC-1.0 profile. When DataProofs ships <c>LegacyVariantVerification.ConstructedVariantOnly</c>,
/// <see cref="LegacyProofCrypto"/> adopts it and this test flips to <see cref="VerificationOutcome.InvalidSignature"/>
/// (tracked follow-up to #159).
/// </summary>
public class LegacyProofCryptoVariantTests
{
    [Theory(DisplayName = "A JCS-variant legacy proof is accepted through DataProofs' fallback (pinned; flips with ConstructedVariantOnly)")]
    [InlineData(KeyType.Ed25519)]
    [InlineData(KeyType.P256)]
    public async Task JcsVariantProof_IsCurrentlyAccepted_AndIsNotAnRdfcSignature(KeyType keyType)
    {
        var did = new InMemoryDidProvider();
        var signing = new SigningService(did, did);
        var caps = new CapabilityService(signing);
        var verifier = new VerificationService(did);

        var owner = did.GenerateDidKey(keyType);
        var agent = did.GenerateDidKey(keyType);
        var root = did.RegisterRoot(await caps.CreateRootCapabilityAsync(owner, $"https://variant.example/{keyType}"));
        var delegated = await caps.DelegateCapabilityAsync(root, agent, new[] { "read" }, DateTime.UtcNow.AddHours(1));
        var rdfcProof = delegated.Proof!.Primary;
        (await verifier.VerifyCapabilityProofDetailedAsync(delegated)).Outcome.Should().Be(VerificationOutcome.Valid);

        // Re-sign the same capability with DataProofs' JCS variant: the same proof options, the proof nested
        // back into the document and JCS-canonicalized (the 3.x zcap-dotnet convention).
        var suite = ZcapSuiteCatalog.GetByProofType(rdfcProof.Type)!;
        var resolved = await did.ResolvePublicKeyAsync(owner);
        ISigner signer = new DidSignerAdapter(did, owner, keyType, suite.ProofType, resolved.PublicKeyBytes);
        ICryptosuite jcsSuite = keyType == KeyType.Ed25519
            ? new Ed25519Signature2020Cryptosuite(LegacyCanonicalization.Jcs)
            : new EcdsaSecp256r1Signature2019Cryptosuite(LegacyCanonicalization.Jcs);
        var withoutProof = ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(delegated);
        var options = new Proof
        {
            Type = rdfcProof.Type,
            Created = rdfcProof.Created,
            ProofPurpose = rdfcProof.ProofPurpose,
            VerificationMethod = rdfcProof.VerificationMethod,
            CapabilityChain = rdfcProof.CapabilityChain,
            ProofValue = string.Empty,
        };
        var jcsProof = await jcsSuite.CreateProofAsync(
            JsonSerializer.SerializeToElement(withoutProof, ZcapJsonOptions.Default),
            LegacyProofCrypto.ToDataIntegrityProof(options),
            signer);
        var forged = new Proof
        {
            Type = rdfcProof.Type,
            Created = rdfcProof.Created,
            ProofPurpose = rdfcProof.ProofPurpose,
            VerificationMethod = rdfcProof.VerificationMethod,
            CapabilityChain = rdfcProof.CapabilityChain,
            ProofValue = jcsProof.ProofValue!,
        };
        forged.ProofValue.Should().NotBe(rdfcProof.ProofValue);

        // Evidence that an acceptance can only come through the fallback: the JCS signature is not a
        // signature over the RDFC-1.0 payload.
        var rdfcPayload = ProofSigningPayloadBuilder.CanonicalizeCapabilityPayload(withoutProof, options);
        var signature = MultibaseCodec.Decode(forged.ProofValue);
        var crypto = new DefaultCryptoProvider();
        var validOverRdfc = keyType == KeyType.Ed25519
            ? crypto.Verify(KeyType.Ed25519, resolved.PublicKeyBytes, rdfcPayload, signature)
            : crypto.Verify(KeyType.P256, resolved.PublicKeyBytes, rdfcPayload, signature, EcdsaSignatureFormat.IeeeP1363);
        validOverRdfc.Should().BeFalse("the JCS variant signs different bytes");

        delegated.Proof = forged;
        var result = await verifier.VerifyCapabilityProofDetailedAsync(delegated);

        result.Outcome.Should().Be(VerificationOutcome.Valid,
            "DataProofs 1.5.0 falls back to the JCS variant; assert InvalidSignature once LegacyProofCrypto " +
            "constructs the suites with LegacyVariantVerification.ConstructedVariantOnly");
    }
}
