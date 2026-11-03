using System.Text.Json;
using DataProofsDotnet.Rdfc;
using FluentAssertions;
using Xunit;
using ZcapLd.Core.Cryptography;

namespace ZcapLd.Core.Tests.Cryptography;

/// <summary>
/// The suite catalog and the offline context loader must agree (#159): a suite the catalog advertises
/// whose context the loader cannot serve fails every signing and RDFC verification for that suite.
/// P-256 was advertised with <c>https://w3id.org/security/suites/ecdsa-2019/v1</c>, a URL from the 2022
/// CG draft that was never published, so no P-256 capability could be created.
/// </summary>
public class RdfcContextDocumentLoaderTests
{
    private const string Ed25519Context = "https://w3id.org/security/suites/ed25519-2020/v1";
    private const string UnpublishedEcdsa2019Url = "https://w3id.org/security/suites/ecdsa-2019/v1";

    [Theory(DisplayName = "Every supported suite's context is served offline and defines the suite's proof and key types")]
    [InlineData("Ed25519Signature2020")]
    [InlineData("EcdsaSecp256r1Signature2019")]
    public void SupportedSuiteContext_IsServedAndDefinesTheSuite(string proofType)
    {
        var suite = ZcapSuiteCatalog.GetByProofType(proofType);
        suite.Should().NotBeNull();

        var loaded = RdfcContextDocumentLoader.Instance.Load(new Uri(suite!.ContextUrl));

        loaded.DocumentUrl.AbsoluteUri.Should().Be(suite.ContextUrl);
        using var document = JsonDocument.Parse(loaded.Content);
        var context = document.RootElement.GetProperty("@context");
        context.GetProperty("@protected").GetBoolean().Should().BeTrue("a suite context must not be overridable");
        context.GetProperty(suite.ProofType).GetProperty("@id").GetString()
            .Should().Be($"https://w3id.org/security#{suite.ProofType}");
        context.GetProperty(suite.KeyType).GetProperty("@id").GetString()
            .Should().Be($"https://w3id.org/security#{suite.KeyType}");

        // The proof terms RDFC must sign (#157) are scoped to the suite's proof type.
        var scoped = context.GetProperty(suite.ProofType).GetProperty("@context");
        scoped.GetProperty("@protected").GetBoolean().Should().BeTrue();
        foreach (var term in new[] { "created", "proofPurpose", "verificationMethod", "proofValue" })
            scoped.TryGetProperty(term, out _).Should().BeTrue($"'{term}' must be signed for {proofType}");
        foreach (var purpose in new[] { "capabilityDelegation", "capabilityInvocation" })
            scoped.GetProperty("proofPurpose").GetProperty("@context").TryGetProperty(purpose, out _)
                .Should().BeTrue($"'{purpose}' must expand under {proofType}");
    }

    [Fact(DisplayName = "The catalog lists exactly the two supported suite contexts, Ed25519 first")]
    public void CatalogContextUrls_AreTheTwoSupportedSuites()
    {
        ZcapSuiteCatalog.ContextUrls.Should().Equal(Ed25519Context, ZcapSuiteCatalog.P256ContextUrl);
        ZcapSuiteCatalog.P256ContextUrl.Should().Be("urn:zcap-dotnet:ecdsa-secp256r1-2019-context:v1");
        ZcapSuiteCatalog.IsSupportedContext(ZcapSuiteCatalog.P256ContextUrl).Should().BeTrue();
    }

    [Fact(DisplayName = "The P-256 context is the ed25519-2020/v1 context with the suite and key type names swapped")]
    public void P256Context_MirrorsTheEd25519Context()
    {
        // Compared as RFC 8785 canonical JSON, so formatting and key order are irrelevant: only the
        // term definitions matter.
        static byte[] Canonical(string json) =>
            NetCid.JcsCanonicalizer.Canonicalize(JsonDocument.Parse(json).RootElement);
        var ed25519 = RdfcContextDocumentLoader.Instance.Load(new Uri(Ed25519Context)).Content;
        var p256 = RdfcContextDocumentLoader.Instance.Load(new Uri(ZcapSuiteCatalog.P256ContextUrl)).Content;

        var renamed = p256.Replace("EcdsaSecp256r1Signature2019", "Ed25519Signature2020")
            .Replace("EcdsaSecp256r1VerificationKey2019", "Ed25519VerificationKey2020");

        Canonical(renamed).Should().Equal(Canonical(ed25519),
            "the local context must define exactly the terms the published suite context shape defines");
    }

    [Fact(DisplayName = "The unpublished ecdsa-2019/v1 URL is neither a supported context nor served")]
    public void UnpublishedEcdsa2019Url_IsNotSupportedOrServed()
    {
        ZcapSuiteCatalog.IsSupportedContext(UnpublishedEcdsa2019Url).Should().BeFalse();

        var act = () => RdfcContextDocumentLoader.Instance.Load(new Uri(UnpublishedEcdsa2019Url));

        act.Should().Throw<RdfCanonicalizationException>("the loader is offline and fails closed on an unknown context");
    }

    [Fact(DisplayName = "The loader serves the revocation context and fails closed on anything else")]
    public void Loader_ServesRevocationContext_AndFailsClosedOtherwise()
    {
        RdfcContextDocumentLoader.Instance.Load(new Uri(RdfcContextDocumentLoader.RevocationContextUrl))
            .Content.Should().Contain("capabilityRevocation");

        var act = () => RdfcContextDocumentLoader.Instance.Load(new Uri("https://w3id.org/security/v2"));

        act.Should().Throw<RdfCanonicalizationException>();
    }
}
