using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using FluentAssertions;
using NetCrypto;
using Xunit;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Core.Tests.Helpers;

namespace ZcapLd.Core.Tests.Caveats;

/// <summary>
/// Known-answer fixtures for caveat profile v1 (#157), published under
/// <c>docs/caveat-profile-v1/</c> for other implementations. Ed25519 is deterministic, so fixed
/// seeds, ids and timestamps reproduce every byte. If a fixture changes, signing or canonicalization
/// drifted: investigate before regenerating (set ZCAP_REGENERATE_CAVEAT_FIXTURES=1).
/// </summary>
public class CaveatProfileFixtureTests
{
    private const string Target = "https://clinical.example/fhir/Observation";
    private const string OrchestratorId = "urn:uuid:9b7e3c1a-0d4f-4c41-8f0a-3a52c0e1b001";
    private const string AgentId = "urn:uuid:9b7e3c1a-0d4f-4c41-8f0a-3a52c0e1b002";
    private const string InvocationId = "urn:uuid:9b7e3c1a-0d4f-4c41-8f0a-3a52c0e1b003";
    private const string Expires = "2099-01-01T00:00:00.000000Z";
    private static readonly DateTime Created = new(2026, 10, 27, 0, 0, 0, DateTimeKind.Utc);

    private static readonly string FixtureDirectory = Path.Combine(FindRepositoryRoot(), "docs", "caveat-profile-v1");

    private sealed record Fixtures(
        InMemoryDidProvider Keys, CaveatTypeRegistry Registry, Capability Root, Capability Orchestrator, Capability Agent,
        JsonObject Invocation, IReadOnlyDictionary<string, string> Files);

    private static async Task<Fixtures> BuildAsync()
    {
        var registry = new CaveatTypeRegistry().Register<EpsilonBudgetCaveat>(EpsilonBudgetCaveat.TypeName);
        var keys = new InMemoryDidProvider();
        string Key(int first)
        {
            var seed = Enumerable.Range(first, 32).Select(i => (byte)i).ToArray();
            var did = $"did:key:{new DefaultKeyGenerator().FromPrivateKey(KeyType.Ed25519, seed).MultibasePublicKey}";
            keys.RegisterKey(did, seed);
            return did;
        }

        var patient = Key(1);
        var orchestrator = Key(33);
        var agent = Key(65);
        var signing = new SigningService(keys, keys, registry);
        var root = keys.RegisterRoot(await new CapabilityService(signing, registry).CreateRootCapabilityAsync(patient, Target));

        Capability Delegated(string id, string parentId, string controller, double budget) => new()
        {
            Context = new object[]
            {
                "https://w3id.org/zcap/v1", "https://w3id.org/security/suites/ed25519-2020/v1",
                CaveatTypeRegistry.GetContextUrl(EpsilonBudgetCaveat.TypeName),
            },
            Id = id,
            ParentCapability = parentId,
            Controller = controller,
            InvocationTarget = Target,
            AllowedAction = new[] { "query" },
            Expires = Expires,
            AdditionalProperties = new Dictionary<string, JsonElement>
            {
                ["caveat"] = JsonSerializer.SerializeToElement(new[]
                {
                    CaveatCodec.Write(new EpsilonBudgetCaveat { MaxEpsilon = budget }, registry),
                }),
            },
        };

        var orchestratorGrant = Delegated(OrchestratorId, root.Id, orchestrator, 8);
        orchestratorGrant.Proof = await signing.SignCapabilityAsync(
            orchestratorGrant, patient, "capabilityDelegation", new object[] { root.Id }, Created);
        var agentGrant = Delegated(AgentId, OrchestratorId, agent, 3);
        agentGrant.Proof = await signing.SignCapabilityAsync(
            agentGrant, orchestrator, "capabilityDelegation", new object[] { root.Id, orchestratorGrant }, Created);

        var invocation = await signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(agentGrant), "query", Target, agent,
            new JsonObject
            {
                ["@context"] = new JsonArray("https://w3id.org/zcap/v1", "https://w3id.org/security/suites/ed25519-2020/v1"),
                ["id"] = InvocationId,
                ["type"] = "https://w3id.org/zcap#CapabilityInvocationRequest",
            },
            Created);

        static string Pretty(object value) => JsonSerializer.Serialize(
            JsonSerializer.SerializeToNode(value, ZcapJsonOptions.Default),
            new JsonSerializerOptions(ZcapJsonOptions.Default) { WriteIndented = true }) + "\n";

        var files = new Dictionary<string, string>
        {
            ["epsilon-budget-context.jsonld"] = registry.GetContextDocument(EpsilonBudgetCaveat.TypeName) + "\n",
            ["root.json"] = Pretty(root),
            ["orchestrator-grant.json"] = Pretty(orchestratorGrant),
            ["agent-grant.json"] = Pretty(agentGrant),
            ["invocation.json"] = Pretty(invocation),
            ["agent-grant-document.nquads"] = Encoding.UTF8.GetString(new RdfcDocumentCanonicalizer(registry)
                .Canonicalize(ProofSigningPayloadBuilder.CloneCapabilityWithoutProof(agentGrant))),
        };
        return new Fixtures(keys, registry, root, orchestratorGrant, agentGrant, invocation, files);
    }

    [Fact(DisplayName = "Published caveat profile v1 fixtures regenerate byte-for-byte")]
    public async Task Fixtures_RegenerateIdentically()
    {
        var fixtures = await BuildAsync();
        if (Environment.GetEnvironmentVariable("ZCAP_REGENERATE_CAVEAT_FIXTURES") == "1")
        {
            Directory.CreateDirectory(FixtureDirectory);
            foreach (var (name, content) in fixtures.Files)
                await File.WriteAllTextAsync(Path.Combine(FixtureDirectory, name), content);
        }

        foreach (var (name, content) in fixtures.Files)
            (await File.ReadAllTextAsync(Path.Combine(FixtureDirectory, name))).Should().Be(content, $"{name} must not drift");
    }

    [Fact(DisplayName = "Published fixtures verify: chain is authentic, invocation is authorized by the handler")]
    public async Task PublishedFixtures_Verify()
    {
        var fixtures = await BuildAsync();
        Capability Load(string name) => CapabilityJson.Parse(File.ReadAllText(Path.Combine(FixtureDirectory, name)));
        var invocation = JsonNode.Parse(File.ReadAllText(Path.Combine(FixtureDirectory, "invocation.json")))!.AsObject();
        var ledger = new InMemoryEpsilonLedger();
        // The fixture invocation is dated 2026-10-27, so widen the freshness window to check its signature.
        var verifier = new VerificationService(fixtures.Keys, new RevocationService(new InMemoryRevocationStore()),
            new InMemoryNonceStore(), nonceWindow: TimeSpan.FromDays(365 * 70), relationshipResolver: fixtures.Keys,
            rootResolver: fixtures.Keys, caveats: fixtures.Registry, caveatHandlers: new[] { ledger });

        var chain = await verifier.VerifyCapabilityChainDetailedAsync(Load("agent-grant.json"));
        var invoked = await verifier.VerifyCapabilityInvocationDetailedAsync(invocation, "query", Target);

        chain.Outcome.Should().Be(VerificationOutcome.CaveatEnforcementRequired);
        chain.Caveats!.Select(g => ((EpsilonBudgetCaveat)g.Caveat).MaxEpsilon).Should().Equal(8, 3);
        invoked.Outcome.Should().Be(VerificationOutcome.Valid, invoked.Message);
        ledger.Spent(chain.Caveats![1].GrantKey).Should().Be(1);
    }

    [Fact(DisplayName = "In the allowed number domain, the signed JSON literal equals RFC 8785")]
    public void NumberDomain_RdfcLiteralEqualsJcs()
    {
        var registry = new CaveatTypeRegistry().Register<TagCaveat>(TagCaveat.TypeName);
        var canonicalizer = new RdfcDocumentCanonicalizer(registry);
        var random = new Random(157);
        var values = new List<double> { 0, 0.0001, -0.0001, 0.1, 0.30000000000000004, 1, 3, 2.5, 1e15 + 0.5, 9007199254740992 };
        while (values.Count < 600)
        {
            var magnitude = Math.Pow(10, random.Next(-4, 16));
            var value = Math.Round(random.NextDouble() * 10, random.Next(0, 12)) * magnitude * (random.Next(2) == 0 ? 1 : -1);
            if (value == 0 || (Math.Abs(value) >= 0.0001 && Math.Abs(value) <= 9007199254740992))
                values.Add(value);
        }

        foreach (var value in values)
        {
            var token = Encoding.UTF8.GetString(NetCid.JcsCanonicalizer.Canonicalize(JsonSerializer.SerializeToElement(value)));
            if (token.Contains('e'))
                continue; // Outside the domain by construction; the codec refuses it.
            var document = JsonNode.Parse(
                $"{{\"@context\":[\"https://w3id.org/zcap/v1\",\"{CaveatTypeRegistry.GetContextUrl("Tag")}\"]," +
                $"\"id\":\"urn:example:n\",\"caveat\":[{{\"data\":{token},\"type\":\"Tag\"}}]}}")!;
            var nquads = Encoding.UTF8.GetString(canonicalizer.Canonicalize(document));
            var literal = Regex.Match(nquads, "#data> \"(.*)\"\\^\\^").Groups[1].Value;

            literal.Should().Be(token, $"{value.ToString("R", CultureInfo.InvariantCulture)} must sign as its RFC 8785 form");
            CaveatCodec.TryRead(document["caveat"].Deserialize<JsonElement>(), new[] { CaveatTypeRegistry.GetContextUrl("Tag") },
                registry, materialize: true, out _).Should().BeNull($"{token} is inside the allowed domain");
        }
    }

    private static string FindRepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "ZcapLd.sln")))
                return directory.FullName;
        }

        throw new InvalidOperationException("Could not locate the repository root (ZcapLd.sln).");
    }
}
