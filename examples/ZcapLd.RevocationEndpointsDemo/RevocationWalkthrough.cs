using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using ZcapLd.AspNetCore.Contracts;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;

namespace ZcapLd.RevocationEndpointsDemo;

/// <summary>
/// Drives the demo's real HTTP endpoints through the signed-revocation flow: a delegated read succeeds,
/// a stranger's revocation is refused, the owner's revocation is accepted, and the same delegate's next
/// read is refused as <c>Revoked</c>. The ASP.NET integration tests run the same code against the host
/// booted by <c>WebApplicationFactory&lt;Program&gt;</c>.
/// </summary>
public static class RevocationWalkthrough
{
    /// <summary>What <see cref="ProvisionAsync"/> set up: the client-side signing stack and the chain.</summary>
    /// <param name="Signing">Signs with the demo keyring; holds the private keys of every DID below.</param>
    /// <param name="OwnerDid">The resource owner: controls the root capability.</param>
    /// <param name="AgentDid">The delegate: controls <paramref name="Delegated"/>.</param>
    /// <param name="StrangerDid">A valid key with no place in the chain.</param>
    /// <param name="Root">The root capability, registered with the server's resolver.</param>
    /// <param name="Delegated">The <c>read</c> capability the owner delegated to the agent.</param>
    public sealed record Provisioned(
        SigningService Signing,
        string OwnerDid,
        string AgentDid,
        string StrangerDid,
        Capability Root,
        Capability Delegated);

    /// <summary>One request of the walkthrough and what came back.</summary>
    public sealed record StepResult(
        string Name,
        string Method,
        string Path,
        HttpStatusCode ExpectedStatus,
        HttpStatusCode ActualStatus,
        string ResponseBody)
    {
        /// <summary>Whether the status matched the expectation.</summary>
        public bool Matched => ExpectedStatus == ActualStatus;
    }

    /// <summary>
    /// Creates the demo keys and capabilities and registers the root with the server's
    /// <see cref="IRootCapabilityResolver"/>.
    /// <para>
    /// This is trusted startup code standing in for "the resource owner provisions its root". It is
    /// never request input: a client-supplied root could name an attacker-chosen controller, so a
    /// resource server resolves roots from its own store and never from a request (#50, #155).
    /// </para>
    /// </summary>
    /// <param name="services">The running host's services; must hold an <see cref="InMemoryRootCapabilityResolver"/>.</param>
    public static async Task<Provisioned> ProvisionAsync(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);

        if (services.GetRequiredService<IRootCapabilityResolver>() is not InMemoryRootCapabilityResolver roots)
        {
            throw new InvalidOperationException(
                "The walkthrough registers its root with the demo's InMemoryRootCapabilityResolver; " +
                "the host has a different IRootCapabilityResolver.");
        }

        // The client side: keys stay here. The server resolves did:key and never sees them.
        var keyring = new DemoKeyring();
        var signing = new SigningService(keyring, new DidKeyResolver());
        var capabilities = new CapabilityService(signing);

        var ownerDid = keyring.GenerateDidKey();
        var agentDid = keyring.GenerateDidKey();
        var strangerDid = keyring.GenerateDidKey();

        var root = await capabilities.CreateRootCapabilityAsync(ownerDid, DemoResource.ReportTarget, new[] { DemoResource.ReadAction });
        var delegated = await capabilities.DelegateCapabilityAsync(
            root, agentDid, new[] { DemoResource.ReadAction }, DateTime.UtcNow.AddDays(1));

        roots.Register(root);

        return new Provisioned(signing, ownerDid, agentDid, strangerDid, root, delegated);
    }

    /// <summary>
    /// Runs the four steps against <paramref name="http"/>, printing each request, response and verdict
    /// to <paramref name="output"/>.
    /// </summary>
    public static async Task<IReadOnlyList<StepResult>> RunAsync(HttpClient http, Provisioned p, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(p);
        ArgumentNullException.ThrowIfNull(output);

        output.WriteLine("Provisioned (trusted startup code, not request input):");
        output.WriteLine($"  owner    {p.OwnerDid}");
        output.WriteLine($"  agent    {p.AgentDid}");
        output.WriteLine($"  stranger {p.StrangerDid}");
        output.WriteLine($"  root     {p.Root.Id}  (registered with the server's root resolver)");
        output.WriteLine($"  delegated {p.Delegated.Id}  read -> agent, expires {p.Delegated.Expires}");
        output.WriteLine();

        var results = new List<StepResult>(4);

        // 1. The agent invokes its delegated capability. Every invocation is freshly signed: the
        //    verifier consumes the proof's nonce, so a replayed document is refused.
        results.Add(await PostAsync(http, output,
            "1. The agent reads the report with its delegated capability",
            DemoResource.ReportPath,
            await ReadInvocationAsync(p),
            HttpStatusCode.OK));

        // 2. A stranger signs a well-formed revocation. The signature verifies (the key is real), but
        //    no controller in the chain authorizes it, so the server records nothing.
        results.Add(await PostAsync(http, output,
            "2. A stranger tries to revoke the agent's capability",
            RevocationPath(p.Delegated),
            await RevocationAsync(p, p.StrangerDid, "stranger"),
            HttpStatusCode.Forbidden));

        // 3. The owner controls the root, the delegated capability's parent, so the owner may revoke it.
        results.Add(await PostAsync(http, output,
            "3. The owner revokes the agent's capability",
            RevocationPath(p.Delegated),
            await RevocationAsync(p, p.OwnerDid, "access withdrawn"),
            HttpStatusCode.OK));

        // 4. A fresh, correctly signed invocation of the same capability is now refused: the check
        //    happens where access is enforced, under the scope of the proof that delegated it (#158).
        results.Add(await PostAsync(http, output,
            "4. The agent reads again with a fresh invocation",
            DemoResource.ReportPath,
            await ReadInvocationAsync(p),
            HttpStatusCode.Forbidden));

        return results;
    }

    /// <summary>Whether every step got the status it expected.</summary>
    public static bool AllMatched(IEnumerable<StepResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);
        return results.All(r => r.Matched);
    }

    /// <summary>
    /// The route of the revocation endpoint for a capability: <c>encodeURIComponent(id)</c>, decoded
    /// exactly once by the endpoint. A root id already contains escapes and so is encoded twice.
    /// </summary>
    public static string RevocationPath(Capability capability)
        => $"/zcaps/revocations/{Uri.EscapeDataString(capability.Id)}";

    /// <summary>A DI-secured application document invoking <c>read</c> on the report with the delegated capability.</summary>
    private static async Task<JsonObject> ReadInvocationAsync(Provisioned p)
        => await p.Signing.SignCapabilityInvocationAsync(
            InvocationCapability.FromCapability(p.Delegated), DemoResource.ReadAction, DemoResource.ReportTarget, p.AgentDid);

    /// <summary>The revocation endpoint's body: the capability with its chain, and the signed request.</summary>
    private static async Task<JsonObject> RevocationAsync(Provisioned p, string signerDid, string reason)
    {
        var signed = await p.Signing.SignRevocationAsync(p.Delegated.Id, signerDid, p.Delegated.InvocationTarget, reason);
        var body = new SignedRevocationHttpRequest { Capability = p.Delegated, SignedRevocation = signed };
        return JsonSerializer.SerializeToNode(body, ZcapJsonOptions.Default)!.AsObject();
    }

    private static async Task<StepResult> PostAsync(
        HttpClient http, TextWriter output, string name, string path, JsonObject body, HttpStatusCode expected)
    {
        output.WriteLine(new string('-', 78));
        output.WriteLine(name);
        output.WriteLine(new string('-', 78));
        output.WriteLine($"POST {path}");
        output.WriteLine(Describe(body));
        output.WriteLine();

        // ZcapJsonOptions.Default is what the endpoints deserialize with; it keeps proofs and extension
        // data byte-for-byte, which is what a signature covers.
        var json = body.ToJsonString(ZcapJsonOptions.Default);
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var response = await http.PostAsync(path, content);
        var responseBody = await response.Content.ReadAsStringAsync();

        var result = new StepResult(name, HttpMethod.Post.Method, path, expected, response.StatusCode, responseBody);
        output.WriteLine($"=> {(int)response.StatusCode} {response.StatusCode}{(responseBody.Length == 0 ? "  (empty body)" : "")}");
        if (responseBody.Length > 0)
        {
            output.WriteLine($"   {responseBody}");
        }

        output.WriteLine(result.Matched
            ? $"   as expected ({(int)expected})"
            : $"   UNEXPECTED: wanted {(int)expected} {expected}");
        output.WriteLine();
        return result;
    }

    /// <summary>
    /// Pretty-prints a request body. A revocation body embeds the whole delegated capability under
    /// <c>capability</c>; it was printed in full inside step 1's invocation, so here it is replaced by its
    /// id and the <c>signedRevocation</c> is shown whole.
    /// </summary>
    private static string Describe(JsonObject body)
    {
        var shown = body;
        if (body.ContainsKey("signedRevocation") && body["capability"] is JsonObject capability)
        {
            shown = (JsonObject)body.DeepClone();
            shown["capability"] = $"<the full delegated capability {capability["id"]}, as printed in step 1>";
        }

        return shown.ToJsonString(new JsonSerializerOptions(ZcapJsonOptions.Default) { WriteIndented = true });
    }
}
