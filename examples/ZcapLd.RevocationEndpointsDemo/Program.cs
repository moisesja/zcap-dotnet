using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Features;
using ZcapLd.AspNetCore.DependencyInjection;
using ZcapLd.AspNetCore.Endpoints;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Services;
using ZcapLd.RevocationEndpointsDemo;

// `--walkthrough` is the demo's own switch, not configuration: strip it before the host's
// command-line provider sees it, so it cannot swallow a following `--urls` as its value.
var walkthrough = args.Contains("--walkthrough", StringComparer.Ordinal);
var builder = WebApplication.CreateBuilder(args.Where(a => a != "--walkthrough").ToArray());

var sqlitePath = builder.Configuration["Revocation:SqlitePath"];
if (string.IsNullOrWhiteSpace(sqlitePath))
{
    sqlitePath = Path.Combine(builder.Environment.ContentRootPath, "revocations-demo.db");
}

var fullPath = Path.GetFullPath(sqlitePath);
var connectionString = $"Data Source={fullPath}";

// Register the full ZCAP service graph. The POST (revoke) endpoint resolves IVerificationService
// to authenticate (signature/proof-of-possession) and authorize the signed revocation request —
// AddZcapRevocationSupport() alone (store + service only) is not sufficient for the POST endpoint.
builder.Services.AddZcapServices();

// Override the revocation store with the SQLite-backed implementation (Replace-based, so it must
// run after AddZcapServices, which registers the in-memory store via TryAdd).
builder.Services.AddZcapRevocationSupport(_ => new SqliteRevocationStore(connectionString));

// A spec-exact delegation chain references the root by id only (Issue #50), so verifying a
// *delegated* invocation or authorizing its revocation requires resolving that root. A real resource
// server resolves roots from its own store. This demo registers an in-memory resolver that starts
// empty: nothing is accepted until trusted code registers a root. `--walkthrough` does that in
// RevocationWalkthrough.ProvisionAsync; a root is never taken from a request.
builder.Services.AddZcapRootCapabilityResolver<InMemoryRootCapabilityResolver>();

var app = builder.Build();

app.MapGet("/", () => Results.Ok(new
{
    service = "zcap revocation endpoints demo",
    sqliteDatabase = fullPath,
    endpoints = new
    {
        read = $"POST {DemoResource.ReportPath}  (body: a DI-secured application document invoking '{DemoResource.ReadAction}' on {DemoResource.ReportTarget})",
        revoke = "POST /zcaps/revocations/{url-encoded-capability-id}"
    },
    revocation = new
    {
        description = "Revocation requires PROOF OF POSSESSION. POST a JSON body " +
                      "{ \"capability\": <the full capability being revoked, with its delegation chain>, " +
                      "\"signedRevocation\": <a revocation request signed via ISigningService.SignRevocationAsync> }. " +
                      "The signer must control the capability or an ancestor in its chain. An unauthenticated, " +
                      "unauthorized, or foreign-key request returns 403 — there is no bare-revokerDid path. " +
                      "The proof's 'created' must be fresh (five minutes by default).",
        bodyShape = new
        {
            capability = "{ @context, id, controller, invocationTarget, parentCapability, allowedAction, expires, proof: { ..., capabilityChain } }",
            signedRevocation = "{ id, capability, capabilityAction: \"revoke\", invocationTarget, proof: { type, created, proofPurpose: \"capabilityRevocation\", verificationMethod, proofValue, capability, capabilityAction: \"revoke\", invocationTarget, revocationReason? } }"
        }
    },
    examples = new
    {
        walkthrough = "dotnet run --project examples/ZcapLd.RevocationEndpointsDemo -- --walkthrough  (provisions a root, then: read 200, stranger revoke 403, owner revoke 200, read 403 Revoked; prints every request body)",
        revoke = "curl -X POST http://localhost:5099/zcaps/revocations/<url-encoded-capability-id> -H \"Content-Type: application/json\" -d @signed-revocation.json"
    }
}));

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapZcapRevocationEndpoints();

// The protected resource. The body is a DI-secured application document: a JSON object carrying a
// `capabilityInvocation` proof that embeds the delegated capability (a root invocation would name the
// root by id). Verification covers the signature, the chain back to a root this server resolves, the
// controller relationship, the action, the target, freshness, replay and revocation.
app.MapPost(DemoResource.ReportPath, async (HttpRequest httpRequest, IVerificationService verification, CancellationToken ct) =>
{
    // Bound the unauthenticated body before materializing it, as the revocation endpoint does: the
    // verifier's structural limits only run after deserialization.
    var bodySize = httpRequest.HttpContext.Features.Get<IHttpMaxRequestBodySizeFeature>();
    if (bodySize is { IsReadOnly: false })
    {
        bodySize.MaxRequestBodySize = 1 * 1024 * 1024; // 1 MB
    }

    JsonObject? document;
    try
    {
        // The shared options reject duplicate properties and keep every field the proof covers.
        document = await JsonSerializer.DeserializeAsync<JsonObject>(httpRequest.Body, ZcapJsonOptions.Default, ct);
    }
    catch (JsonException)
    {
        return Results.BadRequest("Request body is not a JSON object.");
    }
    catch (BadHttpRequestException)
    {
        return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
    }

    if (document is null)
    {
        return Results.BadRequest("Request body is not a JSON object.");
    }

    // The expected action and target come from this server, never from the document. The demo's
    // resolver serves only the root provisioned for this resource, so an invocation under any other
    // root cannot resolve; a real resource server that serves several roots also pins the ids it
    // accepts here, with the `expectedRootCapabilityIds` overload.
    var result = await verification.VerifyCapabilityInvocationDetailedAsync(
        document, DemoResource.ReadAction, DemoResource.ReportTarget);

    if (result.IsValid)
    {
        return Results.Ok(new { document = "report", content = "Quarterly figures: all targets met." });
    }

    // A denial reason is useful while developing, but in production it tells an attacker which check
    // failed (bad signature vs. unknown root vs. revoked). The library logs denials at Debug for the
    // same reason; see appsettings.Development.json. So the outcome is disclosed only in Development.
    return app.Environment.IsDevelopment()
        ? Results.Json(new { outcome = result.Outcome.ToString() }, statusCode: StatusCodes.Status403Forbidden)
        : Results.StatusCode(StatusCodes.Status403Forbidden);
});

if (!walkthrough)
{
    app.Run();
    return;
}

// --walkthrough: start the host, provision a root, drive the endpoints over HTTP, report, exit.
await app.StartAsync();
try
{
    var address = app.Urls.First();
    // Kestrel reports wildcard bindings as "http://[::]:port" or "http://0.0.0.0:port"; connect via loopback.
    var baseAddress = new UriBuilder(address.Replace("[::]", "localhost").Replace("0.0.0.0", "localhost").Replace("+", "localhost").Replace("*", "localhost"));
    using var http = new HttpClient { BaseAddress = baseAddress.Uri };

    Console.WriteLine();
    Console.WriteLine($"Walkthrough against {baseAddress.Uri} (environment: {app.Environment.EnvironmentName})");
    Console.WriteLine();

    var provisioned = await RevocationWalkthrough.ProvisionAsync(app.Services);
    var results = await RevocationWalkthrough.RunAsync(http, provisioned, Console.Out);

    var allMatched = RevocationWalkthrough.AllMatched(results);
    Console.WriteLine(new string('=', 78));
    Console.WriteLine(allMatched
        ? $"Walkthrough complete: all {results.Count} steps returned the expected status."
        : $"Walkthrough FAILED: {results.Count(r => !r.Matched)} of {results.Count} steps did not return the expected status.");
    Console.WriteLine(new string('=', 78));

    Environment.ExitCode = allMatched ? 0 : 1;
}
finally
{
    await app.StopAsync();
}

/// <summary>
/// Exposed so the ASP.NET integration tests can target this host via
/// <c>WebApplicationFactory&lt;Program&gt;</c>. Top-level statements otherwise emit an internal type.
/// </summary>
public partial class Program { }
