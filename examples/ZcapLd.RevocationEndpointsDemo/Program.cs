using ZcapLd.AspNetCore.DependencyInjection;
using ZcapLd.AspNetCore.Endpoints;
using ZcapLd.AspNetCore.Services;
using ZcapLd.RevocationEndpointsDemo;

var builder = WebApplication.CreateBuilder(args);

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

// Enable ValidWhileTrue caveat support.
// This registers HttpValidWhileTrueHandler, which GETs the caveat URI during
// verification and checks the RevocationStatusHttpResponse.IsRevoked field.
// The named HttpClient can be configured for timeouts, retry policies, etc.
builder.Services.AddZcapValidWhileTrueSupport();
builder.Services.AddHttpClient(HttpValidWhileTrueHandler.HttpClientName, client =>
{
    client.Timeout = TimeSpan.FromSeconds(5);
});

var app = builder.Build();

app.MapGet("/", () => Results.Ok(new
{
    service = "zcap revocation endpoints demo",
    sqliteDatabase = fullPath,
    endpoints = new
    {
        getStatus = "GET /zcaps/revocations/{url-encoded-capability-id}",
        revoke = "POST /zcaps/revocations/{url-encoded-capability-id}"
    },
    validWhileTrue = new
    {
        description = "These endpoints also serve as the backend for ValidWhileTrue caveats. " +
                      "Delegators create capabilities with a ValidWhileTrue caveat URI pointing " +
                      "to the GET endpoint. Verifiers with AddZcapValidWhileTrueSupport() check " +
                      "this URI automatically during invocation verification.",
        exampleCaveat = new
        {
            type = "ValidWhileTrue",
            uri = "http://localhost:5099/zcaps/revocations/urn%3Auuid%3A12345"
        }
    },
    revocation = new
    {
        description = "Revocation requires PROOF OF POSSESSION. POST a JSON body " +
                      "{ \"capability\": <the full capability being revoked, with its delegation chain>, " +
                      "\"signedRevocation\": <a revocation request signed via ISigningService.SignRevocationAsync> }. " +
                      "The signer must control the capability or an ancestor in its chain. An unauthenticated, " +
                      "unauthorized, or foreign-key request returns 403 — there is no bare-revokerDid path.",
        bodyShape = new
        {
            capability = "{ id, controller, invocationTarget, parentCapability, proof, ... }",
            signedRevocation = "{ id, capability, capabilityAction: \"revoke\", invocationTarget, proof: { proofPurpose: \"capabilityRevocation\", verificationMethod, proofValue, ... } }"
        }
    },
    examples = new
    {
        revoke = "curl -X POST http://localhost:5099/zcaps/revocations/<url-encoded-capability-id> -H \"Content-Type: application/json\" -d @signed-revocation.json",
        status = "curl http://localhost:5099/zcaps/revocations/urn%3Auuid%3A12345"
    }
}));

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapZcapRevocationEndpoints();

app.Run();

/// <summary>
/// Exposed so the ASP.NET integration tests can target this host via
/// <c>WebApplicationFactory&lt;Program&gt;</c>. Top-level statements otherwise emit an internal type.
/// </summary>
public partial class Program { }
