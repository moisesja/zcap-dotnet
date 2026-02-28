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
    examples = new
    {
        revoke = "curl -X POST http://localhost:5099/zcaps/revocations/urn%3Auuid%3A12345 -H \"Content-Type: application/json\" -d '{\"revokerDid\":\"did:key:z6MkDemo\",\"reason\":\"key compromised\"}'",
        status = "curl http://localhost:5099/zcaps/revocations/urn%3Auuid%3A12345"
    }
}));

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapZcapRevocationEndpoints();

app.Run();
