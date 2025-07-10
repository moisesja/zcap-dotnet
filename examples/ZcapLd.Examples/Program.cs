using ZcapLd.Core.Models;
using ZcapLd.Core.Cryptography;

Console.WriteLine("ZCAP-LD .NET Example");

// Create a sample capability
var capability = new Capability
{
    Id = "urn:uuid:example-capability",
    Controller = "did:example:alice",
    InvocationTarget = "https://example.com/resource",
    AllowedAction = new[] { "read", "write" },
    Context = "https://w3id.org/zcap/v1"
};

Console.WriteLine($"Created capability: {capability.Id}");
Console.WriteLine($"Controller: {capability.Controller}");
Console.WriteLine($"Target: {capability.InvocationTarget}");
Console.WriteLine($"Actions: {string.Join(", ", capability.AllowedAction)}");

// Demonstrate basic signing functionality (stub)
var testData = System.Text.Encoding.UTF8.GetBytes("test data");
var privateKey = new byte[32];
var signature = Ed25519Signer.Sign(testData, privateKey);

Console.WriteLine($"Generated signature length: {signature.Length} bytes");
Console.WriteLine("Example completed successfully!");