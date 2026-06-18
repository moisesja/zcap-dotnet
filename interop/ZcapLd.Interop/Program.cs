using System.Text.Json;
using ZcapLd.Core.Cryptography;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Interop;

// Cross-stack interop harness CLI (zcap-dotnet side).
//
//   gen    <rootOut> <delegatedOut>   — emit a deterministic RDFC-1.0-signed root + delegated zcap
//   verify <delegated> <root>         — verify a delegated capability's delegation chain (RDFC-1.0)
//
// Scope: capability DELEGATION proofs only (the canonicalization interop path). Invocation interop
// is a separate envelope concern and is out of scope here.

const string Target = "https://example.com/api/items";

// Fixed seeds → reproducible did:key identities (distinct from the JS side's 0x01/0x02 on purpose:
// each stack signs with its own keys; the other stack resolves them from the did:key string).
static byte[] Seed(byte b) => Enumerable.Repeat(b, 32).ToArray();

if (args.Length == 0)
{
    Console.Error.WriteLine("Usage: ZcapLd.Interop <gen|verify> ...");
    return 2;
}

try
{
    switch (args[0])
    {
        case "gen":
            if (args.Length != 3)
            {
                Console.Error.WriteLine("Usage: ZcapLd.Interop gen <rootOut> <delegatedOut>");
                return 2;
            }
            return await GenerateAsync(args[1], args[2]);

        case "gen-multi":
            if (args.Length != 4)
            {
                Console.Error.WriteLine("Usage: ZcapLd.Interop gen-multi <rootOut> <l1Out> <l2Out>");
                return 2;
            }
            return await GenerateMultiAsync(args[1], args[2], args[3]);

        case "verify":
            if (args.Length != 3)
            {
                Console.Error.WriteLine("Usage: ZcapLd.Interop verify <delegatedFile> <rootFile>");
                return 2;
            }
            return await VerifyAsync(args[1], args[2]);

        default:
            Console.Error.WriteLine($"Unknown command: {args[0]}");
            return 2;
    }
}
catch (Exception ex)
{
    Console.WriteLine("FAIL");
    Console.WriteLine($"{ex.GetType().Name}: {ex.Message}");
    return 1;
}

async Task<int> GenerateAsync(string rootOut, string delegatedOut)
{
    var provider = new DeterministicDidProvider();
    var rootDid = provider.RegisterDeterministicDidKey(Seed(0x11));
    var delegateDid = provider.RegisterDeterministicDidKey(Seed(0x22));

    // RDFC-1.0 is the only canonicalization — the cross-stack-interoperable one.
    var signing = new SigningService(provider, provider);
    var caps = new CapabilityService(signing);

    var root = await caps.CreateRootCapabilityAsync(rootDid, Target);
    provider.RegisterRoot(root);

    // Fresh expiry so @digitalbazaar/zcap's expiration check passes when it verifies this vector.
    var delegated = await caps.DelegateCapabilityAsync(
        root, delegateDid, new[] { "read" }, DateTime.UtcNow.AddDays(30));

    WriteJson(rootOut, root);
    WriteJson(delegatedOut, delegated);

    Console.WriteLine("GENERATED");
    Console.WriteLine($"  rootController = {rootDid}");
    Console.WriteLine($"  delegate      = {delegateDid}");
    Console.WriteLine($"  root.id       = {root.Id}");
    Console.WriteLine($"  delegated.id  = {delegated.Id}");
    Console.WriteLine($"  -> {rootOut}");
    Console.WriteLine($"  -> {delegatedOut}");
    return 0;
}

async Task<int> GenerateMultiAsync(string rootOut, string l1Out, string l2Out)
{
    var provider = new DeterministicDidProvider();
    var c0 = provider.RegisterDeterministicDidKey(Seed(0x11)); // root controller
    var c1 = provider.RegisterDeterministicDidKey(Seed(0x22)); // mid (level-1 controller)
    var c2 = provider.RegisterDeterministicDidKey(Seed(0x33)); // leaf (level-2 controller)

    var signing = new SigningService(provider, provider);
    var caps = new CapabilityService(signing);

    var root = await caps.CreateRootCapabilityAsync(c0, Target);
    provider.RegisterRoot(root);

    // level-1 delegation (signed by the root controller c0); chain = [rootId]
    var l1 = await caps.DelegateCapabilityAsync(root, c1, new[] { "read", "write" }, DateTime.UtcNow.AddDays(30));
    // level-2 delegation (signed by c1); chain = [rootId, {l1 embedded}]
    var l2 = await caps.DelegateCapabilityAsync(l1, c2, new[] { "read" }, DateTime.UtcNow.AddDays(20));

    WriteJson(rootOut, root);
    WriteJson(l1Out, l1);
    WriteJson(l2Out, l2);

    Console.WriteLine("GENERATED (multi-level)");
    Console.WriteLine($"  root.id = {root.Id}");
    Console.WriteLine($"  l1.id   = {l1.Id}  (chain depth 1)");
    Console.WriteLine($"  l2.id   = {l2.Id}  (chain depth 2 -> [rootId, {{l1}}])");
    return 0;
}

async Task<int> VerifyAsync(string delegatedFile, string rootFile)
{
    var delegated = ReadJson(delegatedFile);
    var root = ReadJson(rootFile);

    var provider = new DeterministicDidProvider();
    provider.RegisterRoot(root); // verifier dereferences the root the chain references by id

    var verifier = new VerificationService(
        provider,
        new CaveatProcessor(),
        new RevocationService(new InMemoryRevocationStore()),
        new InMemoryNonceStore());

    var result = await verifier.VerifyCapabilityChainDetailedAsync(delegated);

    if (result.IsValid)
    {
        Console.WriteLine("PASS");
        return 0;
    }

    Console.WriteLine("FAIL");
    Console.WriteLine($"{result.Outcome}: {result.Message}");
    return 1;
}

static void WriteJson(string path, Capability capability)
{
    Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
    var json = JsonSerializer.Serialize(capability, ZcapJsonOptions.Default);
    File.WriteAllText(path, json);
}

static Capability ReadJson(string path)
{
    var json = File.ReadAllText(path);
    return JsonSerializer.Deserialize<Capability>(json, ZcapJsonOptions.Default)
        ?? throw new InvalidOperationException($"Could not deserialize capability from {path}");
}
