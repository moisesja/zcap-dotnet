using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Examples;

// The example provider keeps private keys in memory. Supply an HSM/KMS-backed IDidSigner
// and your DID resolver in an application.
var dids = new InMemoryDidProvider();
const string owner = "did:key:z6MkOwner";
const string agent = "did:key:z6MkAgent";
const string assistant = "did:key:z6MkAssistant";
foreach (var did in new[] { owner, agent, assistant }) dids.GenerateAndRegisterKeyPair(did);
var signing = new SigningService(dids, dids);
var capabilities = new CapabilityService(signing);
var revocations = new RevocationService(new InMemoryRevocationStore());
var verifier = new VerificationService(dids, revocations, new InMemoryNonceStore(),
    policy: new VerificationPolicy { AllowTargetAttenuation = true });

var root = await capabilities.CreateRootCapabilityAsync(owner, "https://example.com/documents");
dids.RegisterRoot(root);
Console.WriteLine($"Root: {root.Id}");

// Native restrictions are signed and interoperable: target, actions and expiration.
var delegated = await capabilities.DelegateCapabilityAsync(root, agent, new[] { "read", "write" },
    DateTime.UtcNow.AddDays(7), invocationTarget: root.InvocationTarget + "/report");
var leaf = await capabilities.DelegateCapabilityAsync(delegated, assistant, new[] { "read" },
    DateTime.UtcNow.AddDays(1), invocationTarget: delegated.InvocationTarget + "?section=summary");
Console.WriteLine($"Two-level delegation valid: {await verifier.VerifyCapabilityChainAsync(leaf)}");

var invocation = capabilities.CreateInvocation(leaf, "read");
invocation.Proof = await signing.SignInvocationAsync(invocation, assistant);
Console.WriteLine($"Envelope invocation valid: {await verifier.VerifyInvocationAsync(invocation, leaf)}");

// The target API must enforce section=summary. The library enforces lexical narrowing;
// it cannot infer API semantics or prevent an API from ignoring its own query parameters.
var secured = await signing.SignCapabilityInvocationAsync(
    InvocationCapability.FromCapability(leaf), "read", leaf.InvocationTarget, assistant);
Console.WriteLine($"DI invocation valid: {await verifier.VerifyCapabilityInvocationAsync(
    secured, "read", new[] { leaf.InvocationTarget })}");

// Exact targets are the default. A verifier must consciously opt into narrowing.
var exactOnly = new VerificationService(dids);
Console.WriteLine($"Exact-only verifier rejects narrowed chain: {!await exactOnly.VerifyCapabilityChainAsync(leaf)}");

// Revocation is authenticated and recorded at the verifier responsible for the target.
// Replicas must share an authoritative revocation store; no arbitrary caveat URL is polled.
var revoke = await signing.SignRevocationAsync(delegated.Id, signerDid: owner, invocationTarget: delegated.InvocationTarget,
    reason: "Agent access withdrawn");
Console.WriteLine($"Signed revocation accepted: {await verifier.RevokeCapabilityAsync(delegated, revoke)}");
Console.WriteLine($"Descendant rejected after revocation: {!await verifier.VerifyCapabilityChainAsync(leaf)}");

// Custom caveats (#157) are an opt-in extension profile, not part of ZCAP-LD v0.4: other ZCAP
// implementations reject capabilities that carry them. Register the type on every service.
var caveatTypes = new CaveatTypeRegistry().Register<EpsilonBudgetCaveat>("EpsilonBudget");
var clinicalSigning = new SigningService(dids, dids, caveatTypes);
var clinicalCapabilities = new CapabilityService(clinicalSigning, caveatTypes);
var clinicalVerifier = new VerificationService(dids, revocations, new InMemoryNonceStore(),
    caveats: caveatTypes, caveatHandlers: new ICaveatHandler[] { new EpsilonBudgetLedger() });

var records = dids.RegisterRoot(await clinicalCapabilities.CreateRootCapabilityAsync(owner, "https://example.com/fhir"));
var orchestration = await clinicalCapabilities.DelegateCapabilityAsync(records, agent, new[] { "query", "cohort-query" },
    DateTime.UtcNow.AddDays(1), caveats: new Caveat[] { new EpsilonBudgetCaveat { MaxEpsilon = 8 } });
var genomics = await clinicalCapabilities.DelegateCapabilityAsync(orchestration, assistant, new[] { "query", "cohort-query" },
    DateTime.UtcNow.AddHours(4), caveats: new Caveat[] { new EpsilonBudgetCaveat { MaxEpsilon = 3 } });

async Task<VerificationOutcome> QueryAsync(Capability grant, string action)
{
    var request = clinicalCapabilities.CreateInvocation(grant, action);
    request.Proof = await clinicalSigning.SignInvocationAsync(request, assistant);
    return (await clinicalVerifier.VerifyInvocationDetailedAsync(request, grant)).Outcome;
}

Console.WriteLine($"Budget 3: query (cost 1): {await QueryAsync(genomics, "query")}");
Console.WriteLine($"Budget 3: cohort-query (cost 2): {await QueryAsync(genomics, "cohort-query")}");
Console.WriteLine($"Budget 3: one more query: {await QueryAsync(genomics, "query")}");

// Chain verification authenticates caveats but never authorizes them; only invocation enforces.
var chainResult = await clinicalVerifier.VerifyCapabilityChainDetailedAsync(genomics);
Console.WriteLine($"Chain check: {chainResult.Outcome}, budgets {string.Join(" > ",
    chainResult.Caveats!.Select(g => ((EpsilonBudgetCaveat)g.Caveat).MaxEpsilon))}");

// The budget is signed: raising it after delegation breaks the orchestrator's signature.
var raised = System.Text.Json.JsonSerializer.Deserialize<Capability>(
    System.Text.Json.JsonSerializer.Serialize(genomics, ZcapLd.Core.Cryptography.ZcapJsonOptions.Default)
        .Replace("\"maxEpsilon\":3,", "\"maxEpsilon\":30,"), ZcapLd.Core.Cryptography.ZcapJsonOptions.Default)!;
Console.WriteLine($"Raised budget after signing: {(await clinicalVerifier.VerifyCapabilityChainDetailedAsync(raised)).Outcome}");
