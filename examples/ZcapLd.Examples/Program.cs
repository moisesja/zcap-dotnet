using NetCrypto;
using ZcapLd.Core.Models;
using ZcapLd.Core.Services;
using ZcapLd.Examples;

// Every outcome below is checked against the expected value, so this program doubles as a smoke test:
// CI runs it and a mismatch exits non-zero.
var checks = 0;
var failures = 0;
void Check<T>(string label, T expected, T actual)
{
    checks++;
    if (EqualityComparer<T>.Default.Equals(expected, actual))
    {
        Console.WriteLine($"{label}: {actual}");
        return;
    }

    failures++;
    Console.WriteLine($"FAIL {label}: {actual} (expected {expected})");
}

// The example provider keeps private keys in memory. Supply an HSM/KMS-backed IDidSigner
// and your DID resolver in an application.
var dids = new InMemoryDidProvider();
const string owner = "did:key:z6MkOwner";
const string agent = "did:key:z6MkAgent";
const string assistant = "did:key:z6MkAssistant";
const string helperBot = "did:key:z6MkHelper";
// The agent signs with P-256 (EcdsaSecp256r1Signature2019), the others with Ed25519Signature2020:
// each link carries its signer's suite context, and a chain can mix suites (#159).
dids.GenerateAndRegisterKeyPair(owner);
dids.GenerateAndRegisterKeyPair(agent, KeyType.P256);
dids.GenerateAndRegisterKeyPair(assistant);
dids.GenerateAndRegisterKeyPair(helperBot);
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
Check("Two-level delegation", VerificationOutcome.Valid,
    (await verifier.VerifyCapabilityChainDetailedAsync(leaf)).Outcome);

var invocation = capabilities.CreateInvocation(leaf, "read");
invocation.Proof = await signing.SignInvocationAsync(invocation, assistant);
Check("Envelope invocation", VerificationOutcome.Valid,
    (await verifier.VerifyInvocationDetailedAsync(invocation, leaf)).Outcome);

// The target API must enforce section=summary. The library enforces lexical narrowing;
// it cannot infer API semantics or prevent an API from ignoring its own query parameters.
var secured = await signing.SignCapabilityInvocationAsync(
    InvocationCapability.FromCapability(leaf), "read", leaf.InvocationTarget, assistant);
Check("DI invocation", VerificationOutcome.Valid,
    (await verifier.VerifyCapabilityInvocationDetailedAsync(secured, "read", new[] { leaf.InvocationTarget })).Outcome);

// Exact targets are the default. A verifier must consciously opt into narrowing.
var exactOnly = new VerificationService(dids);
Check("Exact-only verifier rejects narrowed chain", VerificationOutcome.AttenuationViolation,
    (await exactOnly.VerifyCapabilityChainDetailedAsync(leaf)).Outcome);

// Revocation is authenticated and recorded at the verifier responsible for the target.
// Replicas must share an authoritative revocation store; no arbitrary caveat URL is polled.
// A signed request is honoured only from a controller of the capability or of one of its ancestors.

// 1. Unauthorized signer: the assistant controls only `leaf`, so it cannot revoke its parent.
var forged = await signing.SignRevocationAsync(delegated.Id, signerDid: assistant, invocationTarget: delegated.InvocationTarget);
Check("Revocation signed by a descendant accepted", false, await verifier.RevokeCapabilityAsync(delegated, forged));
Check("Parent after the refused revocation", VerificationOutcome.Valid,
    (await verifier.VerifyCapabilityChainDetailedAsync(delegated)).Outcome);

// 2. Mid-chain delegator: the agent may revoke what it delegated, and only that. Its own grant stays.
var helper = await capabilities.DelegateCapabilityAsync(delegated, helperBot, new[] { "read" },
    DateTime.UtcNow.AddDays(1), invocationTarget: delegated.InvocationTarget);
var agentRevoke = await signing.SignRevocationAsync(helper.Id, signerDid: agent, invocationTarget: helper.InvocationTarget);
Check("Revocation signed by the delegator accepted", true, await verifier.RevokeCapabilityAsync(helper, agentRevoke));
Check("Helper after its delegator revoked it", VerificationOutcome.Revoked,
    (await verifier.VerifyCapabilityChainDetailedAsync(helper)).Outcome);
Check("Delegator's own grant after revoking the helper", VerificationOutcome.Valid,
    (await verifier.VerifyCapabilityChainDetailedAsync(delegated)).Outcome);

// 3. Ancestor revocation: the owner revokes the agent's grant, which cuts off every descendant.
// A forged copy of an id under another chain lands in another revocation scope (#158); see
// VerificationServiceRevocationScopeTests.
var revoke = await signing.SignRevocationAsync(delegated.Id, signerDid: owner, invocationTarget: delegated.InvocationTarget,
    reason: "Agent access withdrawn");
Check("Revocation signed by the owner accepted", true, await verifier.RevokeCapabilityAsync(delegated, revoke));
Check("Descendant chain after the ancestor was revoked", VerificationOutcome.Revoked,
    (await verifier.VerifyCapabilityChainDetailedAsync(leaf)).Outcome);
var afterRevocation = capabilities.CreateInvocation(leaf, "read");
afterRevocation.Proof = await signing.SignInvocationAsync(afterRevocation, assistant);
Check("Descendant invocation after the ancestor was revoked", VerificationOutcome.Revoked,
    (await verifier.VerifyInvocationDetailedAsync(afterRevocation, leaf)).Outcome);

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

Check("Budget 3: query (cost 1)", VerificationOutcome.Valid, await QueryAsync(genomics, "query"));
Check("Budget 3: cohort-query (cost 2)", VerificationOutcome.Valid, await QueryAsync(genomics, "cohort-query"));
Check("Budget 3: one more query", VerificationOutcome.CaveatNotSatisfied, await QueryAsync(genomics, "query"));

// Chain verification authenticates caveats but never authorizes them; only invocation enforces.
var chainResult = await clinicalVerifier.VerifyCapabilityChainDetailedAsync(genomics);
Check("Chain check", VerificationOutcome.CaveatEnforcementRequired, chainResult.Outcome);
Check("Chain budgets", "8 > 3", string.Join(" > ",
    chainResult.Caveats!.Select(g => ((EpsilonBudgetCaveat)g.Caveat).MaxEpsilon)));

// The budget is signed: raising it after delegation breaks the orchestrator's signature.
var raised = System.Text.Json.JsonSerializer.Deserialize<Capability>(
    System.Text.Json.JsonSerializer.Serialize(genomics, ZcapLd.Core.Cryptography.ZcapJsonOptions.Default)
        .Replace("\"maxEpsilon\":3,", "\"maxEpsilon\":30,"), ZcapLd.Core.Cryptography.ZcapJsonOptions.Default)!;
Check("Raised budget after signing", VerificationOutcome.InvalidSignature,
    (await clinicalVerifier.VerifyCapabilityChainDetailedAsync(raised)).Outcome);

Console.WriteLine(failures == 0 ? $"All {checks} checks passed" : $"{failures} of {checks} check(s) FAILED");
return failures == 0 ? 0 : 1;
