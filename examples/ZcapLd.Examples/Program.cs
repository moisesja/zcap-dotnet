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
